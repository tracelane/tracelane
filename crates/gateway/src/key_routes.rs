//!
//! `POST /v1/keys` — mints a `tlane_<base62>` API key for the authenticated
//! tenant and returns the raw key exactly once. Mounted only when Postgres is
//! configured (`crate::db::global_pool().is_some()`), alongside the BYOK and
//! prompt-management routes.
//!
//! ## Why the gateway mints (not the dashboard)
//!
//! The dashboard runs on the Cloudflare Workers runtime, where the web minter's
//! WASM Argon2 (`hash-wasm`) fails at runtime — every "+ New key" click 500'd
//! same peppered-HMAC + Argon2id derivation as the verifier
//! (`crate::db::api_keys`), so keys stay byte-compatible: a key minted here
//! verifies through `lookup_tenant_by_key_body` unchanged, and any key minted by
//! the legacy web path (non-CF deploys) stays valid too.
//!
//! ## Tenant isolation
//!
//! The tenant id is sourced ONLY from `Claims.tenant_id`
//! (`crate::auth::validate_authorization`) — never a path, query, or body field.
//! The dashboard proxies the end-user's WorkOS JWT here; the JWT `org_id` →
//! internal-UUID bridge (ADR-042) yields the tenant the row is inserted under.

use anyhow::Result;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::db::api_keys::MintedKey;
use tracelane_shared::TenantId;

/// Upper bound on the user-supplied key name (defensive; the column is TEXT).
const MAX_KEY_NAME_LEN: usize = 128;

/// Mint seam — lets the handler be unit-tested without Postgres (real impl is
/// [`PgKeyMinter`]; tests use an in-module mock). Off the request hot path, so
/// `async_trait` is fine — CLAUDE.md bans it only on the gateway hot path.
#[async_trait::async_trait]
pub trait KeyMinter: Send + Sync {
    /// Mint a key for `tenant`, returning the row plus the one-time raw secret.
    /// `minted_by` is the WorkOS user id of the minting user (for §3
    /// key-revoke-on-member-removal); `None` for API-key / service auth.
    async fn mint(
        &self,
        tenant: &TenantId,
        name: &str,
        minted_by: Option<&str>,
    ) -> Result<MintedKey>;
}

/// Production minter — inserts through the shared Postgres pool.
pub struct PgKeyMinter {
    pub pool: deadpool_postgres::Pool,
}

#[async_trait::async_trait]
impl KeyMinter for PgKeyMinter {
    async fn mint(
        &self,
        tenant: &TenantId,
        name: &str,
        minted_by: Option<&str>,
    ) -> Result<MintedKey> {
        crate::db::api_keys::mint(&self.pool, tenant, name, minted_by).await
    }
}

/// Router state — the mint seam behind an `Arc` (clone-cheap per request).
#[derive(Clone)]
pub struct KeyRoutesState {
    pub minter: Arc<dyn KeyMinter>,
}

/// `POST /v1/keys` request body.
#[derive(Debug, Deserialize)]
struct CreateKeyBody {
    name: String,
}

/// `POST /v1/keys` response. camelCase to match the dashboard's `CreateResult`
/// (`apps/web/components/settings/ApiKeyManager.tsx`). `rawKey` is shown once.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateKeyResponse {
    id: String,
    name: String,
    key_prefix: String,
    /// RFC3339 UTC. `null` on a fresh key (matches the list `lastUsedAt`).
    last_used_at: Option<String>,
    created_at: String,
    raw_key: String,
}

/// Mount the mint route. Merged in `server.rs` when Postgres is configured.
pub fn routes() -> Router<KeyRoutesState> {
    Router::new().route("/v1/keys", post(create_key_handler))
}

/// Extract the validated claims from the `Authorization` header. Tenant
/// identity + role are sourced ONLY from a verified JWT / API key — never a
/// body or custom header (CLAUDE.md tenant-isolation invariant).
async fn claims_from_auth(
    headers: &HeaderMap,
) -> Result<crate::auth::Claims, (StatusCode, String)> {
    let header = headers.get("authorization").ok_or((
        StatusCode::UNAUTHORIZED,
        "missing Authorization header".into(),
    ))?;
    let header_str = header.to_str().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Authorization must be ASCII".into(),
        )
    })?;
    crate::auth::validate_authorization(header_str)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("auth failed: {e}")))
}

/// POST /v1/keys — mint an API key for the authenticated tenant.
///
/// 201 with `{id,name,keyPrefix,createdAt,lastUsedAt,rawKey}` on success; 401 if
/// unauthenticated; 400 on an empty/oversized name; 500 if minting fails. The
/// raw key is in the body once and is never logged.
#[tracing::instrument(skip(state, headers, body), fields(tenant_id = tracing::field::Empty))]
async fn create_key_handler(
    State(state): State<KeyRoutesState>,
    headers: HeaderMap,
    Json(body): Json<CreateKeyBody>,
) -> Result<(StatusCode, Json<CreateKeyResponse>), (StatusCode, String)> {
    let claims = claims_from_auth(&headers).await?;
    // IDENTITY_TEAM_SPEC §1: viewers cannot mint keys. Members + owners may
    // (API-key / dev auth is grandfathered). Gateway is the authoritative gate.
    if !claims.can_mint_keys() {
        return Err((
            StatusCode::FORBIDDEN,
            crate::auth::role_forbidden_json("member"),
        ));
    }
    let tenant = claims.tenant_id;
    tracing::Span::current().record("tenant_id", tenant.to_string());

    let name = body.name.trim();
    if name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "name must not be empty".into()));
    }
    if name.chars().count() > MAX_KEY_NAME_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("name must be at most {MAX_KEY_NAME_LEN} characters"),
        ));
    }

    // Record the minting user (WorkOS `sub`) so §3 member-removal can revoke
    // exactly this user's keys. API-key / dev auth has an `apikey:`/`dev-stub`
    // sub — harmless to store; it just won't match a WorkOS user_id on removal.
    let minted_by = claims.sub.clone();
    let minted = state
        .minter
        .mint(&tenant, name, Some(&minted_by))
        .await
        .map_err(|err| {
            // The error chain can reference internal state (pool, pepper); log it,
            // return a terse message. Never surface the raw key or key material.
            tracing::error!(error = %err, "API key mint failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to create API key".into(),
            )
        })?;

    Ok((
        StatusCode::CREATED,
        Json(CreateKeyResponse {
            id: minted.api_key.id.to_string(),
            name: minted.api_key.name,
            key_prefix: minted.key_prefix,
            last_used_at: None,
            created_at: minted.api_key.created_at.to_rfc3339(),
            raw_key: minted.raw_key,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::api_keys::ApiKey;
    use chrono::{DateTime, Utc};
    use std::sync::Mutex;
    use uuid::Uuid;

    const DEV_TENANT: &str = "00000000-0000-0000-0000-000000000001";

    /// Records the tenant it was asked to mint for so tests can prove the
    /// handler passes `Claims.tenant_id` (never a body/header value).
    struct MockKeyMinter {
        seen: Arc<Mutex<Vec<String>>>,
    }
    #[async_trait::async_trait]
    impl KeyMinter for MockKeyMinter {
        async fn mint(
            &self,
            tenant: &TenantId,
            name: &str,
            _minted_by: Option<&str>,
        ) -> Result<MintedKey> {
            self.seen.lock().unwrap().push(tenant.to_string());
            Ok(MintedKey {
                api_key: ApiKey {
                    id: Uuid::nil(),
                    tenant_id: *tenant.as_uuid(),
                    name: name.to_string(),
                    created_at: DateTime::<Utc>::from_timestamp(1_778_000_000, 0).unwrap(),
                    last_used_at: None,
                    revoked_at: None,
                },
                key_prefix: "AbC012".into(),
                raw_key: "tlane_MOCKKEYBODYdonotuseinprod".into(),
            })
        }
    }

    fn mock_state() -> (KeyRoutesState, Arc<Mutex<Vec<String>>>) {
        let seen = Arc::new(Mutex::new(vec![]));
        let state = KeyRoutesState {
            minter: Arc::new(MockKeyMinter { seen: seen.clone() }),
        };
        (state, seen)
    }

    /// Replicates the trace_reads dev-auth guard: the dev-stub claims path needs
    /// `WORKOS_CLIENT_ID` unset. Restores it on drop so the suite stays hermetic.
    struct DevAuthGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        saved: Option<String>,
    }
    impl DevAuthGuard {
        fn new() -> Self {
            static LOCK: Mutex<()> = Mutex::new(());
            let _lock = LOCK.lock().unwrap_or_else(|p| p.into_inner());
            let saved = std::env::var("WORKOS_CLIENT_ID").ok();
            if saved.is_some() {
                unsafe {
                    std::env::remove_var("WORKOS_CLIENT_ID");
                }
            }
            Self { _lock, saved }
        }
    }
    impl Drop for DevAuthGuard {
        fn drop(&mut self) {
            if let Some(v) = &self.saved {
                unsafe {
                    std::env::set_var("WORKOS_CLIENT_ID", v);
                }
            }
        }
    }

    fn bearer_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer dev-token".parse().unwrap(),
        );
        h
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn mint_uses_claims_tenant_and_returns_raw_key() {
        let _g = DevAuthGuard::new();
        let (state, seen) = mock_state();
        let (status, Json(body)) = create_key_handler(
            State(state),
            bearer_headers(),
            Json(CreateKeyBody {
                name: "  prod-agent  ".into(),
            }),
        )
        .await
        .expect("mint should succeed");
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body.raw_key, "tlane_MOCKKEYBODYdonotuseinprod");
        assert_eq!(body.key_prefix, "AbC012");
        assert_eq!(body.name, "prod-agent", "name is trimmed before minting");
        assert!(body.last_used_at.is_none());
        // The tenant handed to the minter is the validated Claims tenant — never
        // a body/header value.
        assert_eq!(*seen.lock().unwrap(), vec![DEV_TENANT.to_string()]);
    }

    #[tokio::test]
    async fn mint_without_auth_is_401_and_never_mints() {
        let (state, seen) = mock_state();
        let (status, _msg) = create_key_handler(
            State(state),
            HeaderMap::new(), // no Authorization
            Json(CreateKeyBody { name: "x".into() }),
        )
        .await
        .expect_err("must reject unauthenticated");
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(
            seen.lock().unwrap().is_empty(),
            "no mint may happen on an auth failure"
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn mint_rejects_blank_name() {
        let _g = DevAuthGuard::new();
        let (state, seen) = mock_state();
        let (status, _msg) = create_key_handler(
            State(state),
            bearer_headers(),
            Json(CreateKeyBody { name: "   ".into() }),
        )
        .await
        .expect_err("blank name must be rejected");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            seen.lock().unwrap().is_empty(),
            "no mint may happen on an invalid name"
        );
    }
}

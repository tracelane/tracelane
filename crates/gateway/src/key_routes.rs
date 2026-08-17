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
        opts: crate::db::api_keys::MintOptions,
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
        opts: crate::db::api_keys::MintOptions,
    ) -> Result<MintedKey> {
        crate::db::api_keys::mint(&self.pool, tenant, name, minted_by, opts).await
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
    /// A13. Omitted ⇒ the full set, spelled out (see `db::api_keys::mint`).
    /// An UNRECOGNISED slug is a 400 here rather than a silent drop: at mint
    /// time the caller is a human choosing capabilities, and quietly ignoring
    /// what they asked for would hand back a key that does less than the UI just
    /// told them it does. (At AUTH time the same slug denies silently — there
    /// the caller is a machine presenting a credential, and the safe answer is
    /// simply "not granted".)
    #[serde(default)]
    scope: Option<Vec<String>>,
    /// RFC3339. Must be in the future.
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    budget_usd_monthly: Option<f64>,
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
    /// A13. `null` only for a pre-A13 key; every newly minted key is explicit.
    scope: Option<Vec<String>>,
    /// A13. RFC3339 UTC, `null` = never expires.
    expires_at: Option<String>,
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

    // ── A13: validate scope / expiry / budget BEFORE minting ───────────────
    // Rejected here rather than at the DB so the caller gets a 400 naming the
    // problem instead of a 500 from a constraint violation.
    let scope = match body.scope {
        None => None,
        Some(raw) => {
            if raw.is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "scope must not be empty — omit it for a full-surface key".into(),
                ));
            }
            let mut out = Vec::with_capacity(raw.len());
            for slug in &raw {
                let Some(parsed) = tracelane_shared::api_scope::Scope::from_slug(slug) else {
                    let known: Vec<&str> = tracelane_shared::api_scope::Scope::all()
                        .iter()
                        .map(|s| s.as_slug())
                        .collect();
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!(
                            "unknown scope {slug:?} — known scopes: {}",
                            known.join(", ")
                        ),
                    ));
                };
                // Normalise + de-duplicate so the stored array is canonical.
                let slug = parsed.as_slug().to_string();
                if !out.contains(&slug) {
                    out.push(slug);
                }
            }
            Some(out)
        }
    };

    let expires_at = match body.expires_at.as_deref() {
        None => None,
        Some(raw) => {
            let parsed = chrono::DateTime::parse_from_rfc3339(raw)
                .map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("expires_at must be RFC3339: {e}"),
                    )
                })?
                .with_timezone(&chrono::Utc);
            // An already-expired key would authenticate nothing — almost
            // certainly a mistake, and silently minting a dead credential is
            // worse than refusing.
            if parsed <= chrono::Utc::now() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "expires_at must be in the future".into(),
                ));
            }
            Some(parsed)
        }
    };

    if let Some(b) = body.budget_usd_monthly
        && (!b.is_finite() || b < 0.0)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "budget_usd_monthly must be a finite, non-negative number".into(),
        ));
    }

    let opts = crate::db::api_keys::MintOptions {
        scope,
        expires_at,
        budget_usd_monthly: body.budget_usd_monthly,
    }
    // An omitted scope becomes the explicit full set here, at the edge, so the
    // 201 body reports what the row actually holds.
    .with_default_scope();

    // Record the minting user (WorkOS `sub`) so §3 member-removal can revoke
    // exactly this user's keys. API-key / dev auth has an `apikey:`/`dev-stub`
    // sub — harmless to store; it just won't match a WorkOS user_id on removal.
    let minted_by = claims.sub.clone();
    let minted = state
        .minter
        .mint(&tenant, name, Some(&minted_by), opts)
        .await
        .map_err(|err| {
            // The error chain can reference internal state (pool, pepper); log it,
            // return a terse message. Never surface the raw key or key material.
            //
            // `{err:#}` — the ALTERNATE form — not `%err`. anyhow's plain Display
            // prints ONLY the outermost `.context()` string, so this line logged
            // `INSERT INTO api_keys failed` and discarded the cause. On 2026-08-14
            // that cause was `error serializing parameter 8` and recovering it
            // took four independent probes (schema replay, prepared-statement type
            // inspection, a scratch-table trigger falsification, and a standalone
            // tokio-postgres binding probe) against one line of output. `{:#}`
            // walks the chain and would have printed it first time.
            tracing::error!(error = %format!("{err:#}"), "API key mint failed");
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
            scope: minted.api_key.scope,
            expires_at: minted.api_key.expires_at.map(|t| t.to_rfc3339()),
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
        /// A13: what the handler actually passed down, so a test can assert the
        /// VALIDATED+NORMALISED scope rather than just that minting happened.
        last_opts: Arc<Mutex<Option<crate::db::api_keys::MintOptions>>>,
    }
    #[async_trait::async_trait]
    impl KeyMinter for MockKeyMinter {
        async fn mint(
            &self,
            tenant: &TenantId,
            name: &str,
            _minted_by: Option<&str>,
            opts: crate::db::api_keys::MintOptions,
        ) -> Result<MintedKey> {
            self.seen.lock().unwrap().push(tenant.to_string());
            let scope = opts.scope.clone();
            let expires_at = opts.expires_at;
            *self.last_opts.lock().unwrap() = Some(opts);
            Ok(MintedKey {
                api_key: ApiKey {
                    id: Uuid::nil(),
                    tenant_id: *tenant.as_uuid(),
                    name: name.to_string(),
                    created_at: DateTime::<Utc>::from_timestamp(1_778_000_000, 0).unwrap(),
                    last_used_at: None,
                    revoked_at: None,
                    scope,
                    expires_at,
                },
                key_prefix: "AbC012".into(),
                raw_key: "tlane_MOCKKEYBODYdonotuseinprod".into(),
            })
        }
    }

    // ── A13: scope / expiry validation at the mint edge ────────────────────

    fn body_with(
        scope: Option<Vec<String>>,
        expires_at: Option<String>,
        budget: Option<f64>,
    ) -> CreateKeyBody {
        CreateKeyBody {
            name: "k".into(),
            scope,
            expires_at,
            budget_usd_monthly: budget,
        }
    }

    /// An omitted scope must be stored as the EXPLICIT full set, not SQL NULL.
    /// NULL is reserved for keys minted before A13; if new keys kept landing as
    /// NULL, `LegacyFullSurface` would keep growing and the distinction that
    /// makes scope enforceable would erode.
    #[tokio::test]
    async fn omitted_scope_is_recorded_explicitly_not_as_null() {
        let (state, _seen) = mock_state();
        let (status, Json(body)) = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(None, None, None)),
        )
        .await
        .expect("mint should succeed");
        assert_eq!(status, StatusCode::CREATED);
        let mut got = body.scope.expect("scope must not be null on a new key");
        got.sort();
        // HAND-MAINTAINED ON PURPOSE — do NOT derive this from `Scope::all()` or
        // from `Scope::default_mint_set()`. Deriving it from the same source the
        // handler reads would make the assertion circular: it would pass for any
        // vocabulary, including a wrong one. This literal is the independent pin,
        // and adding a scope is meant to land here as a red test so a human
        // decides whether "omitted" should really include the new capability.
        //
        // GWY-41 added `ingest`, and it should: a key minted with no scope is the
        // one a customer pastes into an app that both calls models and reports its
        // traces.
        //
        // **`admin` was here and was REMOVED (founder ruling, 2026-08-14).** The
        // literal above read `["admin", "chat", "ingest", "read"]` and this test
        // was GREEN the whole time — it pinned the defect rather than catching it,
        // because the pin was written to match the code instead of to state the
        // intent. That is the lesson worth more than the fix: an independent pin
        // is only independent if it encodes a DECISION.
        assert_eq!(got, vec!["chat", "ingest", "read"]);
    }

    /// The security half of the rule above, asserted as its own property so it
    /// cannot be weakened by a future edit to the vocabulary list.
    ///
    /// **An omitted scope must NEVER grant `admin`.** `admin` is
    /// *"manage the workspace — mint/revoke keys, provider keys, settings"*, so a
    /// silent grant is the exact escalation `is_verified_owner()` was added to
    /// enforced at the gateway rather than in the dashboard dialog on purpose:
    /// the dialog is not the only caller, and it was in fact the caller that
    /// shipped WITHOUT a scope field at all.
    #[tokio::test]
    async fn omitted_scope_never_includes_admin() {
        let (state, _seen) = mock_state();
        let (_status, Json(body)) = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(None, None, None)),
        )
        .await
        .expect("mint should succeed");
        let got = body.scope.expect("scope must not be null on a new key");
        assert!(
            !got.iter().any(|s| s == "admin"),
            "omitting `scope` must never grant admin — got {got:?}"
        );
    }

    /// And the other direction, so the test above cannot be satisfied by
    /// removing `admin` from the vocabulary entirely: `admin` must still be
    /// grantable when it is asked for BY NAME. Opt-in, not unavailable.
    #[tokio::test]
    async fn admin_scope_is_still_grantable_when_requested_explicitly() {
        let (state, _seen) = mock_state();
        let (status, Json(body)) = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(Some(vec!["admin".into()]), None, None)),
        )
        .await
        .expect("an explicit admin scope must still mint");
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(
            body.scope.expect("scope must not be null"),
            vec!["admin".to_string()]
        );
    }

    /// An unknown slug is a 400 naming the problem — never a silent drop that
    /// hands back a key doing less than the caller asked for.
    #[tokio::test]
    async fn unknown_scope_is_rejected_with_the_known_set() {
        let (state, _seen) = mock_state();
        let err = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(Some(vec!["superuser".into()]), None, None)),
        )
        .await
        .expect_err("an unknown scope must be refused");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(
            err.1.contains("superuser"),
            "message must name the bad slug"
        );
        assert!(err.1.contains("chat"), "message must list the known scopes");
    }

    #[tokio::test]
    async fn scope_is_normalised_and_deduplicated() {
        let (state, _seen) = mock_state();
        let (_s, Json(body)) = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(
                Some(vec!["READ".into(), " read ".into(), "chat".into()]),
                None,
                None,
            )),
        )
        .await
        .expect("mint should succeed");
        assert_eq!(
            body.scope,
            Some(vec!["read".to_string(), "chat".to_string()])
        );
    }

    /// `{}` is refused rather than stored: the DB CHECK would reject it anyway,
    /// and a 400 explaining the alternative beats a 500 from a constraint.
    #[tokio::test]
    async fn empty_scope_array_is_refused_with_guidance() {
        let (state, _seen) = mock_state();
        let err = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(Some(vec![]), None, None)),
        )
        .await
        .expect_err("an empty scope must be refused");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("omit it"), "must say how to get a full key");
    }

    /// Minting an already-dead credential is almost certainly a mistake, and
    /// silently doing it is worse than refusing.
    #[tokio::test]
    async fn past_expiry_is_refused() {
        let (state, _seen) = mock_state();
        let err = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(None, Some("2020-01-01T00:00:00Z".into()), None)),
        )
        .await
        .expect_err("a past expiry must be refused");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("future"));
    }

    #[tokio::test]
    async fn malformed_expiry_is_a_400_not_a_500() {
        let (state, _seen) = mock_state();
        let err = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(None, Some("next tuesday".into()), None)),
        )
        .await
        .expect_err("a malformed expiry must be refused");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("RFC3339"));
    }

    #[tokio::test]
    async fn negative_and_nonfinite_budgets_are_refused() {
        for bad in [-1.0_f64, f64::NAN, f64::INFINITY] {
            let (state, _seen) = mock_state();
            let err = create_key_handler(
                State(state),
                bearer_headers(),
                Json(body_with(None, None, Some(bad))),
            )
            .await
            .expect_err("a bad budget must be refused");
            assert_eq!(err.0, StatusCode::BAD_REQUEST, "budget {bad} must 400");
        }
    }

    fn mock_state() -> (KeyRoutesState, Arc<Mutex<Vec<String>>>) {
        let seen = Arc::new(Mutex::new(vec![]));
        let state = KeyRoutesState {
            minter: Arc::new(MockKeyMinter {
                seen: seen.clone(),
                last_opts: Arc::new(Mutex::new(None)),
            }),
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
                scope: None,
                expires_at: None,
                budget_usd_monthly: None,
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
            Json(CreateKeyBody {
                name: "x".into(),
                scope: None,
                expires_at: None,
                budget_usd_monthly: None,
            }),
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
            Json(CreateKeyBody {
                name: "   ".into(),
                scope: None,
                expires_at: None,
                budget_usd_monthly: None,
            }),
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

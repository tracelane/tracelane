//! Public audit-pubkey endpoint (ADR-062 Amendment 1 — the C2 trust channel).
//!
//! `GET /v1/audit/pubkey?tenant_id=<uuid>`
//!
//! Returns a tenant's audit signing public key(s) so an offline verifier or a
//! third-party auditor can obtain the TRUSTED `--tenant-pubkey` from Tracelane's
//! TLS-authenticated domain (the TLS certificate IS the trust channel), rather
//! than trusting the pubkey embedded in the export — which the verifier treats as
//! reference-only and fails closed on mismatch.
//!
//! **Public by design (rider 3).** A public key is public: there is no secret
//! here and no existence oracle beyond the already-opaque tenant UUID (v4, not
//! enumerable). No auth, so an auditor holding only the export + the tenant id can
//! fetch ground truth. Workspace requests use the canonical TCP-peer/trusted-proxy
//! source contract, bounded per-source buckets and a separate global store-work
//! budget. Confirmed misses alone enter a size/TTL-bounded negative cache; policy
//! lives in `translation_policy.v1.json` (`audit_pubkey`). Platform-key/OpenAPI
//! retain their own shared in-memory rate budget and never consume store tokens.

mod abuse;

use axum::{
    Json, Router,
    extract::{Query, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth::workos_webhook::WebhookRateLimiter;
use crate::rate_limiter::RateLimitDecision;

/// Existing in-memory platform-key/OpenAPI budget. Workspace store limits live
/// separately in the reference policy.
const DEFAULT_PUBKEY_RATE_PER_MIN: u32 = 600;

#[derive(Clone)]
pub struct PubkeyState {
    /// In-memory platform-key/OpenAPI budget, isolated from workspace lookups.
    pub rate: Arc<WebhookRateLimiter>,
    /// AUD-29: the PLATFORM key's public half (base64 raw 32 bytes), derived and
    /// self-checked at boot by `audit::platform_pubkey_b64`. `None` = no global
    /// signing key configured (or it failed the self-check) → the route says so.
    pub platform_pubkey_b64: Option<Arc<str>>,
    store: Arc<dyn PubkeyStore>,
    abuse: Option<Arc<abuse::Abuse>>,
}

impl PubkeyState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            rate: Arc::new(WebhookRateLimiter::new(DEFAULT_PUBKEY_RATE_PER_MIN)),
            platform_pubkey_b64: None,
            store: Arc::new(PostgresStore(crate::db::global_pool().cloned())),
            abuse: abuse::Policy::shipped()
                .map(abuse::Abuse::new)
                .map(Arc::new),
        }
    }

    /// AUD-29: attach the platform key's verified public half.
    #[must_use]
    pub fn with_platform_pubkey(mut self, b64: Option<String>) -> Self {
        self.platform_pubkey_b64 = b64.map(Arc::from);
        self
    }
}

impl Default for PubkeyState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Deserialize)]
pub struct PubkeyQuery {
    tenant_id: String,
}

#[derive(Debug, Serialize)]
struct PubkeyResponse {
    tenant_id: String,
    /// base64 raw 32-byte Ed25519 audit signing pubkey — the value to pass to the
    /// offline verifier as `--tenant-pubkey`.
    ed25519_pubkey_b64: String,
    /// SHA-256(pubkey) hex — the human-comparable fingerprint shown on
    /// `/settings/audit` for the "does this match your verifier key?" check.
    ed25519_fingerprint_sha256: String,
    /// base64 DER SPKI ECDSA-P256 anchor pubkey (empty until the first anchor).
    anchor_ecdsa_spki_b64: String,
    /// SHA-256(spki) hex, or empty when no anchor key yet.
    anchor_ecdsa_fingerprint_sha256: String,
    /// AUD-29 — the first ledger `seq` this workspace key signed (the smallest
    /// `batch_start_seq` of a canonical anchor record carrying it), or `null` when it
    /// has signed nothing yet. Verifiers treat any PLATFORM-signed batch reaching this
    /// seq as `platform_key_after_workspace_key`, even in an export window that holds
    /// no workspace-signed batch — the append a platform-key holder would need.
    workspace_key_since_seq: Option<i64>,
}

/// Mount `GET /v1/audit/pubkey`.
pub fn routes() -> Router<PubkeyState> {
    Router::new()
        .route("/v1/audit/pubkey", get(handler))
        .route("/v1/audit/platform-pubkey", get(platform_handler))
        .route("/v1/openapi.json", get(openapi_handler))
}

/// AUD-29 — `GET /v1/audit/platform-pubkey`: Tracelane's shared PLATFORM Ed25519
/// key, the second trust root. It signs a workspace's batches until the workspace
/// has its own key; the verifiers accept it only as a PREFIX of a workspace's
/// ledger and label those batches platform-signed. Public (a public key is
/// public), the same global rate limit, cacheable — it changes only with a key
/// rotation, and the verifiers also pin it per release.
async fn platform_handler(State(state): State<PubkeyState>) -> Response {
    if let RateLimitDecision::Throttle { retry_after_secs } = state.rate.check() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", retry_after_secs.to_string())],
            Json(serde_json::json!({ "error": "rate_limited" })),
        )
            .into_response();
    }
    let Some(b64) = state.platform_pubkey_b64.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "no_platform_key" })),
        )
            .into_response();
    };
    (
        [("cache-control", "public, max-age=3600")],
        Json(serde_json::json!({
            "ed25519_pubkey_b64": b64,
            "fingerprint_sha256": fingerprint_of_b64(b64),
        })),
    )
        .into_response()
}

/// # Errors
/// Fail-CLOSED: invalid input is 400, exhausted limits are 429, and unavailable
/// trust data is 5xx. Only confirmed absence is 404. No stale trust fallback.
async fn handler(
    State(state): State<PubkeyState>,
    Query(q): Query<PubkeyQuery>,
    request: Request,
) -> Response {
    let mut response = workspace_lookup(&state, q, request).await;
    // Never allow intermediary negative caching to outlive our bounded TTL.
    response.headers_mut().insert(
        "cache-control",
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

/// # Errors
/// Fail-CLOSED on bounds, checkout/SQL failures and timeout. Error/cancellation
/// cannot create cached absence. A full cache evicts an entry; the next read is
/// still gated. Slots bound admitted lookup futures; the global rate also bounds
/// attempts when a dropped Postgres future's server-side query is still finishing.
async fn workspace_lookup(state: &PubkeyState, q: PubkeyQuery, request: Request) -> Response {
    // The tenant id is untrusted input → parse to a real UUID and bind as UUID
    // (never string-concatenate into SQL). Reject before source admission so
    // malformed input cannot allocate or refresh per-source state.
    let tenant_uuid = match uuid::Uuid::parse_str(q.tenant_id.trim()) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid tenant_id" })),
            )
                .into_response();
        }
    };

    let Some(abuse) = &state.abuse else {
        return unavailable(StatusCode::SERVICE_UNAVAILABLE);
    };
    let policy = crate::providers::translation_policy::auth_throttle_policy();
    let source = crate::preauth_limiter::peer_of(request.extensions())
        .map_or(crate::preauth_limiter::SourceKey::UNKNOWN, |peer| {
            crate::preauth_limiter::source_of(request.headers(), Some(peer), policy)
        });
    let started = abuse.now();
    if let Err(retry_after) = abuse.source(source, started) {
        return throttled(retry_after);
    }

    if abuse.missing(tenant_uuid, started) {
        return missing();
    }
    // Non-queuing: there is no unbounded waiter or per-UUID lock map.
    let Ok(_slot) = abuse.slots.try_acquire() else {
        return throttled(1);
    };
    if let RateLimitDecision::Throttle { retry_after_secs } = abuse.store_rate.check() {
        return throttled(retry_after_secs);
    }
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(abuse.policy.lookup_timeout_ms),
        state.store.lookup(tenant_uuid),
    )
    .await;
    let (ed25519_pubkey_b64, anchor_ecdsa_spki_b64, workspace_key_since_seq) = match result {
        Ok(Ok(Some(key))) => key,
        Ok(Ok(None)) => {
            abuse.confirm_missing(tenant_uuid, started);
            return missing();
        }
        Ok(Err(status)) => return unavailable(status),
        Err(_) => return unavailable(StatusCode::SERVICE_UNAVAILABLE),
    };
    let ed25519_fingerprint_sha256 = fingerprint_of_b64(&ed25519_pubkey_b64);
    let anchor_ecdsa_fingerprint_sha256 = if anchor_ecdsa_spki_b64.is_empty() {
        String::new()
    } else {
        fingerprint_of_b64(&anchor_ecdsa_spki_b64)
    };

    Json(PubkeyResponse {
        tenant_id: tenant_uuid.to_string(),
        ed25519_pubkey_b64,
        ed25519_fingerprint_sha256,
        anchor_ecdsa_spki_b64,
        anchor_ecdsa_fingerprint_sha256,
        workspace_key_since_seq,
    })
    .into_response()
}

type StoredKey = (String, String, Option<i64>);

#[async_trait::async_trait]
trait PubkeyStore: Send + Sync {
    /// # Errors
    /// Fail-CLOSED: a failed key or takeover read is an error, never absence.
    async fn lookup(&self, tenant: uuid::Uuid) -> Result<Option<StoredKey>, StatusCode>;
}

struct PostgresStore(Option<crate::db::DbPool>);

#[async_trait::async_trait]
impl PubkeyStore for PostgresStore {
    async fn lookup(&self, tenant: uuid::Uuid) -> Result<Option<StoredKey>, StatusCode> {
        let pool = self.0.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let client = pool.get().await.map_err(|err| {
            tracing::warn!(error = %err, "audit pubkey: pg connection failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        let row = client
            .query_opt(
                "SELECT public_key_b64, COALESCE(anchor_pubkey_spki_b64, '') \
             FROM tenant_audit_keys WHERE tenant_id = $1",
                &[&tenant],
            )
            .await
            .map_err(|err| {
                tracing::warn!(error = %err, "audit pubkey lookup failed");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        let Some(row) = row else {
            return Ok(None);
        };
        let key: String = row
            .try_get(0)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let anchor: String = row
            .try_get(1)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let since: Option<i64> = client
            .query_one(
                "SELECT MIN(batch_start_seq) FROM audit_anchor_records \
             WHERE tenant_id = $1 AND ed25519_pubkey = $2",
                &[&tenant, &key],
            )
            .await
            .map_err(|err| {
                tracing::warn!(error = %err, "audit pubkey: workspace-key since-seq lookup failed");
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .try_get(0)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(Some((key, anchor, since)))
    }
}

fn throttled(retry_after: u32) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [("retry-after", retry_after.to_string())],
        Json(serde_json::json!({ "error": "rate_limited" })),
    )
        .into_response()
}

fn unavailable(status: StatusCode) -> Response {
    let error = if status == StatusCode::INTERNAL_SERVER_ERROR {
        "internal"
    } else {
        "unavailable"
    };
    (status, Json(serde_json::json!({ "error": error }))).into_response()
}

fn missing() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "no audit key for tenant" })),
    )
        .into_response()
}

/// SHA-256 hex fingerprint of the bytes a base64 string decodes to. Empty on a
/// malformed base64 (never panics on stored data).
fn fingerprint_of_b64(b64: &str) -> String {
    match B64.decode(b64) {
        Ok(bytes) => {
            let d = ring::digest::digest(&ring::digest::SHA256, &bytes);
            let mut out = String::with_capacity(64);
            for b in d.as_ref() {
                use std::fmt::Write as _;
                let _ = write!(out, "{b:02x}");
            }
            out
        }
        Err(_) => String::new(),
    }
}

/// OG-60 — `GET /v1/openapi.json`: the control API's OpenAPI description. Mounted here so it
/// shares the platform-key route's public posture and in-memory rate bucket (a route
/// of route shapes holds no tenant data); the body and its throttle live in `openapi_route`.
async fn openapi_handler(State(state): State<PubkeyState>) -> Response {
    crate::openapi_route::respond(&state.rate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_sha256_hex_of_decoded_bytes() {
        // SHA-256("") = e3b0c442... — decode of "" is empty bytes.
        assert_eq!(
            fingerprint_of_b64(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // A known 32-byte all-zero key.
        let zeros = B64.encode([0u8; 32]);
        let fp = fingerprint_of_b64(&zeros);
        assert_eq!(fp.len(), 64, "SHA-256 hex is 64 chars");
        // Deterministic.
        assert_eq!(fp, fingerprint_of_b64(&zeros));
    }

    #[tokio::test]
    async fn platform_route_serves_the_configured_key_and_refuses_when_absent() {
        use axum::body::Body;
        use tower::ServiceExt as _;
        let req = || {
            axum::http::Request::builder()
                .uri("/v1/audit/platform-pubkey")
                .body(Body::empty())
                .expect("request")
        };
        let key = B64.encode([7u8; 32]);
        let app = routes().with_state(PubkeyState::new().with_platform_pubkey(Some(key.clone())));
        let res = app.oneshot(req()).await.expect("response");
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), 4096)
            .await
            .expect("body");
        let v: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(v["ed25519_pubkey_b64"], key);
        assert_eq!(v["fingerprint_sha256"], fingerprint_of_b64(&key));

        let app = routes().with_state(PubkeyState::new());
        let res = app.oneshot(req()).await.expect("response");
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn fingerprint_of_malformed_b64_is_empty_not_panic() {
        assert_eq!(fingerprint_of_b64("!!!not base64!!!"), "");
    }
}

#[cfg(test)]
#[path = "audit_pubkey/tests.rs"]
mod abuse_tests;

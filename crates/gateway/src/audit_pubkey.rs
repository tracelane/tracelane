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
//! fetch ground truth. **Rate-limited** (a process-global token bucket) as DoS
//! defense-in-depth — the same no-unspoofable-peer-IP constraint as the WorkOS
//! webhook cap (axum::serve without connect-info), so a global bucket is the right
//! shape.

use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth::workos_webhook::WebhookRateLimiter;
use crate::rate_limiter::RateLimitDecision;

/// Default budget: 600 lookups/min globally (10/s) — generous for occasional
/// auditor fetches, tight enough to bound abuse of the unauthenticated GET.
const DEFAULT_PUBKEY_RATE_PER_MIN: u32 = 600;

#[derive(Clone)]
pub struct PubkeyState {
    /// Process-global token bucket (a generic limiter reused here — the endpoint
    /// has the same no-peer-IP constraint as the webhook cap).
    pub rate: Arc<WebhookRateLimiter>,
    /// AUD-29: the PLATFORM key's public half (base64 raw 32 bytes), derived and
    /// self-checked at boot by `audit::platform_pubkey_b64`. `None` = no global
    /// signing key configured (or it failed the self-check) → the route says so.
    pub platform_pubkey_b64: Option<Arc<str>>,
}

impl PubkeyState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            rate: Arc::new(WebhookRateLimiter::new(DEFAULT_PUBKEY_RATE_PER_MIN)),
            platform_pubkey_b64: None,
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

async fn handler(State(state): State<PubkeyState>, Query(q): Query<PubkeyQuery>) -> Response {
    if let RateLimitDecision::Throttle { retry_after_secs } = state.rate.check() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", retry_after_secs.to_string())],
            Json(serde_json::json!({ "error": "rate_limited" })),
        )
            .into_response();
    }

    // The tenant id is untrusted input → parse to a real UUID and bind as UUID
    // (never string-concatenate into SQL). A bad id is a 400, not a 500.
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

    let Some(pool) = crate::db::global_pool() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "unavailable" })),
        )
            .into_response();
    };
    let client = match pool.get().await {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(error = %err, "audit pubkey: pg connection failed");
            return internal();
        }
    };
    let row = match client
        .query_opt(
            "SELECT public_key_b64, COALESCE(anchor_pubkey_spki_b64, '') \
             FROM tenant_audit_keys WHERE tenant_id = $1",
            &[&tenant_uuid],
        )
        .await
    {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!(error = %err, "audit pubkey lookup failed");
            return internal();
        }
    };
    let Some(row) = row else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "no audit key for tenant" })),
        )
            .into_response();
    };

    let ed25519_pubkey_b64: String = row.get(0);
    let anchor_ecdsa_spki_b64: String = row.get(1);
    // AUD-29: from the CANONICAL anchor store (ADR-078 B). Fail-CLOSED: a failed read
    // is a 500, never a `null` that would widen the platform key's accepted range.
    let workspace_key_since_seq: Option<i64> = match client
        .query_one(
            "SELECT MIN(batch_start_seq) FROM audit_anchor_records \
             WHERE tenant_id = $1 AND ed25519_pubkey = $2",
            &[&tenant_uuid, &ed25519_pubkey_b64],
        )
        .await
    {
        Ok(r) => r.get(0),
        Err(err) => {
            tracing::warn!(error = %err, "audit pubkey: workspace-key since-seq lookup failed");
            return internal();
        }
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

fn internal() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": "internal" })),
    )
        .into_response()
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

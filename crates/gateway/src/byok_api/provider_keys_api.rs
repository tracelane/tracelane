//! `/v1/byok/provider-keys` endpoints — customer-facing BYOK management.
//!
//! A4 closes the BYOK gap on the provider hot path. This module exposes
//! the three CRUD endpoints customers need to actually upload their
//! per-provider keys:
//!
//!   - `POST   /v1/byok/provider-keys`        — upload / overwrite
//!   - `GET    /v1/byok/provider-keys`        — list (returns last4 only)
//!   - `DELETE /v1/byok/provider-keys/:provider_id` — revoke
//!
//! Hot path lookup happens in `db::provider_keys::get_decrypted`. This
//! module owns the management surface only.
//!
//! Auth: the same `validate_jwt` + tenant resolution the chat endpoint
//! uses. Tenant ID comes from the JWT claim — never from the request body.

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use crate::server::AppState;

#[derive(Debug, Deserialize)]
pub struct UploadRequest {
    pub provider_id: String,
    /// Raw API key. Wire it once — the gateway encrypts before persisting
    /// and never returns the plaintext. `secrecy::SecretString` would be
    /// nice here but axum's body extractors only handle plain `String`;
    /// we wrap immediately on receipt.
    pub plaintext: String,
}

#[derive(Debug, Serialize)]
pub struct ProviderKeySummary {
    pub provider_id: String,
    pub last4: String,
}

#[derive(Debug, Serialize)]
pub struct UploadResponse {
    pub provider_id: String,
    pub last4: String,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/byok/provider-keys", post(upload).get(list))
        .route(
            "/v1/byok/provider-keys/{provider_id}",
            axum::routing::delete(revoke),
        )
        .with_state(state)
}

async fn upload(
    headers: HeaderMap,
    State(_state): State<AppState>,
    Json(mut req): Json<UploadRequest>,
) -> impl IntoResponse {
    let tenant = match authenticate(&headers).await {
        Ok(t) => t,
        Err(e) => return e,
    };

    // before storing. A mangled key was previously stored verbatim, then
    // rejected by the upstream as a 401 — surfaced only as an opaque 502 with no
    // signal the key was wrong. Trim so the stored credential is exact; the empty
    // check below then rejects a whitespace-only paste.
    if req.plaintext.trim().len() != req.plaintext.len() {
        req.plaintext = req.plaintext.trim().to_owned();
    }

    // Validate provider_id against the known set.
    if !is_known_provider(&req.provider_id) {
        return error(StatusCode::BAD_REQUEST, "unknown provider_id");
    }
    if req.plaintext.is_empty() || req.plaintext.len() > 4_096 {
        return error(StatusCode::BAD_REQUEST, "plaintext empty or too large");
    }

    let pool = match crate::db::global_pool() {
        Some(p) => p,
        None => return error(StatusCode::SERVICE_UNAVAILABLE, "database not configured"),
    };
    let master = match crate::byok::master_key() {
        Some(m) => m,
        None => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "BYOK not configured (server missing TRACELANE_BYOK_MASTER_KEY)",
            );
        }
    };

    // B-116: provider-aware — an opaque key's tail is a fingerprint, a JSON
    // credential's tail is just its closing brace. `fingerprint_of` knows which.
    let last4 = crate::db::provider_keys::fingerprint_of(&req.provider_id, &req.plaintext);
    let secret = SecretString::from(std::mem::take(&mut req.plaintext));
    let aad = crate::byok::provider_key_aad(&tenant, &req.provider_id);
    let ciphertext = match master.encrypt_with_context(&secret, &aad) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "BYOK encrypt failed during upload");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "encrypt failed");
        }
    };

    if let Err(e) =
        crate::db::provider_keys::upsert(pool, &tenant, &req.provider_id, &ciphertext, &last4).await
    {
        tracing::error!(error = %e, "provider_keys upsert failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "persist failed");
    }
    crate::db::provider_keys::invalidate(&tenant, &req.provider_id);

    // Touch the plaintext through `expose_secret` exactly once to mute
    // the `SecretString` linter — and immediately drop it.
    let _ = secret.expose_secret().len();

    (
        StatusCode::OK,
        Json(UploadResponse {
            provider_id: req.provider_id,
            last4,
        }),
    )
        .into_response()
}

async fn list(headers: HeaderMap, State(_state): State<AppState>) -> impl IntoResponse {
    let tenant = match authenticate(&headers).await {
        Ok(t) => t,
        Err(e) => return e,
    };
    let pool = match crate::db::global_pool() {
        Some(p) => p,
        None => return Json(Vec::<ProviderKeySummary>::new()).into_response(),
    };
    let rows = match crate::db::provider_keys::list(pool, &tenant).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "provider_keys list failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "list failed");
        }
    };
    let summaries: Vec<ProviderKeySummary> = rows
        .into_iter()
        .map(|r| ProviderKeySummary {
            provider_id: r.provider_id,
            last4: r.last4,
        })
        .collect();
    Json(summaries).into_response()
}

async fn revoke(
    Path(provider_id): Path<String>,
    headers: HeaderMap,
    State(_state): State<AppState>,
) -> impl IntoResponse {
    let tenant = match authenticate(&headers).await {
        Ok(t) => t,
        Err(e) => return e,
    };
    if !is_known_provider(&provider_id) {
        return error(StatusCode::BAD_REQUEST, "unknown provider_id");
    }
    let pool = match crate::db::global_pool() {
        Some(p) => p,
        None => return error(StatusCode::SERVICE_UNAVAILABLE, "database not configured"),
    };
    if let Err(e) = crate::db::provider_keys::delete(pool, &tenant, &provider_id).await {
        tracing::error!(error = %e, "provider_keys delete failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "delete failed");
    }
    crate::db::provider_keys::invalidate(&tenant, &provider_id);
    StatusCode::NO_CONTENT.into_response()
}

fn error(status: StatusCode, msg: &str) -> axum::response::Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

async fn authenticate(
    headers: &HeaderMap,
) -> Result<tracelane_shared::TenantId, axum::response::Response> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if auth.is_empty() {
        return Err(error(StatusCode::UNAUTHORIZED, "missing bearer token"));
    }
    match crate::auth::validate_authorization(auth).await {
        Ok(claims) => {
            // IDENTITY_TEAM_SPEC §1: BYOK provider keys are owner-only (view +
            // mutate). One gate here covers upload/list/revoke.
            if !claims.can_admin() {
                return Err((
                    StatusCode::FORBIDDEN,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    crate::auth::role_forbidden_json("owner"),
                )
                    .into_response());
            }
            Ok(claims.tenant_id)
        }
        Err(err) => {
            tracing::warn!(error = %err, "byok auth failed");
            Err(error(StatusCode::UNAUTHORIZED, "invalid credentials"))
        }
    }
}

/// Allowlist of known provider IDs. The customer-supplied value is
/// validated against this so a typo or hostile body can't litter the
/// table with junk. Mirrors `ProviderRegistry::provider_id_for_model`.
fn is_known_provider(p: &str) -> bool {
    matches!(
        p,
        "anthropic"
            | "openai"
            | "google"
            | "vertex"
            | "bedrock"
            | "azure"
            | "cohere"
            | "mistral"
            | "perplexity"
            | "deepseek"
            | "xai"
            | "nvidia"
            | "cerebras"
            | "sambanova"
            | "lepton"
            | "lambda"
            | "novita"
            | "ai21"
            | "hyperbolic"
            | "deepinfra"
            | "cloudflare"
            | "ollama"
            | "baseten"
            | "huggingface"
            | "anyscale"
            | "modal"
            | "predibase"
            | "moonshot"
            | "upstage"
            | "yi"
            | "aleph-alpha"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_known_provider_accepts_known_families() {
        for p in [
            "anthropic",
            "openai",
            "google",
            "bedrock",
            "azure",
            "cohere",
            "mistral",
            "perplexity",
            "deepseek",
            "xai",
            "huggingface",
        ] {
            assert!(is_known_provider(p), "{p}");
        }
    }

    #[test]
    fn is_known_provider_rejects_garbage() {
        assert!(!is_known_provider(""));
        assert!(!is_known_provider("ANTHROPIC")); // case-sensitive — match the canonical id
        assert!(!is_known_provider("../../etc/passwd"));
        assert!(!is_known_provider("openai; DROP TABLE"));
    }
}

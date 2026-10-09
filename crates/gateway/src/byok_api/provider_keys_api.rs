//! `/v1/byok/provider-keys` endpoints — customer-facing BYOK management.
//!
//! A4 closes the BYOK gap on the provider hot path. This module exposes
//! the three CRUD endpoints customers need to actually upload their
//! per-provider keys:
//!
//!   - `POST   /v1/byok/provider-keys`        — upload / overwrite (`label`, OG-11)
//!   - `GET    /v1/byok/provider-keys`        — list (returns last4 + label only)
//!   - `DELETE /v1/byok/provider-keys/:provider_id?label=` — revoke one key (`409
//!     key_in_use_by_routing` while the routing document's key pool names it)
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
    routing::post,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use crate::server::AppState;

#[derive(Debug, Deserialize)]
pub struct UploadRequest {
    pub provider_id: String,
    /// `OG-11`: the key's name within the provider's pool. Absent = `default` — the one
    /// key every workspace had before pools, so an old client keeps working unchanged.
    #[serde(default)]
    pub label: Option<String>,
    /// Raw API key. Wire it once — the gateway encrypts before persisting
    /// and never returns the plaintext. `secrecy::SecretString` would be
    /// nice here but axum's body extractors only handle plain `String`;
    /// we wrap immediately on receipt.
    pub plaintext: String,
}

#[derive(Debug, Serialize)]
pub struct ProviderKeySummary {
    pub provider_id: String,
    /// `OG-11`: the key's pool label (`default` for the pre-pool key).
    pub label: String,
    pub last4: String,
    pub saved_at: chrono::DateTime<chrono::Utc>,
    pub last_validation: Option<crate::db::provider_keys::KeyValidation>,
    pub last_rejected_at: Option<chrono::DateTime<chrono::Utc>>,
    pub rejection_history_available: bool,
}

#[derive(Debug, Serialize)]
pub struct UploadResponse {
    pub provider_id: String,
    pub label: String,
    pub last4: String,
}

/// `?label=` on the revoke route; absent = `default` (OG-11).
#[derive(Debug, Deserialize)]
pub struct LabelQuery {
    #[serde(default)]
    pub label: Option<String>,
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

/// A credential MUTATION: the verified-owner role answer ([`authenticate_with`]),
/// then the admin-plane gate — OG-36's allowlist and SSO-required — which yields the
/// actor the store's OG-35 audit row carries.
async fn authenticate_mutate(
    headers: &HeaderMap,
) -> Result<crate::control_plane::ControlActor, axum::response::Response> {
    let claims = authenticate_with(headers, Access::Mutate).await?;
    crate::control_plane::require_control(
        &claims,
        crate::auth::capability::Capability::ManageProviderKeys,
        headers,
    )
    .await
    .map_err(IntoResponse::into_response)
}

async fn upload(
    headers: HeaderMap,
    State(_state): State<AppState>,
    Json(mut req): Json<UploadRequest>,
) -> impl IntoResponse {
    let actor = match authenticate_mutate(&headers).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    let tenant = actor.tenant_id.clone();

    // Trim copy-paste whitespace (a leading/trailing space or newline)
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
    let label = req
        .label
        .take()
        .unwrap_or_else(|| crate::db::provider_keys::DEFAULT_LABEL.to_owned());
    if !crate::db::provider_keys::valid_label(&label) {
        return error(
            StatusCode::BAD_REQUEST,
            "label must start with a letter or digit and use only letters, digits and . _ - (max 64)",
        );
    }
    if req.plaintext.is_empty() || req.plaintext.len() > 4_096 {
        return error(StatusCode::BAD_REQUEST, "plaintext empty or too large");
    }
    // SB: interior whitespace / control bytes cannot be sent in a header.
    if !crate::db::provider_keys::credential_bytes_ok(&req.plaintext) {
        return error(
            StatusCode::BAD_REQUEST,
            "plaintext contains whitespace or control characters — paste the key exactly",
        );
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

    // Provider-aware — an opaque key's tail is a fingerprint, a JSON
    // credential's tail is just its closing brace. `fingerprint_of` knows which.
    let last4 = crate::db::provider_keys::fingerprint_of(&req.provider_id, &req.plaintext);
    let secret = SecretString::from(std::mem::take(&mut req.plaintext));
    let vault = match crate::kms::KeyVault::global() {
        Ok(v) => v,
        Err(e) => return crate::kms::failure_response(e),
    };
    // H1: seal (a customer-KMS unwrap for a KMS tenant) BEFORE taking the tenant's
    // fence, then re-check under it that the configuration used is still current.
    // Round 2: no pooled connection is held across the seal's KMS await — read, release,
    // seal, re-acquire, re-check.
    let config = match pool.get().await {
        Ok(client) => match crate::kms::vault::load(&**client, &tenant, master).await {
            Ok(c) => c,
            Err(e) => return crate::kms::failure_response(e),
        },
        Err(_) => return crate::kms::failure_response(crate::kms::VaultError::Lookup),
    };
    let ciphertext = match vault
        // OG-11 + OG-37: the AAD subject carries the label (`provider` for `default`).
        .seal(
            config.as_ref(),
            &tenant,
            &crate::db::provider_keys::target_id(&req.provider_id, &label),
            &secret,
            master,
        )
        .await
    {
        Ok(c) => c,
        Err(e) => return crate::kms::failure_response(e),
    };
    let _lock = match vault.lock(&tenant).await {
        Ok(l) => l,
        Err(e) => return crate::kms::failure_response(e.into()),
    };
    let client = match pool.get().await {
        Ok(c) => c,
        Err(_) => return crate::kms::failure_response(crate::kms::VaultError::Lookup),
    };
    match crate::kms::vault::load(&**client, &tenant, master).await {
        Ok(now) if now.as_ref().map(|c| c.id) == config.as_ref().map(|c| c.id) => {}
        Ok(_) => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "kms_conflict",
                    "message": "the workspace key configuration changed while this key was being sealed — retry"
                })),
            )
                .into_response();
        }
        Err(e) => return crate::kms::failure_response(e),
    }
    drop(client);

    if let Err(e) = crate::db::provider_keys::upsert(
        pool,
        &tenant,
        &req.provider_id,
        &label,
        &ciphertext,
        &last4,
        &actor.audit,
    )
    .await
    {
        if e.is::<crate::db::provider_keys::LabelsUnavailable>() {
            return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
                "error": "key_labels_unavailable",
                "message": "Named keys are unavailable until the gateway key-label rollout is complete."
            }))).into_response();
        }
        tracing::error!(error = %e, "provider_keys upsert failed");
        return error(StatusCode::INTERNAL_SERVER_ERROR, "persist failed");
    }
    crate::db::provider_keys::invalidate(&tenant, &req.provider_id, &label);
    // OG-13: the old key's outcomes say nothing about the new one — reset THIS
    // credential's breakers (every region); other labels and tenants are untouched.
    crate::circuit_breaker::global_reset(&crate::circuit_breaker::Credential::byok(
        tenant.as_uuid(),
        &req.provider_id,
        &label,
    ));

    // Touch the plaintext through `expose_secret` exactly once to mute
    // the `SecretString` linter — and immediately drop it.
    let _ = secret.expose_secret().len();

    (
        StatusCode::OK,
        Json(UploadResponse {
            provider_id: req.provider_id,
            label,
            last4,
        }),
    )
        .into_response()
}

async fn list(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    let tenant = match authenticate_with(&headers, Access::Read).await {
        Ok(c) => c.tenant_id,
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
    let rejections = match state.quota_ch_url.as_deref() {
        Some(url) => crate::provider_key_validate::rejections(
            &crate::clickhouse_query::ch_client(url),
            &tenant,
            &rows,
            crate::clickhouse_query::tier_for_tenant(state.entitlements.as_ref(), &tenant).await,
        )
        .await
        .ok(),
        None => None,
    };
    let summaries: Vec<ProviderKeySummary> = rows
        .into_iter()
        .map(|r| {
            let last_rejected_at = rejections
                .as_ref()
                .and_then(|history| crate::provider_key_validate::last_rejected(&r, history));
            ProviderKeySummary {
                provider_id: r.provider_id,
                label: r.label,
                last4: r.last4,
                saved_at: r.saved_at,
                last_validation: r.last_validation,
                last_rejected_at,
                rejection_history_available: rejections.is_some(),
            }
        })
        .collect();
    Json(summaries).into_response()
}

async fn revoke(
    Path(provider_id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<LabelQuery>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let actor = match authenticate_mutate(&headers).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    let tenant = actor.tenant_id.clone();
    if !is_known_provider(&provider_id) {
        return error(StatusCode::BAD_REQUEST, "unknown provider_id");
    }
    let label = q
        .label
        .unwrap_or_else(|| crate::db::provider_keys::DEFAULT_LABEL.to_owned());
    if !crate::db::provider_keys::valid_label(&label) {
        return error(StatusCode::BAD_REQUEST, "invalid label");
    }
    let pool = match crate::db::global_pool() {
        Some(p) => p,
        None => return error(StatusCode::SERVICE_UNAVAILABLE, "database not configured"),
    };
    let vault = match crate::kms::KeyVault::global() {
        Ok(v) => v,
        Err(e) => return crate::kms::failure_response(e),
    };
    let _lock = match vault.lock(&tenant).await {
        Ok(l) => l,
        Err(e) => return crate::kms::failure_response(e.into()),
    };
    match crate::db::provider_keys::delete(pool, &tenant, &provider_id, &label, &actor.audit).await
    {
        Ok(crate::db::provider_keys::DeleteOutcome::InUseByRouting) => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "key_in_use_by_routing",
                    "message": "this key is named in a key pool of the workspace routing document — remove it from the pool (PUT /v1/routing) first",
                    "provider_id": provider_id,
                    "label": label,
                })),
            )
                .into_response();
        }
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "provider_keys delete failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "delete failed");
        }
    }
    crate::db::provider_keys::invalidate(&tenant, &provider_id, &label);
    // OG-13: a removed key's breaker state must not outlive it.
    crate::circuit_breaker::global_reset(&crate::circuit_breaker::Credential::byok(
        tenant.as_uuid(),
        &provider_id,
        &label,
    ));
    // The key set the entitlement-cached routing document was validated against changed.
    if let Some(cache) = state.entitlements.as_ref() {
        cache.invalidate(*tenant.as_uuid()).await;
    }
    StatusCode::NO_CONTENT.into_response()
}

fn error(status: StatusCode, msg: &str) -> axum::response::Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

/// What the caller is allowed to do on this surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    /// May read the key list (provider ids + last4 — never a credential).
    Read,
    /// May also upload and revoke.
    Mutate,
}

async fn authenticate_with(
    headers: &HeaderMap,
    need: Access,
) -> Result<crate::auth::Claims, axum::response::Response> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if auth.is_empty() {
        return Err(error(StatusCode::UNAUTHORIZED, "missing bearer token"));
    }
    match crate::auth::validate_authorization(auth).await {
        Ok(claims) => {
            // . This gate used to be `can_admin` for all three verbs.
            // `can_admin()` grandfathers `role == None` to full access, and
            // API-key auth ALWAYS has `role == None` — while `can_mint_keys()`
            // deliberately lets a MEMBER mint keys. So member → mint a key →
            // upload/revoke provider credentials composed into an escalation:
            // revoking is a denial of service on every BYOK request, and
            // replacing a key redirects upstream traffic through a credential
            // the caller controls.
            //
            // Mutation therefore requires a VERIFIED OWNER JWT
            // (`Claims::is_verified_owner` — the same predicate the guardrail
            // caps gate uses, defined once in `auth`). Reading the list stays on
            // `can_admin()`: it returns provider ids and last4 only, never a
            // credential, and an API key already belongs to the tenant.
            //
            // Consequence, stated rather than discovered: **scripted BYOK key
            // rotation with an API key no longer works** and needs an owner
            // session. That is the intended trade — a credential-management
            // surface should not be reachable by a token a member can mint for
            // themselves.
            let ok = match need {
                Access::Read => claims.can_admin(),
                Access::Mutate => claims.is_verified_owner(),
            };
            if !ok {
                return Err((
                    StatusCode::FORBIDDEN,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    crate::auth::role_forbidden_json("owner"),
                )
                    .into_response());
            }
            Ok(claims)
        }
        Err(err) => {
            tracing::warn!(error = %err, "byok auth failed");
            let (status, msg) = crate::auth::failure(&err);
            Err(error(status, msg))
        }
    }
}

/// Allowlist of known provider IDs. The customer-supplied value is validated
/// against this so a typo or hostile body cannot litter the table with junk.
///
/// GWY-42: DERIVED, not hand-maintained. This was a 35-arm `matches!` that had
/// to mirror `ProviderRegistry` by hand, and ** is what happens when it
/// does not** — Groq, Together, Fireworks and OpenRouter all routed correctly
/// and all had an env-var entry, but were missing from this list, so
/// `POST /v1/byok/provider-keys` answered "unknown provider_id" and a customer
/// could not store a key for them AT ALL. Routed ≠ usable. Deriving it from the
/// catalog removes the second list rather than re-syncing it.
///
/// The six native adapters are named explicitly because they are not catalog
/// rows; `scripts/ci/check-byok-provider-coverage.py` proves this function
/// accepts every provider the registry can route.
fn is_known_provider(p: &str) -> bool {
    matches!(
        p,
        "anthropic" | "google" | "vertex" | "bedrock" | "azure" | "cohere"
    ) || crate::providers::catalog::by_id(p).is_some()
}

/// `OG-11`: the routing writer's "is this a provider" check — the SAME allowlist a key
/// upload uses, so a pool can only name a provider a key can be stored for.
pub(crate) fn known_provider(p: &str) -> bool {
    is_known_provider(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_summary_exposes_saved_timestamp_without_ciphertext() {
        let summary = ProviderKeySummary {
            provider_id: "anthropic".into(),
            label: "default".into(),
            last4: "test".into(),
            saved_at: chrono::Utc::now(),
            last_validation: None,
            last_rejected_at: None,
            rejection_history_available: false,
        };
        let value = serde_json::to_value(summary).unwrap();
        assert!(
            value.get("saved_at").is_some(),
            "provider summary must expose saved_at"
        );
        assert!(value.get("ciphertext_b64").is_none());
    }

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

    /// These four route in `ProviderRegistry` and have an
    /// `env_var_for_provider_id` entry, but were missing from the allowlist — so
    /// a customer could not store a key for them at all. Groq was the sharpest
    /// case: fixed `llama*`/`qwen*`/`gemma*` model routing so a stored Groq
    /// key WOULD resolve, but there was no way to store one.
    /// `scripts/ci/check-byok-provider-coverage.py` enforces the full set.
    #[test]
    fn is_known_provider_accepts_the_openai_compatible_majors() {
        for p in ["groq", "together", "fireworks", "openrouter", "vertex"] {
            assert!(is_known_provider(p), "{p} routes but cannot store a key");
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

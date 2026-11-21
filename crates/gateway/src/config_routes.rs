//! `OG-61a` — `GET /v1/config/export?sections=a,b`: the workspace's control configuration as
//! one JSON document (`specs/OG-61-config-as-code.md` §10).
//!
//! | Route | Who | Audit |
//! |---|---|---|
//! | `GET /v1/config/export` | capability `manage_config` (admin, self-host operator; never an API key) AND each requested section's own read capability | — (it changes nothing) |
//!
//! Registered in `CONTROL_ROUTES` (`auth/capability.rs`); admitted through
//! `control_plane::require_control` (capability, admin IP allowlist, SSO-required, per-principal
//! bucket). Mounted only with a Postgres control plane; the tenant is `claims.tenant_id` ONLY —
//! `validate_authorization` has already bridged the identity-provider org id to the internal
//! tenant (`auth::resolve_tenant_id`), and no query or body field can name another tenant.
//!
//! **Fail-CLOSED, whole-document.** A section whose read fails turns the entire export into
//! `503 config_export_unavailable`; a document over `config.max_document_bytes`
//! (`control_policy.v1.json`) is `413 config_too_large`. There is no partial or truncated
//! document, so a file that exists is complete.

use std::collections::HashMap;

use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::json;

use crate::auth::capability::Capability;
use crate::config_sections::{self, DocumentError, Section};
use crate::db::DbPool;

/// Mounted only when a Postgres control plane exists (`server.rs`).
pub fn router(pool: DbPool) -> Router {
    Router::new()
        .route("/v1/config/export", get(export_handler))
        .with_state(pool)
}

fn error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({ "error": code, "message": message })),
    )
        .into_response()
}

/// `?sections=a,b` → the sections to export, in the order given; absent → every section.
/// An empty list, an empty item or a name this gateway does not know is `unknown_section`
/// (never silently dropped: a typo must not produce a smaller document that looks whole).
fn resolve_sections(raw: Option<&String>) -> Result<Vec<&'static Section>, String> {
    let Some(raw) = raw else {
        return Ok(config_sections::SECTIONS.iter().collect());
    };
    let mut out: Vec<&'static Section> = Vec::new();
    for name in raw.split(',') {
        let section = config_sections::find(name).ok_or_else(|| name.to_owned())?;
        if !out.iter().any(|s| s.name == section.name) {
            out.push(section);
        }
    }
    Ok(out)
}

/// `GET /v1/config/export`.
///
/// # Errors
/// Fail-CLOSED throughout: an unauthenticated or unauthorised caller gets no document; a
/// section that cannot be read, or a document past the cap, gets no document either.
#[tracing::instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn export_handler(
    State(pool): State<DbPool>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let raw = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if raw.is_empty() {
        return error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing bearer token",
        );
    }
    let claims = match crate::auth::validate_authorization(raw).await {
        Ok(c) => c,
        Err(e) => {
            let (status, message) = crate::auth::failure(&e);
            return error(status, crate::auth::failure_code(&e), message);
        }
    };
    tracing::Span::current().record("tenant_id", claims.tenant_id.to_string());
    // OG-34 capability, OG-36 allowlist + SSO-required, per-principal bucket.
    if let Err(refusal) =
        crate::control_plane::require_control(&claims, Capability::ManageConfig, &headers).await
    {
        return refusal.into_response();
    }

    let sections = match resolve_sections(query.get("sections")) {
        Ok(s) => s,
        Err(name) => {
            return error(
                StatusCode::BAD_REQUEST,
                "unknown_section",
                &format!(
                    "`{}` is not a configuration section this gateway exports",
                    name.chars().take(64).collect::<String>()
                ),
            );
        }
    };
    // The export may never show more than the section's own route does.
    for section in &sections {
        if !claims.can(section.capability) {
            return crate::control_plane::ControlRefusal::role_forbidden(section.capability)
                .into_response();
        }
    }

    let parts = match config_sections::export_sections(&pool, &claims.tenant_id, &sections).await {
        Ok(p) => p,
        Err(err) => {
            // The chain names the section and the failure. A decode error can quote a stored
            // non-secret field value; no section reads a credential column (secrets are refs).
            tracing::error!(error = %format!("{err:#}"), "configuration export failed");
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "config_export_unavailable",
                "the configuration could not be read completely — nothing was exported",
            );
        }
    };
    let max = crate::control_plane::policy().config.max_document_bytes;
    match config_sections::build_document(parts, chrono::Utc::now(), max) {
        Ok(bytes) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            bytes,
        )
            .into_response(),
        Err(DocumentError::TooLarge { bytes, max }) => {
            tracing::warn!(bytes, max, "configuration export is over the document cap");
            error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "config_too_large",
                "the configuration is larger than the export limit — export fewer sections",
            )
        }
        Err(DocumentError::Serialise) => {
            tracing::error!("configuration export could not be serialised");
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "config_export_unavailable",
                "the configuration could not be exported — try again",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_sections_param_means_every_section() {
        let all = resolve_sections(None).expect("all");
        assert_eq!(all.len(), config_sections::SECTIONS.len());
    }

    #[test]
    fn a_named_list_keeps_order_and_drops_repeats() {
        let raw = "projects,blocks,projects".to_owned();
        let got: Vec<&str> = resolve_sections(Some(&raw))
            .expect("two")
            .iter()
            .map(|s| s.name)
            .collect();
        assert_eq!(got, ["projects", "blocks"]);
    }

    #[test]
    fn an_unknown_empty_or_miscased_name_is_refused_not_skipped() {
        for raw in [
            "",
            "blocks,",
            ",blocks",
            "nope",
            "Blocks",
            "blocks, projects",
            "budgets",
        ] {
            let raw = raw.to_owned();
            assert!(
                resolve_sections(Some(&raw)).is_err(),
                "`{raw}` must be refused"
            );
        }
    }
}

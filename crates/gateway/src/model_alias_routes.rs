//! GWY-27 — `/v1/model-aliases`: the owner's control over what a model NAME means in
//! their workspace (`specs/GWY-27-model-aliases.md` §2).
//!
//! - `GET    /v1/model-aliases`                    → `{items, max, can_edit}` (admin)
//! - `PUT    /v1/model-aliases` `{alias, target_model, create?}` (verified OWNER JWT)
//! - `DELETE /v1/model-aliases?alias=<alias>`       (verified OWNER JWT)
//!
//! The alias travels in the body / query, never a path segment: an alias may contain
//! `/` (`team/fast`), and a percent-encoded slash in a path is a trap on every proxy.
//!
//! Writes are OWNER-only for the reason `byok_api::provider_keys_api` gives: an alias
//! redirects upstream traffic exactly as a provider-key swap does, and a member can mint
//! an API key for themselves. The target is validated HERE — the one process that knows
//! the routing map — before anything is stored. After a write this process's
//! entitlement cache is invalidated so the owner's next call sees it; other processes
//! see it on their refresh.

use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;
use serde_json::json;

use crate::auth::Claims;
use crate::db::model_aliases::{self as store, AliasError, PutOutcome};
use crate::providers::ProviderRegistry;
use crate::server::AppState;

/// Mounted only when a Postgres control plane exists (`server.rs`).
pub fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/v1/model-aliases",
            get(list).put(put_alias).delete(delete_alias),
        )
        // GWY-52: the workspace's own failover, under the same owner-only write rule.
        .route("/v1/gateway/failover", get(get_failover).put(put_failover))
        .with_state(state)
}

/// What a verb needs. Pure, so the role matrix is tested without a JWT issuer.
#[derive(Debug, Clone, Copy)]
enum Need {
    Read,
    Write,
}

/// The authorization decision — the ONE place it is made.
fn allowed(need: Need, claims: &Claims) -> bool {
    match need {
        Need::Read => claims.can_admin(),
        // A JWT, and an owner's: an API key never writes (a member can mint one).
        Need::Write => claims.is_verified_owner(),
    }
}

fn error(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(json!({ "error": code, "message": message }))).into_response()
}

async fn authorize(headers: &HeaderMap, need: Need) -> Result<Claims, Response> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if auth.is_empty() {
        return Err(error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing bearer token",
        ));
    }
    let claims = crate::auth::validate_authorization(auth)
        .await
        .map_err(|_| {
            error(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "invalid credential",
            )
        })?;
    if !allowed(need, &claims) {
        let role = match need {
            Need::Read => "admin",
            Need::Write => "owner",
        };
        return Err((
            StatusCode::FORBIDDEN,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            crate::auth::role_forbidden_json(role),
        )
            .into_response());
    }
    Ok(claims)
}

/// A WRITE: [`authorize`] (the role answer, unchanged), then the admin-plane gate —
/// OG-36's allowlist and SSO-required — which yields the actor the store's audit row
/// carries (OG-35).
async fn authorize_write(
    headers: &HeaderMap,
) -> Result<(Claims, crate::control_plane::ControlActor), Response> {
    let claims = authorize(headers, Need::Write).await?;
    let actor = crate::control_plane::require_control(
        &claims,
        crate::auth::capability::Capability::EditPolicies,
        headers,
    )
    .await
    .map_err(IntoResponse::into_response)?;
    Ok((claims, actor))
}

fn routable(model: &str) -> bool {
    ProviderRegistry::provider_id_for_model(model).is_some()
}

async fn list(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let claims = match authorize(&headers, Need::Read).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Some(pool) = state.pg.as_ref() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_control_plane",
            "no control plane",
        );
    };
    let aliases = match store::list(pool, &claims.tenant_id).await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, tenant_id = %claims.tenant_id, "model aliases list failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "list_failed",
                "could not read aliases",
            );
        }
    };
    // `null`, never a guessed number, when the policy row is unreadable — the UI then
    // says "limit unavailable" and disables create (spec §3).
    let max = store::read_cap(pool).await.ok().flatten();
    let items: Vec<_> = aliases
        .iter()
        .map(|(alias, target)| {
            json!({
                "alias": alias,
                "target_model": target,
                // Read-time: a target the catalog stopped routing shows as `null`,
                // and the hot path answers `400 unroutable_model` for it (fail-closed).
                "provider": ProviderRegistry::provider_id_for_model(target),
            })
        })
        .collect();
    Json(json!({ "items": items, "max": max, "can_edit": allowed(Need::Write, &claims) }))
        .into_response()
}

#[derive(Debug, Deserialize)]
struct PutBody {
    alias: String,
    target_model: String,
    /// `true` from the CREATE form: refuse an existing alias (`409`) instead of
    /// replacing it — never a silent overwrite (spec §4).
    #[serde(default)]
    create: bool,
}

async fn put_alias(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<PutBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let (claims, actor) = match authorize_write(&headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Ok(Json(body)) = body else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            "expected {alias, target_model}",
        );
    };
    let Some(pool) = state.pg.as_ref() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_control_plane",
            "no control plane",
        );
    };
    let alias = body.alias.trim();
    let target = body.target_model.trim();
    // Fail CLOSED on an unreadable cap: refusing a new alias beats guessing a limit.
    let max = match store::read_cap(pool).await {
        Ok(Some(m)) => m,
        Ok(None) | Err(_) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "alias_limit_unavailable",
                "the workspace alias limit could not be read; try again shortly",
            );
        }
    };
    let existing = match store::list(pool, &claims.tenant_id).await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, tenant_id = %claims.tenant_id, "model aliases read-before-write failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "write_failed",
                "could not save alias",
            );
        }
    };
    if let Err(e) = store::validate_write(alias, target, &existing, max, routable) {
        return refusal(&e, target);
    }
    // OG-11: an alias must not shadow one of the workspace's virtual models (the routing
    // writer refuses the converse). Read fresh — a failed read refuses (fail-CLOSED).
    match crate::db::routing::get(pool, &claims.tenant_id).await {
        Ok(row) => {
            let routing = crate::routing::RoutingState::from_stored(row.as_ref().map(|r| &r.doc));
            if crate::routing::is_virtual(&routing, alias) {
                return error(
                    StatusCode::BAD_REQUEST,
                    "alias_is_virtual_model",
                    "that name is one of your virtual models (PUT /v1/routing) — pick another alias",
                );
            }
        }
        Err(e) => {
            tracing::error!(error = %e, tenant_id = %claims.tenant_id, "routing read before alias write failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "write_failed",
                "could not save alias",
            );
        }
    }
    match store::put(
        pool,
        &claims.tenant_id,
        alias,
        target,
        &actor.audit,
        max,
        body.create,
    )
    .await
    {
        Ok(PutOutcome::Created | PutOutcome::Updated(_)) => {
            if let Some(cache) = state.entitlements.as_ref() {
                cache.invalidate(*claims.tenant_id.as_uuid()).await;
            }
            Json(json!({
                "alias": alias,
                "target_model": target,
                "provider": ProviderRegistry::provider_id_for_model(target),
            }))
            .into_response()
        }
        Ok(PutOutcome::Exists) => error(
            StatusCode::CONFLICT,
            "alias_exists",
            "an alias with that name already exists — edit it instead",
        ),
        Ok(PutOutcome::CapReached) => refusal(&AliasError::CapReached { max }, target),
        Err(e) => {
            tracing::error!(error = %e, tenant_id = %claims.tenant_id, "model alias write failed");
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "write_failed",
                "could not save alias",
            )
        }
    }
}

fn refusal(e: &AliasError, target: &str) -> Response {
    let message = match e {
        AliasError::BadAlias => {
            "alias must start with a letter or digit and use only letters, digits and . _ : / - (max 64)"
                .to_owned()
        }
        AliasError::BadTarget => "target model is required (max 256 characters)".to_owned(),
        AliasError::UnroutableTarget => {
            format!("`{target}` does not route to any provider — check the model name")
        }
        AliasError::TargetIsAlias => {
            "the target is itself an alias — point it at a model name (one hop only)".to_owned()
        }
        AliasError::SelfAlias => "an alias cannot point at itself".to_owned(),
        AliasError::CapReached { max } => {
            format!("{max} of {max} aliases — delete one to add another")
        }
    };
    error(StatusCode::BAD_REQUEST, e.code(), &message)
}

#[derive(Debug, Deserialize)]
struct DeleteQuery {
    alias: String,
}

async fn delete_alias(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<DeleteQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let (claims, actor) = match authorize_write(&headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Ok(Query(q)) = query else {
        return error(StatusCode::BAD_REQUEST, "invalid_query", "expected ?alias=");
    };
    let Some(pool) = state.pg.as_ref() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_control_plane",
            "no control plane",
        );
    };
    match store::delete(pool, &claims.tenant_id, &q.alias, &actor.audit).await {
        Ok(true) => {
            if let Some(cache) = state.entitlements.as_ref() {
                cache.invalidate(*claims.tenant_id.as_uuid()).await;
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error(StatusCode::NOT_FOUND, "not_found", "no such alias"),
        Err(e) => {
            tracing::error!(error = %e, tenant_id = %claims.tenant_id, "model alias delete failed");
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "delete_failed",
                "could not delete alias",
            )
        }
    }
}

// ── GWY-52 — `/v1/gateway/failover` ─────────────────────────────────────────────

async fn get_failover(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let claims = match authorize(&headers, Need::Read).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Some(pool) = state.pg.as_ref() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_control_plane",
            "no control plane",
        );
    };
    let settings = match crate::db::workspace_failover::get(pool, &claims.tenant_id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, tenant_id = %claims.tenant_id, "workspace failover read failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "read_failed",
                "could not read failover settings",
            );
        }
    };
    let max = crate::db::workspace_failover::read_cap(pool)
        .await
        .ok()
        .flatten();
    let models: Vec<_> = settings
        .models
        .iter()
        .map(|m| json!({ "model": m, "provider": ProviderRegistry::provider_id_for_model(m) }))
        .collect();
    Json(json!({
        "enabled": settings.enabled,
        "models": models,
        "max": max,
        "can_edit": allowed(Need::Write, &claims),
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
struct FailoverBody {
    enabled: bool,
    #[serde(default)]
    models: Vec<String>,
}

async fn put_failover(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<FailoverBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    use crate::db::workspace_failover::{self as wf, FailoverError};
    let (claims, actor) = match authorize_write(&headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Ok(Json(body)) = body else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            "expected {enabled, models}",
        );
    };
    let Some(pool) = state.pg.as_ref() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_control_plane",
            "no control plane",
        );
    };
    let models: Vec<String> = body
        .models
        .iter()
        .map(|m| m.trim().to_owned())
        .filter(|m| !m.is_empty())
        .collect();
    let max = match wf::read_cap(pool).await {
        Ok(Some(m)) => m,
        Ok(None) | Err(_) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "failover_limit_unavailable",
                "the failover model limit could not be read; try again shortly",
            );
        }
    };
    let aliases = match store::list(pool, &claims.tenant_id).await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, tenant_id = %claims.tenant_id, "alias read before failover write failed");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "write_failed",
                "could not save failover settings",
            );
        }
    };
    if let Err(e) = wf::validate(&models, &aliases, max, routable) {
        let message = match &e {
            FailoverError::Unroutable(m) => format!("`{m}` does not route to any provider"),
            FailoverError::Duplicate(m) => format!("`{m}` is listed twice"),
            FailoverError::IsAlias(m) => {
                format!("`{m}` is one of your aliases — list the real model it points at")
            }
            FailoverError::TooMany { max } => format!("at most {max} fallback models"),
        };
        return error(StatusCode::BAD_REQUEST, e.code(), &message);
    }
    let settings = wf::WorkspaceFailover {
        enabled: body.enabled,
        models,
    };
    if let Err(e) = wf::put(pool, &claims.tenant_id, &settings, &actor.audit).await {
        tracing::error!(error = %e, tenant_id = %claims.tenant_id, "workspace failover write failed");
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "write_failed",
            "could not save failover settings",
        );
    }
    if let Some(cache) = state.entitlements.as_ref() {
        cache.invalidate(*claims.tenant_id.as_uuid()).await;
    }
    Json(json!({ "enabled": settings.enabled, "models": settings.models })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthMethod, Role};

    fn claims(method: AuthMethod, role: Option<Role>) -> Claims {
        Claims {
            role,
            ..crate::auth::dev_stub_claims(method)
        }
    }

    /// Spec §7 row 3 — the guard blocks. Loosening the write gate to `can_admin()`
    /// goes RED on the self-host master key (admin, but not an owner's JWT) — the ONE
    /// credential that separates the two predicates. Without it this test passed with
    /// the gate loosened (tried 2026-09-26: it did), so it was checking nothing.
    #[test]
    fn only_a_verified_owner_jwt_may_write_and_admins_may_read() {
        let owner_jwt = claims(AuthMethod::JwtBearer, Some(Role::Owner));
        let member_jwt = claims(AuthMethod::JwtBearer, Some(Role::Member));
        let viewer_jwt = claims(AuthMethod::JwtBearer, Some(Role::Viewer));
        // An API key carries `role: None`; since PL-9b `can_admin` is false for it
        // (only the self-host master key has no role system), and a write needs a JWT
        // regardless — the escalation the provider-key rule was written against.
        let api_key = claims(AuthMethod::ApiKey, None);

        // Admin with no role system — the operator's master key. Reads, never writes:
        // the same rule the provider-key mutation gate applies (`is_verified_owner`).
        let master_key = claims(AuthMethod::SelfHostMasterKey, None);

        assert!(allowed(Need::Write, &owner_jwt));
        assert!(allowed(Need::Read, &master_key));
        assert!(
            !allowed(Need::Write, &master_key),
            "a write needs an owner's JWT, not merely admin"
        );
        assert!(
            !allowed(Need::Write, &member_jwt),
            "a member must not redirect traffic"
        );
        assert!(!allowed(Need::Write, &viewer_jwt));
        assert!(
            !allowed(Need::Write, &api_key),
            "an API key must never write an alias"
        );

        assert!(allowed(Need::Read, &owner_jwt));
        assert!(
            !allowed(Need::Read, &api_key),
            "reads follow the provider-key list rule: admin, which an API key is not"
        );
        assert!(!allowed(Need::Read, &member_jwt));
    }

    #[test]
    fn every_refusal_has_a_stable_code_and_a_400() {
        for (e, code) in [
            (AliasError::BadAlias, "invalid_alias"),
            (AliasError::BadTarget, "invalid_target"),
            (AliasError::UnroutableTarget, "unroutable_target"),
            (AliasError::TargetIsAlias, "target_is_alias"),
            (AliasError::SelfAlias, "self_alias"),
            (AliasError::CapReached { max: 50 }, "alias_cap_reached"),
        ] {
            assert_eq!(e.code(), code);
            assert_eq!(refusal(&e, "x").status(), StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn a_real_model_routes_and_a_made_up_one_does_not() {
        assert!(routable("gpt-4o-mini"));
        assert!(!routable("no-such-provider-model-xyz"));
    }
}

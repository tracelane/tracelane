//! Alerting CRUD + test-fire API (ADR-059). Every route is:
//!   1. authenticated (JWT / `tlane_` key → validated claims; tenant from claims),
//!   2. entitlement-gated on `f_alerts` (403 when dark), and
//!   3. role-gated on writes (viewer → 403; member+ may manage).
//!
//! Destinations are SSRF-validated at create time (not just at fire time), so a
//! tenant can't register a loopback/IMDS URL and have it linger.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use super::{METRICS, is_breach};
use crate::db::DbPool;
use crate::entitlement_cache::{EntitlementCache, FeatureKey};

#[derive(Clone)]
pub struct AlertRoutesState {
    pub pool: DbPool,
    pub entitlements: Arc<EntitlementCache>,
}

pub fn routes() -> Router<AlertRoutesState> {
    Router::new()
        .route(
            "/v1/alerts/rules",
            get(list_rules_handler).post(create_rule_handler),
        )
        .route(
            "/v1/alerts/rules/{id}",
            axum::routing::delete(delete_rule_handler),
        )
        .route(
            "/v1/alerts/destinations",
            get(list_dest_handler).post(create_dest_handler),
        )
        .route(
            "/v1/alerts/destinations/{id}",
            axum::routing::delete(delete_dest_handler),
        )
        .route("/v1/alerts/test", post(test_fire_handler))
}

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "error": msg }))).into_response()
}

/// Authenticate + entitlement-gate (+ optional write/role gate). Returns the
/// validated tenant UUID or a ready error `Response`.
async fn gate(
    headers: &HeaderMap,
    state: &AlertRoutesState,
    write: bool,
) -> Result<Uuid, Response> {
    let header = headers
        .get("authorization")
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "missing Authorization header"))?;
    let header_str = header
        .to_str()
        .map_err(|_| err(StatusCode::BAD_REQUEST, "Authorization must be ASCII"))?;
    let claims = crate::auth::validate_authorization(header_str)
        .await
        .map_err(|_| err(StatusCode::UNAUTHORIZED, "auth failed"))?;
    let tenant = *claims.tenant_id.as_uuid();
    if !state.entitlements.check(tenant, FeatureKey::Alerts).await {
        return Err(err(
            StatusCode::FORBIDDEN,
            "alerting is not enabled for this workspace (f_alerts)",
        ));
    }
    if write && !claims.can_mint_keys() {
        return Err(err(
            StatusCode::FORBIDDEN,
            "viewers cannot modify alerts (member role required)",
        ));
    }
    Ok(tenant)
}

// ── Rules ────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct RuleView {
    id: Uuid,
    metric: String,
    comparator: String,
    threshold: f64,
    window_minutes: i32,
    destination_id: Uuid,
    enabled: bool,
    last_state: String,
}

async fn list_rules_handler(State(state): State<AlertRoutesState>, headers: HeaderMap) -> Response {
    let tenant = match gate(&headers, &state, false).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    match super::list_rules(&state.pool, tenant).await {
        Ok(rules) => {
            let views: Vec<RuleView> = rules
                .into_iter()
                .map(|r| RuleView {
                    id: r.id,
                    metric: r.metric,
                    comparator: r.comparator,
                    threshold: r.threshold,
                    window_minutes: r.window_minutes,
                    destination_id: r.destination_id,
                    enabled: r.enabled,
                    last_state: r.last_state,
                })
                .collect();
            Json(json!({ "rules": views })).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "list alert rules failed");
            err(StatusCode::BAD_GATEWAY, "failed to list rules")
        }
    }
}

#[derive(Deserialize)]
struct CreateRuleBody {
    metric: String,
    #[serde(default)]
    comparator: Option<String>,
    threshold: f64,
    #[serde(default)]
    window_minutes: Option<i32>,
    destination_id: Uuid,
}

async fn create_rule_handler(
    State(state): State<AlertRoutesState>,
    headers: HeaderMap,
    Json(body): Json<CreateRuleBody>,
) -> Response {
    let tenant = match gate(&headers, &state, true).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    if !METRICS.contains(&body.metric.as_str()) {
        return err(StatusCode::BAD_REQUEST, "unknown metric");
    }
    let comparator = body.comparator.unwrap_or_else(|| "gt".into());
    if comparator != "gt" && comparator != "lt" {
        return err(StatusCode::BAD_REQUEST, "comparator must be gt or lt");
    }
    if !body.threshold.is_finite() {
        return err(StatusCode::BAD_REQUEST, "threshold must be finite");
    }
    let window = body.window_minutes.unwrap_or(60);
    if !(1..=44_640).contains(&window) {
        return err(
            StatusCode::BAD_REQUEST,
            "window_minutes out of range (1..43200)",
        );
    }
    // The destination must belong to this tenant (tenant-scoped read).
    match super::get_destination(&state.pool, tenant, body.destination_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return err(StatusCode::BAD_REQUEST, "destination not found"),
        Err(e) => {
            tracing::error!(error = %e, "destination lookup failed");
            return err(StatusCode::BAD_GATEWAY, "destination lookup failed");
        }
    }
    match super::create_rule(
        &state.pool,
        tenant,
        &body.metric,
        &comparator,
        body.threshold,
        window,
        body.destination_id,
    )
    .await
    {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id }))).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "create alert rule failed");
            err(StatusCode::BAD_GATEWAY, "failed to create rule")
        }
    }
}

async fn delete_rule_handler(
    State(state): State<AlertRoutesState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let tenant = match gate(&headers, &state, true).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    match super::delete_rule(&state.pool, tenant, id).await {
        Ok(0) => err(StatusCode::NOT_FOUND, "rule not found"),
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "delete alert rule failed");
            err(StatusCode::BAD_GATEWAY, "failed to delete rule")
        }
    }
}

// ── Destinations ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct DestView {
    id: Uuid,
    name: String,
    kind: String,
    url: String,
}

async fn list_dest_handler(State(state): State<AlertRoutesState>, headers: HeaderMap) -> Response {
    let tenant = match gate(&headers, &state, false).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    match super::list_destinations(&state.pool, tenant).await {
        Ok(dests) => {
            let views: Vec<DestView> = dests
                .into_iter()
                .map(|d| DestView {
                    id: d.id,
                    name: d.name,
                    kind: d.kind,
                    url: d.url,
                })
                .collect();
            Json(json!({ "destinations": views })).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "list destinations failed");
            err(StatusCode::BAD_GATEWAY, "failed to list destinations")
        }
    }
}

#[derive(Deserialize)]
struct CreateDestBody {
    name: String,
    #[serde(default)]
    kind: Option<String>,
    url: String,
}

async fn create_dest_handler(
    State(state): State<AlertRoutesState>,
    headers: HeaderMap,
    Json(body): Json<CreateDestBody>,
) -> Response {
    let tenant = match gate(&headers, &state, true).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let name = body.name.trim();
    if name.is_empty() || name.len() > 120 {
        return err(StatusCode::BAD_REQUEST, "name must be 1..120 chars");
    }
    if !body.url.starts_with("https://") || body.url.len() > 2048 {
        return err(StatusCode::BAD_REQUEST, "url must be an https:// webhook");
    }
    // SSRF-validate at create time so a loopback/IMDS URL never persists.
    if crate::ssrf_guard::validate_url(&body.url).await.is_err() {
        return err(StatusCode::BAD_REQUEST, "url rejected (SSRF guard)");
    }
    let kind = body.kind.unwrap_or_else(|| "slack".into());
    let kind = match kind.as_str() {
        "slack" | "discord" | "webhook" => kind,
        _ => "webhook".into(),
    };
    match super::create_destination(&state.pool, tenant, name, &kind, &body.url).await {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id }))).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "create destination failed");
            err(StatusCode::BAD_GATEWAY, "failed to create destination")
        }
    }
}

async fn delete_dest_handler(
    State(state): State<AlertRoutesState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let tenant = match gate(&headers, &state, true).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    match super::delete_destination(&state.pool, tenant, id).await {
        Ok(0) => err(StatusCode::NOT_FOUND, "destination not found"),
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "delete destination failed");
            err(StatusCode::BAD_GATEWAY, "failed to delete destination")
        }
    }
}

// ── Test-fire ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct TestBody {
    destination_id: Uuid,
}

async fn test_fire_handler(
    State(state): State<AlertRoutesState>,
    headers: HeaderMap,
    Json(body): Json<TestBody>,
) -> Response {
    let tenant = match gate(&headers, &state, true).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    match super::get_destination(&state.pool, tenant, body.destination_id).await {
        Ok(Some(dest)) => {
            super::fire_alert_async(
                dest.url,
                "✅ Tracelane test alert — your destination is wired correctly. \
                 (No rule breached; this was a manual test.)"
                    .to_string(),
            );
            (StatusCode::ACCEPTED, Json(json!({ "status": "sent" }))).into_response()
        }
        Ok(None) => err(StatusCode::NOT_FOUND, "destination not found"),
        Err(e) => {
            tracing::error!(error = %e, "test-fire destination lookup failed");
            err(StatusCode::BAD_GATEWAY, "test-fire failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_rule_validation_matches_the_five_metrics_and_comparators() {
        assert!(METRICS.contains(&"cost_usd"));
        assert!(!METRICS.contains(&"nonsense"));
        // is_breach is the evaluator's comparator (routes validate the same set).
        assert!(is_breach(2.0, "gt", 1.0));
        assert!(is_breach(0.5, "lt", 1.0));
    }
}

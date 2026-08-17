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

use super::{DeliveryError, METRICS, is_breach};
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

/// The payload a manual test-fire sends.
const TEST_ALERT_TEXT: &str = "✅ Tracelane test alert — your destination is wired correctly. \
     (No rule breached; this was a manual test.)";

/// Turn a delivery outcome into the tenant-visible response.
///
/// SET-N1: `202 {"status":"sent"}` is emitted **only** when the destination
/// itself answered 2xx. It used to be emitted unconditionally — the POST was
/// spawned and abandoned — so a revoked Slack webhook (`404 no_service`)
/// reported "Test alert sent successfully" forever and the user had no way to
/// learn their alerting was dead. `http_status` is the observed status, so the
/// success case is auditable and not just a label.
///
/// Failures map to `502` (the destination is an upstream we could not deliver
/// to) except an SSRF rejection, which is a `400` about the URL the tenant
/// stored. Neither collides with the `404` that means "destination not found"
/// or the `403` that means "alerts not entitled" — the dashboard proxy
/// distinguishes on exactly those two.
fn delivery_response(outcome: Result<u16, DeliveryError>) -> Response {
    match outcome {
        Ok(http_status) => (
            StatusCode::ACCEPTED,
            Json(json!({ "status": "sent", "http_status": http_status })),
        )
            .into_response(),
        Err(DeliveryError::Status { http_status, body }) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "status": "failed",
                "error": "the destination rejected the test alert",
                "http_status": http_status,
                "detail": body,
            })),
        )
            .into_response(),
        Err(DeliveryError::Unreachable(detail)) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "status": "failed",
                "error": "the destination was unreachable",
                "detail": detail,
            })),
        )
            .into_response(),
        Err(DeliveryError::Rejected(detail)) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "failed",
                "error": "url rejected (SSRF guard)",
                "detail": detail,
            })),
        )
            .into_response(),
    }
}

/// Deliver synchronously and report what actually happened. Bounded by the
/// notifier's own validate + request timeouts (3s + 5s), which sit inside the
/// dashboard proxy's 10s budget.
async fn deliver_and_respond(url: &str, text: &str) -> Response {
    delivery_response(super::deliver_alert(url, text).await)
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
        Ok(Some(dest)) => deliver_and_respond(&dest.url, TEST_ALERT_TEXT).await,
        Ok(None) => err(StatusCode::NOT_FOUND, "destination not found"),
        Err(e) => {
            tracing::error!(error = %e, "test-fire destination lookup failed");
            err(StatusCode::BAD_GATEWAY, "test-fire failed")
        }
    }
}

// `debug_assertions` is load-bearing, not decoration. These tests use
// `LoopbackBypassGuard` → `ssrf_guard::set_loopback_bypass_for_tests`, which is itself
// `#[cfg(debug_assertions)]` because a release binary must NEVER be able to switch the
// SSRF loopback guard off (.claude/rules/security.md). `cargo bench` compiles test
// targets in the BENCH profile, where `debug_assertions` is off — so a plain
// `#[cfg(test)]` here compiles a call to a function that does not exist and takes the
// whole Benchmarks job down with E0425. Same gate `providers/openai.rs:624` already uses.
#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn create_rule_validation_matches_the_five_metrics_and_comparators() {
        assert!(METRICS.contains(&"cost_usd"));
        assert!(!METRICS.contains(&"nonsense"));
        // is_breach is the evaluator's comparator (routes validate the same set).
        assert!(is_breach(2.0, "gt", 1.0));
        assert!(is_breach(0.5, "lt", 1.0));
    }

    // ── SET-N1: what the user sees after pressing "Send test" ────────────────

    struct LoopbackBypassGuard;
    impl LoopbackBypassGuard {
        fn new() -> Self {
            crate::ssrf_guard::set_loopback_bypass_for_tests(true);
            Self
        }
    }
    impl Drop for LoopbackBypassGuard {
        fn drop(&mut self) {
            crate::ssrf_guard::set_loopback_bypass_for_tests(false);
        }
    }

    async fn parts(resp: Response) -> (StatusCode, serde_json::Value) {
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        (
            status,
            serde_json::from_slice(&bytes).expect("response body is JSON"),
        )
    }

    async fn mock_webhook(status: u16, body: &str) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(status).set_body_string(body))
            .mount(&server)
            .await;
        server
    }

    /// MUST ACCEPT: a live destination yields `202 {"status":"sent"}` — the
    /// published contract — and now carries the status that proves it.
    #[tokio::test]
    async fn live_destination_reports_sent_with_the_observed_status() {
        let _bypass = LoopbackBypassGuard::new();
        let server = mock_webhook(200, "ok").await;

        let (status, body) = parts(deliver_and_respond(&server.uri(), TEST_ALERT_TEXT).await).await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body["status"], "sent");
        assert_eq!(body["http_status"], 200);
    }

    /// MUST REJECT — the end state this build exists for. A revoked Slack
    /// webhook answers `404 no_service`; the user must be told, not shown
    /// "Test alert sent successfully". `502` (not `404`) because the dashboard
    /// proxy reads a gateway `404` as "destination not found".
    #[tokio::test]
    async fn revoked_destination_reports_failure_not_sent() {
        let _bypass = LoopbackBypassGuard::new();
        let server = mock_webhook(404, "no_service").await;

        let (status, body) = parts(deliver_and_respond(&server.uri(), TEST_ALERT_TEXT).await).await;

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_ne!(body["status"], "sent", "a dead webhook must never say sent");
        assert_eq!(body["status"], "failed");
        assert_eq!(body["http_status"], 404);
        assert_eq!(body["detail"], "no_service");
    }

    /// MUST REJECT: nothing listening → an unreachable failure, still not "sent".
    #[tokio::test]
    async fn unreachable_destination_reports_failure_not_sent() {
        let _bypass = LoopbackBypassGuard::new();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);

        let url = format!("http://127.0.0.1:{port}/hook");
        let (status, body) = parts(deliver_and_respond(&url, TEST_ALERT_TEXT).await).await;

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["status"], "failed");
        assert!(body["http_status"].is_null(), "no status was observed");
    }

    /// MUST REJECT: an SSRF-blocked destination is a 400 about the stored URL,
    /// never a 202. No loopback bypass — IMDS is blocked unconditionally.
    #[tokio::test]
    async fn ssrf_blocked_destination_reports_a_url_error_not_sent() {
        let url = "http://169.254.169.254/latest/meta-data";
        let (status, body) = parts(deliver_and_respond(url, TEST_ALERT_TEXT).await).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["status"], "failed");
        assert_eq!(body["error"], "url rejected (SSRF guard)");
    }

    /// The mapping is exhaustive and no failure variant can produce "sent".
    #[tokio::test]
    async fn no_delivery_error_variant_maps_to_sent() {
        for e in [
            DeliveryError::Rejected("blocked".into()),
            DeliveryError::Unreachable("refused".into()),
            DeliveryError::Status {
                http_status: 500,
                body: "boom".into(),
            },
        ] {
            let (status, body) = parts(delivery_response(Err(e))).await;
            assert!(status.is_client_error() || status.is_server_error());
            assert_eq!(body["status"], "failed");
        }
    }
}

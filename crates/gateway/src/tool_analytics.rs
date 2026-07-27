//! Tool-analytics read surface — `GET /v1/query/tool-analytics` (Trajectory /
//! ledger #14). Aggregates the tenant's `tool.call` spans by tool name (calls,
//! errors, p95 latency) for the dashboard tool-usage card + the trajectory view.
//!
//! Read-only, tenant-scoped: `tenant_id` comes ONLY from the validated claims,
//! never a request body/header (CLAUDE.md isolation invariant). This is basic
//! observability over spans we already capture — always-on (no entitlement
//! gate); the gated *predictive* trajectory guard (`f_pr7_trajectory`,
//! `ml/trajectory_guard`) is a separate V1.5 surface.

use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};

/// Per-tool aggregate row. Positional column order matches the SELECT.
#[derive(Debug, Clone, Deserialize, Serialize, clickhouse::Row)]
pub struct ToolUsageRow {
    pub tool: String,
    pub calls: u64,
    pub errors: u64,
    pub p95_ms: f64,
}

#[derive(Clone)]
pub struct ToolAnalyticsState {
    pub ch: clickhouse::Client,
}

pub fn routes() -> Router<ToolAnalyticsState> {
    Router::new().route("/v1/query/tool-analytics", get(handler))
}

#[derive(Debug, Deserialize)]
struct ToolAnalyticsQuery {
    hours: Option<u32>,
    limit: Option<u32>,
}

/// Bind order: tenant, hours, limit. Tool identity is the ingest-normalized
/// `gen_ai.tool.name` attribute; the non-empty filter isolates real tool spans
/// (both the SDK `tool.call` shape and gateway `execute_tool` ops carry it).
const SQL: &str = "SELECT JSONExtractString(attributes, 'gen_ai.tool.name') AS tool, \
    toUInt64(count()) AS calls, \
    toUInt64(countIf(status_code = 2)) AS errors, \
    round(if(count() = 0, 0.0, quantile(0.95)(duration_us) / 1000.0), 1) AS p95_ms \
    FROM tracelane.spans FINAL \
    WHERE tenant_id = ? AND JSONExtractString(attributes, 'gen_ai.tool.name') != '' \
    AND start_time >= now() - toIntervalHour(?) \
    GROUP BY tool ORDER BY calls DESC LIMIT ?";

async fn handler(
    State(state): State<ToolAnalyticsState>,
    Query(q): Query<ToolAnalyticsQuery>,
    headers: HeaderMap,
) -> Response {
    let header = match headers.get("authorization").and_then(|h| h.to_str().ok()) {
        Some(h) => h,
        None => {
            return (StatusCode::UNAUTHORIZED, "missing Authorization header").into_response();
        }
    };
    let claims = match crate::auth::validate_authorization(header).await {
        Ok(c) => c,
        Err(_) => return (StatusCode::UNAUTHORIZED, "auth failed").into_response(),
    };
    let tenant = claims.tenant_id.to_string();
    let hours = q.hours.unwrap_or(24).clamp(1, 24 * 90);
    let limit = q.limit.unwrap_or(50).clamp(1, 200);

    match state
        .ch
        .query(SQL)
        .bind(&tenant)
        .bind(hours)
        .bind(limit)
        .fetch_all::<ToolUsageRow>()
        .await
    {
        Ok(tools) => {
            let total: u64 = tools.iter().map(|t| t.calls).sum();
            Json(serde_json::json!({
                "window_hours": hours,
                "total_calls": total,
                "tools": tools,
            }))
            .into_response()
        }
        Err(err) => {
            tracing::error!(error = %err, "tool-analytics query failed");
            (StatusCode::BAD_GATEWAY, "tool analytics read failed").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_is_tenant_first_and_bounded_by_tool_name() {
        // Tenant is the first WHERE predicate (isolation invariant).
        assert!(SQL.contains("WHERE tenant_id = ? AND JSONExtractString"));
        assert!(SQL.contains("gen_ai.tool.name"));
        assert!(SQL.contains("LIMIT ?"));
        // No cross-tenant widening — a single tenant bind, then the window + limit.
        assert_eq!(SQL.matches('?').count(), 3);
    }
}

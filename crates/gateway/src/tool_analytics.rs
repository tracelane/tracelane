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

use crate::clickhouse_query::{PlanTier, TenantQuery};

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
    /// SRE #20: the entitlement cache, so the read runs at the tenant's OWN cap tier.
    pub entitlements: Option<std::sync::Arc<crate::entitlement_cache::EntitlementCache>>,
}

pub fn routes() -> Router<ToolAnalyticsState> {
    Router::new().route("/v1/query/tool-analytics", get(handler))
}

#[derive(Debug, Deserialize)]
struct ToolAnalyticsQuery {
    hours: Option<u32>,
    limit: Option<u32>,
}

/// Bind order: tenant, hours, limit. Tool identity is the `gen_ai.tool.name` attribute
/// as written by the OTLP decoder (`crates/shared/src/otlp/decode.rs`, B-232: it maps
/// both `gen_ai.tool.name` and OpenInference's `tool.name` into the flattened attribute
/// map). Until 2026-09-05 NO ingest path wrote that key and this comment claimed the
/// gateway's `execute_tool` ops carry it — no gateway span sets it; only SDK/OTLP tool
/// spans do.
const SQL: &str = "SELECT JSONExtractString(attributes, 'gen_ai.tool.name') AS tool, \
    toUInt64(count()) AS calls, \
    toUInt64(countIf(status_code = 2)) AS errors, \
    round(if(count() = 0, 0.0, quantile(0.95)(duration_us) / 1000.0), 1) AS p95_ms \
    FROM tracelane.spans FINAL \
    WHERE tenant_id = ? AND JSONExtractString(attributes, 'gen_ai.tool.name') != '' \
    AND start_time >= now() - toIntervalHour(?) \
    GROUP BY tool ORDER BY calls DESC LIMIT ?";

/// `SQL` with the ADR-031 caps appended, at the TIGHTEST (Builder) tier: a tool-usage
/// rollup is a background dashboard read and must not out-consume the workspace's
/// interactive queries. SRE register #28 / B-225 (2026-09-04, fixed 2026-09-05): this
/// route scanned `spans FINAL` over up to 90 days with no execution-time or row ceiling.
fn capped_sql(tier: PlanTier) -> String {
    TenantQuery::new(SQL, tier).sql_with_settings()
}

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
        Err(err) => return (crate::auth::failure_status(&err), "auth failed").into_response(),
    };
    // A13 scope gate — B-230. Entitlement/role gates are NOT scope gates: until
    // 2026-08-13 this route returned tenant data to any authenticated key, so an
    // `ingest`-scoped SDK key (the credential that now lives in a customer's
    // container image, default-on since GWY-41) could read it. `read` is the scope
    // `api_scope.rs:47-49` defines for exactly this.
    if !claims.allows_scope(crate::auth::scope::Scope::Read) {
        tracing::warn!(sub = %claims.sub, "api key lacks the `read` scope");
        return (
            StatusCode::FORBIDDEN,
            "this API key is not scoped to read recorded data — it needs the `read` scope",
        )
            .into_response();
    }

    let tenant = claims.tenant_id.to_string();
    let hours = q.hours.unwrap_or(24).clamp(1, 24 * 90);
    let limit = q.limit.unwrap_or(50).clamp(1, 200);

    match state
        .ch
        .query(&capped_sql(
            crate::clickhouse_query::tier_for_tenant(
                state.entitlements.as_ref(),
                &claims.tenant_id,
            )
            .await,
        ))
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

    #[test]
    fn executed_sql_carries_builder_tier_caps() {
        let sql = capped_sql(PlanTier::Free);
        assert!(
            sql.starts_with(SQL),
            "the cap is appended, never rewrites the body"
        );
        assert!(sql.contains("max_execution_time = 10"), "{sql}");
        assert!(sql.contains("max_rows_to_read = 50000000"), "{sql}");
        // The SETTINGS block carries no placeholder, so the bind count is unchanged.
        assert_eq!(sql.matches('?').count(), 3);
    }
}

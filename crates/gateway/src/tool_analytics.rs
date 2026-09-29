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

/// Per-tool aggregate row. Positional column order matches the SELECT built
/// by `build_sql`.
///
/// `total_calls` / `group_count` are window functions
/// (`sum(calls) OVER ()` / `count() OVER ()`) — they evaluate over the FULL
/// grouped result, before `ORDER BY`/`LIMIT`, so every row carries the
/// window's TRUE total and TRUE distinct-tool count even though only
/// `limit` rows come back. B-524 / CX-25: the PREVIOUS handler summed
/// `calls` only over the LIMIT-capped `Vec<ToolUsageRow>`, so a tenant with
/// more distinct tools than the limit had its `total_calls` SILENTLY
/// under-count — a class invisible to a mocked ClickHouse client, since a
/// mock never evaluates the window function the server does.
#[derive(Debug, Clone, Deserialize, Serialize, clickhouse::Row)]
pub struct ToolUsageRow {
    pub tool: String,
    pub calls: u64,
    pub errors: u64,
    pub p95_ms: f64,
    pub total_calls: u64,
    pub group_count: u64,
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
    /// B-509 / CX-10: the web already sends `since`/`until` (RFC3339) on
    /// EVERY call, beside `hours` as a fallback (`windowParams` +
    /// `hoursOf`, `apps/web/lib/metrics/{time-range,fetch}.ts`). This route
    /// used to keep only `hours`, so a past custom interval silently
    /// rendered the most recent N hours instead. `since` present is what
    /// selects the absolute-window SQL shape below; `hours` alone is
    /// unchanged.
    since: Option<String>,
    until: Option<String>,
}

/// The widest absolute `[since, until]` width this route serves — clamped the
/// same way `trace_reads::MAX_WINDOW_SECS` clamps every other windowed route,
/// but kept as this route's OWN constant: `trace_reads`'s is module-private
/// (720h/30d) and belongs to a different, tighter family of routes. This
/// matches tool-analytics' own pre-existing `hours` clamp (`1..=24*90` below,
/// unchanged), so an absolute window can never reach further back than a
/// rolling one already could.
const MAX_WINDOW_SECS: i64 = 24 * 90 * 3600;

/// Parse an optional RFC3339 timestamp into seconds since epoch. Local copy of
/// `trace_reads::parse_rfc3339_secs` (module-private there, so not reusable
/// across the crate) — same contract: absent/blank => `Ok(None)`, malformed
/// => `Err(())`.
fn parse_rfc3339_secs(s: Option<&str>) -> Result<Option<i64>, ()> {
    match s {
        None => Ok(None),
        Some(t) if t.trim().is_empty() => Ok(None),
        Some(t) => chrono::DateTime::parse_from_rfc3339(t)
            .map(|dt| Some(dt.timestamp()))
            .map_err(|_| ()),
    }
}

/// The two SQL shapes this route serves — pure text, no bind values. Tool
/// identity is the `gen_ai.tool.name` attribute as written by the OTLP
/// decoder (`crates/shared/src/otlp/decode.rs`, B-232: it maps both
/// `gen_ai.tool.name` and OpenInference's `tool.name` into the flattened
/// attribute map). Until 2026-09-05 NO ingest path wrote that key and this
/// comment claimed the gateway's `execute_tool` ops carry it — no gateway
/// span sets it; only SDK/OTLP tool spans do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Window {
    /// No `since` — the historical rolling `hours` window
    /// (`now() - toIntervalHour(?)`).
    Rolling,
    /// `since` present — an absolute `[since_secs, until_secs]` pair,
    /// `toDateTime(?)` on both sides, NEVER `now()` (B-509 / CX-10).
    Absolute,
}

fn build_sql(window: Window) -> String {
    // B-524 / CX-25: `total_calls` / `group_count` are window functions over
    // the INNER (grouped, pre-LIMIT) result — ClickHouse (like standard SQL)
    // evaluates a window function after WHERE/GROUP BY/HAVING but before
    // ORDER BY/LIMIT, so these carry the window's true total/count no matter
    // how small `LIMIT ?` cuts the outer result.
    let mut sql = String::from(
        "SELECT tool, calls, errors, p95_ms, \
        toUInt64(sum(calls) OVER ()) AS total_calls, \
        toUInt64(count() OVER ()) AS group_count \
        FROM (SELECT JSONExtractString(attributes, 'gen_ai.tool.name') AS tool, \
        toUInt64(count()) AS calls, \
        toUInt64(countIf(status_code = 2)) AS errors, \
        round(if(count() = 0, 0.0, quantile(0.95)(duration_us) / 1000.0), 1) AS p95_ms \
        FROM tracelane.spans FINAL \
        WHERE tenant_id = ? AND JSONExtractString(attributes, 'gen_ai.tool.name') != ''",
    );
    match window {
        Window::Rolling => sql.push_str(" AND start_time >= now() - toIntervalHour(?)"),
        Window::Absolute => {
            sql.push_str(" AND start_time >= toDateTime(?) AND start_time <= toDateTime(?)");
        }
    }
    sql.push_str(" GROUP BY tool) ORDER BY calls DESC LIMIT ?");
    sql
}

/// `build_sql(window)` with the ADR-031 caps appended, at the TIGHTEST
/// (Builder) tier: a tool-usage rollup is a background dashboard read and
/// must not out-consume the workspace's interactive queries. SRE register
/// #28 / B-225 (2026-09-04, fixed 2026-09-05): this route scanned
/// `spans FINAL` over up to 90 days with no execution-time or row ceiling.
fn capped_sql(sql: &str, tier: PlanTier) -> String {
    TenantQuery::new(sql, tier).sql_with_settings()
}

/// `GET /v1/query/tool-analytics` response.
///
/// `truncated`: `tools.len() < group_count` — the LIMIT cut real distinct
/// tools out of the per-tool breakdown below (`false`/`0` when `tools` is
/// empty). `total_calls` still covers every one of them: the window
/// function that produces it runs before the LIMIT (B-524 / CX-25). Same
/// shape as `CostBreakdownResponse::truncated` (`trace_reads.rs`).
#[derive(Debug, Clone, Serialize)]
pub struct ToolAnalytics {
    pub window_hours: u32,
    pub total_calls: u64,
    pub truncated: bool,
    pub tools: Vec<ToolUsageRow>,
}

/// The already-resolved bind values for one read. Mirrors `Window`'s SQL
/// shape (`.shape()`) without a caller re-deriving hours/since/until as
/// separate params.
#[derive(Debug, Clone, Copy)]
enum WindowBind {
    Rolling { hours: u32 },
    Absolute { since_secs: i64, until_secs: i64 },
}

impl WindowBind {
    fn shape(self) -> Window {
        match self {
            WindowBind::Rolling { .. } => Window::Rolling,
            WindowBind::Absolute { .. } => Window::Absolute,
        }
    }
}

/// Fetch + shape the tool-analytics read. Extracted from the handler so a
/// real-ClickHouse test can drive it directly without an HTTP round trip —
/// the B-524/CX-25 class (an aggregate silently truncated by a `LIMIT`) is
/// invisible to a mocked client; only a server actually evaluating the
/// window function can show it (CLAUDE.md: "3 ClickHouse SQL shapes no unit
/// test sees"). Bind order matches `build_sql`: tenant, THEN either `hours`
/// (Rolling) or `since_secs, until_secs` (Absolute), THEN `limit`.
async fn read(
    ch: &clickhouse::Client,
    tier: PlanTier,
    tenant: &str,
    window: WindowBind,
    limit: u32,
) -> Result<ToolAnalytics, clickhouse::error::Error> {
    let sql = capped_sql(&build_sql(window.shape()), tier);
    let query = ch.query(&sql).bind(tenant);
    let (query, window_hours) = match window {
        WindowBind::Rolling { hours } => (query.bind(hours), hours),
        WindowBind::Absolute {
            since_secs,
            until_secs,
        } => {
            let hours = u32::try_from((until_secs - since_secs).max(0) / 3600).unwrap_or(u32::MAX);
            (query.bind(since_secs).bind(until_secs), hours)
        }
    };
    let tools: Vec<ToolUsageRow> = query.bind(limit).fetch_all().await?;
    let total_calls = tools.first().map_or(0, |t| t.total_calls);
    let group_count = tools.first().map_or(0, |t| t.group_count);
    Ok(ToolAnalytics {
        window_hours,
        total_calls,
        truncated: (tools.len() as u64) < group_count,
        tools,
    })
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

    let since_secs = match parse_rfc3339_secs(q.since.as_deref()) {
        Ok(v) => v,
        Err(()) => {
            return (StatusCode::BAD_REQUEST, "invalid since timestamp").into_response();
        }
    };
    let until_secs = match parse_rfc3339_secs(q.until.as_deref()) {
        Ok(v) => v,
        Err(()) => {
            return (StatusCode::BAD_REQUEST, "invalid until timestamp").into_response();
        }
    };

    // B-509 / CX-10: `since` present selects the absolute shape, clamped to
    // `MAX_WINDOW_SECS` by `ServedWindow::resolve` — the SAME clamp every
    // other windowed route uses (`trace_reads.rs`). `since` absent keeps the
    // rolling `hours` window byte-identical to every existing caller.
    let window = match since_secs {
        None => WindowBind::Rolling { hours },
        Some(s) => {
            let served = crate::trace_reads::ServedWindow::resolve(
                Some(s),
                until_secs,
                hours,
                chrono::Utc::now().timestamp(),
                MAX_WINDOW_SECS,
            );
            WindowBind::Absolute {
                since_secs: served.since_secs,
                until_secs: served.until_secs,
            }
        }
    };

    let tier =
        crate::clickhouse_query::tier_for_tenant(state.entitlements.as_ref(), &claims.tenant_id)
            .await;
    match read(&state.ch, tier, &tenant, window, limit).await {
        Ok(analytics) => Json(analytics).into_response(),
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
        let sql = build_sql(Window::Rolling);
        // Tenant is the first WHERE predicate (isolation invariant).
        assert!(
            sql.contains("WHERE tenant_id = ? AND JSONExtractString"),
            "{sql}"
        );
        assert!(sql.contains("gen_ai.tool.name"), "{sql}");
        assert!(sql.contains("LIMIT ?"), "{sql}");
        // No cross-tenant widening — a single tenant bind, then the window + limit.
        assert_eq!(sql.matches('?').count(), 3, "{sql}");
    }

    /// B-509 / CX-10: `since` present must bind an absolute `[since, until]`
    /// pair via `toDateTime(?)` and must NEVER fall back to `now()` — the
    /// defect this route shipped with (a past custom interval silently
    /// rendered the most recent N hours because only `hours` was read).
    #[test]
    fn an_absolute_window_binds_since_and_until_and_never_now() {
        let sql = build_sql(Window::Absolute);
        assert!(sql.contains("start_time >= toDateTime(?)"), "{sql}");
        assert!(sql.contains("start_time <= toDateTime(?)"), "{sql}");
        assert!(
            !sql.contains("now()"),
            "an absolute window must never re-derive \"now\": {sql}"
        );
        // tenant, since, until, limit — no extra placeholder for
        // total_calls/group_count (pure window functions, no bind).
        assert_eq!(sql.matches('?').count(), 4, "{sql}");
    }

    #[test]
    fn executed_sql_carries_builder_tier_caps() {
        let rolling = build_sql(Window::Rolling);
        let sql = capped_sql(&rolling, PlanTier::Free);
        assert!(
            sql.starts_with(&rolling),
            "the cap is appended, never rewrites the body"
        );
        assert!(sql.contains("max_execution_time = 10"), "{sql}");
        assert!(sql.contains("max_rows_to_read = 50000000"), "{sql}");
        // The SETTINGS block carries no placeholder, so the bind count is unchanged.
        assert_eq!(sql.matches('?').count(), 3, "{sql}");
    }
}

/// B-524 / CX-25's real behaviour: a window function evaluated by a REAL
/// server, before its own LIMIT. A mocked ClickHouse client hands back
/// whatever struct a test constructs — it never runs `sum(calls) OVER ()`
/// against a result set the LIMIT has not clipped yet, so this class of bug
/// is invisible to every unit test above.
///
/// Run: `scripts/ci/run-clickhouse-integration.sh`
#[cfg(test)]
mod clickhouse_roundtrip {
    use super::*;

    fn ch() -> Option<clickhouse::Client> {
        let url = std::env::var("CLICKHOUSE_TEST_URL").ok()?;
        Some(
            clickhouse::Client::default()
                .with_url(url)
                .with_database("tracelane"),
        )
    }

    /// The `spans` table as this route reads it. Applied from the checked-in
    /// schema, not hand-written here — a test that declares its own columns
    /// proves the code agrees with the TEST, which is the tautology this
    /// module exists to break.
    async fn ensure_spans(c: &clickhouse::Client) {
        clickhouse::Client::default()
            .with_url(std::env::var("CLICKHOUSE_TEST_URL").expect("CLICKHOUSE_TEST_URL"))
            .query("CREATE DATABASE IF NOT EXISTS tracelane")
            .execute()
            .await
            .expect("create database");
        let schema = include_str!("../../../infra/dev/clickhouse/schema.sql");
        for stmt in crate::clickhouse_query::split_migration_statements(schema) {
            let _ = c.query(&stmt).execute().await;
        }
        let exists: u64 = c
            .query("SELECT count() FROM system.tables WHERE database='tracelane' AND name='spans'")
            .fetch_one()
            .await
            .expect("system.tables read");
        assert_eq!(
            exists, 1,
            "`spans` was not created — the rest of this test would pass by querying nothing"
        );
    }

    /// 51 distinct tools (50 × 1 call + 1 × 10 calls) against `limit=50`: the
    /// true total is 60 calls across 51 tools. The OLD handler summed only
    /// the 50 rows the LIMIT returned — the one it cuts is always a 1-call
    /// tool (ORDER BY calls DESC puts the 10-call tool first), so the old
    /// code would have read back 59 and never said the breakdown was
    /// incomplete. `total_calls` must read the TRUE 60 and `truncated` must
    /// say `true`.
    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn the_total_survives_the_limit_and_says_when_it_did() {
        let Some(c) = ch() else {
            panic!("CLICKHOUSE_TEST_URL not set — this test cannot run, which is not a pass");
        };
        ensure_spans(&c).await;
        let tenant = uuid::Uuid::new_v4().to_string();

        async fn insert_tool(c: &clickhouse::Client, tenant: &str, tool: &str, calls: u32) {
            for _ in 0..calls {
                c.query(
                    "INSERT INTO tracelane.spans (tenant_id, trace_id, span_id, name, \
                     start_time, end_time, status_code, attributes) VALUES \
                     (?, ?, ?, 'tool.call', now64(6), now64(6) + toIntervalMillisecond(10), 0, ?)",
                )
                .bind(tenant)
                .bind(uuid::Uuid::new_v4().to_string())
                .bind(uuid::Uuid::new_v4().to_string())
                .bind(format!(r#"{{"gen_ai.tool.name":"{tool}"}}"#))
                .execute()
                .await
                .expect("insert tool span");
            }
        }
        for i in 0..50 {
            insert_tool(&c, &tenant, &format!("tool-{i}"), 1).await;
        }
        insert_tool(&c, &tenant, "tool-hot", 10).await;

        let analytics = read(
            &c,
            PlanTier::Enterprise,
            &tenant,
            WindowBind::Rolling { hours: 24 },
            50,
        )
        .await
        .expect("read");

        assert_eq!(
            analytics.tools.len(),
            50,
            "the LIMIT still caps the per-tool breakdown"
        );
        assert_eq!(
            analytics.total_calls, 60,
            "total_calls must be the window's TRUE sum, not Σ over the capped Vec (which would read 59)"
        );
        assert!(
            analytics.truncated,
            "51 distinct tools > limit 50 must say the breakdown is a subset"
        );
    }
}

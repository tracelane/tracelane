//! `GET /v1/billing/usage` — what the customer has used this month.
//!
//! # Why this exists (SET-07, 2026-08-11)
//!
//! `apps/web/app/api/billing/usage/route.ts:36` has always fetched
//! `${gatewayBase}/v1/billing/usage`. **The gateway never mounted it.** Only
//! `/v1/billing/checkout` and `/v1/billing/portal` exist, so every call 404'd and
//! the dashboard's `fetchMeterUsage` swallowed it (`if (!res.ok) return null`) and
//! rendered "no usage data". A dead endpoint behind a null-coalescing client is
//! invisible: nothing errors, nothing logs, the page just quietly says nothing.
//!
//! # The source, and why it is not negotiable
//!
//! The count comes from [`crate::server::TRACES_THIS_MONTH_SQL`] — **the same
//! constant the quota enforcer reads** before deciding to 429. Not a matching
//! query; the same one. Two queries that agree today drift the first time someone
//! "fixes" one of them, and the failure mode is the worst kind: a customer is cut
//! off while the billing page shows headroom, and they have a screenshot.
//!
//! The founder's ruling was explicit that the predicate must match, and matching
//! by *description* was ruled out. Sharing the definition makes the match
//! structural rather than a claim in a comment.
//!
//! **Rejected: `usage_counters` and the in-process counters.** The Postgres table
//! is written by a flusher that can lag or fail, and the in-process counters are
//! per-process and reset on deploy — neither can be the number a 429 is derived
//! from, so neither can be the number displayed next to it.
//!
//! # Fail direction: OPEN
//!
//! This is a read for a UI, not a control. A ClickHouse failure returns `null`
//! usage rather than an error, matching `quota_baseline_from_clickhouse`, which
//! seeds 0 on failure rather than blocking a paying tenant. A billing page that
//! 500s teaches people to ignore it.

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;

use crate::server::AppState;

/// Response body. Field names match what `apps/web` already destructures
/// (`tokens_processed`, `audit_anchors`) plus the trace count this adds.
#[derive(Debug, Serialize)]
pub struct UsageResponse {
    /// Traces recorded this calendar month — the figure the monthly quota bills
    /// and enforces. `null` when ClickHouse could not be read.
    pub traces_this_month: Option<u64>,
    /// The tenant's included monthly allowance, for rendering "X of Y".
    pub trace_quota_monthly: Option<i64>,
    /// Reserved: the Polar meter figures the web route already reads. Not yet
    /// wired here — declared `None` rather than omitted so the shape is stable
    /// and the client's `?? null` keeps working unchanged.
    pub tokens_processed: Option<u64>,
    pub audit_anchors: Option<u64>,
}

fn error(code: StatusCode, msg: &str) -> Response {
    (
        code,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        format!(r#"{{"error":"{msg}"}}"#),
    )
        .into_response()
}

/// Read the tenant's trace count for the current month.
///
/// # Errors
/// Never — a read failure is `None`, see the module docs on fail direction.
async fn traces_this_month(
    state: &AppState,
    tenant_id: &tracelane_shared::TenantId,
) -> Option<u64> {
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct CountRow {
        n: u64,
    }
    let url = state.quota_ch_url.clone()?;
    match crate::clickhouse_query::ch_client(url)
        .query(crate::server::TRACES_THIS_MONTH_SQL)
        .bind(tenant_id.to_string())
        .fetch_one::<CountRow>()
        .await
    {
        Ok(row) => Some(row.n),
        Err(e) => {
            tracing::warn!(
                error = %e,
                tenant_id = %tenant_id,
                "billing usage ClickHouse read failed; reporting null usage"
            );
            None
        }
    }
}

#[tracing::instrument(skip(state, headers), fields(tenant_id = tracing::field::Empty))]
async fn handler(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if auth.is_empty() {
        return error(StatusCode::UNAUTHORIZED, "missing bearer token");
    }
    // Tenant comes from the validated claim, never a query parameter — this is a
    // per-tenant billing figure and a body/query-supplied tenant would be a
    // cross-tenant read.
    let claims = match crate::auth::validate_authorization(auth).await {
        Ok(c) => c,
        Err(_) => return error(StatusCode::UNAUTHORIZED, "invalid token"),
    };
    // A13 scope gate — B-230. Entitlement/role gates are NOT scope gates: until
    // 2026-08-13 this route returned tenant data to any authenticated key, so an
    // `ingest`-scoped SDK key (the credential that now lives in a customer's
    // container image, default-on since GWY-41) could read it. `read` is the scope
    // `api_scope.rs:47-49` defines for exactly this.
    if !claims.allows_scope(crate::auth::scope::Scope::Read) {
        tracing::warn!(sub = %claims.sub, "api key lacks the `read` scope");
        return error(
            StatusCode::FORBIDDEN,
            "this API key is not scoped to read recorded data — it needs the `read` scope",
        );
    }

    let tenant_id = claims.tenant_id;
    tracing::Span::current().record("tenant_id", tenant_id.to_string());

    // No role gate: usage is a read of the caller's own workspace, and a viewer
    // seeing their own consumption is not a privilege. Contrast the WRITE paths,
    // which are owner-gated (A8).
    let traces = traces_this_month(&state, &tenant_id).await;

    let quota = match &state.entitlements {
        Some(cache) => Some(
            cache
                .resolved(*tenant_id.as_uuid())
                .await
                .trace_quota_monthly,
        ),
        None => None,
    };

    axum::Json(UsageResponse {
        traces_this_month: traces,
        trace_quota_monthly: quota,
        tokens_processed: None,
        audit_anchors: None,
    })
    .into_response()
}

pub fn routes(state: AppState) -> Router {
    Router::new()
        .route("/v1/billing/usage", get(handler))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    /// THE PROPERTY SET-07 EXISTS FOR: the number displayed and the number
    /// enforced come from ONE definition, so they cannot disagree.
    ///
    /// Asserted structurally rather than by comparing two SQL strings — two
    /// strings that match today drift the moment someone edits one, which is
    /// exactly what the founder ruled out ("do not match them by description").
    #[test]
    fn usage_reads_the_same_predicate_the_quota_enforcer_reads() {
        let sql = crate::server::TRACES_THIS_MONTH_SQL;
        assert!(
            sql.contains("trace_summaries"),
            "must count TRACES, not spans — spans over-report by the fan-out of every trace"
        );
        assert!(
            sql.contains("tenant_id = ?"),
            "tenant-scoped and parameter-bound, or it is a cross-tenant read"
        );
        assert!(
            sql.contains("toStartOfMonth(now())"),
            "the month boundary must be the SERVER's, or display and enforcement \
             reset at different instants"
        );
        // B-243: a split trace emits >1 partial row per trace_id in the MV, and
        // those rows never collapse (start_time is in the ORDER BY). `count()`
        // therefore OVER-BILLS real agent traffic. This assertion is what stops
        // the revert — the defect shipped once and read as correct.
        assert!(
            sql.contains("uniqExact(trace_id)"),
            "must count DISTINCT traces — count() over-bills a trace whose spans \
             span more than one ingest batch (B-243)"
        );
        assert!(
            !sql.contains("count()"),
            "no bare count() may remain in the billing predicate (B-243)"
        );
    }

    /// The source file must not carry a second copy of the query. A duplicated
    /// predicate is how "they agree" becomes "they agreed once".
    #[test]
    fn this_module_does_not_define_its_own_count_query() {
        let src = include_str!("usage.rs");
        // The needle is SPLIT so this assertion does not match its own source line.
        // The unsplit version failed on itself — the second self-matching check of
        // the day (the watchdog's `grep sig=.*err_gw` did the same), which is worth
        // naming: a source-scanning test must never be able to see itself.
        let needle = concat!("FROM tracelane.", "trace_summaries");
        assert!(
            !src.contains(needle),
            "usage.rs must reference server::TRACES_THIS_MONTH_SQL, never inline its own copy"
        );
    }
}

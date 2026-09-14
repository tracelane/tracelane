//! Per-key/workspace spend baselines (B-385 §2d split of `server.rs`).
//!
//! **BILL-01 / ADR-076 (2026-09-13) deleted the monthly trace-count quota
//! entirely** — `TRACES_THIS_MONTH_SQL`, the soft-cap/hard-cap notification
//! machinery (`QuotaEvent`, `notify_quota_event_async`, the tenant Slack
//! webhook POST) and `quota_baseline_from_clickhouse` are gone with it. Usage
//! is now six independent per-unit meters (`crate::billing::meters`), and
//! ADR-076 §0.4 is explicit that ingest is never blocked by billing state, so
//! there is no more "traces this month" number to seed a request-blocking
//! counter from.
//!
//! What survives: the GWY-43 per-key/workspace USD spend BUDGET (a customer's
//! own opt-in ceiling, unrelated to the six meters) and its ClickHouse
//! baselines, still consumed by `crate::admission`'s `KeyBudget` /
//! `WorkspaceBudget` steps, and `next_month_boundary_iso`, still used to render
//! `resets_at` on a budget-exceeded 402.

use tracelane_shared::TenantId;

use super::AppState;

/// Current UTC calendar month as `YYYYMM` (e.g. `202607`) — the seed key for
/// the durable monthly spend counters' month-boundary reset.
pub(crate) fn current_year_month() -> u32 {
    use chrono::Datelike as _;
    let now = chrono::Utc::now();
    now.year() as u32 * 100 + now.month()
}

/// This key's recorded spend so far this calendar month, USD.
///
/// **Tenant-first, then key** — the same predicate order every ClickHouse read
/// in this codebase uses, and the reason `tenant_id` leads the table's ORDER BY.
/// Binding the key alone would be a cross-tenant read; binding it second is the
/// isolation the schema is shaped for.
///
/// Only spans written since migration 16 carry `api_key_id`, so this total
/// begins at that cutover. Every surface that renders it must say so rather than
/// implying the history was always attributable.
pub const KEY_SPEND_THIS_MONTH_SQL: &str = "SELECT toFloat64(sum(cost_usd)) AS usd \
        FROM tracelane.spans \
        WHERE tenant_id = ? AND api_key_id = ? \
          AND cost_usd_present = 1 \
          AND start_time >= toStartOfMonth(now())";

/// BILL-01 A3 — the same query, windowed to the current UTC calendar day, for
/// a key whose `budget_reset = 'daily'`.
pub const KEY_SPEND_THIS_DAY_SQL: &str = "SELECT toFloat64(sum(cost_usd)) AS usd \
        FROM tracelane.spans \
        WHERE tenant_id = ? AND api_key_id = ? \
          AND cost_usd_present = 1 \
          AND start_time >= toStartOfDay(now())";

/// BILL-01 A3 — the same query, windowed to the current ISO week (Monday
/// 00:00 UTC), for a key whose `budget_reset = 'weekly'`.
pub const KEY_SPEND_THIS_WEEK_SQL: &str = "SELECT toFloat64(sum(cost_usd)) AS usd \
        FROM tracelane.spans \
        WHERE tenant_id = ? AND api_key_id = ? \
          AND cost_usd_present = 1 \
          AND start_time >= toMonday(now())";

/// Pick the baseline SQL for a key's budget cadence. One query either way —
/// this only chooses WHICH window it reads, never adds a second read.
const fn key_spend_sql(cadence: crate::spend::BudgetReset) -> &'static str {
    match cadence {
        crate::spend::BudgetReset::Daily => KEY_SPEND_THIS_DAY_SQL,
        crate::spend::BudgetReset::Weekly => KEY_SPEND_THIS_WEEK_SQL,
        crate::spend::BudgetReset::Monthly => KEY_SPEND_THIS_MONTH_SQL,
    }
}

/// The whole workspace's recorded spend this calendar month, USD.
///
/// Deliberately NOT filtered on `api_key_id`: a workspace ceiling covers every
/// request the tenant made, including session-authenticated ones that carry no
/// key. Filtering by key here would silently exempt dashboard-driven spend from
/// the workspace cap.
pub const WORKSPACE_SPEND_THIS_MONTH_SQL: &str = "SELECT toFloat64(sum(cost_usd)) AS usd \
        FROM tracelane.spans \
        WHERE tenant_id = ? \
          AND cost_usd_present = 1 \
          AND start_time >= toStartOfMonth(now())";

pub(crate) async fn workspace_spend_baseline_from_clickhouse(
    state: &AppState,
    tenant_id: &TenantId,
) -> f64 {
    let Some(url) = state.quota_ch_url.clone() else {
        return 0.0;
    };
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct SumRow {
        usd: f64,
    }
    // ADR-031 caps at the tenant's OWN tier (B-330's helper; B-225's last
    // hot-path reads, surfaced when B-385's split let `check-ch-reads-capped.py`
    // see this code for the first time). One warm entitlement-cache read —
    // admission just resolved the same tenant. A tenant whose monthly aggregate
    // exceeds its tier's row/time cap lands in the `Err` arm below (fail-open,
    // seed 0, logged), which is the existing posture, now bounded.
    let tier =
        crate::clickhouse_query::tier_for_tenant(state.entitlements.as_ref(), tenant_id).await;
    let sql = crate::clickhouse_query::TenantQuery::new(WORKSPACE_SPEND_THIS_MONTH_SQL, tier)
        .sql_with_settings();
    match crate::clickhouse_query::ch_client(url)
        .query(&sql)
        .bind(tenant_id.to_string())
        .fetch_one::<SumRow>()
        .await
    {
        Ok(row) if row.usd.is_finite() && row.usd > 0.0 => row.usd,
        Ok(_) => 0.0,
        Err(e) => {
            tracing::warn!(
                error = %e,
                tenant_id = %tenant_id,
                "workspace spend baseline ClickHouse read failed; seeding 0 (fail-open)"
            );
            0.0
        }
    }
}

pub(crate) async fn spend_baseline_from_clickhouse(
    state: &AppState,
    tenant_id: &TenantId,
    api_key_id: &str,
    cadence: crate::spend::BudgetReset,
) -> f64 {
    let Some(url) = state.quota_ch_url.clone() else {
        return 0.0;
    };
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct SumRow {
        usd: f64,
    }
    // ADR-031 caps at the tenant's OWN tier (B-330's helper; B-225's last
    // hot-path reads, surfaced when B-385's split let `check-ch-reads-capped.py`
    // see this code for the first time). One warm entitlement-cache read —
    // admission just resolved the same tenant. A tenant whose monthly aggregate
    // exceeds its tier's row/time cap lands in the `Err` arm below (fail-open,
    // seed 0, logged), which is the existing posture, now bounded.
    let tier =
        crate::clickhouse_query::tier_for_tenant(state.entitlements.as_ref(), tenant_id).await;
    // BILL-01 A3: same ONE query either way — `key_spend_sql` only picks which
    // window's WHERE clause it reads, keyed on the key's own `budget_reset`.
    let sql =
        crate::clickhouse_query::TenantQuery::new(key_spend_sql(cadence), tier).sql_with_settings();
    match crate::clickhouse_query::ch_client(url)
        .query(&sql)
        .bind(tenant_id.to_string())
        .bind(api_key_id)
        .fetch_one::<SumRow>()
        .await
    {
        Ok(row) if row.usd.is_finite() && row.usd > 0.0 => row.usd,
        Ok(_) => 0.0,
        Err(e) => {
            // Fail OPEN, and say so. A control-plane read failure must not stop a
            // customer's production traffic — the same choice
            // `workspace_spend_baseline_from_clickhouse` makes. The cost is that a
            // restart during a ClickHouse outage forgives that key's accrued spend
            // until the next month rolls; that is stated in `spend.rs`'s module
            // docs rather than left for an operator to discover.
            tracing::warn!(
                error = %e,
                tenant_id = %tenant_id,
                "per-key spend baseline ClickHouse read failed; seeding 0 (fail-open)"
            );
            0.0
        }
    }
}

/// Compute the first day of next month at 00:00:00 UTC as RFC3339.
///
/// This is the `resets_at` value surfaced in a budget-exceeded 402 response
/// body so customers know when their monthly counter zeroes.
pub fn next_month_boundary_iso() -> String {
    use chrono::{Datelike as _, TimeZone as _};
    let now = chrono::Utc::now();
    let (year, month) = if now.month() == 12 {
        (now.year() + 1, 1)
    } else {
        (now.year(), now.month() + 1)
    };
    match chrono::Utc
        .with_ymd_and_hms(year, month, 1, 0, 0, 0)
        .single()
    {
        Some(dt) => dt.to_rfc3339(),
        // Calendar arithmetic above is total; this branch is unreachable
        // in practice but we never want to panic on the hot path.
        None => now.to_rfc3339(),
    }
}

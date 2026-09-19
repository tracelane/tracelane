//! BILL-01 / ADR-076 — `GET /v1/billing/usage`, `GET /v1/billing/window-breakdown`,
//! `PUT /v1/billing/ceiling`, `DELETE /v1/billing/promotion-freeze`.
//!
//! **Replaces SET-07's trace-count usage route entirely** (the old
//! `TRACES_THIS_MONTH_SQL`-backed body is gone with the quota it mirrored —
//! ADR-076 supersedes ADR-020). The six meters here are BILL-01's, not a
//! trace count.
//!
//! # Sources, per meter (spec §2.1, §3)
//!
//! - **ingest** and **evals**: `sum(value)` over `meter_counters` this
//!   billing period — real data, written by `crate::billing::meters` /
//!   ingest's own OTLP-half sink / `online_eval.rs`.
//! - **hot / series / query(scan-units) / cold**: read from `meter_gauges`,
//!   now populated by the daily metering job (`billing::metering_job`, BILL-01
//!   step 6/7) once it has run at least once. A tenant whose job has not run
//!   yet (a fresh signup, or a job outage) still reports `used: null,
//!   last_computed_at: null` — the spec's own "Partial" state (§4), never a
//!   fabricated zero — which is why every aggregation below reads with
//!   `map_or_else(|| MeterView::unavailable(...), ...)` rather than assuming
//!   rows exist.
//!
//!   The aggregation across THIS PERIOD's daily gauge rows differs per meter
//!   (spec step 7): **hot** = mean(daily resident bytes) → the GB-month
//!   projection, with `used` itself reporting the LATEST day (today's
//!   resident bytes — spec §3 "resident GB today"); **series** = max(daily) —
//!   the job computes a running period-to-date count each day, so the peak IS
//!   the current total; **query (scan-units)** = Σ(daily) — each day's gauge
//!   is that day's OWN scan bytes, so the sum is the period-to-date total;
//!   **cold** = mean(daily) — a smoothed snapshot of a stock, not a flow.
//!
//! # The billing period (B-410, founder ruling 2026-09-19)
//!
//! "This period" is the tenant's OWN Polar cycle
//! (`tenants.current_period_start/end`, via `ResolvedEntitlements
//! ::billing_period`) when that governs now, else the UTC calendar month —
//! ONE rule, `crate::billing::period`, shared with the daily metering job
//! that writes the gauges, so the page cannot disagree with the job or with
//! the invoice Polar renders per cycle. The response's `period_start` /
//! `period_end` name the cycle when one governs and are `null` under the
//! calendar month (a stale cycle included: the page must not show a cycle
//! beside figures that were not rated over it). `projection_month_end` keeps
//! its wire name; it is the projection to the END OF THE RATED PERIOD.
//!
//! # Read/write amplification (spec §2.5b)
//!
//! Zero Postgres per request (entitlements + the rate card both come from
//! existing caches). Exactly TWO ClickHouse queries — one over
//! `meter_counters` GROUP BY meter, one over `meter_gauges` GROUP BY (day,
//! meter) — cached per tenant for 60s so a dashboard poll costs nothing.
//!
//! # Fail direction: OPEN
//!
//! This is a read for a UI, not a control (CLAUDE.md §10). A ClickHouse
//! failure renders `null` usage and `rates_available: false` rather than an
//! error — the recorder never stops; the page must say so (spec §4 "Error").

use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, put},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

use crate::billing::rating::{self, Band, RatedMeter};
use crate::server::AppState;

fn error(code: StatusCode, msg: &str) -> Response {
    (
        code,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        format!(r#"{{"error":"{msg}"}}"#),
    )
        .into_response()
}

/// Authenticate + `read`-scope-gate a billing GET. Tenant from the validated
/// claim only (CLAUDE.md §4) — never a query parameter, which would be a
/// cross-tenant read.
async fn read_tenant(headers: &HeaderMap) -> Result<tracelane_shared::TenantId, Response> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if auth.is_empty() {
        return Err(error(StatusCode::UNAUTHORIZED, "missing bearer token"));
    }
    let claims = crate::auth::validate_authorization(auth)
        .await
        .map_err(|e| error(crate::auth::failure_status(&e), "invalid token"))?;
    if !claims.allows_scope(crate::auth::scope::Scope::Read) {
        tracing::warn!(sub = %claims.sub, "api key lacks the `read` scope");
        return Err(error(
            StatusCode::FORBIDDEN,
            "this API key is not scoped to read recorded data — it needs the `read` scope",
        ));
    }
    Ok(claims.tenant_id)
}

/// Authenticate + `admin`-scope-gate a billing WRITE (`PUT ceiling`,
/// `DELETE promotion-freeze`). Mutating the spend ceiling or clearing a
/// velocity-breaker freeze is a workspace-configuration change, the same
/// bar `prompt_routes.rs`'s `Admin` scope sets for promotion.
async fn admin_tenant(headers: &HeaderMap) -> Result<tracelane_shared::TenantId, Response> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if auth.is_empty() {
        return Err(error(StatusCode::UNAUTHORIZED, "missing bearer token"));
    }
    let claims = crate::auth::validate_authorization(auth)
        .await
        .map_err(|e| error(crate::auth::failure_status(&e), "invalid token"))?;
    if !claims.allows_scope(crate::auth::scope::Scope::Admin) {
        tracing::warn!(sub = %claims.sub, "api key lacks the `admin` scope");
        return Err(error(
            StatusCode::FORBIDDEN,
            "this API key is not scoped to change billing configuration — it needs the `admin` scope",
        ));
    }
    Ok(claims.tenant_id)
}

// ── GET /v1/billing/usage ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
struct MeterView {
    used: Option<f64>,
    /// `None` = custom/unlimited (Enterprise), rendered as such — never a
    /// fabricated large number.
    included: Option<f64>,
    burst_exempt: f64,
    overage_units: f64,
    overage_usd: Option<f64>,
    projection_month_end: Option<f64>,
    last_computed_at: Option<String>,
    unit: &'static str,
}

impl MeterView {
    fn unavailable(unit: &'static str) -> Self {
        Self {
            used: None,
            included: None,
            burst_exempt: 0.0,
            overage_units: 0.0,
            overage_usd: None,
            projection_month_end: None,
            last_computed_at: None,
            unit,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct PlanView {
    lookup_key: String,
    price_monthly_usd: Option<i32>,
    price_annual_month_usd: Option<i32>,
    price_from_usd: Option<i32>,
    indexed_window_days: i32,
    queryable_days: i32,
    ledger_days: i32,
    unlimited_seats: bool,
    f_sso: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageResponse {
    month: String,
    /// B-410: the billing cycle the figures are rated over (RFC 3339), when a
    /// paid subscription cycle GOVERNS now; `None` = the calendar month above
    /// (no cycle stored, or a stale / not-yet-started one that was ignored).
    period_start: Option<String>,
    period_end: Option<String>,
    computed_at: String,
    meters: UsageMeters,
    projected_overage_usd: Option<f64>,
    spend_ceiling_usd: Option<f64>,
    overflow_mode: &'static str,
    rates_available: bool,
    /// The `pricing_rates.price_version` these numbers were rated against.
    /// **Price-version PINNING (a tenant rated against a NON-current version
    /// via `tenants.price_version`) is NOT implemented in this slice** — the
    /// rate card always loads `is_current = true` — because ADR-076 §0.7 is
    /// explicit that price protection is moot today: "Zero customers, no
    /// grandfathering... price protection starts with the first real signup
    /// under this model." `ResolvedEntitlements.price_version` and this field
    /// both exist so the read side and the schema are ready; wiring a
    /// specific tenant onto a pinned version is a follow-up once one exists.
    rate_card_version: String,
    plan: PlanView,
    /// spec §2.6 contract (web slice) — the two warning thresholds (§0.4:
    /// "75% and 90%"), from `card.policy.warn_pct`. Defaults to `[75, 90]`
    /// when the rate card is unavailable (matches `Policy::default`, so the
    /// UI's warning badges have a sane threshold even before Postgres is
    /// configured).
    warn_pct: [u32; 2],
    /// The rated bands for each of the six meters, so the web ladder/pricing
    /// UI needs no second fetch. Empty arrays when `rates_available` is
    /// false — never fabricated numbers.
    rates: UsageRates,
    /// `true` when `spend_ceiling_usd` is set AND this period's accrued
    /// overage has reached it — the SAME figure
    /// `projected_overage_usd` is computed from. `false` whenever either is
    /// `None` (no ceiling set, or rates unavailable).
    ceiling_reached: bool,
    /// BILL-01 / ADR-076 §0.4 — the AUTO-AGE shrunken window, when the daily
    /// metering job has narrowed it (`entitlement_cache::ResolvedEntitlements
    /// ::auto_age_window_days`). `None` = not aged; the full
    /// `plan.indexed_window_days` applies. The web computes "the oldest N
    /// days left your window early" as `plan.indexed_window_days -
    /// auto_age_window_days`, which is why this field stays the CURRENT
    /// (possibly narrowed) value while `plan.indexed_window_days` stays the
    /// plan's own nominal window rather than being overwritten by it.
    auto_age_window_days: Option<i32>,
}

/// One rated band, mirroring `crate::billing::rating::Band`'s three fields —
/// a local copy because `Band` does not derive `Serialize` and `rating.rs` is
/// outside this build's file allowlist.
#[derive(Debug, Clone, Copy, Serialize)]
struct RateBand {
    lo: f64,
    hi: Option<f64>,
    usd_per_unit: f64,
}

impl From<&Band> for RateBand {
    fn from(b: &Band) -> Self {
        Self {
            lo: b.lo,
            hi: b.hi,
            usd_per_unit: b.usd_per_unit,
        }
    }
}

/// spec §2.6 contract: one band array per meter, field names matching the
/// Polar meter names exactly.
#[derive(Debug, Clone, Serialize)]
struct UsageRates {
    ingest_gb: Vec<RateBand>,
    hot_gb_month: Vec<RateBand>,
    series: Vec<RateBand>,
    scan_units: Vec<RateBand>,
    cold_gb_month: Vec<RateBand>,
    eval_runs: Vec<RateBand>,
}

impl UsageRates {
    fn from_card(card: &crate::billing::RateCard) -> Self {
        let bands_for = |m: RatedMeter| -> Vec<RateBand> {
            card.bands
                .get(&m)
                .map(|v| v.iter().map(RateBand::from).collect())
                .unwrap_or_default()
        };
        Self {
            ingest_gb: bands_for(RatedMeter::IngestGb),
            hot_gb_month: bands_for(RatedMeter::HotGbMonth),
            series: bands_for(RatedMeter::Series),
            scan_units: bands_for(RatedMeter::ScanUnits),
            cold_gb_month: bands_for(RatedMeter::ColdGbMonth),
            eval_runs: bands_for(RatedMeter::EvalRuns),
        }
    }

    fn empty() -> Self {
        Self {
            ingest_gb: Vec::new(),
            hot_gb_month: Vec::new(),
            series: Vec::new(),
            scan_units: Vec::new(),
            cold_gb_month: Vec::new(),
            eval_runs: Vec::new(),
        }
    }
}

/// `true` iff a spend ceiling is set and the SAME figure
/// `projected_overage_usd` reports has reached or passed it. Pure — the
/// web-contract predicate, unit-tested without a live request.
fn ceiling_reached(spend_ceiling_usd: Option<f64>, projected_overage_usd: Option<f64>) -> bool {
    match (spend_ceiling_usd, projected_overage_usd) {
        (Some(ceiling), Some(overage)) => overage >= ceiling,
        _ => false,
    }
}

#[derive(Debug, Clone, Serialize)]
struct UsageMeters {
    ingest: MeterView,
    hot: MeterView,
    series: MeterView,
    query: MeterView,
    cold: MeterView,
    evals: MeterView,
}

#[derive(Debug, serde::Deserialize, clickhouse::Row)]
struct DailyRow {
    // ClickHouse `Date` deserializes into `chrono::NaiveDate` without the
    // crate's own `chrono` feature only via a custom visitor; simplest here
    // is to read it as the ISO string ClickHouse renders for `toString(day)`.
    //
    // The FIELD ITSELF is unread (only `.value` is consulted below — the
    // burst-exemption input needs a chronologically-ordered VALUE series,
    // not the date labels), but it is NOT dead: `clickhouse::Row` decodes
    // RowBinary POSITIONALLY, so removing this field would desync every row
    // against the query's 2-column `SELECT toString(day), sum(value)` shape
    // — the exact B-274 class this repo has hit five times.
    #[allow(dead_code)]
    day: String,
    value: f64,
}

#[derive(serde::Deserialize, clickhouse::Row)]
struct SumRow {
    meter: String,
    total: f64,
}

#[derive(Debug, serde::Deserialize, clickhouse::Row)]
struct GaugeRow {
    meter: String,
    // Read (not dead — see `DailyRow`'s own comment on this exact shape):
    // `clickhouse::Row` decodes RowBinary POSITIONALLY, so this column MUST
    // stay in the struct to match the 4-column `GROUP BY meter, day` query,
    // even though its only consumer is `gauge_daily`'s sort.
    day: String,
    value: f64,
    computed_at: String,
}

/// Per-day `ingest_bytes` counter totals for `[since, today]`, oldest first —
/// the burst-exemption input.
///
/// **B-424 (2026-09-16): the projection is `AS day_iso`, NOT `AS day`.** ClickHouse
/// lets a SELECT alias shadow a same-named column across the whole query, so
/// `toString(day) AS day … WHERE day >= toDate(…)` compared the String alias
/// with a Date and failed with `NO_COMMON_TYPE` (code 386) on prod — on every
/// call, since BILL-01 shipped. Proven against a real server by
/// `period_reads_run_against_a_real_clickhouse` (`run-clickhouse-integration.sh`);
/// no unit test can see it, because the defect is the SQL's semantics.
///
/// # Errors
/// The ClickHouse error, for the caller to fail OPEN on (display path, §10).
async fn query_period_daily_ingest(
    ch: &clickhouse::Client,
    tenant_id: &tracelane_shared::TenantId,
    since: chrono::NaiveDate,
    tier: crate::clickhouse_query::PlanTier,
) -> Result<Vec<DailyRow>, clickhouse::error::Error> {
    let sql = crate::clickhouse_query::TenantQuery::new(
        format!(
            "SELECT toString(day) AS day_iso, sum(value) AS value FROM tracelane.meter_counters \
             WHERE tenant_id = ? AND meter = 'ingest_bytes' \
               AND day >= toDate('{since}') AND day <= today() \
             GROUP BY day ORDER BY day"
        ),
        tier,
    )
    .with_log_comment(format!("tenant_id={tenant_id}"))
    .sql_with_settings();
    ch.query(&sql).bind(tenant_id.to_string()).fetch_all().await
}

/// The gauge meters per (meter, day) for `[since, today]`, oldest first, each
/// day collapsed to its latest write. Same B-424 alias rule as
/// [`query_period_daily_ingest`], TWICE: `AS computed_at` beside
/// `argMax(value, computed_at)` made the alias's `max(…)` the argument of the
/// `argMax` — `ILLEGAL_AGGREGATION` (184) on the server.
///
/// # Errors
/// The ClickHouse error, for the caller to fail OPEN on (display path, §10).
async fn query_period_gauges(
    ch: &clickhouse::Client,
    tenant_id: &tracelane_shared::TenantId,
    since: chrono::NaiveDate,
    tier: crate::clickhouse_query::PlanTier,
) -> Result<Vec<GaugeRow>, clickhouse::error::Error> {
    let sql = crate::clickhouse_query::TenantQuery::new(
        format!(
            "SELECT meter, toString(day) AS day_iso, argMax(value, computed_at) AS value, \
                    toString(max(computed_at)) AS computed_at_iso \
             FROM tracelane.meter_gauges \
             WHERE tenant_id = ? AND day >= toDate('{since}') AND day <= today() \
             GROUP BY meter, day \
             ORDER BY day"
        ),
        tier,
    )
    .with_log_comment(format!("tenant_id={tenant_id}"))
    .sql_with_settings();
    ch.query(&sql).bind(tenant_id.to_string()).fetch_all().await
}

/// This meter's per-day gauge rows for the month, sorted oldest-first —
/// spec step 7's aggregation input. `meter_gauges` is `ReplacingMergeTree`,
/// so a re-run for the same day is already collapsed to one row by the
/// `argMax(value, computed_at)` in the SQL; this just groups by meter and
/// orders what the query returns.
fn gauge_daily<'a>(gauges: &'a [GaugeRow], meter: &str) -> Vec<&'a GaugeRow> {
    let mut rows: Vec<&GaugeRow> = gauges.iter().filter(|g| g.meter == meter).collect();
    rows.sort_by(|a, b| a.day.cmp(&b.day));
    rows
}

/// Meter 2's GB-month as Polar totals it: the mean of the daily resident GB
/// (each day's event is `resident_gb / days_in_period`, so the cycle sum is the
/// mean). Never multiplied back by the period length — B-436.
fn hot_gb_month_projection(daily_resident_bytes: &[f64]) -> f64 {
    mean(daily_resident_bytes) / 1e9
}

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}

fn max_of(values: &[f64]) -> f64 {
    values.iter().copied().fold(0.0, f64::max)
}

fn sum_of(values: &[f64]) -> f64 {
    values.iter().sum()
}

/// B-410: the window this tenant's figures are rated over at `now` — its
/// Polar cycle when that governs, else the UTC calendar month. ONE rule,
/// [`crate::billing::period::billing_period`], the same one the metering
/// job rates with; this file carries no calendar arithmetic of its own.
fn rated_period(
    resolved: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    now: chrono::DateTime<chrono::Utc>,
) -> crate::billing::period::BillingPeriod {
    crate::billing::period::billing_period(resolved.and_then(|r| r.billing_period), now)
}

/// One WARN when a stored cycle had to be ignored (it ended without the
/// renewal webhook landing, or has not started): the figures fall back to
/// the calendar month, and the line is what tells an operator the webhook is
/// missing. Rate: once per uncached call, i.e. at most once per tenant per
/// 60 s (`usage_cache`).
fn warn_if_cycle_ignored(
    resolved: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    period: &crate::billing::period::BillingPeriod,
) {
    let stored = resolved.and_then(|r| r.billing_period);
    if period.ignored_cycle(stored)
        && let Some((start, end)) = stored
    {
        tracing::warn!(
            cycle_start = %start.to_rfc3339(),
            cycle_end = %end.to_rfc3339(),
            "billing usage: stored Polar cycle does not contain now — rated over the calendar month; renewal webhook missing?"
        );
    }
}

/// The two RFC 3339 strings the response carries for B-410: the governing
/// cycle's own bounds, or `None` under the calendar month — a stale cycle is
/// NOT echoed, because the figures beside it were not rated over it.
fn period_fields(
    period: &crate::billing::period::BillingPeriod,
) -> (Option<String>, Option<String>) {
    match period.cycle {
        Some((start, end)) => (Some(start.to_rfc3339()), Some(end.to_rfc3339())),
        None => (None, None),
    }
}

/// Linear projection to the end of the rated period: `used / elapsed × total`.
fn projection(used: f64, elapsed: f64, days_in_period: f64) -> Option<f64> {
    if elapsed < 1.0 {
        return None;
    }
    Some(used / elapsed * days_in_period)
}

/// Rate one COUNTER meter (ingest / evals) whose real data lives in
/// `meter_counters`. `daily` is only populated for the burst-exempt meters
/// (ingest); it is empty for evals (§0.4 burst applies to meters 1 and 4 only).
// One parameter per input the view is built from; a struct would only rename them.
#[allow(clippy::too_many_arguments)]
fn view_from_counter(
    card: &crate::billing::RateCard,
    rated_meter: RatedMeter,
    total: f64,
    included: Option<f64>,
    daily: &[f64],
    unit: &'static str,
    overage_allowed: bool,
    progress: (f64, f64),
) -> MeterView {
    let (elapsed, days_in_period) = progress;
    let burst_exempt = if daily.is_empty() {
        0.0
    } else {
        rating::burst_exempt_days(daily, card.policy.burst_multiple)
    };
    let rated = rating::rate(card, rated_meter, total, included, burst_exempt);
    MeterView {
        used: Some(total),
        included,
        burst_exempt: rated.burst_exempt,
        overage_units: rated.overage_units,
        // Free (overage_allowed=false) shows the over-100% USED figure but
        // ZERO dollars — ADR-076 §0.4: Free ages out, never bills overage.
        overage_usd: if overage_allowed && card.available {
            Some(rated.overage_usd)
        } else if card.available {
            Some(0.0)
        } else {
            None
        },
        projection_month_end: projection(total, elapsed, days_in_period),
        last_computed_at: Some(chrono::Utc::now().to_rfc3339()),
        unit,
    }
}

#[derive(Debug, Deserialize)]
struct UsageQuery {}

#[tracing::instrument(skip(state, headers), fields(tenant_id = tracing::field::Empty))]
async fn usage_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(_q): Query<UsageQuery>,
) -> Response {
    let tenant_id = match read_tenant(&headers).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    tracing::Span::current().record("tenant_id", tenant_id.to_string());

    if let Some(hit) = usage_cache().get(&tenant_id).await {
        return axum::Json((*hit).clone()).into_response();
    }

    let resolved = match &state.entitlements {
        Some(cache) => Some(cache.resolved(*tenant_id.as_uuid()).await),
        None => None,
    };
    let card = state.rate_card.load_full();

    let now = chrono::Utc::now();
    let Some(url) = state.quota_ch_url.clone() else {
        // No ClickHouse at all — the whole page is "metering unavailable",
        // never a 500 (fail-OPEN display path).
        let resp = unavailable_response(resolved.as_deref(), now);
        usage_cache()
            .insert(tenant_id, Arc::new(resp.clone()))
            .await;
        return axum::Json(resp).into_response();
    };
    let tier =
        crate::clickhouse_query::tier_for_tenant(state.entitlements.as_ref(), &tenant_id).await;
    let ch = crate::clickhouse_query::ch_client(url);
    // B-410: everything below is period-to-date over the Polar cycle when it
    // governs now (so the page agrees with the invoice), else month-to-date —
    // the SAME rule the metering job wrote the gauges with.
    let rated = rated_period(resolved.as_deref(), now);
    warn_if_cycle_ignored(resolved.as_deref(), &rated);
    let since = rated.start;
    let progress = rated.progress(now.date_naive());
    let period = period_fields(&rated);

    // ONE query: this period's COUNTER totals (ingest_bytes, eval_runs), by meter.
    let counters_sql = crate::clickhouse_query::TenantQuery::new(
        format!(
            "SELECT meter, sum(value) AS total FROM tracelane.meter_counters \
             WHERE tenant_id = ? AND meter IN ('ingest_bytes', 'eval_runs') \
               AND day >= toDate('{since}') AND day <= today() \
             GROUP BY meter"
        ),
        tier,
    )
    .with_log_comment(format!("tenant_id={tenant_id}"))
    .sql_with_settings();
    let counters: Vec<SumRow> = ch
        .query(&counters_sql)
        .bind(tenant_id.to_string())
        .fetch_all()
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "billing usage: meter_counters read failed");
            Vec::new()
        });
    let ingest_bytes_used = counters
        .iter()
        .find(|r| r.meter == "ingest_bytes")
        .map_or(0.0, |r| r.total);
    let eval_runs_used = counters
        .iter()
        .find(|r| r.meter == "eval_runs")
        .map_or(0.0, |r| r.total);

    // ONE query: this period's per-day ingest_bytes, for the burst exemption
    // (§0.4 applies to meters 1 and 4; meter 4 has no producer in this build).
    // Fail-OPEN on a display path (§10): a failed read renders as "no burst",
    // and says so in the log — it was `unwrap_or_default()` with no line at
    // all until B-424, which is how a query that failed on EVERY call stayed
    // invisible.
    let daily_rows = query_period_daily_ingest(&ch, &tenant_id, since, tier)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "billing usage: meter_counters daily read failed");
            Vec::new()
        });
    let ingest_daily: Vec<f64> = daily_rows.into_iter().map(|r| r.value).collect();

    // ONE query: the four GAUGE meters, per (day, meter) this period —
    // `argMax(value, computed_at)` collapses a same-day re-run to its
    // latest write; grouping by day too (not just meter) is what lets the
    // handler apply the RIGHT aggregation per meter (mean / max / sum —
    // spec step 7) instead of collapsing to a single point before it can.
    let gauges = query_period_gauges(&ch, &tenant_id, since, tier)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "billing usage: meter_gauges read failed");
            Vec::new()
        });

    let overage_allowed = resolved.as_ref().is_none_or(|e| e.overage_allowed);
    let ingest_included_gb = resolved
        .as_ref()
        .and_then(|e| e.ingest_bytes_included)
        .map(|b| b as f64 / 1e9);
    let hot_included_gb = resolved
        .as_ref()
        .and_then(|e| e.hot_bytes_included)
        .map(|b| b as f64 / 1e9);
    let series_included = resolved
        .as_ref()
        .and_then(|e| e.series_included)
        .map(|v| v as f64);
    let scan_included = resolved
        .as_ref()
        .and_then(|e| e.scan_units_included)
        .map(|v| v as f64);
    let eval_included = resolved
        .as_ref()
        .and_then(|e| e.eval_runs_included)
        .map(|v| v as f64);
    let cold_included_gb = resolved
        .as_ref()
        .and_then(|e| e.cold_bytes_included)
        .map(|b| b as f64 / 1e9);

    let ingest_view = view_from_counter(
        &card,
        RatedMeter::IngestGb,
        ingest_bytes_used / 1e9,
        ingest_included_gb,
        &ingest_daily.iter().map(|b| b / 1e9).collect::<Vec<_>>(),
        "GB",
        overage_allowed,
        progress,
    );
    let evals_view = view_from_counter(
        &card,
        RatedMeter::EvalRuns,
        eval_runs_used,
        eval_included,
        &[],
        "run",
        overage_allowed,
        progress,
    );
    // Meter 2 (hot): `used` = TODAY (the latest day's resident bytes — spec
    // §3 "resident GB today"); the GB-month projection = the MEAN of the daily
    // resident GB so far. B-436 (2026-09-19): this was `mean × days-in-period`,
    // which is what the spec's proof table (§3 "÷ days elapsed × days in
    // month") said and what Polar does NOT bill — the job emits one event per
    // day = resident_gb / days-in-period (spec §2 meter 2: "GB-month =
    // Σ(daily resident GB)/days-in-month"; `metering_job.rs` gb_month_share),
    // so the invoice's cycle total IS the mean. A steady 0.25 GB resident is
    // 0.25 GB-month on the invoice; the page showed 7.5 and an overage. The
    // founder's B-410 rule decides it: the dashboard agrees with Polar.
    let hot_daily_rows = gauge_daily(&gauges, "hot_resident_bytes");
    let hot_view = if hot_daily_rows.is_empty() {
        MeterView::unavailable("GB-month")
    } else {
        let values: Vec<f64> = hot_daily_rows.iter().map(|g| g.value).collect();
        let today_gb = values.last().copied().unwrap_or(0.0) / 1e9;
        let gb_month_projection = hot_gb_month_projection(&values);
        let rated = rating::rate(
            &card,
            RatedMeter::HotGbMonth,
            gb_month_projection,
            hot_included_gb,
            0.0,
        );
        MeterView {
            used: Some(today_gb),
            included: hot_included_gb,
            burst_exempt: 0.0,
            overage_units: rated.overage_units,
            overage_usd: if card.available {
                Some(if overage_allowed {
                    rated.overage_usd
                } else {
                    0.0
                })
            } else {
                None
            },
            projection_month_end: Some(gb_month_projection),
            last_computed_at: hot_daily_rows.last().map(|g| g.computed_at.clone()),
            unit: "GB-month",
        }
    };

    // Meter 3 (series): the job writes a running PERIOD-TO-DATE count every
    // day (anchored on this same tenant's cycle — B-420), so `max(daily)` IS
    // the current total (non-decreasing within a period in practice; max is
    // the fail-safe reading if a re-run ever wrote a lower value).
    let series_daily_rows = gauge_daily(&gauges, "series");
    let series_view = if series_daily_rows.is_empty() {
        MeterView::unavailable("series")
    } else {
        let values: Vec<f64> = series_daily_rows.iter().map(|g| g.value).collect();
        let (elapsed, days_in_period) = progress;
        let max_val = max_of(&values);
        let rated = rating::rate(&card, RatedMeter::Series, max_val, series_included, 0.0);
        MeterView {
            used: Some(max_val),
            included: series_included,
            burst_exempt: 0.0,
            overage_units: rated.overage_units,
            overage_usd: if card.available {
                Some(if overage_allowed {
                    rated.overage_usd
                } else {
                    0.0
                })
            } else {
                None
            },
            projection_month_end: projection(max_val, elapsed, days_in_period),
            last_computed_at: series_daily_rows.last().map(|g| g.computed_at.clone()),
            unit: "series",
        }
    };

    // Meter 4 (query / scan-units): each day's gauge IS that day's own scan
    // bytes (not cumulative), so Σ(daily) is the period-to-date total.
    let scan_daily_rows = gauge_daily(&gauges, "scan_bytes");
    let query_view = if scan_daily_rows.is_empty() {
        MeterView::unavailable("scan-unit")
    } else {
        let values: Vec<f64> = scan_daily_rows.iter().map(|g| g.value).collect();
        let (elapsed, days_in_period) = progress;
        let used_units = sum_of(&values) / 1e9;
        let rated = rating::rate(&card, RatedMeter::ScanUnits, used_units, scan_included, 0.0);
        MeterView {
            used: Some(used_units),
            included: scan_included,
            burst_exempt: 0.0,
            overage_units: rated.overage_units,
            overage_usd: if card.available {
                Some(if overage_allowed {
                    rated.overage_usd
                } else {
                    0.0
                })
            } else {
                None
            },
            projection_month_end: projection(used_units, elapsed, days_in_period),
            last_computed_at: scan_daily_rows.last().map(|g| g.computed_at.clone()),
            unit: "scan-unit",
        }
    };

    // Meter 5 (cold): a stock, not a flow — mean(daily) smooths noise across
    // this period's snapshots rather than projecting further growth.
    let cold_daily_rows = gauge_daily(&gauges, "cold_bytes");
    let cold_view = if cold_daily_rows.is_empty() {
        MeterView::unavailable("GB-month")
    } else {
        let values: Vec<f64> = cold_daily_rows.iter().map(|g| g.value).collect();
        let mean_gb = mean(&values) / 1e9;
        // BILL-01 A5: the allowance is 24x monthly ingest on paid tiers; meter 5
        // bills only beyond it, on this mean-daily basis (same as meter 2).
        let rated = rating::rate(
            &card,
            RatedMeter::ColdGbMonth,
            mean_gb,
            cold_included_gb,
            0.0,
        );
        MeterView {
            used: Some(mean_gb),
            included: cold_included_gb,
            burst_exempt: 0.0,
            overage_units: rated.overage_units,
            overage_usd: if overage_allowed && card.available {
                Some(rated.overage_usd)
            } else if card.available {
                Some(0.0)
            } else {
                None
            },
            projection_month_end: Some(mean_gb),
            last_computed_at: cold_daily_rows.last().map(|g| g.computed_at.clone()),
            unit: "GB-month",
        }
    };

    let projected_overage_usd = if card.available {
        Some(
            [
                &ingest_view,
                &hot_view,
                &series_view,
                &query_view,
                &cold_view,
                &evals_view,
            ]
            .iter()
            .filter_map(|m| m.overage_usd)
            .sum(),
        )
    } else {
        None
    };
    // Wired from the resolver (`entitlement_cache::ResolvedEntitlements
    // ::spend_ceiling_micro_usd`, sourced from `tenants.spend_ceiling_usd`).
    // `None` when no control plane or no ceiling set — never a coerced zero.
    let spend_ceiling_usd: Option<f64> = resolved
        .as_ref()
        .and_then(|e| e.spend_ceiling_micro_usd)
        .map(|micro| micro as f64 / 1_000_000.0);

    let resp = UsageResponse {
        month: now.format("%Y-%m").to_string(),
        period_start: period.0.clone(),
        period_end: period.1.clone(),
        computed_at: chrono::Utc::now().to_rfc3339(),
        meters: UsageMeters {
            ingest: ingest_view,
            hot: hot_view,
            series: series_view,
            query: query_view,
            cold: cold_view,
            evals: evals_view,
        },
        projected_overage_usd,
        spend_ceiling_usd,
        overflow_mode: resolved
            .as_ref()
            .map_or("auto_age", |e| e.overflow_mode.as_str()),
        rates_available: card.available,
        rate_card_version: card.version.clone(),
        plan: PlanView {
            lookup_key: resolved
                .as_ref()
                .map_or_else(|| "free_v1".to_string(), |e| e.plan_lookup_key.clone()),
            price_monthly_usd: resolved.as_ref().and_then(|e| e.price_monthly_usd),
            price_annual_month_usd: resolved.as_ref().and_then(|e| e.price_annual_month_usd),
            price_from_usd: resolved.as_ref().and_then(|e| e.price_from_usd),
            indexed_window_days: resolved.as_ref().map_or(3, |e| e.indexed_window_days),
            queryable_days: resolved.as_ref().map_or(30, |e| e.queryable_days),
            ledger_days: resolved.as_ref().map_or(30, |e| e.ledger_days),
            unlimited_seats: resolved.as_ref().is_some_and(|e| e.unlimited_seats),
            f_sso: resolved.as_ref().is_some_and(|e| e.f_sso),
        },
        warn_pct: [
            card.policy.warn_pct.first().copied().unwrap_or(75),
            card.policy.warn_pct.get(1).copied().unwrap_or(90),
        ],
        rates: if card.available {
            UsageRates::from_card(&card)
        } else {
            UsageRates::empty()
        },
        ceiling_reached: ceiling_reached(spend_ceiling_usd, projected_overage_usd),
        auto_age_window_days: resolved.as_ref().and_then(|e| e.auto_age_window_days),
    };
    usage_cache()
        .insert(tenant_id, Arc::new(resp.clone()))
        .await;
    axum::Json(resp).into_response()
}

fn unavailable_response(
    resolved: Option<&crate::entitlement_cache::ResolvedEntitlements>,
    now: chrono::DateTime<chrono::Utc>,
) -> UsageResponse {
    let period = period_fields(&rated_period(resolved, now));
    UsageResponse {
        month: now.format("%Y-%m").to_string(),
        period_start: period.0.clone(),
        period_end: period.1.clone(),
        computed_at: chrono::Utc::now().to_rfc3339(),
        meters: UsageMeters {
            ingest: MeterView::unavailable("GB"),
            hot: MeterView::unavailable("GB-month"),
            series: MeterView::unavailable("series"),
            query: MeterView::unavailable("scan-unit"),
            cold: MeterView::unavailable("GB-month"),
            evals: MeterView::unavailable("run"),
        },
        projected_overage_usd: None,
        spend_ceiling_usd: resolved
            .and_then(|e| e.spend_ceiling_micro_usd)
            .map(|micro| micro as f64 / 1_000_000.0),
        overflow_mode: resolved.map_or("auto_age", |e| e.overflow_mode.as_str()),
        rates_available: false,
        rate_card_version: String::new(),
        plan: PlanView {
            lookup_key: resolved
                .map_or_else(|| "free_v1".to_string(), |e| e.plan_lookup_key.clone()),
            price_monthly_usd: resolved.and_then(|e| e.price_monthly_usd),
            price_annual_month_usd: resolved.and_then(|e| e.price_annual_month_usd),
            price_from_usd: resolved.and_then(|e| e.price_from_usd),
            indexed_window_days: resolved.map_or(3, |e| e.indexed_window_days),
            queryable_days: resolved.map_or(30, |e| e.queryable_days),
            ledger_days: resolved.map_or(30, |e| e.ledger_days),
            unlimited_seats: resolved.is_some_and(|e| e.unlimited_seats),
            f_sso: resolved.is_some_and(|e| e.f_sso),
        },
        warn_pct: [75, 90], // Policy::default() — no rate card to read a real one from
        rates: UsageRates::empty(),
        ceiling_reached: false,
        auto_age_window_days: resolved.and_then(|e| e.auto_age_window_days),
    }
}

/// Per-tenant 60s cache for `GET /v1/billing/usage` (spec §2.5b: "cached per
/// tenant for 60 s so a dashboard refresh loop costs nothing"). A process
/// global, matching `entitlement_cache`'s own moka pattern — this route has
/// no other natural home for per-tenant state.
fn usage_cache() -> &'static moka::future::Cache<tracelane_shared::TenantId, Arc<UsageResponse>> {
    static C: std::sync::OnceLock<
        moka::future::Cache<tracelane_shared::TenantId, Arc<UsageResponse>>,
    > = std::sync::OnceLock::new();
    C.get_or_init(|| {
        moka::future::Cache::builder()
            .max_capacity(100_000)
            .time_to_live(Duration::from_secs(60))
            .build()
    })
}

// ── GET /v1/billing/window-breakdown ─────────────────────────────────────

#[derive(Debug, Deserialize)]
struct BreakdownQuery {
    by: Option<String>,
}

#[derive(Serialize)]
struct BreakdownRow {
    key: String,
    bytes: u64,
}

#[derive(Serialize)]
struct BreakdownResponse {
    by: String,
    rows: Vec<BreakdownRow>,
    total_bytes: u64,
    truncated: bool,
}

#[derive(serde::Deserialize, clickhouse::Row)]
struct BreakdownRawRow {
    key: String,
    bytes: u64,
}

#[tracing::instrument(skip(state, headers), fields(tenant_id = tracing::field::Empty))]
async fn window_breakdown_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<BreakdownQuery>,
) -> Response {
    let tenant_id = match read_tenant(&headers).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    tracing::Span::current().record("tenant_id", tenant_id.to_string());

    let by = q.by.as_deref().unwrap_or("project");
    let group_expr = match by {
        "project" => {
            "coalesce(nullIf(JSONExtractString(attributes, 'tracelane_project'), ''), \
             coalesce(nullIf(tracelane_api_key_id, ''), 'unattributed'))"
        }
        "service" => {
            "coalesce(nullIf(JSONExtractString(attributes, 'service_name'), ''), 'unattributed')"
        }
        "capture" => "if(JSONHas(attributes, 'gen_ai_input_messages'), 'content', 'metadata')",
        "shape" => {
            "if((SELECT span_count FROM tracelane.trace_summaries ts \
             WHERE ts.tenant_id = spans.tenant_id AND ts.trace_id = spans.trace_id \
             ORDER BY ts.start_time DESC LIMIT 1) > 1, 'multi-span', 'single-span')"
        }
        _ => {
            return error(
                StatusCode::BAD_REQUEST,
                "by must be one of: project, service, capture, shape",
            );
        }
    };

    let Some(url) = state.quota_ch_url.clone() else {
        return axum::Json(BreakdownResponse {
            by: by.to_string(),
            rows: Vec::new(),
            total_bytes: 0,
            truncated: false,
        })
        .into_response();
    };
    let resolved = match &state.entitlements {
        Some(cache) => Some(cache.resolved(*tenant_id.as_uuid()).await),
        None => None,
    };
    // AUTO-AGE §0.4: the breakdown must read the CURRENT (possibly narrowed)
    // indexed window, never the plan's nominal one — a tenant aged down to
    // 10 days would otherwise see a "top consumers" table sourced from data
    // that has already left the indexed window.
    let window_days = resolved.as_ref().map_or(3, |e| e.effective_window_days());
    let tier =
        crate::clickhouse_query::tier_for_tenant(state.entitlements.as_ref(), &tenant_id).await;
    let sql = crate::clickhouse_query::TenantQuery::new(
        format!(
            "SELECT {group_expr} AS key, sum(span_bytes) AS bytes FROM tracelane.spans \
             WHERE tenant_id = ? AND start_time >= now() - INTERVAL {window_days} DAY \
             GROUP BY key ORDER BY bytes DESC LIMIT 200"
        ),
        tier,
    )
    .with_log_comment(format!("tenant_id={tenant_id}"))
    .sql_with_settings();
    let rows: Vec<BreakdownRawRow> = crate::clickhouse_query::ch_client(url)
        .query(&sql)
        .bind(tenant_id.to_string())
        .fetch_all()
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, by, "window-breakdown query failed");
            Vec::new()
        });
    let total_bytes: u64 = rows.iter().map(|r| r.bytes).sum();
    let truncated = rows.len() >= 200;
    axum::Json(BreakdownResponse {
        by: by.to_string(),
        rows: rows
            .into_iter()
            .map(|r| BreakdownRow {
                key: r.key,
                bytes: r.bytes,
            })
            .collect(),
        total_bytes,
        truncated,
    })
    .into_response()
}

// ── PUT /v1/billing/ceiling ───────────────────────────────────────────────

#[derive(Deserialize)]
struct CeilingBody {
    usd: Option<f64>,
    overflow_mode: Option<String>,
}

/// The ceiling write. `spend_ceiling_usd` is `numeric(12,2)` (migration 0040)
/// and tokio-postgres has NO `ToSql` from `f64` to NUMERIC — with a bare `$2`
/// the server types the parameter as `numeric`, the client refuses
/// (`error serializing parameter 1`), and the route answered **503 on every
/// call on prod**, `null` included (B-394, found by the BILL-01 prod proof on
/// 2026-09-14; the first proof run masked it by writing the same value through
/// psql first). The explicit `::float8` makes the server type `$2` as a float,
/// which `Option<f64>` serialises; the outer cast lands it in the column.
/// The Postgres-integration test `set_ceiling_sql_binds_an_f64_and_a_null`
/// runs this exact string against a real server — a string literal is not a
/// contract until something executes it.
pub const SET_CEILING_SQL: &str = "UPDATE tenants \
     SET spend_ceiling_usd = ($2::float8)::numeric(12,2), overflow_mode = $3 \
     WHERE id = $1";

#[tracing::instrument(skip(state, headers, body), fields(tenant_id = tracing::field::Empty))]
async fn set_ceiling_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CeilingBody>,
) -> Response {
    let tenant_id = match admin_tenant(&headers).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    tracing::Span::current().record("tenant_id", tenant_id.to_string());

    if let Some(usd) = body.usd
        && !(usd.is_finite() && usd >= 0.0)
    {
        return error(
            StatusCode::BAD_REQUEST,
            "usd must be a finite, non-negative number, or null",
        );
    }
    let overflow_mode = match body.overflow_mode.as_deref() {
        Some("auto_age") | None => "auto_age",
        Some("auto_overage") => "auto_overage",
        Some(_) => {
            return error(
                StatusCode::BAD_REQUEST,
                "overflow_mode must be 'auto_age' or 'auto_overage'",
            );
        }
    };

    let Some(pool) = state.pg.as_ref() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "control plane unavailable");
    };
    let client = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "billing ceiling: pool checkout failed");
            return error(StatusCode::SERVICE_UNAVAILABLE, "control plane unavailable");
        }
    };
    if let Err(e) = client
        .execute(
            SET_CEILING_SQL,
            &[&tenant_id.as_uuid(), &body.usd, &overflow_mode],
        )
        .await
    {
        tracing::warn!(error = %e, "billing ceiling: update failed");
        return error(StatusCode::SERVICE_UNAVAILABLE, "update failed");
    }
    // Reading the new ceiling requires the entitlement cache to re-resolve —
    // invalidate this tenant's entry so the NEXT read (this route's own,
    // or the hot path's) sees it rather than waiting out the 15m TTL.
    if let Some(cache) = &state.entitlements {
        cache.invalidate(*tenant_id.as_uuid()).await;
    }
    usage_cache().invalidate(&tenant_id).await;
    StatusCode::NO_CONTENT.into_response()
}

// ── DELETE /v1/billing/promotion-freeze ──────────────────────────────────

#[tracing::instrument(skip(state, headers), fields(tenant_id = tracing::field::Empty))]
async fn clear_promotion_freeze_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let tenant_id = match admin_tenant(&headers).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    tracing::Span::current().record("tenant_id", tenant_id.to_string());

    let Some(pool) = state.pg.as_ref() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "control plane unavailable");
    };
    if let Err(e) = crate::billing::velocity_breaker::clear_freeze(pool, *tenant_id.as_uuid()).await
    {
        tracing::warn!(error = %e, "promotion-freeze clear failed");
        return error(StatusCode::SERVICE_UNAVAILABLE, "clear failed");
    }
    if let Some(cache) = &state.entitlements {
        cache.invalidate(*tenant_id.as_uuid()).await;
    }
    StatusCode::NO_CONTENT.into_response()
}

pub fn routes(state: AppState) -> Router {
    Router::new()
        .route("/v1/billing/usage", get(usage_handler))
        .route(
            "/v1/billing/window-breakdown",
            get(window_breakdown_handler),
        )
        .route("/v1/billing/ceiling", put(set_ceiling_handler))
        .route(
            "/v1/billing/promotion-freeze",
            axum::routing::delete(clear_promotion_freeze_handler),
        )
        .with_state(state)
}

// Referenced so `Band` stays a documented public type of the rating module
// even though this file constructs no literal `Band` itself (it only reads
// them through `RateCard`).
#[allow(dead_code)]
fn _band_type_is_public(_b: Band) {}

#[cfg(test)]
mod tests {

    /// B-436: a steady 0.25 GB resident for a whole period is 0.25 GB-month —
    /// the number Polar's cycle sum produces — never 0.25 × the period length.
    #[test]
    fn hot_gb_month_is_the_mean_of_the_daily_resident_gb_not_times_the_period_length() {
        let thirty_days = vec![0.25e9; 30];
        let got = super::hot_gb_month_projection(&thirty_days);
        assert!(
            (got - 0.25).abs() < 1e-9,
            "got {got}, expected 0.25 GB-month"
        );
        // A ramp: 0 → 1 GB over ten days averages 0.45 GB-month so far.
        let ramp: Vec<f64> = (0..10).map(|d| d as f64 * 0.1e9).collect();
        let got = super::hot_gb_month_projection(&ramp);
        assert!((got - 0.45).abs() < 1e-9, "got {got}");
    }
    use super::*;

    /// B-394 — the ceiling write against a REAL Postgres. `spend_ceiling_usd`
    /// is `numeric(12,2)` and tokio-postgres cannot serialise `f64` to NUMERIC;
    /// with a bare `$2` the server typed the parameter as numeric and every
    /// prod call answered 503 (`error serializing parameter 1`). No unit test
    /// can see that: the refusal is the driver's, made against the server's
    /// declared parameter type. `#[ignore]`d by default, run via
    /// `scripts/ci/run-postgres-integration.sh` (which applies every migration
    /// first, so the column has its real type).
    #[tokio::test]
    #[ignore = "needs POSTGRES_TEST_URL — run scripts/ci/run-postgres-integration.sh"]
    async fn set_ceiling_sql_binds_an_f64_and_a_null() {
        let Ok(url) = std::env::var("POSTGRES_TEST_URL") else {
            panic!("POSTGRES_TEST_URL not set — this test cannot run, which is not a pass");
        };
        let (client, conn) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .expect("connect to the integration Postgres");
        let conn_task = tokio::spawn(conn);

        let org = format!("org_b394_{}", uuid::Uuid::new_v4().simple());
        let id: uuid::Uuid = client
            .query_one(
                "INSERT INTO tenants (workos_org_id, name) VALUES ($1, $2) RETURNING id",
                &[&org, &"b394-ceiling-test"],
            )
            .await
            .expect("insert a throwaway tenant")
            .get(0);

        // Some(f64) → the column must read back as the rounded numeric.
        let some: Option<f64> = Some(12.5);
        let n = client
            .execute(SET_CEILING_SQL, &[&id, &some, &"auto_overage"])
            .await
            .expect("Some(f64) must bind into numeric(12,2) — B-394 is back if this fails");
        assert_eq!(n, 1);
        let row = client
            .query_one(
                "SELECT spend_ceiling_usd::text, overflow_mode FROM tenants WHERE id = $1",
                &[&id],
            )
            .await
            .expect("read back");
        assert_eq!(row.get::<_, String>(0), "12.50");
        assert_eq!(row.get::<_, String>(1), "auto_overage");

        // None → NULL: the customer's "turn the ceiling off" click, which was
        // the exact call the prod proof saw answer 503.
        let none: Option<f64> = None;
        let n = client
            .execute(SET_CEILING_SQL, &[&id, &none, &"auto_age"])
            .await
            .expect("None must bind as NULL");
        assert_eq!(n, 1);
        let row = client
            .query_one(
                "SELECT spend_ceiling_usd IS NULL, overflow_mode FROM tenants WHERE id = $1",
                &[&id],
            )
            .await
            .expect("read back null");
        assert!(
            row.get::<_, bool>(0),
            "ceiling must be NULL after a null PUT"
        );
        assert_eq!(row.get::<_, String>(1), "auto_age");

        client
            .execute("DELETE FROM tenants WHERE id = $1", &[&id])
            .await
            .expect("delete the throwaway tenant");
        conn_task.abort();
    }

    fn at(y: i32, m: u32, d: u32) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_naive_utc_and_offset(
            chrono::NaiveDate::from_ymd_opt(y, m, d)
                .unwrap()
                .and_hms_opt(4, 10, 0)
                .unwrap(),
            chrono::Utc,
        )
    }

    /// B-410 / B-420: a cycle anchored on the 15th rates from the 15th across
    /// the month boundary, names itself in the response, and projects over
    /// the cycle's 30 days — never the calendar month's.
    #[test]
    fn a_15th_anchored_cycle_rates_the_page_from_the_15th() {
        let mut r = crate::entitlement_cache::ResolvedEntitlements::deny_all();
        r.billing_period = Some((at(2026, 9, 15), at(2026, 10, 15)));
        let now = at(2026, 10, 3);
        let rated = rated_period(Some(&r), now);
        assert_eq!(
            rated.start,
            chrono::NaiveDate::from_ymd_opt(2026, 9, 15).unwrap()
        );
        assert_eq!(rated.progress(now.date_naive()), (19.0, 30.0));
        let (a, b) = period_fields(&rated);
        assert_eq!(a.as_deref(), Some("2026-09-15T04:10:00+00:00"));
        assert_eq!(b.as_deref(), Some("2026-10-15T04:10:00+00:00"));
        // No cycle -> the calendar month, exactly as before B-410.
        r.billing_period = None;
        let rated = rated_period(Some(&r), now);
        assert_eq!(
            rated.start,
            chrono::NaiveDate::from_ymd_opt(2026, 10, 1).unwrap()
        );
        assert_eq!(rated.progress(now.date_naive()), (3.0, 31.0));
        let (a, b) = period_fields(&rated);
        assert!(a.is_none() && b.is_none());
        // No control plane at all -> the same calendar month.
        assert_eq!(rated_period(None, now), rated);
    }

    /// B-410: a stored cycle that ENDED without the renewal webhook landing is
    /// not the current cycle. Rating from its start would fold a whole
    /// previous cycle into "period to date" and the page would name a cycle
    /// its figures were not rated over; the calendar month governs instead.
    #[test]
    fn a_stale_cycle_is_rated_over_the_calendar_month_and_not_echoed() {
        let mut r = crate::entitlement_cache::ResolvedEntitlements::deny_all();
        r.billing_period = Some((at(2026, 7, 21), at(2026, 8, 21)));
        let now = at(2026, 9, 19);
        let rated = rated_period(Some(&r), now);
        assert_eq!(
            rated.start,
            chrono::NaiveDate::from_ymd_opt(2026, 9, 1).unwrap(),
            "a stale cycle must not anchor the period-to-date sums"
        );
        assert_eq!(rated.progress(now.date_naive()), (19.0, 30.0));
        assert!(
            rated.ignored_cycle(r.billing_period),
            "the handler warns on this"
        );
        let (a, b) = period_fields(&rated);
        assert!(
            a.is_none() && b.is_none(),
            "a cycle the figures were not rated over must not be shown beside them"
        );
        // The unavailable (no-ClickHouse) shape follows the same rule.
        let resp = unavailable_response(Some(&r), now);
        assert!(resp.period_start.is_none() && resp.period_end.is_none());
        assert_eq!(resp.month, "2026-09");
    }

    #[test]
    fn projection_requires_at_least_one_elapsed_day() {
        assert_eq!(
            projection(10.0, 0.5, 30.0),
            None,
            "before day 1 there is not enough data"
        );
        assert!(projection(10.0, 1.0, 30.0).is_some());
    }

    #[test]
    fn projection_scales_linearly() {
        // 10 units in 10 days of a 30-day month -> 30 units by month end.
        let p = projection(10.0, 10.0, 30.0).expect("projected");
        assert!((p - 30.0).abs() < 1e-9);
    }

    #[test]
    fn meter_view_unavailable_is_all_none() {
        let v = MeterView::unavailable("GB");
        assert_eq!(v.used, None);
        assert_eq!(v.included, None);
        assert_eq!(v.last_computed_at, None);
        assert_eq!(v.unit, "GB");
    }

    // ── BILL-01 step 7 — per-meter daily aggregation (pure) ─────────────

    fn row(meter: &str, day: &str, value: f64) -> GaugeRow {
        GaugeRow {
            meter: meter.to_string(),
            day: day.to_string(),
            value,
            computed_at: format!("{day}T04:10:00Z"),
        }
    }

    #[test]
    fn gauge_daily_filters_and_sorts_one_meter() {
        let gauges = vec![
            row("hot_resident_bytes", "2026-09-03", 30.0),
            row("series", "2026-09-01", 1.0),
            row("hot_resident_bytes", "2026-09-01", 10.0),
            row("hot_resident_bytes", "2026-09-02", 20.0),
        ];
        let hot = gauge_daily(&gauges, "hot_resident_bytes");
        let days: Vec<&str> = hot.iter().map(|g| g.day.as_str()).collect();
        assert_eq!(days, vec!["2026-09-01", "2026-09-02", "2026-09-03"]);
    }

    #[test]
    fn mean_max_sum_agree_with_plain_arithmetic() {
        let values = [1.0, 2.0, 3.0, 4.0];
        assert!((mean(&values) - 2.5).abs() < 1e-9);
        assert_eq!(max_of(&values), 4.0);
        assert_eq!(sum_of(&values), 10.0);
        assert_eq!(mean(&[]), 0.0);
        assert_eq!(max_of(&[]), 0.0);
        assert_eq!(sum_of(&[]), 0.0);
    }

    // ── ceiling_reached (pure) ───────────────────────────────────────────

    #[test]
    fn ceiling_reached_is_false_when_no_ceiling_is_set() {
        assert!(!ceiling_reached(None, Some(500.0)));
    }

    #[test]
    fn ceiling_reached_is_false_when_projection_is_unavailable() {
        assert!(!ceiling_reached(Some(100.0), None));
    }

    #[test]
    fn ceiling_reached_is_true_at_or_above_the_ceiling() {
        assert!(ceiling_reached(Some(100.0), Some(100.0)));
        assert!(ceiling_reached(Some(100.0), Some(150.0)));
        assert!(!ceiling_reached(Some(100.0), Some(99.99)));
    }

    // ── UsageRates ────────────────────────────────────────────────────

    #[test]
    fn usage_rates_empty_has_every_meter_as_an_empty_array() {
        let r = UsageRates::empty();
        assert!(r.ingest_gb.is_empty());
        assert!(r.hot_gb_month.is_empty());
        assert!(r.series.is_empty());
        assert!(r.scan_units.is_empty());
        assert!(r.cold_gb_month.is_empty());
        assert!(r.eval_runs.is_empty());
    }

    #[test]
    fn usage_rates_from_card_copies_the_real_bands() {
        let mut bands = std::collections::HashMap::new();
        bands.insert(
            RatedMeter::IngestGb,
            vec![Band {
                lo: 0.0,
                hi: None,
                usd_per_unit: 0.2,
            }],
        );
        let card = crate::billing::RateCard {
            version: "v3".to_string(),
            bands,
            policy: rating::Policy {
                warn_pct: vec![75, 90],
                ..Default::default()
            },
            available: true,
        };
        let rates = UsageRates::from_card(&card);
        assert_eq!(rates.ingest_gb.len(), 1);
        assert!((rates.ingest_gb[0].usd_per_unit - 0.2).abs() < 1e-9);
        assert!(
            rates.series.is_empty(),
            "no band loaded for series -> empty, not fabricated"
        );
    }

    // ── Full JSON key set — pins the web contract so the fixture and this
    // struct cannot silently drift apart again (coordinator's step-7 addendum) ─

    #[test]
    fn usage_response_serializes_the_full_contracted_key_set() {
        let resp = unavailable_response(None, chrono::Utc::now());
        let v = serde_json::to_value(&resp).expect("UsageResponse must serialize");
        let top = v.as_object().expect("top-level object");
        let mut keys: Vec<&str> = top.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "auto_age_window_days",
                "ceiling_reached",
                "computed_at",
                "meters",
                "month",
                "overflow_mode",
                "period_end",
                "period_start",
                "plan",
                "projected_overage_usd",
                "rate_card_version",
                "rates",
                "rates_available",
                "spend_ceiling_usd",
                "warn_pct",
            ],
            "UsageResponse's top-level JSON keys changed — update the web fixture in the SAME change"
        );

        let meters = top["meters"].as_object().expect("meters object");
        let mut meter_keys: Vec<&str> = meters.keys().map(String::as_str).collect();
        meter_keys.sort_unstable();
        assert_eq!(
            meter_keys,
            vec!["cold", "evals", "hot", "ingest", "query", "series"]
        );

        let rates = top["rates"].as_object().expect("rates object");
        let mut rate_keys: Vec<&str> = rates.keys().map(String::as_str).collect();
        rate_keys.sort_unstable();
        assert_eq!(
            rate_keys,
            vec![
                "cold_gb_month",
                "eval_runs",
                "hot_gb_month",
                "ingest_gb",
                "scan_units",
                "series",
            ],
            "rates' meter-name keys must match the Polar meter names exactly"
        );

        assert_eq!(top["warn_pct"].as_array().map(Vec::len), Some(2));
        assert_eq!(top["ceiling_reached"], false);
    }

    /// B-424, against a REAL ClickHouse: the two period reads the usage page
    /// renders from. Both carried `toString(day) AS day … WHERE day >= …`, and
    /// the gauge read ALSO `toString(max(computed_at)) AS computed_at` beside
    /// `argMax(value, computed_at)` — a SELECT alias shadows a same-named column
    /// across the whole query, so the server answered `NO_COMMON_TYPE` (386) and
    /// `ILLEGAL_AGGREGATION` (184) respectively, and the handler rendered "no
    /// burst, no gauges" on every call (`unwrap_or_default()`, no log line).
    /// A unit test cannot see either: the defect is the SQL's semantics.
    /// `#[ignore]`d by default; `scripts/ci/run-clickhouse-integration.sh` runs it.
    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn period_reads_run_against_a_real_clickhouse() {
        let Ok(url) = std::env::var("CLICKHOUSE_TEST_URL") else {
            panic!("CLICKHOUSE_TEST_URL not set — this test cannot run, which is not a pass");
        };
        clickhouse::Client::default()
            .with_url(&url)
            .query("CREATE DATABASE IF NOT EXISTS tracelane")
            .execute()
            .await
            .expect("create database");
        let ch = clickhouse::Client::default()
            .with_url(&url)
            .with_database("tracelane");
        for stmt in crate::clickhouse_query::split_migration_statements(include_str!(
            "../../../../infra/dev/clickhouse/migrations/24_bill01_meters_blobs_tiering.sql"
        )) {
            let _ = ch.query(&stmt).execute().await;
        }
        let tenant = tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        let tid = tenant.to_string();
        let today = chrono::Utc::now().date_naive();
        ch.query(
            "INSERT INTO tracelane.meter_counters (tenant_id, day, meter, value) VALUES \
             (?, today(), 'ingest_bytes', 3), (?, today(), 'ingest_bytes', 4)",
        )
        .bind(&tid)
        .bind(&tid)
        .execute()
        .await
        .expect("insert counters");
        ch.query(
            "INSERT INTO tracelane.meter_gauges (tenant_id, day, meter, value, computed_at) VALUES \
             (?, today(), 'hot_resident_bytes', 100, now64(3) - INTERVAL 1 MINUTE), \
             (?, today(), 'hot_resident_bytes', 250, now64(3))",
        )
        .bind(&tid)
        .bind(&tid)
        .execute()
        .await
        .expect("insert gauges");

        let daily =
            query_period_daily_ingest(&ch, &tenant, today, crate::clickhouse_query::PlanTier::Team)
                .await
                .expect("daily read must run (B-424: NO_COMMON_TYPE until fixed)");
        let values: Vec<f64> = daily.iter().map(|r| r.value).collect();
        assert_eq!(values, vec![7.0], "one day, summed");
        assert_eq!(daily[0].day, today.to_string());

        let gauges =
            query_period_gauges(&ch, &tenant, today, crate::clickhouse_query::PlanTier::Team)
                .await
                .expect(
                    "gauge read must run (B-424: NO_COMMON_TYPE / ILLEGAL_AGGREGATION until fixed)",
                );
        assert_eq!(gauges.len(), 1, "one (meter, day): {gauges:?}");
        assert_eq!(gauges[0].meter, "hot_resident_bytes");
        assert_eq!(gauges[0].day, today.to_string());
        assert_eq!(
            gauges[0].value, 250.0,
            "the LATEST write wins (argMax over computed_at)"
        );
        assert!(gauges[0].computed_at.starts_with(&today.to_string()));
    }
}

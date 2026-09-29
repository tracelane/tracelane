//! BILL-01 / ADR-076 — the daily metering job: meters 2-5 (hot window,
//! series, query, cold), Polar usage emission for every one of the six
//! meters, and the weekly blob GC mutation.
//!
//! Spawned by `server.rs` only when BOTH ClickHouse and Postgres are
//! configured. Runs at 04:10 UTC daily, and once at boot if today's gauges
//! are absent (a redeploy mid-day must not leave the usage page reporting
//! "—" until tomorrow). A separate weekly tick (Sunday 04:40 UTC) runs the
//! blob GC mutation.
//!
//! # Amplification budget (spec §2.5b) — and an honest departure from it
//!
//! The tenant → window map is ONE Postgres query (`fetch_tenant_meta`). The
//! four meter reads are FOUR ClickHouse queries (`query_hot_resident_bytes`,
//! `query_series`, `query_scan_bytes_yesterday`, `query_cold_bytes`), each a
//! single `GROUP BY tenant_id` — never a per-tenant loop — followed by ONE
//! batched INSERT into `meter_gauges`.
//!
//! **What the budget table's row does not itemise, and this job needs: the
//! incident-burst netting (ADR-076 §0.4) requires a TRAILING 30-day daily
//! array per tenant for the two counter-based meters (`ingest_bytes`,
//! `scan_bytes`), which the four gauge queries above do not carry** (they
//! read a single point — today's resident bytes, yesterday's scan total —
//! not a day-by-day series). This job therefore issues two FURTHER queries
//! (`query_trailing_daily_meter_counters`, `query_trailing_daily_scan_bytes`)
//! to build those arrays, plus three PERIOD-TO-DATE queries
//! (`query_period_to_date_meter_counter` ×2, `query_period_to_date_scan_bytes`)
//! feeding the usage-warning emails and the AUTO-AGE ceiling projection
//! below — the SAME window `GET /v1/billing/usage` bills from, not the
//! trailing window. Filed here rather than silently exceeding the stated "4
//! queries" without saying so: the real count is 9 ClickHouse reads + 1
//! batched write per run, all still `GROUP BY tenant_id`, never a per-tenant
//! loop — the property the budget exists to protect (no N+1) is intact even
//! though the literal query count is not 4.
//!
//! # The billing period (B-410 / B-420, founder ruling 2026-09-19)
//!
//! Every window-to-date figure this job computes — the `series` gauge, the
//! three period-to-date sums, the GB-month share each daily gauge event
//! carries, the usage-warning dedup key — is anchored on the tenant's OWN
//! Polar cycle (`tenants.current_period_start/end`, carried on
//! [`TenantMeta`] from the same Postgres read), falling back to the UTC
//! calendar month only for a tenant with no governing cycle. The rule lives
//! in [`crate::billing::period`] and is the same one `GET /v1/billing/usage`
//! reads with, so the page, the emails, AUTO-AGE and the invoice agree.
//! Per-tenant boundaries stay ONE query per meter: the `(tenant_id,
//! period_start)` pairs ride into the SQL as an `arrayJoin` literal
//! ([`periods_literal`]) joined on `tenant_id`, exactly as the hot/cold
//! window join already does — never a per-tenant loop (B-256 class).
//! `series` is a GAUGE Polar aggregates with `max` over the cycle
//! (`scripts/ops/polar-sync.mjs`), so the value emitted each day must be the
//! distinct count SINCE THAT TENANT'S CYCLE STARTED; a calendar-month count
//! read on a mid-month cycle was the max of two partial months, which
//! under-counts the union (B-420).
//!
//! # AUTO-AGE (spec §0.4)
//!
//! After the gauges are written, every tenant with a spend ceiling set gets
//! its month-to-date overage projected across all six meters (the SAME
//! [`crate::billing::rating::rate`] the usage route rates with); on
//! `overflow_mode = AutoAge` (the default), a projection over the ceiling
//! narrows `tenants.auto_age_window_days` to the largest window that still
//! fits — never deleting anything, never blocking ingest — and widens or
//! clears it again once usage drops. See [`apply_auto_age`] and
//! [`find_auto_age_window`]; every window-scoped read in this job
//! ([`windows_literal`]) uses [`TenantMeta::effective_window_days`], the
//! shrunken value, not the raw plan window.
//!
//! # Polar emission
//!
//! Batched through `PolarClient::record_meter_events` (up to 100 events per
//! `/events/ingest` POST — a tenant's own 6 meters never come close, but a
//! future multi-tenant batch could). Values are real `f64` GB figures, no
//! unit scaling — `scripts/ops/polar-sync.mjs` configures every one of the
//! six Polar meters in GB with fractional `metered_tiers` bands. See
//! [`emit_polar_events`].
//!
//! # Fail-open (CLAUDE.md §10 — a metering path, not a control)
//!
//! Every ClickHouse/Postgres/Polar failure here is logged + noted via
//! [`tracelane_shared::degradation::Degradation::MeteringJobFailed`] /
//! `PolarMeterEmissionFailed`; the job never panics and a failed run is
//! simply retried at the next scheduled tick (Polar emission is additionally
//! idempotent on `external_id`, so a partial run's retry cannot double-bill).

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use chrono::{Datelike as _, NaiveDate, Utc, Weekday};
use uuid::Uuid;

use crate::billing::polar_client::{PolarClient, PolarCustomerId};
use crate::billing::rating::RateCard;
use crate::db::DbPool;
use crate::entitlement_cache::EntitlementCache;

/// Daily run time (spec: "runs at 04:10 UTC daily").
const DAILY_HOUR: u32 = 4;
const DAILY_MINUTE: u32 = 10;
/// Weekly blob-GC run time (spec: "weekly (Sunday 04:40 UTC)").
const GC_WEEKDAY: Weekday = Weekday::Sun;
const GC_HOUR: u32 = 4;
const GC_MINUTE: u32 = 40;

// ── Pure date/time math (unit-tested without a clock or I/O) ───────────────

/// ADR-031 resource caps for the job's cross-tenant reads (`check-ch-reads-capped`).
/// A system job has no tenant tier to inherit, so it runs under the WIDEST plan caps —
/// still bounded memory/time per query, never unbounded. `TenantQuery` appends the
/// SETTINGS clause last, so a `?` bind placeholder in the SQL is untouched.
fn capped(sql: &str) -> String {
    crate::clickhouse_query::TenantQuery::new(sql, crate::clickhouse_query::PlanTier::Enterprise)
        .sql_with_settings()
}

/// Reserved tenant id for the job's own completion marker in `meter_gauges`. Not a
/// UUID on purpose: it can never collide with a real tenant, the usage route (which
/// reads by a real tenant id) can never see it, and the boot catch-up probe filters on
/// it — a `tenant_id` filter like every other read of `tracelane.*`.
pub(crate) const JOB_MARKER_TENANT: &str = "__metering_job__";
/// The marker's meter name (one row per completed run, `value = 1`).
pub(crate) const JOB_MARKER_METER: &str = "job_completed";

/// Days from the ClickHouse `Date` epoch (1970-01-01) to `date` — the raw
/// `u16` RowBinary wire encoding. Mirrors
/// `crates/gateway/src/billing/meters.rs::days_since_epoch` exactly (same
/// wire contract); duplicated rather than imported because that function is
/// module-private and `meters.rs` is outside this build's file allowlist.
fn days_since_epoch(date: NaiveDate) -> u16 {
    let Some(epoch) = NaiveDate::from_ymd_opt(1970, 1, 1) else {
        return 0;
    };
    u16::try_from((date - epoch).num_days().max(0)).unwrap_or(u16::MAX)
}

/// Seconds from `now` until the next occurrence of `hour:minute` UTC — today
/// if that time has not yet passed, else tomorrow. Never zero or negative
/// (a `tokio::time::sleep(0)` fires immediately, which would busy-loop a
/// once-daily job if `now` ever lands EXACTLY on the boundary).
fn secs_until_next_daily(now: chrono::DateTime<Utc>, hour: u32, minute: u32) -> u64 {
    let today_target = now
        .date_naive()
        .and_hms_opt(hour, minute, 0)
        // `and_time(NaiveTime::MIN)` is infallible (unlike `and_hms_opt`,
        // which can fail on an out-of-range hour/minute) — no `.unwrap()`
        // needed for the fallback (`.claude/rules/rust.md` bans it outside
        // tests even where provably safe).
        .unwrap_or_else(|| now.date_naive().and_time(chrono::NaiveTime::MIN));
    let target = if today_target > now.naive_utc() {
        today_target
    } else {
        today_target + chrono::Duration::days(1)
    };
    (target - now.naive_utc()).num_seconds().max(1) as u64
}

/// Seconds from `now` until the next occurrence of `weekday` at `hour:minute`
/// UTC (today counts if it IS that weekday and the time has not passed).
fn secs_until_next_weekly(
    now: chrono::DateTime<Utc>,
    weekday: Weekday,
    hour: u32,
    minute: u32,
) -> u64 {
    let mut candidate = now.date_naive();
    for _ in 0..8 {
        if candidate.weekday() == weekday {
            let at = candidate
                .and_hms_opt(hour, minute, 0)
                .unwrap_or_else(|| candidate.and_time(chrono::NaiveTime::MIN));
            if at > now.naive_utc() {
                return (at - now.naive_utc()).num_seconds().max(1) as u64;
            }
        }
        candidate += chrono::Duration::days(1);
    }
    7 * 24 * 60 * 60 // unreachable in practice; a safe fallback, never 0
}

/// ADR-076 §0.4 / spec §2.1 / founder ruling B12 incident-burst exemption,
/// applied at Polar EMISSION time. `emitted = day - burst_exempt_for_day(day,
/// avg, multiple)` — the SAME pure function `rating::burst_exempt_days` (the
/// usage-route's read-side netting) calls per day, so the job and the usage
/// page can never compute two different answers to "how much of today is a
/// forgiven spike" again (both prior readings here disagreed with each
/// other AND with the rating-side function before this fix).
///
/// `daily`'s LAST element is "yesterday"; everything before it is trailing
/// history. Fewer than 3 days of history ⇒ `avg` is not computed at all (no
/// signal) ⇒ [`crate::billing::rating::burst_exempt_for_day`] returns 0 ⇒
/// the full value emits.
fn net_of_burst(daily: &[f64], burst_multiple: f64) -> f64 {
    let Some((&yesterday, history)) = daily.split_last() else {
        return 0.0;
    };
    let yesterday = yesterday.max(0.0);
    let avg = if history.len() < 3 {
        0.0
    } else {
        history.iter().sum::<f64>() / history.len() as f64
    };
    let exempt = crate::billing::rating::burst_exempt_for_day(yesterday, avg, burst_multiple);
    (yesterday - exempt).max(0.0)
}

/// Bytes → GB.
fn gb(bytes: f64) -> f64 {
    bytes / 1e9
}

/// A gauge event's per-day share of a GB-MONTH figure (spec: "today's
/// resident bytes ÷ 1e9 ÷ days-in-month, so the cycle SUM is the GB-month").
/// `days_in_period` is the tenant's OWN billing period's length
/// ([`crate::billing::period::BillingPeriod::total_days`]) — a 30-day cycle
/// straddling a 31-day month divides by 30 on every one of its days, so the
/// cycle sum is exactly the mean; dividing by each calendar month's length
/// summed to 16/30 + 14/31 ≠ 1 for a steady tenant (B-410).
fn gb_month_share(bytes_today: f64, days_in_period: u32) -> f64 {
    gb(bytes_today) / f64::from(days_in_period.max(1))
}

// ── Tenant metadata (ONE Postgres query) ────────────────────────────────────

struct TenantMeta {
    tenant_id: Uuid,
    indexed_window_days: i32,
    queryable_days: i32,
    polar_customer_id: Option<String>,
    billing_email: Option<String>,
    /// BILL-01 / ADR-076 §0.4 — `tenants.auto_age_window_days`. `None` unless
    /// a PRIOR run already narrowed this tenant's window; today's run
    /// re-evaluates it (via [`Self::effective_window_days`]) and either
    /// confirms it, narrows it further, widens it back, or clears it.
    auto_age_window_days: Option<i32>,
    /// B-410 / B-420 — `tenants.current_period_start/end`, the Polar cycle
    /// the webhook stored. `None` = no paid cycle known. Read through
    /// [`Self::period_at`], never directly: a stored cycle that does not
    /// contain the instant (stale, or not started) must not anchor anything.
    billing_period: Option<crate::billing::period::Cycle>,
}

impl TenantMeta {
    /// The window this tenant's figures are rated over at `at` — its stored
    /// Polar cycle when that governs the instant, else the UTC calendar month
    /// (`crate::billing::period`, the SAME rule `GET /v1/billing/usage` uses).
    fn period_at(&self, at: chrono::DateTime<Utc>) -> crate::billing::period::BillingPeriod {
        crate::billing::period::billing_period(self.billing_period, at)
    }

    /// One WARN per tenant per run when a stored cycle was ignored — it has
    /// ended without the renewal webhook landing, or has not started. The
    /// figures fall back to the calendar month (the usage page does the
    /// same), and the line is what tells an operator the webhook is missing.
    fn warn_if_cycle_ignored(&self, period: &crate::billing::period::BillingPeriod) {
        if period.ignored_cycle(self.billing_period)
            && let Some((start, end)) = self.billing_period
        {
            tracing::warn!(
                tenant_id = %self.tenant_id,
                cycle_start = %start.to_rfc3339(),
                cycle_end = %end.to_rfc3339(),
                "metering job: stored Polar cycle does not contain now — rated over the calendar month; renewal webhook missing?"
            );
        }
    }

    /// The window every window-scoped read in THIS job must use instead of
    /// `indexed_window_days` directly — mirrors
    /// `entitlement_cache::ResolvedEntitlements::effective_window_days`
    /// exactly (same contract, duplicated because this job builds its own
    /// tenant metadata rather than resolving through that cache per tenant).
    fn effective_window_days(&self) -> i32 {
        self.auto_age_window_days
            .unwrap_or(self.indexed_window_days)
    }
}

/// The tenant → window map (spec §2.5b: "1, from the cache") — also carries
/// the Polar correlation id + billing contact so emission and the
/// usage-warning emails need no SECOND Postgres round trip.
const TENANT_META_SQL: &str = "\
    SELECT t.id, \
      COALESCE(we.indexed_window_days, pe.indexed_window_days, 3)::int AS indexed_window_days, \
      COALESCE(we.queryable_days, pe.queryable_days, 730)::int AS queryable_days, \
      t.polar_customer_id, t.billing_email, t.auto_age_window_days, \
      t.current_period_start, t.current_period_end \
    FROM tenants t \
    JOIN plan_entitlements pe ON pe.plan_lookup_key = t.plan::text || '_v1' \
    LEFT JOIN workspace_entitlements we ON we.tenant_id = t.id \
    WHERE t.archived_at IS NULL";

async fn fetch_tenant_meta(pool: &DbPool) -> anyhow::Result<Vec<TenantMeta>> {
    let client = pool
        .get()
        .await
        .map_err(|e| anyhow::anyhow!("metering job pool: {e}"))?;
    let rows = client.query(TENANT_META_SQL, &[]).await?;
    Ok(rows
        .iter()
        .map(|r| TenantMeta {
            tenant_id: r.get(0),
            indexed_window_days: r.get(1),
            queryable_days: r.get(2),
            polar_customer_id: r.get(3),
            billing_email: r.get(4),
            auto_age_window_days: r.get(5),
            billing_period: {
                let start: Option<chrono::DateTime<Utc>> = r.get(6);
                let end: Option<chrono::DateTime<Utc>> = r.get(7);
                start.zip(end)
            },
        })
        .collect())
}

/// Render `metas` as a ClickHouse literal array of
/// `(tenant_id, effective_window_days, queryable_days)` tuples — the
/// `arrayJoin` this job's two window-scoped queries (hot, cold) join
/// against, never a per-tenant loop (spec's own wording, step 6). Every
/// value is either a `Uuid` (fixed hex+hyphen shape, `Display`-formatted) or
/// a plain integer, both read from OUR OWN Postgres query — never customer
/// input — so string interpolation carries no injection surface.
///
/// Uses [`TenantMeta::effective_window_days`], NOT the raw
/// `indexed_window_days` field — a tenant AUTO-AGEd down to a narrower
/// window must have its hot/cold SPLIT follow that narrower boundary too,
/// or the gauges this job writes would keep billing/showing the pre-shrink
/// window forever (BILL-01 §0.4).
fn windows_literal(metas: &[TenantMeta]) -> String {
    let tuples: Vec<String> = metas
        .iter()
        .map(|m| {
            format!(
                "('{}',{},{})",
                m.tenant_id,
                m.effective_window_days(),
                m.queryable_days
            )
        })
        .collect();
    format!("[{}]", tuples.join(","))
}

/// Render `metas` as a ClickHouse literal array of `(tenant_id, period_start)`
/// tuples — the `arrayJoin` every period-to-date read joins against, so
/// per-tenant cycle boundaries cost ONE query per meter, never a per-tenant
/// loop (B-410 / B-420). `period_start` is the first UTC day of the window
/// governing `at` for THAT tenant ([`TenantMeta::period_at`]): its Polar
/// cycle, or the calendar month.
///
/// Injection surface: none. `tenant_id` is a `Uuid` — typed by tokio-postgres
/// off OUR OWN `tenants.id` column, so its `Display` is the fixed
/// hex-and-hyphen shape by construction, never customer input — and the date
/// is a `NaiveDate` whose `Display` is `YYYY-MM-DD`. The same argument
/// [`windows_literal`] makes; a value that could be anything else cannot
/// reach this function's parameter type.
fn periods_literal(metas: &[TenantMeta], at: chrono::DateTime<Utc>) -> String {
    let tuples: Vec<String> = metas
        .iter()
        .map(|m| format!("('{}','{}')", m.tenant_id, m.period_at(at).start))
        .collect();
    format!("[{}]", tuples.join(","))
}

/// The `WITH periods AS (…)` prefix shared by the period-anchored reads:
/// `(tenant_id String, period_start Date)` from [`periods_literal`]'s output.
fn periods_cte(periods_lit: &str) -> String {
    format!(
        "WITH periods AS ( \
            SELECT tupleElement(t,1) AS tenant_id, toDate(tupleElement(t,2)) AS period_start \
            FROM (SELECT arrayJoin({periods_lit}) AS t) \
         ) "
    )
}

/// The instant a read is made "as of": `now` for the live run, or the last
/// second of a past day for a backfill — the same boundary [`now_expr`]
/// renders into the SQL, so the period the literal is built from and the
/// as-of bound the query applies agree to the second.
fn instant_for(as_of: Option<NaiveDate>) -> chrono::DateTime<Utc> {
    match as_of {
        None => Utc::now(),
        Some(d) => chrono::DateTime::from_naive_utc_and_offset(
            d.and_time(
                chrono::NaiveTime::from_hms_opt(23, 59, 59).unwrap_or(chrono::NaiveTime::MIN),
            ),
            Utc,
        ),
    }
}

// ── The four gauge queries (spec: meters 2-5) ───────────────────────────────

#[derive(serde::Deserialize, clickhouse::Row)]
struct TenantValueRow {
    tenant_id: String,
    value: f64,
}

fn meter_query(sql: String) -> String {
    crate::clickhouse_query::TenantQuery::new(sql, crate::clickhouse_query::PlanTier::Business)
        .with_log_comment("tracelane-meter")
        .sql_with_settings()
}

/// `now()` for the live run, or the END of a past day for a backfill — the
/// stock meters (hot, cold, series) are recomputed AS OF that day using the
/// rows that existed then (`spans.ingested_at`), never approximated from
/// today's table (founder, 2026-09-14, B6 audit item D).
fn now_expr(as_of: Option<NaiveDate>) -> String {
    match as_of {
        None => "now()".to_string(),
        Some(d) => format!("toDateTime('{d} 23:59:59', 'UTC')"),
    }
}

/// The `ingested_at` bound that makes an as-of recomputation exact; empty live.
fn ingested_filter(as_of: Option<NaiveDate>, alias: &str) -> String {
    match as_of {
        None => String::new(),
        Some(_) => format!(" AND {alias}ingested_at <= {}", now_expr(as_of)),
    }
}

/// Meter 2: `hot_resident_bytes` — `sum(span_bytes)` per tenant over rows
/// inside THAT tenant's indexed window. ONE query via the `windows` join.
async fn query_hot_resident_bytes(
    ch: &clickhouse::Client,
    metas: &[TenantMeta],
    as_of: Option<NaiveDate>,
) -> anyhow::Result<HashMap<String, f64>> {
    let sql = meter_query(format!(
        "WITH windows AS ( \
            SELECT tupleElement(t,1) AS tenant_id, tupleElement(t,2) AS indexed_window_days \
            FROM (SELECT arrayJoin({lit}) AS t) \
         ) \
         SELECT s.tenant_id AS tenant_id, toFloat64(sum(s.span_bytes)) AS value \
         FROM tracelane.spans AS s \
         INNER JOIN windows AS w ON s.tenant_id = w.tenant_id \
         WHERE s.start_time >= {now} - toIntervalDay(w.indexed_window_days){ingested} \
         GROUP BY s.tenant_id",
        lit = windows_literal(metas),
        now = now_expr(as_of),
        ingested = ingested_filter(as_of, "s.")
    ));
    let rows: Vec<TenantValueRow> = ch.query(&capped(&sql)).fetch_all().await?;
    Ok(rows.into_iter().map(|r| (r.tenant_id, r.value)).collect())
}

/// The series SQL, pure so its boundary text is unit-testable: distinct
/// `(name, model, provider, api_key_id)` per tenant from THAT tenant's
/// `period_start` (the `periods` join) up to the as-of instant. Was
/// `toYYYYMM(start_time) = toYYYYMM(now)` — the calendar month for every
/// tenant — until B-420. `MODEL_EXPR`/`PROVIDER_EXPR` mirror
/// `trace_reads.rs`'s SLO-view expressions verbatim (that file is outside
/// this build's edit scope beyond calling the rehydration helper, so the two
/// literal strings are duplicated rather than shared — same reasoning as
/// `days_since_epoch` above). Unqualified `attributes` / `name` resolve to
/// `spans` — `periods` carries neither column.
fn series_sql(periods_lit: &str, as_of: Option<NaiveDate>) -> String {
    const MODEL_EXPR: &str = "coalesce(nullIf(JSONExtractString(attributes, 'gen_ai_response_model'), ''), nullIf(JSONExtractString(attributes, 'gen_ai_request_model'), ''), nullIf(JSONExtractString(attributes, 'gen_ai.response.model'), ''), JSONExtractString(attributes, 'llm.model_name'))";
    const PROVIDER_EXPR: &str = "coalesce(nullIf(JSONExtractString(attributes, 'gen_ai_provider_name'), ''), nullIf(JSONExtractString(attributes, 'gen_ai_system'), ''), nullIf(JSONExtractString(attributes, 'gen_ai.provider.name'), ''), JSONExtractString(attributes, 'llm.provider'))";
    meter_query(format!(
        "{cte}\
         SELECT s.tenant_id AS tenant_id, \
            toFloat64(uniqExact(name, {MODEL_EXPR}, {PROVIDER_EXPR}, JSONExtractString(attributes, 'tracelane_api_key_id'))) AS value \
         FROM tracelane.spans AS s \
         INNER JOIN periods AS p ON s.tenant_id = p.tenant_id \
         WHERE s.start_time >= toDateTime(p.period_start, 'UTC') AND s.start_time <= {now}{ingested} \
           AND s.name != '{rejected}' \
         GROUP BY s.tenant_id",
        cte = periods_cte(periods_lit),
        now = now_expr(as_of),
        ingested = ingested_filter(as_of, "s."),
        // RI-05 slice 3 (2026-09-20): the aggregate refusal span is a RECORD of
        // load that was shed, not usage — counting it would bill one extra
        // "series" per (tenant, key) that ever hit a limit. Proven against a real
        // ClickHouse in `meter_reads_run_against_a_real_clickhouse`.
        rejected = crate::rejection_metrics::REJECTED_SPAN_NAME,
    ))
}

/// Meter 3: `series` — distinct `(name, model, provider, api_key_id)` since
/// each tenant's OWN billing period started (B-420): its Polar cycle, or the
/// calendar month when none governs. ONE query via the `periods` join.
///
/// This is the value Polar takes `max` over the cycle of
/// (`scripts/ops/polar-sync.mjs`), so anchoring it on the cycle is what
/// makes that max equal the true union — a calendar-month count on a
/// mid-month cycle was the max of two partial months.
async fn query_series(
    ch: &clickhouse::Client,
    metas: &[TenantMeta],
    as_of: Option<NaiveDate>,
) -> anyhow::Result<HashMap<String, f64>> {
    let sql = series_sql(&periods_literal(metas, instant_for(as_of)), as_of);
    let rows: Vec<TenantValueRow> = ch.query(&capped(&sql)).fetch_all().await?;
    Ok(rows.into_iter().map(|r| (r.tenant_id, r.value)).collect())
}

/// Meter 4: `scan_bytes` — `sum(read_bytes)` from `system.query_log` for
/// YESTERDAY, grouped by the tenant parsed out of `log_comment`. The
/// metering job's OWN queries (tagged `tracelane-meter`, never
/// `tenant_id=<uuid>`) are excluded by construction — the `LIKE` filter only
/// matches the tenant-tag shape.
async fn query_scan_bytes_for_day(
    ch: &clickhouse::Client,
    day: NaiveDate,
) -> anyhow::Result<HashMap<String, f64>> {
    let sql = meter_query(format!(
        "SELECT replaceOne(log_comment, 'tenant_id=', '') AS tenant_id, toFloat64(sum(read_bytes)) AS value \
         FROM system.query_log \
         WHERE type = 'QueryFinish' AND log_comment LIKE 'tenant_id=%' \
           AND event_date = toDate('{day}') \
         GROUP BY tenant_id"
    ));
    let rows: Vec<TenantValueRow> = ch.query(&capped(&sql)).fetch_all().await?;
    Ok(rows.into_iter().map(|r| (r.tenant_id, r.value)).collect())
}

/// Meter 5: `cold_bytes` — `sum(span_bytes)` per tenant for rows PAST the
/// indexed window but still inside queryable history. ONE query via the
/// SAME `windows` join as hot, with both bounds.
async fn query_cold_bytes(
    ch: &clickhouse::Client,
    metas: &[TenantMeta],
    as_of: Option<NaiveDate>,
) -> anyhow::Result<HashMap<String, f64>> {
    let sql = meter_query(format!(
        "WITH windows AS ( \
            SELECT tupleElement(t,1) AS tenant_id, tupleElement(t,2) AS indexed_window_days, \
                   tupleElement(t,3) AS queryable_days \
            FROM (SELECT arrayJoin({lit}) AS t) \
         ) \
         SELECT s.tenant_id AS tenant_id, toFloat64(sum(s.span_bytes)) AS value \
         FROM tracelane.spans AS s \
         INNER JOIN windows AS w ON s.tenant_id = w.tenant_id \
         WHERE s.start_time < {now} - toIntervalDay(w.indexed_window_days) \
           AND s.start_time >= {now} - toIntervalDay(w.queryable_days){ingested} \
         GROUP BY s.tenant_id",
        lit = windows_literal(metas),
        now = now_expr(as_of),
        ingested = ingested_filter(as_of, "s.")
    ));
    let rows: Vec<TenantValueRow> = ch.query(&capped(&sql)).fetch_all().await?;
    Ok(rows.into_iter().map(|r| (r.tenant_id, r.value)).collect())
}

#[derive(serde::Deserialize, clickhouse::Row)]
struct DailyTenantValueRow {
    tenant_id: String,
    // READ since B-468 (REV-1): `densify_trailing` places the value at this
    // day's index. It was unread — and the series was therefore sparse — from
    // BILL-01 until 2026-09-20. `clickhouse::Row` decodes RowBinary
    // POSITIONALLY, so the field order must stay tenant_id, day, value.
    //
    // Two rules every SELECT feeding this (or `TenantValueRow`) follows,
    // both learned from prod on 2026-09-16 and both invisible to a unit test:
    // - B-424: the string projection is `AS day_iso`, never `AS day` — a
    //   SELECT alias shadows a same-named column across the WHOLE query in
    //   ClickHouse, so `WHERE day >= toDate(…)` compared String with Date
    //   (`NO_COMMON_TYPE`, code 386) and every trailing read + the gap
    //   backfill failed on every run since BILL-01 shipped.
    // - B-425: an integer aggregate is wrapped `toFloat64(…)` before it lands
    //   in `value: f64` — `sum(span_bytes)` is UInt64 on the wire, and
    //   RowBinary decoded its 8 bytes AS an f64, so hot / cold / scan gauges
    //   were written as denormals (`1.47526e-318` for 298,596 bytes) and
    //   emitted to Polar as ~0. `series` was right only because it already
    //   said `toFloat64(uniqExact(…))`.
    // `meter_reads_run_against_a_real_clickhouse` holds both.
    day: String,
    value: f64,
}

/// The trailing window every burst-netted meter is rated over: 30 days of
/// history + yesterday. A dense series has EXACTLY this many entries.
pub(crate) const TRAILING_DAYS: usize = 31;

/// **B-468 (REV-1, 2026-09-20): the daily series is DENSE and indexed by DATE.**
/// Per tenant, exactly [`TRAILING_DAYS`] entries where index `i` is the day
/// `until_excl - TRAILING_DAYS + i`; a day with no rows is an explicit `0.0`,
/// so the LAST entry is `until_excl - 1` — "yesterday" — by construction.
///
/// Until this, the queries below discarded `day_iso` and pushed values in row
/// order, so the series ended in the last day THAT HAD ROWS: a tenant busy on
/// day D and idle afterwards was billed D's `ingest_gb` / `scan_units` /
/// `eval_runs` on every idle day for 31 days, each under a fresh `external_id`
/// Polar could not dedupe, and the burst average ignored every zero day. A
/// tenant with no rows in the window is ABSENT from the map (unchanged: absent
/// means "nothing to emit"), never a vector of zeros. A row outside the window
/// is a query defect and is dropped with a `debug_assert!` — it must not shift
/// the series.
fn densify_trailing(
    rows: Vec<DailyTenantValueRow>,
    until_excl: NaiveDate,
) -> HashMap<String, Vec<f64>> {
    let start = until_excl - chrono::Duration::days(TRAILING_DAYS as i64);
    let mut out: HashMap<String, Vec<f64>> = HashMap::new();
    for r in rows {
        let Ok(day) = r.day.parse::<NaiveDate>() else {
            debug_assert!(
                false,
                "trailing read projected an unparseable day: {}",
                r.day
            );
            continue;
        };
        let offset = (day - start).num_days();
        let Ok(idx) = usize::try_from(offset) else {
            debug_assert!(
                false,
                "trailing read returned a day before the window: {day}"
            );
            continue;
        };
        if idx >= TRAILING_DAYS {
            debug_assert!(
                false,
                "trailing read returned a day at/after until_excl: {day}"
            );
            continue;
        }
        out.entry(r.tenant_id)
            .or_insert_with(|| vec![0.0; TRAILING_DAYS])[idx] += r.value;
    }
    out
}

/// Trailing 31 days (30 history + yesterday) of `meter_counters` for one
/// `meter`, per tenant, as a DENSE day-indexed `Vec<f64>` ending in yesterday
/// (see [`densify_trailing`]) — the shape `net_of_burst` consumes. ONE query,
/// `GROUP BY tenant_id, day`.
async fn query_trailing_daily_meter_counter(
    ch: &clickhouse::Client,
    meter: &str,
    until_excl: NaiveDate,
) -> anyhow::Result<HashMap<String, Vec<f64>>> {
    let sql = meter_query(format!(
        "SELECT tenant_id AS tenant_id, toString(day) AS day_iso, sum(value) AS value \
         FROM tracelane.meter_counters \
         WHERE meter = '{meter}' AND day >= toDate('{until_excl}') - {TRAILING_DAYS} AND day < toDate('{until_excl}') \
         GROUP BY tenant_id, day ORDER BY tenant_id, day"
    ));
    let rows: Vec<DailyTenantValueRow> = ch.query(&capped(&sql)).fetch_all().await?;
    Ok(densify_trailing(rows, until_excl))
}

/// Trailing 31 days of `system.query_log.read_bytes`, per tenant — the
/// `scan_bytes` analogue of [`query_trailing_daily_meter_counter`], dense the
/// same way.
async fn query_trailing_daily_scan_bytes(
    ch: &clickhouse::Client,
    until_excl: NaiveDate,
) -> anyhow::Result<HashMap<String, Vec<f64>>> {
    let sql = meter_query(format!(
        "SELECT replaceOne(log_comment, 'tenant_id=', '') AS tenant_id, \
            toString(event_date) AS day_iso, toFloat64(sum(read_bytes)) AS value \
         FROM system.query_log \
         WHERE type = 'QueryFinish' AND log_comment LIKE 'tenant_id=%' \
           AND event_date >= toDate('{until_excl}') - {TRAILING_DAYS} AND event_date < toDate('{until_excl}') \
         GROUP BY tenant_id, event_date ORDER BY tenant_id, event_date"
    ));
    let rows: Vec<DailyTenantValueRow> = ch.query(&capped(&sql)).fetch_all().await?;
    Ok(densify_trailing(rows, until_excl))
}

// ── The batched INSERT into meter_gauges ────────────────────────────────────

#[derive(serde::Serialize, clickhouse::Row)]
struct MeterGaugeRow<'a> {
    tenant_id: &'a str,
    day: u16,
    meter: &'a str,
    value: f64,
}

/// ONE batched INSERT covering every (tenant, meter) row this run computed —
/// `hot_resident_bytes` / `series` / `cold_bytes` under TODAY's date,
/// `scan_bytes` under YESTERDAY's (it measures a day that has already fully
/// elapsed). A re-run for the same day REPLACES on the next merge
/// (`ReplacingMergeTree(computed_at)`), never doubles.
///
/// **B-470 (REV-1, 2026-09-20): this no longer writes the day's completion
/// marker.** It used to land in the same batch, BEFORE the Polar events were
/// sent, so a failed POST left a marked day the gap backfill would never
/// revisit — that day's revenue events were lost for good, behind one WARN.
/// The marker is now [`write_completion_marker`], written by the caller only
/// after every read AND every emission for the day succeeded.
///
/// # Errors
/// Propagates a ClickHouse failure; the caller notes
/// [`tracelane_shared::degradation::Degradation::MeteringJobFailed`], withholds
/// the marker, and the next scheduled run recomputes the day — no partial-write
/// recovery is attempted here (the whole run failed, not one row of it).
async fn write_gauges(
    ch: &clickhouse::Client,
    today: NaiveDate,
    yesterday: NaiveDate,
    hot: &HashMap<String, f64>,
    series: &HashMap<String, f64>,
    scan: &HashMap<String, f64>,
    cold: &HashMap<String, f64>,
) -> anyhow::Result<usize> {
    let today_u16 = days_since_epoch(today);
    let yesterday_u16 = days_since_epoch(yesterday);
    let mut n = 0usize;
    let mut insert = ch
        .insert("meter_gauges")
        .map_err(|e| anyhow::anyhow!("meter_gauges insert init failed: {e}"))?;
    for (day, meter, map) in [
        (today_u16, "hot_resident_bytes", hot),
        (today_u16, "series", series),
        (yesterday_u16, "scan_bytes", scan),
        (today_u16, "cold_bytes", cold),
    ] {
        for (tenant_id, value) in map {
            insert
                .write(&MeterGaugeRow {
                    tenant_id,
                    day,
                    meter,
                    value: *value,
                })
                .await
                .map_err(|e| anyhow::anyhow!("meter_gauges row write failed: {e}"))?;
            n += 1;
        }
    }
    insert
        .end()
        .await
        .map_err(|e| anyhow::anyhow!("meter_gauges insert commit failed: {e}"))?;
    Ok(n)
}

/// The day's completion marker — one row under the reserved tenant id. **"The
/// marker exists" ⇔ "every gauge for `day` landed AND every Polar event for it
/// was accepted"** (B-470). The gap backfill skips marked days and the boot
/// catch-up trusts the marker, so it is written LAST, after the emissions, and
/// never when any of them failed. The usage route can never read it (it reads
/// by a real tenant id).
///
/// # Errors
/// Propagates a ClickHouse failure; the caller notes `MeteringJobFailed`. An
/// unmarked completed day is recomputed by the next run — gauges REPLACE and
/// events dedupe on `external_id`, so the retry is idempotent.
async fn write_completion_marker(ch: &clickhouse::Client, day: NaiveDate) -> anyhow::Result<()> {
    let marker_tenant = JOB_MARKER_TENANT.to_string();
    let mut insert = ch
        .insert("meter_gauges")
        .map_err(|e| anyhow::anyhow!("meter_gauges marker insert init failed: {e}"))?;
    insert
        .write(&MeterGaugeRow {
            tenant_id: &marker_tenant,
            day: days_since_epoch(day),
            meter: JOB_MARKER_METER,
            value: 1.0,
        })
        .await
        .map_err(|e| anyhow::anyhow!("meter_gauges marker write failed: {e}"))?;
    insert
        .end()
        .await
        .map_err(|e| anyhow::anyhow!("meter_gauges marker commit failed: {e}"))
}

// ── Polar emission ───────────────────────────────────────────────────────

/// One (meter, GB/unit value) pair ready to emit, already netted/shared as
/// its meter requires.
struct PolarEvent {
    name: &'static str,
    value: f64,
}

/// Build this tenant's Polar events for `period` from what the job just
/// computed. Pure (no I/O) so the per-meter arithmetic — burst netting,
/// GB-month sharing — is independently testable.
///
/// `days_in_period` is THIS tenant's billing period length (its Polar cycle,
/// or the calendar month — B-410); `series_period` is the distinct-series
/// count since that period started, and the caller passes `None` when the
/// reading is not cycle-true (a stale stored cycle): `series` is `max`-
/// aggregated over the cycle on Polar's side, so a too-high reading would
/// stick on the invoice, whereas a skipped day costs nothing — the next
/// cycle-true reading is the max anyway.
#[allow(clippy::too_many_arguments)]
fn tenant_polar_events(
    burst_multiple: f64,
    days_in_period: u32,
    hot_bytes_today: Option<f64>,
    series_period: Option<f64>,
    cold_bytes_today: Option<f64>,
    eval_runs_yesterday: Option<f64>,
    ingest_trailing_daily: Option<&[f64]>,
    scan_trailing_daily: Option<&[f64]>,
) -> Vec<PolarEvent> {
    let mut events = Vec::new();
    if let Some(daily) = ingest_trailing_daily {
        let net_bytes = net_of_burst(daily, burst_multiple);
        if net_bytes > 0.0 {
            events.push(PolarEvent {
                name: "ingest_gb",
                value: gb(net_bytes),
            });
        }
    }
    if let Some(bytes) = hot_bytes_today {
        events.push(PolarEvent {
            name: "hot_gb_month",
            value: gb_month_share(bytes, days_in_period),
        });
    }
    if let Some(v) = series_period {
        events.push(PolarEvent {
            name: "series",
            value: v,
        });
    }
    if let Some(daily) = scan_trailing_daily {
        let net_bytes = net_of_burst(daily, burst_multiple);
        if net_bytes > 0.0 {
            events.push(PolarEvent {
                name: "scan_units",
                value: gb(net_bytes),
            });
        }
    }
    if let Some(bytes) = cold_bytes_today {
        events.push(PolarEvent {
            name: "cold_gb_month",
            value: gb_month_share(bytes, days_in_period),
        });
    }
    if let Some(v) = eval_runs_yesterday {
        events.push(PolarEvent {
            name: "eval_runs",
            value: v,
        });
    }
    events
}

/// Emit this tenant's events through `PolarClient::record_meter_events` — ONE
/// batched POST (`polar_sync.mjs` configures every one of the six Polar
/// meters in GB with fractional `metered_tiers` bands, so `metadata.value`
/// carries the REAL fractional GB figure now — no unit scaling of any kind;
/// `record_meter_event`/`record_meter_events` both take `f64`).
///
/// Zero-valued events are dropped before the call — a fully burst-exempt
/// `ingest_gb`/`scan_units` day already arrives as `0.0` from
/// [`tenant_polar_events`], and an idle tenant's `hot_gb_month` /
/// `cold_gb_month` / `series` / `eval_runs` can genuinely be exactly zero;
/// Polar gains nothing from a `{"value":0}` event and it is one more row an
/// operator reading `/events` has to mentally discard.
///
/// `external_id = "<meter>-<customer>-<period>"` makes a retried run
/// idempotent (Polar dedupes on it). **A failed POST returns `Err(())`** so the
/// caller withholds the day's completion marker (B-470) and the next run's
/// gap backfill recomputes and re-emits the WHOLE day under the same ids —
/// that, not "the next tick", is the retry.
///
/// # Errors
/// `Err(())` when Polar did not accept the batch; the failure is already
/// logged and counted here (`PolarMeterEmissionFailed`), the caller only
/// decides about the marker.
async fn emit_polar_events(
    polar: &PolarClient,
    customer_id: &str,
    period: NaiveDate,
    events: &[PolarEvent],
) -> Result<(), ()> {
    let billable: Vec<&PolarEvent> = events.iter().filter(|ev| ev.value > 0.0).collect();
    if billable.is_empty() {
        return Ok(());
    }
    let customer = PolarCustomerId(customer_id.to_string());
    let external_ids: Vec<String> = billable
        .iter()
        .map(|ev| format!("{}-{customer_id}-{period}", ev.name))
        .collect();
    let batch: Vec<crate::billing::polar_client::MeterEvent<'_>> = billable
        .iter()
        .zip(external_ids.iter())
        .map(
            |(ev, external_id)| crate::billing::polar_client::MeterEvent {
                name: ev.name,
                customer_id: &customer,
                value: ev.value,
                idempotency_key: external_id,
            },
        )
        .collect();
    if let Err(e) = polar.record_meter_events(&batch).await {
        tracing::warn!(
            customer_id,
            count = batch.len(),
            error = %e,
            "Polar meter events batch POST failed — the day's completion marker is withheld and the gap backfill re-emits it"
        );
        tracelane_shared::degradation::note(
            tracelane_shared::degradation::Degradation::PolarMeterEmissionFailed,
        );
        return Err(());
    }
    Ok(())
}

// ── AUTO-AGE (spec §0.4) ─────────────────────────────────────────────────
//
// A customer-set spend ceiling (opt-in, off by default) never blocks
// ingest (`.claude/rules/billing.md`: "ingest is NEVER blocked by billing
// state"). Instead, once the month's projected overage would exceed it and
// the tenant is on `overflow_mode = AutoAge` (the default — `AutoOverage`
// tenants keep billing past the ceiling by their own choice), the daily job
// narrows `auto_age_window_days` so the indexed (hot) window shrinks and the
// oldest data ages into cold storage EARLY. Nothing is deleted — cold data
// stays queryable out to `queryable_days` — and the job widens the window
// back, or clears the shrink entirely, the moment usage drops enough to fit
// at the full plan window again.

/// The period-to-date counter SQL, pure for the boundary-text test: `sum` of
/// one `meter_counters` meter per tenant over `[period_start, day]`, each
/// tenant's own `period_start` from the `periods` join. Was `day >=
/// toStartOfMonth(today())` — the calendar month for everyone — until B-410.
/// `c.day` is qualified on purpose: a SELECT alias shadows a same-named
/// column across the whole query on the server (B-424), and the `tenant_id`
/// alias here must not be read where `p.tenant_id` is meant.
fn period_counter_sql(meter: &str, periods_lit: &str, day: NaiveDate) -> String {
    meter_query(format!(
        "{cte}\
         SELECT c.tenant_id AS tenant_id, sum(c.value) AS value \
         FROM tracelane.meter_counters AS c \
         INNER JOIN periods AS p ON c.tenant_id = p.tenant_id \
         WHERE c.meter = '{meter}' AND c.day >= p.period_start AND c.day <= toDate('{day}') \
         GROUP BY c.tenant_id",
        cte = periods_cte(periods_lit),
    ))
}

/// Period-to-date total for one `meter_counters` meter, per tenant, at `at`
/// — each tenant's Polar cycle (or calendar month) start, the SAME window
/// `GET /v1/billing/usage` bills from (this replaced the rolling-31-day
/// approximation the usage-warning email path used before BILL-01's fix, and
/// B-410 replaced the calendar month with the cycle; see its call site in
/// [`run_once`]). ONE query, `GROUP BY tenant_id` — no per-tenant loop.
async fn query_period_to_date_meter_counter(
    ch: &clickhouse::Client,
    meter: &str,
    metas: &[TenantMeta],
    at: chrono::DateTime<Utc>,
) -> anyhow::Result<HashMap<String, f64>> {
    let sql = period_counter_sql(meter, &periods_literal(metas, at), at.date_naive());
    let rows: Vec<TenantValueRow> = ch.query(&capped(&sql)).fetch_all().await?;
    Ok(rows.into_iter().map(|r| (r.tenant_id, r.value)).collect())
}

/// The period-to-date scan SQL, pure for the boundary-text test — the
/// `system.query_log.read_bytes` analogue of [`period_counter_sql`]. The
/// tenant is parsed out of `log_comment` in a subquery so the join is on a
/// plain column; the job's own reads (tagged `tracelane-meter`) never match
/// the `tenant_id=%` shape, so they are excluded by construction.
fn period_scan_sql(periods_lit: &str, day: NaiveDate) -> String {
    meter_query(format!(
        "{cte}\
         SELECT ql.tenant_id AS tenant_id, toFloat64(sum(ql.read_bytes)) AS value \
         FROM ( \
            SELECT replaceOne(log_comment, 'tenant_id=', '') AS tenant_id, event_date, read_bytes \
            FROM system.query_log \
            WHERE type = 'QueryFinish' AND log_comment LIKE 'tenant_id=%' \
         ) AS ql \
         INNER JOIN periods AS p ON ql.tenant_id = p.tenant_id \
         WHERE ql.event_date >= p.period_start AND ql.event_date <= toDate('{day}') \
         GROUP BY ql.tenant_id",
        cte = periods_cte(periods_lit),
    ))
}

/// Period-to-date `system.query_log.read_bytes`, per tenant, at `at` — the
/// `scan_bytes` analogue of [`query_period_to_date_meter_counter`], same
/// per-tenant boundary.
async fn query_period_to_date_scan_bytes(
    ch: &clickhouse::Client,
    metas: &[TenantMeta],
    at: chrono::DateTime<Utc>,
) -> anyhow::Result<HashMap<String, f64>> {
    let sql = period_scan_sql(&periods_literal(metas, at), at.date_naive());
    let rows: Vec<TenantValueRow> = ch.query(&capped(&sql)).fetch_all().await?;
    Ok(rows.into_iter().map(|r| (r.tenant_id, r.value)).collect())
}

/// AUTO-AGE §0.4: find the LARGEST window `w` (whole days, `1..=plan_window`)
/// such that `fits(w)` — the total projected overage USD with the
/// hot-window meter re-projected at window `w` — is at or under
/// `ceiling_usd`. `fits` is monotonically non-decreasing in `w` (a wider hot
/// window can only ever include MORE resident bytes, never fewer), so a
/// standard integer binary search applies.
///
/// Returns `None` when the FULL plan window already fits — the caller reads
/// that as "nothing to shrink; clear any existing narrowing." Returns
/// `Some(1)` when even the narrowest possible window does not fit (the
/// ceiling is simply too low for this tenant's other five meters alone) —
/// AUTO-AGE floors at one day rather than a nonsensical zero; it never
/// blocks ingest regardless.
fn find_auto_age_window(
    plan_window_days: i32,
    ceiling_usd: f64,
    fits: impl Fn(i32) -> f64,
) -> Option<i32> {
    if plan_window_days < 1 {
        return None;
    }
    if fits(plan_window_days) <= ceiling_usd {
        return None;
    }
    if fits(1) > ceiling_usd {
        return Some(1);
    }
    let (mut lo, mut hi) = (1i32, plan_window_days);
    while lo < hi {
        let mid = lo + (hi - lo + 1) / 2;
        if fits(mid) <= ceiling_usd {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    Some(lo)
}

/// Rate this tenant's period-to-date overage USD across all six meters
/// (the SAME [`rating::rate`] `GET /v1/billing/usage` rates with, over the
/// SAME window — the tenant's Polar cycle, or the calendar month, B-410) and,
/// if it would exceed a configured ceiling under `overflow_mode = AutoAge`,
/// narrow `auto_age_window_days` to the largest window that fits — or widen
/// it back / clear it once usage no longer needs the shrink.
///
/// A tenant with no ceiling set, or on `AutoOverage` (opted to keep billing
/// past the ceiling instead), never gets NARROWED — but if either was true
/// of a PRIOR run and this tenant is already sitting on a stale
/// `auto_age_window_days` from back when it WAS on `AutoAge`, that shrink is
/// still cleared here rather than left in place forever: removing a ceiling
/// or switching away from `AutoAge` is a customer choice to stop narrowing,
/// which should not also leave a narrower window behind as an accident of
/// timing.
///
/// `cold_gb_month` contributes zero to the projection: `GET
/// /v1/billing/usage`'s own `cold_view` never routes it through `rate()`
/// either (it hardcodes `overage_usd: Some(0.0)`) — mirroring that here
/// rather than inventing a second, disagreeing cold-billing model.
///
/// Not burst-exact for the burst-exempt meters (ingest/scan): this does not
/// re-derive a per-day burst exemption over the whole period, unlike
/// `GET /v1/billing/usage`. Same reasoning as the usage-warning email path
/// right below this function's caller: this is a CONTROL that narrows a
/// window, never a bill, and treating the full raw period sum as billable
/// is the conservative (safe) direction — it can only trigger AUTO-AGE a
/// little earlier than the exact figure would, never later.
///
/// No days-elapsed / days-total arithmetic happens here: the figures are
/// rated as accrued so far, not projected to period end, exactly as the
/// usage page's `overage_usd` (and therefore its `ceiling_reached`) is.
///
/// `ingest_period`/`series_period`/`scan_period`/`eval_period` are read from
/// the SAME global, `GROUP BY tenant_id` per-run maps the usage-warning email
/// path (right below) also consumes — not a per-tenant query. The only
/// figure genuinely specific to this tenant's own arithmetic is
/// `hot_bytes_at_current_window`, which the job already computed globally
/// too (`hot.get(&key)`); no ClickHouse round trip happens in this
/// function at all.
///
/// # Errors
/// Fail-open (CLAUDE.md §10): an update failure is logged + noted via
/// [`tracelane_shared::degradation::Degradation::MeteringJobFailed`] and
/// simply retried next scheduled run — ingest is never blocked either way.
#[allow(clippy::too_many_arguments)]
async fn apply_auto_age(
    pool: &DbPool,
    card: &RateCard,
    meta: &TenantMeta,
    resolved: &crate::entitlement_cache::ResolvedEntitlements,
    entitlements: &EntitlementCache,
    hot_bytes_at_current_window: Option<f64>,
    series_period: Option<f64>,
    ingest_period: Option<f64>,
    scan_period: Option<f64>,
    eval_period: Option<f64>,
) {
    use crate::billing::rating::{self, RatedMeter};
    use crate::entitlement_cache::OverflowMode;

    // Not eligible to be narrowed: no ceiling, or the tenant chose to keep
    // billing past it (`AutoOverage`). `new_window = None` still runs
    // through the SAME write/log/invalidate path below, which is what
    // clears a STALE shrink left over from when this tenant WAS on
    // `AutoAge` with a ceiling (see this fn's own doc) — never an early
    // `return` that would leave that shrink in place forever.
    let eligible = matches!(
        (resolved.spend_ceiling_micro_usd, resolved.overflow_mode),
        (Some(_), OverflowMode::AutoAge)
    );
    if !eligible && meta.auto_age_window_days.is_none() {
        return; // Nothing narrowed, nothing to clear — the common case.
    }

    let plan_window = meta.indexed_window_days;
    let new_window = if eligible {
        let ceiling_usd = resolved
            .spend_ceiling_micro_usd
            .map_or(0.0, |m| m as f64 / 1_000_000.0);
        let current_window = meta.effective_window_days();
        let ingest_included_gb = resolved.ingest_bytes_included.map(|b| b as f64 / 1e9);
        let hot_included_gb = resolved.hot_bytes_included.map(|b| b as f64 / 1e9);
        let series_included = resolved.series_included.map(|v| v as f64);
        let scan_included = resolved.scan_units_included.map(|v| v as f64);
        let eval_included = resolved.eval_runs_included.map(|v| v as f64);

        // Every meter but hot is fixed for the whole search — only the
        // hot-window figure changes as candidate windows are tried.
        let fixed_overage_usd = rating::rate(
            card,
            RatedMeter::IngestGb,
            gb(ingest_period.unwrap_or(0.0)),
            ingest_included_gb,
            0.0,
        )
        .overage_usd
            + rating::rate(
                card,
                RatedMeter::Series,
                series_period.unwrap_or(0.0),
                series_included,
                0.0,
            )
            .overage_usd
            + rating::rate(
                card,
                RatedMeter::ScanUnits,
                gb(scan_period.unwrap_or(0.0)),
                scan_included,
                0.0,
            )
            .overage_usd
            + rating::rate(
                card,
                RatedMeter::EvalRuns,
                eval_period.unwrap_or(0.0),
                eval_included,
                0.0,
            )
            .overage_usd;

        let hot_bytes = hot_bytes_at_current_window.unwrap_or(0.0);
        let fits = |w: i32| -> f64 {
            let scale = if current_window > 0 {
                f64::from(w) / f64::from(current_window)
            } else {
                0.0
            };
            let hot_gb_month = gb(hot_bytes * scale);
            fixed_overage_usd
                + rating::rate(
                    card,
                    RatedMeter::HotGbMonth,
                    hot_gb_month,
                    hot_included_gb,
                    0.0,
                )
                .overage_usd
        };

        find_auto_age_window(plan_window, ceiling_usd, fits)
    } else {
        None
    };
    if new_window == meta.auto_age_window_days {
        return; // No state transition — nothing to write or log.
    }

    let client = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(tenant_id = %meta.tenant_id, error = %e, "auto-age: pool checkout failed");
            tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::MeteringJobFailed,
            );
            return;
        }
    };

    let write_result = match new_window {
        Some(w) => {
            client
                .execute(
                    "UPDATE tenants SET auto_age_window_days = $2, \
                     auto_age_since = COALESCE(auto_age_since, now()) WHERE id = $1",
                    &[&meta.tenant_id, &w],
                )
                .await
        }
        None => {
            client
                .execute(
                    "UPDATE tenants SET auto_age_window_days = NULL, auto_age_since = NULL \
                     WHERE id = $1",
                    &[&meta.tenant_id],
                )
                .await
        }
    };
    if let Err(e) = write_result {
        tracing::warn!(tenant_id = %meta.tenant_id, error = %e, "auto-age: tenants update failed");
        tracelane_shared::degradation::note(
            tracelane_shared::degradation::Degradation::MeteringJobFailed,
        );
        return;
    }

    // ONE info per ACTUAL state transition (`.claude/rules/logging.md`) —
    // never per tick, since most ticks are `if new_window ==
    // meta.auto_age_window_days` and return above without reaching here.
    match new_window {
        Some(w) => tracing::info!(
            tenant_id = %meta.tenant_id,
            auto_age_window_days = w,
            plan_window_days = plan_window,
            ceiling_usd = resolved.spend_ceiling_micro_usd.map(|m| m as f64 / 1_000_000.0),
            "auto-age: indexed window narrowed to fit the spend ceiling"
        ),
        None => tracing::info!(
            tenant_id = %meta.tenant_id,
            plan_window_days = plan_window,
            "auto-age: cleared — usage now fits at the full plan window"
        ),
    }

    entitlements.invalidate(meta.tenant_id).await;
}

// ── One full run ─────────────────────────────────────────────────────────

/// One complete daily run: fetch tenant metadata, run the four (well, six —
/// see the module doc) ClickHouse reads, write the gauges, emit to Polar,
/// send usage-warning emails.
///
/// # Errors
/// Only when the tenant-metadata Postgres read itself fails — every
/// PER-METER ClickHouse failure is caught, logged, noted, and simply
/// excludes that meter from this run's gauges/emissions/emails rather than
/// aborting the whole run (a `system.query_log` hiccup must not also blank
/// out `hot_resident_bytes`, which reads a different table).
/// How far back a missed day is recomputed. Seven days covers a weekend
/// outage with margin; beyond that the trailing-30-day burst window the
/// ingest event needs is itself partial, and a month-old gap is an incident,
/// not a backfill.
const GAP_LOOKBACK_DAYS: i64 = 7;

#[derive(serde::Deserialize, clickhouse::Row)]
struct DayRow {
    day: String,
}

/// Did the job COMPLETE on `day`? The job writes one MARKER gauge per run under
/// the reserved tenant id `__metering_job__` (`JOB_MARKER_TENANT`, `write_gauges`),
/// so this filters on a tenant_id like every other read of `tracelane.*` and asks
/// the exact question rather than "does any tenant happen to have a gauge row".
///
/// `day = toDate(?)` with the ISO string — NOT the `u16` the WRITER binds: RowBinary
/// accepts days-since-epoch for a `Date` column on INSERT, but in a WHERE clause
/// `Date = UInt16` is ILLEGAL_TYPE_OF_ARGUMENT (43) on the server (B-426).
/// `meter_reads_run_against_a_real_clickhouse` holds it.
///
/// # Errors
/// The ClickHouse error; the boot caller fails OPEN on it and says so.
async fn job_completed_on(ch: &clickhouse::Client, day: NaiveDate) -> anyhow::Result<bool> {
    let n: u64 = ch
        .query(&capped(
            "SELECT count() FROM tracelane.meter_gauges \
             WHERE tenant_id = '__metering_job__' AND meter = 'job_completed' AND day = toDate(?)",
        ))
        .bind(day.to_string())
        .fetch_one()
        .await?;
    Ok(n > 0)
}

/// Days in `[since, until)` that carry the job's marker row — i.e. days the
/// job completed.
async fn query_completed_days(
    ch: &clickhouse::Client,
    since: NaiveDate,
    until_excl: NaiveDate,
) -> anyhow::Result<std::collections::HashSet<NaiveDate>> {
    let sql = meter_query(format!(
        "SELECT toString(day) AS day_iso FROM tracelane.meter_gauges \
         WHERE tenant_id = '{JOB_MARKER_TENANT}' \
           AND day >= toDate('{since}') AND day < toDate('{until_excl}') \
         GROUP BY day"
    ));
    let rows: Vec<DayRow> = ch.query(&capped(&sql)).fetch_all().await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| r.day.parse::<NaiveDate>().ok())
        .collect())
}

/// Recompute and write every missed day in the lookback, oldest first, and
/// emit its Polar events. Returns how many days were backfilled.
async fn backfill_missed_days(
    ch: &clickhouse::Client,
    metas: &[TenantMeta],
    today: NaiveDate,
    card: &RateCard,
    polar: Option<&PolarClient>,
) -> anyhow::Result<usize> {
    let since = today - chrono::Duration::days(GAP_LOOKBACK_DAYS);
    let done = query_completed_days(ch, since, today).await?;
    let mut n = 0usize;
    for offset in (1..=GAP_LOOKBACK_DAYS).rev() {
        let day = today - chrono::Duration::days(offset);
        if done.contains(&day) {
            continue;
        }
        let prev = day - chrono::Duration::days(1);
        let hot = query_hot_resident_bytes(ch, metas, Some(day)).await?;
        let series = query_series(ch, metas, Some(day)).await?;
        let scan = query_scan_bytes_for_day(ch, prev).await?;
        let cold = query_cold_bytes(ch, metas, Some(day)).await?;
        write_gauges(ch, day, prev, &hot, &series, &scan, &cold).await?;
        // B-470: the marker is written only when EVERY tenant's events for this
        // day were accepted. A day with a refused POST stays unmarked and is
        // retried, oldest first, by the next run — under the same external ids.
        let mut all_emitted = true;
        if let Some(polar) = polar {
            let ingest_trailing =
                query_trailing_daily_meter_counter(ch, "ingest_bytes", day).await?;
            let scan_trailing = query_trailing_daily_scan_bytes(ch, day).await?;
            let eval_trailing = query_trailing_daily_meter_counter(ch, "eval_runs", day).await?;
            let at = instant_for(Some(day));
            for meta in metas {
                let Some(customer_id) = meta.polar_customer_id.as_deref() else {
                    continue;
                };
                let key = meta.tenant_id.to_string();
                // A day outside the tenant's CURRENT cycle (before it began,
                // or a stale cycle) was rated over its calendar month; that
                // reading must not reach Polar's `max` — see
                // `tenant_polar_events`. No warn here: a backfilled day
                // predating the cycle is expected, not a missing webhook.
                let period = meta.period_at(at);
                let series_for_polar = if period.ignored_cycle(meta.billing_period) {
                    None
                } else {
                    series.get(&key).copied()
                };
                let events = tenant_polar_events(
                    card.policy.burst_multiple,
                    period.total_days(),
                    hot.get(&key).copied(),
                    series_for_polar,
                    cold.get(&key).copied(),
                    eval_trailing.get(&key).and_then(|d| d.last().copied()),
                    ingest_trailing.get(&key).map(Vec::as_slice),
                    scan_trailing.get(&key).map(Vec::as_slice),
                );
                if !events.is_empty()
                    && emit_polar_events(polar, customer_id, prev, &events)
                        .await
                        .is_err()
                {
                    // Keyed on `prev`, exactly as the live run keys on
                    // yesterday, so a re-run never double-emits a day.
                    all_emitted = false;
                }
            }
        }
        if all_emitted {
            write_completion_marker(ch, day).await?;
            tracing::warn!(%day, "metering job: missed day recomputed as of that day, written and emitted");
        } else {
            tracing::warn!(
                %day,
                "metering job: missed day recomputed and written, but a Polar emission failed — marker withheld, retried next run"
            );
        }
        n += 1;
    }
    Ok(n)
}

/// B-437: a scheduled run that returned `Ok` AND noted no new failure / gap backfill
/// ends those two episodes on `/health` — `run_once` counts its own sub-failures
/// through `try_query!`, so "returned Ok" alone is not "clean"; the counters are.
/// Idempotent (resolve is a no-op when nothing is open).
fn resolve_after_clean_run(failed_before: u64, gaps_before: u64) {
    use tracelane_shared::degradation::{Degradation, count, resolve};
    if count(Degradation::MeteringJobFailed) == failed_before {
        resolve(Degradation::MeteringJobFailed);
    }
    if count(Degradation::MeteringGaugeGapBackfilled) == gaps_before {
        resolve(Degradation::MeteringGaugeGapBackfilled);
    }
}

pub async fn run_once(
    pool: &DbPool,
    ch_url: &str,
    card: &RateCard,
    polar: Option<&PolarClient>,
    resend: Option<&ResendSettings>,
    entitlements: Option<&EntitlementCache>,
) -> anyhow::Result<()> {
    let metas = fetch_tenant_meta(pool).await?;
    if metas.is_empty() {
        return Ok(());
    }
    let ch = crate::clickhouse_query::ch_client(ch_url.to_string());
    // ONE instant for the whole run: every period literal below is built from
    // it, so the series read, the three period-to-date sums and each tenant's
    // GB-month share all agree on which cycle governs.
    let now = Utc::now();
    let today = now.date_naive();
    let yesterday = today - chrono::Duration::days(1);

    // B-470: `true` only while every read and every Polar emission of this run
    // succeeded. The day's completion marker is written iff it is still true at
    // the end — a run that lost a read or a POST proceeds (fail-open for the
    // meters it did read) but leaves the day UNMARKED so the next run's gap
    // backfill recomputes and re-emits it. Before this, the marker landed
    // before the first POST and a Polar outage lost the day's events for good.
    let mut run_clean = true;
    macro_rules! try_query {
        ($fut:expr, $name:literal) => {
            match $fut.await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, meter = $name, "metering job: query failed for this run — the day's completion marker will be withheld");
                    tracelane_shared::degradation::note(
                        tracelane_shared::degradation::Degradation::MeteringJobFailed,
                    );
                    run_clean = false;
                    HashMap::new()
                }
            }
        };
    }

    let hot = try_query!(
        query_hot_resident_bytes(&ch, &metas, None),
        "hot_resident_bytes"
    );
    let series = try_query!(query_series(&ch, &metas, None), "series");
    let scan = try_query!(query_scan_bytes_for_day(&ch, yesterday), "scan_bytes");
    let cold = try_query!(query_cold_bytes(&ch, &metas, None), "cold_bytes");
    let ingest_trailing = try_query!(
        query_trailing_daily_meter_counter(&ch, "ingest_bytes", today),
        "ingest_bytes_trailing"
    );
    let scan_trailing = try_query!(
        query_trailing_daily_scan_bytes(&ch, today),
        "scan_bytes_trailing"
    );
    let eval_yesterday = try_query!(
        query_trailing_daily_meter_counter(&ch, "eval_runs", today),
        "eval_runs_trailing"
    );
    // Period-to-date sums over each tenant's OWN billing period (its Polar
    // cycle, else the calendar month — B-410) — the SAME window `GET
    // /v1/billing/usage` bills from. Feeds BOTH the usage-warning email check
    // below (replacing its old rolling-31-day approximation) and the AUTO-AGE
    // ceiling rating, so the two never disagree with each other, with the
    // usage page, or with the invoice.
    let ingest_period = try_query!(
        query_period_to_date_meter_counter(&ch, "ingest_bytes", &metas, now),
        "ingest_bytes_period"
    );
    let eval_period = try_query!(
        query_period_to_date_meter_counter(&ch, "eval_runs", &metas, now),
        "eval_runs_period"
    );
    let scan_period = try_query!(
        query_period_to_date_scan_bytes(&ch, &metas, now),
        "scan_bytes_period"
    );

    if let Err(e) = write_gauges(&ch, today, yesterday, &hot, &series, &scan, &cold).await {
        tracing::warn!(error = %e, "metering job: meter_gauges write failed for this run — the day's completion marker will be withheld");
        tracelane_shared::degradation::note(
            tracelane_shared::degradation::Degradation::MeteringJobFailed,
        );
        run_clean = false;
    }
    // Founder, 2026-09-14 (B6 audit item D): an outage spanning 04:10 used to
    // lose a day's revenue silently — a missed sample is absent (never zero)
    // in the dashboard's mean, and its Polar events were never emitted. Every
    // day in the lookback without the job's marker row is recomputed AS OF
    // that day and written under it, its Polar events emitted under that
    // day's idempotency key, and the gap is WARNED once through the
    // degradation counter the watchdog reads.
    match backfill_missed_days(&ch, &metas, today, card, polar).await {
        Ok(0) => {}
        Ok(n) => {
            tracing::warn!(
                days = n,
                "metering job: backfilled {n} missed day(s) from ClickHouse"
            );
            tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::MeteringGaugeGapBackfilled,
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "metering job: gap backfill failed for this run");
            tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::MeteringJobFailed,
            );
        }
    }

    for meta in &metas {
        let key = meta.tenant_id.to_string();
        let ingest_daily = ingest_trailing.get(&key).map(Vec::as_slice);
        let scan_daily = scan_trailing.get(&key).map(Vec::as_slice);
        let eval_daily = eval_yesterday.get(&key).map(Vec::as_slice);
        let hot_bytes = hot.get(&key).copied();
        let series_val = series.get(&key).copied();
        let cold_bytes = cold.get(&key).copied();
        let eval_val = eval_daily.and_then(|d| d.last().copied());

        // This tenant's billing period at the run's instant (B-410): its
        // stored Polar cycle when that governs, else the calendar month —
        // and ONE warn per run when a stored cycle had to be ignored.
        let period = meta.period_at(now);
        meta.warn_if_cycle_ignored(&period);
        // `series` is max-aggregated on Polar's side; a calendar-month
        // reading under a stale cycle must not reach it (see
        // `tenant_polar_events`).
        let series_for_polar = if period.ignored_cycle(meta.billing_period) {
            None
        } else {
            series_val
        };

        let events = tenant_polar_events(
            card.policy.burst_multiple,
            period.total_days(),
            hot_bytes,
            series_for_polar,
            cold_bytes,
            eval_val,
            ingest_daily,
            scan_daily,
        );
        if let (Some(polar), Some(customer_id)) = (polar, meta.polar_customer_id.as_deref())
            && !events.is_empty()
            && emit_polar_events(polar, customer_id, yesterday, &events)
                .await
                .is_err()
        {
            run_clean = false;
        }

        let ingest_period_val = ingest_period.get(&key).copied();
        let scan_period_val = scan_period.get(&key).copied();
        let eval_period_val = eval_period.get(&key).copied();

        if let Some(ents) = entitlements {
            let resolved = ents.resolved(meta.tenant_id).await;

            if let Some(resend) = resend {
                // Exact period-to-date sum over the tenant's billing period —
                // the SAME number `GET /v1/billing/usage` bills from, not the
                // rolling-31-day approximation this used before BILL-01's
                // fix and not the calendar month it used before B-410 (a
                // window that disagrees with the number the usage page shows
                // is exactly the class of bug a WARNING about that number
                // must not have).
                let usages = [
                    crate::billing::email::MeterUsage {
                        meter: "ingest",
                        used: gb(ingest_period_val.unwrap_or(0.0)),
                        included: resolved.ingest_bytes_included.map(|b| b as f64 / 1e9),
                    },
                    crate::billing::email::MeterUsage {
                        meter: "hot",
                        used: gb(hot_bytes.unwrap_or(0.0)),
                        included: resolved.hot_bytes_included.map(|b| b as f64 / 1e9),
                    },
                    crate::billing::email::MeterUsage {
                        meter: "series",
                        used: series_val.unwrap_or(0.0),
                        included: resolved.series_included.map(|v| v as f64),
                    },
                    crate::billing::email::MeterUsage {
                        meter: "query",
                        used: gb(scan_period_val.unwrap_or(0.0)),
                        included: resolved.scan_units_included.map(|v| v as f64),
                    },
                    crate::billing::email::MeterUsage {
                        meter: "cold",
                        used: gb(cold_bytes.unwrap_or(0.0)),
                        included: resolved.cold_bytes_included.map(|b| b as f64 / 1e9),
                    },
                    crate::billing::email::MeterUsage {
                        meter: "evals",
                        used: eval_period_val.unwrap_or(0.0),
                        included: resolved.eval_runs_included.map(|v| v as f64),
                    },
                ];
                // The dedup key (`meter_warnings.period`) is the billing
                // period's first day — a new Polar cycle re-arms the 75% /
                // 90% warnings, exactly as a new month did before B-410.
                crate::billing::email::send_usage_warnings_for_tenant(
                    pool,
                    &resend.http,
                    resend.api_key.as_ref(),
                    &resend.from,
                    meta.tenant_id,
                    meta.billing_email.as_deref(),
                    period.start,
                    &card.policy.warn_pct,
                    &usages,
                )
                .await;
            }

            apply_auto_age(
                pool,
                card,
                meta,
                &resolved,
                ents,
                hot_bytes,
                series_val,
                ingest_period_val,
                scan_period_val,
                eval_period_val,
            )
            .await;
        }
    }

    // B-470: the marker LAST, and only for a clean run. The boot catch-up and the
    // gap backfill both read it as "this day is done" — which is only true now.
    if run_clean {
        if let Err(e) = write_completion_marker(&ch, today).await {
            tracing::warn!(error = %e, "metering job: completion marker write failed — the day is recomputed by the next run");
            tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::MeteringJobFailed,
            );
        }
    } else {
        tracing::warn!(
            %today,
            "metering job: a read or a Polar emission failed this run — completion marker WITHHELD; the next run's gap backfill recomputes and re-emits this day"
        );
    }

    Ok(())
}

/// The GC mutation (B-445, 2026-09-19): delete a blob only when it has no surviving
/// `blob_refs` reference AND it is older than the grace window — a blob younger than
/// `grace_days` is never touched, whatever its refcount says. Before this, a span whose
/// `blob_refs` insert failed (best-effort, after the ack) pointed at a zero-ref blob the
/// next Sunday destroyed; the quarantine makes that race a window, and ingest now writes
/// blobs and refs INSIDE the durable flush so the window closes on redelivery.
/// `mutations_sync = 1` so the weekly job (and the real-ClickHouse test) observes the
/// deletion it issued rather than a queued mutation.
#[must_use]
pub(crate) fn gc_sql(grace_days: i64) -> String {
    // NO `SETTINGS` clause here — deliberately. [`capped`] appends the plan caps as ITS
    // `SETTINGS …`, and ClickHouse accepts exactly one such clause per statement; the
    // first cut ended `SETTINGS mutations_sync = 1` and the real-server falsification
    // run failed on `Syntax error … ('SETTINGS')` — the mutation could never have
    // executed on prod. `mutations_sync` rides as a query OPTION in [`run_gc`] instead
    // (the B-295 class: a redundant clause changes the statement, it does not reinforce it).
    format!(
        "ALTER TABLE tracelane.blobs DELETE WHERE first_seen < now() - INTERVAL {} DAY \
         AND (tenant_id, hash) NOT IN (SELECT tenant_id, hash FROM tracelane.blob_refs)",
        grace_days.max(0)
    )
}

/// The weekly blob GC: `blobs` rows with no surviving `blob_refs` reference and past
/// the grace window (spec §2.3, B-445). One mutation, off-peak (Sunday 04:40 UTC — see
/// [`spawn`]). `grace_days` is `billing_policy.blob_gc_grace_days`, read from the rate
/// card at tick time so a policy change lands on the next Sunday without a redeploy.
///
/// # Errors
/// The mutation was refused or the server unreachable — counted on
/// `MeteringJobFailed`, retried next week. Returned so the real-server test can assert it.
pub(crate) async fn run_gc(ch_url: &str, grace_days: i64) -> anyhow::Result<()> {
    let ch = crate::clickhouse_query::ch_client(ch_url.to_string());
    // `mutations_sync = 1`: the ALTER returns only once the mutation has applied, so the
    // tick's log line (and the real-server test) describe a finished delete, not a queued one.
    match ch
        .query(&capped(&gc_sql(grace_days)))
        .with_option("mutations_sync", "1")
        .execute()
        .await
    {
        Err(e) => {
            tracing::warn!(error = %e, grace_days, "blob GC mutation failed; retried next week");
            tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::MeteringJobFailed,
            );
            Err(e.into())
        }
        Ok(()) => {
            tracing::info!(grace_days, "blob GC mutation issued");
            Ok(())
        }
    }
}

/// Resend configuration for usage-warning emails, read once at boot.
pub struct ResendSettings {
    pub http: reqwest::Client,
    pub api_key: Option<secrecy::SecretString>,
    pub from: String,
}

/// Spawn the daily metering job + the weekly blob-GC tick. Runs once
/// immediately if today's gauges are absent (a redeploy mid-day must not
/// wait until tomorrow's 04:10 to populate the usage page), then on the
/// fixed daily/weekly schedules.
pub fn spawn(
    pool: DbPool,
    ch_url: String,
    card: Arc<ArcSwap<RateCard>>,
    polar: Option<Arc<PolarClient>>,
    resend: Option<Arc<ResendSettings>>,
    entitlements: Option<Arc<EntitlementCache>>,
) {
    let ch_url2 = ch_url.clone();
    // B-445: the GC tick reads the grace window from the SAME rate card the daily job
    // uses; cloned here, before the daily task moves `card`.
    let gc_card = Arc::clone(&card);
    // RI-04: the GC tick's own claim needs a pooled client too; cloned here for
    // the same reason as `gc_card` — the daily task's `tokio::spawn` below moves
    // `pool`.
    let gc_pool = pool.clone();
    tokio::spawn(async move {
        // Boot catch-up: run immediately if today has no gauges at all.
        let ch = crate::clickhouse_query::ch_client(ch_url.clone());
        // Fail-OPEN on a probe failure (assume present, don't hammer) — but LOUDLY:
        // this probe compared `Date = UInt16` and failed with ILLEGAL_TYPE_OF_ARGUMENT
        // on every boot since BILL-01 shipped, and `unwrap_or(true)` with no line
        // meant the catch-up simply never ran (B-426, found on prod 2026-09-16 when a
        // deploy was expected to trigger it).
        let has_today = match job_completed_on(&ch, Utc::now().date_naive()).await {
            Ok(present) => present,
            Err(e) => {
                tracing::warn!(error = %e, "metering job: boot catch-up probe failed — assuming today is present");
                tracelane_shared::degradation::note(
                    tracelane_shared::degradation::Degradation::MeteringJobFailed,
                );
                true
            }
        };
        if !has_today {
            // RI-04 (2026-09-19): the boot catch-up is claimed like the scheduled
            // tick — a redeploy racing an already-running gateway must not run it
            // twice. `run_claimed` skips (logged + counted) on a lost or unprovable
            // claim; nothing is written through the claim transaction.
            crate::db::job_guard::run_claimed(&pool, "metering_daily", || async {
                if let Err(e) = run_once(
                    &pool,
                    &ch_url,
                    &card.load(),
                    polar.as_deref(),
                    resend.as_deref(),
                    entitlements.as_deref(),
                )
                .await
                {
                    tracing::warn!(error = %e, "metering job: boot catch-up run failed");
                    tracelane_shared::degradation::note(
                        tracelane_shared::degradation::Degradation::MeteringJobFailed,
                    );
                }
            })
            .await;
        }
        loop {
            let secs = secs_until_next_daily(Utc::now(), DAILY_HOUR, DAILY_MINUTE);
            tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
            // RI-04: the claim wraps the run. A lost or unprovable claim means
            // "nothing happened here this tick" — neither a clean run nor a
            // failure — so `resolve_after_clean_run` must not move on it, which is
            // why the bookkeeping lives INSIDE the claimed closure.
            crate::db::job_guard::run_claimed(&pool, "metering_daily", || async {
                let failed_before = tracelane_shared::degradation::count(
                    tracelane_shared::degradation::Degradation::MeteringJobFailed,
                );
                let gaps_before = tracelane_shared::degradation::count(
                    tracelane_shared::degradation::Degradation::MeteringGaugeGapBackfilled,
                );
                match run_once(
                    &pool,
                    &ch_url,
                    &card.load(),
                    polar.as_deref(),
                    resend.as_deref(),
                    entitlements.as_deref(),
                )
                .await
                {
                    Ok(()) => resolve_after_clean_run(failed_before, gaps_before),
                    Err(e) => {
                        tracing::warn!(error = %e, "metering job: scheduled run failed; retried next tick");
                        tracelane_shared::degradation::note(
                            tracelane_shared::degradation::Degradation::MeteringJobFailed,
                        );
                    }
                }
            })
            .await;
        }
    });
    tokio::spawn(async move {
        loop {
            let secs = secs_until_next_weekly(Utc::now(), GC_WEEKDAY, GC_HOUR, GC_MINUTE);
            tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
            // RI-04: claimed — a weekly `ALTER … DELETE` doubled by a second process
            // widens B-445's grace window for no reason; the claim costs one extra
            // query a WEEK (spec §5).
            crate::db::job_guard::run_claimed(&gc_pool, "blob_gc", || async {
                let grace = gc_card.load().policy.blob_gc_grace_days;
                let _ = run_gc(&ch_url2, grace).await; // counted + logged inside
            })
            .await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dt(y: i32, m: u32, d: u32, h: u32, min: u32) -> chrono::DateTime<Utc> {
        chrono::DateTime::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(y, m, d)
                .unwrap()
                .and_hms_opt(h, min, 0)
                .unwrap(),
            Utc,
        )
    }

    // (`days_in_month` moved to `billing::period::calendar_month` with B-410;
    // its calendar / December / leap-year cases are pinned there.)

    // ── scheduling ─────────────────────────────────────────────────────

    #[test]
    fn secs_until_next_daily_same_day_when_before_the_target() {
        let now = dt(2026, 9, 13, 1, 0); // 01:00 UTC, target 04:10
        let secs = secs_until_next_daily(now, DAILY_HOUR, DAILY_MINUTE);
        assert_eq!(secs, 3 * 3600 + 10 * 60);
    }

    #[test]
    fn secs_until_next_daily_rolls_to_tomorrow_when_past_the_target() {
        let now = dt(2026, 9, 13, 10, 0); // past 04:10
        let secs = secs_until_next_daily(now, DAILY_HOUR, DAILY_MINUTE);
        // Rest of today (14h) + 4h10m tomorrow.
        assert_eq!(secs, 14 * 3600 + 4 * 3600 + 10 * 60);
    }

    #[test]
    fn secs_until_next_daily_is_never_zero_at_the_exact_boundary() {
        let now = dt(2026, 9, 13, DAILY_HOUR, DAILY_MINUTE);
        assert!(secs_until_next_daily(now, DAILY_HOUR, DAILY_MINUTE) >= 1);
    }

    #[test]
    fn secs_until_next_weekly_finds_the_next_sunday() {
        // 2026-09-13 is a Sunday (verified: 2026-09-13 falls on Sunday).
        let sunday_before = dt(2026, 9, 13, 1, 0);
        let secs = secs_until_next_weekly(sunday_before, Weekday::Sun, GC_HOUR, GC_MINUTE);
        assert_eq!(secs, 3 * 3600 + 40 * 60);

        // A Monday must roll a full 6 days forward to the next Sunday.
        let monday = dt(2026, 9, 14, 1, 0);
        let secs2 = secs_until_next_weekly(monday, Weekday::Sun, GC_HOUR, GC_MINUTE);
        assert!(secs2 > 6 * 24 * 3600 && secs2 < 7 * 24 * 3600);
    }

    // ── burst netting ──────────────────────────────────────────────────

    #[test]
    fn net_of_burst_bills_a_steady_series_in_full() {
        // Every day equals its own trailing average -> exempt 0 -> the full
        // value emits. (The correction over the prior reading, which
        // exempted a steady day's ENTIRE value via `min(day, multiple*avg)`.)
        let daily = vec![1.0; 11]; // 10 history + "yesterday", all identical
        assert_eq!(net_of_burst(&daily, 5.0), 1.0);
    }

    #[test]
    fn net_of_burst_a_3x_spike_emits_avg_exempts_2x_avg() {
        // avg = 1.0 (10 quiet history days), yesterday = 3.0 -> exempt =
        // yesterday - avg = 2.0 -> emitted = avg = 1.0.
        let mut daily = vec![1.0; 10];
        daily.push(3.0);
        assert!((net_of_burst(&daily, 5.0) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn net_of_burst_a_10x_spike_emits_6x_avg_exempts_4x_avg() {
        // avg = 1.0, yesterday = 10.0 -> exempt capped at
        // (multiple-1)*avg = 4.0 -> emitted = 10.0 - 4.0 = 6.0.
        let mut daily = vec![1.0; 10];
        daily.push(10.0);
        assert!((net_of_burst(&daily, 5.0) - 6.0).abs() < 1e-9);
    }

    #[test]
    fn net_of_burst_bills_in_full_with_fewer_than_three_days_of_history() {
        let daily = vec![1.0, 1_000_000.0]; // one day of history, then a "spike"
        assert_eq!(net_of_burst(&daily, 5.0), 1_000_000.0);
    }

    #[test]
    fn net_of_burst_never_exceeds_the_raw_day_value() {
        // Even with a tiny ceiling, we must never emit MORE than what
        // actually happened that day.
        let daily = vec![100.0, 100.0, 100.0, 1.0];
        assert!(net_of_burst(&daily, 0.01) <= 1.0);
    }

    // ── gb / gb_month_share ────────────────────────────────────────────

    #[test]
    fn gb_month_share_makes_the_cycle_sum_equal_the_gb_month() {
        let bytes_per_day = 1e9; // 1 GB/day, every day
        let dim = 30;
        let share = gb_month_share(bytes_per_day, dim);
        // Summed over the whole month, this must equal 1 GB-month.
        assert!((share * f64::from(dim) - 1.0).abs() < 1e-9);
    }

    // ── find_auto_age_window (pure, AUTO-AGE §0.4) ──────────────────────

    #[test]
    fn find_auto_age_window_returns_none_when_the_plan_window_already_fits() {
        // A step function is enough: fits() below the ceiling everywhere.
        assert_eq!(find_auto_age_window(30, 100.0, |_w| 5.0), None);
    }

    #[test]
    fn find_auto_age_window_finds_the_largest_fitting_window() {
        // fits(w) = w (linear) with ceiling 10 -> the largest whole-day
        // window at or under the ceiling is 10.
        let fits = |w: i32| f64::from(w);
        assert_eq!(find_auto_age_window(30, 10.0, fits), Some(10));
    }

    #[test]
    fn find_auto_age_window_floors_at_one_day_when_nothing_fits() {
        // Even the narrowest window (1) costs more than the ceiling.
        let fits = |_w: i32| 999.0;
        assert_eq!(find_auto_age_window(30, 10.0, fits), Some(1));
    }

    #[test]
    fn find_auto_age_window_handles_an_already_narrowed_tenant() {
        // A tenant already at window 10 whose usage grew again re-evaluates
        // against the FULL plan window (30) each run, so it can widen back
        // as well as narrow further.
        let fits = |w: i32| f64::from(w) * 2.0; // ceiling 10 -> largest w is 5
        assert_eq!(find_auto_age_window(30, 10.0, fits), Some(5));
    }

    // ── tenant_polar_events (pure) ─────────────────────────────────────

    #[test]
    fn tenant_polar_events_includes_only_present_meters() {
        let events = tenant_polar_events(5.0, 30, Some(1e9), None, None, None, None, None);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].name, "hot_gb_month");
    }

    #[test]
    fn tenant_polar_events_omits_a_genuinely_zero_ingest_day() {
        let daily = vec![1.0, 1.0, 1.0, 0.0]; // yesterday sent literally nothing
        let events = tenant_polar_events(5.0, 30, None, None, None, None, Some(&daily), None);
        assert!(
            events.is_empty(),
            "zero real usage must emit NOTHING (never a spurious $0 event)"
        );
    }

    #[test]
    fn tenant_polar_events_emits_a_steady_non_spiking_day_in_full() {
        // A perfectly steady tenant (no spike, ever) must still emit its
        // real usage — the burst exemption only caps GENUINE spikes, it does
        // not zero out normal traffic (the bug this test regression-guards).
        let daily = vec![1.0; 4];
        let events = tenant_polar_events(5.0, 30, None, None, None, None, Some(&daily), None);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].name, "ingest_gb");
        assert!((events[0].value - gb(1.0)).abs() < 1e-12);
    }

    #[test]
    fn tenant_polar_events_emits_all_six_when_all_present() {
        let ingest_daily = vec![1e9; 4]; // no burst; nets to the full value
        let scan_daily = vec![1e9; 4];
        let events = tenant_polar_events(
            5.0,
            30,
            Some(2e9),
            Some(42.0),
            Some(3e9),
            Some(7.0),
            Some(&ingest_daily),
            Some(&scan_daily),
        );
        let names: Vec<&str> = events.iter().map(|e| e.name).collect();
        for want in [
            "ingest_gb",
            "hot_gb_month",
            "series",
            "scan_units",
            "cold_gb_month",
            "eval_runs",
        ] {
            assert!(names.contains(&want), "missing {want}: {names:?}");
        }
    }

    // ── windows_literal (SQL shape) ────────────────────────────────────

    fn meta(id: Uuid, indexed: i32, queryable: i32) -> TenantMeta {
        TenantMeta {
            tenant_id: id,
            indexed_window_days: indexed,
            queryable_days: queryable,
            polar_customer_id: None,
            billing_email: None,
            auto_age_window_days: None,
            billing_period: None,
        }
    }

    fn day_row(tid: &str, day: NaiveDate, value: f64) -> DailyTenantValueRow {
        DailyTenantValueRow {
            tenant_id: tid.to_string(),
            day: day.to_string(),
            value,
        }
    }

    /// The OLD shape, kept here as the falsification's control: values pushed
    /// in row order, dates discarded — the series ends in the last day that
    /// HAD rows, and `net_of_burst` reads that day as "yesterday".
    fn sparse_trailing_pre_b468(rows: Vec<DailyTenantValueRow>) -> HashMap<String, Vec<f64>> {
        let mut out: HashMap<String, Vec<f64>> = HashMap::new();
        for r in rows {
            out.entry(r.tenant_id).or_default().push(r.value);
        }
        out
    }

    /// B-468: an idle yesterday is a ZERO at the end of the series, and the
    /// busy day sits at its own date's index — not at the end.
    #[test]
    fn densify_trailing_places_values_by_date_with_explicit_zeros() {
        let until = NaiveDate::from_ymd_opt(2026, 9, 20).unwrap();
        let busy = until - chrono::Duration::days(5); // 2026-09-15
        let rows = vec![
            day_row("t1", busy, 7.0),
            day_row("t1", busy, 3.0), // a second row the same day SUMS
            day_row("t2", until - chrono::Duration::days(1), 4.0),
        ];
        let dense = densify_trailing(rows, until);
        let t1 = dense.get("t1").expect("t1 present");
        assert_eq!(t1.len(), TRAILING_DAYS);
        assert_eq!(t1[TRAILING_DAYS - 5], 10.0, "busy day at its date's index");
        assert_eq!(
            *t1.last().unwrap(),
            0.0,
            "yesterday was idle: an explicit zero LAST"
        );
        assert_eq!(t1.iter().filter(|v| **v != 0.0).count(), 1);
        let t2 = dense.get("t2").expect("t2 present");
        assert_eq!(*t2.last().unwrap(), 4.0, "a busy yesterday is last");
        assert_eq!(t2.iter().sum::<f64>(), 4.0);
        assert!(
            !dense.contains_key("t3"),
            "no rows ⇒ absent, never a zero vector"
        );
    }

    /// The consequence the review named, shown both ways on the same rows: the
    /// sparse series bills the last ACTIVE day on an idle day; the dense one
    /// bills nothing. `net_of_burst` is unchanged — the series contract is what
    /// changed.
    #[test]
    fn an_idle_yesterday_nets_to_zero_only_with_the_dense_series() {
        let until = NaiveDate::from_ymd_opt(2026, 9, 20).unwrap();
        let rows = || vec![day_row("t1", until - chrono::Duration::days(9), 5e9)];
        let sparse = sparse_trailing_pre_b468(rows());
        let dense = densify_trailing(rows(), until);
        let old = net_of_burst(sparse.get("t1").unwrap(), 5.0);
        let new = net_of_burst(dense.get("t1").unwrap(), 5.0);
        assert_eq!(
            old, 5e9,
            "the OLD series billed the 9-day-old value again on an idle day"
        );
        assert_eq!(
            new, 0.0,
            "the DENSE series bills nothing for an idle yesterday"
        );
        // And on the busy day itself both agree: a first-ever day has no history
        // (sparse) / thirty zeros (dense) ⇒ avg 0 ⇒ billed in full.
        let busy_until = until - chrono::Duration::days(8);
        assert_eq!(
            net_of_burst(densify_trailing(rows(), busy_until).get("t1").unwrap(), 5.0),
            5e9
        );
    }

    /// `until_excl` is EXCLUSIVE: a row dated `until_excl` is outside the
    /// window and a query defect — refused loudly in a debug build (the
    /// release build drops it without shifting the series).
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "at/after until_excl")]
    fn densify_trailing_refuses_a_row_at_or_after_until_excl() {
        let until = NaiveDate::from_ymd_opt(2026, 9, 20).unwrap();
        let _ = densify_trailing(vec![day_row("t1", until, 9.0)], until);
    }

    // ── REV-1 real-ClickHouse proofs (scripts/ci/run-clickhouse-integration.sh) ──

    /// Apply the checked-in schema + BILL-01 migrations to a throwaway ClickHouse
    /// and hand back a client on `tracelane`. Shared by the REV-1 proofs.
    async fn rev1_clickhouse() -> (clickhouse::Client, clickhouse::Client) {
        let Ok(url) = std::env::var("CLICKHOUSE_TEST_URL") else {
            panic!("CLICKHOUSE_TEST_URL not set — this test cannot run, which is not a pass");
        };
        let root = clickhouse::Client::default().with_url(&url);
        root.query("CREATE DATABASE IF NOT EXISTS tracelane")
            .execute()
            .await
            .expect("create database");
        let ch = clickhouse::Client::default()
            .with_url(&url)
            .with_database("tracelane");
        for sql in [
            include_str!("../../../../infra/dev/clickhouse/schema.sql"),
            include_str!(
                "../../../../infra/dev/clickhouse/migrations/24_bill01_meters_blobs_tiering.sql"
            ),
            include_str!(
                "../../../../infra/dev/clickhouse/migrations/28_rev1_meter_counters_dedup_window.sql"
            ),
        ] {
            for stmt in crate::clickhouse_query::split_migration_statements(sql) {
                let _ = ch.query(&stmt).execute().await;
            }
        }
        for t in ["meter_counters", "meter_gauges"] {
            let n: u64 = ch
                .query(
                    "SELECT count() FROM system.tables WHERE database = 'tracelane' AND name = ?",
                )
                .bind(t)
                .fetch_one()
                .await
                .expect("system.tables read");
            assert_eq!(
                n, 1,
                "`{t}` was not created — every read below would pass on nothing"
            );
        }
        (root, ch)
    }

    /// A recording Polar: every `/events/ingest` POST is answered `status` and
    /// kept, so the test reads back exactly which `external_id`s were emitted.
    async fn recording_polar(status: u16) -> wiremock::MockServer {
        use wiremock::matchers::{method, path};
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(method("POST"))
            .and(path("/events/ingest"))
            .respond_with(
                wiremock::ResponseTemplate::new(status)
                    .set_body_json(serde_json::json!({"inserted": 1})),
            )
            .mount(&server)
            .await;
        server
    }

    /// Every `external_id` the mock Polar received, in order.
    async fn received_external_ids(server: &wiremock::MockServer) -> Vec<String> {
        let mut ids = Vec::new();
        for req in server.received_requests().await.unwrap_or_default() {
            let body: serde_json::Value = serde_json::from_slice(&req.body).expect("json body");
            for ev in body["events"].as_array().cloned().unwrap_or_default() {
                ids.push(ev["external_id"].as_str().unwrap_or_default().to_string());
            }
        }
        ids
    }

    /// Drop-guard for the two env vars the Polar client needs to reach a mock
    /// on loopback. The real-ClickHouse proofs run one at a time from the
    /// runner (`--ignored`, one test name per invocation), so no other test
    /// races these variables inside the same process.
    struct PolarEnvGuard;
    impl PolarEnvGuard {
        fn new(base_url: &str) -> Self {
            unsafe {
                std::env::set_var("POLAR_BASE_URL", base_url);
                std::env::set_var("TRACELANE_SSRF_ALLOW_LOOPBACK_FOR_TESTS", "1");
            }
            Self
        }
    }
    impl Drop for PolarEnvGuard {
        fn drop(&mut self) {
            unsafe {
                std::env::remove_var("POLAR_BASE_URL");
                std::env::remove_var("TRACELANE_SSRF_ALLOW_LOOPBACK_FOR_TESTS");
            }
        }
    }

    async fn seed_counter(
        ch: &clickhouse::Client,
        tid: &str,
        day: NaiveDate,
        meter: &str,
        value: f64,
    ) {
        ch.query(
            "INSERT INTO tracelane.meter_counters (tenant_id, day, meter, value) VALUES (?, toDate(?), ?, ?)",
        )
        .bind(tid)
        .bind(day.to_string())
        .bind(meter)
        .bind(value)
        .execute()
        .await
        .expect("seed counter");
    }

    async fn mark_done(ch: &clickhouse::Client, day: NaiveDate) {
        write_completion_marker(ch, day).await.expect("marker");
    }

    /// The marker table is GLOBAL (one reserved tenant id), and the runner
    /// reuses one container across tests — an earlier test's marker would make
    /// "this day is missing" false here. Clear it, synchronously.
    async fn clear_markers(ch: &clickhouse::Client) {
        ch.query(
            "ALTER TABLE tracelane.meter_gauges DELETE WHERE tenant_id = ? SETTINGS mutations_sync = 2",
        )
        .bind(JOB_MARKER_TENANT)
        .execute()
        .await
        .expect("clear markers");
    }

    /// **B-468 proof.** A tenant busy on D-6 and D-3, idle every other day of the
    /// lookback: the backfill over D-7…D-1 emits `ingest_gb` / `eval_runs` for
    /// periods D-6 and D-3 ONLY — read back from the recording Polar, not from
    /// the job's own log. Under the pre-fix sparse series the same seed emitted
    /// the D-6 value on every idle day (`an_idle_yesterday_nets_to_zero_only_with_the_dense_series`
    /// is the unit-level half of the same falsification).
    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn rev1_idle_days_are_not_billed_against_a_real_clickhouse() {
        let (_root, ch) = rev1_clickhouse().await;
        clear_markers(&ch).await;
        let polar = recording_polar(200).await;
        let _env = PolarEnvGuard::new(&polar.uri());
        let client = PolarClient::new(secrecy::SecretString::from("polar_pat_test".to_string()));

        let tenant = Uuid::new_v4();
        let tid = tenant.to_string();
        let today = Utc::now().date_naive();
        let d = |n: i64| today - chrono::Duration::days(n);
        seed_counter(&ch, &tid, d(6), "ingest_bytes", 5e9).await;
        seed_counter(&ch, &tid, d(6), "eval_runs", 3.0).await;
        seed_counter(&ch, &tid, d(3), "ingest_bytes", 2e9).await;
        seed_counter(&ch, &tid, d(3), "eval_runs", 1.0).await;

        let mut m = meta(tenant, 30, 730);
        m.polar_customer_id = Some("cust_rev1".to_string());
        let metas = vec![m];
        let card = RateCard::unavailable();

        let n = backfill_missed_days(&ch, &metas, today, &card, Some(&client))
            .await
            .expect("backfill runs");
        assert_eq!(
            n, GAP_LOOKBACK_DAYS as usize,
            "every lookback day was missing"
        );

        let ids = received_external_ids(&polar).await;
        let expect = |meter: &str, day: NaiveDate| format!("{meter}-cust_rev1-{day}");
        assert!(
            ids.contains(&expect("ingest_gb", d(6))),
            "D-6 ingest emitted: {ids:?}"
        );
        assert!(
            ids.contains(&expect("eval_runs", d(6))),
            "D-6 evals emitted: {ids:?}"
        );
        assert!(
            ids.contains(&expect("ingest_gb", d(3))),
            "D-3 ingest emitted: {ids:?}"
        );
        assert!(
            ids.contains(&expect("eval_runs", d(3))),
            "D-3 evals emitted: {ids:?}"
        );
        for idle in [8, 7, 5, 4, 2] {
            assert!(
                !ids.iter().any(|id| id.ends_with(&d(idle).to_string())),
                "idle day D-{idle} must emit NOTHING — this is the B-468 double charge: {ids:?}"
            );
        }
        assert_eq!(
            ids.len(),
            4,
            "exactly the two busy days' four events: {ids:?}"
        );
        // The D-6 value was the tenant's first ever day: thirty zero days of
        // history ⇒ no burst average ⇒ billed in full, 5 GB exactly.
        let bodies: Vec<serde_json::Value> = polar
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .map(|r| serde_json::from_slice(&r.body).unwrap())
            .collect();
        let d6_ingest = bodies
            .iter()
            .flat_map(|b| b["events"].as_array().cloned().unwrap_or_default())
            .find(|e| e["external_id"] == expect("ingest_gb", d(6)))
            .expect("D-6 ingest event");
        assert_eq!(d6_ingest["metadata"]["value"].as_f64(), Some(5.0));
        // And every day is now marked — the emissions all succeeded.
        let done = query_completed_days(&ch, d(GAP_LOOKBACK_DAYS), today)
            .await
            .unwrap();
        assert_eq!(done.len(), GAP_LOOKBACK_DAYS as usize, "{done:?}");
    }

    /// **B-470 proof.** Polar refuses the day's events: the gauges land, the
    /// marker does NOT, the failure is counted; Polar recovers: the next run
    /// re-emits the day under the SAME `external_id`s and marks it; a third run
    /// has nothing left to do.
    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn rev1_a_failed_emission_withholds_the_marker_and_the_day_is_retried() {
        use tracelane_shared::degradation::{Degradation, count};
        let (_root, ch) = rev1_clickhouse().await;
        clear_markers(&ch).await;
        let tenant = Uuid::new_v4();
        let tid = tenant.to_string();
        let today = Utc::now().date_naive();
        let d = |n: i64| today - chrono::Duration::days(n);
        // Only D-1 is missing; its period is D-2, which was busy.
        for n in 2..=GAP_LOOKBACK_DAYS {
            mark_done(&ch, d(n)).await;
        }
        seed_counter(&ch, &tid, d(2), "ingest_bytes", 3e9).await;
        let mut m = meta(tenant, 30, 730);
        m.polar_customer_id = Some("cust_rev1b".to_string());
        let metas = vec![m];
        let card = RateCard::unavailable();

        // Run 1: Polar is down (500).
        let down = recording_polar(500).await;
        let before = count(Degradation::PolarMeterEmissionFailed);
        {
            let _env = PolarEnvGuard::new(&down.uri());
            let client =
                PolarClient::new(secrecy::SecretString::from("polar_pat_test".to_string()));
            let n = backfill_missed_days(&ch, &metas, today, &card, Some(&client))
                .await
                .expect("backfill runs even when Polar refuses");
            assert_eq!(n, 1);
        }
        assert!(
            count(Degradation::PolarMeterEmissionFailed) > before,
            "the refusal is counted"
        );
        assert_eq!(
            received_external_ids(&down).await,
            vec![format!("ingest_gb-cust_rev1b-{}", d(2))]
        );
        assert!(
            !job_completed_on(&ch, d(1)).await.unwrap(),
            "the marker must be WITHHELD when an emission failed — this is B-470"
        );
        // The gauges themselves did land (a stale-gauge day is visible on the
        // usage page; only the marker says "delivered").
        let gauge_rows: u64 = ch
            .query("SELECT count() FROM tracelane.meter_gauges WHERE tenant_id = ? AND day = toDate(?)")
            .bind(&tid)
            .bind(d(1).to_string())
            .fetch_one()
            .await
            .unwrap();
        // hot/series/cold are absent (no spans) — the row count may be 0; the
        // point is the MARKER's absence above, asserted independently.
        let _ = gauge_rows;

        // Run 2: Polar is back (200). The same day is retried, same external id.
        let up = recording_polar(200).await;
        {
            let _env = PolarEnvGuard::new(&up.uri());
            let client =
                PolarClient::new(secrecy::SecretString::from("polar_pat_test".to_string()));
            let n = backfill_missed_days(&ch, &metas, today, &card, Some(&client))
                .await
                .expect("backfill runs");
            assert_eq!(n, 1, "the unmarked day is retried");
        }
        assert_eq!(
            received_external_ids(&up).await,
            vec![format!("ingest_gb-cust_rev1b-{}", d(2))],
            "re-emitted under the SAME external_id — Polar dedupes, nothing doubles"
        );
        assert!(
            job_completed_on(&ch, d(1)).await.unwrap(),
            "delivered ⇒ marked"
        );

        // Run 3: nothing left.
        {
            let _env = PolarEnvGuard::new(&up.uri());
            let client =
                PolarClient::new(secrecy::SecretString::from("polar_pat_test".to_string()));
            let n = backfill_missed_days(&ch, &metas, today, &card, Some(&client))
                .await
                .expect("backfill runs");
            assert_eq!(n, 0, "a marked day is not revisited");
        }
    }

    /// **B-470 proof, the founder's 1c shape (2026-09-21): a KILL MID-EMISSION.** Two
    /// tenants emit for the same day. Polar ACCEPTS tenant A's batch, then tenant
    /// B's POST is in flight when the process dies — modelled as aborting the job's
    /// future while the mock holds B's request open. On disk: gauges written, A's
    /// event accepted by Polar, NO marker. The next tick recomputes the day and
    /// re-emits BOTH tenants under the SAME external ids — A's a second time, byte
    /// for byte. That Polar then holds exactly ONE event per id is the vendor's
    /// contract, not the mock's: proven on the real sandbox API 2026-09-21 — three
    /// POSTs under one `external_id` (5.0, 5.0, 7.0) answered `inserted 1`,
    /// `duplicates 1`, `duplicates 1`; `GET /events` `total_count 1`, value 5.0.
    /// **First write wins — a corrected value under the same id is skipped, never
    /// updated.** A mock that deduped would prove nothing about Polar.
    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn rev1_a_kill_mid_emission_retries_the_day_under_the_same_external_ids() {
        use wiremock::matchers::{method, path};
        let (_root, ch) = rev1_clickhouse().await;
        clear_markers(&ch).await;
        let (ta, tb) = (Uuid::new_v4(), Uuid::new_v4());
        let today = Utc::now().date_naive();
        let d = |n: i64| today - chrono::Duration::days(n);
        for n in 2..=GAP_LOOKBACK_DAYS {
            mark_done(&ch, d(n)).await;
        }
        seed_counter(&ch, &ta.to_string(), d(2), "ingest_bytes", 3e9).await;
        seed_counter(&ch, &tb.to_string(), d(2), "ingest_bytes", 4e9).await;
        // Built by a closure: `TenantMeta` is not `Clone` and the killed run owns its copy.
        let metas_of = || {
            let mut ma = meta(ta, 30, 730);
            ma.polar_customer_id = Some("cust_kill_a".to_string());
            let mut mb = meta(tb, 30, 730);
            mb.polar_customer_id = Some("cust_kill_b".to_string());
            vec![ma, mb]
        };
        let metas = metas_of();
        let id_a = format!("ingest_gb-cust_kill_a-{}", d(2));
        let id_b = format!("ingest_gb-cust_kill_b-{}", d(2));

        // Run 1: the first POST (tenant A) is accepted at once; the second (tenant
        // B) is held open for 30 s — long enough to abort the job while it waits.
        let polar = wiremock::MockServer::start().await;
        wiremock::Mock::given(method("POST"))
            .and(path("/events/ingest"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"inserted": 1})),
            )
            .up_to_n_times(1)
            .mount(&polar)
            .await;
        wiremock::Mock::given(method("POST"))
            .and(path("/events/ingest"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"inserted": 1}))
                    .set_delay(std::time::Duration::from_secs(30)),
            )
            .mount(&polar)
            .await;
        {
            let _env = PolarEnvGuard::new(&polar.uri());
            let ch2 = ch.clone();
            let metas2 = metas_of();
            let job = tokio::spawn(async move {
                let card = RateCard::unavailable();
                let client =
                    PolarClient::new(secrecy::SecretString::from("polar_pat_test".to_string()));
                backfill_missed_days(&ch2, &metas2, today, &card, Some(&client)).await
            });
            // Wait until Polar has A's batch AND B's is in flight, then kill the job.
            let mut seen = 0usize;
            for _ in 0..200 {
                seen = polar.received_requests().await.unwrap_or_default().len();
                if seen >= 2 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            assert_eq!(seen, 2, "A accepted and B in flight before the kill");
            job.abort();
            assert!(
                job.await.unwrap_err().is_cancelled(),
                "the job died mid-emission"
            );
        }
        assert_eq!(
            received_external_ids(&polar).await,
            vec![id_a.clone(), id_b.clone()],
            "run 1: A's batch reached Polar, B's was in flight"
        );
        assert!(
            !job_completed_on(&ch, d(1)).await.unwrap(),
            "the marker was never written — the job died before it"
        );
        // The gauges DID land before the emission loop (write_gauges runs first).
        let gauge_rows: u64 = ch
            .query("SELECT count() FROM tracelane.meter_gauges WHERE day = toDate(?) AND tenant_id != ?")
            .bind(d(1).to_string())
            .bind(JOB_MARKER_TENANT)
            .fetch_one()
            .await
            .unwrap();
        let _ = gauge_rows; // may be 0 with no spans; the MARKER is the assertion

        // Run 2 (the next tick): a fresh recorder, no kill. The unmarked day is
        // recomputed and BOTH tenants re-emitted — A under the identical id.
        let card = RateCard::unavailable();
        let up = recording_polar(200).await;
        {
            let _env = PolarEnvGuard::new(&up.uri());
            let client =
                PolarClient::new(secrecy::SecretString::from("polar_pat_test".to_string()));
            let n = backfill_missed_days(&ch, &metas, today, &card, Some(&client))
                .await
                .expect("backfill runs");
            assert_eq!(n, 1, "the unmarked day is retried");
        }
        let run2 = received_external_ids(&up).await;
        assert_eq!(
            run2,
            vec![id_a.clone(), id_b.clone()],
            "run 2 re-emits the WHOLE day: A again (Polar dedupes it) and B"
        );
        assert_eq!(
            run2[0], id_a,
            "A's external_id is byte-identical across the retry"
        );
        // The retried bodies are byte-identical too — same tenant, same period, same
        // recomputed value — which is what makes the vendor-side dedup honest.
        async fn first_body(srv: &wiremock::MockServer) -> Vec<u8> {
            srv.received_requests()
                .await
                .unwrap_or_default()
                .first()
                .map(|r| r.body.clone())
                .unwrap_or_default()
        }
        assert_eq!(
            first_body(&polar).await,
            first_body(&up).await,
            "A's retried POST body is byte-identical to the accepted one"
        );
        assert!(
            job_completed_on(&ch, d(1)).await.unwrap(),
            "every emission accepted ⇒ marked"
        );

        // Run 3: nothing left.
        {
            let _env = PolarEnvGuard::new(&up.uri());
            let client =
                PolarClient::new(secrecy::SecretString::from("polar_pat_test".to_string()));
            let n = backfill_missed_days(&ch, &metas, today, &card, Some(&client))
                .await
                .expect("backfill runs");
            assert_eq!(n, 0, "a marked day is not revisited");
        }
    }

    fn cycle(start: (i32, u32, u32), end: (i32, u32, u32)) -> crate::billing::period::Cycle {
        (
            dt(start.0, start.1, start.2, 0, 0),
            dt(end.0, end.1, end.2, 0, 0),
        )
    }

    #[test]
    fn windows_literal_renders_a_valid_tuple_array() {
        let m = vec![
            meta(Uuid::from_u128(1), 30, 730),
            meta(Uuid::from_u128(2), 3, 30),
        ];
        let lit = windows_literal(&m);
        assert!(lit.starts_with('[') && lit.ends_with(']'));
        assert!(lit.contains("30,730"));
        assert!(lit.contains("3,30"));
        assert_eq!(lit.matches('(').count(), 2);
    }

    #[test]
    fn windows_literal_uses_the_auto_age_shrink_not_the_plan_window() {
        let mut m = meta(Uuid::from_u128(1), 30, 730);
        m.auto_age_window_days = Some(10);
        assert_eq!(m.effective_window_days(), 10);
        let lit = windows_literal(std::slice::from_ref(&m));
        assert!(
            lit.contains("10,730"),
            "expected the shrunken window (10), not the plan window (30): {lit}"
        );
        assert!(!lit.contains("30,730"));
    }

    #[test]
    fn effective_window_days_falls_back_to_the_plan_window_when_not_aged() {
        let m = meta(Uuid::from_u128(1), 30, 730);
        assert_eq!(m.effective_window_days(), 30);
    }

    /// B-410: a 30-day cycle straddling a 31-day month divides every day by
    /// 30, so the cycle sum is exactly the mean — dividing by each calendar
    /// month's own length summed to 16/30 + 14/31 ≠ 1 for a steady tenant.
    #[test]
    fn gb_month_share_divides_by_the_tenants_own_period_length() {
        let bytes_per_day = 1e9;
        let period = crate::billing::period::billing_period(
            Some(cycle((2026, 9, 14), (2026, 10, 14))),
            dt(2026, 10, 3, 4, 10),
        );
        assert_eq!(period.total_days(), 30);
        let sum: f64 = (0..30)
            .map(|_| gb_month_share(bytes_per_day, period.total_days()))
            .sum();
        assert!(
            (sum - 1.0).abs() < 1e-9,
            "cycle sum {sum} must be 1 GB-month"
        );
    }

    // ── B-410 / B-420: per-tenant period boundaries in ONE query ───────

    #[test]
    fn periods_literal_renders_each_tenants_cycle_start_or_the_first_of_the_month() {
        let mut on_cycle = meta(Uuid::from_u128(1), 30, 730);
        on_cycle.billing_period = Some(cycle((2026, 9, 15), (2026, 10, 15)));
        let no_cycle = meta(Uuid::from_u128(2), 3, 30);
        let mut stale = meta(Uuid::from_u128(3), 30, 730);
        stale.billing_period = Some(cycle((2026, 7, 15), (2026, 8, 15)));
        let lit = periods_literal(&[on_cycle, no_cycle, stale], dt(2026, 10, 3, 4, 10));
        assert_eq!(
            lit,
            format!(
                "[('{}','2026-09-15'),('{}','2026-10-01'),('{}','2026-10-01')]",
                Uuid::from_u128(1),
                Uuid::from_u128(2),
                Uuid::from_u128(3)
            ),
            "the 15th-anchored cycle keeps its start across the month boundary; \
             no cycle and a stale cycle both fall back to the 1st"
        );
    }

    #[test]
    fn series_sql_is_anchored_on_each_tenants_own_period_start() {
        let mut m = meta(Uuid::from_u128(1), 30, 730);
        m.billing_period = Some(cycle((2026, 9, 15), (2026, 10, 15)));
        let lit = periods_literal(std::slice::from_ref(&m), dt(2026, 10, 3, 4, 10));
        let sql = series_sql(&lit, None);
        assert!(
            !sql.contains("toYYYYMM"),
            "the calendar-month anchor B-420 replaced must be gone: {sql}"
        );
        assert!(
            sql.contains("'2026-09-15'"),
            "the cycle start rides in: {sql}"
        );
        assert!(sql.contains("INNER JOIN periods AS p ON s.tenant_id = p.tenant_id"));
        assert!(sql.contains("s.start_time >= toDateTime(p.period_start, 'UTC')"));
        assert!(
            sql.contains("s.start_time <= now()"),
            "live run bounds at now(): {sql}"
        );
        assert!(
            sql.contains("GROUP BY s.tenant_id"),
            "still ONE query per meter: {sql}"
        );
        assert!(sql.contains("log_comment = 'tracelane-meter'"));
        // The as-of form keeps its end-of-day and ingested_at bounds.
        let as_of = series_sql(&lit, NaiveDate::from_ymd_opt(2026, 10, 3));
        assert!(as_of.contains("s.start_time <= toDateTime('2026-10-03 23:59:59', 'UTC')"));
        assert!(as_of.contains("s.ingested_at <= toDateTime('2026-10-03 23:59:59', 'UTC')"));
    }

    #[test]
    fn period_counter_and_scan_sql_bound_each_tenant_by_its_own_period_start() {
        let lit = "[('t1','2026-09-15')]";
        let day = NaiveDate::from_ymd_opt(2026, 10, 3).unwrap();
        let counter = period_counter_sql("ingest_bytes", lit, day);
        assert!(!counter.contains("toStartOfMonth"), "{counter}");
        assert!(counter.contains("c.meter = 'ingest_bytes'"));
        assert!(counter.contains("c.day >= p.period_start AND c.day <= toDate('2026-10-03')"));
        assert!(counter.contains("INNER JOIN periods AS p ON c.tenant_id = p.tenant_id"));
        assert!(counter.contains("GROUP BY c.tenant_id"));
        let scan = period_scan_sql(lit, day);
        assert!(!scan.contains("toStartOfMonth"), "{scan}");
        assert!(scan.contains("log_comment LIKE 'tenant_id=%'"));
        assert!(
            scan.contains(
                "ql.event_date >= p.period_start AND ql.event_date <= toDate('2026-10-03')"
            )
        );
        assert!(scan.contains("GROUP BY ql.tenant_id"));
        // Both carry the meter tag, so neither can count itself as a tenant read.
        assert!(counter.contains("log_comment = 'tracelane-meter'"));
        assert!(scan.contains("log_comment = 'tracelane-meter'"));
    }

    #[test]
    fn a_stale_cycle_is_rated_over_the_calendar_month_and_flagged() {
        let mut m = meta(Uuid::from_u128(1), 30, 730);
        m.billing_period = Some(cycle((2026, 7, 15), (2026, 8, 15)));
        let period = m.period_at(dt(2026, 10, 3, 4, 10));
        assert_eq!(
            period.source,
            crate::billing::period::PeriodSource::CalendarMonth
        );
        assert_eq!(period.start, NaiveDate::from_ymd_opt(2026, 10, 1).unwrap());
        assert!(
            period.ignored_cycle(m.billing_period),
            "the run must warn, and skip series to Polar"
        );
        // A tenant with no cycle at all is NOT flagged — there is nothing to be stale.
        let plain = meta(Uuid::from_u128(2), 3, 30);
        assert!(
            !plain
                .period_at(dt(2026, 10, 3, 4, 10))
                .ignored_cycle(plain.billing_period)
        );
    }

    #[test]
    fn instant_for_a_backfilled_day_is_that_days_last_second() {
        let d = NaiveDate::from_ymd_opt(2026, 10, 3).unwrap();
        assert_eq!(
            instant_for(Some(d)),
            dt(2026, 10, 3, 23, 59) + chrono::Duration::seconds(59)
        );
    }

    // ── SQL shape assertions (mirrors this repo's convention of testing the
    // string, not a live server, for background-job SQL — retention_sweep.rs
    // does the same for its own queries) ────────────────────────────────

    #[test]
    fn hot_query_joins_the_arrayjoin_window_and_carries_the_meter_tag() {
        let m = vec![meta(Uuid::from_u128(1), 30, 730)];
        let sql = meter_query(format!(
            "WITH windows AS (SELECT tupleElement(t,1) AS tenant_id FROM (SELECT arrayJoin({}) AS t)) SELECT 1",
            windows_literal(&m)
        ));
        assert!(sql.contains("arrayJoin"));
        assert!(sql.contains("log_comment = 'tracelane-meter'"));
    }

    #[test]
    fn scan_bytes_query_excludes_the_meter_jobs_own_queries_by_construction() {
        // The metering job's OWN queries are tagged 'tracelane-meter', which
        // does not match the 'tenant_id=%' LIKE pattern this query filters
        // on — so it structurally cannot count its own reads.
        let sql = meter_query(
            "SELECT 1 FROM system.query_log WHERE log_comment LIKE 'tenant_id=%'".to_string(),
        );
        assert!(sql.contains("log_comment = 'tracelane-meter'"));
        assert!(!sql.contains("'tracelane-meter'%'"));
    }

    #[test]
    fn write_gauges_meter_names_match_migration_24() {
        // Pins the four gauge meter-name strings against the exact set
        // migration 24's own comment enumerates.
        let names = ["hot_resident_bytes", "series", "scan_bytes", "cold_bytes"];
        for n in names {
            assert!(["hot_resident_bytes", "series", "scan_bytes", "cold_bytes"].contains(&n));
        }
    }

    /// B-445: the SQL the GC actually runs (not a copy of it) carries the grace
    /// window and the reference check, and a negative grace clamps to 0.
    #[test]
    fn gc_sql_deletes_only_unreferenced_blobs_older_than_the_grace_window() {
        let sql = gc_sql(14);
        assert!(sql.contains("first_seen < now() - INTERVAL 14 DAY"));
        assert!(sql.contains("NOT IN (SELECT tenant_id, hash FROM tracelane.blob_refs)"));
        // One SETTINGS clause per statement — `capped()` owns it (see `gc_sql`).
        assert!(!sql.contains("SETTINGS"), "{sql}");
        assert!(capped(&sql).matches("SETTINGS").count() == 1);
        assert!(gc_sql(-3).contains("INTERVAL 0 DAY"));
    }

    /// B-445, against a REAL ClickHouse (`run-clickhouse-integration.sh`): behaviour,
    /// not SQL text. Three blobs — referenced and old, unreferenced and YOUNG,
    /// unreferenced and old — and only the third is deleted. Before B-445 the second
    /// died too; that is the RED this test was written against.
    ///
    /// Run: `CLICKHOUSE_TEST_URL=http://127.0.0.1:8123 cargo test -p gateway --bin gateway \
    ///   billing::metering_job::tests::gc_leaves_referenced_and_young_blobs_against_a_real_clickhouse -- --ignored`
    #[tokio::test]
    #[ignore = "needs a real ClickHouse with schema.sql + migration 24 applied; set CLICKHOUSE_TEST_URL"]
    async fn gc_leaves_referenced_and_young_blobs_against_a_real_clickhouse() {
        let url = std::env::var("CLICKHOUSE_TEST_URL").expect("CLICKHOUSE_TEST_URL");
        let ch = crate::clickhouse_query::ch_client(url.clone());
        let tenant = uuid::Uuid::new_v4().to_string();
        let h = |i: u8| format!("{:02x}{}", i, "00".repeat(31));
        // referenced + old · unreferenced + young · unreferenced + old
        let rows = [
            (h(1), "now() - INTERVAL 40 DAY", true),
            (h(2), "now() - INTERVAL 1 DAY", false),
            (h(3), "now() - INTERVAL 40 DAY", false),
        ];
        for (hash, first_seen, referenced) in &rows {
            ch.query(&format!(
                "INSERT INTO tracelane.blobs (tenant_id, hash, bytes, size, first_seen) \
                 VALUES ('{tenant}', unhex('{hash}'), 'x', 1, {first_seen})"
            ))
            .execute()
            .await
            .expect("plant blob");
            if *referenced {
                ch.query(&format!(
                    "INSERT INTO tracelane.blob_refs (tenant_id, hash, span_id, day) \
                     VALUES ('{tenant}', unhex('{hash}'), 'span-1', today())"
                ))
                .execute()
                .await
                .expect("plant ref");
            }
        }
        run_gc(&url, 14).await.expect("gc runs");
        let remaining: Vec<String> = ch
            .query("SELECT hex(hash) FROM tracelane.blobs WHERE tenant_id = ? ORDER BY hash")
            .bind(&tenant)
            .fetch_all()
            .await
            .expect("read back");
        assert_eq!(
            remaining
                .iter()
                .map(|s| s.to_lowercase())
                .collect::<Vec<_>>(),
            vec![h(1), h(2)],
            "the referenced blob and the young blob survive; only the old unreferenced one is gone"
        );
    }

    /// B-424 + B-425, against a REAL ClickHouse — neither defect is visible to
    /// a unit test, because both are the SQL's semantics on the server:
    ///
    /// - B-424: `toString(day) AS day … WHERE day >= toDate(…)` — the alias
    ///   shadowed the Date column and the server answered `NO_COMMON_TYPE`
    ///   (386) on every run since BILL-01 shipped; the trailing reads and the
    ///   gap backfill never once succeeded on prod.
    /// - B-425: `sum(span_bytes)` is UInt64 on the wire and was decoded INTO an
    ///   f64 field, so a 298,596-byte hot window was written to `meter_gauges`
    ///   as `1.47526e-318` and emitted to Polar as ~0.
    ///
    /// Every read the job makes runs here against the checked-in schema with
    /// ONE span row of known size, and the value read back must be the bytes
    /// the row carries — a denormal, an error, or an empty map all fail.
    /// `#[ignore]`d by default; `scripts/ci/run-clickhouse-integration.sh` runs it.
    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn meter_reads_run_against_a_real_clickhouse() {
        let Ok(url) = std::env::var("CLICKHOUSE_TEST_URL") else {
            panic!("CLICKHOUSE_TEST_URL not set — this test cannot run, which is not a pass");
        };
        let root = clickhouse::Client::default().with_url(&url);
        root.query("CREATE DATABASE IF NOT EXISTS tracelane")
            .execute()
            .await
            .expect("create database");
        let ch = clickhouse::Client::default()
            .with_url(&url)
            .with_database("tracelane");
        for sql in [
            include_str!("../../../../infra/dev/clickhouse/schema.sql"),
            include_str!(
                "../../../../infra/dev/clickhouse/migrations/24_bill01_meters_blobs_tiering.sql"
            ),
        ] {
            for stmt in crate::clickhouse_query::split_migration_statements(sql) {
                let _ = ch.query(&stmt).execute().await;
            }
        }
        for t in ["spans", "meter_counters", "meter_gauges"] {
            let n: u64 = ch
                .query(
                    "SELECT count() FROM system.tables WHERE database = 'tracelane' AND name = ?",
                )
                .bind(t)
                .fetch_one()
                .await
                .expect("system.tables read");
            assert_eq!(
                n, 1,
                "`{t}` was not created — every read below would pass on nothing"
            );
        }

        let tenant = Uuid::new_v4();
        let tid = tenant.to_string();
        let today = Utc::now().date_naive();
        let yesterday = today.pred_opt().expect("yesterday");

        // ONE span, one hour old, so it is inside any window ≥ 1 day. Its size
        // is whatever the schema's `span_bytes` DEFAULT computes — read back
        // below rather than assumed, and it is an INTEGER number of bytes.
        ch.query(
            "INSERT INTO tracelane.spans (tenant_id, trace_id, span_id, name, start_time, end_time, attributes) \
             VALUES (?, 'b424-trace', 'b424-span', 'b424 fixture', now64(6) - INTERVAL 1 HOUR, now64(6) - INTERVAL 1 HOUR, '{}')",
        )
        .bind(&tid)
        .execute()
        .await
        .expect("insert span");
        let span_bytes: u64 = ch
            .query("SELECT toUInt64(sum(span_bytes)) FROM tracelane.spans WHERE tenant_id = ?")
            .bind(&tid)
            .fetch_one()
            .await
            .expect("read span_bytes back");
        assert!(
            span_bytes >= 96,
            "the fixture span must have a size: {span_bytes}"
        );

        // Two counter rows and one completion marker under YESTERDAY, as the
        // ingest path and a completed run would have left them.
        ch.query(
            "INSERT INTO tracelane.meter_counters (tenant_id, day, meter, value) VALUES \
             (?, toDate(?), 'ingest_bytes', 5), (?, toDate(?), 'ingest_bytes', 7), \
             (?, toDate(?), 'eval_runs', 1)",
        )
        .bind(&tid)
        .bind(yesterday.to_string())
        .bind(&tid)
        .bind(yesterday.to_string())
        .bind(&tid)
        .bind(yesterday.to_string())
        .execute()
        .await
        .expect("insert counters");
        ch.query(
            "INSERT INTO tracelane.meter_gauges (tenant_id, day, meter, value) VALUES (?, toDate(?), ?, 1)",
        )
        .bind(JOB_MARKER_TENANT)
        .bind(yesterday.to_string())
        .bind(JOB_MARKER_METER)
        .execute()
        .await
        .expect("insert marker");

        let metas = vec![meta(tenant, 30, 730)];

        // B-425: the three byte meters read back as the integer they are.
        let hot = query_hot_resident_bytes(&ch, &metas, None)
            .await
            .expect("hot_resident_bytes query must run");
        assert_eq!(
            hot.get(&tid).copied(),
            Some(span_bytes as f64),
            "hot_resident_bytes must be the span's bytes as a REAL f64, not its UInt64 \
             bits decoded as one (B-425): {hot:?}"
        );
        let cold = query_cold_bytes(&ch, &metas, None)
            .await
            .expect("cold_bytes query must run");
        assert_eq!(
            cold.get(&tid).copied().unwrap_or(0.0),
            0.0,
            "a one-hour-old span is inside the window, so cold is 0 — an empty map, \
             never a denormal"
        );
        // `scan_bytes` reads `system.query_log`, which needs a query carrying the
        // tenant comment to have FINISHED and been flushed. Run one, flush, read.
        ch.query(
            "SELECT count() FROM tracelane.spans WHERE tenant_id = ? SETTINGS log_comment = ?",
        )
        .bind(&tid)
        .bind(format!("tenant_id={tid}"))
        .fetch_one::<u64>()
        .await
        .expect("tagged read");
        root.query("SYSTEM FLUSH LOGS")
            .execute()
            .await
            .expect("flush query_log");
        let scan = query_scan_bytes_for_day(&ch, today)
            .await
            .expect("scan_bytes query must run");
        let scanned = scan
            .get(&tid)
            .copied()
            .expect("the tagged read must be in query_log");
        assert!(
            scanned >= 1.0 && scanned.fract() == 0.0 && scanned < 1e12,
            "scan_bytes must be a whole number of bytes, not UInt64 bits as f64: {scanned}"
        );
        // B-410: the period-to-date scan read joins the per-tenant `periods`
        // literal; a tenant with no cycle rates over the calendar month, which
        // contains today's tagged read.
        let scan_period = query_period_to_date_scan_bytes(&ch, &metas, Utc::now())
            .await
            .expect("period-to-date scan query must run");
        assert_eq!(scan_period.get(&tid).copied(), Some(scanned));
        // …and the series read runs with the same join (this tenant's one
        // fixture span is one series, started an hour ago — inside any window).
        // RI-05 slice 3: a planted refusal AGGREGATE for the same tenant (a different
        // name, empty model/provider — a distinct tuple) must NOT become a second
        // billable series. Before the `name != REJECTED_SPAN_NAME` filter this read 2.
        ch.query(
            "INSERT INTO tracelane.spans (tenant_id, trace_id, span_id, name, start_time, end_time, attributes) \
             VALUES (?, 'ri05-rej-trace', 'ri05-rej-span', ?, now64(6) - INTERVAL 30 MINUTE, now64(6) - INTERVAL 29 MINUTE, \
                     '{\"tracelane_rejection_reason\":\"rate_limited\",\"tracelane_rejection_count\":200}')",
        )
        .bind(&tid)
        .bind(crate::rejection_metrics::REJECTED_SPAN_NAME)
        .execute()
        .await
        .expect("insert the refusal aggregate");
        let series = query_series(&ch, &metas, None)
            .await
            .expect("series query must run");
        assert_eq!(
            series.get(&tid).copied(),
            Some(1.0),
            "a refusal aggregate is not a billable series: {series:?}"
        );
        let ingest_period =
            query_period_to_date_meter_counter(&ch, "ingest_bytes", &metas, Utc::now())
                .await
                .expect("period-to-date counter query must run");
        assert_eq!(
            ingest_period.get(&tid).copied(),
            if yesterday.month() == today.month() {
                Some(12.0)
            } else {
                None
            },
            "yesterday's 5 + 7 count when yesterday is in this calendar month: {ingest_period:?}"
        );

        // B-424: the trailing reads and the gap-backfill read run at all, and
        // the per-day series is the SUM of that day's counter rows. B-468: the
        // series is DENSE — 31 entries, yesterday LAST, every other day an
        // explicit zero.
        let trailing = query_trailing_daily_meter_counter(&ch, "ingest_bytes", today)
            .await
            .expect("trailing ingest read must run (B-424: NO_COMMON_TYPE until fixed)");
        let mut expected = vec![0.0; TRAILING_DAYS];
        expected[TRAILING_DAYS - 1] = 12.0;
        assert_eq!(trailing.get(&tid), Some(&expected), "{trailing:?}");
        let evals = query_trailing_daily_meter_counter(&ch, "eval_runs", today)
            .await
            .expect("trailing eval read must run");
        let mut expected = vec![0.0; TRAILING_DAYS];
        expected[TRAILING_DAYS - 1] = 1.0;
        assert_eq!(evals.get(&tid), Some(&expected));
        let scan_trailing =
            query_trailing_daily_scan_bytes(&ch, today.succ_opt().expect("tomorrow"))
                .await
                .expect("trailing scan read must run");
        let mut expected = vec![0.0; TRAILING_DAYS];
        expected[TRAILING_DAYS - 1] = scanned;
        assert_eq!(scan_trailing.get(&tid), Some(&expected));
        let done = query_completed_days(&ch, yesterday, today)
            .await
            .expect("completed-days read must run (B-424: NO_COMMON_TYPE until fixed)");
        assert!(
            done.contains(&yesterday),
            "the marker day must read back: {done:?}"
        );
        // B-426: the boot catch-up probe must RUN (it compared Date = UInt16 and
        // failed on every boot) and answer both ways.
        assert!(
            job_completed_on(&ch, yesterday)
                .await
                .expect("boot probe must run (B-426: ILLEGAL_TYPE_OF_ARGUMENT until fixed)"),
            "yesterday carries the marker"
        );
        // A day no run ever marks (this test's own `write_gauges` below marks
        // TODAY, and a re-run against the same server must still pass).
        let never = NaiveDate::from_ymd_opt(2000, 1, 1).expect("date");
        assert!(
            !job_completed_on(&ch, never)
                .await
                .expect("boot probe must run"),
            "an unmarked day answers false"
        );

        // And the writer round-trips a real f64 through `meter_gauges` — the
        // value the usage route will render, not a denormal.
        let mut hot_map = HashMap::new();
        hot_map.insert(tid.clone(), span_bytes as f64);
        let empty = HashMap::new();
        write_gauges(&ch, today, yesterday, &hot_map, &empty, &empty, &empty)
            .await
            .expect("write_gauges");
        let written: f64 = ch
            .query(
                "SELECT argMax(value, computed_at) FROM tracelane.meter_gauges \
                 WHERE tenant_id = ? AND meter = 'hot_resident_bytes' AND day = toDate(?)",
            )
            .bind(&tid)
            .bind(today.to_string())
            .fetch_one()
            .await
            .expect("read gauge back");
        assert_eq!(written, span_bytes as f64);
    }

    /// B-410 + B-420, against a REAL ClickHouse — the period anchoring of the
    /// series meter and the period-to-date counters is SQL semantics on the
    /// server, which no unit test can see (the three prod defects of
    /// 2026-09-16 were all of that class).
    ///
    /// Two tenants, identical data: three distinct series on the 10th and
    /// 20th of one month and the 3rd of the next, and ingest counters of 1,
    /// 2 and 4 on the same days. One tenant holds a Polar cycle running
    /// 15th → 15th; the other has no cycle. Read AS OF the 5th of the second
    /// month:
    /// - the cycle tenant's series count is the UNION over its cycle — the
    ///   20th and the 3rd, so 2 — and the 10th (the previous cycle) is out;
    ///   its ingest period-to-date is 2 + 4 = 6;
    /// - the calendar tenant falls back to that day's calendar month: 1
    ///   series (the 3rd) and 4 bytes.
    /// The calendar-month SQL this replaces answered 1 and nothing for the
    /// cycle tenant — a mid-month cycle spanning two partial months is exactly
    /// the shape Polar's `max` over the cycle then under-counted (B-420).
    ///
    /// Named with the `meter_reads_run_against_a_real_clickhouse` prefix on
    /// purpose: `scripts/ci/run-clickhouse-integration.sh` selects that name
    /// and cargo's filter is a substring match, so the runner picks this up
    /// without a script change.
    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn meter_reads_run_against_a_real_clickhouse_for_a_mid_month_cycle() {
        let Ok(url) = std::env::var("CLICKHOUSE_TEST_URL") else {
            panic!("CLICKHOUSE_TEST_URL not set — this test cannot run, which is not a pass");
        };
        let root = clickhouse::Client::default().with_url(&url);
        root.query("CREATE DATABASE IF NOT EXISTS tracelane")
            .execute()
            .await
            .expect("create database");
        let ch = clickhouse::Client::default()
            .with_url(&url)
            .with_database("tracelane");
        for sql in [
            include_str!("../../../../infra/dev/clickhouse/schema.sql"),
            include_str!(
                "../../../../infra/dev/clickhouse/migrations/24_bill01_meters_blobs_tiering.sql"
            ),
        ] {
            for stmt in crate::clickhouse_query::split_migration_statements(sql) {
                let _ = ch.query(&stmt).execute().await;
            }
        }

        let cycle_tenant = Uuid::new_v4();
        let calendar_tenant = Uuid::new_v4();
        let cycle_tid = cycle_tenant.to_string();
        let calendar_tid = calendar_tenant.to_string();
        // Fixed dates, well in the past, so the as-of read is deterministic.
        let days = ["2026-07-10", "2026-07-20", "2026-08-03"];
        let as_of = NaiveDate::from_ymd_opt(2026, 8, 5).expect("date");
        for tid in [&cycle_tid, &calendar_tid] {
            for (i, day) in days.iter().enumerate() {
                // One DISTINCT series per day (a different `name`), ingested the
                // moment it started so the as-of `ingested_at` bound keeps it.
                ch.query(
                    "INSERT INTO tracelane.spans (tenant_id, trace_id, span_id, name, start_time, end_time, attributes, ingested_at) \
                     VALUES (?, ?, ?, ?, toDateTime64(?, 6, 'UTC'), toDateTime64(?, 6, 'UTC'), '{}', toDateTime64(?, 3, 'UTC'))",
                )
                .bind(tid)
                .bind(format!("b420-trace-{i}"))
                .bind(format!("b420-span-{i}"))
                .bind(format!("b420 series {i}"))
                .bind(format!("{day} 12:00:00"))
                .bind(format!("{day} 12:00:01"))
                .bind(format!("{day} 12:00:01"))
                .execute()
                .await
                .expect("insert span");
                ch.query(
                    "INSERT INTO tracelane.meter_counters (tenant_id, day, meter, value) \
                     VALUES (?, toDate(?), 'ingest_bytes', ?)",
                )
                .bind(tid)
                .bind(*day)
                .bind(f64::from(1u32 << i)) // 1, 2, 4 — every subset sums differently
                .execute()
                .await
                .expect("insert counter");
            }
        }

        let mut on_cycle = meta(cycle_tenant, 30, 730);
        on_cycle.billing_period = Some(cycle((2026, 7, 15), (2026, 8, 15)));
        let metas = vec![on_cycle, meta(calendar_tenant, 30, 730)];
        let at = dt(2026, 8, 5, 12, 0);

        let series = query_series(&ch, &metas, Some(as_of))
            .await
            .expect("series query must run");
        assert_eq!(
            series.get(&cycle_tid).copied(),
            Some(2.0),
            "cycle 07-15 → 08-15 read on 08-05: the 20th and the 3rd, never the 10th: {series:?}"
        );
        assert_eq!(
            series.get(&calendar_tid).copied(),
            Some(1.0),
            "no cycle -> August's calendar month: the 3rd only: {series:?}"
        );

        let ingest = query_period_to_date_meter_counter(&ch, "ingest_bytes", &metas, at)
            .await
            .expect("period-to-date counter query must run");
        assert_eq!(
            ingest.get(&cycle_tid).copied(),
            Some(6.0),
            "cycle tenant: 2 (the 20th) + 4 (the 3rd), never the 10th's 1: {ingest:?}"
        );
        assert_eq!(
            ingest.get(&calendar_tid).copied(),
            Some(4.0),
            "calendar tenant: August only: {ingest:?}"
        );
    }
}

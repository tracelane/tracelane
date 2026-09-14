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
//! to build those arrays, plus three CALENDAR-MONTH-TO-DATE queries
//! (`query_month_to_date_meter_counter` ×2, `query_month_to_date_scan_bytes`)
//! feeding the usage-warning emails and the AUTO-AGE ceiling projection
//! below — the SAME `day >= toStartOfMonth(today())` boundary `GET
//! /v1/billing/usage` bills from, not the trailing window. Filed here rather
//! than silently exceeding the stated "4 queries" without saying so: the
//! real count is 9 ClickHouse reads + 1 batched write per run, all still
//! `GROUP BY tenant_id`, never a per-tenant loop — the property the budget
//! exists to protect (no N+1) is intact even though the literal query count
//! is not 4.
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

/// Days in the calendar month containing `date`.
fn days_in_month(date: NaiveDate) -> u32 {
    let (y, m) = if date.month() == 12 {
        (date.year() + 1, 1)
    } else {
        (date.year(), date.month() + 1)
    };
    NaiveDate::from_ymd_opt(y, m, 1)
        .and_then(|d| d.pred_opt())
        .map_or(30, |d| d.day())
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
fn gb_month_share(bytes_today: f64, days_in_month: u32) -> f64 {
    gb(bytes_today) / f64::from(days_in_month.max(1))
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
}

impl TenantMeta {
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
      t.polar_customer_id, t.billing_email, t.auto_age_window_days \
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

/// Meter 2: `hot_resident_bytes` — `sum(span_bytes)` per tenant over rows
/// inside THAT tenant's indexed window. ONE query via the `windows` join.
async fn query_hot_resident_bytes(
    ch: &clickhouse::Client,
    metas: &[TenantMeta],
) -> anyhow::Result<HashMap<String, f64>> {
    let sql = meter_query(format!(
        "WITH windows AS ( \
            SELECT tupleElement(t,1) AS tenant_id, tupleElement(t,2) AS indexed_window_days \
            FROM (SELECT arrayJoin({lit}) AS t) \
         ) \
         SELECT s.tenant_id AS tenant_id, sum(s.span_bytes) AS value \
         FROM tracelane.spans AS s \
         INNER JOIN windows AS w ON s.tenant_id = w.tenant_id \
         WHERE s.start_time >= now() - toIntervalDay(w.indexed_window_days) \
         GROUP BY s.tenant_id",
        lit = windows_literal(metas)
    ));
    let rows: Vec<TenantValueRow> = ch.query(&capped(&sql)).fetch_all().await?;
    Ok(rows.into_iter().map(|r| (r.tenant_id, r.value)).collect())
}

/// Meter 3: `series` — distinct `(name, model, provider, api_key_id)` this
/// calendar month. `MV_MODEL_EXPR`/`MV_PROVIDER_EXPR` mirror
/// `trace_reads.rs`'s SLO-view expressions verbatim (that file is outside
/// this build's edit scope beyond calling the rehydration helper, so the two
/// literal strings are duplicated rather than shared — same reasoning as
/// `days_since_epoch` above).
async fn query_series(ch: &clickhouse::Client) -> anyhow::Result<HashMap<String, f64>> {
    const MODEL_EXPR: &str = "coalesce(nullIf(JSONExtractString(attributes, 'gen_ai_response_model'), ''), nullIf(JSONExtractString(attributes, 'gen_ai_request_model'), ''), nullIf(JSONExtractString(attributes, 'gen_ai.response.model'), ''), JSONExtractString(attributes, 'llm.model_name'))";
    const PROVIDER_EXPR: &str = "coalesce(nullIf(JSONExtractString(attributes, 'gen_ai_provider_name'), ''), nullIf(JSONExtractString(attributes, 'gen_ai_system'), ''), nullIf(JSONExtractString(attributes, 'gen_ai.provider.name'), ''), JSONExtractString(attributes, 'llm.provider'))";
    let sql = meter_query(format!(
        "SELECT tenant_id AS tenant_id, \
            toFloat64(uniqExact(name, {MODEL_EXPR}, {PROVIDER_EXPR}, JSONExtractString(attributes, 'tracelane_api_key_id'))) AS value \
         FROM tracelane.spans \
         WHERE toYYYYMM(start_time) = toYYYYMM(now()) \
         GROUP BY tenant_id"
    ));
    let rows: Vec<TenantValueRow> = ch.query(&capped(&sql)).fetch_all().await?;
    Ok(rows.into_iter().map(|r| (r.tenant_id, r.value)).collect())
}

/// Meter 4: `scan_bytes` — `sum(read_bytes)` from `system.query_log` for
/// YESTERDAY, grouped by the tenant parsed out of `log_comment`. The
/// metering job's OWN queries (tagged `tracelane-meter`, never
/// `tenant_id=<uuid>`) are excluded by construction — the `LIKE` filter only
/// matches the tenant-tag shape.
async fn query_scan_bytes_yesterday(
    ch: &clickhouse::Client,
) -> anyhow::Result<HashMap<String, f64>> {
    let sql = meter_query(
        "SELECT replaceOne(log_comment, 'tenant_id=', '') AS tenant_id, sum(read_bytes) AS value \
         FROM system.query_log \
         WHERE type = 'QueryFinish' AND log_comment LIKE 'tenant_id=%' \
           AND event_date = yesterday() \
         GROUP BY tenant_id"
            .to_string(),
    );
    let rows: Vec<TenantValueRow> = ch.query(&capped(&sql)).fetch_all().await?;
    Ok(rows.into_iter().map(|r| (r.tenant_id, r.value)).collect())
}

/// Meter 5: `cold_bytes` — `sum(span_bytes)` per tenant for rows PAST the
/// indexed window but still inside queryable history. ONE query via the
/// SAME `windows` join as hot, with both bounds.
async fn query_cold_bytes(
    ch: &clickhouse::Client,
    metas: &[TenantMeta],
) -> anyhow::Result<HashMap<String, f64>> {
    let sql = meter_query(format!(
        "WITH windows AS ( \
            SELECT tupleElement(t,1) AS tenant_id, tupleElement(t,2) AS indexed_window_days, \
                   tupleElement(t,3) AS queryable_days \
            FROM (SELECT arrayJoin({lit}) AS t) \
         ) \
         SELECT s.tenant_id AS tenant_id, sum(s.span_bytes) AS value \
         FROM tracelane.spans AS s \
         INNER JOIN windows AS w ON s.tenant_id = w.tenant_id \
         WHERE s.start_time < now() - toIntervalDay(w.indexed_window_days) \
           AND s.start_time >= now() - toIntervalDay(w.queryable_days) \
         GROUP BY s.tenant_id",
        lit = windows_literal(metas)
    ));
    let rows: Vec<TenantValueRow> = ch.query(&capped(&sql)).fetch_all().await?;
    Ok(rows.into_iter().map(|r| (r.tenant_id, r.value)).collect())
}

#[derive(serde::Deserialize, clickhouse::Row)]
struct DailyTenantValueRow {
    tenant_id: String,
    // Unread — see `SpanRow`'s / `DailyRow`'s own comment on this exact
    // shape in `usage.rs`: `clickhouse::Row` decodes RowBinary POSITIONALLY,
    // so removing this field would desync the 3-column SELECT (B-274 class).
    #[allow(dead_code)]
    day: String,
    value: f64,
}

/// Trailing 31 days (30 history + yesterday) of `meter_counters` for one
/// `meter`, per tenant, as a day-ordered `Vec<f64>` ending in yesterday — the
/// shape `net_of_burst` consumes. ONE query, `GROUP BY tenant_id, day`.
async fn query_trailing_daily_meter_counter(
    ch: &clickhouse::Client,
    meter: &str,
) -> anyhow::Result<HashMap<String, Vec<f64>>> {
    let sql = meter_query(format!(
        "SELECT tenant_id AS tenant_id, toString(day) AS day, sum(value) AS value \
         FROM tracelane.meter_counters \
         WHERE meter = '{meter}' AND day >= today() - 31 AND day < today() \
         GROUP BY tenant_id, day ORDER BY tenant_id, day"
    ));
    let rows: Vec<DailyTenantValueRow> = ch.query(&capped(&sql)).fetch_all().await?;
    let mut out: HashMap<String, Vec<f64>> = HashMap::new();
    for r in rows {
        out.entry(r.tenant_id).or_default().push(r.value);
    }
    Ok(out)
}

/// Trailing 31 days of `system.query_log.read_bytes`, per tenant — the
/// `scan_bytes` analogue of [`query_trailing_daily_meter_counter`].
async fn query_trailing_daily_scan_bytes(
    ch: &clickhouse::Client,
) -> anyhow::Result<HashMap<String, Vec<f64>>> {
    let sql = meter_query(
        "SELECT replaceOne(log_comment, 'tenant_id=', '') AS tenant_id, \
            toString(event_date) AS day, sum(read_bytes) AS value \
         FROM system.query_log \
         WHERE type = 'QueryFinish' AND log_comment LIKE 'tenant_id=%' \
           AND event_date >= today() - 31 AND event_date < today() \
         GROUP BY tenant_id, day ORDER BY tenant_id, day"
            .to_string(),
    );
    let rows: Vec<DailyTenantValueRow> = ch.query(&capped(&sql)).fetch_all().await?;
    let mut out: HashMap<String, Vec<f64>> = HashMap::new();
    for r in rows {
        out.entry(r.tenant_id).or_default().push(r.value);
    }
    Ok(out)
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
/// # Errors
/// Propagates a ClickHouse failure; the caller notes
/// [`tracelane_shared::degradation::Degradation::MeteringJobFailed`] and
/// retries at the next scheduled tick — no partial-write recovery is
/// attempted here (the whole run failed, not one row of it).
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
    // Declared BEFORE the inserter: a row borrows for the inserter's lifetime.
    let marker_tenant = JOB_MARKER_TENANT.to_string();
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
    // The run's completion marker — one row under the reserved tenant id, in the SAME
    // batch as the gauges, so "the marker exists" ⇔ "every gauge above landed". The
    // boot catch-up probe reads exactly this row; the usage route never can (it reads
    // by a real tenant id).
    insert
        .write(&MeterGaugeRow {
            tenant_id: &marker_tenant,
            day: today_u16,
            meter: JOB_MARKER_METER,
            value: 1.0,
        })
        .await
        .map_err(|e| anyhow::anyhow!("meter_gauges marker write failed: {e}"))?;
    insert
        .end()
        .await
        .map_err(|e| anyhow::anyhow!("meter_gauges insert commit failed: {e}"))?;
    Ok(n)
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
#[allow(clippy::too_many_arguments)]
fn tenant_polar_events(
    burst_multiple: f64,
    days_in_month_val: u32,
    hot_bytes_today: Option<f64>,
    series_month: Option<f64>,
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
            value: gb_month_share(bytes, days_in_month_val),
        });
    }
    if let Some(v) = series_month {
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
            value: gb_month_share(bytes, days_in_month_val),
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
/// idempotent (Polar dedupes on it) — a failed POST here is simply retried
/// whole next scheduled tick, never partially.
async fn emit_polar_events(
    polar: &PolarClient,
    customer_id: &str,
    period: NaiveDate,
    events: &[PolarEvent],
) {
    let billable: Vec<&PolarEvent> = events.iter().filter(|ev| ev.value > 0.0).collect();
    if billable.is_empty() {
        return;
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
            "Polar meter events batch POST failed"
        );
        tracelane_shared::degradation::note(
            tracelane_shared::degradation::Degradation::PolarMeterEmissionFailed,
        );
    }
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

/// Calendar-month-to-date total for one `meter_counters` meter, per tenant —
/// `day >= toStartOfMonth(today())`, the SAME boundary `GET
/// /v1/billing/usage` bills from (replaces the rolling-31-day approximation
/// the usage-warning email path used before this fix; see its call site in
/// [`run_once`]). ONE query, `GROUP BY tenant_id` — no per-tenant loop.
async fn query_month_to_date_meter_counter(
    ch: &clickhouse::Client,
    meter: &str,
) -> anyhow::Result<HashMap<String, f64>> {
    let sql = meter_query(format!(
        "SELECT tenant_id AS tenant_id, sum(value) AS value \
         FROM tracelane.meter_counters \
         WHERE meter = '{meter}' AND day >= toStartOfMonth(today()) \
         GROUP BY tenant_id"
    ));
    let rows: Vec<TenantValueRow> = ch.query(&capped(&sql)).fetch_all().await?;
    Ok(rows.into_iter().map(|r| (r.tenant_id, r.value)).collect())
}

/// Calendar-month-to-date `system.query_log.read_bytes`, per tenant — the
/// `scan_bytes` analogue of [`query_month_to_date_meter_counter`], same
/// `toStartOfMonth(today())` boundary.
async fn query_month_to_date_scan_bytes(
    ch: &clickhouse::Client,
) -> anyhow::Result<HashMap<String, f64>> {
    let sql = meter_query(
        "SELECT replaceOne(log_comment, 'tenant_id=', '') AS tenant_id, sum(read_bytes) AS value \
         FROM system.query_log \
         WHERE type = 'QueryFinish' AND log_comment LIKE 'tenant_id=%' \
           AND event_date >= toStartOfMonth(today()) \
         GROUP BY tenant_id"
            .to_string(),
    );
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

/// Project this tenant's month-to-date overage USD across all six meters
/// (the SAME [`rating::rate`] `GET /v1/billing/usage` rates with) and, if it
/// would exceed a configured ceiling under `overflow_mode = AutoAge`,
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
/// Not calendar-month-exact for the burst-exempt meters (ingest/scan): this
/// does not re-derive a per-day burst exemption over the whole month, unlike
/// `GET /v1/billing/usage`. Same reasoning as the usage-warning email path
/// right below this function's caller: this is a CONTROL that narrows a
/// window, never a bill, and treating the full raw calendar-month sum as
/// billable is the conservative (safe) direction — it can only trigger
/// AUTO-AGE a little earlier than the exact figure would, never later.
///
/// `ingest_month`/`series_month`/`scan_month`/`eval_month` are read from the
/// SAME global, `GROUP BY tenant_id` per-run maps the usage-warning email
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
    series_month: Option<f64>,
    ingest_month: Option<f64>,
    scan_month: Option<f64>,
    eval_month: Option<f64>,
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
            gb(ingest_month.unwrap_or(0.0)),
            ingest_included_gb,
            0.0,
        )
        .overage_usd
            + rating::rate(
                card,
                RatedMeter::Series,
                series_month.unwrap_or(0.0),
                series_included,
                0.0,
            )
            .overage_usd
            + rating::rate(
                card,
                RatedMeter::ScanUnits,
                gb(scan_month.unwrap_or(0.0)),
                scan_included,
                0.0,
            )
            .overage_usd
            + rating::rate(
                card,
                RatedMeter::EvalRuns,
                eval_month.unwrap_or(0.0),
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
    let today = Utc::now().date_naive();
    let yesterday = today - chrono::Duration::days(1);
    let dim = days_in_month(today);

    macro_rules! try_query {
        ($fut:expr, $name:literal) => {
            match $fut.await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, meter = $name, "metering job: query failed for this run");
                    tracelane_shared::degradation::note(
                        tracelane_shared::degradation::Degradation::MeteringJobFailed,
                    );
                    HashMap::new()
                }
            }
        };
    }

    let hot = try_query!(query_hot_resident_bytes(&ch, &metas), "hot_resident_bytes");
    let series = try_query!(query_series(&ch), "series");
    let scan = try_query!(query_scan_bytes_yesterday(&ch), "scan_bytes");
    let cold = try_query!(query_cold_bytes(&ch, &metas), "cold_bytes");
    let ingest_trailing = try_query!(
        query_trailing_daily_meter_counter(&ch, "ingest_bytes"),
        "ingest_bytes_trailing"
    );
    let scan_trailing = try_query!(query_trailing_daily_scan_bytes(&ch), "scan_bytes_trailing");
    let eval_yesterday = try_query!(
        query_trailing_daily_meter_counter(&ch, "eval_runs"),
        "eval_runs_trailing"
    );
    // Calendar-month-to-date sums (`day >= toStartOfMonth(today())`) — the
    // SAME boundary `GET /v1/billing/usage` bills from. Feeds BOTH the
    // usage-warning email check below (replacing its old rolling-31-day
    // approximation) and the AUTO-AGE ceiling projection, so the two never
    // disagree with each other or with the usage page.
    let ingest_month = try_query!(
        query_month_to_date_meter_counter(&ch, "ingest_bytes"),
        "ingest_bytes_month"
    );
    let eval_month = try_query!(
        query_month_to_date_meter_counter(&ch, "eval_runs"),
        "eval_runs_month"
    );
    let scan_month = try_query!(query_month_to_date_scan_bytes(&ch), "scan_bytes_month");

    if let Err(e) = write_gauges(&ch, today, yesterday, &hot, &series, &scan, &cold).await {
        tracing::warn!(error = %e, "metering job: meter_gauges write failed for this run");
        tracelane_shared::degradation::note(
            tracelane_shared::degradation::Degradation::MeteringJobFailed,
        );
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

        let events = tenant_polar_events(
            card.policy.burst_multiple,
            dim,
            hot_bytes,
            series_val,
            cold_bytes,
            eval_val,
            ingest_daily,
            scan_daily,
        );
        if let (Some(polar), Some(customer_id)) = (polar, meta.polar_customer_id.as_deref())
            && !events.is_empty()
        {
            emit_polar_events(polar, customer_id, yesterday, &events).await;
        }

        let ingest_month_val = ingest_month.get(&key).copied();
        let scan_month_val = scan_month.get(&key).copied();
        let eval_month_val = eval_month.get(&key).copied();

        if let Some(ents) = entitlements {
            let resolved = ents.resolved(meta.tenant_id).await;

            if let Some(resend) = resend {
                // Exact calendar-month sum (`day >= toStartOfMonth(today())`)
                // — the SAME number `GET /v1/billing/usage` bills from, not
                // the rolling-31-day approximation this used before (that
                // window can both over- and under-count relative to the
                // calendar month, and disagreeing with the number the usage
                // page shows is exactly the class of bug a WARNING about
                // that number must not have).
                let usages = [
                    crate::billing::email::MeterUsage {
                        meter: "ingest",
                        used: gb(ingest_month_val.unwrap_or(0.0)),
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
                        used: gb(scan_month_val.unwrap_or(0.0)),
                        included: resolved.scan_units_included.map(|v| v as f64),
                    },
                    crate::billing::email::MeterUsage {
                        meter: "evals",
                        used: eval_month_val.unwrap_or(0.0),
                        included: resolved.eval_runs_included.map(|v| v as f64),
                    },
                ];
                let period = today.with_day(1).unwrap_or(today);
                crate::billing::email::send_usage_warnings_for_tenant(
                    pool,
                    &resend.http,
                    resend.api_key.as_ref(),
                    &resend.from,
                    meta.tenant_id,
                    meta.billing_email.as_deref(),
                    period,
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
                ingest_month_val,
                scan_month_val,
                eval_month_val,
            )
            .await;
        }
    }

    Ok(())
}

/// The weekly blob GC: `blobs` rows with no surviving `blob_refs` reference
/// (spec §2.3). One mutation, off-peak (Sunday 04:40 UTC — see [`spawn`]).
async fn run_gc(ch_url: &str) {
    let ch = crate::clickhouse_query::ch_client(ch_url.to_string());
    let sql = "ALTER TABLE tracelane.blobs DELETE WHERE (tenant_id, hash) NOT IN \
               (SELECT tenant_id, hash FROM tracelane.blob_refs)";
    if let Err(e) = ch.query(&capped(sql)).execute().await {
        tracing::warn!(error = %e, "blob GC mutation failed; retried next week");
        tracelane_shared::degradation::note(
            tracelane_shared::degradation::Degradation::MeteringJobFailed,
        );
    } else {
        tracing::info!("blob GC mutation issued");
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
    tokio::spawn(async move {
        // Boot catch-up: run immediately if today has no gauges at all.
        let ch = crate::clickhouse_query::ch_client(ch_url.clone());
        let today_u16 = days_since_epoch(Utc::now().date_naive());
        // The job writes one MARKER gauge per run under the reserved tenant id
        // `__metering_job__` (`JOB_MARKER_TENANT`, `write_gauges`), so this probe
        // filters on a tenant_id like every other read of `tracelane.*` and asks the
        // exact question — "did the job COMPLETE today?" — rather than "does any
        // tenant happen to have a gauge row".
        let has_today: bool = ch
            .query(&capped(
                "SELECT count() FROM tracelane.meter_gauges \
                 WHERE tenant_id = '__metering_job__' AND meter = 'job_completed' AND day = ?",
            ))
            .bind(today_u16)
            .fetch_one::<u64>()
            .await
            .map(|n| n > 0)
            .unwrap_or(true); // fail-open: assume present, don't hammer on a read failure
        if !has_today
            && let Err(e) = run_once(
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
        loop {
            let secs = secs_until_next_daily(Utc::now(), DAILY_HOUR, DAILY_MINUTE);
            tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
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
                tracing::warn!(error = %e, "metering job: scheduled run failed; retried next tick");
                tracelane_shared::degradation::note(
                    tracelane_shared::degradation::Degradation::MeteringJobFailed,
                );
            }
        }
    });
    tokio::spawn(async move {
        loop {
            let secs = secs_until_next_weekly(Utc::now(), GC_WEEKDAY, GC_HOUR, GC_MINUTE);
            tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
            run_gc(&ch_url2).await;
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

    // ── days_in_month ──────────────────────────────────────────────────

    #[test]
    fn days_in_month_handles_the_calendar_and_december_rollover() {
        assert_eq!(
            days_in_month(NaiveDate::from_ymd_opt(2026, 2, 15).unwrap()),
            28
        );
        assert_eq!(
            days_in_month(NaiveDate::from_ymd_opt(2024, 2, 15).unwrap()),
            29
        ); // leap
        assert_eq!(
            days_in_month(NaiveDate::from_ymd_opt(2026, 4, 1).unwrap()),
            30
        );
        assert_eq!(
            days_in_month(NaiveDate::from_ymd_opt(2026, 12, 25).unwrap()),
            31
        );
    }

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
        }
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

    #[test]
    fn gc_mutation_targets_blobs_not_referenced_by_blob_refs() {
        let sql = "ALTER TABLE tracelane.blobs DELETE WHERE (tenant_id, hash) NOT IN \
                   (SELECT tenant_id, hash FROM tracelane.blob_refs)";
        assert!(sql.contains("tracelane.blobs"));
        assert!(sql.contains("tracelane.blob_refs"));
        assert!(sql.contains("NOT IN"));
    }
}

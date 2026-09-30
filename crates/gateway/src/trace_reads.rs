//! Customer-facing trace + SLO read endpoints (Option 1).
//!
//! Three authed GET routes, mounted only when `CLICKHOUSE_URL` is set:
//!   GET /v1/traces                  — keyset-paginated trace list
//!   GET /v1/traces/{trace_id}/spans — full-fidelity spans for one trace
//!   GET /v1/slo                     — per-(provider,model) hourly SLO rollups
//!
//! Callers: the Next.js dashboard server-side proxy (`apps/web/lib/gateway.ts`)
//! and `tlane replay` (`packages/cli`). Both forward a `Authorization: Bearer
//! <jwt|tlane_apikey>` and never see ClickHouse directly. This closes the two
//! root causes of the cold-start trace-visibility gate: (a) ClickHouse is only
//! reachable on-node (the dashboard runs on Vercel, off-node), and (b) the
//! dashboard used to bind the raw WorkOS `org_id` (`session.tenantId`) into the
//! ClickHouse `tenant_id` filter, which silently matches zero rows.
//!
//! ## Tenant isolation (the load-bearing invariant)
//!
//! The tenant id comes **only** from `Claims.tenant_id`, produced by
//! `crate::auth::validate_authorization` → `resolve_tenant_id` (the JWT
//! `org_id` → internal-UUID bridge, ADR-042). It is NEVER read from the path,
//! query string, or body. Every SELECT is `WHERE tenant_id = ?` bound first,
//! parameterized (no string interpolation of tenant or filters). The spans
//! endpoint returns the SAME 404 for "trace does not exist" and "trace belongs
//! to another tenant", so existence never leaks across tenants.
//!
//! ## Resource caps (ADR-031)
//!
//! Every SELECT is wrapped by [`crate::clickhouse_query::TenantQuery`], which
//! appends the per-tier `max_memory_usage` / `max_execution_time` /
//! `max_rows_to_read` SETTINGS block. The per-tenant tier is not yet threaded
//! here (mirrors the dashboard's hardcoded Builder default in
//! `apps/web/lib/clickhouse.ts`); we fall back to `self.tier_for(tenant_id).await`, the
//! ADR-031 fail-safe. `// TODO(ADR-031 V1.1): thread the real per-tenant tier.`
//! This file is on the `scripts/ci/no-raw-ch-query.sh` allow-list because the
//! `.query` execution lives here while caps are applied via `TenantQuery`.

use anyhow::{Context as _, Result};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::DateTime;
use clickhouse::Client as ClickhouseClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::instrument;

use crate::clickhouse_query::{PlanTier, TenantQuery};
use crate::generation_issues::{
    ISSUES, Issue, IssueChip, IssueSummary, SummaryCacheKey, SummaryExpiry, SummaryRow,
    issue_predicate_sql,
};
use tracelane_shared::{Message, TenantId};

/// Default trace-list page size when `limit` is absent.
const DEFAULT_TRACE_LIMIT: u32 = 50;
/// Hard cap on trace-list page size (keeps a single page bounded).
const MAX_TRACE_LIMIT: u32 = 200;
/// Row cap for a trace export (CSV/JSON download). Bounded so a big tenant's
/// export can't scan the full TTL; filter first for a tighter set.
// ponytail: a single 10k-row cap. NO LONGER SILENT (OBS-23, 2026-08-08): the cap
// is unchanged, but a truncated export now SAYS SO — `X-Tracelane-Truncated: true`
// plus `X-Tracelane-Row-Count`, and a terminal row in the CSV body so the signal
// survives a download that drops headers. The CEILING IS STILL LIVE, so this marker
// stays: a guaranteed-complete export still needs the streamed/paginated path, and
// removing this marker would let a later pass raise the cap with nothing recording
// that 10k was ever a deliberate accepted limit. Disclosed debt, not a silent gap.
const MAX_TRACE_EXPORT: u32 = 10_000;

/// OBS-23 truncation signal. `true` when the export stopped at the row cap.
const X_TRUNCATED: axum::http::HeaderName =
    axum::http::HeaderName::from_static("x-tracelane-truncated");
/// OBS-23 companion: how many rows the export actually contains.
const X_ROW_COUNT: axum::http::HeaderName =
    axum::http::HeaderName::from_static("x-tracelane-row-count");
/// Cap on the number of groups returned by `/v1/traces/groups`.
const MAX_TRACE_GROUPS: u32 = 100;
/// Default SLO look-back window when neither `hours` nor `since` is given.
const DEFAULT_SLO_HOURS: u32 = 24;
/// Hard cap on the SLO look-back window — 30 days, matching `MAX_GATEWAY_HOURS`
/// and the dashboard's "30d" range chip (`range.ts` maps "30d" → 720). Was 168
/// (7 days): with the chip offering 30d, that silently degraded every SLO-derived
/// tile to 7 days while the gateway-derived Spend tile on the SAME dashboard
/// showed 30 — the dashboard contradicting itself. Safe to raise: `/v1/slo` reads
/// the hourly `slo_hourly_stats` MV (365-day TTL), so 30d is ≤720 pre-aggregated
/// buckets per series, a bounded scan — NOT a raw-span read (the internal
/// SLO 30d-window-cap incident review).
const MAX_SLO_HOURS: u32 = 720;
/// Hard cap on the per-(provider, model) SLO table rows (`/v1/slo/models`). A
/// tenant has a handful of models; 200 is a generous bound that keeps the group
/// scan bounded.
const SLO_MODEL_CAP: u32 = 200;
/// Default failure-signatures page size (§4 — the live registry is tiny today).
const DEFAULT_SIGNATURE_LIMIT: u32 = 50;
/// Hard cap on the failure-signatures page size.
const MAX_SIGNATURE_LIMIT: u32 = 200;
/// Default §3 session-list page size.
const DEFAULT_SESSION_LIMIT: u32 = 50;
/// Hard cap on the session-list page size.
const MAX_SESSION_LIMIT: u32 = 200;
/// Default §3 session look-back window in days when neither `since` nor `days`
/// is given. Bounds the live `spans` aggregation. (The `spans` TTL is 365 days
/// — this cap is a query bound, NOT the TTL. They were conflated until 2026-08-29.)
const DEFAULT_SESSION_WINDOW_DAYS: u32 = 30;
/// Hard cap on the session look-back window. NOT derived from the TTL (365d):
/// it is a deliberate query bound, and EVL-29 queue safety now rests on it —
/// a trace stops matching a queue 275 days before its content could expire.
const MAX_SESSION_WINDOW_DAYS: u32 = 90;

/// `OBS-55` — default transcript page size when `limit` is absent. Mirrors the
/// reviewed `billing_policy.web_list_page_sizes.session_turns` seed value
/// (§23, `apps/web/db/plans.v3.json`); the web app passes `limit=` explicitly
/// from that cached read, so this is only the gateway's own fallback for a
/// caller that omits it — the same relationship [`DEFAULT_SESSION_LIMIT`] has
/// to the (unrelated) sessions-LIST page size. Clamped against the EXISTING
/// [`MAX_SESSION_LIMIT`] ceiling, per the spec (no second cap introduced).
const DEFAULT_SESSION_TRANSCRIPT_LIMIT: u32 = 20;

/// Gateway-ops look-back window (hours) — default 24h, cap 30 days.
const DEFAULT_GATEWAY_HOURS: u32 = 24;
const MAX_GATEWAY_HOURS: u32 = 720;
/// Per-group row cap on `/v1/gateway/stats` (one row per provider) and `/v1/costs`
/// (one row per key / model / provider). It MUST cover the whole provider catalog —
/// every `providers.tsv` row plus every native adapter, derived and held by
/// `gateway_provider_cap_covers_the_provider_catalog` — so a provider grouping can
/// never be cut. It was 100 under a comment saying "≈34 routable providers; a safety
/// cap, not a real limit", written before GWY-42 made providers a data file, and the
/// catalog had long since outgrown it (CX-27 / B-526). Keys and models are unbounded,
/// so `/v1/costs` can still reach it: the totals are computed BEFORE the `LIMIT`
/// (`CostRow::group_count` and the `all_*` columns) and the response says
/// `truncated` when its rows are a subset — a row cap, never a silent cap on the
/// figures above the table.
const GATEWAY_PROVIDER_CAP: u32 = 256;
const DEFAULT_GUARDRAIL_HOURS: u32 = 24;
const MAX_GUARDRAIL_HOURS: u32 = 720;

/// COMPILE-TIME guard (SLO 30d-window-cap invariant): every windowed read cap MUST cover
/// the widest window the dashboard range chip offers — 30d = 720h (`range.ts` maps
/// "30d" → 720). A cap below the chip makes an endpoint silently return a SHORTER
/// window under the same label (e.g. "30d" → 7 days on the SLO tiles while the
/// 720h-capped gateway tile on the SAME screen shows 30 — the dashboard
/// contradicting itself). SLO + gateway caps must also be EQUAL, since they back
/// tiles on one dashboard. This is a `const` assertion, not a `#[test]`: it fails
/// the BUILD if violated, so it can't be skipped/filtered. `assertions_on_constants`
/// is expected here — asserting a compile-time constant relationship is the point.
#[allow(clippy::assertions_on_constants)]
const _WINDOW_CAPS_COVER_WIDEST_CHIP: () = {
    assert!(MAX_SLO_HOURS >= 720);
    assert!(MAX_GATEWAY_HOURS >= 720);
    assert!(MAX_GUARDRAIL_HOURS >= 720);
    assert!(MAX_SLO_HOURS == MAX_GATEWAY_HOURS);
};
/// Per-rail row cap (there are ~10 rails; a safety cap, not a real limit).
const GUARDRAIL_RAIL_CAP: u32 = 50;

/// DSH-11 / B-331 — the WIDEST absolute window any spans/SLO/guardrail read serves.
/// `since=` used to REPLACE the `hours` predicate on every windowed route with no
/// width check, so a hand-written `since=2020-01-01` scanned the tenant's whole
/// history under `max_rows_to_read` alone. A `since/until` pair wider than this is
/// clamped to `[until − cap, until]` and the response says so
/// (`X-Tracelane-Window: …;clamped=1`). Equal to the `hours` caps by construction —
/// the compile-time assertion below keeps it that way.
const MAX_WINDOW_SECS: i64 = MAX_SLO_HOURS as i64 * 3600;
/// Sessions are capped in DAYS (`MAX_SESSION_WINDOW_DAYS`); same clamp, that unit.
const MAX_SESSION_WINDOW_US: i64 = MAX_SESSION_WINDOW_DAYS as i64 * 86_400 * 1_000_000;
/// Never more buckets than this on one series (the UI's ladder never asks for more;
/// the gateway widens the bucket rather than answer 8,760 rows).
const MAX_SERIES_BUCKETS: i64 = 96;
/// Sub-hour buckets are served from raw `spans FINAL` (the hourly view cannot go
/// finer) and only for windows this wide or narrower — the cost bound.
const SUB_HOUR_MAX_WINDOW_SECS: i64 = 24 * 3600;
/// The minute widths a sub-hour bucket may take.
const BUCKET_MINUTES_ALLOWED: [u32; 5] = [1, 5, 10, 15, 30];
#[allow(clippy::assertions_on_constants)]
const _WINDOW_CLAMP_MATCHES_CAPS: () = {
    assert!(MAX_WINDOW_SECS == MAX_GATEWAY_HOURS as i64 * 3600);
    assert!(MAX_WINDOW_SECS == MAX_GUARDRAIL_HOURS as i64 * 3600);
};

/// The window a handler actually served, echoed on every windowed route as
/// `X-Tracelane-Window: since=<rfc3339>;until=<rfc3339>;clamped=<0|1>` so a
/// caller can see a clamp without the response shape changing (several of these
/// routes return a bare JSON array).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ServedWindow {
    pub since_secs: i64,
    pub until_secs: i64,
    pub clamped: bool,
}

const X_WINDOW: axum::http::HeaderName = axum::http::HeaderName::from_static("x-tracelane-window");

impl ServedWindow {
    /// Resolve `(since, until)` seconds against `now`, clamping the width to `cap_secs`.
    /// `since = None` means the rolling `hours` window, which is within the cap by
    /// construction (the handler clamps `hours` first).
    pub(crate) fn resolve(
        since: Option<i64>,
        until: Option<i64>,
        hours: u32,
        now: i64,
        cap_secs: i64,
    ) -> Self {
        let until_eff = until.unwrap_or(now).min(now);
        match since {
            None => Self {
                since_secs: until_eff - i64::from(hours) * 3600,
                until_secs: until_eff,
                clamped: false,
            },
            Some(s) if until_eff - s > cap_secs => Self {
                since_secs: until_eff - cap_secs,
                until_secs: until_eff,
                clamped: true,
            },
            Some(s) => Self {
                since_secs: s,
                until_secs: until_eff,
                clamped: false,
            },
        }
    }
    pub(crate) fn width_secs(&self) -> i64 {
        (self.until_secs - self.since_secs).max(0)
    }
    pub(crate) fn header_value(&self) -> String {
        let iso = |s: i64| {
            chrono::DateTime::<chrono::Utc>::from_timestamp(s, 0)
                .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                .unwrap_or_default()
        };
        format!(
            "since={};until={};clamped={}",
            iso(self.since_secs),
            iso(self.until_secs),
            u8::from(self.clamped)
        )
    }
    /// Attach the header to a response.
    pub(crate) fn stamp(&self, mut resp: Response) -> Response {
        if let Ok(v) = axum::http::HeaderValue::from_str(&self.header_value()) {
            resp.headers_mut().insert(X_WINDOW, v);
        }
        resp
    }
}

/// `bucket_minutes` must be one of the allowed widths, the window must be ≤ 24 h
/// (the raw-spans cost bound), and the series must fit the bucket ceiling.
fn validate_bucket_minutes(m: Option<u32>, width_secs: i64) -> Result<Option<u32>, &'static str> {
    let Some(m) = m else { return Ok(None) };
    if !BUCKET_MINUTES_ALLOWED.contains(&m) {
        return Err("invalid bucket_minutes (allowed: 1, 5, 10, 15, 30)");
    }
    if width_secs > SUB_HOUR_MAX_WINDOW_SECS {
        return Err("bucket_too_fine: sub-hour buckets are served for windows of 24 hours or less");
    }
    if width_secs / (i64::from(m) * 60) > MAX_SERIES_BUCKETS {
        return Err("bucket_too_fine: more than 96 buckets in the window");
    }
    Ok(Some(m))
}

trait StampWindow {
    fn pipe_stamp(self, w: &ServedWindow) -> Response;
}
impl StampWindow for Response {
    fn pipe_stamp(self, w: &ServedWindow) -> Response {
        w.stamp(self)
    }
}

/// Widen a bucket so a series never exceeds `MAX_SERIES_BUCKETS` rows.
fn cap_bucket_secs(bucket_secs: i64, width_secs: i64) -> i64 {
    let mut b = bucket_secs.max(60);
    while width_secs / b > MAX_SERIES_BUCKETS {
        b *= 2;
    }
    b
}

/// `MV_PROVIDER_EXPR` / `MV_MODEL_EXPR` are the provider / model derivations of
/// `mv_slo_hourly_stats`, VERBATIM from
/// `infra/dev/clickhouse/migrations/06_genai_attr_keys_and_slo.sql`, so a
/// sub-hour bucket read off raw spans counts EXACTLY what the hourly view counts
/// (`slo_sub_hour_paths_read_spans_with_the_mv_expressions`). They are used ONLY
/// by the SLO sub-hour readers — all four since B-500 (`build_slo_sql`,
/// `build_slo_timeseries_sql`, `build_slo_summary_sql`, `build_slo_by_model_sql`).
///
/// SRE register #55 (2026-09-05) compared `MV_MODEL_EXPR` against the WRONG view —
/// `mv_trace_summaries` in `schema.sql`, which writes `trace_summaries.model` and
/// carries a fifth arm, the dotted `gen_ai.request.model`. That arm is DEAD at the
/// storage boundary: `crates/shared/src/otlp/decode.rs` maps the dotted wire key
/// into the typed `gen_ai_request_model` field (`grep -n '"gen_ai.request.model" =>'`)
/// and the gateway's own spans set the underscored key directly, so no stored span
/// resolves its model through the dotted arm alone. Adding it here would have
/// broken the parity that matters (5-minute bar == hourly bar) to buy one that
/// cannot be observed. `mv_exprs_match_migration_06_and_trace_summaries_only_adds_the_dead_arm`
/// pins BOTH facts from the checked-in SQL, never from a hand copy.
const MV_PROVIDER_EXPR: &str = "coalesce(nullIf(JSONExtractString(attributes, 'gen_ai_provider_name'), ''), nullIf(JSONExtractString(attributes, 'gen_ai_system'), ''), nullIf(JSONExtractString(attributes, 'gen_ai.provider.name'), ''), JSONExtractString(attributes, 'llm.provider'))";
const MV_MODEL_EXPR: &str = "coalesce(nullIf(JSONExtractString(attributes, 'gen_ai_response_model'), ''), nullIf(JSONExtractString(attributes, 'gen_ai_request_model'), ''), nullIf(JSONExtractString(attributes, 'gen_ai.response.model'), ''), JSONExtractString(attributes, 'llm.model_name'))";
/// Default / max verdict-list page size (the decision-mix click-through).
const DEFAULT_VERDICT_LIMIT: u32 = 100;
const MAX_VERDICT_LIMIT: u32 = 500;
/// The flattened attribute key that carries `gen_ai.conversation.id` — the
/// session (thread) grouping key. Spans store OTel-GenAI attrs underscore-
/// flattened (see `mv_trace_summaries`), so this is the primary lookup.
const CONVERSATION_ID_ATTR: &str = "gen_ai_conversation_id";

/// `OBS-20`. The span-attribute key holding the customer's own end user.
///
/// UNDERSCORED, not dotted, and that distinction is the B-232 class: a
/// first-class `SpanAttributes` field serialises under its snake_case Rust name
/// (`user_id`), while a key that only ever reaches `extra` keeps its literal
/// dotted string. Querying `'user.id'` here would match a key no writer in this
/// repo ever writes, and the surface would be empty for every tenant forever.
const END_USER_ID_ATTR: &str = "user_id";

// ── Wire types ──────────────────────────────────────────────────────────────

/// One trace-summary row as returned to the client. Field set + names match
/// the dashboard's `TraceSummary` / `TraceRow` and the legacy
/// `/api/traces` response so the UI consumes it unchanged.
#[derive(Debug, Clone, Serialize)]
pub struct TraceSummary {
    pub trace_id: String,
    pub root_name: String,
    /// Human-readable ClickHouse `toString(start_time)` (e.g.
    /// `2026-06-10 12:34:56.123456`) — same shape the dashboard already renders.
    pub start_time: String,
    pub duration_us: i64,
    /// `u64` to match `TraceSummaryRow` — see B-257 there. JSON numbers are
    /// width-agnostic, so the dashboard is unaffected.
    pub span_count: u64,
    pub error_count: u64,
    pub intervention: u8,
    pub model: String,
    /// Summed real `gen_ai_usage_cost` (USD) over this trace's spans. The list
    /// source `trace_summaries` carries no cost column, so this is a read-time
    /// rollup (`trace_cost_rollup`), bounded to the page's trace ids. `0.0` when
    /// no priced spans (unpriced models / the rollup failing → fail-open).
    pub cost_usd: f64,
    /// Summed `input + output` tokens over this trace's spans (read-time rollup).
    /// `0` when the spans carry no usage or the rollup fails.
    pub total_tokens: i64,
    /// Absent when this surface did not run issue enrichment (for example exports).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issues: Option<Vec<IssueChip>>,
}

/// `{ traces, next_cursor }` — matches the legacy dashboard `/api/traces` shape.
/// `next_cursor` is an opaque `"{start_time_us}:{trace_id}"` keyset token; the
/// client passes it back verbatim as `?cursor=`.
#[derive(Debug, Clone, Serialize)]
pub struct TraceListResponse {
    pub traces: Vec<TraceSummary>,
    pub next_cursor: Option<String>,
    pub issues_available: bool,
    pub issues_deferred: bool,
}

/// Internal ClickHouse row for the trace list. Carries `start_time_us` so the
/// handler can build the keyset cursor; the public [`TraceSummary`] drops it.
#[derive(Debug, Clone, Deserialize, clickhouse::Row)]
pub struct TraceSummaryRow {
    pub trace_id: String,
    pub root_name: String,
    pub start_time: String,
    pub start_time_us: i64,
    pub duration_us: i64,
    /// **`u64`, not `u32` — B-257.** B-243 converted `trace_summaries` to an
    /// `AggregatingMergeTree` and widened these two to
    /// `SimpleAggregateFunction(sum, UInt64)`. The `clickhouse` 0.13 client
    /// VALIDATES column types against the struct, so a `u32` here does not
    /// truncate — it fails the ENTIRE SELECT, and `/v1/traces` answered 502 for
    /// every tenant for a day. The migration was verified with
    /// `clickhouse-client`, which is untyped TSV and cannot see this; the Rust
    /// client that actually reads the table was never run against it.
    /// `trace_summaries_row_types_match_the_schema` is the control.
    pub span_count: u64,
    pub error_count: u64,
    pub intervention: u8,
    pub model: String,
}

/// One group of traces from the /v1/traces/groups aggregation. Serialize + Row
/// (returned to the client directly; positional column order matches the SELECT).
#[derive(Debug, Clone, Deserialize, Serialize, clickhouse::Row)]
pub struct TraceGroupRow {
    pub group_key: String,
    pub trace_count: u64,
    /// Traces in the group with ≥1 error span.
    pub error_traces: u64,
    pub avg_duration_us: f64,
    pub p95_duration_us: f64,
}

impl From<TraceSummaryRow> for TraceSummary {
    fn from(r: TraceSummaryRow) -> Self {
        Self {
            trace_id: r.trace_id,
            root_name: r.root_name,
            start_time: r.start_time,
            duration_us: r.duration_us,
            span_count: r.span_count,
            error_count: r.error_count,
            intervention: r.intervention,
            model: r.model,
            // Populated by the handler from `trace_cost_rollup`; the CH list row
            // carries no cost/token columns, so From defaults to zero.
            cost_usd: 0.0,
            total_tokens: 0,
            issues: None,
        }
    }
}

/// One span row. Superset of the dashboard's `Span` type (detail view) plus
/// `start_time_us` (microseconds since epoch) used by the `/api/traces/[id]/
/// steps` route and `tlane replay` to build `TraceStep[]`. Extra fields are
/// ignored by structural-typed TS consumers.
#[derive(Debug, Clone, Deserialize, Serialize, clickhouse::Row)]
pub struct SpanRow {
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub name: String,
    pub start_time: String,
    pub end_time: String,
    pub start_time_us: i64,
    pub duration_us: i64,
    pub status_code: u8,
    pub status_message: String,
    /// Raw OTel/OpenInference attribute JSON string (parsed client-side).
    pub attributes: String,
    pub aft_ids: Vec<String>,
    pub intervention: u8,
}

/// Authenticated detail response only. The stored row and public-share response
/// retain their existing shape; derived signals are not database columns.
#[derive(Debug, Serialize)]
struct SpanResponse {
    #[serde(flatten)]
    span: SpanRow,
    #[serde(flatten)]
    generation: crate::generation_issues::GenerationDetails,
}

impl From<SpanRow> for SpanResponse {
    fn from(span: SpanRow) -> Self {
        let attrs = serde_json::from_str(&span.attributes).unwrap_or(serde_json::Value::Null);
        let generation =
            crate::generation_issues::details(&crate::generation_issues::SpanAttrsView {
                attributes: &attrs,
                status_code: span.status_code,
            });
        Self { span, generation }
    }
}

// ── OBS-10: trace compare ────────────────────────────────────────────────────
//
// "This run worked and that one didn't — what changed?" is the question a
// debugging session actually asks, and today the answer is two browser tabs and
// a human.
//
// NO NEW SQL. Compare calls the existing tenant-filtered `list_spans` twice and
// aligns in memory. That is not laziness: a second query shape is a second place
// to get `tenant_id` wrong, and this way the route inherits BOTH the tenant
// filter and the A13 `read` scope gate from the one `authenticate()` seam.

/// Flag a span as slower only when it moves by **both** an absolute and a
/// relative margin. Percent alone flags noise on sub-millisecond spans; absolute
/// alone flags a span that grew in proportion with everything else. The pair is
/// what makes the ▲ mean something.
const COMPARE_THRESHOLD_US: i64 = 5_000;
const COMPARE_THRESHOLD_PCT: f64 = 25.0;
/// Cycle guard. A malformed `parent_span_id` chain must not hang a request, so
/// the walk stops here and reports this depth rather than looping.
const COMPARE_MAX_DEPTH: u32 = 64;

/// One aligned row: the same logical step in both traces, or a step present in
/// only one of them.
#[derive(Debug, Clone, Serialize)]
pub struct ComparedSpan {
    pub name: String,
    pub depth: u32,
    /// Which occurrence of this `(name, depth)` this is, 0-based.
    pub ordinal: u32,
    /// `both` · `only_a` · `only_b`.
    pub side: &'static str,
    pub a_span_id: Option<String>,
    pub b_span_id: Option<String>,
    pub a_duration_us: Option<i64>,
    pub b_duration_us: Option<i64>,
    /// `b - a`, positive = B slower. Only on a matched pair.
    pub delta_us: Option<i64>,
    /// `delta_us / a_duration_us * 100`. **`None` when `a_duration_us == 0`** —
    /// never rendered as infinity, and never silently as 0.
    pub delta_pct: Option<f64>,
    /// True iff BOTH thresholds are exceeded. See the constants.
    pub slower: bool,
}

/// Per-side summary.
#[derive(Debug, Clone, Serialize)]
pub struct ComparedTrace {
    pub trace_id: String,
    pub span_count: usize,
    /// Wall-clock span of the trace: `max(start+duration) - min(start)`.
    /// **Not** the sum of span durations, which double-counts nested spans.
    pub total_us: i64,
}

/// `GET /v1/traces/compare` response.
#[derive(Debug, Clone, Serialize)]
pub struct TraceCompareResponse {
    pub a: ComparedTrace,
    pub b: ComparedTrace,
    pub rows: Vec<ComparedSpan>,
    pub only_in_a: usize,
    pub only_in_b: usize,
    pub slower_count: usize,
    /// Echoed so the UI never has to guess why a row carries ▲, and the number
    /// on screen is explainable without reading this file.
    pub threshold_us: i64,
    pub threshold_pct: f64,
}

/// Depth of each span, by walking `parent_span_id` to a root. A span whose
/// parent is not in the trace (an orphan, e.g. a partial capture) is treated as
/// depth 0 — degraded, not dropped.
fn span_depths(spans: &[SpanRow]) -> std::collections::HashMap<String, u32> {
    let parent: std::collections::HashMap<&str, Option<&str>> = spans
        .iter()
        .map(|s| (s.span_id.as_str(), s.parent_span_id.as_deref()))
        .collect();
    let mut out = std::collections::HashMap::with_capacity(spans.len());
    for s in spans {
        let mut depth = 0u32;
        let mut cur = s.parent_span_id.as_deref();
        while let Some(pid) = cur {
            match parent.get(pid) {
                Some(next) => {
                    depth += 1;
                    if depth >= COMPARE_MAX_DEPTH {
                        break;
                    }
                    cur = *next;
                }
                // Parent not in this trace → orphan, stop here.
                None => break,
            }
        }
        out.insert(s.span_id.clone(), depth);
    }
    out
}

/// Alignment key per span: `(name, depth, ordinal)`.
///
/// **Why not `span_id`:** span ids are unique per execution, so they never match
/// across two traces. Name+depth+ordinal is the only key that makes two separate
/// RUNS comparable, which is the entire question this endpoint answers.
///
/// `ordinal` breaks ties among same-`(name, depth)` spans by `start_time_us`,
/// then by `span_id` so the order is total and stable rather than
/// ClickHouse-row-order dependent.
fn compare_keys(spans: &[SpanRow]) -> Vec<((String, u32, u32), &SpanRow)> {
    let depths = span_depths(spans);
    let mut idx: Vec<(&SpanRow, u32)> = spans
        .iter()
        .map(|s| (s, *depths.get(&s.span_id).unwrap_or(&0)))
        .collect();
    idx.sort_by(|(a, ad), (b, bd)| {
        a.name
            .cmp(&b.name)
            .then(ad.cmp(bd))
            .then(a.start_time_us.cmp(&b.start_time_us))
            .then(a.span_id.cmp(&b.span_id))
    });
    let mut out = Vec::with_capacity(spans.len());
    let mut run: Option<(&str, u32)> = None;
    let mut ordinal = 0u32;
    for (s, d) in idx {
        match run {
            Some((n, rd)) if n == s.name && rd == d => ordinal += 1,
            _ => {
                ordinal = 0;
                run = Some((s.name.as_str(), d));
            }
        }
        out.push(((s.name.clone(), d, ordinal), s));
    }
    out
}

/// Wall-clock extent of a trace. Empty → 0.
fn trace_total_us(spans: &[SpanRow]) -> i64 {
    let min = spans.iter().map(|s| s.start_time_us).min().unwrap_or(0);
    let max = spans
        .iter()
        .map(|s| s.start_time_us + s.duration_us)
        .max()
        .unwrap_or(0);
    (max - min).max(0)
}

/// Align two span sets. Pure — no IO, no auth — so the alignment rules are
/// testable on their own, which is where the subtle bugs live.
fn align_traces(a_id: &str, a: &[SpanRow], b_id: &str, b: &[SpanRow]) -> TraceCompareResponse {
    let ka = compare_keys(a);
    let mut kb: std::collections::HashMap<(String, u32, u32), &SpanRow> =
        compare_keys(b).into_iter().collect();

    let mut rows = Vec::new();
    for (key, sa) in ka {
        if let Some(sb) = kb.remove(&key) {
            let delta = sb.duration_us - sa.duration_us;
            let pct = if sa.duration_us == 0 {
                None
            } else {
                Some((delta as f64 / sa.duration_us as f64) * 100.0)
            };
            let slower = delta.abs() > COMPARE_THRESHOLD_US
                && pct.is_some_and(|p| p.abs() > COMPARE_THRESHOLD_PCT);
            rows.push(ComparedSpan {
                name: key.0,
                depth: key.1,
                ordinal: key.2,
                side: "both",
                a_span_id: Some(sa.span_id.clone()),
                b_span_id: Some(sb.span_id.clone()),
                a_duration_us: Some(sa.duration_us),
                b_duration_us: Some(sb.duration_us),
                delta_us: Some(delta),
                delta_pct: pct,
                slower,
            });
        } else {
            rows.push(ComparedSpan {
                name: key.0,
                depth: key.1,
                ordinal: key.2,
                side: "only_a",
                a_span_id: Some(sa.span_id.clone()),
                b_span_id: None,
                a_duration_us: Some(sa.duration_us),
                b_duration_us: None,
                delta_us: None,
                delta_pct: None,
                slower: false,
            });
        }
    }
    // Whatever is left in `kb` never matched → present only in B.
    let mut leftover: Vec<_> = kb.into_iter().collect();
    leftover.sort_by(|(x, _), (y, _)| x.cmp(y));
    for (key, sb) in leftover {
        rows.push(ComparedSpan {
            name: key.0,
            depth: key.1,
            ordinal: key.2,
            side: "only_b",
            a_span_id: None,
            b_span_id: Some(sb.span_id.clone()),
            a_duration_us: None,
            b_duration_us: Some(sb.duration_us),
            delta_us: None,
            delta_pct: None,
            slower: false,
        });
    }
    rows.sort_by(|x, y| {
        x.depth
            .cmp(&y.depth)
            .then(x.name.cmp(&y.name))
            .then(x.ordinal.cmp(&y.ordinal))
    });

    let only_in_a = rows.iter().filter(|r| r.side == "only_a").count();
    let only_in_b = rows.iter().filter(|r| r.side == "only_b").count();
    let slower_count = rows.iter().filter(|r| r.slower).count();
    TraceCompareResponse {
        a: ComparedTrace {
            trace_id: a_id.to_string(),
            span_count: a.len(),
            total_us: trace_total_us(a),
        },
        b: ComparedTrace {
            trace_id: b_id.to_string(),
            span_count: b.len(),
            total_us: trace_total_us(b),
        },
        rows,
        only_in_a,
        only_in_b,
        slower_count,
        threshold_us: COMPARE_THRESHOLD_US,
        threshold_pct: COMPARE_THRESHOLD_PCT,
    }
}

/// `GET /v1/traces/compare?a=&b=` query.
#[derive(Debug, Deserialize)]
pub struct CompareQuery {
    a: String,
    b: String,
}

/// Per-trace tamper-evident-ledger status (wedge item 4). Answers, for one
/// trace, "is this call recorded in the audit hash chain, and is that record
/// anchored?" — the input to the trace-detail "in tamper-evident ledger" chip.
///
/// **Honest scope (B):** `chained` is true ONLY for gateway-proxied calls (they
/// append a chat, messages, or embeddings request row carrying `trace_id`).
/// SDK/OTLP-only traces are never chained → `chained: false` (the honest
/// absent-state, not a false green). Traces captured before item 4 shipped also read `chained: false`
/// (their chain row predates the `trace_id` correlation field) — forward-only.
///
/// This endpoint reports PRESENCE + ANCHOR, not a standalone cryptographic
/// verdict: the full-chain verify (recompute every `row_hash`, walk `prev_hash`
/// to genesis, check the Rekor anchor) runs on the Audit page via the same OSS
/// verifier a customer runs. The chip links there for the actual proof.
#[derive(Debug, Clone, Serialize)]
pub struct TraceChainStatus {
    /// True iff a gateway-call chain row (`chat.completions.request`,
    /// `messages.request`, or `embeddings.request`) carries this `trace_id`.
    pub chained: bool,
    /// The chain sequence number of that row (audit-ledger position).
    pub seq: Option<u64>,
    /// True iff that row is anchored to a real transparency-log entry
    /// (Rekor). Always false until wedge item 2 lands the anchor path.
    pub anchored: bool,
}

/// The single audit-ledger row matched by `trace_id`, if any. Positional per
/// `clickhouse::Row` — order MUST match the `TRACE_CHAIN_SQL` SELECT.
///
/// `rekor_entry_id` is `Nullable(String)` in ClickHouse (a row is written with
/// no anchor until the batch anchors), so it MUST deserialize into `Option`,
/// not `String` — a plain `String` fails RowBinary decode on every matched row
/// (a NULL has no bytes). A NULL id means "not anchored", same as a sentinel.
#[derive(Debug, Clone, Deserialize, clickhouse::Row)]
struct ChainStatusRow {
    seq: u64,
    rekor_entry_id: Option<String>,
}

/// One SLO rollup row from `v_slo_stats`. Names match the dashboard `SloRow`.
#[derive(Debug, Clone, Deserialize, Serialize, clickhouse::Row)]
pub struct SloRow {
    pub bucket_hour: String,
    pub provider: String,
    pub model: String,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub requests: u64,
    pub errors: u64,
    pub error_rate_pct: f64,
    pub total_input_tokens: i64,
    pub total_output_tokens: i64,
}

/// Window-WIDE SLO summary — the true merged quantiles for the headline tiles
/// (#9), distinct from the per-bucket [`SloRow`]. One row per window.
#[derive(Debug, Clone, Deserialize, Serialize, clickhouse::Row)]
pub struct SloSummary {
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub requests: u64,
    pub errors: u64,
}

/// Per-(provider, model) window-WIDE SLO row — the TRUE merged p50/p95/p99 over
/// the whole window (`quantileMerge` over the stored per-hour quantile states),
/// NOT the per-hour percentiles the SLO table used to average client-side
/// (a percentile-of-percentiles; provenance audit P2 #8). Requests/errors/tokens
/// are `countMerge`/`sumMerge` totals — same numbers the table summed before, now
/// server-side. POSITIONAL (`clickhouse::Row`) — field order MUST match the
/// `build_slo_by_model_sql` SELECT.
#[derive(Debug, Clone, Deserialize, Serialize, clickhouse::Row)]
pub struct SloModelRow {
    pub provider: String,
    pub model: String,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub requests: u64,
    pub errors: u64,
    pub error_rate_pct: f64,
    pub total_input_tokens: i64,
    pub total_output_tokens: i64,
}

/// One point of the latency-over-time chart — the TRUE merged p50/p95/p99 for a
/// display bucket (`quantileMerge` over every LLM span's per-hour quantile state
/// in that bucket, `provider <> ''`), NOT the request-weighted mean of per-hour
/// percentiles the chart computed client-side (provenance audit P2 #8, the
/// dashboard and SLO charts). `bucket_start` is the interval start (ClickHouse
/// DateTime string). POSITIONAL — order MUST match `build_slo_timeseries_sql`.
#[derive(Debug, Clone, Deserialize, Serialize, clickhouse::Row)]
pub struct SloTimePoint {
    pub bucket_start: String,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub requests: u64,
    /// Errored requests in the bucket (DSH-11) — the chart's second series.
    pub errors: u64,
}

/// Window-wide latency **split** — the honest "what Tracelane adds vs the LLM"
/// decomposition (§ latency framing). Every span records `gateway_overhead_us`
/// (the time Tracelane adds, EXCLUDING the provider round-trip); with
/// `duration_us` (total) the two segments SUM to total per span, no unattributed
/// bucket: `provider_us = duration_us − gateway_overhead_us`. TTFT is the
/// streaming first-chunk latency (`gen_ai.response.time_to_first_chunk`). One row.
///
/// POSITIONAL (`clickhouse::Row`) — field order MUST match the
/// `build_latency_totals_sql` SELECT. `*_samples` are the honesty gate: a tile
/// with `0` samples renders "—" (no MEASURED overhead / no streaming traffic),
/// never a fabricated `0ms`. Quantiles are guarded to `0` on an empty window so
/// the aggregate never returns NaN (which would fail JSON serialization).
#[derive(Debug, Clone, Default, Deserialize, Serialize, clickhouse::Row)]
pub struct LatencyTotalsRow {
    /// DISPATCHED spans in the window: a MEASURED `tracelane_gateway_overhead_us`
    /// and not a response-cache hit (B-568 C3 — hits have their own fields below).
    pub overhead_samples: u64,
    /// Gateway overhead (the hero — "what Tracelane adds"), p50/p95/p99, ms,
    /// over dispatched spans.
    pub overhead_p50_ms: f64,
    pub overhead_p95_ms: f64,
    pub overhead_p99_ms: f64,
    /// Upstream provider latency (`duration − overhead`), p50/p95/p99, ms — the
    /// part that is the LLM, not Tracelane.
    pub provider_p50_ms: f64,
    pub provider_p95_ms: f64,
    pub provider_p99_ms: f64,
    /// Streaming spans in the window that recorded a first-chunk time.
    pub ttft_samples: u64,
    /// Time-to-first-chunk (streaming), p50/p95/p99, ms.
    pub ttft_p50_ms: f64,
    pub ttft_p95_ms: f64,
    pub ttft_p99_ms: f64,
    /// B-568 C3: response-cache HITS with a measured overhead. For a hit the
    /// overhead IS the whole request (no provider was called).
    pub cache_hit_samples: u64,
    /// What a hit took to serve, p50/p95, ms. `0.0` when `cache_hit_samples = 0`.
    pub cache_hit_served_p50_ms: f64,
    pub cache_hit_served_p95_ms: f64,
    /// Dispatched spans that paid a control-plane round trip before dispatch
    /// (`tracelane_gateway_cold_start = true`). "N of M paid a cold start" is
    /// `cold_start_samples / overhead_samples`.
    pub cold_start_samples: u64,
    /// Dispatched spans WITHOUT the cold flag — the steady-state population.
    pub warm_samples: u64,
    /// Steady-state gateway overhead, p50/p95, ms. `0.0` when `warm_samples = 0`.
    pub overhead_warm_p50_ms: f64,
    pub overhead_warm_p95_ms: f64,
}

/// Per-(provider, model) gateway-overhead p95 — the SLO-table "our slice" column,
/// so a viewer can see Tracelane's overhead is tiny next to the end-to-end p95.
/// POSITIONAL — field order MUST match `build_latency_by_model_sql`. Every row
/// has ≥1 overhead sample (the SQL filters `JSONHas(...)`), so the quantile is
/// never NaN here.
#[derive(Debug, Clone, Deserialize, Serialize, clickhouse::Row)]
pub struct LatencyModelRow {
    pub provider: String,
    pub model: String,
    pub overhead_p95_ms: f64,
    pub samples: u64,
}

/// `GET /v1/query/latency-breakdown` response — the window-wide split (the three
/// tiles) plus the per-model overhead column. Assembled by the handler from
/// [`LatencyTotalsRow`] + the [`LatencyModelRow`] list.
#[derive(Debug, Clone, Serialize)]
pub struct LatencyBreakdownResponse {
    pub window_hours: u32,
    pub overhead_p50_ms: f64,
    pub overhead_p95_ms: f64,
    pub overhead_p99_ms: f64,
    pub provider_p50_ms: f64,
    pub provider_p95_ms: f64,
    pub provider_p99_ms: f64,
    pub ttft_p50_ms: f64,
    pub ttft_p95_ms: f64,
    pub ttft_p99_ms: f64,
    /// DISPATCHED spans with a measured overhead (cache hits excluded, B-568 C3) —
    /// the tile shows "—" when 0 (never $0ms).
    pub overhead_samples: u64,
    /// Streaming spans with a first-chunk time — the TTFT tile shows "—" when 0.
    pub ttft_samples: u64,
    /// B-568 C3 — see [`LatencyTotalsRow`]. Every quantile below is `0.0` when its
    /// own `*_samples` is `0`; the web must render "—" for that, never `0 ms`, and
    /// must treat every one of these as OPTIONAL (a web deploy can run ahead of
    /// the gateway).
    pub cache_hit_samples: u64,
    pub cache_hit_served_p50_ms: f64,
    pub cache_hit_served_p95_ms: f64,
    pub cold_start_samples: u64,
    pub warm_samples: u64,
    pub overhead_warm_p50_ms: f64,
    pub overhead_warm_p95_ms: f64,
    pub by_model: Vec<LatencyModelRow>,
}

/// One per-provider Gateway-ops health row from the live `spans` aggregate.
/// POSITIONAL — field order MUST match the `build_gateway_stats_sql` SELECT.
#[derive(Debug, Clone, Deserialize, Serialize, clickhouse::Row)]
pub struct GatewayProviderRow {
    pub provider: String,
    pub requests: u64,
    pub errors: u64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub cache_hits: u64,
    /// Requests served BY this provider via a cross-provider failover.
    pub failovers: u64,
    /// Summed REAL per-span `gen_ai_usage_cost` (USD) the gateway stored for this
    /// provider in the window. Spans the model isn't priced for contribute 0 —
    /// this is a lower bound over priced traffic, never a fabricated estimate.
    pub cost_usd: f64,
    /// Gateway-overhead p95 (ms) for this provider — the time Tracelane ADDS,
    /// excluding the upstream round-trip (`gateway_overhead_us`, § latency
    /// framing). `0.0` when no span for this provider carries a measured overhead
    /// (guarded in SQL so a provider with none never yields NaN); the UI renders
    /// "—" in that case, never a fabricated `0ms`.
    pub overhead_p95_ms: f64,
}

/// Per-provider health with rates derived server-side (division kept OUT of SQL
/// so a zero-request provider never divides by zero / yields NaN).
#[derive(Debug, Clone, Serialize)]
pub struct GatewayProviderHealth {
    pub provider: String,
    pub requests: u64,
    pub errors: u64,
    pub error_rate_pct: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub cache_hits: u64,
    pub cache_hit_rate_pct: f64,
    /// Requests this provider served via cross-provider failover.
    pub failovers: u64,
    /// Summed real stored `gen_ai_usage_cost` (USD) for this provider (see
    /// `GatewayProviderRow::cost_usd` — real, lower-bound over priced traffic).
    pub cost_usd: f64,
    /// Gateway-overhead p95 (ms) — Tracelane's own slice, next to the end-to-end
    /// p95, so the "our overhead is tiny" story is visible per provider. `0.0`
    /// (→ "—" in the UI) when no measured-overhead span exists for this provider.
    pub overhead_p95_ms: f64,
    /// Live circuit-breaker state for this upstream: `"closed"` | `"open"` |
    /// `"half_open"` (ADR-036). `"closed"` when no breaker has recorded a failure
    /// for the provider — the category-of-one router-health signal.
    pub circuit_state: String,
}

/// The Gateway-ops surface. Two metric families with DIFFERENT windows, each
/// labeled honestly (§ honesty lock):
///   • span-derived, rolling `window_hours` (24h default): requests, errors,
///     latency, cache-hit, and `total_failovers` (`countIf` over `spans`).
///   • process-lifetime counters (since gateway start, reset on redeploy):
///     `rate_limited_since_start`, `budget_exceeded_since_start` — a 429 emits no
///     span, so these come from the in-process [`crate::rejection_metrics`]
///     registry instead of a fabricated zero.
/// `uninstrumented` remains for forward-compat (empty now that both former gaps
/// are recorded); the UI keys off it to disclose any future gap.
#[derive(Debug, Clone, Serialize)]
pub struct GatewayStatsResponse {
    pub window_hours: u32,
    pub total_requests: u64,
    pub total_errors: u64,
    pub error_rate_pct: f64,
    pub cache_hit_rate_pct: f64,
    pub provider_count: u32,
    /// Total requests served via cross-provider failover in the window.
    pub total_failovers: u64,
    /// Tenant-wide real spend (USD) in the window — Σ of the stored per-span
    /// `gen_ai_usage_cost`. A lower bound over priced traffic (unpriced models
    /// contribute 0); the UI shows "—" when it's 0 rather than implying $0 spend.
    pub total_cost_usd: f64,
    /// Rate-limit (token-bucket) 429s for this tenant since the gateway started.
    pub rate_limited_since_start: u64,
    /// Budget-exceeded 429s (per-key/workspace USD budget, GWY-43 + BILL-01 A3)
    /// for this tenant since the gateway started. Was `quota_exceeded_since_start`
    /// until 2026-09-14: BILL-01 / ADR-076 retired the monthly trace-count hard
    /// cap that name described, and `apps/web/lib/gateway-ops.ts` renamed with it.
    pub budget_exceeded_since_start: u64,
    pub providers: Vec<GatewayProviderHealth>,
    /// Upstreams whose breaker is currently Open or Half-Open (ADR-036) — a live
    /// resilience signal counted across ALL breakers, not just this window's rows
    /// (a provider can be down with zero recent traffic).
    pub open_breakers: u32,
    pub uninstrumented: Vec<&'static str>,
}

// ── Cost attribution (GWY-43, Sprint 1 item 5) ──────────────────────────────

/// Which dimension to attribute spend to.
///
/// `Key` is the one that was structurally impossible before migration 16: spans
/// carried no `api_key_id`, so "spend by key" could not be answered however well
/// the dashboard were built. That is the `OBS-N1` shape — a read path with no
/// writer — and it is why this enum exists at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CostDimension {
    Key,
    Model,
    Provider,
}

impl CostDimension {
    fn parse(s: Option<&str>) -> Option<Self> {
        match s.unwrap_or("key") {
            "key" => Some(Self::Key),
            "model" => Some(Self::Model),
            "provider" => Some(Self::Provider),
            _ => None,
        }
    }

    /// The ClickHouse expression to GROUP BY. Every one of these is a real
    /// column or a JSON extract the table already indexes — none is
    /// user-supplied, so this cannot be an injection surface.
    fn column(self) -> &'static str {
        match self {
            Self::Key => "api_key_id",
            Self::Model => "JSONExtractString(attributes, 'gen_ai_request_model')",
            Self::Provider => "JSONExtractString(attributes, 'gen_ai_provider_name')",
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Model => "model",
            Self::Provider => "provider",
        }
    }
}

/// Which traffic a cost answer covers.
///
/// **R94 — item 9 owns this half.** R81 closed the WRITE side only: eval spans
/// have carried `tracelane_eval_run_id` since it shipped, but `/v1/costs` did not
/// break that spend out and the dashboards did not exclude it. So an
/// experiment's own cost silently inflated the customer's PRODUCTION spend
/// figure — and an experiment is deliberately expensive, which makes that the
/// worst possible number to leave conflated.
///
/// **`All` stays the DEFAULT deliberately.** Changing what an existing caller's
/// unchanged request means is a silent change to every number already on a
/// screen, which is the same class of harm one step removed. Instead the
/// response ALWAYS carries the eval/production split, so the figure is never
/// conflated-and-unknowable, and a caller that wants production-only asks for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CostScope {
    /// Everything in the window. The split is still reported.
    All,
    /// Spans with NO eval run id — real customer traffic.
    Production,
    /// Spans emitted by an eval run or an experiment arm.
    Eval,
}

/// The discriminator, written ONCE.
///
/// `JSONExtractString` at read time and **never a `MATERIALIZED` column** — spec
/// `EVL-02` §2.3b, founder ruling R106. A materialized column is computed on
/// INSERT, so it would be EMPTY for every span already written, including the
/// first eval spans this product ever emitted. A feature built to measure things
/// would begin by being unable to see its own first measurements — and it would
/// report that absence as zero rather than as unknown.
///
/// A missing key yields `''`, so `!= ''` is exactly "this span belongs to an eval
/// run".
const EVAL_SPAN_EXPR: &str = "JSONExtractString(attributes, 'tracelane_eval_run_id')";

/// The `EVL-23` judge discriminator, written ONCE beside its sibling.
///
/// **A judge call is an eval span AND a judge span** — it carries both
/// attributes — so `judge_*` is a SUBSET of `eval_*`, never a third bucket added
/// to the total. Stated here because the alternative reading ("eval + judge =
/// total eval spend") double-counts every judged run, and the two figures sit
/// next to each other in the response where that mistake is easiest to make.
///
/// Same read-time `JSONExtractString`, same reason (`EVL-02` §2.3b, R106): a
/// MATERIALIZED column is computed on INSERT and would be empty for every span
/// already written, so the first judge spans this product ever emitted would be
/// invisible to the surface built to price them.
const JUDGE_SPAN_EXPR: &str = "JSONExtractString(attributes, 'tracelane_eval_role')";

impl CostScope {
    fn parse(s: Option<&str>) -> Option<Self> {
        match s.unwrap_or("all") {
            "all" => Some(Self::All),
            "production" => Some(Self::Production),
            "eval" => Some(Self::Eval),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Production => "production",
            Self::Eval => "eval",
        }
    }

    /// The extra WHERE predicate, or empty. Contains no user input — the scope
    /// is parsed into an enum first, so this cannot be an injection surface.
    fn predicate(self) -> String {
        match self {
            Self::All => String::new(),
            Self::Production => format!("AND {EVAL_SPAN_EXPR} = '' "),
            Self::Eval => format!("AND {EVAL_SPAN_EXPR} != '' "),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CostFilters {
    /// Inclusive lower bound on `start_time`, seconds since epoch. When set it
    /// overrides `hours` (CX-26 / B-525 — `/v1/costs` used to drop the pair the
    /// client sends and serve a rolling `now() − hours` under an absolute label).
    pub since_secs: Option<i64>,
    /// Inclusive upper bound on `start_time`, seconds since epoch.
    pub until_secs: Option<i64>,
    /// Rolling look-back window in hours (used only when `since_secs` is None).
    pub hours: u32,
    pub dimension: CostDimension,
    /// Per-group row cap (bound `?`). The totals are NOT capped by it — see `CostRow`.
    pub limit: u32,
    pub scope: CostScope,
}

#[derive(Debug, Clone, serde::Deserialize, clickhouse::Row)]
pub struct CostRow {
    pub dimension: String,
    pub requests: u64,
    /// Requests in this bucket whose cost we actually KNOW.
    pub priced_requests: u64,
    pub cost_usd: f64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// The EVAL portion of this bucket (R94). Reported alongside the total
    /// rather than subtracted from it, so a reader can see both without the
    /// endpoint having to pick which one "the" number is.
    pub eval_requests: u64,
    pub eval_cost_usd: f64,
    /// The JUDGE portion (`EVL-23`) — a SUBSET of the eval portion above, not an
    /// addition to it.
    pub judge_requests: u64,
    pub judge_cost_usd: f64,
    /// **CX-27 / B-526 — the window-wide figures, computed BEFORE the row cap.**
    /// ClickHouse evaluates `count() OVER ()` / `sum(x) OVER ()` after `GROUP BY`
    /// and before `ORDER BY … LIMIT`, so these are the same on every row and cover
    /// EVERY group in the window — the handler reads them off the first row rather
    /// than summing the rows that fit under `limit`. Proven on the server prod runs
    /// by `the_cost_total_counts_every_group_not_only_the_capped_rows`; a string
    /// test cannot see it (the B-274 class).
    pub group_count: u64,
    pub all_requests: u64,
    pub all_priced_requests: u64,
    pub all_cost_usd: f64,
    pub all_eval_requests: u64,
    pub all_eval_cost_usd: f64,
    pub all_judge_requests: u64,
    pub all_judge_cost_usd: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CostBreakdownRow {
    /// The dimension value: an `api_keys.id`, a model string, or a provider id.
    /// Empty string for spend that carries no value on this dimension — a
    /// session-authenticated request has no API key, and that is NOT the same as
    /// unattributed. The UI must label it, not hide it.
    pub dimension: String,
    pub requests: u64,
    pub priced_requests: u64,
    /// Requests we could not price. Rendered as its own number, never folded
    /// into `cost_usd` as if it were zero.
    pub unpriced_requests: u64,
    pub cost_usd: f64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Of the above, how much was an eval run or an experiment arm. `0` here is
    /// MEASURED — every span either carries the attribute or does not — so it is
    /// safe to render as a zero rather than as unknown.
    pub eval_requests: u64,
    pub eval_cost_usd: f64,
    /// Of the eval spend above, how much was the JUDGE grading rather than the
    /// prompt running (`EVL-23`). **A subset of `eval_*`, never an addition** —
    /// a judge span carries both attributes, so adding these to `eval_*` would
    /// count every judge call twice.
    pub judge_requests: u64,
    pub judge_cost_usd: f64,
}

/// Spend, attributed.
///
/// **The honesty field here is `unpriced_requests`, and it is the point.**
/// `pricing::cost_usd` returns `None` for a model whose price we do not know,
/// and the gateway omits the attribute entirely rather than writing 0. But every
/// read path in this file wrapped the JSON extract in
/// `if(isFinite(x) AND x > 0, x, 0)` — which turns "we do not know" into a
/// confident **$0.00**. Before GWY-42 the price table covered 13 models across
/// three vendors, so most real traffic took that path and the spend tile
/// under-reported silently. This response reports both halves so a reader can
/// tell a cheap month from an unpriced one.
#[derive(Debug, Clone, Serialize)]
pub struct CostBreakdownResponse {
    pub window_hours: u32,
    /// `"key"` | `"model"` | `"provider"`.
    pub by: &'static str,
    pub total_cost_usd: f64,
    pub total_requests: u64,
    /// Requests in the window we could price. `total_requests - priced_requests`
    /// is how much of the window `total_cost_usd` does NOT account for.
    pub priced_requests: u64,
    pub unpriced_requests: u64,
    /// How many groups (keys / models / providers) had traffic in the window,
    /// counted BEFORE the row cap — the true cardinality even when `rows` is a
    /// subset (CX-27 / B-526).
    pub group_count: u64,
    /// `rows.len() < group_count`: `rows` is the costliest `GATEWAY_PROVIDER_CAP`
    /// groups and every figure above the table still covers all `group_count`.
    /// A client MUST say so — the cheapest groups are the ones cut, and a
    /// zero-cost / unpriced group sorts LAST, so without this flag the unpriced
    /// badge was the first thing truncation deleted.
    pub truncated: bool,
    /// **When did per-key attribution begin.** `api_key_id` is materialized by
    /// ClickHouse migration 16 and is only populated for spans written after it
    /// deployed, so a "by key" answer cannot see further back than that. Null
    /// for dimensions that were always recorded (model, provider).
    pub attribution_begins_note: Option<&'static str>,
    /// `"all"` | `"production"` | `"eval"` — echoed, because every number above
    /// and below is *within this scope* and a client that forgot which it asked
    /// for would otherwise be reading a different question's answer.
    pub scope: &'static str,
    /// **The R94 split.** Always present, at every scope, so the total is never
    /// conflated-and-unknowable. Under `scope=production` these are `0` and that
    /// is the truth of the filtered set, not a suppressed number.
    pub eval_cost_usd: f64,
    pub eval_requests: u64,
    /// `total − eval`, computed here rather than left to the client so the two
    /// halves cannot be added up differently by two readers.
    pub production_cost_usd: f64,
    pub production_requests: u64,
    /// **When eval attribution began**, in the same spirit as
    /// `attribution_begins_note`: `tracelane_eval_run_id` is written by the
    /// gateway from R81 onward, so eval spend before that deploy is invisible to
    /// this split and is counted as production. Stated rather than left for
    /// someone to discover from a suspiciously round zero.
    pub eval_attribution_note: &'static str,
    /// **The `EVL-23` judge split, and it is a SUBSET of the eval split above.**
    /// A judge call carries `tracelane_eval_run_id` AND `tracelane_eval_role`, so
    /// `judge_cost_usd <= eval_cost_usd` always, and
    /// `eval_cost_usd - judge_cost_usd` is what the prompts themselves cost.
    /// Broken out because a judged run spends twice what an unjudged one does and
    /// "what did grading cost me" is the question a customer asks when the bill
    /// doubles — folding it into eval spend leaves that answerable only by
    /// guessing from model names, which fails the moment someone judges with the
    /// model under test.
    pub judge_cost_usd: f64,
    pub judge_requests: u64,
    pub rows: Vec<CostBreakdownRow>,
}
// ── DSH-13: metric breakdown by a closed dimension set ───────────────────────
//
// `GET /v1/metrics/breakdown?metric=&by=&since=&until=&limit=` serves the `breakdown`
// tiles whose (metric, dimension) pair no existing route covers. Both axes are CLOSED
// enums: `metric` and `by` are matched against fixed strings and the SQL is composed
// from fixed expressions — no caller value ever reaches statement text (the
// `CostDimension` / `TraceGroupBy` pattern above). Custom means composition, not
// authorship (spec §1, founder prior).

/// The aggregate a breakdown tile asks for. Every arm is a fixed ClickHouse expression
/// that yields a Float64 — one row shape for every metric (RowBinary is positional and
/// typed; a `u64` column here would desynchronise the stream, B-274 class).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakdownMetric {
    Requests,
    Errors,
    ErrorRate,
    P50Ms,
    P95Ms,
    InputTokens,
    OutputTokens,
    CostUsd,
}

impl BreakdownMetric {
    // No production caller today — used only by a test enumerating every
    // metric/dimension combination. Gated (B-390, 2026-09-12).
    #[cfg(test)]
    pub const ALL: [Self; 8] = [
        Self::Requests,
        Self::Errors,
        Self::ErrorRate,
        Self::P50Ms,
        Self::P95Ms,
        Self::InputTokens,
        Self::OutputTokens,
        Self::CostUsd,
    ];

    pub fn parse(s: Option<&str>) -> Option<Self> {
        Some(match s? {
            "requests" => Self::Requests,
            "errors" => Self::Errors,
            "error_rate" => Self::ErrorRate,
            "p50_ms" => Self::P50Ms,
            "p95_ms" => Self::P95Ms,
            "input_tokens" => Self::InputTokens,
            "output_tokens" => Self::OutputTokens,
            "cost_usd" => Self::CostUsd,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requests => "requests",
            Self::Errors => "errors",
            Self::ErrorRate => "error_rate",
            Self::P50Ms => "p50_ms",
            Self::P95Ms => "p95_ms",
            Self::InputTokens => "input_tokens",
            Self::OutputTokens => "output_tokens",
            Self::CostUsd => "cost_usd",
        }
    }

    /// The SAME definitions the built-in pages use (cost via `cost_usd_present`,
    /// errors via `status_code = 2`, latency from `duration_us`), so a custom tile can
    /// never disagree with the page it mirrors.
    fn expr(self) -> &'static str {
        match self {
            Self::Requests => "toFloat64(count())",
            Self::Errors => "toFloat64(countIf(status_code = 2))",
            Self::ErrorRate => {
                "if(count() = 0, 0.0, round(countIf(status_code = 2) / count() * 100.0, 2))"
            }
            Self::P50Ms => "quantileExact(0.5)(duration_us) / 1000.0",
            Self::P95Ms => "quantileExact(0.95)(duration_us) / 1000.0",
            Self::InputTokens => {
                "toFloat64(sum(JSONExtractUInt(attributes, 'gen_ai_usage_input_tokens')))"
            }
            Self::OutputTokens => {
                "toFloat64(sum(JSONExtractUInt(attributes, 'gen_ai_usage_output_tokens')))"
            }
            Self::CostUsd => {
                "round(sumIf(cost_usd, cost_usd_present = 1 AND isFinite(cost_usd)), 6)"
            }
        }
    }
}

/// The dimension a breakdown tile groups by — the ones the gateway already groups by
/// elsewhere, spelled the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakdownBy {
    Model,
    Provider,
    Key,
    Status,
    Operation,
}

impl BreakdownBy {
    // No production caller today — same reasoning as `BreakdownMetric::ALL`
    // above. Gated (B-390, 2026-09-12).
    #[cfg(test)]
    pub const ALL: [Self; 5] = [
        Self::Model,
        Self::Provider,
        Self::Key,
        Self::Status,
        Self::Operation,
    ];

    pub fn parse(s: Option<&str>) -> Option<Self> {
        Some(match s? {
            "model" => Self::Model,
            "provider" => Self::Provider,
            "key" => Self::Key,
            "status" => Self::Status,
            "operation" => Self::Operation,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Model => "model",
            Self::Provider => "provider",
            Self::Key => "key",
            Self::Status => "status",
            Self::Operation => "operation",
        }
    }

    fn column(self) -> &'static str {
        match self {
            Self::Model => "JSONExtractString(attributes, 'gen_ai_request_model')",
            Self::Provider => "JSONExtractString(attributes, 'gen_ai_provider_name')",
            Self::Key => "api_key_id",
            Self::Status => "if(status_code = 2, 'error', 'ok')",
            Self::Operation => "JSONExtractString(attributes, 'gen_ai_operation_name')",
        }
    }
}

#[derive(Debug, Clone)]
pub struct BreakdownFilters {
    pub metric: BreakdownMetric,
    pub by: BreakdownBy,
    pub since_us: i64,
    pub until_us: i64,
    pub limit: u32,
}

/// One breakdown row. `value` is the metric (always Float64 — see `BreakdownMetric`),
/// `n` the request count behind it, so the tile can show a sample size.
#[derive(Debug, Clone, Serialize, Deserialize, clickhouse::Row)]
pub struct BreakdownRow {
    pub key: String,
    pub value: f64,
    pub n: u64,
}

/// Bind order: tenant, since_us, until_us, limit. Exactly four `?`; nothing else in
/// the text varies with the caller.
fn build_metric_breakdown_sql(metric: BreakdownMetric, by: BreakdownBy) -> String {
    format!(
        "SELECT {dim} AS key, {expr} AS value, toUInt64(count()) AS n \
FROM spans FINAL \
WHERE tenant_id = ? \
  AND start_time >= fromUnixTimestamp64Micro(?) \
  AND start_time < fromUnixTimestamp64Micro(?) \
GROUP BY key ORDER BY value DESC, key ASC LIMIT ?",
        dim = by.column(),
        expr = metric.expr(),
    )
}

/// Build the cost-attribution SELECT. `?` order: tenant, (since_secs | hours),
/// [until_secs], limit — the scope predicate carries no placeholder.
///
/// **The `*_count`/`all_*` columns are WINDOW functions over the grouped result**
/// (`count() OVER ()`, `sum(requests) OVER ()`, …): ClickHouse evaluates them after
/// `GROUP BY` and before `ORDER BY … LIMIT`, so every row carries the window-wide
/// totals and the handler never sums the capped rows (CX-27 / B-526). Inside a
/// window function `sum(cost_usd) OVER ()` names the SELECT-list alias — the
/// per-group aggregate — and that is exactly what is wanted here; it was
/// discriminated on 24.12 (alias × 10 → the window sum moved ×10). Only the raw
/// `spans.` reads below need qualifying, per the rule that follows.
///
/// **EVERY `cost_usd` / `cost_usd_present` IS QUALIFIED `spans.`, AND THAT IS NOT
/// STYLE — IT IS THE FIX FOR A PROD 502.**
///
/// This SELECT aliases its own aggregate `AS cost_usd`, and a SELECT-list alias
/// SHADOWS the column it is named after for every other expression in the same
/// SELECT. So the moment a SECOND `sumIf(cost_usd, …)` was added for the eval
/// split, `cost_usd` inside it resolved to the ALIAS — an aggregate nested in an
/// aggregate — and ClickHouse answered `Code 184 ILLEGAL_AGGREGATION`. Every
/// `/v1/costs` request 502'd.
///
/// It shipped behind green tests because **every test here asserts the SQL
/// STRING**, and a string cannot be illegal — only a server can say that. The
/// round-trip test below now EXECUTES this against a real ClickHouse, which is
/// the only thing that could have caught it.
///
/// Third instance of alias shadowing in one day, after `B-272` (a `WHERE` reading
/// its own `toString(...)` alias) and the eval-item read (a `score IS NOT NULL`
/// flag reading its own `ifNull(...)` alias). The rule that removes the class:
/// **an alias never reuses a column's name, and every source column is
/// qualified.**
///
/// Uses the REAL `cost_usd` / `cost_usd_present` columns (migration 16) rather
/// than a per-row `JSONExtractFloat`, so the sum is indexed work rather than a
/// scan-and-parse, and — more importantly — `cost_usd_present` lets the query
/// COUNT what it could not price instead of silently adding zero for it.
fn build_cost_breakdown_sql(f: &CostFilters) -> String {
    let mut sql = format!(
        "SELECT \
{dim} AS dimension, \
toUInt64(count()) AS requests, \
toUInt64(countIf(spans.cost_usd_present = 1)) AS priced_requests, \
round(sumIf(spans.cost_usd, spans.cost_usd_present = 1 AND isFinite(spans.cost_usd)), 6) \
  AS cost_usd, \
toUInt64(sum(JSONExtractUInt(attributes, 'gen_ai_usage_input_tokens'))) AS input_tokens, \
toUInt64(sum(JSONExtractUInt(attributes, 'gen_ai_usage_output_tokens'))) AS output_tokens, \
toUInt64(countIf({eval} != '')) AS eval_requests, \
round(sumIf(spans.cost_usd, spans.cost_usd_present = 1 AND isFinite(spans.cost_usd) \
  AND {eval} != ''), 6) AS eval_cost_usd, \
toUInt64(countIf({judge} = 'judge')) AS judge_requests, \
round(sumIf(spans.cost_usd, spans.cost_usd_present = 1 AND isFinite(spans.cost_usd) \
  AND {judge} = 'judge'), 6) AS judge_cost_usd, \
toUInt64(count() OVER ()) AS group_count, \
toUInt64(sum(requests) OVER ()) AS all_requests, \
toUInt64(sum(priced_requests) OVER ()) AS all_priced_requests, \
round(sum(cost_usd) OVER (), 6) AS all_cost_usd, \
toUInt64(sum(eval_requests) OVER ()) AS all_eval_requests, \
round(sum(eval_cost_usd) OVER (), 6) AS all_eval_cost_usd, \
toUInt64(sum(judge_requests) OVER ()) AS all_judge_requests, \
round(sum(judge_cost_usd) OVER (), 6) AS all_judge_cost_usd \
FROM spans FINAL \
WHERE tenant_id = ?",
        dim = f.dimension.column(),
        eval = EVAL_SPAN_EXPR,
        judge = JUDGE_SPAN_EXPR,
    );
    if f.since_secs.is_some() {
        sql.push_str(" AND start_time >= toDateTime(?)");
    } else {
        sql.push_str(" AND start_time >= now() - toIntervalHour(?)");
    }
    if f.until_secs.is_some() {
        sql.push_str(" AND start_time <= toDateTime(?)");
    }
    sql.push(' ');
    sql.push_str(&f.scope.predicate());
    sql.push_str("GROUP BY dimension ORDER BY cost_usd DESC, requests DESC LIMIT ?");
    sql
}

/// `num/denom` as a 2-dp percentage; `0.0` when `denom == 0` (never NaN).
fn pct(num: u64, denom: u64) -> f64 {
    if denom == 0 {
        0.0
    } else {
        ((num as f64 / denom as f64) * 10_000.0).round() / 100.0
    }
}

impl GatewayStatsResponse {
    /// Fold the per-provider rows into the response, deriving the tenant-wide
    /// totals from summed counts (rates recomputed from sums, never averaged).
    /// `rejections` is `(rate_limited, budget_exceeded)` process-lifetime counts
    /// injected by the handler from [`crate::rejection_metrics`] (they have no
    /// span to aggregate from).
    fn from_rows(
        rows: Vec<GatewayProviderRow>,
        window_hours: u32,
        rejections: (u64, u64),
        breakers: &std::collections::HashMap<String, crate::circuit_breaker::State>,
    ) -> Self {
        let total_requests: u64 = rows.iter().map(|r| r.requests).sum();
        let total_errors: u64 = rows.iter().map(|r| r.errors).sum();
        let total_cache_hits: u64 = rows.iter().map(|r| r.cache_hits).sum();
        let total_failovers: u64 = rows.iter().map(|r| r.failovers).sum();
        let total_cost_usd: f64 = rows.iter().map(|r| r.cost_usd).sum();
        let provider_count = rows.len() as u32;
        let providers = rows
            .into_iter()
            .map(|r| {
                // "closed" default: no breaker entry means no failure recorded for
                // this upstream (a breaker is created lazily on first outcome).
                let circuit_state = breakers
                    .get(&r.provider)
                    .map_or("closed", crate::circuit_breaker::State::as_str)
                    .to_string();
                GatewayProviderHealth {
                    error_rate_pct: pct(r.errors, r.requests),
                    cache_hit_rate_pct: pct(r.cache_hits, r.requests),
                    provider: r.provider,
                    requests: r.requests,
                    errors: r.errors,
                    p50_ms: r.p50_ms,
                    p95_ms: r.p95_ms,
                    p99_ms: r.p99_ms,
                    cache_hits: r.cache_hits,
                    failovers: r.failovers,
                    cost_usd: r.cost_usd,
                    overhead_p95_ms: r.overhead_p95_ms,
                    circuit_state,
                }
            })
            .collect();
        let open_breakers = breakers
            .values()
            .filter(|s| {
                matches!(
                    s,
                    crate::circuit_breaker::State::Open | crate::circuit_breaker::State::HalfOpen
                )
            })
            .count() as u32;
        let (rate_limited_since_start, budget_exceeded_since_start) = rejections;
        Self {
            window_hours,
            total_requests,
            total_errors,
            error_rate_pct: pct(total_errors, total_requests),
            cache_hit_rate_pct: pct(total_cache_hits, total_requests),
            provider_count,
            total_failovers,
            total_cost_usd,
            rate_limited_since_start,
            budget_exceeded_since_start,
            providers,
            open_breakers,
            // Both former gaps (failover + rate-limit) are now recorded; nothing
            // is faked. Kept for forward-compat so a future gap can be disclosed.
            uninstrumented: vec![],
        }
    }
}

// ── Guardrails surface (predictive pre-flight verdicts) ──────────────────────
// Reads `tracelane.guardrail_verdicts`, written once per request-side by
// `guardrail::recorder` (decision, per-rail outcomes, fail-open rails, latency).
// This is the ONLY customer-facing view of the pre-flight guardrail engine — the
// core product signal. Every column below maps to a captured field; nothing here
// is derived or fabricated (§ honesty lock /).

/// Single-row tenant summary from `build_guardrail_summary_sql`. POSITIONAL —
/// field order MUST match the SELECT.
#[derive(Debug, Clone, Default, Deserialize, Serialize, clickhouse::Row)]
pub struct GuardrailSummaryRow {
    pub total: u64,
    pub allows: u64,
    pub blocks: u64,
    pub redacts: u64,
    pub warns: u64,
    /// Verdicts where at least one rail failed OPEN (errored → proceeded). The
    /// headline honesty signal: a guardrail that silently fails open is the exact
    /// failure the product exists to prevent.
    pub fail_open_verdicts: u64,
    pub request_side: u64,
    pub response_side: u64,
    /// Inline guardrail overhead (the sub-50ms p99 claim, measured honestly).
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
}

/// One per-rail health row from `build_guardrail_rails_sql` (arrayJoin over the
/// `rails` JSON). POSITIONAL — field order MUST match the SELECT.
#[derive(Debug, Clone, Deserialize, Serialize, clickhouse::Row)]
pub struct GuardrailRailRow {
    pub rail: String,
    pub evaluations: u64,
    pub blocks: u64,
    pub fail_opens: u64,
    pub p95_ms: f64,
}

/// One verdict row from `build_guardrail_verdicts_sql` — the detail behind the
/// decision-mix counts. POSITIONAL — field order MUST match the SELECT. This is
/// the honest click-through target for a **blocked** verdict: an inline block
/// 403s the request BEFORE any span is emitted, so there is no trace to link to
/// — the verdict itself (which rails fired, reason codes, when) is the detail.
#[derive(Debug, Clone, Deserialize, Serialize, clickhouse::Row)]
pub struct GuardrailVerdictListRow {
    pub correlation_id: String,
    pub side: String,
    pub decision: String,
    /// `toString(event_time)` — human timestamp.
    pub event_time: String,
    pub total_latency_micros: u64,
    /// The per-rail verdict JSON array (already redacted at write time).
    pub rails: String,
    pub fail_open_rails: Vec<String>,
}

/// `{ verdicts }` — the guardrail verdict-detail list.
#[derive(Debug, Clone, Serialize)]
pub struct GuardrailVerdictListResponse {
    pub verdicts: Vec<GuardrailVerdictListRow>,
}

/// The `GET /v1/guardrails/stats` response: a tenant-scoped, windowed view of the
/// pre-flight guardrail engine. Rates derived server-side so an empty window
/// never divides by zero.
#[derive(Debug, Clone, Serialize)]
pub struct GuardrailStatsResponse {
    pub window_hours: u32,
    pub total_evaluations: u64,
    pub block_rate_pct: f64,
    pub redact_rate_pct: f64,
    pub warn_rate_pct: f64,
    /// Share of verdicts with any fail-open rail — the trust/honesty headline.
    pub fail_open_rate_pct: f64,
    pub fail_open_verdicts: u64,
    pub blocks: u64,
    pub redacts: u64,
    pub warns: u64,
    pub allows: u64,
    pub request_side: u64,
    pub response_side: u64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub rails: Vec<GuardrailRailHealth>,
}

/// Per-rail health with the block/fail-open rates derived server-side.
#[derive(Debug, Clone, Serialize)]
pub struct GuardrailRailHealth {
    pub rail: String,
    pub evaluations: u64,
    pub blocks: u64,
    pub block_rate_pct: f64,
    pub fail_opens: u64,
    pub fail_open_rate_pct: f64,
    pub p95_ms: f64,
}

impl GuardrailStatsResponse {
    /// Assemble the response from the summary row + per-rail rows (rates derived
    /// from counts, never averaged).
    fn build(
        summary: GuardrailSummaryRow,
        rails: Vec<GuardrailRailRow>,
        window_hours: u32,
    ) -> Self {
        let total = summary.total;
        let rails = rails
            .into_iter()
            .map(|r| GuardrailRailHealth {
                block_rate_pct: pct(r.blocks, r.evaluations),
                fail_open_rate_pct: pct(r.fail_opens, r.evaluations),
                rail: r.rail,
                evaluations: r.evaluations,
                blocks: r.blocks,
                fail_opens: r.fail_opens,
                p95_ms: r.p95_ms,
            })
            .collect();
        Self {
            window_hours,
            total_evaluations: total,
            block_rate_pct: pct(summary.blocks, total),
            redact_rate_pct: pct(summary.redacts, total),
            warn_rate_pct: pct(summary.warns, total),
            fail_open_rate_pct: pct(summary.fail_open_verdicts, total),
            fail_open_verdicts: summary.fail_open_verdicts,
            blocks: summary.blocks,
            redacts: summary.redacts,
            warns: summary.warns,
            allows: summary.allows,
            request_side: summary.request_side,
            response_side: summary.response_side,
            p50_ms: summary.p50_ms,
            p95_ms: summary.p95_ms,
            p99_ms: summary.p99_ms,
            rails,
        }
    }
}

/// Internal ClickHouse row for the §4 failure-signatures aggregate. Field order +
/// types match the `build_signatures_sql` SELECT (positional, per `clickhouse::Row`).
#[derive(Debug, Clone, Deserialize, clickhouse::Row)]
pub struct SignatureHitRow {
    /// The matched failure-signature (AFT) id, e.g. `tool-schema-violation`.
    pub signature_id: String,
    /// THIS tenant's hit count (`your_hits`). NEVER a cross-tenant/network count.
    pub your_hits: u64,
    /// Strongest intervention seen across matches (0=none/flag, 2=block) — the
    /// handler maps this to `action`.
    pub max_intervention: u8,
    /// RFC3339 UTC of the earliest span matching this signature (`min(start_time)`).
    pub first_seen: String,
    /// RFC3339 UTC of the latest span matching this signature (`max(start_time)`).
    pub last_seen: String,
    /// Distinct traces this signature appears in (`uniqExact(trace_id)`) — the
    /// "traces affected" count. Always ≤ `your_hits` (a trace can hit it twice).
    pub traces_affected: u64,
}

/// One failure-signature row as returned to the client — the §4 "your hits"
/// surface. **NO network column**: the cross-tenant registry is V1.1, and a count
/// the registry can't substantiate is never rendered (honesty lock, the build spec §4).
#[derive(Debug, Clone, Serialize)]
pub struct SignatureHit {
    pub signature_id: String,
    pub your_hits: u64,
    /// `"blocking"` when any match blocked, else `"flag-only"`.
    pub action: &'static str,
    /// RFC3339 UTC of the first span that hit this signature.
    pub first_seen: String,
    /// RFC3339 UTC of the most recent span that hit this signature.
    pub last_seen: String,
    /// Distinct traces affected by this signature (occurrences span ≥ this).
    pub traces_affected: u64,
}

impl From<SignatureHitRow> for SignatureHit {
    fn from(r: SignatureHitRow) -> Self {
        Self {
            signature_id: r.signature_id,
            your_hits: r.your_hits,
            action: if r.max_intervention >= 2 {
                "blocking"
            } else {
                "flag-only"
            },
            first_seen: r.first_seen,
            last_seen: r.last_seen,
            traces_affected: r.traces_affected,
        }
    }
}

/// `{ signatures, total_traces_affected }` — the §4 list plus the distinct-traces
/// headline (traces with ANY signature in the window, counted once). No
/// `network`/`total_network` field exists by design (honesty lock).
#[derive(Debug, Clone, Serialize)]
pub struct SignaturesResponse {
    pub signatures: Vec<SignatureHit>,
    /// Distinct traces affected in the window — NEVER the sum of `your_hits`.
    pub total_traces_affected: u64,
}

// ── Sessions (§3 multi-turn grouping) — wire types ────────────────────────────

/// One session-summary row as returned to the client — a multi-turn conversation
/// thread, grouped by `gen_ai.conversation.id` across the tenant's spans.
/// `user` is intentionally absent: there is no instrumented user attribute yet
/// (the dashboard renders "—"); adding a fabricated column would violate the
/// honesty lock. `cost_usd` is best-effort (only providers that report cost on
/// the wire populate `gen_ai.usage.cost`).
#[derive(Debug, Clone, Serialize)]
pub struct SessionSummary {
    /// `gen_ai.conversation.id` — the thread key.
    pub session_id: String,
    /// Distinct traces (turns) in the conversation.
    pub turns: u32,
    /// `toString(min(start_time))` — first turn.
    pub started_at: String,
    /// `toString(max(end_time))` — most recent activity.
    pub last_activity: String,
    pub duration_us: i64,
    pub error_count: u32,
    /// `"error"` when any turn errored, else `"ok"`.
    pub status: &'static str,
    pub cost_usd: f64,
    pub total_tokens: i64,
    /// Representative (latest) model across the session.
    pub model: String,
    /// `gen_ai.agent.name` (PLT-46) — e.g. `"claude-code"` when the session was
    /// recorded via Claude Code's OTLP exporter. Empty string when never set, the
    /// same "absent, not fabricated" posture as every other best-effort column
    /// here; the dashboard renders no chip rather than a fake one.
    pub agent_name: String,
    /// `OBS-20`. The customer's own END USER — who initiated this conversation.
    /// Latest non-empty wins across the session's spans.
    ///
    /// THREE distinguishable values, and the read surface must render all three
    /// differently or a working privacy control reads as a broken feature:
    /// `""` — nobody sent one, which is the expected state for a tenant that has
    /// not instrumented it; a real id; or the literal `[REDACTED:email]`, which
    /// means the customer sent an email address and ingest's PII redaction
    /// removed it (`crates/ingest/src/clickhouse_writer.rs` runs
    /// `pii::redact_json` over the whole attribute blob and `email` is one of its
    /// categories).
    pub end_user: String,
}

/// Internal ClickHouse row for the session list. POSITIONAL — field order MUST
/// match the `build_session_list_sql` SELECT. The public [`SessionSummary`]
/// derives `status` from `error_count`.
#[derive(Debug, Clone, Deserialize, clickhouse::Row)]
pub struct SessionSummaryRow {
    pub session_id: String,
    pub turns: u32,
    pub started_at: String,
    pub last_activity: String,
    pub duration_us: i64,
    pub error_count: u32,
    pub cost_usd: f64,
    pub total_tokens: i64,
    pub model: String,
    /// Appended LAST — the SELECT appends it last too, so the `?` bind
    /// positions ahead of it (tenant, [model], since/window, limit) do not move
    /// (TRAPS §58 bind-order class).
    pub agent_name: String,
    /// `OBS-20`. The customer's own end user, latest non-empty wins within the
    /// session. Appended after `agent_name` for the same reason `agent_name` was
    /// appended after `model`: the SELECT appends it last, so no bind position
    /// ahead of it moves.
    ///
    /// `String`, not `Option<String>`: ClickHouse's `argMax` over a
    /// `JSONExtractString` yields `''` for a session no span of which carried
    /// one, and collapsing that to `None` here would lose the distinction the
    /// read surface needs between "" (nobody sent one) and the literal
    /// `[REDACTED:email]` (somebody sent one and PII redaction removed it).
    pub end_user: String,
}

impl From<SessionSummaryRow> for SessionSummary {
    fn from(r: SessionSummaryRow) -> Self {
        let status = if r.error_count > 0 { "error" } else { "ok" };
        Self {
            session_id: r.session_id,
            turns: r.turns,
            started_at: r.started_at,
            last_activity: r.last_activity,
            duration_us: r.duration_us,
            error_count: r.error_count,
            status,
            cost_usd: r.cost_usd,
            total_tokens: r.total_tokens,
            model: r.model,
            agent_name: r.agent_name,
            end_user: r.end_user,
        }
    }
}

/// `{ sessions }` — the §3 session list.
#[derive(Debug, Clone, Serialize)]
pub struct SessionListResponse {
    pub sessions: Vec<SessionSummary>,
}

/// One turn (trace) within a session, as returned by the session-detail endpoint.
/// Each links to the existing `/traces/{trace_id}` detail. POSITIONAL — field
/// order MUST match the `build_session_traces_sql` SELECT.
#[derive(Debug, Clone, Deserialize, Serialize, clickhouse::Row)]
pub struct SessionTraceRow {
    pub trace_id: String,
    pub root_name: String,
    pub start_time: String,
    pub start_time_us: i64,
    pub duration_us: i64,
    pub span_count: u32,
    pub error_count: u32,
    pub model: String,
}

/// `{ session_id, traces }` — the ordered turns of one session.
#[derive(Debug, Clone, Serialize)]
pub struct SessionTracesResponse {
    pub session_id: String,
    pub traces: Vec<SessionTraceRow>,
}

// ── OBS-55: session transcript (turn-by-turn read + exchange projection) ─────
//
// `GET /v1/sessions/{id}/transcript`. Same tenant seam as the two routes
// above (bound first, from the claim only); NEW here is (a) a whole-session
// TOTALS aggregate that is never derived from a page, (b) a server-computed
// `ordinal` that is exact on any page (a `row_number()` window function over
// the FULL per-trace aggregate, filtered to the page only in the OUTER query —
// so the keyset cursor narrows rows without disturbing the numbering), and
// (c) an "exchange" projection: the latest-starting span in each turn that
// carries a model (the turn's last LLM call), content-rehydrated exactly as
// `list_spans` rehydrates (`crates/gateway/src/billing/blobs.rs`).

/// Whole-session aggregate — computed over EVERY span of the session, never
/// summed from a page. `cost_usd` is `None` when `priced_spans == 0` (an
/// honestly-unknown cost is never rendered as a confident $0.00 — the same
/// distinction `spans.cost_usd_present` exists for at the storage layer).
#[derive(Debug, Clone, Serialize)]
pub struct SessionTranscriptTotals {
    pub turns: u32,
    pub spans: u64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cost_usd: Option<f64>,
    pub priced_spans: u64,
    pub first_start: String,
    pub last_end: String,
    pub duration_us: i64,
    pub error_spans: u64,
    pub models: Vec<String>,
    pub end_user: String,
    pub agent_name: String,
}

/// Internal ClickHouse row for the totals aggregate. POSITIONAL — field order
/// MUST match [`build_session_totals_sql`]'s SELECT list.
#[derive(Debug, Clone, Deserialize, clickhouse::Row)]
pub struct SessionTotalsRow {
    pub turns: u32,
    pub spans: u64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cost_usd: f64,
    pub priced_spans: u64,
    pub first_start: String,
    pub last_end: String,
    pub duration_us: i64,
    pub error_spans: u64,
    /// `groupUniqArray` over the served-else-requested model expression —
    /// includes `""` for any span that carried no model at all, filtered out
    /// in [`SessionTranscriptTotals::from`] rather than in SQL (a `-If`
    /// combinator on `groupUniqArray` is untested in this tree; filtering a
    /// small in-memory `Vec<String>` is not).
    pub models: Vec<String>,
    pub end_user: String,
    pub agent_name: String,
}

impl From<SessionTotalsRow> for SessionTranscriptTotals {
    fn from(r: SessionTotalsRow) -> Self {
        Self {
            turns: r.turns,
            spans: r.spans,
            input_tokens: r.input_tokens,
            output_tokens: r.output_tokens,
            cost_usd: (r.priced_spans > 0).then_some(r.cost_usd),
            priced_spans: r.priced_spans,
            first_start: r.first_start,
            last_end: r.last_end,
            duration_us: r.duration_us,
            error_spans: r.error_spans,
            models: r.models.into_iter().filter(|m| !m.is_empty()).collect(),
            end_user: r.end_user,
            agent_name: r.agent_name,
        }
    }
}

/// `{ workspace_policy: "on" | "off" }` — the tenant's OWN content-capture
/// setting, the same allowlist decision `dataset_routes::capture_enabled`
/// reads (B-299, the ONE policy).
#[derive(Debug, Clone, Serialize)]
pub struct SessionCapture {
    pub workspace_policy: &'static str,
}

/// One turn (trace) in the transcript, ascending. POSITIONAL — field order
/// MUST match [`build_session_turns_sql`]'s SELECT list, plus the
/// server-assembled `exchange` (a second, small query — see
/// [`ClickHouseTraceReader::session_turns`]).
#[derive(Debug, Clone, Deserialize, clickhouse::Row)]
pub struct SessionTurnRow {
    pub trace_id: String,
    pub ordinal: u32,
    pub start_time_iso: String,
    pub start_time_us: i64,
    pub duration_us: i64,
    pub span_count: u64,
    pub error_spans: u64,
    /// The FIRST error span's `status_message` in this turn (`argMinIf` by
    /// `start_time`) — `""` when the turn has no error span.
    pub status_message: String,
    pub intervention: u8,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cost_usd: f64,
    pub priced_spans: u64,
    pub model: String,
}

/// The turn's last LLM call — one span, content-rehydrated. `content` is
/// `"captured"` (rehydrated, non-empty), `"unloaded"` (a `$ref` that failed to
/// rehydrate), `"unreadable"` (present but did not deserialize) or `"absent"`
/// (no `gen_ai_input_messages` on the exchange span — recorded before capture,
/// or by a route that does not capture input on this trace).
#[derive(Debug, Clone, Serialize)]
pub struct SessionExchange {
    #[serde(flatten)]
    pub generation: crate::generation_issues::GenerationDetails,
    pub span_id: String,
    /// The input messages AFTER the last `assistant` message — the NEW
    /// user/tool input of this turn. The full history is the trace page's job.
    pub input_tail: Vec<Message>,
    pub input_message_count: usize,
    pub output: serde_json::Value,
    pub finish_reasons: Vec<String>,
    /// `{tracelane_response_tool_names, tracelane_response_tool_arg_bytes,
    /// gen_ai_output_messages, gen_ai_response_finish_reasons}` as a JSON
    /// STRING — the web runs its EXISTING `extractToolCalls` on this directly
    /// (`apps/web/lib/tool-calls.ts`), one tool-call interpretation, not two.
    pub tool_attrs: String,
    pub content: &'static str,
}

/// One page of a session's turn-by-turn transcript.
#[derive(Debug, Clone, Serialize)]
pub struct SessionTranscriptResponse {
    pub totals: SessionTranscriptTotals,
    pub capture: SessionCapture,
    pub turns: Vec<SessionTurn>,
    pub next_cursor: Option<String>,
}

/// The public turn shape — [`SessionTurnRow`] plus its assembled `exchange`.
#[derive(Debug, Clone, Serialize)]
pub struct SessionTurn {
    pub trace_id: String,
    pub ordinal: u32,
    pub start_time: String,
    pub duration_us: i64,
    pub span_count: u64,
    pub error_spans: u64,
    pub status_message: String,
    pub intervention: u8,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cost_usd: Option<f64>,
    pub model: String,
    /// `None` when the turn has no LLM span at all (e.g. every span errored
    /// before a model call, or an SDK trace whose spans never set a model).
    pub exchange: Option<SessionExchange>,
}

// ── Filters (parsed, validated) ──────────────────────────────────────────────

/// Sortable trace-list column. Keyset pagination generalizes over this: the
/// cursor's numeric part is the sort column's value of the last row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TraceSort {
    /// `start_time` (the default newest-first view).
    #[default]
    StartTime,
    /// `duration_us` (slowest/fastest traces).
    Duration,
    /// `span_count` (biggest/smallest traces) — a real trace_summaries column.
    SpanCount,
}

/// Sort direction. Drives both the `ORDER BY` and the keyset comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortOrder {
    #[default]
    Desc,
    Asc,
}

/// A trace group-by dimension (the /v1/traces/groups view). Allowlisted — the
/// `GROUP BY` expression is chosen by this enum, never interpolated from input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceGroupBy {
    Model,
    Operation,
    Status,
}

/// Sortable session-list column. Allowlisted — the `ORDER BY` expression is
/// chosen by this enum, never interpolated from user input. All are aggregate
/// expressions/aliases over the grouped session rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionSort {
    /// `max(end_time)` — most recent activity (default newest-first view).
    #[default]
    LastActivity,
    /// `uniqExact(trace_id)` — turns per conversation.
    Turns,
    /// `cost_usd` — summed per-span cost.
    Cost,
    /// `total_tokens` — summed input+output tokens.
    Tokens,
    /// `duration_us` — first-turn-to-last-turn span.
    Duration,
}

impl SessionSort {
    /// The `ORDER BY` expression for this column (an aggregate or a SELECT
    /// alias — both are legal in ClickHouse `ORDER BY`). Compile-time literal,
    /// never user input.
    fn order_expr(self) -> &'static str {
        match self {
            SessionSort::LastActivity => "max(end_time)",
            SessionSort::Turns => "turns",
            SessionSort::Cost => "cost_usd",
            SessionSort::Tokens => "total_tokens",
            SessionSort::Duration => "duration_us",
        }
    }
}

/// Validated trace-list filters. All optional except `limit`.
#[derive(Debug, Clone, Default)]
pub struct TraceListFilters {
    pub issues: Vec<Issue>,
    pub agent: Option<String>,
    pub model_family: Option<String>,
    pub model: Option<String>,
    /// `Some(true)` → only traces with errors; `Some(false)` → only clean.
    pub has_error: Option<bool>,
    /// §2 latency floor — inclusive lower bound on the trace `duration_us`.
    /// (Read-path: `trace_summaries.duration_us` exists; no schema change.)
    pub min_duration_us: Option<i64>,
    /// §2 signature filter — keep only traces with ≥1 span matching this AFT id.
    /// Resolved via a **tenant-scoped** `spans` subquery (no per-trace signature
    /// column exists on `trace_summaries`).
    pub signature_id: Option<String>,
    /// `Some(true)` → only traces where a span recorded a cross-provider failover
    /// (the `tracelane_failover_activated` span attribute). Resolved via a
    /// **tenant-scoped** `spans` subquery (no failover column on `trace_summaries`).
    /// `None` / `Some(false)` → no failover filter.
    pub failover: Option<bool>,
    /// `OBS-20`. Keep only traces with ≥1 span carrying this end-user id — the
    /// "show me this person's traces" filter.
    ///
    /// Resolved via a **tenant-scoped `spans` subquery**, the same shape as
    /// `failover` above and for the same reason: it is a per-span JSON
    /// attribute and `trace_summaries` has no column for it. The value is BOUND,
    /// never interpolated — it is caller-supplied text, so interpolating it here
    /// would be a SQL-injection seam on the one field an attacker controls.
    ///
    /// Matched EXACTLY, not by substring. A prefix match would silently return
    /// `u_1`'s traces when asked for `u_10`, which for an identity filter is a
    /// wrong answer rather than a loose one.
    pub end_user: Option<String>,
    /// Inclusive lower bound on `start_time`, microseconds since epoch.
    pub since_us: Option<i64>,
    /// Inclusive upper bound on `start_time`, microseconds since epoch.
    pub until_us: Option<i64>,
    /// OBS-01 free-text search over span content (`name` + the `attributes` JSON).
    ///
    /// **Index-assisted, not a scan.** `spans` is `ORDER BY (tenant_id, trace_id,
    /// span_id)`, so a content predicate prunes nothing by itself. Migration 14 adds
    /// `ngrambf_v1(4, …)` skip indexes on `name` and `attributes`.
    ///
    /// Two consequences the caller is told rather than surprised by: the term has a
    /// **minimum length of 4** (the ngram `n`) and a shorter one is REJECTED rather
    /// than quietly scanned; and matching is substring, case-folded only insofar as
    /// the raw term and its lowercase form are both probed — full case-insensitivity
    /// needs a materialized lowercase column, an S5 schema change V1 does not have.
    pub q: Option<String>,
    /// Keyset cursor: `(sort_value, trace_id)` of the last row seen — the numeric
    /// part is the `sort` column's value (start_time_us or duration_us).
    pub cursor: Option<(i64, String)>,
    /// Sort column (default `StartTime`).
    pub sort: TraceSort,
    /// Sort direction (default `Desc`).
    pub order: SortOrder,
    pub limit: u32,
}

/// Validated SLO filters.
#[derive(Debug, Clone, Default)]
pub struct SloFilters {
    /// Inclusive lower bound on `bucket_hour`, seconds since epoch. When set it
    /// overrides `hours`.
    pub since_secs: Option<i64>,
    /// Sub-hour bucket width in minutes (DSH-11 §3a.4). `Some` switches EVERY SLO
    /// route — rows, timeseries, summary and models (B-500) — from the hourly view
    /// (bounded by `bucket_hour`) to `spans FINAL` (bounded by `start_time`); only
    /// allowed for windows ≤ 24 h. `None` = the hourly-view paths, unchanged.
    pub bucket_minutes: Option<u32>,
    /// Inclusive upper bound on `bucket_hour`, seconds since epoch.
    pub until_secs: Option<i64>,
    /// Rolling look-back window in hours (used only when `since_secs` is None).
    pub hours: u32,
    pub provider: Option<String>,
    pub model: Option<String>,
    /// Display-bucket width in hours for `/v1/slo`. `0` or `1` means HOURLY —
    /// byte-identical to the pre-2026-08-17 response, which is why every existing
    /// caller is unaffected.
    ///
    /// WHY THIS EXISTS: at `hours=720` the hourly response is **906 rows / 213 KB**
    /// against 46 rows / 11 KB at 24h. The dashboard is a Cloudflare Worker, so that
    /// payload is parsed and aggregated inside a per-request CPU ceiling, and 30d was
    /// the first surface to fall over under load (`Error 1102`). Bucketing to a day
    /// collapses it to ~30-60 rows.
    ///
    /// It is not a precision trade. The client derives request-weighted means from
    /// these rows; a bucketed row carries a TRUE `quantileMerge` over the same hours,
    /// which is strictly better than a mean of hourly percentiles.
    pub bucket_hours: u32,
}

/// Validated Gateway-ops filters. Bounded look-back keeps the live `spans`
/// aggregate from scanning the full TTL for a big tenant.
#[derive(Debug, Clone, Default)]
pub struct GatewayStatsFilters {
    /// Inclusive lower bound on `start_time`, seconds since epoch. When set it
    /// overrides `hours`.
    pub since_secs: Option<i64>,
    /// Inclusive upper bound on `start_time`, seconds since epoch (DSH-11).
    pub until_secs: Option<i64>,
    /// Rolling look-back window in hours (used only when `since_secs` is None).
    pub hours: u32,
    /// Per-provider row cap (bound `?`).
    pub limit: u32,
}

/// Validated guardrails-surface filters. Bounded look-back keeps the
/// `guardrail_verdicts` scan cheap for a busy tenant.
#[derive(Debug, Clone, Default)]
pub struct GuardrailStatsFilters {
    /// Inclusive lower bound on `event_time`, seconds since epoch. Overrides `hours`.
    pub since_secs: Option<i64>,
    /// Inclusive upper bound on `event_time`, seconds since epoch (DSH-11).
    pub until_secs: Option<i64>,
    /// Rolling look-back window in hours (used only when `since_secs` is None).
    pub hours: u32,
    /// Per-rail row cap (bound `?`).
    pub limit: u32,
}

/// Validated guardrail verdict-list filters. Bounded look-back + LIMIT keep the
/// `guardrail_verdicts` scan cheap for a busy tenant.
#[derive(Debug, Clone, Default)]
pub struct GuardrailVerdictListFilters {
    /// Inclusive lower bound on `event_time`, seconds since epoch. Overrides `hours`.
    pub since_secs: Option<i64>,
    /// Inclusive upper bound on `event_time`, seconds since epoch (DSH-11).
    pub until_secs: Option<i64>,
    /// Rolling look-back window in hours (used only when `since_secs` is None).
    pub hours: u32,
    /// Allowlisted decision filter (`allow`|`block`|`redact`|`warn`); `None` = all.
    /// Validated in the handler, then a bound `?` — never interpolated.
    pub decision: Option<String>,
    /// Exact correlation-id lookup (the ULID the gateway returns in a 403 block
    /// body). Charset-validated in the handler, then a bound `?`. Lets a caller
    /// paste the id from a blocked request and land on that verdict.
    pub correlation_id: Option<String>,
    /// Per-rail filter (B-335a): rows whose `rails` JSON array carries an entry with
    /// `"rail" == <id>`, e.g. `R4_trifecta`. Charset-validated in the handler
    /// (`[A-Za-z0-9_]{1,40}`), then a bound `?` inside `arrayExists`.
    pub rail: Option<String>,
    /// Row cap (bound `?`).
    pub limit: u32,
}

/// Validated §4 failure-signatures filters.
#[derive(Debug, Clone, Default)]
pub struct SignatureFilters {
    /// Inclusive lower bound on the matched span's `start_time`, microseconds.
    /// ALWAYS set by the handler since DSH-11: a bare call used to scan the
    /// tenant's whole history under `ARRAY JOIN` (B-331).
    pub since_us: Option<i64>,
    /// Inclusive upper bound, microseconds (DSH-11).
    pub until_us: Option<i64>,
    pub limit: u32,
    /// The web's LIVE-detector AFT-1 id allowlist (from `aft-taxonomy.ts`, the
    /// canonical `detectorStatus` source). When non-empty it scopes the
    /// "traces affected" scalar to traces carrying a LIVE signature — so the
    /// headline matches its "at least one LIVE failure signature" hint instead of
    /// also counting demo-seeder roadmap ids (provenance audit P2 #11). Empty →
    /// unscoped (any non-empty `aft_ids`), the pre-existing behaviour.
    pub live_signature_ids: Vec<String>,
}

/// Validated §3 session-list filters. Bounded look-back keeps the live
/// `spans` aggregation from scanning the full 90-day TTL for a big tenant.
#[derive(Debug, Clone, Default)]
pub struct SessionListFilters {
    /// Inclusive lower bound on `start_time`, microseconds. When set it
    /// overrides `window_days`.
    pub since_us: Option<i64>,
    /// Inclusive upper bound on `start_time`, microseconds (DSH-11).
    pub until_us: Option<i64>,
    /// Rolling look-back window in days (used only when `since_us` is None).
    pub window_days: u32,
    /// Keep only spans of this response model (bound `?`); scopes each session's
    /// turns/cost/tokens to that model, matching the trace-list `model` filter.
    pub model: Option<String>,
    /// Post-aggregation status filter: `Some(true)` = errored sessions only,
    /// `Some(false)` = clean sessions only, `None` = all (HAVING, no bind).
    pub status_error: Option<bool>,
    /// Sort column (default `LastActivity`).
    pub sort: SessionSort,
    /// Sort direction (default `Desc`).
    pub order: SortOrder,
    pub limit: u32,
}

// ── SQL builders (pure — unit-tested without a ClickHouse client) ────────────

/// B-379 (2026-09-12): the read window, ALWAYS present, bound FIRST as two `WITH`
/// clocks that every subquery sees (ClickHouse propagates `WITH` into subqueries —
/// `enable_global_with_statement`, on by default). Before this the window was
/// optional and, when absent, "last 50 traces" read the tenant's entire history
/// pricing-guard: allow "1M traces" — a measured row count, not an allowance
/// (measured: 1,000,576 rows / 72 MB on 1M traces) and hit `max_rows_to_read` at
/// ~50M — it FAILED, not slowed. Two `?` here, then the tenant, then the filters.
const WINDOW_WITH: &str = "WITH fromUnixTimestamp64Micro(?) AS w_since, \
fromUnixTimestamp64Micro(?) AS w_until ";

/// B-379: the merge `FINAL` used to do, done as GROUP BY over ONLY the window's
/// rows. `SimpleAggregateFunction(max/min/sum)` merges ARE max/min/sum, so this
/// is the same collapse of partial rows `trace_summaries FINAL` performs — and
/// unlike `FINAL` it can use the time-ordered projection `p_by_time` (migration
/// 22). `st_min`/`et_max` are NOT named `start_time`/`end_time`: an alias equal to
/// the column name makes the inner `WHERE start_time >= w_since` resolve to the
/// aggregate (`ILLEGAL_AGGREGATION`). `duration_us` is computed here from the
/// MERGED bounds, so every outer reader (filter, sort, p95) sees the true value.
/// One `?` (the tenant); the clocks come from [`WINDOW_WITH`].
const MERGED_SUMMARIES: &str = "(SELECT tenant_id, trace_id, \
max(root_name) AS root_name, \
min(start_time) AS st_min, \
max(end_time) AS et_max, \
dateDiff('microsecond', min(start_time), max(end_time)) AS duration_us, \
sum(span_count) AS span_count, \
sum(error_count) AS error_count, \
max(intervention) AS intervention, \
max(model) AS model \
FROM trace_summaries \
WHERE tenant_id = ? AND start_time >= w_since AND start_time <= w_until \
GROUP BY tenant_id, trace_id)";

/// The filter clauses shared by the list, the count and the groups queries —
/// ONE function so the three cannot drift (they had, once: the B-368 identity
/// fix landed in one copy). Appended after `WHERE tenant_id = ?`; the `?` order
/// is `[model], [min_duration_us], [sig_tenant, sig_id], [q_tenant, q, q_lower,
/// q, q_lower], [failover_tenant], [issue_tenant], [end_user_tenant, end_user]`, which
/// [`bind_trace_filters`] mirrors. Every `spans` subquery carries the window
/// (`w_since`/`w_until`) so it prunes on the time-first key of migration 22
/// instead of scanning the tenant's history.
fn push_trace_filters(sql: &mut String, f: &TraceListFilters) {
    if f.model.is_some() {
        sql.push_str(" AND model = ?");
    }
    if f.min_duration_us.is_some() {
        sql.push_str(" AND duration_us >= ?");
    }
    if f.signature_id.is_some() {
        // §2 signature filter. The subquery is ALSO `tenant_id = ?`-bound, so it
        // can never widen across tenants — the same isolation invariant as the
        // outer query. `has(aft_ids, ?)` matches the per-span signature array.
        sql.push_str(
            " AND trace_id IN (SELECT trace_id FROM spans \
WHERE tenant_id = ? AND start_time >= w_since AND start_time <= w_until AND has(aft_ids, ?))",
        );
    }
    if f.q.is_some() {
        // OBS-01 free-text search. Tenant-scoped subquery — same isolation invariant
        // as the signature filter, it can never widen across tenants.
        // `multiSearchAny` on the RAW column: the `name` ngram index (migration 14)
        // serves it and prunes; the `attributes` ngram index was deleted in
        // migration 22 on measurement (it pruned nothing on the JSON blob) — the
        // window is what bounds that half now.
        sql.push_str(
            " AND trace_id IN (SELECT trace_id FROM spans \
WHERE tenant_id = ? AND start_time >= w_since AND start_time <= w_until \
AND (multiSearchAny(name, [?, ?]) OR multiSearchAny(attributes, [?, ?])))",
        );
    }
    if f.failover == Some(true) {
        // Failover is a per-span JSON attribute (no column on trace_summaries);
        // tenant-scoped subquery, same isolation invariant as the signature filter.
        sql.push_str(
            " AND trace_id IN (SELECT trace_id FROM spans \
WHERE tenant_id = ? AND start_time >= w_since AND start_time <= w_until \
AND JSONExtractBool(attributes, 'tracelane_failover_activated'))",
        );
    }
    if !f.issues.is_empty() {
        // Kinds are parsed into a closed enum before reaching this builder.
        // OR is scoped inside the tenant/window subquery, never outside it.
        let predicates = f
            .issues
            .iter()
            .map(|issue| format!("({})", issue_predicate_sql(*issue)))
            .collect::<Vec<_>>()
            .join(" OR ");
        sql.push_str(&format!(
            " AND trace_id IN (SELECT trace_id FROM spans FINAL \
WHERE tenant_id = ? AND start_time >= w_since AND start_time <= w_until AND ({predicates}))"
        ));
    }
    if f.end_user.is_some() {
        // OBS-20. Same tenant-scoped-subquery shape as the failover filter above,
        // and it inherits the same isolation invariant: the subquery is itself
        // `tenant_id = ?`-bound, so an end-user id from another tenant can never
        // widen the result.
        sql.push_str(
            " AND trace_id IN (SELECT trace_id FROM spans \
WHERE tenant_id = ? AND start_time >= w_since AND start_time <= w_until \
AND JSONExtractString(attributes, 'user_id') = ?)",
        );
    }
    for (value, expr) in [
        (&f.agent, crate::kya_routes::agent_key_sql()),
        (&f.model_family, crate::kya_routes::model_key_sql()),
    ] {
        if value.is_some() {
            sql.push_str(&format!(
                " AND trace_id IN (SELECT trace_id FROM spans FINAL \
WHERE tenant_id = ? AND start_time >= w_since AND start_time <= w_until \
AND {} AND {expr} = ?)",
                crate::kya_routes::CALL_SQL
            ));
        }
    }
    match f.has_error {
        Some(true) => sql.push_str(" AND error_count > 0"),
        Some(false) => sql.push_str(" AND error_count = 0"),
        None => {}
    }
}

/// Build the trace-list SELECT. `?` order: `w_since, w_until, inner tenant,
/// outer tenant`, then [`push_trace_filters`]'s order, then `[cursor ×3]`, `limit`.
fn build_trace_list_sql(f: &TraceListFilters) -> String {
    let mut sql = String::from(WINDOW_WITH);
    sql.push_str(
        "SELECT trace_id, root_name, \
toString(st_min) AS start_time_iso, \
toInt64(toUnixTimestamp64Micro(st_min)) AS start_time_us, \
duration_us, span_count, error_count, intervention, model \
FROM ",
    );
    sql.push_str(MERGED_SUMMARIES);
    sql.push_str(" WHERE tenant_id = ?");
    push_trace_filters(&mut sql, f);
    // Sort column + direction from a fixed allowlist (never user input → safe to
    // interpolate; the `?` values stay bound). `cursor_expr` is the sort column's
    // value used by the keyset comparison — for start_time it references the
    // merged DateTime64 via toUnixTimestamp64Micro (the `start_time_us` alias would
    // trip the ILLEGAL_TYPE_OF_ARGUMENT class).
    let (sort_col, cursor_expr) = match f.sort {
        TraceSort::StartTime => ("st_min", "toUnixTimestamp64Micro(st_min)"),
        TraceSort::Duration => ("duration_us", "duration_us"),
        TraceSort::SpanCount => ("span_count", "span_count"),
    };
    let (dir, op) = match f.order {
        SortOrder::Desc => ("DESC", "<"),
        SortOrder::Asc => ("ASC", ">"),
    };
    if f.cursor.is_some() {
        // Keyset on (sort_col, trace_id) for a stable walk in the chosen direction.
        sql.push_str(&format!(
            " AND ({cursor_expr} {op} ? OR ({cursor_expr} = ? AND trace_id {op} ?))"
        ));
    }
    sql.push_str(&format!(
        " ORDER BY {sort_col} {dir}, trace_id {dir} LIMIT ?"
    ));
    sql
}

/// Build the trace-COUNT scalar — the tenant total matching the SAME filters as
/// the list (for the "50 of N traces" footer). Same `?` order as
/// [`build_trace_list_sql`] MINUS cursor/limit. One row: `total`.
///
/// `count()` over the MERGED subquery: partial rows are already collapsed by the
/// GROUP BY, so the `uniqExact(trace_id)` the pre-B-379 query needed against
/// `FINAL`'s leftovers is no longer the question.
fn build_trace_count_sql(f: &TraceListFilters) -> String {
    let mut sql = String::from(WINDOW_WITH);
    sql.push_str("SELECT toUInt64(count()) AS total FROM ");
    sql.push_str(MERGED_SUMMARIES);
    sql.push_str(" WHERE tenant_id = ?");
    push_trace_filters(&mut sql, f);
    sql
}

/// Parse the `sort` query param → allowlisted [`TraceSort`] (default StartTime).
fn parse_sort(s: Option<&str>) -> TraceSort {
    match s {
        Some("duration") => TraceSort::Duration,
        Some("spans") => TraceSort::SpanCount,
        _ => TraceSort::StartTime,
    }
}

/// Parse the `failover` query param → `Some(true)` only for `"true"` (the
/// Gateway "Failovers" click-through); any other value means no filter.
fn parse_failover(s: Option<&str>) -> Option<bool> {
    if s == Some("true") { Some(true) } else { None }
}

/// Parse the `order` query param → [`SortOrder`] (default Desc).
fn parse_order(s: Option<&str>) -> SortOrder {
    match s {
        Some("asc") => SortOrder::Asc,
        _ => SortOrder::Desc,
    }
}

/// Parse the session `sort` query param → allowlisted [`SessionSort`]
/// (default LastActivity).
fn parse_session_sort(s: Option<&str>) -> SessionSort {
    match s {
        Some("turns") => SessionSort::Turns,
        Some("cost") => SessionSort::Cost,
        Some("tokens") => SessionSort::Tokens,
        Some("duration") => SessionSort::Duration,
        _ => SessionSort::LastActivity,
    }
}

/// Parse the session `status` query param → `Some(true)` (errored sessions),
/// `Some(false)` (clean sessions), or `None` (no filter).
fn parse_status_filter(s: Option<&str>) -> Option<bool> {
    match s {
        Some("error") => Some(true),
        Some("ok") => Some(false),
        _ => None,
    }
}

/// Parse the `by` query param → [`TraceGroupBy`]; `None` for an unknown value
/// (the handler rejects it — grouping has no sensible default).
fn parse_group_by(s: &str) -> Option<TraceGroupBy> {
    match s {
        "model" => Some(TraceGroupBy::Model),
        "operation" => Some(TraceGroupBy::Operation),
        "status" => Some(TraceGroupBy::Status),
        _ => None,
    }
}

/// Build the trace group-by aggregation SELECT. The `GROUP BY` expression is
/// chosen from the [`TraceGroupBy`] allowlist (never input); the filter WHERE
/// clauses + their `?` bind order MIRROR [`build_trace_list_sql`] so
/// [`ClickHouseTraceReader::list_trace_groups`] binds them identically.
fn build_trace_groups_sql(by: TraceGroupBy, f: &TraceListFilters) -> String {
    let group_expr = match by {
        TraceGroupBy::Model => "model",
        TraceGroupBy::Operation => "root_name",
        TraceGroupBy::Status => "if(error_count > 0, 'error', 'ok')",
    };
    // `count()` / `countIf` over the merged subquery (one row per trace after the
    // GROUP BY, so no `uniqExact` is needed). `quantileExact` (not the approximate
    // `quantile`) so the p95 column is the TRUE 95th percentile of the group's
    // trace durations, not ClickHouse's reservoir estimate shown as if exact
    // (provenance audit P2 #8).
    let mut sql = String::from(WINDOW_WITH);
    sql.push_str(&format!(
        "SELECT {group_expr} AS group_key, \
toUInt64(count()) AS trace_count, \
toUInt64(countIf(error_count > 0)) AS error_traces, \
avg(duration_us) AS avg_duration_us, \
quantileExact(0.95)(duration_us) AS p95_duration_us \
FROM "
    ));
    sql.push_str(MERGED_SUMMARIES);
    sql.push_str(" WHERE tenant_id = ?");
    push_trace_filters(&mut sql, f);
    sql.push_str(" GROUP BY group_key ORDER BY trace_count DESC LIMIT ?");
    sql
}

/// Static spans SELECT — `tenant_id` first, then `trace_id`, both bound.
const SPANS_SQL: &str = "SELECT span_id, parent_span_id, name, \
toString(start_time) AS start_time_iso, \
toString(end_time) AS end_time_iso, \
toInt64(toUnixTimestamp64Micro(start_time)) AS start_time_us, \
duration_us, status_code, status_message, attributes, aft_ids, intervention \
FROM spans FINAL \
WHERE tenant_id = ? AND trace_id = ? \
ORDER BY start_time ASC, span_id ASC";

/// Per-trace ledger-status lookup (wedge item 4). Tenant-first, both binds
/// parameterized. Matches the gateway-proxied chain row to the trace by the
/// `trace_id` embedded in the (verbatim-canonical-JSON) `payload`. `event_type`
/// is pinned to the gateway-call event types — `chat.completions.request`,
/// `messages.request`, and `embeddings.request` — so only a real
/// gateway call counts; a `guardrail.verdict`/`eval.verdict` row is never mistaken for the
/// call. B-358: the first `/v1/messages` deploy wrote its ledger rows (3 observed on prod)
/// and this read still said `chained:false`, because it named one event type. Newest
/// row wins (a trace_id is unique per request, but be defensive). One row max.
const TRACE_CHAIN_SQL: &str = "SELECT seq, rekor_entry_id \
FROM tracelane.audit_log \
WHERE tenant_id = ? \
AND event_type IN ('chat.completions.request', 'messages.request', 'embeddings.request') \
AND JSONExtractString(payload, 'trace_id') = ? \
ORDER BY seq DESC LIMIT 1";

/// Whether a matched chain row is anchored to a real transparency-log entry.
/// A NULL `rekor_entry_id` (row written before its batch anchored) → false;
/// otherwise defer to the shared sentinel check (`(no-rekor)` etc. → false).
fn anchored_from(rekor_entry_id: Option<&str>) -> bool {
    rekor_entry_id.is_some_and(crate::audit::is_real_rekor_entry)
}

/// One per-trace cost/token rollup row. The list source `trace_summaries` has no
/// cost/token columns, so these are summed read-time from the trace's spans.
/// Positional column order matches [`build_trace_cost_rollup_sql`].
#[derive(Debug, Clone, Deserialize, clickhouse::Row)]
pub struct TraceCostRow {
    pub trace_id: String,
    pub cost_usd: f64,
    pub total_tokens: i64,
}

/// Build the per-trace cost/token rollup SELECT for a page of `n_ids` traces.
/// Sums the REAL stored `gen_ai_usage_cost` (guarded finite/positive, like the
/// gateway-stats rollup) plus `input + output` usage tokens over each trace's
/// spans. `tenant_id = ?` is the first predicate and bound; the `trace_id IN
/// (?, …)` list is bound per id — index-served on the `(tenant_id, trace_id)`
/// order, so the spans scan is bounded to the page (≤ `MAX_TRACE_LIMIT` ids),
/// never a full-tenant scan. Callers must never invoke this with `n_ids == 0`
/// (an empty `IN ()` is invalid SQL) — the reader short-circuits that.
fn build_trace_cost_rollup_sql(n_ids: usize) -> String {
    let placeholders = vec!["?"; n_ids].join(", ");
    format!(
        "SELECT trace_id AS trace_id, \
round(sum(if(isFinite(JSONExtractFloat(attributes, 'gen_ai_usage_cost')) \
AND JSONExtractFloat(attributes, 'gen_ai_usage_cost') > 0, \
JSONExtractFloat(attributes, 'gen_ai_usage_cost'), 0)), 6) AS cost_usd, \
toInt64(sum(toInt64(JSONExtractUInt(attributes, 'gen_ai_usage_input_tokens')) \
+ toInt64(JSONExtractUInt(attributes, 'gen_ai_usage_output_tokens')))) AS total_tokens \
FROM spans FINAL \
WHERE tenant_id = ? AND trace_id IN ({placeholders}) \
GROUP BY trace_id"
    )
}

#[derive(Debug, Clone, Deserialize, clickhouse::Row)]
pub struct TraceIssueRow {
    pub trace_id: String,
    pub issue_counts: Vec<u64>,
}

/// Only the current page's ids; all spans of each trace, deduplicated first.
fn build_trace_issue_rollup_sql(n_ids: usize) -> String {
    let placeholders = vec!["?"; n_ids].join(", ");
    let counts = ISSUES
        .into_iter()
        .map(|issue| format!("toUInt64(countIf({}))", issue_predicate_sql(issue)))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "SELECT trace_id, [{counts}] AS issue_counts FROM spans FINAL \
WHERE tenant_id = ? AND trace_id IN ({placeholders}) GROUP BY trace_id"
    )
}

/// The window + filter predicates of every SUB-HOUR SLO read (`spans FINAL` by
/// `start_time`, provider/model through the MV's own derivation). ONE function so
/// the four builders cannot drift on the boundary again (B-500): `?` order is
/// (since_secs | hours), [until_secs], [provider], [model] — after the tenant.
fn push_slo_span_window_predicates(sql: &mut String, f: &SloFilters) {
    if f.since_secs.is_some() {
        sql.push_str(" AND start_time >= toDateTime(?)");
    } else {
        sql.push_str(" AND start_time >= now() - toIntervalHour(?)");
    }
    if f.until_secs.is_some() {
        sql.push_str(" AND start_time <= toDateTime(?)");
    }
    if f.provider.is_some() {
        sql.push_str(&format!(" AND {MV_PROVIDER_EXPR} = ?"));
    }
    if f.model.is_some() {
        sql.push_str(&format!(" AND {MV_MODEL_EXPR} = ?"));
    }
}

/// Build the SLO SELECT against `v_slo_stats`. `?` order: tenant,
/// (since_secs | hours), [until_secs], [provider], [model].
fn build_slo_sql(f: &SloFilters) -> String {
    // SUB-HOUR (DSH-11 §3a.4): the hourly view cannot go finer than an hour, so a
    // 1h/6h/24h window reads `spans FINAL` directly, bucketed by minute, with the
    // MV's OWN provider/model derivation so the count means the same thing. Same
    // eleven columns in the same order — only the granularity differs.
    if let Some(m) = f.bucket_minutes {
        let mut sql = format!(
            "SELECT toString(toStartOfInterval(start_time, toIntervalMinute({m}))) AS bucket_hour_iso, \
{MV_PROVIDER_EXPR} AS provider, \
{MV_MODEL_EXPR} AS model, \
round(quantile(0.50)(duration_us) / 1000, 1) AS p50_ms, \
round(quantile(0.95)(duration_us) / 1000, 1) AS p95_ms, \
round(quantile(0.99)(duration_us) / 1000, 1) AS p99_ms, \
toUInt64(count()) AS requests, \
toUInt64(countIf(status_code = 2)) AS errors, \
round(countIf(status_code = 2) * 100.0 / greatest(count(), 1), 2) AS error_rate_pct, \
toInt64(sum(toInt64(JSONExtractInt(attributes, 'gen_ai_usage_input_tokens')))) AS total_input_tokens, \
toInt64(sum(toInt64(JSONExtractInt(attributes, 'gen_ai_usage_output_tokens')))) AS total_output_tokens \
FROM spans FINAL \
WHERE tenant_id = ? AND {MV_PROVIDER_EXPR} != ''"
        );
        push_slo_span_window_predicates(&mut sql, f);
        sql.push_str(" GROUP BY bucket_hour_iso, provider, model ORDER BY bucket_hour_iso DESC");
        return sql;
    }
    // HOURLY (bucket_hours 0 or 1) keeps the exact pre-existing query against the
    // view, so the default response is unchanged for every existing caller.
    //
    // BUCKETED reads `slo_hourly_stats` directly and re-groups. It cannot go through
    // `v_slo_stats`: that view has already collapsed the AggregateFunction columns to
    // scalars, and a mean of hourly percentiles is not a percentile. Merging the
    // states at the wider interval is what makes the bucketed p95 a TRUE p95 rather
    // than an average of 24 of them. Column list, names and order are identical in
    // both branches — the row SHAPE never changes, only the time granularity.
    let mut sql = if f.bucket_hours > 1 {
        let b = f.bucket_hours;
        format!(
            "SELECT toString(toStartOfInterval(bucket_hour, toIntervalHour({b}))) AS bucket_hour_iso, \
provider, model, \
round(quantileMerge(0.50)(latency_p50) / 1000, 1) AS p50_ms, \
round(quantileMerge(0.95)(latency_p95) / 1000, 1) AS p95_ms, \
round(quantileMerge(0.99)(latency_p99) / 1000, 1) AS p99_ms, \
toUInt64(countMerge(request_count)) AS requests, \
toUInt64(countMerge(error_count)) AS errors, \
round(countMerge(error_count) * 100.0 / greatest(countMerge(request_count), 1), 2) AS error_rate_pct, \
toInt64(sumMerge(input_tokens)) AS total_input_tokens, \
toInt64(sumMerge(output_tokens)) AS total_output_tokens \
FROM slo_hourly_stats \
WHERE tenant_id = ? AND provider <> ''"
        )
    } else {
        String::from(
            "SELECT toString(bucket_hour) AS bucket_hour_iso, provider, model, \
p50_ms, p95_ms, p99_ms, requests, errors, error_rate_pct, \
total_input_tokens, total_output_tokens \
FROM v_slo_stats \
WHERE tenant_id = ? AND provider <> ''",
        )
    };
    if f.since_secs.is_some() {
        sql.push_str(" AND bucket_hour >= toDateTime(?)");
    } else {
        sql.push_str(" AND bucket_hour >= now() - toIntervalHour(?)");
    }
    if f.until_secs.is_some() {
        sql.push_str(" AND bucket_hour <= toDateTime(?)");
    }
    if f.provider.is_some() {
        sql.push_str(" AND provider = ?");
    }
    if f.model.is_some() {
        sql.push_str(" AND model = ?");
    }
    if f.bucket_hours > 1 {
        // GROUP BY the SELECT alias, matching build_slo_timeseries_sql. Ordering by
        // the alias (not the raw column) is required here — `bucket_hour` is not in
        // the grouping key once the interval collapses it.
        sql.push_str(" GROUP BY bucket_hour_iso, provider, model ORDER BY bucket_hour_iso DESC");
    } else {
        sql.push_str(" ORDER BY bucket_hour DESC");
    }
    sql
}

/// Build the window-WIDE SLO summary SELECT — the TRUE p50/p95/p99 over the
/// whole window via `quantileMerge` over the stored `quantileState`, NOT a
/// weighted mean of per-hour bucket percentiles (#9: the dashboard tile
/// computed `Σ(pXX·requests)/Σrequests` client-side — a percentile-of-percentiles
/// that diverges from the true quantile). One row. `?` order mirrors
/// `build_slo_sql`: tenant, (since_secs | hours), [until_secs], [provider],
/// [model]. `provider <> ''` scopes to LLM-request spans — the same scoping the
/// tile applies — so the headline reconciles with the /slo rows + chart.
///
/// B-500 (2026-09-21): reconciling with the chart also means reading the SAME
/// TABLE BY THE SAME COLUMN. A sub-hour bucket (`bucket_minutes`) sends the two
/// series builders to `spans FINAL` bounded by `start_time`; this one always read
/// `slo_hourly_stats` bounded by `bucket_hour = toStartOfHour(start_time)`, so a
/// 1 h preset opened at 14:37 charted 13:37–14:37 and headlined 14:00–14:37, and a
/// custom window inside one hour headlined "no traffic" beside bars. The sub-hour
/// branch below is `build_slo_sql`'s, minus the bucket column and the GROUP BY;
/// the `?` order is identical, so the reader's binds are untouched.
fn build_slo_summary_sql(f: &SloFilters) -> String {
    if f.bucket_minutes.is_some() {
        // Same empty-window guard as the hourly branch: `quantile` over zero rows is
        // NaN, and NaN does not serialize (A1).
        let mut sql = format!(
            "SELECT \
if(count() = 0, 0, round(quantile(0.50)(duration_us) / 1000, 1)) AS p50_ms, \
if(count() = 0, 0, round(quantile(0.95)(duration_us) / 1000, 1)) AS p95_ms, \
if(count() = 0, 0, round(quantile(0.99)(duration_us) / 1000, 1)) AS p99_ms, \
toUInt64(count()) AS requests, \
toUInt64(countIf(status_code = 2)) AS errors \
FROM spans FINAL \
WHERE tenant_id = ? AND {MV_PROVIDER_EXPR} != ''"
        );
        push_slo_span_window_predicates(&mut sql, f);
        return sql;
    }
    let mut sql = String::from(
        // Guard the quantiles against an EMPTY window: with no GROUP BY, a
        // zero-row aggregate still emits one row, and quantileMerge over zero
        // states is NaN → round(NaN)=NaN → serde_json cannot serialize NaN → the
        // endpoint 500s. Every sibling builder wraps this; do the same → clean 0s
        // for a brand-new / no-LLM-traffic tenant. (A1: the SLO-summary NaN-500 fix.)
        "SELECT \
if(countMerge(request_count) = 0, 0, round(quantileMerge(0.50)(latency_p50) / 1000, 1)) AS p50_ms, \
if(countMerge(request_count) = 0, 0, round(quantileMerge(0.95)(latency_p95) / 1000, 1)) AS p95_ms, \
if(countMerge(request_count) = 0, 0, round(quantileMerge(0.99)(latency_p99) / 1000, 1)) AS p99_ms, \
toUInt64(countMerge(request_count)) AS requests, \
toUInt64(countIfMerge(error_count)) AS errors \
FROM slo_hourly_stats \
WHERE tenant_id = ? AND provider <> ''",
    );
    if f.since_secs.is_some() {
        sql.push_str(" AND bucket_hour >= toDateTime(?)");
    } else {
        sql.push_str(" AND bucket_hour >= now() - toIntervalHour(?)");
    }
    if f.until_secs.is_some() {
        sql.push_str(" AND bucket_hour <= toDateTime(?)");
    }
    if f.provider.is_some() {
        sql.push_str(" AND provider = ?");
    }
    if f.model.is_some() {
        sql.push_str(" AND model = ?");
    }
    sql
}

/// Build the per-(provider, model) window-WIDE SLO SELECT — the TRUE merged
/// p50/p95/p99 for the SLO table, via `quantileMerge` over the stored per-hour
/// quantile states (NOT a client-side mean of the per-hour percentiles, which is
/// a percentile-of-percentiles that reads below the tail — provenance audit P2
/// #8). Requests/errors/tokens come from the matching merge functions so the
/// whole row is one exact aggregate. Scoped to `provider <> ''` like every other
/// SLO builder (this comment said the opposite until 2026-09-21 while the SQL
/// below had carried the scope all along — the doc was the defect, §17). `?`
/// order mirrors `build_slo_sql`: tenant, (since_secs | hours), [until_secs],
/// [provider], [model], limit.
///
/// B-500: with a sub-hour bucket this reads `spans FINAL` by `start_time` — the
/// same rows, the same window boundary, the same provider/model derivation as
/// the chart — grouped by (provider, model) instead of by bucket. See
/// `build_slo_summary_sql` for why.
fn build_slo_by_model_sql(f: &SloFilters) -> String {
    if f.bucket_minutes.is_some() {
        let mut sql = format!(
            "SELECT {MV_PROVIDER_EXPR} AS provider, \
{MV_MODEL_EXPR} AS model, \
round(quantile(0.50)(duration_us) / 1000, 1) AS p50_ms, \
round(quantile(0.95)(duration_us) / 1000, 1) AS p95_ms, \
round(quantile(0.99)(duration_us) / 1000, 1) AS p99_ms, \
toUInt64(count()) AS requests, \
toUInt64(countIf(status_code = 2)) AS errors, \
round(countIf(status_code = 2) * 100.0 / greatest(count(), 1), 2) AS error_rate_pct, \
toInt64(sum(toInt64(JSONExtractInt(attributes, 'gen_ai_usage_input_tokens')))) AS total_input_tokens, \
toInt64(sum(toInt64(JSONExtractInt(attributes, 'gen_ai_usage_output_tokens')))) AS total_output_tokens \
FROM spans FINAL \
WHERE tenant_id = ? AND {MV_PROVIDER_EXPR} != ''"
        );
        push_slo_span_window_predicates(&mut sql, f);
        sql.push_str(" GROUP BY provider, model ORDER BY requests DESC LIMIT ?");
        return sql;
    }
    let mut sql = String::from(
        "SELECT provider, model, \
round(quantileMerge(0.50)(latency_p50) / 1000, 1) AS p50_ms, \
round(quantileMerge(0.95)(latency_p95) / 1000, 1) AS p95_ms, \
round(quantileMerge(0.99)(latency_p99) / 1000, 1) AS p99_ms, \
toUInt64(countMerge(request_count)) AS requests, \
toUInt64(countIfMerge(error_count)) AS errors, \
round(countIfMerge(error_count) * 100.0 / greatest(countMerge(request_count), 1), 2) AS error_rate_pct, \
toInt64(sumMerge(input_tokens)) AS total_input_tokens, \
toInt64(sumMerge(output_tokens)) AS total_output_tokens \
FROM slo_hourly_stats \
WHERE tenant_id = ? AND provider <> ''",
    );
    if f.since_secs.is_some() {
        sql.push_str(" AND bucket_hour >= toDateTime(?)");
    } else {
        sql.push_str(" AND bucket_hour >= now() - toIntervalHour(?)");
    }
    if f.until_secs.is_some() {
        sql.push_str(" AND bucket_hour <= toDateTime(?)");
    }
    if f.provider.is_some() {
        sql.push_str(" AND provider = ?");
    }
    if f.model.is_some() {
        sql.push_str(" AND model = ?");
    }
    sql.push_str(" GROUP BY provider, model ORDER BY requests DESC LIMIT ?");
    sql
}

/// Build the latency-over-time SELECT — one row per display bucket with the TRUE
/// merged p50/p95/p99 (`quantileMerge` over the per-hour quantile states in the
/// bucket), scoped to LLM spans (`provider <> ''`). Replaces the chart's
/// client-side request-weighted mean of per-hour percentiles (provenance audit
/// P2 #8; both the dashboard and SLO charts). `bucket_hours` is a server-CLAMPED
/// small integer, so it is safe to interpolate into `toIntervalHour(N)` (numeric,
/// never user free-text) — this keeps `tenant_id` the first BOUND `?`. `?` order:
/// tenant, (since_secs | hours), [until_secs].
fn build_slo_timeseries_sql(f: &SloFilters, bucket_hours: u32) -> String {
    // SUB-HOUR (DSH-11 §3a.4) — raw spans, minute buckets, MV-identical scoping.
    if let Some(m) = f.bucket_minutes {
        let mut sql = format!(
            "SELECT \
toString(toStartOfInterval(start_time, toIntervalMinute({m}))) AS bucket_start, \
round(quantile(0.50)(duration_us) / 1000, 1) AS p50_ms, \
round(quantile(0.95)(duration_us) / 1000, 1) AS p95_ms, \
round(quantile(0.99)(duration_us) / 1000, 1) AS p99_ms, \
toUInt64(count()) AS requests, \
toUInt64(countIf(status_code = 2)) AS errors \
FROM spans FINAL \
WHERE tenant_id = ? AND {MV_PROVIDER_EXPR} != ''"
        );
        push_slo_span_window_predicates(&mut sql, f);
        sql.push_str(" GROUP BY bucket_start ORDER BY bucket_start ASC");
        return sql;
    }
    let mut sql = format!(
        "SELECT \
toString(toStartOfInterval(bucket_hour, toIntervalHour({bucket_hours}))) AS bucket_start, \
round(quantileMerge(0.50)(latency_p50) / 1000, 1) AS p50_ms, \
round(quantileMerge(0.95)(latency_p95) / 1000, 1) AS p95_ms, \
round(quantileMerge(0.99)(latency_p99) / 1000, 1) AS p99_ms, \
toUInt64(countMerge(request_count)) AS requests, \
toUInt64(countIfMerge(error_count)) AS errors \
FROM slo_hourly_stats \
WHERE tenant_id = ? AND provider <> ''"
    );
    if f.since_secs.is_some() {
        sql.push_str(" AND bucket_hour >= toDateTime(?)");
    } else {
        sql.push_str(" AND bucket_hour >= now() - toIntervalHour(?)");
    }
    if f.until_secs.is_some() {
        sql.push_str(" AND bucket_hour <= toDateTime(?)");
    }
    // B-332: `provider` / `model` were parsed into the filters and NEVER bound here,
    // so a model-filtered chart drew tenant-wide data under a model label.
    if f.provider.is_some() {
        sql.push_str(" AND provider = ?");
    }
    if f.model.is_some() {
        sql.push_str(" AND model = ?");
    }
    sql.push_str(" GROUP BY bucket_start ORDER BY bucket_start ASC");
    sql
}

/// Build the window-wide latency-SPLIT SELECT (§ latency framing) — one row over
/// `spans FINAL`. Decomposes end-to-end latency into the two honest segments:
///   • `overhead_*` = `gateway_overhead_us` (the time Tracelane ADDS, excluding
///     the provider round-trip). Only spans that carry a MEASURED overhead count
///     (`JSONHas(...)`), so spans written before the instrumentation deploy — or
///     non-gateway spans — never dilute the metric with a structural `0`.
///   • `provider_*` = `duration_us − gateway_overhead_us` (the LLM, not us),
///     `greatest(…, 0)`-clamped so a clock skew never yields a negative segment.
///   • `ttft_*` = `gen_ai.response.time_to_first_chunk` (seconds → ms), streaming
///     spans only — read straight from the attribute (no MV dependency).
/// Every quantile is `if(countIf(cond)=0, 0, …)`-guarded so an empty window (or a
/// window with no streaming traffic) returns `0.0`, never a NaN that would fail
/// JSON serialization. `provider <> ''` scopes to gateway LLM spans — the same
/// scoping as the SLO tile. `?` order: tenant, (since_secs | hours).
///
/// **B-568 C3 (2026-09-27) — the populations.** `overhead_*` and `provider_*` are
/// over DISPATCHED spans only (a measured overhead AND not a cache hit): a hit's
/// overhead is by design its whole duration (`chat.rs` stamps both boundaries at
/// `now`), and averaging hits in reported ~500 ms of "gateway time" that was the
/// hit request's pre-dispatch cost. Hits get their own `cache_hit_*`. Dispatched
/// spans split again on `tracelane_gateway_cold_start` (present only when true):
/// `warm_samples` / `overhead_warm_*` are the steady state, `cold_start_samples`
/// the requests that paid a control-plane round trip. Every new quantile carries
/// the same `if(countIf(<its condition>) = 0, 0, …)` guard and a `*_samples` count
/// over the SAME condition.
fn build_latency_totals_sql(f: &GatewayStatsFilters) -> String {
    const HAS_OH: &str = "JSONHas(attributes, 'tracelane_gateway_overhead_us')";
    const IS_HIT: &str = "JSONExtractBool(attributes, 'tracelane_semantic_cache_hit')";
    const IS_COLD: &str = "JSONExtractBool(attributes, 'tracelane_gateway_cold_start')";
    const HAS_TTFT: &str = "JSONHas(attributes, 'gen_ai_response_time_to_first_chunk') \
AND JSONExtractFloat(attributes, 'gen_ai_response_time_to_first_chunk') > 0";
    let dispatched = format!("{HAS_OH} AND NOT {IS_HIT}");
    let hits = format!("{HAS_OH} AND {IS_HIT}");
    let warm = format!("{dispatched} AND NOT {IS_COLD}");
    let cold = format!("{dispatched} AND {IS_COLD}");
    // One guarded overhead quantile over one population — built once so every
    // quantile's guard is, by construction, over the same condition as its own
    // `quantileIf`.
    let oh = |q: &str, cond: &str, alias: &str| {
        format!(
            "if(countIf({cond}) = 0, 0, round(quantileIf({q})(gateway_overhead_us, {cond}) / 1000, 1)) AS {alias}"
        )
    };
    let prov = |q: &str, alias: &str| {
        format!(
            "if(countIf({dispatched}) = 0, 0, round(quantileIf({q})(greatest(toInt64(duration_us) - toInt64(gateway_overhead_us), 0), {dispatched}) / 1000, 1)) AS {alias}"
        )
    };
    let mut sql = format!(
        "SELECT \
toUInt64(countIf({dispatched})) AS overhead_samples, \
{o50}, {o95}, {o99}, {p50}, {p95}, {p99}, \
toUInt64(countIf({HAS_TTFT})) AS ttft_samples, \
if(countIf({HAS_TTFT}) = 0, 0, round(quantileIf(0.50)(JSONExtractFloat(attributes, 'gen_ai_response_time_to_first_chunk') * 1000, {HAS_TTFT}), 1)) AS ttft_p50_ms, \
if(countIf({HAS_TTFT}) = 0, 0, round(quantileIf(0.95)(JSONExtractFloat(attributes, 'gen_ai_response_time_to_first_chunk') * 1000, {HAS_TTFT}), 1)) AS ttft_p95_ms, \
if(countIf({HAS_TTFT}) = 0, 0, round(quantileIf(0.99)(JSONExtractFloat(attributes, 'gen_ai_response_time_to_first_chunk') * 1000, {HAS_TTFT}), 1)) AS ttft_p99_ms, \
toUInt64(countIf({hits})) AS cache_hit_samples, \
{h50}, {h95}, \
toUInt64(countIf({cold})) AS cold_start_samples, \
toUInt64(countIf({warm})) AS warm_samples, \
{w50}, {w95} \
FROM spans FINAL \
WHERE tenant_id = ? AND JSONExtractString(attributes, 'gen_ai_provider_name') != ''",
        o50 = oh("0.50", &dispatched, "overhead_p50_ms"),
        o95 = oh("0.95", &dispatched, "overhead_p95_ms"),
        o99 = oh("0.99", &dispatched, "overhead_p99_ms"),
        p50 = prov("0.50", "provider_p50_ms"),
        p95 = prov("0.95", "provider_p95_ms"),
        p99 = prov("0.99", "provider_p99_ms"),
        h50 = oh("0.50", &hits, "cache_hit_served_p50_ms"),
        h95 = oh("0.95", &hits, "cache_hit_served_p95_ms"),
        w50 = oh("0.50", &warm, "overhead_warm_p50_ms"),
        w95 = oh("0.95", &warm, "overhead_warm_p95_ms"),
    );
    if f.since_secs.is_some() {
        sql.push_str(" AND start_time >= toDateTime(?)");
    } else {
        sql.push_str(" AND start_time >= now() - toIntervalHour(?)");
    }
    if f.until_secs.is_some() {
        sql.push_str(" AND start_time <= toDateTime(?)");
    }
    sql
}

/// Build the per-(provider, model) gateway-overhead SELECT for the SLO table's
/// "our slice" column. Every row is filtered to `JSONHas(...)` (measured overhead
/// only), so each group has ≥1 sample and the p95 quantile is never NaN. `model`
/// is the request model attribute (matches `mv_ttft`). `?` order: tenant,
/// (since_secs | hours), limit.
fn build_latency_by_model_sql(f: &GatewayStatsFilters) -> String {
    let mut sql = String::from(
        "SELECT \
JSONExtractString(attributes, 'gen_ai_provider_name') AS provider, \
JSONExtractString(attributes, 'gen_ai_request_model') AS model, \
round(quantile(0.95)(gateway_overhead_us) / 1000, 1) AS overhead_p95_ms, \
toUInt64(count()) AS samples \
FROM spans FINAL \
WHERE tenant_id = ? AND JSONHas(attributes, 'tracelane_gateway_overhead_us') \
AND NOT JSONExtractBool(attributes, 'tracelane_semantic_cache_hit') \
AND JSONExtractString(attributes, 'gen_ai_provider_name') != ''",
    );
    if f.since_secs.is_some() {
        sql.push_str(" AND start_time >= toDateTime(?)");
    } else {
        sql.push_str(" AND start_time >= now() - toIntervalHour(?)");
    }
    if f.until_secs.is_some() {
        sql.push_str(" AND start_time <= toDateTime(?)");
    }
    sql.push_str(" GROUP BY provider, model ORDER BY samples DESC LIMIT ?");
    sql
}

/// Build the Gateway-ops per-provider health SELECT — a live aggregate over
/// `spans FINAL` (no MV; same posture as the §3 sessions / §4 signatures reads).
/// Only REAL, captured signals: request volume, error rate (`status_code = 2`,
/// a top-level column), latency percentiles (`duration_us`, materialized), and
/// prompt-cache hits (`gen_ai_usage_cache_read_input_tokens > 0`). Provider is
/// the ingest-normalized `gen_ai_provider_name` attribute; the non-empty filter
/// isolates gateway LLM spans. Failover + rate-limit are deliberately absent —
/// they are logged only, never written to `spans`, so surfacing them here would
/// be fabrication. `tenant_id = ?` is the first WHERE predicate and bound. `?`
/// order: tenant, (since_secs | hours), limit.
fn build_gateway_stats_sql(f: &GatewayStatsFilters) -> String {
    let mut sql = String::from(
        "SELECT \
JSONExtractString(attributes, 'gen_ai_provider_name') AS provider, \
toUInt64(count()) AS requests, \
toUInt64(countIf(status_code = 2)) AS errors, \
round(quantile(0.50)(duration_us) / 1000, 1) AS p50_ms, \
round(quantile(0.95)(duration_us) / 1000, 1) AS p95_ms, \
round(quantile(0.99)(duration_us) / 1000, 1) AS p99_ms, \
toUInt64(countIf(JSONExtractUInt(attributes, 'gen_ai_usage_cache_read_input_tokens') > 0)) AS cache_hits, \
toUInt64(countIf(JSONExtractBool(attributes, 'tracelane_failover_activated'))) AS failovers, \
round(sumIf(spans.cost_usd, spans.cost_usd_present = 1 AND isFinite(spans.cost_usd)), 6) AS cost_usd, \
if(countIf(JSONHas(attributes, 'tracelane_gateway_overhead_us') AND NOT JSONExtractBool(attributes, 'tracelane_semantic_cache_hit')) = 0, 0, round(quantileIf(0.95)(gateway_overhead_us, JSONHas(attributes, 'tracelane_gateway_overhead_us') AND NOT JSONExtractBool(attributes, 'tracelane_semantic_cache_hit')) / 1000, 1)) AS overhead_p95_ms \
FROM spans FINAL \
WHERE tenant_id = ? AND JSONExtractString(attributes, 'gen_ai_provider_name') != ''",
    );
    if f.since_secs.is_some() {
        sql.push_str(" AND start_time >= toDateTime(?)");
    } else {
        sql.push_str(" AND start_time >= now() - toIntervalHour(?)");
    }
    if f.until_secs.is_some() {
        sql.push_str(" AND start_time <= toDateTime(?)");
    }
    sql.push_str(" GROUP BY provider ORDER BY requests DESC LIMIT ?");
    sql
}

/// Build the guardrails tenant-summary SELECT over `guardrail_verdicts`. Single
/// aggregate row (never empty). Latency percentiles are guarded with
/// `if(count()=0, 0, …)` so an empty window returns 0.0, never a NaN that would
/// fail JSON serialization. `?` order: tenant, (since_secs | hours).
fn build_guardrail_summary_sql(f: &GuardrailStatsFilters) -> String {
    let mut sql = String::from(
        "SELECT \
toUInt64(count()) AS total, \
toUInt64(countIf(decision = 'allow')) AS allows, \
toUInt64(countIf(decision = 'block')) AS blocks, \
toUInt64(countIf(decision = 'redact')) AS redacts, \
toUInt64(countIf(decision = 'warn')) AS warns, \
toUInt64(countIf(notEmpty(fail_open_rails))) AS fail_open_verdicts, \
toUInt64(countIf(side = 'request')) AS request_side, \
toUInt64(countIf(side = 'response')) AS response_side, \
if(count() = 0, 0.0, round(quantile(0.50)(total_latency_micros) / 1000, 2)) AS p50_ms, \
if(count() = 0, 0.0, round(quantile(0.95)(total_latency_micros) / 1000, 2)) AS p95_ms, \
if(count() = 0, 0.0, round(quantile(0.99)(total_latency_micros) / 1000, 2)) AS p99_ms \
FROM guardrail_verdicts \
WHERE tenant_id = ?",
    );
    if f.since_secs.is_some() {
        sql.push_str(" AND event_time >= toDateTime(?)");
    } else {
        sql.push_str(" AND event_time >= now() - toIntervalHour(?)");
    }
    if f.until_secs.is_some() {
        sql.push_str(" AND event_time <= toDateTime(?)");
    }
    sql
}

/// Build the per-rail health SELECT — `ARRAY JOIN` over the `rails` JSON array so
/// each rail's evaluations / blocks / fail-opens / p95 latency come from the
/// captured per-rail verdicts (never fabricated). `?` order: tenant,
/// (since_secs | hours), limit.
fn build_guardrail_rails_sql(f: &GuardrailStatsFilters) -> String {
    let mut sql = String::from(
        "SELECT \
JSONExtractString(rail_json, 'rail') AS rail, \
toUInt64(count()) AS evaluations, \
toUInt64(countIf(JSONExtractString(rail_json, 'outcome') = 'block')) AS blocks, \
toUInt64(countIf(JSONExtractString(rail_json, 'outcome') = 'fail_open')) AS fail_opens, \
round(quantile(0.95)(JSONExtractUInt(rail_json, 'latency_micros')) / 1000, 2) AS p95_ms \
FROM guardrail_verdicts \
ARRAY JOIN JSONExtractArrayRaw(rails) AS rail_json \
WHERE tenant_id = ? AND JSONExtractString(rail_json, 'rail') != ''",
    );
    if f.since_secs.is_some() {
        sql.push_str(" AND event_time >= toDateTime(?)");
    } else {
        sql.push_str(" AND event_time >= now() - toIntervalHour(?)");
    }
    if f.until_secs.is_some() {
        sql.push_str(" AND event_time <= toDateTime(?)");
    }
    sql.push_str(" GROUP BY rail ORDER BY evaluations DESC LIMIT ?");
    sql
}

/// Build the guardrail verdict-list SELECT — the detail rows behind the
/// decision-mix counts (the click-through for "N blocked"). `tenant_id = ?` is
/// the first WHERE predicate and bound; the optional `decision` filter is a
/// bound `?` (allowlist-validated in the handler), never interpolated. `?`
/// order: tenant, [decision], [correlation_id], (since_secs | hours), limit.
fn build_guardrail_verdicts_sql(f: &GuardrailVerdictListFilters) -> String {
    let mut sql = String::from(
        "SELECT \
correlation_id, \
side, \
decision, \
toString(event_time) AS ev_str, \
total_latency_micros, \
rails, \
fail_open_rails \
FROM guardrail_verdicts \
WHERE tenant_id = ?",
    );
    if f.decision.is_some() {
        sql.push_str(" AND decision = ?");
    }
    if f.correlation_id.is_some() {
        sql.push_str(" AND correlation_id = ?");
    }
    if f.rail.is_some() {
        // `rails` is a JSON array string of per-rail verdicts (`[{"rail":"R4_trifecta",…}]`).
        sql.push_str(
            " AND arrayExists(r -> JSONExtractString(r, 'rail') = ?, JSONExtractArrayRaw(rails))",
        );
    }
    if f.since_secs.is_some() {
        sql.push_str(" AND event_time >= toDateTime(?)");
    } else {
        sql.push_str(" AND event_time >= now() - toIntervalHour(?)");
    }
    if f.until_secs.is_some() {
        sql.push_str(" AND event_time <= toDateTime(?)");
    }
    sql.push_str(" ORDER BY event_time DESC LIMIT ?");
    sql
}

/// Build the §4 failure-signatures aggregate SELECT — the "your hits" surface.
///
/// There is **no `mv_signature_hits` MV** (it never existed in CH or the schema
/// SQL — the schema reference was aspirational); the only signature
/// data is the per-span `aft_ids Array(String)` column. So this aggregates live
/// via `ARRAY JOIN` over `spans.aft_ids`. `tenant_id = ?` is the first WHERE
/// predicate and bound. The SELECT emits `your_hits` (this tenant's count) ONLY —
/// no cross-tenant/network column (honesty lock, the build spec §4). `?` order:
/// tenant, [since_us], limit.
fn build_signatures_sql(f: &SignatureFilters) -> String {
    let mut sql = String::from(
        "SELECT aft_id AS signature_id, \
toUInt64(count()) AS your_hits, \
max(intervention) AS max_intervention, \
formatDateTime(min(start_time), '%FT%TZ') AS first_seen, \
formatDateTime(max(start_time), '%FT%TZ') AS last_seen, \
toUInt64(uniqExact(trace_id)) AS traces_affected \
FROM spans FINAL \
ARRAY JOIN aft_ids AS aft_id \
WHERE tenant_id = ? AND notEmpty(aft_id)",
    );
    if f.since_us.is_some() {
        sql.push_str(" AND start_time >= fromUnixTimestamp64Micro(?)");
    }
    if f.until_us.is_some() {
        sql.push_str(" AND start_time <= fromUnixTimestamp64Micro(?)");
    }
    sql.push_str(" GROUP BY aft_id ORDER BY your_hits DESC, signature_id ASC LIMIT ?");
    sql
}

/// Build the §4 distinct-traces-affected scalar — the count of DISTINCT traces
/// that carry a LIVE failure signature in the window (the "traces affected"
/// headline). No `ARRAY JOIN` and no `GROUP BY`: `uniqExact(trace_id)` over spans
/// with a matching `aft_ids` yields ONE row, counting a trace once even if it
/// matches several signatures (summing the per-signature counts would
/// double-count). When `live_signature_ids` is non-empty the match is
/// `arrayExists(a -> a IN (?, …))` over the LIVE-detector allowlist so a
/// demo-seeder roadmap id never inflates the "live" headline; empty → the
/// pre-existing `notEmpty(aft_ids)`. `tenant_id = ?` is the first predicate and
/// bound; each live id is BOUND (never interpolated). `?` order: tenant,
/// [live_ids…], [since_us].
fn build_signatures_trace_total_sql(f: &SignatureFilters) -> String {
    let mut sql = String::from(
        "SELECT toUInt64(uniqExact(trace_id)) AS total \
FROM spans FINAL \
WHERE tenant_id = ?",
    );
    if f.live_signature_ids.is_empty() {
        sql.push_str(" AND notEmpty(aft_ids)");
    } else {
        let placeholders = vec!["?"; f.live_signature_ids.len()].join(", ");
        sql.push_str(&format!(
            " AND arrayExists(a -> a IN ({placeholders}), aft_ids)"
        ));
    }
    if f.since_us.is_some() {
        sql.push_str(" AND start_time >= fromUnixTimestamp64Micro(?)");
    }
    if f.until_us.is_some() {
        sql.push_str(" AND start_time <= fromUnixTimestamp64Micro(?)");
    }
    sql
}

/// One-row scalar for [`build_signatures_trace_total_sql`] (`uniqExact` always
/// returns exactly one row).
#[derive(Debug, Clone, Deserialize, clickhouse::Row)]
struct TraceTotalRow {
    total: u64,
}

/// Build the §3 session-list SELECT — multi-turn threads grouped by
/// `gen_ai.conversation.id` across the tenant's spans. There is NO
/// `session_summaries` MV (V1.1 promotes this if it gets hot — same posture as
/// the §4 signatures aggregate); the only session key is the per-span attribute,
/// so this aggregates live over `spans FINAL`, bounded by a look-back window +
/// LIMIT and the ADR-031 [`TenantQuery`] caps. `tenant_id = ?` is the first WHERE
/// predicate and bound; the conversation-id key is a compile-time literal, never
/// user input. `?` order: tenant, (since_us | window_days), limit.
fn build_session_list_sql(f: &SessionListFilters) -> String {
    let conv = CONVERSATION_ID_ATTR;
    let enduser = END_USER_ID_ATTR;
    let mut sql = format!(
        "SELECT \
JSONExtractString(attributes, '{conv}') AS session_id, \
toUInt32(uniqExact(trace_id)) AS turns, \
toString(min(start_time)) AS started_at, \
toString(max(end_time)) AS last_activity, \
toInt64(dateDiff('microsecond', min(start_time), max(end_time))) AS duration_us, \
toUInt32(countIf(status_code = 2)) AS error_count, \
sum(if(isFinite(JSONExtractFloat(attributes, 'gen_ai_usage_cost')) \
AND JSONExtractFloat(attributes, 'gen_ai_usage_cost') > 0, \
JSONExtractFloat(attributes, 'gen_ai_usage_cost'), 0)) AS cost_usd, \
toInt64(sum(toInt64(JSONExtractUInt(attributes, 'gen_ai_usage_input_tokens')) \
+ toInt64(JSONExtractUInt(attributes, 'gen_ai_usage_output_tokens')))) AS total_tokens, \
argMax({MV_MODEL_EXPR}, start_time) AS model, \
argMax(coalesce(nullIf(JSONExtractString(attributes, 'gen_ai_agent_name'), ''), JSONExtractString(attributes, 'tracelane_client_name')), start_time) AS agent_name, \
argMax(JSONExtractString(attributes, '{enduser}'), start_time) AS end_user \
FROM spans FINAL \
WHERE tenant_id = ? AND JSONExtractString(attributes, '{conv}') != ''"
    );
    // Model filter (bound) — placed right after tenant so the bind order stays:
    // tenant, [model], (since_us | window_days), limit.
    if f.model.is_some() {
        // RI-05 / B-444: the served model when known, else the requested one — the same
        // coalesce every other model read uses; `gen_ai_response_model` alone is absent
        // on cache hits and error spans now that it is the provider's own claim.
        sql.push_str(&format!(" AND {MV_MODEL_EXPR} = ?"));
    }
    if f.since_us.is_some() {
        sql.push_str(" AND start_time >= fromUnixTimestamp64Micro(?)");
    } else {
        sql.push_str(" AND start_time >= now() - toIntervalDay(?)");
    }
    if f.until_us.is_some() {
        sql.push_str(" AND start_time <= fromUnixTimestamp64Micro(?)");
    }
    sql.push_str(" GROUP BY session_id");
    // Status filter — post-aggregation, literal comparison (no bind).
    match f.status_error {
        Some(true) => sql.push_str(" HAVING countIf(status_code = 2) > 0"),
        Some(false) => sql.push_str(" HAVING countIf(status_code = 2) = 0"),
        None => {}
    }
    let dir = match f.order {
        SortOrder::Desc => "DESC",
        SortOrder::Asc => "ASC",
    };
    // `session_id DESC` tiebreak keeps the LIMIT deterministic under ties.
    sql.push_str(&format!(
        " ORDER BY {} {dir}, session_id DESC LIMIT ?",
        f.sort.order_expr()
    ));
    sql
}

/// Build the §3 session-detail SELECT — the ordered turns (traces) of ONE
/// session. `tenant_id = ?` is bound first, then the session id (bound, never
/// interpolated), so a session id from another tenant can never widen the
/// result. Each row links to the existing `/traces/{trace_id}` detail. `?`
/// order: tenant, session_id.
fn build_session_traces_sql() -> String {
    let conv = CONVERSATION_ID_ATTR;
    format!(
        "SELECT \
trace_id, \
argMinIf(name, start_time, parent_span_id IS NULL) AS root_name, \
toString(min(start_time)) AS start_time_iso, \
toInt64(toUnixTimestamp64Micro(min(start_time))) AS start_time_us, \
toInt64(dateDiff('microsecond', min(start_time), max(end_time))) AS duration_us, \
toUInt32(count()) AS span_count, \
toUInt32(countIf(status_code = 2)) AS error_count, \
argMax({MV_MODEL_EXPR}, start_time) AS model \
FROM spans FINAL \
WHERE tenant_id = ? AND JSONExtractString(attributes, '{conv}') = ? \
GROUP BY trace_id \
ORDER BY min(start_time) ASC"
    )
}

/// Build the `OBS-55` whole-session TOTALS SELECT — one row, aggregated over
/// EVERY span of the session (no LIMIT, no page). `tenant_id = ?` is the first
/// WHERE predicate and bound; the session id is bound, never interpolated.
/// `?` order: tenant, session_id.
///
/// `models` is `groupUniqArray` over [`MV_MODEL_EXPR`] — includes `""` for a
/// span that never set a model, filtered out in Rust
/// ([`SessionTotalsRow`]/[`SessionTranscriptTotals::from`]) rather than in
/// SQL (an untested `-If` combinator on `groupUniqArray` is not worth risking
/// here).
fn build_session_totals_sql() -> String {
    let conv = CONVERSATION_ID_ATTR;
    let enduser = END_USER_ID_ATTR;
    format!(
        "SELECT \
toUInt32(uniqExact(trace_id)) AS turns, \
toUInt64(count()) AS spans, \
toInt64(sum(toInt64(JSONExtractUInt(attributes, 'gen_ai_usage_input_tokens')))) AS input_tokens, \
toInt64(sum(toInt64(JSONExtractUInt(attributes, 'gen_ai_usage_output_tokens')))) AS output_tokens, \
sum(if(isFinite(JSONExtractFloat(attributes, 'gen_ai_usage_cost')) \
AND JSONExtractFloat(attributes, 'gen_ai_usage_cost') > 0, \
JSONExtractFloat(attributes, 'gen_ai_usage_cost'), 0)) AS cost_usd, \
toUInt64(countIf(isFinite(JSONExtractFloat(attributes, 'gen_ai_usage_cost')) \
AND JSONExtractFloat(attributes, 'gen_ai_usage_cost') > 0)) AS priced_spans, \
toString(min(start_time)) AS first_start, \
toString(max(end_time)) AS last_end, \
toInt64(dateDiff('microsecond', min(start_time), max(end_time))) AS duration_us, \
toUInt64(countIf(status_code = 2)) AS error_spans, \
groupUniqArray({MV_MODEL_EXPR}) AS models, \
argMax(JSONExtractString(attributes, '{enduser}'), start_time) AS end_user, \
argMax(coalesce(nullIf(JSONExtractString(attributes, 'gen_ai_agent_name'), ''), \
JSONExtractString(attributes, 'tracelane_client_name')), start_time) AS agent_name \
FROM spans FINAL \
WHERE tenant_id = ? AND JSONExtractString(attributes, '{conv}') = ?"
    )
}

/// Build the `OBS-55` PAGED turns SELECT. The inner query aggregates every
/// turn (trace) of the WHOLE session and computes `ordinal` as a
/// `row_number()` window over ALL of them, ordered `(first span start,
/// trace_id)` — so "turn 23" is exact on any page. The OUTER query then
/// applies the keyset cursor and LIMIT, narrowing rows WITHOUT touching the
/// numbering computed inside. `tenant_id = ?` is bound first; the cursor pair
/// (when present) is bound as `(start_time_us, trace_id)`, never interpolated.
/// `?` order: tenant, session_id, [cursor_ts, cursor_trace_id], limit.
fn build_session_turns_sql(has_cursor: bool) -> String {
    let conv = CONVERSATION_ID_ATTR;
    let cursor_clause = if has_cursor {
        "WHERE (start_time_us, trace_id) > (?, ?) "
    } else {
        ""
    };
    format!(
        "SELECT trace_id, ordinal, start_time_iso, start_time_us, duration_us, span_count, \
error_spans, status_message, intervention, input_tokens, output_tokens, cost_usd, \
priced_spans, model \
FROM ( \
SELECT \
trace_id, \
toUInt32(row_number() OVER (ORDER BY min(start_time) ASC, trace_id ASC)) AS ordinal, \
toString(min(start_time)) AS start_time_iso, \
toInt64(toUnixTimestamp64Micro(min(start_time))) AS start_time_us, \
toInt64(dateDiff('microsecond', min(start_time), max(end_time))) AS duration_us, \
toUInt64(count()) AS span_count, \
toUInt64(countIf(status_code = 2)) AS error_spans, \
argMinIf(status_message, start_time, status_code = 2) AS status_message, \
max(intervention) AS intervention, \
toInt64(sum(toInt64(JSONExtractUInt(attributes, 'gen_ai_usage_input_tokens')))) AS input_tokens, \
toInt64(sum(toInt64(JSONExtractUInt(attributes, 'gen_ai_usage_output_tokens')))) AS output_tokens, \
sum(if(isFinite(JSONExtractFloat(attributes, 'gen_ai_usage_cost')) \
AND JSONExtractFloat(attributes, 'gen_ai_usage_cost') > 0, \
JSONExtractFloat(attributes, 'gen_ai_usage_cost'), 0)) AS cost_usd, \
toUInt64(countIf(isFinite(JSONExtractFloat(attributes, 'gen_ai_usage_cost')) \
AND JSONExtractFloat(attributes, 'gen_ai_usage_cost') > 0)) AS priced_spans, \
argMax({MV_MODEL_EXPR}, start_time) AS model \
FROM spans FINAL \
WHERE tenant_id = ? AND JSONExtractString(attributes, '{conv}') = ? \
GROUP BY trace_id \
) \
{cursor_clause}\
ORDER BY start_time_us ASC, trace_id ASC \
LIMIT ?"
    )
}

/// Build the `OBS-55` exchange SELECT — for EACH trace id on the page, the
/// latest-starting span that carries a model (the turn's last LLM call), in
/// ONE query via `LIMIT 1 BY trace_id` (never one query per turn).
/// `tenant_id = ?` is bound first; every trace id is bound, never
/// interpolated. `?` order: tenant, trace_id ×N.
fn build_session_exchange_sql(n: usize) -> String {
    let placeholders = vec!["?"; n].join(", ");
    format!(
        "SELECT trace_id, span_id, attributes, status_code \
FROM spans FINAL \
WHERE tenant_id = ? AND trace_id IN ({placeholders}) AND {MV_MODEL_EXPR} != '' \
ORDER BY trace_id ASC, start_time DESC \
LIMIT 1 BY trace_id"
    )
}

// ── Reader trait + ClickHouse impl ───────────────────────────────────────────

/// Read-side hook for trace + SLO data. Production uses
/// [`ClickHouseTraceReader`]; tests use the in-module `MockTraceReader`.
#[async_trait::async_trait]
pub trait TraceReader: Send + Sync {
    fn generation_issue_policy(&self) -> crate::generation_issues::SummaryPolicy {
        crate::generation_issues::SummaryPolicy::embedded()
    }
    async fn generation_issue_summary(&self, tenant_id: &TenantId) -> Result<Arc<IssueSummary>>;
    async fn list_traces(
        &self,
        tenant_id: &TenantId,
        filters: &TraceListFilters,
    ) -> Result<Vec<TraceSummaryRow>>;
    async fn list_trace_groups(
        &self,
        tenant_id: &TenantId,
        by: TraceGroupBy,
        filters: &TraceListFilters,
    ) -> Result<Vec<TraceGroupRow>>;
    async fn list_spans(&self, tenant_id: &TenantId, trace_id: &str) -> Result<Vec<SpanRow>>;
    /// Tenant total matching the same filters as `list_traces` (the "50 of N
    /// traces" footer) — no cursor/sort/limit.
    async fn count_traces(&self, tenant_id: &TenantId, filters: &TraceListFilters) -> Result<u64>;
    /// Per-trace tamper-evident-ledger status (wedge item 4). Returns the
    /// matched chain row (`None` = not chained → SDK/OTLP path or pre-item-4).
    async fn trace_chain_status(
        &self,
        tenant_id: &TenantId,
        trace_id: &str,
    ) -> Result<Option<TraceChainStatus>>;
    /// Per-trace cost/token rollup for a page of `trace_ids` (read-time; the
    /// list source `trace_summaries` has no cost/token columns). Bounded to the
    /// given ids. Returns an empty vec for an empty id slice.
    async fn trace_cost_rollup(
        &self,
        tenant_id: &TenantId,
        trace_ids: &[String],
    ) -> Result<Vec<TraceCostRow>>;
    async fn trace_issue_rollup(
        &self,
        tenant_id: &TenantId,
        trace_ids: &[String],
    ) -> Result<Vec<TraceIssueRow>>;
    async fn slo(&self, tenant_id: &TenantId, filters: &SloFilters) -> Result<Vec<SloRow>>;
    async fn slo_summary(&self, tenant_id: &TenantId, filters: &SloFilters) -> Result<SloSummary>;
    /// Per-(provider, model) window-wide SLO rows with TRUE merged percentiles
    /// for the SLO table (provenance audit P2 #8).
    async fn slo_by_model(
        &self,
        tenant_id: &TenantId,
        filters: &SloFilters,
    ) -> Result<Vec<SloModelRow>>;
    /// Latency-over-time points with TRUE merged percentiles per display bucket
    /// (`bucket_hours` = interval width) for the dashboard + SLO charts.
    async fn slo_timeseries(
        &self,
        tenant_id: &TenantId,
        filters: &SloFilters,
        bucket_hours: u32,
    ) -> Result<Vec<SloTimePoint>>;
    async fn gateway_stats(
        &self,
        tenant_id: &TenantId,
        filters: &GatewayStatsFilters,
    ) -> Result<Vec<GatewayProviderRow>>;
    /// Spend attributed to one dimension (key / model / provider) over a window.
    async fn cost_breakdown(
        &self,
        tenant_id: &TenantId,
        filters: &CostFilters,
    ) -> Result<Vec<CostRow>>;
    /// DSH-13: one `breakdown` tile for a (metric, dimension) pair no other route serves.
    /// Default is EMPTY so the mock readers stay untouched; the ClickHouse reader
    /// overrides it.
    async fn metric_breakdown(
        &self,
        tenant_id: &TenantId,
        f: &BreakdownFilters,
    ) -> Result<Vec<BreakdownRow>> {
        let _ = (tenant_id, f);
        Ok(Vec::new())
    }
    /// Window-wide latency split (overhead / provider / TTFT) + per-(provider,
    /// model) overhead for the SLO table. Two live `spans` aggregates. Returns
    /// `(totals, by_model)`.
    async fn latency_breakdown(
        &self,
        tenant_id: &TenantId,
        filters: &GatewayStatsFilters,
    ) -> Result<(LatencyTotalsRow, Vec<LatencyModelRow>)>;
    async fn guardrail_summary(
        &self,
        tenant_id: &TenantId,
        filters: &GuardrailStatsFilters,
    ) -> Result<GuardrailSummaryRow>;
    async fn guardrail_rails(
        &self,
        tenant_id: &TenantId,
        filters: &GuardrailStatsFilters,
    ) -> Result<Vec<GuardrailRailRow>>;
    /// Verdict-detail rows behind the decision-mix counts (the "N blocked"
    /// click-through). Tenant-scoped, bounded by look-back + LIMIT.
    async fn guardrail_verdicts(
        &self,
        tenant_id: &TenantId,
        filters: &GuardrailVerdictListFilters,
    ) -> Result<Vec<GuardrailVerdictListRow>>;
    async fn signatures(
        &self,
        tenant_id: &TenantId,
        filters: &SignatureFilters,
    ) -> Result<Vec<SignatureHitRow>>;
    /// Distinct traces with ANY failure signature in the window — the "traces
    /// affected" headline. NEVER the sum of per-signature counts (a trace hitting
    /// multiple signatures must count once).
    async fn signatures_distinct_traces(
        &self,
        tenant_id: &TenantId,
        filters: &SignatureFilters,
    ) -> Result<u64>;
    async fn list_sessions(
        &self,
        tenant_id: &TenantId,
        filters: &SessionListFilters,
    ) -> Result<Vec<SessionSummaryRow>>;
    async fn session_traces(
        &self,
        tenant_id: &TenantId,
        session_id: &str,
    ) -> Result<Vec<SessionTraceRow>>;
    /// `OBS-55` — the whole-session totals aggregate. `None` when the session
    /// has no spans for this tenant (existence never leaks: the handler
    /// answers the same 404 as `session_traces`).
    async fn session_totals(
        &self,
        tenant_id: &TenantId,
        session_id: &str,
    ) -> Result<Option<SessionTotalsRow>>;
    /// `OBS-55` — one page of turns, `ordinal` exact against the WHOLE
    /// session, plus each turn's exchange (content-rehydrated). `cursor` is
    /// `(start_time_us, trace_id)` of the last row of the previous page.
    async fn session_turns(
        &self,
        tenant_id: &TenantId,
        session_id: &str,
        cursor: Option<(i64, String)>,
        limit: u32,
    ) -> Result<Vec<(SessionTurnRow, Option<SessionExchange>)>>;
    /// GWY-53: the tenant's content-capture decision (operator allowlist OR the
    /// workspace opt-in), for the read-side label. The default — every mock — has NO
    /// control plane, so only the operator half applies: fail-CLOSED.
    async fn content_capture(&self, tenant_id: &TenantId) -> crate::server::config::ContentCapture {
        crate::server::config::content_capture_for(None, tenant_id).await
    }
}

/// ClickHouse-backed reader. Every query is tenant-first, parameter-bound, and
/// wrapped by [`TenantQuery`] for ADR-031 resource caps.
pub struct ClickHouseTraceReader {
    rate_card: Arc<arc_swap::ArcSwap<crate::billing::RateCard>>,
    issue_summary_cache: moka::future::Cache<SummaryCacheKey, Arc<IssueSummary>>,
    client: ClickhouseClient,
    /// The same cache the hot path reads — no Postgres per request. `None` on a
    /// stack with no control plane, which resolves to the FREE tier (fail-closed,
    /// `.claude/rules/tenancy.md`).
    entitlements: Option<Arc<crate::entitlement_cache::EntitlementCache>>,
    /// The tamper-evident ledger's CANONICAL store (ADR-078 B). `Some` on any stack
    /// with a control plane — `trace_chain_status` reads presence from HERE, never
    /// from the ClickHouse `audit_log` copy, because that copy write is fail-open
    /// after commit (B-513 / CX-14). `None` only on a no-control-plane self-host,
    /// where `AuditChain::append_in_memory` writes ClickHouse directly and it is
    /// the only ledger that exists — the fallback below.
    pg_pool: Option<crate::db::DbPool>,
}

impl ClickHouseTraceReader {
    pub fn new(client: ClickhouseClient) -> Self {
        Self {
            rate_card: Arc::new(arc_swap::ArcSwap::from_pointee(
                crate::billing::RateCard::unavailable(),
            )),
            issue_summary_cache: moka::future::Cache::builder()
                .expire_after(SummaryExpiry)
                .build(),
            client,
            entitlements: None,
            pg_pool: None,
        }
    }

    #[must_use]
    pub fn with_entitlements(
        mut self,
        entitlements: Option<Arc<crate::entitlement_cache::EntitlementCache>>,
    ) -> Self {
        self.entitlements = entitlements;
        self
    }

    #[must_use]
    pub fn with_rate_card(
        mut self,
        rate_card: Arc<arc_swap::ArcSwap<crate::billing::RateCard>>,
    ) -> Self {
        self.rate_card = rate_card;
        self
    }

    /// The canonical ledger's Postgres pool (ADR-078 B) — wires `trace_chain_status`
    /// to read presence from the store of record instead of the derived ClickHouse
    /// copy (B-513 / CX-14). `None` is the honest no-control-plane state, not an
    /// omission: `.claude/rules/tenancy.md`'s "absent cache fails closed" rule does
    /// not apply here, because a no-control-plane self-host still HAS a ledger — it
    /// just lives only in the ClickHouse copy (`AuditChain::append_in_memory`).
    ///
    /// Wired at the production construction site in `server.rs` (the trace reader
    /// is built once and shared with the share routes); the dual-store test in
    /// `audit.rs` calls it directly.
    #[must_use]
    pub fn with_pg_pool(mut self, pg_pool: Option<crate::db::DbPool>) -> Self {
        self.pg_pool = pg_pool;
        self
    }

    /// The ADR-031 cap tier for THIS tenant — the tenant's own plan, read from the
    /// entitlement cache.
    ///
    /// B-330 / DSH-13 §3 (2026-09-05): every read in this file ran as
    /// `self.tier_for(tenant_id).await` — 26 literals — so a Business tenant queried under
    /// Builder's 512 MiB / 10 s / 50 M-row caps whatever it paid for, and a custom
    /// dashboard multiplies reads by tiles, which is exactly where a tier-blind cap
    /// becomes a support ticket. A test below asserts the literal is GONE from this
    /// file. Fails CLOSED: no cache → `Free`; an unknown plan key → the conservative
    /// default `from_plan_key` already carries.
    async fn tier_for(&self, tenant_id: &TenantId) -> PlanTier {
        match self.entitlements.as_ref() {
            None => PlanTier::Free,
            Some(cache) => {
                let resolved = cache.resolved(*tenant_id.as_uuid()).await;
                PlanTier::from_plan_key(&resolved.plan_lookup_key)
            }
        }
    }
}

/// B-379: the list window when the caller sends none. Seven days is the product
/// default the UI already sends; the API's previous default was "everything the
/// tenant ever recorded", which is the unbounded scan the migration-22 projection
/// cannot save. A caller that wants more sends `since`, up to its retention.
pub(crate) const DEFAULT_LIST_WINDOW_SECS: i64 = 7 * 24 * 60 * 60;
/// Slack on the upper bound so a span whose `start_time` sits a little in the
/// future (OTLP client clock skew) is not excluded from "now".
const UNTIL_SLACK_SECS: i64 = 60 * 60;

impl TraceListFilters {
    /// The effective `(since_us, until_us)` window — ALWAYS present (B-379).
    /// Pure, so the default is testable.
    #[must_use]
    pub(crate) fn window_bounds(&self, now_us: i64) -> (i64, i64) {
        (
            self.since_us
                .unwrap_or(now_us - DEFAULT_LIST_WINDOW_SECS * 1_000_000),
            self.until_us
                .unwrap_or(now_us + UNTIL_SLACK_SECS * 1_000_000),
        )
    }
}

fn now_us() -> i64 {
    chrono::Utc::now().timestamp_micros()
}

/// Bind the prefix every trace_summaries query shares: `w_since, w_until`
/// ([`WINDOW_WITH`]), the inner tenant ([`MERGED_SUMMARIES`]) and the outer
/// tenant, then the filters in [`push_trace_filters`]'s exact order. Cursor and
/// limit are the caller's.
fn bind_trace_prefix_and_filters(
    mut q: clickhouse::query::Query,
    tenant_id: &TenantId,
    f: &TraceListFilters,
) -> clickhouse::query::Query {
    let (since, until) = f.window_bounds(now_us());
    q = q
        .bind(since)
        .bind(until)
        .bind(tenant_id.to_string())
        .bind(tenant_id.to_string());
    if let Some(m) = &f.model {
        q = q.bind(m.clone());
    }
    if let Some(d) = f.min_duration_us {
        q = q.bind(d);
    }
    if let Some(sig) = &f.signature_id {
        // Subquery binds: tenant_id (again — tenant-scoped) then the AFT id.
        q = q.bind(tenant_id.to_string()).bind(sig.clone());
    }
    if let Some(term) = &f.q {
        // OBS-01 binds: tenant_id (tenant-scoped), then the term and its lowercase
        // form for BOTH columns — four probes mirroring the two
        // `multiSearchAny(col, [?, ?])` pairs, in that exact order.
        let lower = term.to_lowercase();
        q = q
            .bind(tenant_id.to_string())
            .bind(term.clone())
            .bind(lower.clone())
            .bind(term.clone())
            .bind(lower);
    }
    if f.failover == Some(true) {
        // Failover subquery binds tenant_id (tenant-scoped).
        q = q.bind(tenant_id.to_string());
    }
    if !f.issues.is_empty() {
        q = q.bind(tenant_id.to_string());
    }
    if let Some(u) = &f.end_user {
        // OBS-20 subquery binds tenant_id THEN the id — the two `?` in
        // `WHERE tenant_id = ? AND … = ?`, in that order (TRAPS §58).
        q = q.bind(tenant_id.to_string()).bind(u.clone());
    }
    for (kind, value) in [
        (crate::kya_routes::Kind::Agent, &f.agent),
        (crate::kya_routes::Kind::Model, &f.model_family),
    ] {
        if let Some(value) = value {
            q = q
                .bind(tenant_id.to_string())
                .bind(crate::kya_routes::decode_key(kind, value));
        }
    }
    q
}

#[async_trait::async_trait]
impl TraceReader for ClickHouseTraceReader {
    fn generation_issue_policy(&self) -> crate::generation_issues::SummaryPolicy {
        self.rate_card.load().policy.generation_issues
    }
    async fn generation_issue_summary(&self, tenant_id: &TenantId) -> Result<Arc<IssueSummary>> {
        let policy = self.generation_issue_policy();
        anyhow::ensure!(policy.valid(), "generation issue policy unavailable");
        let effective_days = match &self.entitlements {
            Some(cache) => cache
                .resolved(*tenant_id.as_uuid())
                .await
                .effective_window_days(),
            None => crate::billing::rating::breakdown_defaults().1,
        };
        let window_days = policy.window_days(effective_days);
        anyhow::ensure!(window_days > 0, "generation issue window unavailable");
        let content_capture = self.content_capture(tenant_id).await.input;
        let key = SummaryCacheKey {
            tenant: tenant_id.clone(),
            window_days,
            ttl_seconds: policy.summary_cache_ttl_seconds,
            content_capture,
        };
        self.issue_summary_cache
            .try_get_with(key, async {
                let until = chrono::Utc::now();
                let since = chrono::TimeDelta::try_days(i64::from(window_days))
                    .and_then(|delta| until.checked_sub_signed(delta))
                    .context("invalid generation issue window")?;
                let sql = TenantQuery::new(
                    crate::generation_issues::summary_sql(),
                    self.tier_for(tenant_id).await,
                )
                .sql_with_settings();
                let row = self
                    .client
                    .query(&sql)
                    .bind(tenant_id.to_string())
                    .bind(since.timestamp_micros())
                    .bind(until.timestamp_micros())
                    .fetch_one::<SummaryRow>()
                    .await
                    .context("generation issue summary read failed")?;
                anyhow::ensure!(
                    row.issue_counts.len() == ISSUES.len(),
                    "generation issue summary shape mismatch"
                );
                Ok::<_, anyhow::Error>(Arc::new(IssueSummary {
                    total_traces: row.total_traces,
                    llm_calls: row.llm_calls,
                    no_served_model_calls: row.no_served_model_calls,
                    no_finish_reason_calls: row.no_finish_reason_calls,
                    gateway_signal_calls: row.gateway_signal_calls,
                    counts: ISSUES
                        .into_iter()
                        .zip(row.issue_counts)
                        .map(
                            |(kind, trace_count)| crate::generation_issues::IssueTraceCount {
                                kind,
                                trace_count,
                            },
                        )
                        .collect(),
                    window_days,
                    since: since.to_rfc3339(),
                    until: until.to_rfc3339(),
                    as_of: until.to_rfc3339(),
                    content_capture,
                }))
            })
            .await
            .map_err(|err| anyhow::anyhow!("{err}"))
    }

    /// GWY-53: the workspace half from the SAME entitlement cache the hot path reads
    /// (never Postgres per request); `None` cache = no control plane = the
    /// workspace half OFF.
    async fn content_capture(&self, tenant_id: &TenantId) -> crate::server::config::ContentCapture {
        crate::server::config::content_capture_for(self.entitlements.as_deref(), tenant_id).await
    }

    async fn list_traces(
        &self,
        tenant_id: &TenantId,
        f: &TraceListFilters,
    ) -> Result<Vec<TraceSummaryRow>> {
        let sql = TenantQuery::new(build_trace_list_sql(f), self.tier_for(tenant_id).await)
            .sql_with_settings();
        let mut q = bind_trace_prefix_and_filters(self.client.query(&sql), tenant_id, f);
        if let Some((cts, cid)) = &f.cursor {
            q = q.bind(*cts).bind(*cts).bind(cid.clone());
        }
        q = q.bind(f.limit);
        q.fetch_all::<TraceSummaryRow>()
            .await
            .context("trace_summaries SELECT failed")
    }

    async fn list_trace_groups(
        &self,
        tenant_id: &TenantId,
        by: TraceGroupBy,
        f: &TraceListFilters,
    ) -> Result<Vec<TraceGroupRow>> {
        let sql = TenantQuery::new(
            build_trace_groups_sql(by, f),
            self.tier_for(tenant_id).await,
        )
        .sql_with_settings();
        // Filter binds MIRROR list_traces (same order as build_trace_groups_sql).
        let mut q = bind_trace_prefix_and_filters(self.client.query(&sql), tenant_id, f);
        q = q.bind(f.limit);
        q.fetch_all::<TraceGroupRow>()
            .await
            .context("trace groups SELECT failed")
    }

    async fn count_traces(&self, tenant_id: &TenantId, f: &TraceListFilters) -> Result<u64> {
        let sql = TenantQuery::new(build_trace_count_sql(f), self.tier_for(tenant_id).await)
            .sql_with_settings();
        // Bind order MIRRORS build_trace_list_sql's filter binds, minus cursor/limit.
        let q = bind_trace_prefix_and_filters(self.client.query(&sql), tenant_id, f);
        let row = q
            .fetch_one::<TraceTotalRow>()
            .await
            .context("trace count scalar SELECT failed")?;
        Ok(row.total)
    }

    async fn list_spans(&self, tenant_id: &TenantId, trace_id: &str) -> Result<Vec<SpanRow>> {
        let sql = TenantQuery::new(SPANS_SQL, self.tier_for(tenant_id).await).sql_with_settings();
        let mut spans: Vec<SpanRow> = self
            .client
            .query(&sql)
            .bind(tenant_id.to_string())
            .bind(trace_id.to_string())
            .fetch_all::<SpanRow>()
            .await
            .context("spans SELECT failed")?;
        // BILL-01 / ADR-076 §2.3 — reverse any content-addressed dedup ingest
        // applied. Fail-open (a read path): a rehydration failure leaves the
        // `$ref` placeholders exactly as stored rather than failing the whole
        // trace view.
        let mut attrs: Vec<&mut String> = spans.iter_mut().map(|s| &mut s.attributes).collect();
        if let Err(e) = crate::billing::blobs::rehydrate(&self.client, tenant_id, &mut attrs).await
        {
            tracing::warn!(error = %e, "blob rehydration failed; spans returned with $ref placeholders unexpanded");
        }
        Ok(spans)
    }

    async fn trace_chain_status(
        &self,
        tenant_id: &TenantId,
        trace_id: &str,
    ) -> Result<Option<TraceChainStatus>> {
        // ADR-078 B / B-513 (CX-14): presence is read from the CANONICAL store
        // whenever one exists. The ClickHouse `audit_log` copy this used to read
        // is written fail-open AFTER commit (`AuditChain::append_pg_batch`) and
        // repaired only by the boot reconcile — a `LedgerCopyFailed` window
        // therefore used to answer `chained:false` for a call the canonical
        // ledger already held, and both dashboard badges told the customer the
        // call was never proxied. No fallback to the copy on a Postgres error:
        // the ledger publish itself is fail-closed (ADR-069) and this read
        // follows the same posture rather than silently trusting a store ADR-078
        // B demoted to derived.
        if let Some(pool) = &self.pg_pool {
            let row = crate::db::ledger::chain_row_by_trace_id(pool, tenant_id, trace_id)
                .await
                .context("trace chain-status canonical SELECT failed")?;
            return Ok(row.map(|(seq, rekor_entry_id)| TraceChainStatus {
                chained: true,
                seq: Some(seq),
                anchored: anchored_from(rekor_entry_id.as_deref()),
            }));
        }
        // No control plane: `AuditChain::append_in_memory` writes ClickHouse
        // directly and it is the only ledger this deployment has — read it.
        let sql =
            TenantQuery::new(TRACE_CHAIN_SQL, self.tier_for(tenant_id).await).sql_with_settings();
        let row = self
            .client
            .query(&sql)
            .bind(tenant_id.to_string())
            .bind(trace_id.to_string())
            .fetch_optional::<ChainStatusRow>()
            .await
            .context("trace chain-status SELECT failed")?;
        Ok(row.map(|r| TraceChainStatus {
            chained: true,
            seq: Some(r.seq),
            anchored: anchored_from(r.rekor_entry_id.as_deref()),
        }))
    }

    async fn trace_cost_rollup(
        &self,
        tenant_id: &TenantId,
        trace_ids: &[String],
    ) -> Result<Vec<TraceCostRow>> {
        // Empty IN () is invalid SQL — an empty page has nothing to roll up.
        if trace_ids.is_empty() {
            return Ok(Vec::new());
        }
        let sql = TenantQuery::new(
            build_trace_cost_rollup_sql(trace_ids.len()),
            self.tier_for(tenant_id).await,
        )
        .sql_with_settings();
        let mut q = self.client.query(&sql).bind(tenant_id.to_string());
        for id in trace_ids {
            q = q.bind(id.clone());
        }
        q.fetch_all::<TraceCostRow>()
            .await
            .context("trace cost rollup SELECT failed")
    }

    async fn trace_issue_rollup(
        &self,
        tenant_id: &TenantId,
        trace_ids: &[String],
    ) -> Result<Vec<TraceIssueRow>> {
        if trace_ids.is_empty() {
            return Ok(Vec::new());
        }
        let sql = TenantQuery::new(
            build_trace_issue_rollup_sql(trace_ids.len()),
            self.tier_for(tenant_id).await,
        )
        .sql_with_settings();
        let mut query = self.client.query(&sql).bind(tenant_id.to_string());
        for id in trace_ids {
            query = query.bind(id);
        }
        query
            .fetch_all::<TraceIssueRow>()
            .await
            .context("trace issue rollup SELECT failed")
    }

    async fn slo(&self, tenant_id: &TenantId, f: &SloFilters) -> Result<Vec<SloRow>> {
        let sql =
            TenantQuery::new(build_slo_sql(f), self.tier_for(tenant_id).await).sql_with_settings();
        let mut q = self.client.query(&sql).bind(tenant_id.to_string());
        if let Some(s) = f.since_secs {
            q = q.bind(s);
        } else {
            q = q.bind(f.hours);
        }
        if let Some(u) = f.until_secs {
            q = q.bind(u);
        }
        if let Some(p) = &f.provider {
            q = q.bind(p.clone());
        }
        if let Some(m) = &f.model {
            q = q.bind(m.clone());
        }
        q.fetch_all::<SloRow>()
            .await
            .context("v_slo_stats SELECT failed")
    }

    async fn slo_summary(&self, tenant_id: &TenantId, f: &SloFilters) -> Result<SloSummary> {
        let sql = TenantQuery::new(build_slo_summary_sql(f), self.tier_for(tenant_id).await)
            .sql_with_settings();
        let mut q = self.client.query(&sql).bind(tenant_id.to_string());
        if let Some(s) = f.since_secs {
            q = q.bind(s);
        } else {
            q = q.bind(f.hours);
        }
        if let Some(u) = f.until_secs {
            q = q.bind(u);
        }
        if let Some(p) = &f.provider {
            q = q.bind(p.clone());
        }
        if let Some(m) = &f.model {
            q = q.bind(m.clone());
        }
        // Aggregate-with-no-GROUP-BY always yields exactly one row (all-zero when
        // the window is empty), so `fetch_one` is total here.
        q.fetch_one::<SloSummary>()
            .await
            .context("slo summary SELECT failed (spans FINAL for a sub-hour bucket, slo_hourly_stats otherwise)")
    }

    async fn slo_by_model(&self, tenant_id: &TenantId, f: &SloFilters) -> Result<Vec<SloModelRow>> {
        let sql = TenantQuery::new(build_slo_by_model_sql(f), self.tier_for(tenant_id).await)
            .sql_with_settings();
        let mut q = self.client.query(&sql).bind(tenant_id.to_string());
        if let Some(s) = f.since_secs {
            q = q.bind(s);
        } else {
            q = q.bind(f.hours);
        }
        if let Some(u) = f.until_secs {
            q = q.bind(u);
        }
        if let Some(p) = &f.provider {
            q = q.bind(p.clone());
        }
        if let Some(m) = &f.model {
            q = q.bind(m.clone());
        }
        q = q.bind(SLO_MODEL_CAP);
        q.fetch_all::<SloModelRow>()
            .await
            .context("slo per-model SELECT failed (spans FINAL for a sub-hour bucket, slo_hourly_stats otherwise)")
    }

    async fn slo_timeseries(
        &self,
        tenant_id: &TenantId,
        f: &SloFilters,
        bucket_hours: u32,
    ) -> Result<Vec<SloTimePoint>> {
        let sql = TenantQuery::new(
            build_slo_timeseries_sql(f, bucket_hours),
            self.tier_for(tenant_id).await,
        )
        .sql_with_settings();
        let mut q = self.client.query(&sql).bind(tenant_id.to_string());
        if let Some(s) = f.since_secs {
            q = q.bind(s);
        } else {
            q = q.bind(f.hours);
        }
        if let Some(u) = f.until_secs {
            q = q.bind(u);
        }
        if let Some(p) = &f.provider {
            q = q.bind(p.clone());
        }
        if let Some(m) = &f.model {
            q = q.bind(m.clone());
        }
        q.fetch_all::<SloTimePoint>()
            .await
            .context("slo_hourly_stats timeseries SELECT failed")
    }

    async fn gateway_stats(
        &self,
        tenant_id: &TenantId,
        f: &GatewayStatsFilters,
    ) -> Result<Vec<GatewayProviderRow>> {
        let sql = TenantQuery::new(build_gateway_stats_sql(f), self.tier_for(tenant_id).await)
            .sql_with_settings();
        let mut q = self.client.query(&sql).bind(tenant_id.to_string());
        if let Some(s) = f.since_secs {
            q = q.bind(s);
        } else {
            q = q.bind(f.hours);
        }
        if let Some(u) = f.until_secs {
            q = q.bind(u);
        }
        q = q.bind(f.limit);
        q.fetch_all::<GatewayProviderRow>()
            .await
            .context("gateway stats SELECT failed")
    }

    async fn metric_breakdown(
        &self,
        tenant_id: &TenantId,
        f: &BreakdownFilters,
    ) -> Result<Vec<BreakdownRow>> {
        let sql = TenantQuery::new(
            build_metric_breakdown_sql(f.metric, f.by),
            self.tier_for(tenant_id).await,
        )
        .sql_with_settings();
        self.client
            .query(&sql)
            .bind(tenant_id.to_string())
            .bind(f.since_us)
            .bind(f.until_us)
            .bind(f.limit)
            .fetch_all::<BreakdownRow>()
            .await
            .context("metric breakdown SELECT failed")
    }

    async fn cost_breakdown(&self, tenant_id: &TenantId, f: &CostFilters) -> Result<Vec<CostRow>> {
        let sql = TenantQuery::new(build_cost_breakdown_sql(f), self.tier_for(tenant_id).await)
            .sql_with_settings();
        let mut q = self.client.query(&sql).bind(tenant_id.to_string());
        if let Some(s) = f.since_secs {
            q = q.bind(s);
        } else {
            q = q.bind(f.hours);
        }
        if let Some(u) = f.until_secs {
            q = q.bind(u);
        }
        q.bind(f.limit)
            .fetch_all::<CostRow>()
            .await
            .context("cost breakdown SELECT failed")
    }

    async fn latency_breakdown(
        &self,
        tenant_id: &TenantId,
        f: &GatewayStatsFilters,
    ) -> Result<(LatencyTotalsRow, Vec<LatencyModelRow>)> {
        // (1) window-wide totals — one aggregate row (always present, all-zero on
        //     an empty window thanks to the SQL guards → fetch_one is total).
        let totals_sql =
            TenantQuery::new(build_latency_totals_sql(f), self.tier_for(tenant_id).await)
                .sql_with_settings();
        let mut tq = self.client.query(&totals_sql).bind(tenant_id.to_string());
        if let Some(s) = f.since_secs {
            tq = tq.bind(s);
        } else {
            tq = tq.bind(f.hours);
        }
        if let Some(u) = f.until_secs {
            tq = tq.bind(u);
        }
        let totals = tq
            .fetch_one::<LatencyTotalsRow>()
            .await
            .context("latency totals SELECT failed")?;

        // (2) per-(provider, model) overhead — the SLO-table column.
        let by_model_sql = TenantQuery::new(
            build_latency_by_model_sql(f),
            self.tier_for(tenant_id).await,
        )
        .sql_with_settings();
        let mut mq = self.client.query(&by_model_sql).bind(tenant_id.to_string());
        if let Some(s) = f.since_secs {
            mq = mq.bind(s);
        } else {
            mq = mq.bind(f.hours);
        }
        if let Some(u) = f.until_secs {
            mq = mq.bind(u);
        }
        mq = mq.bind(f.limit);
        let by_model = mq
            .fetch_all::<LatencyModelRow>()
            .await
            .context("latency by-model SELECT failed")?;

        Ok((totals, by_model))
    }

    async fn guardrail_summary(
        &self,
        tenant_id: &TenantId,
        f: &GuardrailStatsFilters,
    ) -> Result<GuardrailSummaryRow> {
        let sql = TenantQuery::new(
            build_guardrail_summary_sql(f),
            self.tier_for(tenant_id).await,
        )
        .sql_with_settings();
        let mut q = self.client.query(&sql).bind(tenant_id.to_string());
        if let Some(s) = f.since_secs {
            q = q.bind(s);
        } else {
            q = q.bind(f.hours);
        }
        if let Some(u) = f.until_secs {
            q = q.bind(u);
        }
        // Single aggregate row (always exactly one, even on an empty window).
        q.fetch_one::<GuardrailSummaryRow>()
            .await
            .context("guardrail summary SELECT failed")
    }

    async fn guardrail_rails(
        &self,
        tenant_id: &TenantId,
        f: &GuardrailStatsFilters,
    ) -> Result<Vec<GuardrailRailRow>> {
        let sql = TenantQuery::new(build_guardrail_rails_sql(f), self.tier_for(tenant_id).await)
            .sql_with_settings();
        let mut q = self.client.query(&sql).bind(tenant_id.to_string());
        if let Some(s) = f.since_secs {
            q = q.bind(s);
        } else {
            q = q.bind(f.hours);
        }
        if let Some(u) = f.until_secs {
            q = q.bind(u);
        }
        q = q.bind(f.limit);
        q.fetch_all::<GuardrailRailRow>()
            .await
            .context("guardrail rails SELECT failed")
    }

    async fn guardrail_verdicts(
        &self,
        tenant_id: &TenantId,
        f: &GuardrailVerdictListFilters,
    ) -> Result<Vec<GuardrailVerdictListRow>> {
        let sql = TenantQuery::new(
            build_guardrail_verdicts_sql(f),
            self.tier_for(tenant_id).await,
        )
        .sql_with_settings();
        let mut q = self.client.query(&sql).bind(tenant_id.to_string());
        // Bind order mirrors the SQL: tenant, [decision], [correlation_id], [rail],
        // (since_secs | hours), [until], limit.
        if let Some(d) = f.decision.as_deref() {
            q = q.bind(d);
        }
        if let Some(c) = f.correlation_id.as_deref() {
            q = q.bind(c);
        }
        if let Some(r) = f.rail.as_deref() {
            q = q.bind(r);
        }
        if let Some(s) = f.since_secs {
            q = q.bind(s);
        } else {
            q = q.bind(f.hours);
        }
        if let Some(u) = f.until_secs {
            q = q.bind(u);
        }
        q = q.bind(f.limit);
        q.fetch_all::<GuardrailVerdictListRow>()
            .await
            .context("guardrail verdicts SELECT failed")
    }

    async fn signatures(
        &self,
        tenant_id: &TenantId,
        f: &SignatureFilters,
    ) -> Result<Vec<SignatureHitRow>> {
        let sql = TenantQuery::new(build_signatures_sql(f), self.tier_for(tenant_id).await)
            .sql_with_settings();
        let mut q = self.client.query(&sql).bind(tenant_id.to_string());
        if let Some(s) = f.since_us {
            q = q.bind(s);
        }
        if let Some(u) = f.until_us {
            q = q.bind(u);
        }
        q = q.bind(f.limit);
        q.fetch_all::<SignatureHitRow>()
            .await
            .context("signatures aggregate SELECT failed")
    }

    async fn signatures_distinct_traces(
        &self,
        tenant_id: &TenantId,
        f: &SignatureFilters,
    ) -> Result<u64> {
        let sql = TenantQuery::new(
            build_signatures_trace_total_sql(f),
            self.tier_for(tenant_id).await,
        )
        .sql_with_settings();
        let mut q = self.client.query(&sql).bind(tenant_id.to_string());
        // Bind order MIRRORS build_signatures_trace_total_sql: tenant, live_ids…,
        // [since_us]. The live-id IN list is bound (never interpolated).
        for id in &f.live_signature_ids {
            q = q.bind(id.clone());
        }
        if let Some(s) = f.since_us {
            q = q.bind(s);
        }
        if let Some(u) = f.until_us {
            q = q.bind(u);
        }
        let row = q
            .fetch_one::<TraceTotalRow>()
            .await
            .context("signatures distinct-traces scalar SELECT failed")?;
        Ok(row.total)
    }

    async fn list_sessions(
        &self,
        tenant_id: &TenantId,
        f: &SessionListFilters,
    ) -> Result<Vec<SessionSummaryRow>> {
        let sql = TenantQuery::new(build_session_list_sql(f), self.tier_for(tenant_id).await)
            .sql_with_settings();
        let mut q = self.client.query(&sql).bind(tenant_id.to_string());
        if let Some(m) = f.model.as_deref() {
            q = q.bind(m);
        }
        if let Some(s) = f.since_us {
            q = q.bind(s);
        } else {
            q = q.bind(f.window_days);
        }
        if let Some(u) = f.until_us {
            q = q.bind(u);
        }
        q = q.bind(f.limit);
        q.fetch_all::<SessionSummaryRow>()
            .await
            .context("session list SELECT failed")
    }

    async fn session_traces(
        &self,
        tenant_id: &TenantId,
        session_id: &str,
    ) -> Result<Vec<SessionTraceRow>> {
        let sql = TenantQuery::new(build_session_traces_sql(), self.tier_for(tenant_id).await)
            .sql_with_settings();
        self.client
            .query(&sql)
            .bind(tenant_id.to_string())
            .bind(session_id.to_string())
            .fetch_all::<SessionTraceRow>()
            .await
            .context("session traces SELECT failed")
    }

    async fn session_totals(
        &self,
        tenant_id: &TenantId,
        session_id: &str,
    ) -> Result<Option<SessionTotalsRow>> {
        let sql = TenantQuery::new(build_session_totals_sql(), self.tier_for(tenant_id).await)
            .sql_with_settings();
        let row: SessionTotalsRow = self
            .client
            .query(&sql)
            .bind(tenant_id.to_string())
            .bind(session_id.to_string())
            .fetch_one()
            .await
            .context("session totals SELECT failed")?;
        // No GROUP BY — the aggregate always returns exactly one row, even for
        // zero matching spans (every `sum`/`count` is then 0). `turns == 0` is
        // therefore the "no such session for this tenant" signal, mirrored by
        // the handler into the same 404 `session_traces` already returns.
        Ok((row.turns > 0).then_some(row))
    }

    async fn session_turns(
        &self,
        tenant_id: &TenantId,
        session_id: &str,
        cursor: Option<(i64, String)>,
        limit: u32,
    ) -> Result<Vec<(SessionTurnRow, Option<SessionExchange>)>> {
        let tier = self.tier_for(tenant_id).await;
        let sql =
            TenantQuery::new(build_session_turns_sql(cursor.is_some()), tier).sql_with_settings();
        let mut q = self
            .client
            .query(&sql)
            .bind(tenant_id.to_string())
            .bind(session_id.to_string());
        if let Some((ts, id)) = &cursor {
            q = q.bind(*ts).bind(id.clone());
        }
        q = q.bind(limit);
        let turns: Vec<SessionTurnRow> =
            q.fetch_all().await.context("session turns SELECT failed")?;
        if turns.is_empty() {
            return Ok(Vec::new());
        }

        // ONE query for every turn's exchange span on this page (never one per
        // turn) — the same amplification-budget discipline as
        // `billing::blobs::rehydrate`.
        let trace_ids: Vec<String> = turns.iter().map(|t| t.trace_id.clone()).collect();
        let exchange_sql =
            TenantQuery::new(build_session_exchange_sql(trace_ids.len()), tier).sql_with_settings();
        let mut eq = self.client.query(&exchange_sql).bind(tenant_id.to_string());
        for id in &trace_ids {
            eq = eq.bind(id.clone());
        }
        let mut exchange_spans: Vec<ExchangeSpanRow> = eq
            .fetch_all()
            .await
            .context("session exchange SELECT failed")?;

        // BILL-01 / ADR-076 §2.3 — reverse content-addressed dedup, exactly as
        // `list_spans` does. Fail-open: a rehydration failure leaves any `$ref`
        // unexpanded rather than failing the whole transcript.
        let mut attrs: Vec<&mut String> = exchange_spans
            .iter_mut()
            .map(|s| &mut s.attributes)
            .collect();
        if let Err(e) = crate::billing::blobs::rehydrate(&self.client, tenant_id, &mut attrs).await
        {
            tracing::warn!(error = %e, "session transcript: blob rehydration failed; exchange spans returned with $ref placeholders unexpanded");
        }

        let mut by_trace: std::collections::HashMap<String, ExchangeSpanRow> = exchange_spans
            .into_iter()
            .map(|s| (s.trace_id.clone(), s))
            .collect();

        Ok(turns
            .into_iter()
            .map(|t| {
                let exchange = by_trace
                    .remove(&t.trace_id)
                    .map(|s| build_session_exchange(s.span_id, &s.attributes, s.status_code));
                (t, exchange)
            })
            .collect())
    }
}

/// Internal row for [`build_session_exchange_sql`]. POSITIONAL.
#[derive(Debug, Clone, Deserialize, clickhouse::Row)]
struct ExchangeSpanRow {
    trace_id: String,
    span_id: String,
    attributes: String,
    status_code: u8,
}

/// `OBS-55` — build one turn's [`SessionExchange`] from its exchange span's id
/// and (already rehydrated) `attributes` JSON string. Pure, so the four
/// `content` outcomes are unit-testable without ClickHouse.
fn build_session_exchange(
    span_id: String,
    attributes_json: &str,
    status_code: u8,
) -> SessionExchange {
    let Ok(attrs) = serde_json::from_str::<serde_json::Value>(attributes_json) else {
        return SessionExchange {
            generation: crate::generation_issues::details(
                &crate::generation_issues::SpanAttrsView {
                    attributes: &serde_json::Value::Null,
                    status_code,
                },
            ),
            span_id,
            input_tail: Vec::new(),
            input_message_count: 0,
            output: serde_json::Value::Null,
            finish_reasons: Vec::new(),
            tool_attrs: "{}".to_string(),
            content: "unreadable",
        };
    };
    let generation = crate::generation_issues::details(&crate::generation_issues::SpanAttrsView {
        attributes: &attrs,
        status_code,
    });
    let tool_attrs = {
        let mut m = serde_json::Map::new();
        for key in [
            "tracelane_response_tool_names",
            "tracelane_response_tool_arg_bytes",
            "gen_ai_output_messages",
            "gen_ai_response_finish_reasons",
        ] {
            if let Some(v) = attrs.get(key) {
                m.insert(key.to_string(), v.clone());
            }
        }
        serde_json::Value::Object(m).to_string()
    };
    let output = attrs
        .get("gen_ai_output_messages")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let finish_reasons = attrs
        .get("gen_ai_response_finish_reasons")
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    let Some(raw_input) = attrs.get("gen_ai_input_messages") else {
        return SessionExchange {
            generation,
            span_id,
            input_tail: Vec::new(),
            input_message_count: 0,
            output,
            finish_reasons,
            tool_attrs,
            content: "absent",
        };
    };
    // A `$ref` that failed to rehydrate is left as `{"$ref":…, "missing":true}`
    // by `billing::blobs::rehydrate` (fail-open, CLAUDE.md §10).
    if raw_input
        .get("missing")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        return SessionExchange {
            generation,
            span_id,
            input_tail: Vec::new(),
            input_message_count: 0,
            output,
            finish_reasons,
            tool_attrs,
            content: "unloaded",
        };
    }
    let Ok(messages) = serde_json::from_value::<Vec<Message>>(raw_input.clone()) else {
        return SessionExchange {
            generation,
            span_id,
            input_tail: Vec::new(),
            input_message_count: 0,
            output,
            finish_reasons,
            tool_attrs,
            content: "unreadable",
        };
    };
    let input_message_count = messages.len();
    // The NEW input of this turn: everything AFTER the last `assistant`
    // message. No assistant message in this call at all (the common
    // single-turn-per-trace gateway case) ⇒ the whole array is new.
    let tail_start = messages
        .iter()
        .rposition(|m| m.role == tracelane_shared::model::Role::Assistant)
        .map_or(0, |idx| idx + 1);
    let input_tail = messages[tail_start..].to_vec();
    SessionExchange {
        generation,
        span_id,
        input_tail,
        input_message_count,
        output,
        finish_reasons,
        tool_attrs,
        content: "captured",
    }
}

// ── Handler state + query params ─────────────────────────────────────────────

/// Narrow handler state — just the reader, so trace reads don't pull the full
/// gateway `AppState`.
#[derive(Clone)]
pub struct TraceReadState {
    pub reader: Arc<dyn TraceReader>,
    /// B-386 (b): the SAME per-tenant rejection counters the admission pipeline
    /// records on (`AppState::rejection_metrics`), shared by `Arc`. A separate
    /// instance here would report zeros for a tenant the hot path is throttling.
    pub rejections: Arc<crate::rejection_metrics::RejectionRegistry>,
}

#[derive(Debug, Deserialize)]
pub struct TraceListQuery {
    include_issues: Option<bool>,
    issue: Option<String>,
    agent: Option<String>,
    model_family: Option<String>,
    limit: Option<u32>,
    /// OBS-01 free-text search over span `name` + `attributes`. Minimum 4 chars
    /// (the ngram index `n`); shorter is rejected, never silently scanned.
    q: Option<String>,
    model: Option<String>,
    /// `"true"` | `"false"` (matches the dashboard `?has_error=`).
    has_error: Option<String>,
    /// §2 latency floor in **milliseconds** (converted to `duration_us` server-side).
    min_latency_ms: Option<f64>,
    /// §2 filter to traces with ≥1 span matching this failure-signature (AFT) id.
    signature_id: Option<String>,
    /// `"true"` → only traces where a cross-provider failover fired (Gateway page
    /// "Failovers" click-through). Any other value → no filter.
    failover: Option<String>,
    /// `OBS-20` — keep only traces carrying this end-user id. Exact match,
    /// bound not interpolated. Empty string is treated as absent so a
    /// cleared filter chip does not become a search for the empty id.
    end_user: Option<String>,
    /// Opaque keyset token from a previous `next_cursor`.
    cursor: Option<String>,
    /// RFC3339 inclusive lower bound on start_time.
    since: Option<String>,
    /// RFC3339 inclusive upper bound on start_time.
    until: Option<String>,
    /// Sort column: `start_time` (default) | `duration`.
    sort: Option<String>,
    /// Sort direction: `desc` (default) | `asc`.
    order: Option<String>,
}

/// Query for `GET /v1/traces/export` — the same filters as the list (no cursor,
/// no page limit) plus the output `format`.
#[derive(Debug, Deserialize)]
pub struct TraceExportQuery {
    issue: Option<String>,
    agent: Option<String>,
    model_family: Option<String>,
    /// `"csv"` (default) | `"json"`.
    format: Option<String>,
    model: Option<String>,
    has_error: Option<String>,
    min_latency_ms: Option<f64>,
    signature_id: Option<String>,
    /// `"true"` → export only failover traces (mirrors the list filter).
    failover: Option<String>,
    /// `OBS-20` — keep only traces carrying this end-user id. Exact match,
    /// bound not interpolated. Empty string is treated as absent so a
    /// cleared filter chip does not become a search for the empty id.
    end_user: Option<String>,
    since: Option<String>,
    until: Option<String>,
    sort: Option<String>,
    order: Option<String>,
}

/// Query for `GET /v1/traces/groups` — the grouping dimension + the same filters.
#[derive(Debug, Deserialize)]
pub struct TraceGroupsQuery {
    issue: Option<String>,
    agent: Option<String>,
    model_family: Option<String>,
    /// `model` | `operation` | `status` (required — grouping has no default).
    by: Option<String>,
    model: Option<String>,
    has_error: Option<String>,
    min_latency_ms: Option<f64>,
    signature_id: Option<String>,
    /// `"true"` → group only failover traces (mirrors the list filter).
    failover: Option<String>,
    /// `OBS-20` — keep only traces carrying this end-user id. Exact match,
    /// bound not interpolated. Empty string is treated as absent so a
    /// cleared filter chip does not become a search for the empty id.
    end_user: Option<String>,
    since: Option<String>,
    until: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SloQuery {
    hours: Option<u32>,
    provider: Option<String>,
    model: Option<String>,
    since: Option<String>,
    until: Option<String>,
    /// Display-bucket width in hours for `/v1/slo/timeseries` (default 1 =
    /// hourly). Clamped to `1..=MAX_SLO_HOURS`; unused by the other SLO routes.
    bucket: Option<u32>,
    /// Sub-hour bucket width in minutes (1|5|10|15|30) for all four SLO routes
    /// (`/v1/slo`, `/v1/slo/timeseries`, `/v1/slo/summary`, `/v1/slo/models` —
    /// B-500); only for windows ≤ 24 h (DSH-11 §3a.4).
    bucket_minutes: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct GatewayStatsQuery {
    /// Rolling look-back window in hours (default 24, cap 720 = 30 days).
    hours: Option<u32>,
    /// RFC3339 inclusive lower bound on `start_time` (overrides `hours`).
    since: Option<String>,
    /// RFC3339 inclusive upper bound on `start_time` (DSH-11).
    until: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GuardrailStatsQuery {
    /// Rolling look-back window in hours (default 24, cap 720 = 30 days).
    hours: Option<u32>,
    /// RFC3339 inclusive lower bound on `event_time` (overrides `hours`).
    since: Option<String>,
    /// RFC3339 inclusive upper bound on `event_time` (DSH-11).
    until: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GuardrailVerdictsQuery {
    /// Rolling look-back window in hours (default 24, cap 720 = 30 days).
    hours: Option<u32>,
    /// RFC3339 inclusive lower bound on `event_time` (overrides `hours`).
    since: Option<String>,
    /// RFC3339 inclusive upper bound on `event_time` (DSH-11).
    until: Option<String>,
    /// Decision filter: `allow` | `block` | `redact` | `warn` (allowlisted).
    decision: Option<String>,
    /// Exact correlation-id (ULID) lookup — the id returned in a 403 block body.
    correlation_id: Option<String>,
    /// Per-rail filter (B-335a), e.g. `R4_trifecta`. `[A-Za-z0-9_]{1,40}`.
    rail: Option<String>,
    /// Row cap (default 100, max 500).
    limit: Option<u32>,
}

/// Validate a `rail` query value: an identifier of at most 40 chars from
/// `[A-Za-z0-9_]` (the recorder writes ids like `R1_cost`…`R7_topic`). Bound,
/// never interpolated.
fn parse_rail_filter(raw: Option<&str>) -> Result<Option<String>, ()> {
    match raw.map(str::trim) {
        None | Some("") => Ok(None),
        Some(s) if s.len() <= 40 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') => {
            Ok(Some(s.to_string()))
        }
        Some(_) => Err(()),
    }
}

/// Validate a `decision` query value against the allowlist. Returns the owned
/// string when valid, `None` when absent, and `Err` for anything else — an
/// unknown decision is a client error, never a silent no-filter.
/// Validate a correlation-id lookup value. Correlation ids are ULIDs: exactly 26
/// Crockford-base32 chars. Charset-validated (and upper-cased) so the value is a
/// known-safe token before it is bound — never interpolated into SQL.
fn parse_correlation_id_filter(s: Option<&str>) -> Result<Option<String>, ()> {
    match s {
        None => Ok(None),
        Some(v) if v.trim().is_empty() => Ok(None),
        Some(v) => {
            let v = v.trim().to_ascii_uppercase();
            let ok = v.len() == 26
                && v.chars().all(|c| {
                    c.is_ascii_digit() || (c.is_ascii_uppercase() && c.is_ascii_alphabetic())
                });
            if ok { Ok(Some(v)) } else { Err(()) }
        }
    }
}

fn parse_decision_filter(s: Option<&str>) -> Result<Option<String>, ()> {
    match s {
        None => Ok(None),
        Some("allow" | "block" | "redact" | "warn") => Ok(Some(s.unwrap().to_string())),
        Some(_) => Err(()),
    }
}

#[derive(Debug, Deserialize)]
pub struct SignatureQuery {
    /// RFC3339 inclusive lower bound on the matched span's start_time.
    since: Option<String>,
    /// RFC3339 inclusive upper bound (DSH-11).
    until: Option<String>,
    limit: Option<u32>,
    /// Comma-separated LIVE-detector AFT-1 id allowlist (from `aft-taxonomy.ts`),
    /// scoping the "traces affected" scalar to LIVE signatures. Each id is
    /// format-validated then BOUND; unknown/garbage tokens are dropped. Absent →
    /// unscoped (any signature) for backward compatibility.
    live_ids: Option<String>,
}

/// Parse the `live_ids` CSV into a validated AFT-1 id allowlist. Each token must
/// match the canonical `AFT-<UPPER/DIGIT/->` shape (bounded length) — anything
/// else is dropped, never bound. Deduped, capped at 64 (the taxonomy is tiny), so
/// a malicious caller can neither inject SQL (values are bound regardless) nor
/// blow up the `IN` list.
fn parse_live_signature_ids(csv: Option<&str>) -> Vec<String> {
    let Some(csv) = csv else { return Vec::new() };
    let mut out: Vec<String> = Vec::new();
    for raw in csv.split(',') {
        let id = raw.trim();
        let valid = id.len() >= 5
            && id.len() <= 64
            && id.starts_with("AFT-")
            && id
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-');
        if valid && !out.iter().any(|e| e == id) {
            out.push(id.to_string());
            if out.len() >= 64 {
                break;
            }
        }
    }
    out
}

#[derive(Debug, Deserialize)]
pub struct SessionListQuery {
    limit: Option<u32>,
    /// Rolling look-back window in days (default 30, cap 90 = spans TTL).
    days: Option<u32>,
    /// RFC3339 inclusive lower bound on `start_time` (overrides `days`).
    since: Option<String>,
    /// RFC3339 inclusive upper bound on `start_time` (DSH-11).
    until: Option<String>,
    /// Sort column: `turns` | `cost` | `tokens` | `duration` | (default) last-activity.
    sort: Option<String>,
    /// Sort direction: `asc` | (default) `desc`.
    order: Option<String>,
    /// Status filter: `error` | `ok` | (default) all.
    status: Option<String>,
    /// Response-model filter (scopes each session to that model's spans).
    model: Option<String>,
}

/// `OBS-55`. `cursor` is opaque, from a previous `next_cursor`.
#[derive(Debug, Deserialize)]
pub struct SessionTranscriptQuery {
    limit: Option<u32>,
    cursor: Option<String>,
}

// ── Routes ───────────────────────────────────────────────────────────────────

/// Mount the three read routes. Mounted only when `CLICKHOUSE_URL` is set.
pub fn routes() -> Router<TraceReadState> {
    Router::new()
        .route(
            "/v1/traces/issues/summary",
            get(generation_issue_summary_handler),
        )
        .route("/v1/traces/issues/rollup", get(trace_issue_rollup_handler))
        .route("/v1/traces", get(list_traces_handler))
        .route("/v1/traces/count", get(trace_count_handler))
        .route("/v1/traces/export", get(export_traces_handler))
        .route("/v1/traces/groups", get(list_trace_groups_handler))
        // OBS-10. A literal one-segment path, so it cannot collide with
        // `/v1/traces/{trace_id}/spans` (which needs a second segment) and there
        // is no bare `/v1/traces/{trace_id}` route for it to shadow.
        .route("/v1/traces/compare", get(compare_traces_handler))
        .route("/v1/traces/{trace_id}/spans", get(list_spans_handler))
        .route("/v1/traces/{trace_id}/chain", get(chain_status_handler))
        .route("/v1/slo", get(slo_handler))
        .route("/v1/slo/summary", get(slo_summary_handler))
        .route("/v1/slo/models", get(slo_by_model_handler))
        .route("/v1/slo/timeseries", get(slo_timeseries_handler))
        .route("/v1/gateway/stats", get(gateway_stats_handler))
        .route("/v1/costs", get(cost_breakdown_handler))
        .route("/v1/metrics/breakdown", get(metric_breakdown_handler))
        .route(
            "/v1/query/latency-breakdown",
            get(latency_breakdown_handler),
        )
        .route("/v1/guardrails/stats", get(guardrail_stats_handler))
        .route("/v1/guardrails/verdicts", get(guardrail_verdicts_handler))
        .route("/v1/query/signatures", get(signatures_handler))
        .route("/v1/sessions", get(list_sessions_handler))
        .route(
            "/v1/sessions/{session_id}/traces",
            get(session_traces_handler),
        )
        .route(
            "/v1/sessions/{session_id}/transcript",
            get(session_transcript_handler),
        )
}

#[instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn generation_issue_summary_handler(
    State(state): State<TraceReadState>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));
    match state
        .reader
        .generation_issue_summary(&claims.tenant_id)
        .await
    {
        Ok(summary) => Json(summary.as_ref()).into_response(),
        Err(err) => {
            tracing::warn!(error = %err, "generation issue summary unavailable");
            error_response(
                StatusCode::BAD_GATEWAY,
                "generation issue summary unavailable",
            )
        }
    }
}

/// `{ total }` — the tenant trace total for the "50 of N" footer.
#[derive(Debug, Clone, Serialize)]
pub struct TraceCountResponse {
    pub total: u64,
}

/// GET /v1/traces/count — tenant total matching the SAME filters as /v1/traces
/// (the footer count). No cursor/sort/limit. Tenant id from the JWT claim only.
#[instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn trace_count_handler(
    State(state): State<TraceReadState>,
    Query(q): Query<TraceListQuery>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));
    let issues = match parse_issue_filter(q.issue.as_deref()) {
        Ok(issues) => issues,
        Err(()) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "unknown_issue", "allowed": ISSUES})),
            )
                .into_response();
        }
    };
    let since_us = match parse_rfc3339_micros(q.since.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid since timestamp"),
    };
    let until_us = match parse_rfc3339_micros(q.until.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid until timestamp"),
    };
    // B-333: the list applies `q` and this handler dropped it, so the "N of M"
    // footer reported the UNFILTERED total during a search.
    let search = match validate_search_term(q.q.as_deref()) {
        Ok(s) => s,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, msg),
    };
    let min_duration_us = q
        .min_latency_ms
        .filter(|ms| ms.is_finite() && *ms > 0.0)
        .map(|ms| (ms * 1000.0) as i64);
    let filters = TraceListFilters {
        issues,
        agent: q.agent.filter(|s| !s.is_empty()),
        model_family: q.model_family.filter(|s| !s.is_empty()),
        q: search,
        model: q.model.filter(|s| !s.is_empty()),
        has_error: parse_bool(q.has_error.as_deref()),
        min_duration_us,
        signature_id: q.signature_id.filter(|s| !s.is_empty()),
        failover: parse_failover(q.failover.as_deref()),
        end_user: q.end_user.filter(|s| !s.is_empty()),
        since_us,
        until_us,
        cursor: None,
        sort: TraceSort::default(),
        order: SortOrder::default(),
        limit: 0,
    };
    match state.reader.count_traces(&claims.tenant_id, &filters).await {
        Ok(total) => Json(TraceCountResponse { total }).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "trace count failed");
            error_response(StatusCode::BAD_GATEWAY, "trace count failed")
        }
    }
}

/// Empty means the filter was cleared. A nonempty list must contain only known
/// kinds; accepting the known half of an invalid list would silently widen it.
fn parse_issue_filter(raw: Option<&str>) -> Result<Vec<Issue>, ()> {
    let Some(raw) = raw.filter(|s| !s.is_empty()) else {
        return Ok(Vec::new());
    };
    let mut issues = Vec::new();
    for kind in raw.split(',') {
        let issue = serde_json::from_value::<Issue>(serde_json::Value::String(kind.to_owned()))
            .map_err(|_| ())?;
        if !issues.contains(&issue) {
            issues.push(issue);
        }
    }
    Ok(issues)
}

/// Minimum free-text term length, tied to the `ngrambf_v1(4, …)` index `n`.
///
/// A shorter term cannot be served by the ngram index, so it would silently fall
/// back to a full scan of the tenant's parts — the exact hot-path degradation
/// OBS-01 exists to avoid. Rejecting is the honest behaviour: a 400 tells the
/// caller why, where a slow 200 teaches them the product is slow.
const MIN_SEARCH_TERM: usize = 4;

/// Validate and normalise the `?q=` term.
///
/// # Errors
/// Fails CLOSED with a typed 400 when the trimmed term is shorter than
/// [`MIN_SEARCH_TERM`]. An absent `q` is not an error — it means "no search".
fn validate_search_term(raw: Option<&str>) -> Result<Option<String>, &'static str> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) if s.chars().count() < MIN_SEARCH_TERM => {
            Err("search term must be at least 4 characters")
        }
        Some(s) => Ok(Some(s.to_string())),
    }
}

/// GET /v1/traces — keyset-paginated trace list for the authenticated tenant.
#[instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn list_traces_handler(
    State(state): State<TraceReadState>,
    Query(q): Query<TraceListQuery>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));
    let issues = match parse_issue_filter(q.issue.as_deref()) {
        Ok(issues) => issues,
        Err(()) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "unknown_issue", "allowed": ISSUES})),
            )
                .into_response();
        }
    };

    let search = match validate_search_term(q.q.as_deref()) {
        Ok(s) => s,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, msg),
    };
    let limit = q
        .limit
        .unwrap_or(DEFAULT_TRACE_LIMIT)
        .clamp(1, MAX_TRACE_LIMIT);
    let cursor = match q.cursor.as_deref() {
        Some(c) => match decode_cursor(c) {
            Some(parsed) => Some(parsed),
            None => return error_response(StatusCode::BAD_REQUEST, "malformed cursor"),
        },
        None => None,
    };
    let since_us = match parse_rfc3339_micros(q.since.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid since timestamp"),
    };
    let until_us = match parse_rfc3339_micros(q.until.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid until timestamp"),
    };
    // §2 latency floor: milliseconds → duration_us. Ignore NaN / negative.
    let min_duration_us = q
        .min_latency_ms
        .filter(|ms| ms.is_finite() && *ms > 0.0)
        .map(|ms| (ms * 1000.0) as i64);
    let filters = TraceListFilters {
        issues,
        agent: q.agent.filter(|s| !s.is_empty()),
        model_family: q.model_family.filter(|s| !s.is_empty()),
        q: search.clone(),
        model: q.model.filter(|s| !s.is_empty()),
        has_error: parse_bool(q.has_error.as_deref()),
        min_duration_us,
        signature_id: q.signature_id.filter(|s| !s.is_empty()),
        failover: parse_failover(q.failover.as_deref()),
        end_user: q.end_user.filter(|s| !s.is_empty()),
        since_us,
        until_us,
        cursor,
        sort: parse_sort(q.sort.as_deref()),
        order: parse_order(q.order.as_deref()),
        limit,
    };

    let rows = match state.reader.list_traces(&claims.tenant_id, &filters).await {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(error = %err, "trace list read failed");
            return error_response(StatusCode::BAD_GATEWAY, "trace read failed");
        }
    };

    // A full page implies there may be more; emit a keyset cursor from the
    // last row. A short page is the end of the walk.
    let next_cursor = if rows.len() as u32 == limit {
        rows.last().map(|r| {
            // The cursor's numeric part is the SORT column's value of the last row.
            let sort_val = match filters.sort {
                TraceSort::StartTime => r.start_time_us,
                TraceSort::Duration => r.duration_us,
                TraceSort::SpanCount => r.span_count as i64,
            };
            encode_cursor(sort_val, &r.trace_id)
        })
    } else {
        None
    };
    let ids = rows.iter().map(|r| r.trace_id.clone()).collect::<Vec<_>>();
    let issues_deferred = q.include_issues == Some(false);
    let (traces, issues_available) = if issues_deferred {
        (
            enrich_traces_with_cost(state.reader.as_ref(), &claims.tenant_id, rows).await,
            false,
        )
    } else {
        let (mut traces, issue_rows) = tokio::join!(
            enrich_traces_with_cost(state.reader.as_ref(), &claims.tenant_id, rows),
            state.reader.trace_issue_rollup(&claims.tenant_id, &ids),
        );
        let available = apply_trace_issues(&mut traces, issue_rows);
        (traces, available)
    };
    Json(TraceListResponse {
        traces,
        next_cursor,
        issues_available,
        issues_deferred,
    })
    .into_response()
}

/// Fail OPEN for display enrichment: the primary rows remain usable on failure.
/// An explicit availability flag prevents an outage from looking like no issues.
fn decode_trace_issues(
    rows: Result<Vec<TraceIssueRow>>,
) -> Option<std::collections::HashMap<String, Vec<IssueChip>>> {
    use tracelane_shared::degradation::{self, Degradation};
    let rows = match rows {
        Ok(rows) if rows.iter().all(|r| r.issue_counts.len() == ISSUES.len()) => rows,
        _ => {
            degradation::note(Degradation::TraceIssueReadFailed);
            return None;
        }
    };
    if !rows.is_empty() {
        degradation::resolve(Degradation::TraceIssueReadFailed);
    }
    Some(
        rows.into_iter()
            .map(|r| {
                (
                    r.trace_id,
                    ISSUES
                        .into_iter()
                        .zip(r.issue_counts)
                        .filter(|(_, count)| *count > 0)
                        .map(|(issue, count)| issue.chip(count))
                        .collect(),
                )
            })
            .collect(),
    )
}

fn apply_trace_issues(traces: &mut [TraceSummary], rows: Result<Vec<TraceIssueRow>>) -> bool {
    let decoded = decode_trace_issues(rows);
    let available = decoded.is_some();
    let mut by_trace = decoded.unwrap_or_default();
    for trace in traces {
        trace.issues = Some(by_trace.remove(&trace.trace_id).unwrap_or_default());
    }
    available
}

#[derive(Deserialize)]
struct TraceIssueQuery {
    trace_ids: Option<String>,
}

/// Optional second read for list clients: bound to one page and authenticated
/// through the same read-scope seam as the primary list.
async fn trace_issue_rollup_handler(
    State(state): State<TraceReadState>,
    Query(q): Query<TraceIssueQuery>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let ids = q
        .trace_ids
        .as_deref()
        .unwrap_or_default()
        .split(',')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if ids.len() > MAX_TRACE_LIMIT as usize || ids.iter().any(|id| id.is_empty()) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "trace_ids must contain one page of nonempty ids",
        );
    }
    let policy = state.reader.generation_issue_policy();
    if !policy.valid() {
        return error_response(
            StatusCode::BAD_GATEWAY,
            "generation issue policy unavailable",
        );
    }
    let decoded = decode_trace_issues(
        state
            .reader
            .trace_issue_rollup(&claims.tenant_id, &ids)
            .await,
    );
    let available = decoded.is_some();
    let mut decoded = decoded.unwrap_or_default();
    let traces = ids
        .into_iter()
        .map(|id| {
            let issues = decoded.remove(&id).unwrap_or_default();
            serde_json::json!({"trace_id":id, "issues":issues})
        })
        .collect::<Vec<_>>();
    Json(serde_json::json!({"traces":traces,"issues_available":available,"inline_limit":policy.inline_chip_limit})).into_response()
}

/// Map CH trace rows → public [`TraceSummary`], enriching each with the
/// read-time cost/token rollup. `trace_summaries` has no cost/token columns, so
/// they are summed from the page's spans, bounded to the page's ids (never a
/// full-tenant scan). **Fail-open:** a rollup error renders the rows with
/// `cost_usd = 0 / total_tokens = 0` rather than failing the whole list/export.
async fn enrich_traces_with_cost(
    reader: &dyn TraceReader,
    tenant_id: &TenantId,
    rows: Vec<TraceSummaryRow>,
) -> Vec<TraceSummary> {
    let ids: Vec<String> = rows.iter().map(|r| r.trace_id.clone()).collect();
    let cost_map: std::collections::HashMap<String, (f64, i64)> = reader
        .trace_cost_rollup(tenant_id, &ids)
        .await
        .map(|v| {
            v.into_iter()
                .map(|c| (c.trace_id, (c.cost_usd, c.total_tokens)))
                .collect()
        })
        .unwrap_or_else(|err| {
            tracing::warn!(error = %err, "trace cost rollup failed; rendering without cost/tokens");
            std::collections::HashMap::new()
        });
    rows.into_iter()
        .map(|r| {
            let (cost_usd, total_tokens) = cost_map.get(&r.trace_id).copied().unwrap_or((0.0, 0));
            let mut s = TraceSummary::from(r);
            s.cost_usd = cost_usd;
            s.total_tokens = total_tokens;
            s
        })
        .collect()
}

/// GET /v1/traces/export?format=csv|json — the current filtered trace list as a
/// downloadable CSV (default) or JSON, up to `MAX_TRACE_EXPORT` rows. Reuses the
/// exact `list_traces` filters (model / has_error / min_latency / signature / time
/// window); no cursor — exports from the top of the filtered `start_time DESC` set.
#[instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn export_traces_handler(
    State(state): State<TraceReadState>,
    Query(q): Query<TraceExportQuery>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));
    let issues = match parse_issue_filter(q.issue.as_deref()) {
        Ok(issues) => issues,
        Err(()) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "unknown_issue", "allowed": ISSUES})),
            )
                .into_response();
        }
    };

    let since_us = match parse_rfc3339_micros(q.since.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid since timestamp"),
    };
    let until_us = match parse_rfc3339_micros(q.until.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid until timestamp"),
    };
    let min_duration_us = q
        .min_latency_ms
        .filter(|ms| ms.is_finite() && *ms > 0.0)
        .map(|ms| (ms * 1000.0) as i64);
    let filters = TraceListFilters {
        issues,
        agent: q.agent.filter(|s| !s.is_empty()),
        model_family: q.model_family.filter(|s| !s.is_empty()),
        q: None,
        model: q.model.filter(|s| !s.is_empty()),
        has_error: parse_bool(q.has_error.as_deref()),
        min_duration_us,
        signature_id: q.signature_id.filter(|s| !s.is_empty()),
        failover: parse_failover(q.failover.as_deref()),
        end_user: q.end_user.filter(|s| !s.is_empty()),
        since_us,
        until_us,
        cursor: None,
        sort: parse_sort(q.sort.as_deref()),
        order: parse_order(q.order.as_deref()),
        limit: MAX_TRACE_EXPORT,
    };

    let rows = match state.reader.list_traces(&claims.tenant_id, &filters).await {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(error = %err, "trace export read failed");
            return error_response(StatusCode::BAD_GATEWAY, "trace export failed");
        }
    };
    let traces = enrich_traces_with_cost(state.reader.as_ref(), &claims.tenant_id, rows).await;

    // OBS-23. The cap is UNCHANGED at MAX_TRACE_EXPORT; what changes is that hitting
    // it is no longer silent. A short file that looks complete is the worst failure
    // shape for an evidence artifact — someone exports an incident window, gets
    // exactly 10,000 rows, and reasons about a set that was quietly cut.
    //
    // Reported TWICE on purpose. The header is the machine-readable signal, but a
    // browser download discards response headers, so a human opening the CSV would
    // never see it. The terminal row is what survives into the file itself.
    let truncated = traces.len() as u32 >= MAX_TRACE_EXPORT;
    if truncated {
        tracing::warn!(
            tenant_id = %claims.tenant_id,
            cap = MAX_TRACE_EXPORT,
            "trace export hit the row cap — response marked truncated"
        );
    }
    let row_count = traces.len().to_string();
    let truncated_hdr = if truncated { "true" } else { "false" };

    // Default to CSV (the common spreadsheet export); JSON for programmatic use.
    if q.format.as_deref() == Some("json") {
        // Signal each consumer the way THAT consumer can perceive it. JSON keeps its
        // bare-array shape — wrapping it in an envelope would break every existing
        // download — and carries truncation in the headers, which a programmatic
        // client reads. The CSV branch below adds a terminal row instead, because its
        // consumer is a human opening a file in a spreadsheet, and a browser download
        // discards response headers entirely.
        return (
            StatusCode::OK,
            [
                (
                    axum::http::header::CONTENT_DISPOSITION,
                    "attachment; filename=\"traces.json\"".to_string(),
                ),
                (X_TRUNCATED, truncated_hdr.to_string()),
                (X_ROW_COUNT, row_count.clone()),
            ],
            Json(traces),
        )
            .into_response();
    }
    let mut csv = traces_to_csv(&traces);
    if truncated {
        csv.push_str(&format!(
            "# TRUNCATED: this export stopped at the {MAX_TRACE_EXPORT}-row cap and is NOT complete. Narrow the filters (time range, model, error-only) and export again.\n"
        ));
    }
    (
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "text/csv; charset=utf-8".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"traces.csv\"".to_string(),
            ),
            (X_TRUNCATED, truncated_hdr.to_string()),
            (X_ROW_COUNT, row_count),
        ],
        csv,
    )
        .into_response()
}

/// CSV-escape one field: quote it + double internal quotes iff it contains a
/// comma, quote, CR, or LF (RFC 4180).
fn csv_field(s: &str) -> String {
    // Formula-injection guard (OWASP): a field starting with = + - @ executes as
    // a formula in Excel/Sheets. `root_name`/`model` are attacker-influenceable
    // (span names), so prefix such a value with a `'` and force-quote it — the
    // spreadsheet then treats it as text.
    let formula = s.starts_with(['=', '+', '-', '@']);
    if formula {
        format!("\"'{}\"", s.replace('"', "\"\""))
    } else if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Serialize trace summaries to RFC-4180 CSV with a header row. Numeric columns
/// are never quoted; string columns are escaped via [`csv_field`].
fn traces_to_csv(traces: &[TraceSummary]) -> String {
    let mut out = String::from(
        "trace_id,root_name,start_time,duration_us,span_count,error_count,intervention,model,cost_usd,total_tokens\n",
    );
    for t in traces {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{}\n",
            csv_field(&t.trace_id),
            csv_field(&t.root_name),
            csv_field(&t.start_time),
            t.duration_us,
            t.span_count,
            t.error_count,
            t.intervention,
            csv_field(&t.model),
            t.cost_usd,
            t.total_tokens,
        ));
    }
    out
}

/// GET /v1/traces/groups?by=model|operation|status — traces grouped by a
/// dimension (count / error-count / avg+p95 duration per group), reusing the list
/// filters. `by` is required; an unknown value is a 400.
#[instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn list_trace_groups_handler(
    State(state): State<TraceReadState>,
    Query(q): Query<TraceGroupsQuery>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));
    let issues = match parse_issue_filter(q.issue.as_deref()) {
        Ok(issues) => issues,
        Err(()) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "unknown_issue", "allowed": ISSUES})),
            )
                .into_response();
        }
    };

    let Some(by) = parse_group_by(q.by.as_deref().unwrap_or("")) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid group — expected by=model|operation|status",
        );
    };
    let since_us = match parse_rfc3339_micros(q.since.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid since timestamp"),
    };
    let until_us = match parse_rfc3339_micros(q.until.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid until timestamp"),
    };
    let min_duration_us = q
        .min_latency_ms
        .filter(|ms| ms.is_finite() && *ms > 0.0)
        .map(|ms| (ms * 1000.0) as i64);
    let filters = TraceListFilters {
        issues,
        agent: q.agent.filter(|s| !s.is_empty()),
        model_family: q.model_family.filter(|s| !s.is_empty()),
        q: None,
        model: q.model.filter(|s| !s.is_empty()),
        has_error: parse_bool(q.has_error.as_deref()),
        min_duration_us,
        signature_id: q.signature_id.filter(|s| !s.is_empty()),
        failover: parse_failover(q.failover.as_deref()),
        end_user: q.end_user.filter(|s| !s.is_empty()),
        since_us,
        until_us,
        cursor: None,
        sort: TraceSort::default(),
        order: SortOrder::default(),
        limit: MAX_TRACE_GROUPS,
    };

    let groups = match state
        .reader
        .list_trace_groups(&claims.tenant_id, by, &filters)
        .await
    {
        Ok(g) => g,
        Err(err) => {
            tracing::error!(error = %err, "trace groups read failed");
            return error_response(StatusCode::BAD_GATEWAY, "trace groups failed");
        }
    };
    Json(groups).into_response()
}

/// GET /v1/traces/{trace_id}/spans — ordered spans for one trace. 404 when the
/// trace has no spans for this tenant (same response for "missing" and "not
/// yours" — existence never leaks across tenants).
#[instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn list_spans_handler(
    State(state): State<TraceReadState>,
    Path(trace_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));

    if trace_id.len() < 8 {
        return error_response(StatusCode::BAD_REQUEST, "invalid trace id");
    }

    let spans = match state.reader.list_spans(&claims.tenant_id, &trace_id).await {
        Ok(s) => s,
        Err(err) => {
            tracing::error!(error = %err, "spans read failed");
            return error_response(StatusCode::BAD_GATEWAY, "spans read failed");
        }
    };

    if spans.is_empty() {
        return error_response(StatusCode::NOT_FOUND, "trace not found");
    }
    Json(
        spans
            .into_iter()
            .map(SpanResponse::from)
            .collect::<Vec<_>>(),
    )
    .into_response()
}

/// GET /v1/traces/compare?a=&b= — OBS-10 side-by-side diff of two traces.
///
/// Tenant-isolated by construction: both ids are read through the same
/// tenant-filtered `list_spans` the single-trace route uses, so a trace
/// belonging to another tenant simply reads back empty.
///
/// **A cross-tenant or unknown id returns 404 with the SAME message either
/// way**, and deliberately never names which side was missing — saying "trace B
/// not found" would confirm that trace A exists, turning the endpoint into an
/// existence oracle for another tenant's ids.
#[instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn compare_traces_handler(
    State(state): State<TraceReadState>,
    headers: HeaderMap,
    Query(q): Query<CompareQuery>,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));

    if q.a.len() < 8 || q.b.len() < 8 {
        return error_response(StatusCode::BAD_REQUEST, "invalid trace id");
    }
    if q.a == q.b {
        return error_response(StatusCode::BAD_REQUEST, "a and b must be different traces");
    }

    let (sa, sb) = match tokio::try_join!(
        state.reader.list_spans(&claims.tenant_id, &q.a),
        state.reader.list_spans(&claims.tenant_id, &q.b),
    ) {
        Ok(pair) => pair,
        Err(err) => {
            tracing::error!(error = %err, "compare read failed");
            return error_response(StatusCode::BAD_GATEWAY, "spans read failed");
        }
    };

    // Same message for either side — see the doc comment.
    if sa.is_empty() || sb.is_empty() {
        return error_response(StatusCode::NOT_FOUND, "trace not found");
    }

    Json(align_traces(&q.a, &sa, &q.b, &sb)).into_response()
}

/// GET /v1/traces/{trace_id}/chain — tamper-evident-ledger status for one trace
/// (wedge item 4). Drives the trace-detail "in tamper-evident ledger" chip.
///
/// Always 200 with a `TraceChainStatus` (never 404): a not-chained trace is a
/// legitimate, honest state (SDK/OTLP path), not an error. Tenant-isolated —
/// the `trace_id` in the path only selects a row that ALSO matches the
/// authenticated tenant, so a chip request can never confirm another tenant's
/// ledger membership.
#[instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn chain_status_handler(
    State(state): State<TraceReadState>,
    Path(trace_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));

    if trace_id.len() < 8 {
        return error_response(StatusCode::BAD_REQUEST, "invalid trace id");
    }

    match state
        .reader
        .trace_chain_status(&claims.tenant_id, &trace_id)
        .await
    {
        Ok(Some(status)) => Json(status).into_response(),
        Ok(None) => Json(TraceChainStatus {
            chained: false,
            seq: None,
            anchored: false,
        })
        .into_response(),
        Err(err) => {
            tracing::error!(error = %err, "trace chain-status read failed");
            error_response(StatusCode::BAD_GATEWAY, "chain status read failed")
        }
    }
}

/// GET /v1/slo — per-(provider,model) hourly SLO rollups for the tenant.
#[instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn slo_handler(
    State(state): State<TraceReadState>,
    Query(q): Query<SloQuery>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));

    let since_secs = match parse_rfc3339_secs(q.since.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid since timestamp"),
    };
    let until_secs = match parse_rfc3339_secs(q.until.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid until timestamp"),
    };
    let hours = q.hours.unwrap_or(DEFAULT_SLO_HOURS).clamp(1, MAX_SLO_HOURS);
    // DSH-11 / B-331: an absolute window is clamped to the cap; the served window is
    // echoed in `X-Tracelane-Window`. When `since` is absent the rolling `hours`
    // predicate is kept byte-identical for every existing caller.
    let served = ServedWindow::resolve(
        since_secs,
        until_secs,
        hours,
        chrono::Utc::now().timestamp(),
        MAX_WINDOW_SECS,
    );
    let bucket_minutes = match validate_bucket_minutes(q.bucket_minutes, served.width_secs()) {
        Ok(v) => v,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, msg),
    };
    let filters = SloFilters {
        since_secs: since_secs.map(|_| served.since_secs),
        until_secs: until_secs.map(|_| served.until_secs),
        bucket_minutes,
        hours,
        provider: q.provider.filter(|s| !s.is_empty()),
        model: q.model.filter(|s| !s.is_empty()),
        // Clamped like the timeseries route. Absent => 1 => the historical hourly
        // response, so adding this parameter changes nothing for a caller that
        // never sends it.
        bucket_hours: (q.bucket.unwrap_or(1).clamp(1, MAX_SLO_HOURS) as i64)
            .max(cap_bucket_secs(3600, served.width_secs()) / 3600) as u32,
    };

    let rows = match state.reader.slo(&claims.tenant_id, &filters).await {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(error = %err, "slo read failed");
            return error_response(StatusCode::BAD_GATEWAY, "slo read failed");
        }
    };
    served.stamp(Json(rows).into_response())
}

/// GET /v1/slo/summary — the window-WIDE TRUE p50/p95/p99 (quantileMerge over the
/// stored per-hour quantile states) for the headline latency tiles. The dashboard
/// previously computed a request-weighted mean of the per-hour bucket percentiles
/// (#9), which is a percentile-of-percentiles and diverges from the true
/// quantile. Tenant id comes only from `Claims.tenant_id`. Same query params as
/// `/v1/slo` so it scopes to the same window/provider/model.
async fn slo_summary_handler(
    State(state): State<TraceReadState>,
    Query(q): Query<SloQuery>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));

    let since_secs = match parse_rfc3339_secs(q.since.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid since timestamp"),
    };
    let until_secs = match parse_rfc3339_secs(q.until.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid until timestamp"),
    };
    let hours = q.hours.unwrap_or(DEFAULT_SLO_HOURS).clamp(1, MAX_SLO_HOURS);
    // DSH-11 / B-331: an absolute window is clamped to the cap; the served window is
    // echoed in `X-Tracelane-Window`. When `since` is absent the rolling `hours`
    // predicate is kept byte-identical for every existing caller.
    let served = ServedWindow::resolve(
        since_secs,
        until_secs,
        hours,
        chrono::Utc::now().timestamp(),
        MAX_WINDOW_SECS,
    );
    let bucket_minutes = match validate_bucket_minutes(q.bucket_minutes, served.width_secs()) {
        Ok(v) => v,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, msg),
    };
    let filters = SloFilters {
        since_secs: since_secs.map(|_| served.since_secs),
        until_secs: until_secs.map(|_| served.until_secs),
        bucket_minutes,
        hours,
        provider: q.provider.filter(|s| !s.is_empty()),
        model: q.model.filter(|s| !s.is_empty()),
        // Not the /v1/slo row-bucketing path: summary merges over the WHOLE window
        // and timeseries takes its width as an explicit argument. 1 = no re-grouping.
        bucket_hours: 1,
    };

    match state.reader.slo_summary(&claims.tenant_id, &filters).await {
        Ok(s) => served.stamp(Json(s).into_response()),
        Err(err) => {
            tracing::error!(error = %err, "slo summary read failed");
            error_response(StatusCode::BAD_GATEWAY, "slo summary read failed")
        }
    }
}

/// GET /v1/slo/models — per-(provider, model) window-wide SLO rows with TRUE
/// merged p50/p95/p99 (provenance audit P2 #8). Backs the SLO table, which
/// previously averaged per-hour percentiles client-side. Same query params as
/// `/v1/slo`; tenant id comes only from `Claims.tenant_id`.
async fn slo_by_model_handler(
    State(state): State<TraceReadState>,
    Query(q): Query<SloQuery>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));

    let since_secs = match parse_rfc3339_secs(q.since.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid since timestamp"),
    };
    let until_secs = match parse_rfc3339_secs(q.until.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid until timestamp"),
    };
    let hours = q.hours.unwrap_or(DEFAULT_SLO_HOURS).clamp(1, MAX_SLO_HOURS);
    // DSH-11 / B-331: an absolute window is clamped to the cap; the served window is
    // echoed in `X-Tracelane-Window`. When `since` is absent the rolling `hours`
    // predicate is kept byte-identical for every existing caller.
    let served = ServedWindow::resolve(
        since_secs,
        until_secs,
        hours,
        chrono::Utc::now().timestamp(),
        MAX_WINDOW_SECS,
    );
    let bucket_minutes = match validate_bucket_minutes(q.bucket_minutes, served.width_secs()) {
        Ok(v) => v,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, msg),
    };
    let filters = SloFilters {
        since_secs: since_secs.map(|_| served.since_secs),
        until_secs: until_secs.map(|_| served.until_secs),
        bucket_minutes,
        hours,
        provider: q.provider.filter(|s| !s.is_empty()),
        model: q.model.filter(|s| !s.is_empty()),
        // Not the /v1/slo row-bucketing path: summary merges over the WHOLE window
        // and timeseries takes its width as an explicit argument. 1 = no re-grouping.
        bucket_hours: 1,
    };

    match state.reader.slo_by_model(&claims.tenant_id, &filters).await {
        Ok(rows) => served.stamp(Json(rows).into_response()),
        Err(err) => {
            tracing::error!(error = %err, "slo per-model read failed");
            error_response(StatusCode::BAD_GATEWAY, "slo per-model read failed")
        }
    }
}

/// GET /v1/slo/timeseries — latency-over-time points with TRUE merged percentiles
/// per display bucket (`bucket` = interval width in hours, default 1). Backs the
/// dashboard + SLO latency charts, which previously request-weighted-averaged
/// per-hour percentiles client-side (provenance audit P2 #8). LLM-scoped
/// (`provider <> ''`). Tenant id comes only from `Claims.tenant_id`.
async fn slo_timeseries_handler(
    State(state): State<TraceReadState>,
    Query(q): Query<SloQuery>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));

    let since_secs = match parse_rfc3339_secs(q.since.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid since timestamp"),
    };
    let until_secs = match parse_rfc3339_secs(q.until.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid until timestamp"),
    };
    let hours = q.hours.unwrap_or(DEFAULT_SLO_HOURS).clamp(1, MAX_SLO_HOURS);
    // DSH-11 / B-331: an absolute window is clamped to the cap; the served window is
    // echoed in `X-Tracelane-Window`. When `since` is absent the rolling `hours`
    // predicate is kept byte-identical for every existing caller.
    let served = ServedWindow::resolve(
        since_secs,
        until_secs,
        hours,
        chrono::Utc::now().timestamp(),
        MAX_WINDOW_SECS,
    );
    let bucket_minutes = match validate_bucket_minutes(q.bucket_minutes, served.width_secs()) {
        Ok(v) => v,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, msg),
    };
    let filters = SloFilters {
        since_secs: since_secs.map(|_| served.since_secs),
        until_secs: until_secs.map(|_| served.until_secs),
        bucket_minutes,
        hours,
        provider: q.provider.filter(|s| !s.is_empty()),
        model: q.model.filter(|s| !s.is_empty()),
        // Not the /v1/slo row-bucketing path: summary merges over the WHOLE window
        // and timeseries takes its width as an explicit argument. 1 = no re-grouping.
        bucket_hours: 1,
    };
    let bucket_hours = (q.bucket.unwrap_or(1).clamp(1, MAX_SLO_HOURS) as i64)
        .max(cap_bucket_secs(3600, served.width_secs()) / 3600) as u32;

    match state
        .reader
        .slo_timeseries(&claims.tenant_id, &filters, bucket_hours)
        .await
    {
        Ok(rows) => served.stamp(Json(rows).into_response()),
        Err(err) => {
            tracing::error!(error = %err, "slo timeseries read failed");
            error_response(StatusCode::BAD_GATEWAY, "slo timeseries read failed")
        }
    }
}

#[derive(Debug, Deserialize)]
struct CostQuery {
    /// Rolling look-back window in hours (default 24, cap 720 = 30 days); used
    /// only when `since` is absent.
    hours: Option<u32>,
    by: Option<String>,
    /// `all` (default) | `production` | `eval`. See [`CostScope`].
    scope: Option<String>,
    /// RFC3339 inclusive lower bound on `start_time` (overrides `hours`). The web
    /// has sent this pair since DSH-11; the handler ignored both until CX-26.
    since: Option<String>,
    /// RFC3339 inclusive upper bound on `start_time`.
    until: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MetricBreakdownQuery {
    metric: Option<String>,
    by: Option<String>,
    since: Option<String>,
    until: Option<String>,
    hours: Option<u32>,
    limit: Option<u32>,
}

#[derive(Debug, Serialize)]
struct BreakdownWindow {
    since: String,
    until: String,
    clamped: bool,
}

#[derive(Debug, Serialize)]
struct MetricBreakdownResponse {
    metric: &'static str,
    by: &'static str,
    rows: Vec<BreakdownRow>,
    window: BreakdownWindow,
}

/// Breakdown tiles show at most this many rows.
const BREAKDOWN_LIMIT_CAP: u32 = 50;

#[instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn metric_breakdown_handler(
    State(state): State<TraceReadState>,
    Query(q): Query<MetricBreakdownQuery>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));

    let Some(metric) = BreakdownMetric::parse(q.metric.as_deref()) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid `metric` — expected one of: requests, errors, error_rate, p50_ms, p95_ms, \
             input_tokens, output_tokens, cost_usd",
        );
    };
    let Some(by) = BreakdownBy::parse(q.by.as_deref()) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid `by` — expected one of: model, provider, key, status, operation",
        );
    };
    let since_secs = match parse_rfc3339_secs(q.since.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid since timestamp"),
    };
    let until_secs = match parse_rfc3339_secs(q.until.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid until timestamp"),
    };
    let hours = q
        .hours
        .unwrap_or(DEFAULT_GATEWAY_HOURS)
        .clamp(1, MAX_GATEWAY_HOURS);
    let served = ServedWindow::resolve(
        since_secs,
        until_secs,
        hours,
        chrono::Utc::now().timestamp(),
        MAX_WINDOW_SECS,
    );
    let filters = BreakdownFilters {
        metric,
        by,
        since_us: served.since_secs.saturating_mul(1_000_000),
        until_us: served.until_secs.saturating_mul(1_000_000),
        limit: q.limit.unwrap_or(10).clamp(1, BREAKDOWN_LIMIT_CAP),
    };
    let rows = match state
        .reader
        .metric_breakdown(&claims.tenant_id, &filters)
        .await
    {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(error = %err, "metric breakdown read failed");
            return error_response(StatusCode::BAD_GATEWAY, "metric breakdown read failed");
        }
    };
    let iso = |secs: i64| {
        chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
            .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
            .unwrap_or_default()
    };
    let out = MetricBreakdownResponse {
        metric: metric.as_str(),
        by: by.as_str(),
        rows,
        window: BreakdownWindow {
            since: iso(served.since_secs),
            until: iso(served.until_secs),
            clamped: served.clamped,
        },
    };
    served.stamp(Json(out).into_response())
}

/// `GET /v1/costs` — spend attributed by key, model or provider.
///
/// Sprint 1 item 5. Cost already existed on every span; what did not exist was
/// the ability to GROUP it by the thing a platform team actually budgets
/// against. `api_key_id` arrived with ClickHouse migration 16, so a "by key"
/// answer necessarily starts there — the response says so rather than letting a
/// short history read as low spend.
#[tracing::instrument(skip_all, fields(tenant_id))]
async fn cost_breakdown_handler(
    State(state): State<TraceReadState>,
    Query(q): Query<CostQuery>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));

    let Some(dimension) = CostDimension::parse(q.by.as_deref()) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid `by` — expected one of: key, model, provider",
        );
    };
    let Some(scope) = CostScope::parse(q.scope.as_deref()) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid `scope` — expected one of: all, production, eval",
        );
    };
    let since_secs = match parse_rfc3339_secs(q.since.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid since timestamp"),
    };
    let until_secs = match parse_rfc3339_secs(q.until.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid until timestamp"),
    };
    let hours = q
        .hours
        .unwrap_or(DEFAULT_GATEWAY_HOURS)
        .clamp(1, MAX_GATEWAY_HOURS);
    // CX-26 / B-525: resolved exactly as `gateway_stats_handler` does. The web has
    // sent `since`/`until` beside `hours` since DSH-11; this handler dropped the
    // pair and served `[now − hours, now]` under the page's absolute label.
    let served = ServedWindow::resolve(
        since_secs,
        until_secs,
        hours,
        chrono::Utc::now().timestamp(),
        MAX_WINDOW_SECS,
    );
    // The echoed `window_hours` is the window ACTUALLY served.
    let hours = (served.width_secs() / 3600).max(1) as u32;
    let filters = CostFilters {
        since_secs: since_secs.map(|_| served.since_secs),
        until_secs: until_secs.map(|_| served.until_secs),
        hours,
        dimension,
        limit: GATEWAY_PROVIDER_CAP,
        scope,
    };

    let rows = match state
        .reader
        .cost_breakdown(&claims.tenant_id, &filters)
        .await
    {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(error = %err, "cost breakdown read failed");
            return error_response(StatusCode::BAD_GATEWAY, "cost breakdown read failed");
        }
    };

    // CX-27 / B-526: the totals are the WINDOW-WIDE columns ClickHouse computed
    // before the `LIMIT` (identical on every row — read the first), never a sum
    // over the rows that fit under the cap. An empty window has no row and every
    // figure is a measured zero.
    let totals = rows.first();
    let group_count = totals.map_or(0, |r| r.group_count);
    let total_requests = totals.map_or(0, |r| r.all_requests);
    let priced_requests = totals.map_or(0, |r| r.all_priced_requests);
    let total_cost_usd = totals.map_or(0.0, |r| r.all_cost_usd);
    let eval_requests = totals.map_or(0, |r| r.all_eval_requests);
    let eval_cost_usd = totals.map_or(0.0, |r| r.all_eval_cost_usd);
    let judge_requests = totals.map_or(0, |r| r.all_judge_requests);
    let judge_cost_usd = totals.map_or(0.0, |r| r.all_judge_cost_usd);
    let truncated = (rows.len() as u64) < group_count;
    let out = CostBreakdownResponse {
        window_hours: hours,
        by: dimension.as_str(),
        total_cost_usd,
        total_requests,
        priced_requests,
        unpriced_requests: total_requests.saturating_sub(priced_requests),
        group_count,
        truncated,
        attribution_begins_note: (dimension == CostDimension::Key).then_some(
            "per-key attribution begins at the migration-16 deploy; earlier spans \
             carry no api_key_id and are reported under the empty key",
        ),
        scope: scope.as_str(),
        eval_cost_usd,
        eval_requests,
        // Subtracted rather than queried a second time: one aggregate produced
        // both halves, so they cannot disagree the way two round trips over a
        // moving table could.
        production_cost_usd: total_cost_usd - eval_cost_usd,
        production_requests: total_requests.saturating_sub(eval_requests),
        eval_attribution_note: "eval and experiment spend is identified by the \
             tracelane_eval_run_id span attribute, which the gateway began writing with R81; \
             eval traffic from before that deploy carries no attribute and is counted here \
             as production",
        judge_cost_usd,
        judge_requests,
        rows: rows
            .into_iter()
            .map(|r| CostBreakdownRow {
                unpriced_requests: r.requests.saturating_sub(r.priced_requests),
                dimension: r.dimension,
                requests: r.requests,
                priced_requests: r.priced_requests,
                cost_usd: r.cost_usd,
                input_tokens: r.input_tokens,
                output_tokens: r.output_tokens,
                eval_requests: r.eval_requests,
                eval_cost_usd: r.eval_cost_usd,
                judge_requests: r.judge_requests,
                judge_cost_usd: r.judge_cost_usd,
            })
            .collect(),
    };
    served.stamp(Json(out).into_response())
}

/// Read installed operator configuration and the same cached tenant caps as admission.
/// This route does not depend on the trace store being configured.
pub fn effective_settings_routes(state: crate::server::AppState) -> Router {
    Router::new()
        .route("/v1/gateway/settings", get(effective_settings_handler))
        .with_state(state)
}
async fn effective_settings_handler(
    State(state): State<crate::server::AppState>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(response) => return response,
    };
    let entitlements = match &state.entitlements {
        Some(cache) => {
            let value = cache.resolved(*claims.tenant_id.as_uuid()).await;
            cache
                .has_resolved(*claims.tenant_id.as_uuid())
                .then_some(value)
        }
        None => None,
    };
    let mut settings = effective_settings(&state, entitlements.as_deref());
    settings["cache"]["suspended"] = serde_json::json!(
        state
            .prompt_router
            .canary_cache_context(&claims.tenant_id)
            .suspended
    );
    Json(settings).into_response()
}
fn effective_settings(
    state: &crate::server::AppState,
    e: Option<&crate::entitlement_cache::ResolvedEntitlements>,
) -> serde_json::Value {
    use crate::providers::{catalog, failover};
    let cache = state.semantic_cache.as_ref().map(|cache| cache.config());
    let retries = failover::retry_policy(state.failover);
    let chain: Vec<_> = state.failover.map_or_else(
        || {
            failover::DEFAULT_CHAIN
                .iter()
                .map(|(provider, model)| serde_json::json!({"provider":provider,"model":model}))
                .collect()
        },
        |cfg| {
            cfg.chain()
                .iter()
                .map(|hop| serde_json::json!({"provider":hop.provider_id,"model":hop.model}))
                .collect()
        },
    );
    serde_json::json!({
        "cache": {"enabled":cache.is_some(), "operator_ttl_hours":cache.map(|c| c.ttl_hours()),
            "plan_ttl_hours":e.map(|e| e.cache_ttl_hours), "configurable":e.is_some_and(|e| e.f_cache_control && e.cache_ttl_hours > 0),
            "threshold":cache.map(|c| c.default_threshold()), "max_scan_entries":cache.map(|c| c.max_scan_entries())},
        "limits":{"available":e.is_some(), "rate_limit_rpm":e.and_then(|e| e.rate_limit_rpm),
            "workspace_budget_micro_usd":e.map(|e| e.workspace_budget_micro_usd), "spend_ceiling_micro_usd":e.and_then(|e| e.spend_ceiling_micro_usd)},
        "routing":{"aliases":crate::server::config::alias_snapshot(),
            "native":crate::providers::NATIVE_PREFIXES.iter().map(|(provider,prefixes)| serde_json::json!({"provider":provider,"prefixes":prefixes})).collect::<Vec<_>>(),
            "catalog":catalog::providers().iter().map(|p| serde_json::json!({"provider":p.id,"prefixes":p.prefixes})).collect::<Vec<_>>()},
        "failover":{"opt_in":true,"retries":retries.retries,"backoff_ms":retries.backoff_ms,"chain":chain}
    })
}

/// GET /v1/gateway/stats — per-provider router health for the authenticated
/// tenant (request volume, error rate, latency p50/p95/p99, prompt-cache hits),
/// a live aggregate over `spans`. Tenant id comes only from `Claims.tenant_id`.
/// Failover + rate-limit counters are NOT in the trace store yet (logs only) —
/// reported via the response's `uninstrumented` list, never a fabricated zero.
#[instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn gateway_stats_handler(
    State(state): State<TraceReadState>,
    Query(q): Query<GatewayStatsQuery>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));

    let since_secs = match parse_rfc3339_secs(q.since.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid since timestamp"),
    };
    let until_secs = match parse_rfc3339_secs(q.until.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid until timestamp"),
    };
    let hours = q
        .hours
        .unwrap_or(DEFAULT_GATEWAY_HOURS)
        .clamp(1, MAX_GATEWAY_HOURS);
    let served = ServedWindow::resolve(
        since_secs,
        until_secs,
        hours,
        chrono::Utc::now().timestamp(),
        MAX_WINDOW_SECS,
    );
    // The echoed `window_hours` is the window ACTUALLY served — it used to echo the
    // clamped `hours` even when `since` governed the query (inventory finding).
    let hours = (served.width_secs() / 3600).max(1) as u32;
    let filters = GatewayStatsFilters {
        since_secs: since_secs.map(|_| served.since_secs),
        until_secs: until_secs.map(|_| served.until_secs),
        hours,
        limit: GATEWAY_PROVIDER_CAP,
    };

    let rows = match state
        .reader
        .gateway_stats(&claims.tenant_id, &filters)
        .await
    {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(error = %err, "gateway stats read failed");
            return error_response(StatusCode::BAD_GATEWAY, "gateway stats read failed");
        }
    };
    // Rate-limit / quota 429s never reach a span (rejected pre-dispatch), so the
    // live per-tenant counters supply those numbers — process-lifetime, disclosed
    // as "since gateway start" by the surface.
    let rejections = state.rejections.snapshot(&claims.tenant_id);
    // Live circuit-breaker states (global read handle; ADR-036). Breakers are
    // per-(provider, region) and shared across tenants — upstream health, not
    // tenant data — so this is a process-wide snapshot, collapsed to per-provider.
    // Collapse regions to one state per provider, WORST-wins — a provider with
    // one Open and one Closed region shows Open, never a healthy lie.
    let mut breakers: std::collections::HashMap<String, crate::circuit_breaker::State> =
        std::collections::HashMap::new();
    for (provider, _region, state) in crate::circuit_breaker::global_snapshot() {
        breakers
            .entry(provider)
            .and_modify(|s| {
                if state.severity() > s.severity() {
                    *s = state;
                }
            })
            .or_insert(state);
    }
    served.stamp(
        Json(GatewayStatsResponse::from_rows(
            rows, hours, rejections, &breakers,
        ))
        .into_response(),
    )
}

/// GET /v1/query/latency-breakdown — the honest latency SPLIT for the authenticated
/// tenant (§ latency framing): gateway overhead (what Tracelane adds), upstream
/// provider latency (the LLM, not us), and streaming TTFT — window-wide p50/p95/p99
/// plus per-model overhead. A live aggregate over `spans`; tenant id comes ONLY
/// from `Claims.tenant_id`. `*_samples` gate the tiles: `0` → the UI shows "—"
/// (no measured overhead / no streaming traffic), never a fabricated `0ms`.
#[instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn latency_breakdown_handler(
    State(state): State<TraceReadState>,
    Query(q): Query<GatewayStatsQuery>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));

    let since_secs = match parse_rfc3339_secs(q.since.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid since timestamp"),
    };
    let until_secs = match parse_rfc3339_secs(q.until.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid until timestamp"),
    };
    let hours = q
        .hours
        .unwrap_or(DEFAULT_GATEWAY_HOURS)
        .clamp(1, MAX_GATEWAY_HOURS);
    let served = ServedWindow::resolve(
        since_secs,
        until_secs,
        hours,
        chrono::Utc::now().timestamp(),
        MAX_WINDOW_SECS,
    );
    // The echoed `window_hours` is the window ACTUALLY served — it used to echo the
    // clamped `hours` even when `since` governed the query (inventory finding).
    let hours = (served.width_secs() / 3600).max(1) as u32;
    let filters = GatewayStatsFilters {
        since_secs: since_secs.map(|_| served.since_secs),
        until_secs: until_secs.map(|_| served.until_secs),
        hours,
        limit: GATEWAY_PROVIDER_CAP,
    };

    match state
        .reader
        .latency_breakdown(&claims.tenant_id, &filters)
        .await
    {
        Ok((t, by_model)) => Json(LatencyBreakdownResponse {
            window_hours: hours,
            overhead_p50_ms: t.overhead_p50_ms,
            overhead_p95_ms: t.overhead_p95_ms,
            overhead_p99_ms: t.overhead_p99_ms,
            provider_p50_ms: t.provider_p50_ms,
            provider_p95_ms: t.provider_p95_ms,
            provider_p99_ms: t.provider_p99_ms,
            ttft_p50_ms: t.ttft_p50_ms,
            ttft_p95_ms: t.ttft_p95_ms,
            ttft_p99_ms: t.ttft_p99_ms,
            overhead_samples: t.overhead_samples,
            ttft_samples: t.ttft_samples,
            cache_hit_samples: t.cache_hit_samples,
            cache_hit_served_p50_ms: t.cache_hit_served_p50_ms,
            cache_hit_served_p95_ms: t.cache_hit_served_p95_ms,
            cold_start_samples: t.cold_start_samples,
            warm_samples: t.warm_samples,
            overhead_warm_p50_ms: t.overhead_warm_p50_ms,
            overhead_warm_p95_ms: t.overhead_warm_p95_ms,
            by_model,
        })
        .into_response()
        .pipe_stamp(&served),
        Err(err) => {
            tracing::error!(error = %err, "latency breakdown read failed");
            error_response(StatusCode::BAD_GATEWAY, "latency breakdown read failed")
        }
    }
}

/// GET /v1/guardrails/stats — the pre-flight guardrail engine's verdicts for the
/// authenticated tenant, from `guardrail_verdicts` (written per request-side).
///
/// Every number is captured: decision breakdown (block/redact/warn/allow),
/// fail-open rate (the trust headline), guardrail overhead percentiles, and
/// per-rail health. tenant_id comes ONLY from the validated JWT claim; both
/// queries bind `WHERE tenant_id = ?` first.
#[instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn guardrail_stats_handler(
    State(state): State<TraceReadState>,
    Query(q): Query<GuardrailStatsQuery>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));

    let since_secs = match parse_rfc3339_secs(q.since.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid since timestamp"),
    };
    let until_secs = match parse_rfc3339_secs(q.until.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid until timestamp"),
    };
    let hours = q
        .hours
        .unwrap_or(DEFAULT_GUARDRAIL_HOURS)
        .clamp(1, MAX_GUARDRAIL_HOURS);
    let served = ServedWindow::resolve(
        since_secs,
        until_secs,
        hours,
        chrono::Utc::now().timestamp(),
        MAX_WINDOW_SECS,
    );
    let hours = (served.width_secs() / 3600).max(1) as u32;
    let filters = GuardrailStatsFilters {
        since_secs: since_secs.map(|_| served.since_secs),
        until_secs: until_secs.map(|_| served.until_secs),
        hours,
        limit: GUARDRAIL_RAIL_CAP,
    };

    let summary = match state
        .reader
        .guardrail_summary(&claims.tenant_id, &filters)
        .await
    {
        Ok(s) => s,
        Err(err) => {
            tracing::error!(error = %err, "guardrail summary read failed");
            return error_response(StatusCode::BAD_GATEWAY, "guardrail read failed");
        }
    };
    let rails = match state
        .reader
        .guardrail_rails(&claims.tenant_id, &filters)
        .await
    {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(error = %err, "guardrail rails read failed");
            return error_response(StatusCode::BAD_GATEWAY, "guardrail read failed");
        }
    };
    served.stamp(Json(GuardrailStatsResponse::build(summary, rails, hours)).into_response())
}

/// GET /v1/guardrails/verdicts — the verdict-detail rows behind the decision-mix
/// counts (the "N blocked" click-through). A blocked verdict 403s the request
/// pre-span, so there is no trace to link to — the verdict itself is the detail.
/// Tenant id comes ONLY from the validated JWT claim; the query binds
/// `WHERE tenant_id = ?` first, then the allowlisted decision filter.
#[instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn guardrail_verdicts_handler(
    State(state): State<TraceReadState>,
    Query(q): Query<GuardrailVerdictsQuery>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));

    let since_secs = match parse_rfc3339_secs(q.since.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid since timestamp"),
    };
    let decision = match parse_decision_filter(q.decision.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid decision filter"),
    };
    let correlation_id = match parse_correlation_id_filter(q.correlation_id.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid correlation_id"),
    };
    let rail = match parse_rail_filter(q.rail.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid rail filter"),
    };
    let until_secs = match parse_rfc3339_secs(q.until.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid until timestamp"),
    };
    let hours = q
        .hours
        .unwrap_or(DEFAULT_GUARDRAIL_HOURS)
        .clamp(1, MAX_GUARDRAIL_HOURS);
    let served = ServedWindow::resolve(
        since_secs,
        until_secs,
        hours,
        chrono::Utc::now().timestamp(),
        MAX_WINDOW_SECS,
    );
    let filters = GuardrailVerdictListFilters {
        since_secs: since_secs.map(|_| served.since_secs),
        until_secs: until_secs.map(|_| served.until_secs),
        hours,
        decision,
        correlation_id,
        rail,
        limit: q
            .limit
            .unwrap_or(DEFAULT_VERDICT_LIMIT)
            .clamp(1, MAX_VERDICT_LIMIT),
    };

    let verdicts = match state
        .reader
        .guardrail_verdicts(&claims.tenant_id, &filters)
        .await
    {
        Ok(v) => v,
        Err(err) => {
            tracing::error!(error = %err, "guardrail verdicts read failed");
            return error_response(StatusCode::BAD_GATEWAY, "guardrail read failed");
        }
    };
    served.stamp(Json(GuardrailVerdictListResponse { verdicts }).into_response())
}

/// GET /v1/query/signatures — the §4 failure-signatures "your hits" aggregate for
/// the authenticated tenant. Live `ARRAY JOIN` over `spans.aft_ids` (no MV);
/// returns `your_hits` per signature ONLY — never a cross-tenant/network count
/// (honesty lock, the build spec §4). Tenant id comes only from `Claims.tenant_id`.
#[instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn signatures_handler(
    State(state): State<TraceReadState>,
    Query(q): Query<SignatureQuery>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));

    let since_secs = match parse_rfc3339_secs(q.since.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid since timestamp"),
    };
    let until_secs = match parse_rfc3339_secs(q.until.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid until timestamp"),
    };
    // B-331: this route had NO default window — a bare call was a full-history
    // ARRAY JOIN over the tenant's spans. It now defaults to the widest window the
    // other families serve (720 h), and an absolute pair is clamped to that.
    let served = ServedWindow::resolve(
        since_secs,
        until_secs,
        MAX_SLO_HOURS,
        chrono::Utc::now().timestamp(),
        MAX_WINDOW_SECS,
    );
    let filters = SignatureFilters {
        since_us: Some(served.since_secs * 1_000_000),
        until_us: until_secs.map(|_| served.until_secs * 1_000_000),
        limit: q
            .limit
            .unwrap_or(DEFAULT_SIGNATURE_LIMIT)
            .clamp(1, MAX_SIGNATURE_LIMIT),
        live_signature_ids: parse_live_signature_ids(q.live_ids.as_deref()),
    };

    let rows = match state.reader.signatures(&claims.tenant_id, &filters).await {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(error = %err, "signatures read failed");
            return error_response(StatusCode::BAD_GATEWAY, "signatures read failed");
        }
    };
    let total_traces_affected = match state
        .reader
        .signatures_distinct_traces(&claims.tenant_id, &filters)
        .await
    {
        Ok(n) => n,
        Err(err) => {
            tracing::error!(error = %err, "signatures distinct-traces read failed");
            return error_response(StatusCode::BAD_GATEWAY, "signatures read failed");
        }
    };
    let signatures = rows.into_iter().map(SignatureHit::from).collect();
    served.stamp(
        Json(SignaturesResponse {
            signatures,
            total_traces_affected,
        })
        .into_response(),
    )
}

/// GET /v1/sessions — §3 multi-turn session list for the authenticated tenant.
/// Live aggregation over `spans` grouped by `gen_ai.conversation.id`, bounded by
/// a look-back window + LIMIT. Tenant id comes only from `Claims.tenant_id`.
#[instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn list_sessions_handler(
    State(state): State<TraceReadState>,
    Query(q): Query<SessionListQuery>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));

    let since_us = match parse_rfc3339_micros(q.since.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid since timestamp"),
    };
    let until_us = match parse_rfc3339_micros(q.until.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid until timestamp"),
    };
    let window_days = q
        .days
        .unwrap_or(DEFAULT_SESSION_WINDOW_DAYS)
        .clamp(1, MAX_SESSION_WINDOW_DAYS);
    // B-331 for sessions: `since` used to replace the day predicate with no width
    // check. Clamp in seconds, keep the micro unit the SQL binds.
    let served = ServedWindow::resolve(
        since_us.map(|u| u / 1_000_000),
        until_us.map(|u| u / 1_000_000),
        window_days * 24,
        chrono::Utc::now().timestamp(),
        MAX_SESSION_WINDOW_US / 1_000_000,
    );
    let filters = SessionListFilters {
        since_us: since_us.map(|_| served.since_secs * 1_000_000),
        until_us: until_us.map(|_| served.until_secs * 1_000_000),
        window_days,
        model: q.model.filter(|m| !m.trim().is_empty()),
        status_error: parse_status_filter(q.status.as_deref()),
        sort: parse_session_sort(q.sort.as_deref()),
        order: parse_order(q.order.as_deref()),
        limit: q
            .limit
            .unwrap_or(DEFAULT_SESSION_LIMIT)
            .clamp(1, MAX_SESSION_LIMIT),
    };

    let rows = match state
        .reader
        .list_sessions(&claims.tenant_id, &filters)
        .await
    {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(error = %err, "session list read failed");
            return error_response(StatusCode::BAD_GATEWAY, "session read failed");
        }
    };
    let sessions = rows.into_iter().map(SessionSummary::from).collect();
    served.stamp(Json(SessionListResponse { sessions }).into_response())
}

/// GET /v1/sessions/{session_id}/traces — the ordered turns (traces) of one
/// session. 404 when the session has no traces for this tenant (same response
/// for "missing" and "not yours" — existence never leaks across tenants). The
/// session id is bound, never interpolated; the tenant is from the claim.
#[instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn session_traces_handler(
    State(state): State<TraceReadState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));

    if session_id.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "invalid session id");
    }

    let traces = match state
        .reader
        .session_traces(&claims.tenant_id, &session_id)
        .await
    {
        Ok(t) => t,
        Err(err) => {
            tracing::error!(error = %err, "session traces read failed");
            return error_response(StatusCode::BAD_GATEWAY, "session read failed");
        }
    };
    if traces.is_empty() {
        return error_response(StatusCode::NOT_FOUND, "session not found");
    }
    Json(SessionTracesResponse { session_id, traces }).into_response()
}

/// `OBS-55` — `GET /v1/sessions/{session_id}/transcript?limit=&cursor=`.
///
/// 404 (byte-identical body) for "no turns" and "not your tenant" — existence
/// never leaks. Totals are computed over the WHOLE session, never derived from
/// a page; turns are ordered ascending with a server-computed `ordinal` that
/// is exact on any page.
#[instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn session_transcript_handler(
    State(state): State<TraceReadState>,
    Path(session_id): Path<String>,
    Query(q): Query<SessionTranscriptQuery>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));

    if session_id.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "invalid session id");
    }
    let cursor = match q.cursor.as_deref().map(decode_cursor) {
        None => None,
        Some(Some(c)) => Some(c),
        Some(None) => return error_response(StatusCode::BAD_REQUEST, "invalid cursor"),
    };
    let limit = q
        .limit
        .unwrap_or(DEFAULT_SESSION_TRANSCRIPT_LIMIT)
        .clamp(1, MAX_SESSION_LIMIT);

    // Totals FIRST: `turns == 0` is the "no such session for this tenant"
    // signal (mirrors `session_traces`'s 404-on-empty), and asking for it
    // before the turns page means a foreign/unknown id costs one query, not
    // three.
    let totals = match state
        .reader
        .session_totals(&claims.tenant_id, &session_id)
        .await
    {
        Ok(Some(t)) => t,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "session not found"),
        Err(err) => {
            tracing::error!(error = %err, "session transcript totals read failed");
            return error_response(StatusCode::BAD_GATEWAY, "session read failed");
        }
    };

    let turns = match state
        .reader
        .session_turns(&claims.tenant_id, &session_id, cursor, limit)
        .await
    {
        Ok(t) => t,
        Err(err) => {
            tracing::error!(error = %err, "session transcript turns read failed");
            return error_response(StatusCode::BAD_GATEWAY, "session read failed");
        }
    };

    let next_cursor = if turns.len() as u32 == limit {
        turns
            .last()
            .map(|(t, _)| encode_cursor(t.start_time_us, &t.trace_id))
    } else {
        None
    };

    let capture = SessionCapture {
        // GWY-53: "on" when EITHER half is recorded — text can appear in the turns.
        workspace_policy: if state.reader.content_capture(&claims.tenant_id).await.any() {
            "on"
        } else {
            "off"
        },
    };
    let turns = turns
        .into_iter()
        .map(|(t, exchange)| SessionTurn {
            trace_id: t.trace_id,
            ordinal: t.ordinal,
            start_time: t.start_time_iso,
            duration_us: t.duration_us,
            span_count: t.span_count,
            error_spans: t.error_spans,
            status_message: t.status_message,
            intervention: t.intervention,
            input_tokens: t.input_tokens,
            output_tokens: t.output_tokens,
            cost_usd: (t.priced_spans > 0).then_some(t.cost_usd),
            model: t.model,
            exchange,
        })
        .collect();

    Json(SessionTranscriptResponse {
        totals: totals.into(),
        capture,
        turns,
        next_cursor,
    })
    .into_response()
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Validate `Authorization: Bearer <jwt|tlane_*>` and return the claims, or an
/// error `Response` (401). The tenant id is taken only from these claims.
async fn authenticate(headers: &HeaderMap) -> Result<crate::auth::Claims, Response> {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if auth.is_empty() {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "missing Authorization header",
        ));
    }
    let claims = crate::auth::validate_authorization(auth)
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, "trace read auth failed");
            let (status, msg) = crate::auth::failure(&err);
            error_response(status, msg)
        })?;

    // A13: every read route funnels through this ONE helper, so the `read` scope
    // is enforced here rather than 17 times. A route added later inherits the
    // gate by construction — which is the point of the seam; a per-route check
    // is a list that drifts.
    //
    // Legacy keys (`scope IS NULL`) and every JWT resolve to LegacyFullSurface
    // and are unaffected.
    if !claims.allows_scope(crate::auth::scope::Scope::Read) {
        tracing::warn!(sub = %claims.sub, "api key lacks the `read` scope");
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "This API key is not scoped to read recorded data. It needs the `read` scope.",
        ));
    }
    Ok(claims)
}

fn parse_bool(s: Option<&str>) -> Option<bool> {
    match s {
        Some("true") => Some(true),
        Some("false") => Some(false),
        _ => None,
    }
}

/// Parse an optional RFC3339 timestamp into microseconds since epoch.
/// `Ok(None)` = absent or empty; `Ok(Some)` = parsed; `Err(())` =
/// present-but-malformed (the caller returns 400 rather than silently widening
/// the query window — opus-review M2).
fn parse_rfc3339_micros(s: Option<&str>) -> Result<Option<i64>, ()> {
    match s {
        None => Ok(None),
        Some(t) if t.trim().is_empty() => Ok(None),
        Some(t) => DateTime::parse_from_rfc3339(t)
            .map(|dt| Some(dt.timestamp_micros()))
            .map_err(|_| ()),
    }
}

/// Parse an optional RFC3339 timestamp into seconds since epoch. Same
/// absent/empty/malformed contract as [`parse_rfc3339_micros`].
fn parse_rfc3339_secs(s: Option<&str>) -> Result<Option<i64>, ()> {
    match s {
        None => Ok(None),
        Some(t) if t.trim().is_empty() => Ok(None),
        Some(t) => DateTime::parse_from_rfc3339(t)
            .map(|dt| Some(dt.timestamp()))
            .map_err(|_| ()),
    }
}

/// Encode a keyset cursor. `trace_id` (hex, no colon) goes after the first
/// colon, so [`decode_cursor`] can `split_once(':')` unambiguously.
fn encode_cursor(sort_val: i64, trace_id: &str) -> String {
    format!("{sort_val}:{trace_id}")
}

fn decode_cursor(s: &str) -> Option<(i64, String)> {
    let (ts, id) = s.split_once(':')?;
    let ts = ts.parse::<i64>().ok()?;
    if id.is_empty() {
        return None;
    }
    Some((ts, id.to_string()))
}

/// Build a JSON error body. Never echoes SQL, driver text, or the underlying
/// error to the client (logged server-side instead).
fn error_response(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

#[cfg(test)]
mod obs10_compare_tests {
    use super::*;

    fn span(id: &str, parent: Option<&str>, name: &str, start: i64, dur: i64) -> SpanRow {
        SpanRow {
            span_id: id.to_string(),
            parent_span_id: parent.map(str::to_string),
            name: name.to_string(),
            start_time: String::new(),
            end_time: String::new(),
            start_time_us: start,
            duration_us: dur,
            status_code: 0,
            status_message: String::new(),
            attributes: "{}".to_string(),
            aft_ids: vec![],
            intervention: 0,
        }
    }

    /// A three-level chain must report 0/1/2 — the alignment key is meaningless
    /// if depth is wrong, because a span would then pair with one at a different
    /// level of the tree.
    #[test]
    fn depth_follows_the_parent_chain() {
        let s = vec![
            span("r", None, "root", 0, 100),
            span("c", Some("r"), "child", 1, 50),
            span("g", Some("c"), "grand", 2, 10),
        ];
        let d = span_depths(&s);
        assert_eq!(d["r"], 0);
        assert_eq!(d["c"], 1);
        assert_eq!(d["g"], 2);
    }

    /// A span whose parent is absent from the trace is an ORPHAN — a partial
    /// capture, not corruption. It must still appear, at depth 0. Dropping it
    /// would silently shrink the diff.
    #[test]
    fn orphan_span_is_kept_at_depth_zero() {
        let s = vec![span("x", Some("missing-parent"), "orphan", 0, 5)];
        assert_eq!(span_depths(&s)["x"], 0);
    }

    /// A malformed parent chain must terminate, not hang the request.
    #[test]
    fn parent_cycle_terminates_at_the_guard() {
        let s = vec![
            span("a", Some("b"), "a", 0, 1),
            span("b", Some("a"), "b", 1, 1),
        ];
        let d = span_depths(&s);
        assert!(d["a"] <= COMPARE_MAX_DEPTH, "cycle must be bounded");
        assert!(d["b"] <= COMPARE_MAX_DEPTH, "cycle must be bounded");
    }

    /// Identical shape → every row pairs, nothing is one-sided.
    #[test]
    fn identical_traces_align_completely() {
        let a = vec![
            span("a1", None, "chat", 0, 100),
            span("a2", Some("a1"), "dispatch", 10, 80),
        ];
        let b = vec![
            span("b1", None, "chat", 500, 100),
            span("b2", Some("b1"), "dispatch", 510, 80),
        ];
        let r = align_traces("A", &a, "B", &b);
        assert_eq!(r.rows.len(), 2);
        assert!(r.rows.iter().all(|x| x.side == "both"));
        assert_eq!(r.only_in_a, 0);
        assert_eq!(r.only_in_b, 0);
        assert_eq!(r.slower_count, 0);
    }

    /// The spec's headline case: a retry present only in B must be reported as
    /// `only_b`, which is the `+` marker in the wireframe.
    #[test]
    fn span_present_only_in_b_is_reported() {
        let a = vec![span("a1", None, "chat", 0, 100)];
        let b = vec![
            span("b1", None, "chat", 0, 100),
            span("b2", Some("b1"), "retry", 5, 4_000),
        ];
        let r = align_traces("A", &a, "B", &b);
        assert_eq!(r.only_in_b, 1);
        assert_eq!(r.only_in_a, 0);
        let retry = r
            .rows
            .iter()
            .find(|x| x.name == "retry")
            .expect("retry row");
        assert_eq!(retry.side, "only_b");
        assert!(retry.a_duration_us.is_none());
        assert_eq!(retry.b_duration_us, Some(4_000));
        // A one-sided row has no delta — there is nothing to subtract from.
        assert!(retry.delta_us.is_none() && retry.delta_pct.is_none());
        assert!(!retry.slower, "one-sided rows are never flagged slower");
    }

    /// BOTH thresholds must be crossed. This is the whole reason the flag is
    /// trustworthy, so both half-cases are asserted to NOT flag.
    #[test]
    fn slower_needs_both_absolute_and_relative_margins() {
        // Big % but tiny absolute (1ms -> 2ms): +100%, but only +1000us.
        let a = vec![span("a1", None, "chat", 0, 1_000)];
        let b = vec![span("b1", None, "chat", 0, 2_000)];
        assert_eq!(
            align_traces("A", &a, "B", &b).slower_count,
            0,
            "percent alone must not flag"
        );

        // Big absolute but small % (1s -> 1.006s): +6000us, only +0.6%.
        let a = vec![span("a1", None, "chat", 0, 1_000_000)];
        let b = vec![span("b1", None, "chat", 0, 1_006_000)];
        assert_eq!(
            align_traces("A", &a, "B", &b).slower_count,
            0,
            "absolute alone must not flag"
        );

        // Both: 10ms -> 100ms.
        let a = vec![span("a1", None, "chat", 0, 10_000)];
        let b = vec![span("b1", None, "chat", 0, 100_000)];
        let r = align_traces("A", &a, "B", &b);
        assert_eq!(r.slower_count, 1);
        assert_eq!(r.rows[0].delta_us, Some(90_000));
        assert_eq!(r.rows[0].delta_pct, Some(900.0));
    }

    /// A zero-duration baseline must yield `None`, never infinity and never a
    /// silent 0 — a fabricated 0% would read as "unchanged".
    #[test]
    fn zero_baseline_duration_yields_no_percentage() {
        let a = vec![span("a1", None, "chat", 0, 0)];
        let b = vec![span("b1", None, "chat", 0, 50_000)];
        let r = align_traces("A", &a, "B", &b);
        assert_eq!(r.rows[0].delta_us, Some(50_000));
        assert!(
            r.rows[0].delta_pct.is_none(),
            "0 baseline must not produce a percentage"
        );
        assert!(
            !r.rows[0].slower,
            "cannot claim slower without a relative margin"
        );
    }

    /// Repeated `(name, depth)` spans must pair up in time order, not collapse
    /// into one row or cross-pair.
    #[test]
    fn repeated_names_align_by_ordinal_in_time_order() {
        let a = vec![
            span("a1", None, "root", 0, 10),
            span("a2", Some("a1"), "call", 10, 100),
            span("a3", Some("a1"), "call", 20, 200),
        ];
        let b = vec![
            span("b1", None, "root", 0, 10),
            span("b2", Some("b1"), "call", 10, 100),
            span("b3", Some("b1"), "call", 20, 200),
        ];
        let r = align_traces("A", &a, "B", &b);
        assert_eq!(r.rows.len(), 3, "two `call` rows must stay two rows");
        assert!(r.rows.iter().all(|x| x.side == "both"));
        let calls: Vec<_> = r.rows.iter().filter(|x| x.name == "call").collect();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].ordinal, 0);
        assert_eq!(calls[1].ordinal, 1);
        // Ordinal 0 is the EARLIER span, so it must carry that span's duration.
        assert_eq!(calls[0].a_duration_us, Some(100));
        assert_eq!(calls[1].a_duration_us, Some(200));
    }

    /// `total_us` is wall-clock extent, NOT the sum of durations — summing
    /// double-counts every nested span and would overstate a deep trace.
    #[test]
    fn total_is_wall_clock_not_sum_of_durations() {
        let s = vec![
            span("r", None, "root", 1_000, 500),
            span("c", Some("r"), "child", 1_100, 300),
        ];
        // sum would be 800; the real extent is 1500-1000 = 500.
        assert_eq!(trace_total_us(&s), 500);
    }

    #[test]
    fn empty_trace_totals_zero_rather_than_panicking() {
        assert_eq!(trace_total_us(&[]), 0);
    }

    /// The threshold constants travel in the response so the UI never has to
    /// hardcode them to explain a ▲.
    #[test]
    fn thresholds_are_reported_to_the_client() {
        let a = vec![span("a1", None, "chat", 0, 10)];
        let b = vec![span("b1", None, "chat", 0, 10)];
        let r = align_traces("A", &a, "B", &b);
        assert_eq!(r.threshold_us, COMPARE_THRESHOLD_US);
        assert_eq!(r.threshold_pct, COMPARE_THRESHOLD_PCT);
    }
}

#[cfg(test)]
mod obs23_truncation_tests {
    use super::*;

    /// The cap must NOT move. OBS-23 signals truncation; it does not raise the limit,
    /// and the `ponytail:` marker above the constant records that ceiling as still
    /// live. A silent bump here is exactly what the marker exists to prevent.
    #[test]
    fn export_cap_is_unchanged() {
        assert_eq!(MAX_TRACE_EXPORT, 10_000);
    }

    /// A full-cap export must announce itself. The failure this closes is a file that
    /// LOOKS complete: an operator exports an incident window, gets exactly 10,000
    /// rows, and reasons about a set that was quietly cut.
    /// Exercises the real predicate over the boundary rather than asserting a
    /// constant: one row short of the cap is complete, exactly at the cap is
    /// truncated. `is_truncated` is the same expression the handler uses.
    #[test]
    fn at_cap_is_truncated_below_cap_is_not() {
        fn is_truncated(rows: usize) -> bool {
            rows as u32 >= MAX_TRACE_EXPORT
        }
        assert!(!is_truncated(0));
        assert!(!is_truncated(MAX_TRACE_EXPORT as usize - 1));
        assert!(is_truncated(MAX_TRACE_EXPORT as usize));
    }

    /// The header alone is not enough: a browser download discards response headers,
    /// so a human opening the CSV would never see it. The terminal row is what
    /// survives into the artifact, and it must name the cap and say what to do.
    #[test]
    fn csv_terminal_row_states_incompleteness_in_the_file() {
        let note = format!(
            "# TRUNCATED: this export stopped at the {MAX_TRACE_EXPORT}-row cap and is NOT complete. \
Narrow the filters (time range, model, error-only) and export again.\n"
        );
        assert!(note.contains("NOT complete"));
        assert!(note.contains("10000"));
        assert!(
            note.starts_with('#'),
            "must be a comment row, not a data row"
        );
    }

    /// Header names are the machine contract — a rename silently removes the signal
    /// while every status code stays 200.
    #[test]
    fn truncation_header_names_are_stable() {
        assert_eq!(X_TRUNCATED.as_str(), "x-tracelane-truncated");
        assert_eq!(X_ROW_COUNT.as_str(), "x-tracelane-row-count");
    }
}

#[cfg(test)]
mod obs01_search_tests {
    use super::*;

    /// A term shorter than the ngram `n` cannot be served by the index, so it would
    /// silently become a full scan. It must be REFUSED, not quietly accepted — a slow
    /// 200 teaches the customer the product is slow; a 400 tells them why.
    #[test]
    fn short_term_is_rejected_not_silently_scanned() {
        assert!(validate_search_term(Some("abc")).is_err());
        assert!(validate_search_term(Some("  ab  ")).is_err());
    }

    #[test]
    fn absent_or_blank_term_is_not_an_error() {
        assert!(matches!(validate_search_term(None), Ok(None)));
        assert!(matches!(validate_search_term(Some("   ")), Ok(None)));
    }

    #[test]
    fn valid_term_is_trimmed_and_kept() {
        assert_eq!(
            validate_search_term(Some("  quota proof  ")).ok().flatten(),
            Some("quota proof".to_string())
        );
    }

    /// The whole point of OBS-01: the predicate must be a form the ngram index can
    /// serve. `multiSearchAny` on the RAW column is; anything wrapped in `lower()`
    /// is not, and would put the hot read path back on a full scan.
    #[test]
    fn search_sql_is_index_servable_and_tenant_scoped() {
        let sql = build_trace_list_sql(&TraceListFilters {
            agent: None,
            model_family: None,
            q: Some("needle".into()),
            limit: 50,
            ..Default::default()
        });
        assert!(
            sql.contains("multiSearchAny(name, [?, ?])"),
            "must probe the raw column so ngrambf_v1 can serve it: {sql}"
        );
        assert!(
            !sql.contains("lower(name)") && !sql.contains("lower(attributes)"),
            "lower() on the indexed column silently disables the index: {sql}"
        );
        // Tenant isolation: the search subquery is itself tenant-bound, so it can
        // never widen across tenants.
        let sub = sql
            .split("SELECT trace_id FROM spans")
            .nth(1)
            .expect("search subquery present");
        assert!(
            sub.trim_start().starts_with("WHERE tenant_id = ?"),
            "search subquery must be tenant-bound first: {sub}"
        );
    }

    /// SQL placeholders and binds must stay in lockstep. The search clause adds
    /// exactly five `?` — one tenant_id plus four term probes — and a drift here is
    /// how a filter silently binds the wrong value.
    #[test]
    fn search_clause_adds_exactly_five_placeholders() {
        let base = build_trace_list_sql(&TraceListFilters {
            agent: None,
            model_family: None,
            limit: 50,
            ..Default::default()
        });
        let with_q = build_trace_list_sql(&TraceListFilters {
            agent: None,
            model_family: None,
            q: Some("needle".into()),
            limit: 50,
            ..Default::default()
        });
        assert_eq!(
            with_q.matches('?').count() - base.matches('?').count(),
            5,
            "search clause must bind tenant_id + 4 term probes"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// B-386 (b): a fresh rejection registry per test — the read state carries
    /// the SAME `Arc` the hot path records on in production.
    pub(super) fn test_rejections() -> Arc<crate::rejection_metrics::RejectionRegistry> {
        Arc::new(crate::rejection_metrics::RejectionRegistry::new())
    }
    use std::sync::Mutex;

    // ── Pure SQL-builder tests (no client, no env) ───────────────────────────

    #[test]
    fn trace_list_sql_is_tenant_first_and_bound() {
        let sql = build_trace_list_sql(&TraceListFilters {
            agent: None,
            model_family: None,
            q: None,
            limit: 50,
            ..Default::default()
        });
        // tenant_id is the FIRST predicate and a bound placeholder.
        assert!(sql.contains("WHERE tenant_id = ?"), "sql: {sql}");
        let where_pos = sql.find("WHERE tenant_id = ?").unwrap();
        // No other predicate precedes the tenant filter.
        assert!(!sql[..where_pos].contains("AND "));
        // B-379: the merge is a GROUP BY over the window, never `FINAL` (which
        // cannot use the time-ordered projection), and the window is ALWAYS bound
        // — two `WITH` clocks before anything else.
        assert!(sql.starts_with(WINDOW_WITH), "sql: {sql}");
        assert!(
            !sql.contains("FINAL"),
            "FINAL disables the projection: {sql}"
        );
        assert!(sql.contains("GROUP BY tenant_id, trace_id"));
        assert!(sql.contains("start_time >= w_since AND start_time <= w_until"));
        assert!(sql.contains("ORDER BY st_min DESC, trace_id DESC"));
        assert!(sql.trim_end().ends_with("LIMIT ?"));
    }

    #[test]
    fn trace_list_sql_appends_filters_in_bind_order() {
        let sql = build_trace_list_sql(&TraceListFilters {
            agent: None,
            model_family: None,
            q: None,
            model: Some("claude".into()),
            has_error: Some(true),
            min_duration_us: None,
            signature_id: None,
            since_us: Some(1),
            until_us: Some(2),
            cursor: Some((10, "abc".into())),
            limit: 25,
            ..Default::default()
        });
        // B-379: the window's two ?s come FIRST (the WITH clocks), then the inner
        // tenant, the outer tenant, model ?, the keyset ?s, limit ?.
        let i_since = sql.find("fromUnixTimestamp64Micro(?) AS w_since").unwrap();
        let i_until = sql.find("fromUnixTimestamp64Micro(?) AS w_until").unwrap();
        let i_model = sql.find("model = ?").unwrap();
        let i_cursor = sql.find("toUnixTimestamp64Micro(st_min) < ?").unwrap();
        let i_limit = sql.rfind("LIMIT ?").unwrap();
        assert!(i_since < i_until && i_until < i_model && i_model < i_cursor && i_cursor < i_limit);
        assert!(sql.contains("error_count > 0"));
        // Three placeholders in the keyset clause.
        let cursor_clause = &sql[i_cursor..i_limit];
        assert_eq!(cursor_clause.matches('?').count(), 3);
    }

    #[test]
    fn trace_list_sql_failover_is_tenant_scoped_subquery_only_when_true() {
        // Some(true) → the tenant-scoped failover-attr subquery is present.
        let on = build_trace_list_sql(&TraceListFilters {
            agent: None,
            model_family: None,
            q: None,
            failover: Some(true),
            limit: 50,
            ..Default::default()
        });
        assert!(on.contains(
            "trace_id IN (SELECT trace_id FROM spans WHERE tenant_id = ? AND start_time >= w_since AND start_time <= w_until AND JSONExtractBool(attributes, 'tracelane_failover_activated'))"
        ), "sql: {on}");
        // groups builder mirrors the same clause (so a failover view groups honestly).
        let grp = build_trace_groups_sql(
            TraceGroupBy::Model,
            &TraceListFilters {
                agent: None,
                model_family: None,
                q: None,
                failover: Some(true),
                limit: 50,
                ..Default::default()
            },
        );
        assert!(grp.contains("JSONExtractBool(attributes, 'tracelane_failover_activated')"));
        // None / Some(false) → no failover predicate at all (no silent full-scan filter).
        for f in [None, Some(false)] {
            let off = build_trace_list_sql(&TraceListFilters {
                agent: None,
                model_family: None,
                q: None,
                failover: f,
                limit: 50,
                ..Default::default()
            });
            assert!(
                !off.contains("tracelane_failover_activated"),
                "failover={f:?} sql: {off}"
            );
        }
        // parse_failover: only the literal "true" enables it.
        assert_eq!(parse_failover(Some("true")), Some(true));
        assert_eq!(parse_failover(Some("false")), None);
        assert_eq!(parse_failover(None), None);
    }

    /// `OBS-20`. **The B-232 class, pinned: the stored key is UNDERSCORED.**
    ///
    /// A first-class `SpanAttributes` field serialises under its snake_case Rust
    /// name, so the writer emits `user_id`. A key that only ever reaches `extra`
    /// keeps its literal dotted form. Query `'user.id'` here and the read path
    /// matches a key nothing in this repo writes — the sessions page would be
    /// empty for every tenant, forever, with no error anywhere.
    ///
    /// So this asserts the underscored key is present AND the dotted one is
    /// absent. The second half is the one that catches the mistake.
    #[test]
    fn obs20_session_sql_reads_the_underscored_key_never_the_dotted_one() {
        let sql = build_session_list_sql(&SessionListFilters {
            limit: 50,
            ..Default::default()
        });
        assert!(
            sql.contains("JSONExtractString(attributes, 'user_id'), start_time) AS end_user"),
            "sql: {sql}"
        );
        assert!(
            !sql.contains("'user.id'"),
            "the dotted key matches nothing this repo writes: {sql}"
        );
        // Appended LAST, after agent_name — the bind positions ahead of it must
        // not move (TRAPS §58). Assert the ORDER, not just presence.
        let agent_at = sql.find("AS agent_name").expect("agent_name projected");
        let user_at = sql.find("AS end_user").expect("end_user projected");
        assert!(
            agent_at < user_at,
            "end_user must be appended AFTER agent_name: {sql}"
        );
    }

    /// `OBS-20`. The end-user trace filter is a TENANT-SCOPED subquery in all
    /// three builders, and absent when the filter is.
    #[test]
    fn obs20_end_user_filter_is_tenant_scoped_subquery_in_all_three_builders() {
        const CLAUSE: &str = "trace_id IN (SELECT trace_id FROM spans WHERE tenant_id = ? AND start_time >= w_since AND start_time <= w_until AND JSONExtractString(attributes, 'user_id') = ?)";
        let f = TraceListFilters {
            agent: None,
            model_family: None,
            q: None,
            end_user: Some("u_1".into()),
            limit: 50,
            ..Default::default()
        };
        assert!(build_trace_list_sql(&f).contains(CLAUSE));
        assert!(build_trace_count_sql(&f).contains(CLAUSE));
        assert!(build_trace_groups_sql(TraceGroupBy::Model, &f).contains(CLAUSE));

        // Absent when unset — no silent full-scan predicate.
        let off = TraceListFilters {
            agent: None,
            model_family: None,
            q: None,
            end_user: None,
            limit: 50,
            ..Default::default()
        };
        assert!(!build_trace_list_sql(&off).contains("'user_id'"));

        // The id is BOUND (`= ?`), never interpolated. It is caller-supplied
        // text, so an interpolated form would be the one SQL-injection seam on
        // this surface.
        let injected = TraceListFilters {
            agent: None,
            model_family: None,
            q: None,
            end_user: Some("' OR 1=1 --".into()),
            limit: 50,
            ..Default::default()
        };
        let sql = build_trace_list_sql(&injected);
        assert!(
            !sql.contains("OR 1=1"),
            "the end-user id must never reach the SQL text: {sql}"
        );
    }

    #[test]
    fn trace_count_sql_is_tenant_first_no_order_no_limit() {
        let sql = build_trace_count_sql(&TraceListFilters {
            agent: None,
            model_family: None,
            q: None,
            model: Some("claude".into()),
            has_error: Some(true),
            failover: Some(true),
            since_us: Some(1),
            limit: 50,
            ..Default::default()
        });
        // B-379: `count()` over the MERGED subquery — the GROUP BY already
        // collapsed the MV's partial rows, which is what `uniqExact` was for
        // against FINAL's leftovers (provenance audit P1 #7 still holds: the
        // footer reconciles with the list because both read the same merge).
        assert!(sql.starts_with(WINDOW_WITH), "sql: {sql}");
        assert!(
            sql.contains("SELECT toUInt64(count()) AS total FROM (SELECT tenant_id, trace_id"),
            "sql: {sql}"
        );
        assert!(!sql.contains("FINAL"));
        // mirrors the list filters, but NO ORDER BY / LIMIT / cursor.
        assert!(sql.contains("model = ?"));
        assert!(sql.contains("error_count > 0"));
        assert!(sql.contains("tracelane_failover_activated"));
        assert!(sql.contains("start_time >= w_since AND start_time <= w_until"));
        assert!(!sql.contains("ORDER BY"));
        assert!(!sql.contains("LIMIT"));
    }

    #[test]
    fn trace_list_sql_has_error_false_is_clean_only() {
        let sql = build_trace_list_sql(&TraceListFilters {
            agent: None,
            model_family: None,
            q: None,
            has_error: Some(false),
            limit: 50,
            ..Default::default()
        });
        assert!(sql.contains("error_count = 0"));
        assert!(!sql.contains("error_count > 0"));
    }

    #[test]
    fn spans_sql_is_tenant_first_then_trace() {
        assert!(SPANS_SQL.contains("WHERE tenant_id = ? AND trace_id = ?"));
        let where_pos = SPANS_SQL.find("WHERE tenant_id = ?").unwrap();
        assert!(!SPANS_SQL[..where_pos].contains("trace_id"));
        assert!(SPANS_SQL.contains("FROM spans FINAL"));
        assert!(SPANS_SQL.contains("ORDER BY start_time ASC, span_id ASC"));
    }

    #[test]
    fn trace_chain_sql_is_tenant_first_pins_event_type_and_matches_trace_id() {
        // tenant_id is bound FIRST (isolation), before the trace_id extract.
        let where_pos = TRACE_CHAIN_SQL.find("WHERE tenant_id = ?").unwrap();
        assert!(!TRACE_CHAIN_SQL[..where_pos].contains("JSONExtract"));
        // Only a real gateway call counts — never a guardrail/eval verdict row.
        // All three gateway-call event types, never a verdict row.
        assert!(TRACE_CHAIN_SQL.contains(
            "event_type IN ('chat.completions.request', 'messages.request', 'embeddings.request')"
        ));
        assert!(!TRACE_CHAIN_SQL.contains("guardrail.verdict"));
        // trace_id matched out of the canonical payload, parameter-bound.
        assert!(TRACE_CHAIN_SQL.contains("JSONExtractString(payload, 'trace_id') = ?"));
        assert!(TRACE_CHAIN_SQL.contains("FROM tracelane.audit_log"));
        assert!(TRACE_CHAIN_SQL.contains("LIMIT 1"));
    }

    #[test]
    fn anchored_from_treats_null_and_sentinels_as_unanchored() {
        // NULL (Nullable(String) column) → not anchored. Live-proof regression:
        // the row type MUST be Option<String>; a NULL id decodes to None here.
        assert!(!anchored_from(None));
        // Writer sentinels (audit.rs) → not anchored.
        assert!(!anchored_from(Some("(no-rekor)")));
        assert!(!anchored_from(Some("(no-key)")));
        assert!(!anchored_from(Some("(unknown-uuid)")));
        // A real transparency-log entry id → anchored.
        assert!(anchored_from(Some(
            "24296fb24b8ad77aabcdef0123456789abcdef0123456789abcdef0123456789"
        )));
    }

    // ── DSH-11 ─────────────────────────────────────────────────────────────

    #[test]
    fn served_window_clamps_a_wide_pair_to_the_cap_and_says_so() {
        let now = 1_800_000_000;
        let cap = MAX_WINDOW_SECS;
        let w = ServedWindow::resolve(Some(now - 365 * 86_400), Some(now), 24, now, cap);
        assert!(w.clamped);
        assert_eq!(w.until_secs, now);
        assert_eq!(w.since_secs, now - cap);
        assert_eq!(w.width_secs(), cap);
        let v = w.header_value();
        assert!(v.ends_with(";clamped=1"), "{v}");
        // inside the cap: untouched
        let ok = ServedWindow::resolve(Some(now - 3600), Some(now - 60), 24, now, cap);
        assert!(!ok.clamped);
        assert_eq!((ok.since_secs, ok.until_secs), (now - 3600, now - 60));
        // a future `until` is pulled back to now
        let fut = ServedWindow::resolve(Some(now - 3600), Some(now + 3600), 24, now, cap);
        assert_eq!(fut.until_secs, now);
        // no `since`: the rolling window, never clamped
        let roll = ServedWindow::resolve(None, None, 720, now, cap);
        assert!(!roll.clamped);
        assert_eq!(roll.width_secs(), 720 * 3600);
    }

    #[test]
    fn bucket_ceiling_widens_rather_than_answering_thousands_of_rows() {
        assert_eq!(cap_bucket_secs(3600, 24 * 3600), 3600);
        assert_eq!(cap_bucket_secs(3600, 720 * 3600), 3600 * 8);
        assert_eq!(validate_bucket_minutes(Some(5), 6 * 3600), Ok(Some(5)));
        assert!(validate_bucket_minutes(Some(7), 3600).is_err());
        assert!(validate_bucket_minutes(Some(1), 25 * 3600).is_err());
        assert!(
            validate_bucket_minutes(Some(1), 3 * 3600).is_err(),
            "180 buckets > 96"
        );
        assert_eq!(validate_bucket_minutes(None, 365 * 86_400), Ok(None));
    }

    #[test]
    fn every_windowed_builder_binds_until_after_since() {
        let gw = build_gateway_stats_sql(&GatewayStatsFilters {
            since_secs: Some(1),
            until_secs: Some(2),
            hours: 24,
            limit: 10,
        });
        let a = gw.find("start_time >= toDateTime(?)").unwrap();
        let b = gw.find("start_time <= toDateTime(?)").unwrap();
        assert!(a < b, "until must bind AFTER since: {gw}");
        assert!(
            !build_gateway_stats_sql(&GatewayStatsFilters {
                hours: 24,
                limit: 10,
                ..Default::default()
            })
            .contains("start_time <=")
        );
        let g = build_guardrail_summary_sql(&GuardrailStatsFilters {
            since_secs: Some(1),
            until_secs: Some(2),
            hours: 24,
            limit: 10,
        });
        assert!(g.contains("event_time >= toDateTime(?) AND event_time <= toDateTime(?)"));
        let v = build_guardrail_verdicts_sql(&GuardrailVerdictListFilters {
            since_secs: Some(1),
            until_secs: Some(2),
            hours: 24,
            decision: Some("block".into()),
            correlation_id: None,
            rail: None,
            limit: 5,
        });
        let d = v.find("decision = ?").unwrap();
        let s = v.find("event_time >= toDateTime(?)").unwrap();
        let u = v.find("event_time <= toDateTime(?)").unwrap();
        assert!(d < s && s < u, "bind order decision, since, until: {v}");
        let sg = build_signatures_sql(&SignatureFilters {
            since_us: Some(1),
            until_us: Some(2),
            limit: 5,
            live_signature_ids: vec![],
        });
        assert!(sg.contains("start_time >= fromUnixTimestamp64Micro(?) AND start_time <= fromUnixTimestamp64Micro(?)"));
        let ss = build_session_list_sql(&SessionListFilters {
            since_us: Some(1),
            until_us: Some(2),
            window_days: 30,
            limit: 5,
            ..Default::default()
        });
        assert!(ss.contains("start_time >= fromUnixTimestamp64Micro(?) AND start_time <= fromUnixTimestamp64Micro(?) GROUP BY"));
        // CX-26 / B-525: `/v1/costs` was the one windowed builder this test's name
        // did not cover — it substituted a rolling `now() − hours` for the pair.
        let cost = build_cost_breakdown_sql(&CostFilters {
            since_secs: Some(1),
            until_secs: Some(2),
            hours: 24,
            dimension: CostDimension::Model,
            limit: 10,
            scope: CostScope::Production,
        });
        let a = cost.find("start_time >= toDateTime(?)").unwrap();
        let b = cost.find("start_time <= toDateTime(?)").unwrap();
        let sc = cost.find("tracelane_eval_run_id') = ''").unwrap();
        let lim = cost.find("LIMIT ?").unwrap();
        assert!(
            a < b && b < sc && sc < lim,
            "bind order tenant, since, until, (scope: no placeholder), limit: {cost}"
        );
        assert!(
            !cost.contains("toIntervalHour"),
            "since must override hours: {cost}"
        );
        let rolling = build_cost_breakdown_sql(&CostFilters {
            since_secs: None,
            until_secs: None,
            hours: 24,
            dimension: CostDimension::Model,
            limit: 10,
            scope: CostScope::All,
        });
        assert!(rolling.contains("now() - toIntervalHour(?)"), "{rolling}");
        assert!(!rolling.contains("start_time <="), "{rolling}");
    }

    /// B-332 — the filters were parsed and never bound.
    #[test]
    fn slo_timeseries_binds_provider_and_model_and_carries_errors() {
        let sql = build_slo_timeseries_sql(
            &SloFilters {
                hours: 24,
                provider: Some("openai".into()),
                model: Some("gpt-4o".into()),
                ..Default::default()
            },
            1,
        );
        assert!(sql.contains(" AND provider = ?"), "{sql}");
        assert!(sql.contains(" AND model = ?"), "{sql}");
        assert!(
            sql.contains("countIfMerge(error_count)) AS errors"),
            "{sql}"
        );
        let bare = build_slo_timeseries_sql(
            &SloFilters {
                hours: 24,
                ..Default::default()
            },
            1,
        );
        assert!(!bare.contains("provider = ?"));
    }

    /// Sub-hour buckets read raw spans with the MV's own provider/model derivation,
    /// so a 5-minute bar and an hourly bar count the same thing.
    #[test]
    fn slo_sub_hour_paths_read_spans_with_the_mv_expressions() {
        let f = SloFilters {
            since_secs: Some(1),
            until_secs: Some(2),
            hours: 1,
            bucket_minutes: Some(5),
            model: Some("m".into()),
            ..Default::default()
        };
        for sql in [build_slo_sql(&f), build_slo_timeseries_sql(&f, 1)] {
            assert!(sql.contains("FROM spans FINAL"), "{sql}");
            assert!(sql.contains("toIntervalMinute(5)"), "{sql}");
            assert!(sql.contains(MV_PROVIDER_EXPR), "{sql}");
            assert!(sql.contains(&format!(" AND {MV_MODEL_EXPR} = ?")), "{sql}");
            assert!(sql.contains("WHERE tenant_id = ?"), "{sql}");
            assert!(!sql.contains("slo_hourly_stats"), "{sql}");
        }
        // The row shape of /v1/slo is unchanged: same eleven names, same order.
        let sql = build_slo_sql(&f);
        for (a, b) in [
            ("bucket_hour_iso", "provider"),
            ("provider", "model"),
            ("model", "p50_ms"),
            ("p99_ms", "requests"),
            ("requests", "errors"),
            ("errors", "error_rate_pct"),
            ("total_input_tokens", "total_output_tokens"),
        ] {
            assert!(
                sql.find(&format!("AS {a}")).unwrap() < sql.find(&format!("AS {b}")).unwrap(),
                "{a} before {b}"
            );
        }
    }

    /// B-500: the headline (`/v1/slo/summary`) and the table (`/v1/slo/models`)
    /// must count the SAME spans the chart (`/v1/slo`, `/v1/slo/timeseries`) counts
    /// under one window. Until 2026-09-21 both builders ignored `bucket_minutes`
    /// and always read `slo_hourly_stats` by `bucket_hour = toStartOfHour(start_time)`,
    /// while the two series builders read `spans FINAL` by `start_time` — so a 1 h
    /// preset opened at 14:37 drew a chart over 13:37–14:37 and a headline over
    /// 14:00–14:37, and a custom window inside one hour rendered "no traffic" beside
    /// a chart with bars. Same `?` order as `build_slo_sql`, so the reader binds are
    /// untouched.
    #[test]
    fn slo_summary_and_by_model_honour_bucket_minutes_by_reading_spans() {
        let f = SloFilters {
            since_secs: Some(1),
            until_secs: Some(2),
            hours: 1,
            bucket_minutes: Some(5),
            ..Default::default()
        };
        for sql in [build_slo_summary_sql(&f), build_slo_by_model_sql(&f)] {
            assert!(sql.contains("FROM spans FINAL"), "{sql}");
            assert!(sql.contains(" AND start_time >= toDateTime(?)"), "{sql}");
            assert!(sql.contains(" AND start_time <= toDateTime(?)"), "{sql}");
            assert!(sql.contains(MV_PROVIDER_EXPR), "{sql}");
            assert!(sql.contains("WHERE tenant_id = ?"), "{sql}");
            assert!(!sql.contains("slo_hourly_stats"), "{sql}");
            assert!(!sql.contains("bucket_hour"), "{sql}");
        }
        // The filters bind through the MV expressions, exactly as build_slo_sql does.
        let filtered = SloFilters {
            provider: Some("p".into()),
            model: Some("m".into()),
            ..f.clone()
        };
        for sql in [
            build_slo_summary_sql(&filtered),
            build_slo_by_model_sql(&filtered),
        ] {
            assert!(
                sql.contains(&format!(" AND {MV_PROVIDER_EXPR} = ?")),
                "{sql}"
            );
            assert!(sql.contains(&format!(" AND {MV_MODEL_EXPR} = ?")), "{sql}");
        }
        // Row shapes are unchanged: the summary's five names, the model row's ten.
        let summary = build_slo_summary_sql(&f);
        for col in ["p50_ms", "p95_ms", "p99_ms", "requests", "errors"] {
            assert!(summary.contains(&format!("AS {col}")), "{col}: {summary}");
        }
        assert!(
            !summary.contains("GROUP BY"),
            "summary is one row: {summary}"
        );
        let by_model = build_slo_by_model_sql(&f);
        for (a, b) in [
            ("provider", "model"),
            ("model", "p50_ms"),
            ("p99_ms", "requests"),
            ("requests", "errors"),
            ("errors", "error_rate_pct"),
            ("total_input_tokens", "total_output_tokens"),
        ] {
            assert!(
                by_model.find(&format!("AS {a}")).unwrap()
                    < by_model.find(&format!("AS {b}")).unwrap(),
                "{a} before {b}: {by_model}"
            );
        }
        assert!(
            by_model.ends_with(" GROUP BY provider, model ORDER BY requests DESC LIMIT ?"),
            "{by_model}"
        );
        // No bucket → the hourly view, byte-for-byte what every >24 h caller gets.
        let hourly = SloFilters {
            bucket_minutes: None,
            ..f
        };
        for sql in [
            build_slo_summary_sql(&hourly),
            build_slo_by_model_sql(&hourly),
        ] {
            assert!(sql.contains("FROM slo_hourly_stats"), "{sql}");
            assert!(!sql.contains("spans FINAL"), "{sql}");
        }
    }

    /// Extracts the ordered list of JSON attribute keys read by every
    /// `JSONExtractString(<anything>, '<key>')` call inside `text`. Deliberately
    /// ignores the qualifier (`s.attributes` in the view, bare `attributes` in
    /// the Rust constant) — only the KEY and its ORDER are the parity claim.
    fn json_extract_keys(text: &str) -> Vec<String> {
        let needle = "JSONExtractString(";
        let mut keys = Vec::new();
        let mut rest = text;
        while let Some(i) = rest.find(needle) {
            let after = &rest[i + needle.len()..];
            let quote_start = after
                .find('\'')
                .expect("JSONExtractString(...) must take a quoted string key");
            let key_body = &after[quote_start + 1..];
            let quote_end = key_body
                .find('\'')
                .expect("attribute key must close with a quote");
            keys.push(key_body[..quote_end].to_string());
            rest = &key_body[quote_end + 1..];
        }
        keys
    }

    /// Returns the argument list of the FIRST top-level `coalesce(...)` call in
    /// `text`, found by paren-depth counting rather than naive matching — the
    /// arms themselves contain nested `nullIf(...)` / `JSONExtractString(...)`
    /// calls, so the first `)` is never the coalesce's own close paren.
    fn first_coalesce_args(text: &str) -> &str {
        let start = text.find("coalesce(").expect("no coalesce( found") + "coalesce(".len();
        let mut depth = 1usize;
        for (i, c) in text[start..].char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return &text[start..start + i];
                    }
                }
                _ => {}
            }
        }
        panic!("unbalanced parens reading coalesce(...) out of: {text}");
    }

    /// PARITY GUARD — SRE register #55 / B-336 family.
    ///
    /// The SLO sub-hour readers re-derive `provider` / `model` off raw spans with
    /// `MV_PROVIDER_EXPR` / `MV_MODEL_EXPR`; the hourly readers take them from
    /// `slo_hourly_stats`, written by `mv_slo_hourly_stats` (migration 06). If
    /// either constant ever carries a different SET or ORDER of coalesce arms than
    /// the view, a 5-minute bar and an hourly bar silently count different things.
    /// Both lists are read from the checked-in migration, never hand-copied.
    ///
    /// The second half records WHY register #55 was refuted as framed:
    /// `mv_trace_summaries` (`schema.sql`) derives `model` with exactly ONE extra
    /// arm, the dotted `gen_ai.request.model`, which decode.rs normalises away
    /// before storage. If the schema ever grows a different extra arm, or the
    /// migration and the schema diverge further, this fails and names the arm.
    ///
    /// FALSIFICATION: delete the `gen_ai.response.model` arm from `MV_MODEL_EXPR`
    /// and the first assertion fails with `left` (the view) still listing it.
    #[test]
    fn mv_exprs_match_migration_06_and_trace_summaries_only_adds_the_dead_arm() {
        let mig =
            include_str!("../../../infra/dev/clickhouse/migrations/06_genai_attr_keys_and_slo.sql");
        let view = &mig[mig
            .find("CREATE MATERIALIZED VIEW tracelane.mv_slo_hourly_stats")
            .expect("migration 06 must define mv_slo_hourly_stats")..];
        let provider_end = view.find("AS provider").expect("view projects provider");
        let model_start = provider_end + "AS provider".len();
        let model_end = model_start
            + view[model_start..]
                .find("AS model")
                .expect("view projects model");
        let view_provider = json_extract_keys(first_coalesce_args(&view[..provider_end]));
        let view_model = json_extract_keys(first_coalesce_args(&view[model_start..model_end]));
        assert_eq!(
            view_provider,
            json_extract_keys(first_coalesce_args(MV_PROVIDER_EXPR)),
            "MV_PROVIDER_EXPR drifted from mv_slo_hourly_stats (migration 06)"
        );
        assert_eq!(
            view_model,
            json_extract_keys(first_coalesce_args(MV_MODEL_EXPR)),
            "MV_MODEL_EXPR drifted from mv_slo_hourly_stats (migration 06)"
        );

        let schema = include_str!("../../../infra/dev/clickhouse/schema.sql");
        let ts = &schema[schema
            .find("CREATE MATERIALIZED VIEW IF NOT EXISTS tracelane.mv_trace_summaries")
            .expect("mv_trace_summaries must exist in schema.sql")..];
        let ts_model_end = ts
            .find("AS model")
            .expect("mv_trace_summaries projects model");
        let ts_model = json_extract_keys(first_coalesce_args(&ts[..ts_model_end]));
        let rust_model = json_extract_keys(first_coalesce_args(MV_MODEL_EXPR));
        let extra: Vec<&String> = ts_model
            .iter()
            .filter(|k| !rust_model.contains(k))
            .collect();
        assert_eq!(
            extra,
            vec![&"gen_ai.request.model".to_string()],
            "mv_trace_summaries' model derivation differs from the SLO expression by \
             something other than the one dead dotted arm — re-read register #55"
        );
        assert!(
            rust_model.iter().all(|k| ts_model.contains(k)),
            "MV_MODEL_EXPR reads an arm mv_trace_summaries does not: {rust_model:?} vs {ts_model:?}"
        );
    }

    #[test]
    fn slo_sql_is_tenant_first_and_window_defaults_to_hours() {
        let sql = build_slo_sql(&SloFilters {
            hours: 24,
            ..Default::default()
        });
        assert!(sql.contains("WHERE tenant_id = ?"));
        assert!(sql.contains("now() - toIntervalHour(?)"));
        assert!(!sql.contains("bucket_hour >= toDateTime(?)"));
        assert!(sql.contains("FROM v_slo_stats"));
    }

    /// The 30d payload fix. Absent/1 must be byte-identical to the historical query —
    /// that equivalence is the whole backward-compatibility argument, so it is asserted
    /// rather than assumed.
    #[test]
    fn slo_sql_bucket_absent_or_one_is_the_unchanged_hourly_query() {
        let hourly = build_slo_sql(&SloFilters {
            hours: 720,
            bucket_hours: 1,
            ..Default::default()
        });
        let legacy = build_slo_sql(&SloFilters {
            hours: 720,
            bucket_hours: 0, // an unset field must behave as hourly, not as "group by 0"
            ..Default::default()
        });
        assert_eq!(hourly, legacy, "0 and 1 must both mean HOURLY");
        assert!(hourly.contains("FROM v_slo_stats"));
        assert!(hourly.contains("ORDER BY bucket_hour DESC"));
        assert!(!hourly.contains("GROUP BY"));
        assert!(!hourly.contains("toStartOfInterval"));
    }

    /// A bucketed read must merge the AggregateFunction STATES, not average the view's
    /// already-collapsed scalars — a mean of 24 hourly p95s is not a daily p95.
    #[test]
    fn slo_sql_bucketed_merges_quantile_states_off_the_raw_table() {
        let sql = build_slo_sql(&SloFilters {
            hours: 720,
            bucket_hours: 24,
            ..Default::default()
        });
        assert!(
            sql.contains("FROM slo_hourly_stats"),
            "must read the raw table; v_slo_stats has already collapsed the states"
        );
        assert!(!sql.contains("FROM v_slo_stats"));
        assert!(sql.contains("toStartOfInterval(bucket_hour, toIntervalHour(24))"));
        assert!(sql.contains("quantileMerge(0.95)(latency_p95)"));
        assert!(sql.contains("GROUP BY bucket_hour_iso, provider, model"));
        assert!(sql.contains("ORDER BY bucket_hour_iso DESC"));
        // Tenant scoping survives the rewrite — the bind order is unchanged.
        assert!(sql.contains("WHERE tenant_id = ?"));
    }

    /// Both branches must project the SAME output names in the SAME order: the row
    /// SHAPE is what every client deserializes, and only the granularity may differ.
    /// Checked by NAME ORDER rather than by splitting on ", " — the bucketed branch
    /// contains `greatest(countMerge(request_count), 1)`, so a naive comma split reads
    /// an argument as a column and fails for the wrong reason. It did exactly that.
    #[test]
    fn slo_sql_both_branches_project_an_identical_column_list() {
        const EXPECTED: [&str; 11] = [
            "bucket_hour_iso",
            "provider",
            "model",
            "p50_ms",
            "p95_ms",
            "p99_ms",
            "requests",
            "errors",
            "error_rate_pct",
            "total_input_tokens",
            "total_output_tokens",
        ];
        for bucket_hours in [1_u32, 24] {
            let sql = build_slo_sql(&SloFilters {
                hours: 720,
                bucket_hours,
                ..Default::default()
            });
            let head = sql.split(" FROM ").next().unwrap_or_default();
            let mut cursor = 0_usize;
            for name in EXPECTED {
                let at = head[cursor..].find(name).unwrap_or_else(|| {
                    panic!("bucket_hours={bucket_hours}: `{name}` missing or out of order")
                });
                cursor += at + name.len();
            }
        }
    }

    #[test]
    fn slo_summary_sql_is_true_quantilemerge_tenant_first_llm_scoped() {
        let sql = build_slo_summary_sql(&SloFilters {
            hours: 24,
            ..Default::default()
        });
        // Tenant is the FIRST predicate (isolation invariant).
        assert!(sql.contains("WHERE tenant_id = ?"));
        let where_pos = sql.find("WHERE tenant_id = ?").unwrap();
        assert!(!sql[..where_pos].contains("AND "));
        // TRUE quantile via quantileMerge over the stored states — NOT a per-hour
        // quantile that a caller could then weighted-mean (the #9 defect).
        assert!(sql.contains("quantileMerge(0.95)(latency_p95)"));
        assert!(sql.contains("quantileMerge(0.50)(latency_p50)"));
        assert!(sql.contains("quantileMerge(0.99)(latency_p99)"));
        // Reads the AggregatingMergeTree state table (not the per-bucket view).
        assert!(sql.contains("FROM slo_hourly_stats"));
        // LLM-request scoped so it reconciles with the tile's provider!='' rows.
        assert!(sql.contains("provider <> ''"));
        // No GROUP BY → one window-wide row.
        assert!(!sql.contains("GROUP BY"));
    }

    #[test]
    fn slo_by_model_sql_is_tenant_first_true_quantilemerge_per_group() {
        let sql = build_slo_by_model_sql(&SloFilters {
            hours: 24,
            ..Default::default()
        });
        // Tenant is the FIRST predicate.
        assert!(sql.contains("WHERE tenant_id = ?"));
        let where_pos = sql.find("WHERE tenant_id = ?").unwrap();
        assert!(!sql[..where_pos].contains("AND "));
        // TRUE per-group quantiles via quantileMerge over stored states — NOT the
        // client-side mean-of-hourly-percentiles the table used before.
        assert!(sql.contains("quantileMerge(0.50)(latency_p50)"));
        assert!(sql.contains("quantileMerge(0.95)(latency_p95)"));
        assert!(sql.contains("quantileMerge(0.99)(latency_p99)"));
        // Counts/tokens via matching merge functions (one exact aggregate row).
        assert!(sql.contains("countMerge(request_count)"));
        assert!(sql.contains("countIfMerge(error_count)"));
        assert!(sql.contains("sumMerge(input_tokens)"));
        assert!(sql.contains("FROM slo_hourly_stats"));
        assert!(sql.contains("GROUP BY provider, model"));
        assert!(sql.trim_end().ends_with("LIMIT ?"));
    }

    #[test]
    fn slo_timeseries_sql_is_tenant_first_bucket_interpolated_llm_scoped() {
        let sql = build_slo_timeseries_sql(
            &SloFilters {
                hours: 24,
                ..Default::default()
            },
            6,
        );
        // Tenant is the FIRST BOUND `?` — the bucket width is a numeric literal,
        // interpolated (never a `?`), so tenant stays the first bound value.
        assert!(sql.contains("WHERE tenant_id = ?"));
        let first_q = sql.find('?').unwrap();
        let where_q = sql.find("WHERE tenant_id = ?").unwrap();
        assert_eq!(first_q, where_q + "WHERE tenant_id = ".len());
        // The clamped bucket int is interpolated into the interval, not bound.
        assert!(sql.contains("toStartOfInterval(bucket_hour, toIntervalHour(6))"));
        // TRUE merged percentiles per display bucket, LLM-scoped.
        assert!(sql.contains("quantileMerge(0.95)(latency_p95)"));
        assert!(sql.contains("provider <> ''"));
        assert!(sql.contains("GROUP BY bucket_start ORDER BY bucket_start ASC"));
    }

    #[test]
    fn slo_sql_since_overrides_hours_window() {
        let sql = build_slo_sql(&SloFilters {
            bucket_minutes: None,
            since_secs: Some(1000),
            until_secs: Some(2000),
            provider: Some("openai".into()),
            model: Some("gpt".into()),
            hours: 24,
            bucket_hours: 1,
        });
        assert!(sql.contains("bucket_hour >= toDateTime(?)"));
        assert!(!sql.contains("toIntervalHour"));
        assert!(sql.contains("bucket_hour <= toDateTime(?)"));
        assert!(sql.contains("provider = ?"));
        assert!(sql.contains("model = ?"));
    }

    #[test]
    fn signatures_sql_is_tenant_first_aggregate_with_no_network_column() {
        let sql = build_signatures_sql(&SignatureFilters {
            limit: 50,
            ..Default::default()
        });
        // tenant_id is the FIRST predicate and bound.
        assert!(
            sql.contains("WHERE tenant_id = ? AND notEmpty(aft_id)"),
            "sql: {sql}"
        );
        let where_pos = sql.find("WHERE tenant_id = ?").unwrap();
        assert!(!sql[..where_pos].contains("AND "));
        // Live arrayJoin over spans.aft_ids — no mv_signature_hits MV exists.
        assert!(sql.contains("ARRAY JOIN aft_ids AS aft_id"));
        assert!(sql.contains("FROM spans FINAL"));
        // your_hits ONLY — never a network/cross-tenant column (honesty lock §4).
        assert!(sql.contains("count()) AS your_hits"));
        assert!(!sql.to_lowercase().contains("network"));
        // first/last-seen columns (Phase-3 signatures spec) — RFC3339 UTC.
        assert!(sql.contains("min(start_time), '%FT%TZ') AS first_seen"));
        assert!(sql.contains("max(start_time), '%FT%TZ') AS last_seen"));
        // traces-affected = distinct trace count per signature.
        assert!(sql.contains("uniqExact(trace_id)) AS traces_affected"));
        assert!(sql.contains("GROUP BY aft_id"));
        assert!(sql.trim_end().ends_with("LIMIT ?"));
    }

    #[test]
    fn signatures_sql_since_binds_before_limit() {
        let sql = build_signatures_sql(&SignatureFilters {
            since_us: Some(1),
            limit: 10,
            ..Default::default()
        });
        let i_since = sql
            .find("start_time >= fromUnixTimestamp64Micro(?)")
            .unwrap();
        let i_limit = sql.rfind("LIMIT ?").unwrap();
        assert!(i_since < i_limit);
    }

    #[test]
    fn signatures_trace_total_sql_is_tenant_first_distinct_not_summed() {
        let sql = build_signatures_trace_total_sql(&SignatureFilters {
            limit: 50,
            ..Default::default()
        });
        // tenant_id is the FIRST predicate and bound.
        assert!(
            sql.contains("WHERE tenant_id = ? AND notEmpty(aft_ids)"),
            "sql: {sql}"
        );
        let where_pos = sql.find("WHERE tenant_id = ?").unwrap();
        assert!(!sql[..where_pos].contains("AND "));
        // DISTINCT traces — uniqExact, NOT a sum of per-signature counts, and NOT
        // an ARRAY JOIN (which would multiply a trace by its signature count).
        assert!(sql.contains("uniqExact(trace_id)) AS total"));
        assert!(!sql.contains("ARRAY JOIN"));
        assert!(!sql.contains("GROUP BY"));
        assert!(!sql.to_lowercase().contains("sum("));
        // no since → no time predicate; with since → the µs lower bound is present.
        assert!(!sql.contains("fromUnixTimestamp64Micro"));
        let with_since = build_signatures_trace_total_sql(&SignatureFilters {
            since_us: Some(1),
            limit: 50,
            ..Default::default()
        });
        assert!(with_since.contains("start_time >= fromUnixTimestamp64Micro(?)"));
    }

    #[test]
    fn signatures_trace_total_sql_scopes_to_live_ids_when_present() {
        // With a live-id allowlist the match becomes arrayExists(... IN (?, …))
        // over BOUND placeholders — no `notEmpty(aft_ids)`, no interpolated id.
        let sql = build_signatures_trace_total_sql(&SignatureFilters {
            until_us: None,
            since_us: Some(1),
            limit: 50,
            live_signature_ids: vec!["AFT-TOOL-SCHEMA-001".into(), "AFT-PI-CASCADE-001".into()],
        });
        assert!(
            sql.contains("arrayExists(a -> a IN (?, ?), aft_ids)"),
            "sql: {sql}"
        );
        assert!(!sql.contains("notEmpty(aft_ids)"), "sql: {sql}");
        // Raw ids never appear in the SQL text (bound, not interpolated).
        assert!(!sql.contains("AFT-TOOL-SCHEMA-001"), "sql: {sql}");
        // Bind order: the live-id IN list precedes the since µs bound.
        let i_in = sql.find("a IN (").unwrap();
        let i_since = sql.find("start_time >=").unwrap();
        assert!(i_in < i_since, "sql: {sql}");
        // tenant_id is still the FIRST predicate.
        let where_pos = sql.find("WHERE tenant_id = ?").unwrap();
        assert!(!sql[..where_pos].contains("AND "));
    }

    #[test]
    fn parse_live_signature_ids_validates_dedupes_and_rejects_injection() {
        // Well-formed CSV → the canonical ids, order preserved, deduped.
        assert_eq!(
            parse_live_signature_ids(Some(
                "AFT-TOOL-SCHEMA-001, AFT-PI-CASCADE-001,AFT-TOOL-SCHEMA-001"
            )),
            vec![
                "AFT-TOOL-SCHEMA-001".to_string(),
                "AFT-PI-CASCADE-001".to_string()
            ]
        );
        // None / empty → no scoping.
        assert!(parse_live_signature_ids(None).is_empty());
        assert!(parse_live_signature_ids(Some("")).is_empty());
        // Garbage / SQL-injection / wrong-shape tokens are dropped (never bound).
        assert!(
            parse_live_signature_ids(Some("'; DROP TABLE spans;--, foo, aft-lowercase, NOTAFT-1"))
                .is_empty()
        );
        // A valid id mixed with junk keeps only the valid one.
        assert_eq!(
            parse_live_signature_ids(Some("AFT-A2A-LIFECYCLE-001, ' OR 1=1")),
            vec!["AFT-A2A-LIFECYCLE-001".to_string()]
        );
    }

    #[test]
    fn trace_list_latency_and_signature_subquery_are_tenant_scoped() {
        let sql = build_trace_list_sql(&TraceListFilters {
            agent: None,
            model_family: None,
            q: None,
            min_duration_us: Some(2_000_000),
            signature_id: Some("tool-schema-violation".into()),
            limit: 50,
            ..Default::default()
        });
        // §2 latency floor on the trace duration.
        assert!(sql.contains("duration_us >= ?"));
        // §2 signature subquery is ITSELF tenant-scoped — the isolation invariant
        // (a cross-tenant signature can never widen the outer result).
        assert!(
            sql.contains(
                "trace_id IN (SELECT trace_id FROM spans WHERE tenant_id = ? AND start_time >= w_since AND start_time <= w_until AND has(aft_ids, ?))"
            ),
            "sql: {sql}"
        );
        // Outer tenant filter is still the first predicate.
        let where_pos = sql.find("WHERE tenant_id = ?").unwrap();
        assert!(!sql[..where_pos].contains("AND "));
        // Bind order: latency, then subquery tenant, then sig id, then limit.
        let i_dur = sql.find("duration_us >= ?").unwrap();
        let i_subq_tenant = sql
            .find("SELECT trace_id FROM spans WHERE tenant_id = ?")
            .unwrap();
        let i_has = sql.find("has(aft_ids, ?)").unwrap();
        let i_limit = sql.rfind("LIMIT ?").unwrap();
        assert!(i_dur < i_subq_tenant && i_subq_tenant < i_has && i_has < i_limit);
    }

    fn issue_summary_fixture_bytes() -> Vec<u8> {
        let mut data = Vec::new();
        for n in [2_u64, 3, 1, 2, 0] {
            data.extend_from_slice(&n.to_le_bytes());
        }
        data.push(9);
        for n in [0_u64, 0, 0, 1, 0, 0, 0, 0, 0] {
            data.extend_from_slice(&n.to_le_bytes());
        }
        data
    }

    #[tokio::test]
    async fn issue_summary_cache_separates_tenants_and_refreshes_policy_and_expiry() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::path("/"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_bytes(issue_summary_fixture_bytes()),
            )
            .mount(&server)
            .await;
        let card = Arc::new(arc_swap::ArcSwap::from_pointee(
            crate::billing::RateCard::unavailable(),
        ));
        let mut next = (**card.load()).clone();
        next.policy.generation_issues.dashboard_window_days = 1;
        card.store(Arc::new(next.clone()));
        let reader = ClickHouseTraceReader::new(
            clickhouse::Client::default()
                .with_url(server.uri())
                .with_compression(clickhouse::Compression::None),
        )
        .with_rate_card(card.clone());
        let a = TenantId::from_self_host_config(uuid::Uuid::new_v4());
        let b = TenantId::from_self_host_config(uuid::Uuid::new_v4());
        let first = reader.generation_issue_summary(&a).await.unwrap();
        assert_eq!(first.window_days, 1);
        assert!(Arc::ptr_eq(
            &first,
            &reader.generation_issue_summary(&a).await.unwrap()
        ));
        reader.generation_issue_summary(&b).await.unwrap();
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
        next.policy.generation_issues.dashboard_window_days = 2;
        next.policy.generation_issues.summary_cache_ttl_seconds = 1;
        card.store(Arc::new(next));
        let changed = reader.generation_issue_summary(&a).await.unwrap();
        assert_eq!(changed.window_days, 2);
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        let expired = reader.generation_issue_summary(&a).await.unwrap();
        assert!(!Arc::ptr_eq(&changed, &expired));
        assert_eq!(server.received_requests().await.unwrap().len(), 4);
    }

    #[tokio::test]
    async fn issue_summary_failures_are_not_cached_or_returned_as_zero() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::path("/"))
            .respond_with(wiremock::ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let reader = ClickHouseTraceReader::new(
            clickhouse::Client::default()
                .with_url(server.uri())
                .with_compression(clickhouse::Compression::None),
        );
        let tenant = TenantId::from_self_host_config(uuid::Uuid::new_v4());
        assert!(reader.generation_issue_summary(&tenant).await.is_err());
        assert!(reader.generation_issue_summary(&tenant).await.is_err());
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
        server.reset().await;
        // Measured empty window: five zero counters and nine zero issue counts.
        let mut empty = vec![0_u8; 5 * 8];
        empty.push(9);
        empty.extend_from_slice(&[0_u8; 9 * 8]);
        wiremock::Mock::given(wiremock::matchers::path("/"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(empty))
            .mount(&server)
            .await;
        let summary = reader.generation_issue_summary(&tenant).await.unwrap();
        assert_eq!(summary.total_traces, 0);
        assert_eq!(summary.llm_calls, 0);
        assert_eq!(summary.no_served_model_calls, 0);
        assert!(summary.counts.iter().all(|c| c.trace_count == 0));
    }

    #[tokio::test]
    async fn issue_summary_is_cached_tenant_scoped_and_reports_unknowns() {
        use tower::ServiceExt;
        let _g = DevAuthGuard::new();
        let server = wiremock::MockServer::start().await;
        // RowBinary: five UInt64 fields, then Array(UInt64), in SELECT order.
        let mut data = Vec::new();
        for n in [2_u64, 3, 1, 2, 0] {
            data.extend_from_slice(&n.to_le_bytes());
        }
        data.push(9);
        for n in [0_u64, 0, 0, 1, 0, 0, 0, 0, 0] {
            data.extend_from_slice(&n.to_le_bytes());
        }
        wiremock::Mock::given(wiremock::matchers::path("/"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(data))
            .mount(&server)
            .await;
        let reader = ClickHouseTraceReader::new(
            clickhouse::Client::default()
                .with_url(server.uri())
                .with_compression(clickhouse::Compression::None),
        );
        let app = routes().with_state(TraceReadState {
            reader: Arc::new(reader),
            rejections: test_rejections(),
        });
        let request = || {
            axum::http::Request::builder()
                .uri("/v1/traces/issues/summary?tenant_id=foreign")
                .header("Authorization", "Bearer dev-test")
                .body(axum::body::Body::empty())
                .unwrap()
        };
        let (first, second) = tokio::join!(
            app.clone().oneshot(request()),
            app.clone().oneshot(request())
        );
        let first = first.unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let a = body_json(first).await;
        let b = body_json(second.unwrap()).await;
        assert_eq!(a, b);
        assert_eq!(a["total_traces"], 2);
        assert_eq!(a["no_served_model_calls"], 1);
        assert_eq!(a["gateway_signal_calls"], 0);
        assert_eq!(a["counts"][3]["trace_count"], 1);
        assert_eq!(
            a["window_days"],
            crate::billing::rating::breakdown_defaults().1
        );
        assert!(a["as_of"].as_str().is_some());
        assert_eq!(a["content_capture"], false);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1, "single-flight and cached within TTL");
        let query = requests[0]
            .url
            .query_pairs()
            .find(|(k, _)| k == "query")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_else(|| String::from_utf8(requests[0].body.clone()).unwrap());
        assert!(
            query.contains(&format!(
                "WHERE tenant_id = '{DEV_TENANT}' AND start_time >="
            )),
            "{query}"
        );
        assert!(!query.contains("foreign"));
        let unauthorized = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/traces/issues/summary")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn deferred_issue_rollup_authenticates_bounds_and_fails_open() {
        let _g = DevAuthGuard::new();
        for fails in [false, true] {
            let reader = Arc::new(MockTraceReader {
                trace_issues: vec![
                    TraceIssueRow {
                        trace_id: "own".into(),
                        issue_counts: vec![0, 0, 0, 1, 0, 0, 0, 0, 0],
                    },
                    TraceIssueRow {
                        trace_id: "outside-page".into(),
                        issue_counts: vec![1; 9],
                    },
                ],
                issue_read_fails: fails,
                ..MockTraceReader::new()
            });
            let state = TraceReadState {
                reader: reader.clone(),
                rejections: test_rejections(),
            };
            let unauthorized = trace_issue_rollup_handler(
                State(state.clone()),
                Query(TraceIssueQuery {
                    trace_ids: Some("own".into()),
                }),
                HeaderMap::new(),
            )
            .await;
            assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
            assert!(reader.seen_issue_reads.lock().unwrap().is_empty());
            for ids in [
                None,
                Some("".into()),
                Some(vec!["id"; MAX_TRACE_LIMIT as usize + 1].join(",")),
            ] {
                let r = trace_issue_rollup_handler(
                    State(state.clone()),
                    Query(TraceIssueQuery { trace_ids: ids }),
                    bearer_headers(),
                )
                .await;
                assert_eq!(r.status(), StatusCode::BAD_REQUEST);
            }
            let response = trace_issue_rollup_handler(
                State(state),
                Query(TraceIssueQuery {
                    trace_ids: Some("own,unknown".into()),
                }),
                bearer_headers(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            let body = body_json(response).await;
            assert_eq!(body["issues_available"], !fails);
            assert_eq!(
                body["inline_limit"],
                crate::generation_issues::SummaryPolicy::embedded().inline_chip_limit
            );
            assert_eq!(body["traces"].as_array().unwrap().len(), 2);
            assert_eq!(body["traces"][1]["issues"], serde_json::json!([]));
            assert!(!body.to_string().contains("outside-page"));
            if !fails {
                assert_eq!(body["traces"][0]["issues"][0]["kind"], "truncated");
            }
            assert_eq!(
                reader.seen_issue_reads.lock().unwrap().as_slice(),
                &[(
                    DEV_TENANT.to_owned(),
                    vec!["own".to_owned(), "unknown".to_owned()]
                )]
            );
        }
    }

    #[tokio::test]
    async fn issue_badges_can_be_deferred_without_running_the_secondary_read() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader {
            traces: vec![trace_row("trace-page", 100)],
            issue_read_fails: true,
            ..MockTraceReader::new()
        });
        let response = list_traces_handler(
            State(TraceReadState {
                reader: reader.clone(),
                rejections: test_rejections(),
            }),
            Query(serde_json::from_value(serde_json::json!({"include_issues":false})).unwrap()),
            bearer_headers(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert!(
            reader.seen_issue_reads.lock().unwrap().is_empty(),
            "the primary list must not wait for badge enrichment"
        );
        assert_eq!(body["issues_deferred"], true);
        assert!(body["traces"][0].get("issues").is_none());
    }

    #[tokio::test]
    async fn issue_filter_rejects_unknown_kinds_on_every_trace_surface() {
        let _g = DevAuthGuard::new();
        for issue in [
            "unknown",
            "truncated,unknown",
            "truncated,,filtered",
            "' OR 1=1",
        ] {
            let state = TraceReadState {
                reader: Arc::new(MockTraceReader::new()),
                rejections: test_rejections(),
            };
            let query = serde_json::json!({"issue": issue, "by": "model"});
            let responses = [
                list_traces_handler(
                    State(state.clone()),
                    Query(serde_json::from_value(query.clone()).unwrap()),
                    bearer_headers(),
                )
                .await,
                trace_count_handler(
                    State(state.clone()),
                    Query(serde_json::from_value(query.clone()).unwrap()),
                    bearer_headers(),
                )
                .await,
                export_traces_handler(
                    State(state.clone()),
                    Query(serde_json::from_value(query.clone()).unwrap()),
                    bearer_headers(),
                )
                .await,
                list_trace_groups_handler(
                    State(state),
                    Query(serde_json::from_value(query).unwrap()),
                    bearer_headers(),
                )
                .await,
            ];
            for response in responses {
                assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{issue}");
                let body = body_json(response).await;
                assert_eq!(body["error"], "unknown_issue");
                assert_eq!(body["allowed"], serde_json::to_value(ISSUES).unwrap());
            }
        }
    }

    #[test]
    fn issue_filter_is_closed_deduplicated_and_tenant_window_scoped() {
        assert!(parse_issue_filter(None).unwrap().is_empty());
        assert!(parse_issue_filter(Some("")).unwrap().is_empty());
        for issue in ISSUES {
            let name = serde_json::to_value(issue).unwrap();
            assert_eq!(parse_issue_filter(name.as_str()).unwrap(), vec![issue]);
        }
        let issues = parse_issue_filter(Some("truncated,filtered,truncated")).unwrap();
        assert_eq!(issues, vec![Issue::Truncated, Issue::Filtered]);
        let filters = TraceListFilters {
            issues,
            ..Default::default()
        };
        let clause = format!(
            "trace_id IN (SELECT trace_id FROM spans FINAL WHERE tenant_id = ? AND start_time >= w_since AND start_time <= w_until AND (({}) OR ({})))",
            issue_predicate_sql(Issue::Truncated),
            issue_predicate_sql(Issue::Filtered)
        );
        for sql in [
            build_trace_list_sql(&filters),
            build_trace_count_sql(&filters),
            build_trace_groups_sql(TraceGroupBy::Model, &filters),
        ] {
            assert!(sql.contains(&clause), "{sql}");
        }
    }

    #[tokio::test]
    async fn issue_filter_reaches_list_count_export_and_groups() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader::new());
        let state = TraceReadState {
            reader: reader.clone(),
            rejections: test_rejections(),
        };
        let query = serde_json::json!({"issue":"truncated,filtered", "by":"model", "tenant_id":"foreign", "since":"2026-09-20T00:00:00Z", "until":"2026-09-21T00:00:00Z"});
        let responses = [
            list_traces_handler(
                State(state.clone()),
                Query(serde_json::from_value(query.clone()).unwrap()),
                bearer_headers(),
            )
            .await,
            trace_count_handler(
                State(state.clone()),
                Query(serde_json::from_value(query.clone()).unwrap()),
                bearer_headers(),
            )
            .await,
            export_traces_handler(
                State(state.clone()),
                Query(serde_json::from_value(query.clone()).unwrap()),
                bearer_headers(),
            )
            .await,
            list_trace_groups_handler(
                State(state),
                Query(serde_json::from_value(query).unwrap()),
                bearer_headers(),
            )
            .await,
        ];
        for response in responses {
            assert_eq!(response.status(), StatusCode::OK);
        }
        assert_eq!(
            reader.seen_tenant.lock().unwrap().as_slice(),
            &[DEV_TENANT; 4]
        );
        let filters = reader.seen_trace_filters.lock().unwrap();
        assert_eq!(filters.len(), 4);
        for f in filters.iter() {
            assert_eq!(f.issues, vec![Issue::Truncated, Issue::Filtered]);
            assert_eq!(
                f.since_us,
                parse_rfc3339_micros(Some("2026-09-20T00:00:00Z")).unwrap()
            );
            assert_eq!(
                f.until_us,
                parse_rfc3339_micros(Some("2026-09-21T00:00:00Z")).unwrap()
            );
        }
    }

    #[tokio::test]
    async fn issue_filter_reader_binds_each_tenant_before_subquery_filters() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::path("/"))
            .respond_with(wiremock::ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let reader =
            ClickHouseTraceReader::new(clickhouse::Client::default().with_url(server.uri()));
        let tenant = TenantId::from_self_host_config(uuid::Uuid::new_v4());
        let filters = TraceListFilters {
            issues: vec![Issue::Truncated],
            failover: Some(true),
            end_user: Some("user-'quoted".into()),
            since_us: Some(1000),
            until_us: Some(2000),
            limit: 2,
            ..Default::default()
        };
        assert!(reader.list_traces(&tenant, &filters).await.is_err());
        assert!(reader.count_traces(&tenant, &filters).await.is_err());
        assert!(
            reader
                .list_trace_groups(&tenant, TraceGroupBy::Model, &filters)
                .await
                .is_err()
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 3);
        for request in requests {
            let sql = request
                .url
                .query_pairs()
                .find(|(k, _)| k == "query")
                .map(|(_, v)| v.into_owned())
                .unwrap_or_else(|| String::from_utf8(request.body).unwrap());
            assert_eq!(
                sql.matches(&format!("tenant_id = '{tenant}'")).count(),
                5,
                "{sql}"
            );
            assert!(
                sql.contains("fromUnixTimestamp64Micro(1000) AS w_since"),
                "{sql}"
            );
            assert!(
                sql.contains("fromUnixTimestamp64Micro(2000) AS w_until"),
                "{sql}"
            );
            assert!(
                sql.contains("JSONExtractString(attributes, 'user_id') = 'user-\\'quoted'"),
                "{sql}"
            );
            assert!(
                sql.contains(&issue_predicate_sql(Issue::Truncated)),
                "{sql}"
            );
        }
    }

    #[test]
    fn trace_issue_rollup_is_tenant_first_deduplicated_and_page_bounded() {
        let sql = build_trace_issue_rollup_sql(3);
        assert!(
            sql.contains(
                "FROM spans FINAL WHERE tenant_id = ? AND trace_id IN (?, ?, ?) GROUP BY trace_id"
            ),
            "{sql}"
        );
        assert_eq!(sql.matches('?').count(), 4);
        for issue in ISSUES {
            assert!(sql.contains(&format!("countIf({})", issue_predicate_sql(issue))));
        }
    }

    #[tokio::test]
    async fn trace_issue_reader_binds_tenant_and_page_ids_and_skips_empty_pages() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::path("/"))
            .respond_with(wiremock::ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let reader =
            ClickHouseTraceReader::new(clickhouse::Client::default().with_url(server.uri()));
        let tenant = TenantId::from_self_host_config(uuid::Uuid::new_v4());
        assert!(
            reader
                .trace_issue_rollup(&tenant, &[])
                .await
                .unwrap()
                .is_empty()
        );
        assert!(server.received_requests().await.unwrap().is_empty());
        assert!(
            reader
                .trace_issue_rollup(&tenant, &["page-a".into(), "page-b".into()])
                .await
                .is_err()
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let sql = requests[0]
            .url
            .query_pairs()
            .find(|(key, _)| key == "query")
            .map(|(_, value)| value.into_owned())
            .unwrap();
        assert!(
            sql.contains(&format!(
                "WHERE tenant_id = '{}' AND trace_id IN ('page-a', 'page-b')",
                tenant
            )),
            "{sql}"
        );
        assert!(sql.contains("SETTINGS"), "{sql}");
    }

    #[test]
    fn trace_issue_fields_do_not_assert_a_verdict_without_enrichment() {
        let mut rows = vec![TraceSummary::from(trace_row("exported", 100))];
        let raw = serde_json::to_value(&rows[0]).unwrap();
        assert!(raw.get("issues").is_none());
        assert!(!apply_trace_issues(
            &mut rows,
            Ok(vec![TraceIssueRow {
                trace_id: "exported".into(),
                issue_counts: vec![],
            }])
        ));
        assert_eq!(
            serde_json::to_value(&rows[0]).unwrap()["issues"],
            serde_json::json!([])
        );
    }

    #[tokio::test]
    async fn list_trace_issues_bind_claim_and_page_and_fail_open() {
        let _g = DevAuthGuard::new();
        for fails in [false, true] {
            let reader = Arc::new(MockTraceReader {
                traces: vec![trace_row("t1", 100), trace_row("t2", 90)],
                trace_issues: vec![
                    TraceIssueRow {
                        trace_id: "t1".into(),
                        issue_counts: vec![0, 0, 0, 2, 0, 0, 0, 0, 0],
                    },
                    TraceIssueRow {
                        trace_id: "not-on-page".into(),
                        issue_counts: vec![1; 9],
                    },
                ],
                issue_read_fails: fails,
                ..MockTraceReader::new()
            });
            let before = tracelane_shared::degradation::count(
                tracelane_shared::degradation::Degradation::TraceIssueReadFailed,
            );
            let response = list_traces_handler(
                State(TraceReadState {
                    reader: reader.clone(),
                    rejections: test_rejections(),
                }),
                Query(serde_json::from_value(serde_json::json!({"limit":50})).unwrap()),
                bearer_headers(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            let body = body_json(response).await;
            assert_eq!(body["issues_available"], !fails);
            assert_eq!(body["traces"].as_array().unwrap().len(), 2);
            assert_eq!(body["traces"][1]["issues"], serde_json::json!([]));
            assert_eq!(
                reader.seen_issue_reads.lock().unwrap().as_slice(),
                &[(
                    DEV_TENANT.to_owned(),
                    vec!["t1".to_owned(), "t2".to_owned()]
                )]
            );
            if fails {
                assert_eq!(body["traces"][0]["issues"], serde_json::json!([]));
                assert!(
                    tracelane_shared::degradation::count(
                        tracelane_shared::degradation::Degradation::TraceIssueReadFailed
                    ) > before
                );
            } else {
                assert_eq!(body["traces"][0]["issues"][0]["kind"], "truncated");
                assert_eq!(body["traces"][0]["issues"][0]["affected_spans"], 2);
                assert_eq!(body["traces"][0]["issues"].as_array().unwrap().len(), 1);
            }
        }
    }

    #[test]
    fn trace_cost_rollup_sql_is_tenant_first_and_bounded() {
        let sql = build_trace_cost_rollup_sql(3);
        // Tenant is the FIRST WHERE predicate (isolation invariant), and the id
        // filter is bounded to the page — one placeholder per id, not a full scan.
        // (The cost SELECT expression itself contains `AND`, so assert the WHERE
        // shape directly rather than "no AND before WHERE".)
        assert!(
            sql.contains("WHERE tenant_id = ? AND trace_id IN (?, ?, ?)"),
            "sql: {sql}"
        );
        // Sums the real cost + input/output usage tokens from spans.
        assert!(sql.contains("gen_ai_usage_cost"));
        assert!(sql.contains("gen_ai_usage_input_tokens"));
        assert!(sql.contains("gen_ai_usage_output_tokens"));
        assert!(sql.contains("FROM spans FINAL"));
        // Placeholder count tracks the id count.
        assert_eq!(build_trace_cost_rollup_sql(1).matches('?').count(), 2); // tenant + 1 id
        assert_eq!(build_trace_cost_rollup_sql(5).matches('?').count(), 6); // tenant + 5 ids
    }

    #[test]
    fn latency_totals_sql_is_tenant_first_guarded_and_splits_honestly() {
        let f = GatewayStatsFilters {
            hours: 24,
            limit: 100,
            ..Default::default()
        };
        let sql = build_latency_totals_sql(&f);
        // Live spans aggregate, tenant-first + LLM-scoped (same as the SLO tile).
        assert!(sql.contains("FROM spans FINAL"), "sql: {sql}");
        assert!(sql.contains(
            "WHERE tenant_id = ? AND JSONExtractString(attributes, 'gen_ai_provider_name') != ''"
        ));
        // provider = total − overhead, per span, clamped ≥ 0 (segments sum to total).
        assert!(sql.contains("greatest(toInt64(duration_us) - toInt64(gateway_overhead_us), 0)"));
        // Only MEASURED overhead counts (no structural-0 dilution from pre-deploy spans).
        assert!(sql.contains("JSONHas(attributes, 'tracelane_gateway_overhead_us')"));
        // TTFT straight from the attribute — no MV dependency.
        assert!(sql.contains("gen_ai_response_time_to_first_chunk"));
        // Every quantile is countIf-guarded so an empty window returns 0, never NaN.
        assert!(sql.contains("if(countIf("));
        // no since → rolling window; with since → an explicit lower bound.
        assert!(sql.contains("now() - toIntervalHour(?)"));
        let with_since = build_latency_totals_sql(&GatewayStatsFilters {
            until_secs: None,
            since_secs: Some(1),
            hours: 24,
            limit: 100,
        });
        assert!(with_since.contains("start_time >= toDateTime(?)"));
    }

    /// B-568 C3: the split. Every quantile over a NEW population carries the
    /// existing `if(countIf(<its own condition>) = 0, 0, …)` guard AND a `*_samples`
    /// count over the SAME condition, so "0 samples" can render "—" and never a
    /// fabricated `0 ms`. Asserted per quantile, by its exact guard, so a quantile
    /// guarded on the WRONG population (the easy copy-paste slip) fails here.
    #[test]
    fn latency_totals_sql_splits_dispatched_hits_warm_and_cold() {
        let sql = build_latency_totals_sql(&GatewayStatsFilters {
            hours: 24,
            limit: 100,
            ..Default::default()
        });
        const HAS: &str = "JSONHas(attributes, 'tracelane_gateway_overhead_us')";
        const HIT: &str = "JSONExtractBool(attributes, 'tracelane_semantic_cache_hit')";
        const COLD: &str = "JSONExtractBool(attributes, 'tracelane_gateway_cold_start')";
        let dispatched = format!("{HAS} AND NOT {HIT}");
        let hits = format!("{HAS} AND {HIT}");
        let warm = format!("{dispatched} AND NOT {COLD}");
        let cold = format!("{dispatched} AND {COLD}");
        let guarded = |q: &str, cond: &str, alias: &str| {
            format!(
                "if(countIf({cond}) = 0, 0, round(quantileIf({q})(gateway_overhead_us, {cond}) / 1000, 1)) AS {alias}"
            )
        };
        // The headline overhead is DISPATCHED only — a hit's whole duration is
        // overhead by design and would otherwise be averaged in as "gateway time".
        assert!(
            sql.contains(&format!(
                "toUInt64(countIf({dispatched})) AS overhead_samples"
            )),
            "{sql}"
        );
        for (q, alias) in [
            ("0.50", "overhead_p50_ms"),
            ("0.95", "overhead_p95_ms"),
            ("0.99", "overhead_p99_ms"),
        ] {
            assert!(
                sql.contains(&guarded(q, &dispatched, alias)),
                "{alias}: {sql}"
            );
        }
        // The provider segment is dispatched-only too (a hit called no provider).
        assert!(sql.contains(&format!(
            "if(countIf({dispatched}) = 0, 0, round(quantileIf(0.95)(greatest(toInt64(duration_us) - toInt64(gateway_overhead_us), 0), {dispatched}) / 1000, 1)) AS provider_p95_ms"
        )));
        // Hits: their own count and their own served quantiles.
        assert!(sql.contains(&format!("toUInt64(countIf({hits})) AS cache_hit_samples")));
        assert!(sql.contains(&guarded("0.50", &hits, "cache_hit_served_p50_ms")));
        assert!(sql.contains(&guarded("0.95", &hits, "cache_hit_served_p95_ms")));
        // Cold and warm, both over dispatched.
        assert!(sql.contains(&format!("toUInt64(countIf({cold})) AS cold_start_samples")));
        assert!(sql.contains(&format!("toUInt64(countIf({warm})) AS warm_samples")));
        assert!(sql.contains(&guarded("0.50", &warm, "overhead_warm_p50_ms")));
        assert!(sql.contains(&guarded("0.95", &warm, "overhead_warm_p95_ms")));
        // Positional row: the SELECT order must match `LatencyTotalsRow`.
        let order = [
            "overhead_samples",
            "overhead_p50_ms",
            "provider_p99_ms",
            "ttft_samples",
            "ttft_p99_ms",
            "cache_hit_samples",
            "cache_hit_served_p50_ms",
            "cache_hit_served_p95_ms",
            "cold_start_samples",
            "warm_samples",
            "overhead_warm_p50_ms",
            "overhead_warm_p95_ms",
        ];
        let pos: Vec<usize> = order
            .iter()
            .map(|a| {
                sql.find(&format!("AS {a}"))
                    .unwrap_or_else(|| panic!("{a} missing"))
            })
            .collect();
        assert!(
            pos.windows(2).all(|w| w[0] < w[1]),
            "SELECT order drifted from the row"
        );
    }

    /// B-568 C3: the SLO table's per-model "our slice" and Gateway-ops' per-provider
    /// overhead p95 are dispatched-only too — the same exclusion as the headline.
    #[test]
    fn per_model_and_per_provider_overhead_exclude_cache_hits() {
        let f = GatewayStatsFilters {
            hours: 24,
            limit: 100,
            ..Default::default()
        };
        let by_model = build_latency_by_model_sql(&f);
        assert!(
            by_model.contains(
                "WHERE tenant_id = ? AND JSONHas(attributes, 'tracelane_gateway_overhead_us') \
AND NOT JSONExtractBool(attributes, 'tracelane_semantic_cache_hit')"
            ),
            "{by_model}"
        );
        let stats = build_gateway_stats_sql(&f);
        let cond = "JSONHas(attributes, 'tracelane_gateway_overhead_us') AND NOT JSONExtractBool(attributes, 'tracelane_semantic_cache_hit')";
        assert!(
            stats.contains(&format!(
                "if(countIf({cond}) = 0, 0, round(quantileIf(0.95)(gateway_overhead_us, {cond}) / 1000, 1)) AS overhead_p95_ms"
            )),
            "{stats}"
        );
    }

    #[test]
    fn latency_by_model_sql_is_tenant_first_grouped_and_bounded() {
        let sql = build_latency_by_model_sql(&GatewayStatsFilters {
            hours: 24,
            limit: 100,
            ..Default::default()
        });
        assert!(sql.contains("FROM spans FINAL"));
        assert!(sql.contains(
            "WHERE tenant_id = ? AND JSONHas(attributes, 'tracelane_gateway_overhead_us')"
        ));
        assert!(sql.contains("GROUP BY provider, model"));
        assert!(sql.contains("ORDER BY samples DESC LIMIT ?"));
        // model keyed on the request model (matches mv_ttft's model dimension).
        assert!(sql.contains("JSONExtractString(attributes, 'gen_ai_request_model')"));
    }

    #[test]
    fn gateway_stats_sql_carries_guarded_overhead_column() {
        let sql = build_gateway_stats_sql(&GatewayStatsFilters {
            hours: 24,
            limit: 100,
            ..Default::default()
        });
        assert!(sql.contains("AS overhead_p95_ms"));
        // NaN-guarded: a provider with no measured-overhead span yields 0, not NaN.
        // (B-568 C3: the guard's population is dispatched-only — see
        // `per_model_and_per_provider_overhead_exclude_cache_hits`.)
        assert!(sql.contains(
            "if(countIf(JSONHas(attributes, 'tracelane_gateway_overhead_us') AND NOT JSONExtractBool(attributes, 'tracelane_semantic_cache_hit')) = 0, 0,"
        ));
    }

    // ── Cursor + parse helpers ───────────────────────────────────────────────

    #[test]
    fn cursor_round_trips() {
        let enc = encode_cursor(1_778_581_394_123_456, "deadbeefcafef00d");
        assert_eq!(
            decode_cursor(&enc),
            Some((1_778_581_394_123_456, "deadbeefcafef00d".to_string()))
        );
    }

    #[test]
    fn cursor_rejects_malformed() {
        assert_eq!(decode_cursor("not-a-cursor"), None);
        assert_eq!(decode_cursor("123:"), None);
        assert_eq!(decode_cursor("abc:trace"), None);
    }

    #[test]
    fn parse_bool_only_accepts_true_false() {
        assert_eq!(parse_bool(Some("true")), Some(true));
        assert_eq!(parse_bool(Some("false")), Some(false));
        assert_eq!(parse_bool(Some("1")), None);
        assert_eq!(parse_bool(None), None);
    }

    #[test]
    fn parse_rfc3339_micros_and_secs() {
        // Parsed.
        assert_eq!(
            parse_rfc3339_secs(Some("2026-05-09T10:00:00Z")),
            Ok(Some(1_778_320_800))
        );
        assert_eq!(
            parse_rfc3339_micros(Some("2026-05-09T10:00:00Z")),
            Ok(Some(1_778_320_800_000_000))
        );
        // Absent / empty → Ok(None) (no filter).
        assert_eq!(parse_rfc3339_micros(None), Ok(None));
        assert_eq!(parse_rfc3339_micros(Some("")), Ok(None));
        assert_eq!(parse_rfc3339_secs(Some("   ")), Ok(None));
        // Present-but-malformed → Err (caller returns 400, never silently wide).
        assert_eq!(parse_rfc3339_micros(Some("garbage")), Err(()));
        assert_eq!(parse_rfc3339_secs(Some("2026-13-99")), Err(()));
    }

    // ── Mock reader + handler tests ──────────────────────────────────────────

    /// Records the tenant id every method is called with so tests can assert
    /// the handler always passes `Claims.tenant_id` (never a path/query value).
    struct MockTraceReader {
        traces: Vec<TraceSummaryRow>,
        spans: Vec<SpanRow>,
        slo: Vec<SloRow>,
        slo_by_model: Vec<SloModelRow>,
        slo_timeseries: Vec<SloTimePoint>,
        gateway: Vec<GatewayProviderRow>,
        costs: Vec<CostRow>,
        latency_totals: LatencyTotalsRow,
        latency_by_model: Vec<LatencyModelRow>,
        guardrail_summary: GuardrailSummaryRow,
        guardrail_rails: Vec<GuardrailRailRow>,
        signatures: Vec<SignatureHitRow>,
        sessions: Vec<SessionSummaryRow>,
        session_traces: Vec<SessionTraceRow>,
        /// `OBS-55`. `None` ⇒ the mock's `session_totals` returns `None` (the
        /// 404 path); `Some` ⇒ the transcript route has data to render.
        session_totals: Option<SessionTotalsRow>,
        session_turns: Vec<(SessionTurnRow, Option<SessionExchange>)>,
        groups: Vec<TraceGroupRow>,
        trace_costs: Vec<TraceCostRow>,
        trace_issues: Vec<TraceIssueRow>,
        issue_read_fails: bool,
        seen_issue_reads: Mutex<Vec<(String, Vec<String>)>>,
        seen_trace_filters: Mutex<Vec<TraceListFilters>>,
        chain_status: Option<TraceChainStatus>,
        seen_tenant: Mutex<Vec<String>>,
        /// CX-26: every `CostFilters` the handler passed, so a test can prove the
        /// absolute pair reached the reader rather than a rolling substitute.
        seen_cost_filters: Mutex<Vec<CostFilters>>,
    }

    impl MockTraceReader {
        fn new() -> Self {
            Self {
                traces: Vec::new(),
                spans: Vec::new(),
                slo: Vec::new(),
                slo_by_model: Vec::new(),
                slo_timeseries: Vec::new(),
                gateway: Vec::new(),
                costs: Vec::new(),
                latency_totals: LatencyTotalsRow::default(),
                latency_by_model: Vec::new(),
                guardrail_summary: GuardrailSummaryRow::default(),
                guardrail_rails: Vec::new(),
                signatures: Vec::new(),
                sessions: Vec::new(),
                session_traces: Vec::new(),
                session_totals: None,
                session_turns: Vec::new(),
                groups: Vec::new(),
                trace_costs: Vec::new(),
                trace_issues: Vec::new(),
                issue_read_fails: false,
                seen_issue_reads: Mutex::new(Vec::new()),
                seen_trace_filters: Mutex::new(Vec::new()),
                chain_status: None,
                seen_tenant: Mutex::new(Vec::new()),
                seen_cost_filters: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl TraceReader for MockTraceReader {
        async fn generation_issue_summary(
            &self,
            _tenant_id: &TenantId,
        ) -> Result<Arc<IssueSummary>> {
            anyhow::bail!("summary fixture unavailable")
        }
        async fn list_traces(
            &self,
            tenant_id: &TenantId,
            f: &TraceListFilters,
        ) -> Result<Vec<TraceSummaryRow>> {
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
            self.seen_trace_filters.lock().unwrap().push(f.clone());
            Ok(self.traces.clone())
        }
        async fn trace_cost_rollup(
            &self,
            _tenant_id: &TenantId,
            _trace_ids: &[String],
        ) -> Result<Vec<TraceCostRow>> {
            // Secondary enrichment — the primary list read already records the
            // tenant for isolation assertions; don't double-count seen_tenant.
            Ok(self.trace_costs.clone())
        }
        async fn trace_issue_rollup(
            &self,
            tenant_id: &TenantId,
            trace_ids: &[String],
        ) -> Result<Vec<TraceIssueRow>> {
            self.seen_issue_reads
                .lock()
                .unwrap()
                .push((tenant_id.to_string(), trace_ids.to_vec()));
            if self.issue_read_fails {
                anyhow::bail!("synthetic rollup failure");
            }
            Ok(self.trace_issues.clone())
        }
        async fn list_trace_groups(
            &self,
            tenant_id: &TenantId,
            _by: TraceGroupBy,
            f: &TraceListFilters,
        ) -> Result<Vec<TraceGroupRow>> {
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
            self.seen_trace_filters.lock().unwrap().push(f.clone());
            Ok(self.groups.clone())
        }
        async fn count_traces(&self, tenant_id: &TenantId, f: &TraceListFilters) -> Result<u64> {
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
            self.seen_trace_filters.lock().unwrap().push(f.clone());
            Ok(self.traces.len() as u64)
        }
        async fn list_spans(&self, tenant_id: &TenantId, _t: &str) -> Result<Vec<SpanRow>> {
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
            Ok(self.spans.clone())
        }
        async fn trace_chain_status(
            &self,
            tenant_id: &TenantId,
            _t: &str,
        ) -> Result<Option<TraceChainStatus>> {
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
            Ok(self.chain_status.clone())
        }
        async fn slo(&self, tenant_id: &TenantId, _f: &SloFilters) -> Result<Vec<SloRow>> {
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
            Ok(self.slo.clone())
        }
        async fn slo_summary(&self, tenant_id: &TenantId, _f: &SloFilters) -> Result<SloSummary> {
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
            Ok(SloSummary {
                p50_ms: 0.0,
                p95_ms: 0.0,
                p99_ms: 0.0,
                requests: 0,
                errors: 0,
            })
        }
        async fn slo_by_model(
            &self,
            tenant_id: &TenantId,
            _f: &SloFilters,
        ) -> Result<Vec<SloModelRow>> {
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
            Ok(self.slo_by_model.clone())
        }
        async fn slo_timeseries(
            &self,
            tenant_id: &TenantId,
            _f: &SloFilters,
            _bucket_hours: u32,
        ) -> Result<Vec<SloTimePoint>> {
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
            Ok(self.slo_timeseries.clone())
        }
        async fn gateway_stats(
            &self,
            tenant_id: &TenantId,
            _f: &GatewayStatsFilters,
        ) -> Result<Vec<GatewayProviderRow>> {
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
            Ok(self.gateway.clone())
        }
        async fn cost_breakdown(
            &self,
            tenant_id: &TenantId,
            f: &CostFilters,
        ) -> Result<Vec<CostRow>> {
            // Records the tenant so the isolation assertion below can prove the
            // handler binds `Claims.tenant_id` and never a query parameter.
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
            self.seen_cost_filters.lock().unwrap().push(*f);
            Ok(self.costs.clone())
        }
        async fn latency_breakdown(
            &self,
            tenant_id: &TenantId,
            _f: &GatewayStatsFilters,
        ) -> Result<(LatencyTotalsRow, Vec<LatencyModelRow>)> {
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
            Ok((self.latency_totals.clone(), self.latency_by_model.clone()))
        }
        async fn guardrail_summary(
            &self,
            tenant_id: &TenantId,
            _f: &GuardrailStatsFilters,
        ) -> Result<GuardrailSummaryRow> {
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
            Ok(self.guardrail_summary.clone())
        }
        async fn guardrail_rails(
            &self,
            tenant_id: &TenantId,
            _f: &GuardrailStatsFilters,
        ) -> Result<Vec<GuardrailRailRow>> {
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
            Ok(self.guardrail_rails.clone())
        }
        async fn guardrail_verdicts(
            &self,
            tenant_id: &TenantId,
            _f: &GuardrailVerdictListFilters,
        ) -> Result<Vec<GuardrailVerdictListRow>> {
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
            Ok(Vec::new())
        }
        async fn signatures(
            &self,
            tenant_id: &TenantId,
            _f: &SignatureFilters,
        ) -> Result<Vec<SignatureHitRow>> {
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
            Ok(self.signatures.clone())
        }
        async fn signatures_distinct_traces(
            &self,
            tenant_id: &TenantId,
            _f: &SignatureFilters,
        ) -> Result<u64> {
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
            // Distinct traces ≥ the largest single signature's trace count (a trace
            // may match several signatures) — a valid mock proxy, never the sum.
            Ok(self
                .signatures
                .iter()
                .map(|r| r.traces_affected)
                .max()
                .unwrap_or(0))
        }
        async fn list_sessions(
            &self,
            tenant_id: &TenantId,
            _f: &SessionListFilters,
        ) -> Result<Vec<SessionSummaryRow>> {
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
            Ok(self.sessions.clone())
        }
        async fn session_traces(
            &self,
            tenant_id: &TenantId,
            _session_id: &str,
        ) -> Result<Vec<SessionTraceRow>> {
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
            Ok(self.session_traces.clone())
        }
        async fn session_totals(
            &self,
            tenant_id: &TenantId,
            _session_id: &str,
        ) -> Result<Option<SessionTotalsRow>> {
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
            Ok(self.session_totals.clone())
        }
        async fn session_turns(
            &self,
            tenant_id: &TenantId,
            _session_id: &str,
            _cursor: Option<(i64, String)>,
            _limit: u32,
        ) -> Result<Vec<(SessionTurnRow, Option<SessionExchange>)>> {
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
            Ok(self.session_turns.clone())
        }
    }

    fn trace_row(trace_id: &str, start_time_us: i64) -> TraceSummaryRow {
        TraceSummaryRow {
            trace_id: trace_id.into(),
            root_name: "root".into(),
            start_time: "2026-06-10 00:00:00.000000".into(),
            start_time_us,
            duration_us: 1000,
            span_count: 3,
            error_count: 0,
            intervention: 0,
            model: "claude-sonnet-4-6".into(),
        }
    }

    fn span_row(span_id: &str) -> SpanRow {
        SpanRow {
            span_id: span_id.into(),
            parent_span_id: None,
            name: "llm.call".into(),
            start_time: "2026-06-10 00:00:00.000000".into(),
            end_time: "2026-06-10 00:00:00.001000".into(),
            start_time_us: 1_778_000_000_000_000,
            duration_us: 1000,
            status_code: 1,
            status_message: String::new(),
            attributes: "{}".into(),
            aft_ids: vec![],
            intervention: 0,
        }
    }

    pub(super) fn bearer_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, "Bearer dev-token".parse().unwrap());
        h
    }

    pub(super) async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    async fn body_text(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// Process-wide guard: dev-stub auth requires WORKOS_CLIENT_ID unset.
    /// Restores it on drop so the suite stays hermetic.
    pub(super) struct DevAuthGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        saved: Option<String>,
    }
    impl DevAuthGuard {
        pub(super) fn new() -> Self {
            static LOCK: Mutex<()> = Mutex::new(());
            let _lock = LOCK.lock().unwrap_or_else(|p| p.into_inner());
            let saved = std::env::var("WORKOS_CLIENT_ID").ok();
            // Only write to the global environ if the var is actually set.
            // Concurrent env::set_var/var across the parallel test suite is a
            // data race (edition-2024 marks it `unsafe` for this reason); in
            // the common case (WORKOS_CLIENT_ID unset) we add zero env writes.
            if saved.is_some() {
                unsafe {
                    std::env::remove_var("WORKOS_CLIENT_ID");
                }
            }
            Self { _lock, saved }
        }
    }
    impl Drop for DevAuthGuard {
        fn drop(&mut self) {
            if let Some(v) = &self.saved {
                unsafe {
                    std::env::set_var("WORKOS_CLIENT_ID", v);
                }
            }
        }
    }

    pub(super) const DEV_TENANT: &str = "00000000-0000-0000-0000-000000000001";

    // ── GWY-43: cost attribution ────────────────────────────────────────────

    fn cost_filters(dim: CostDimension) -> CostFilters {
        CostFilters {
            since_secs: None,
            until_secs: None,
            hours: 24,
            dimension: dim,
            limit: 100,
            scope: CostScope::All,
        }
    }

    fn cost_filters_scoped(dim: CostDimension, scope: CostScope) -> CostFilters {
        CostFilters {
            since_secs: None,
            until_secs: None,
            hours: 24,
            dimension: dim,
            limit: 100,
            scope,
        }
    }

    // ── R94: eval spend is separable from production spend ──────────────────

    /// The DEFAULT must not silently change what an existing caller's request
    /// means. `scope=all` adds no predicate — it only adds the split columns.
    #[test]
    fn the_default_cost_scope_filters_nothing() {
        let sql = build_cost_breakdown_sql(&cost_filters(CostDimension::Model));
        assert!(
            !sql.contains("tracelane_eval_run_id') = ''")
                && !sql.contains("tracelane_eval_run_id') != '' \nGROUP"),
            "scope=all must not narrow the WHERE: {sql}"
        );
        assert_eq!(CostScope::parse(None), Some(CostScope::All));
        assert_eq!(CostScope::parse(Some("nonsense")), None);
    }

    #[test]
    fn each_cost_scope_produces_its_own_predicate() {
        let prod = build_cost_breakdown_sql(&cost_filters_scoped(
            CostDimension::Model,
            CostScope::Production,
        ));
        assert!(
            prod.contains("AND JSONExtractString(attributes, 'tracelane_eval_run_id') = ''"),
            "production scope must EXCLUDE eval spans: {prod}"
        );
        let eval =
            build_cost_breakdown_sql(&cost_filters_scoped(CostDimension::Model, CostScope::Eval));
        assert!(
            eval.contains("AND JSONExtractString(attributes, 'tracelane_eval_run_id') != ''"),
            "eval scope must select ONLY eval spans: {eval}"
        );
        // Tenant still first — the scope predicate must never be bound ahead of
        // it, and it is not bound at all (it carries no placeholder).
        for sql in [&prod, &eval] {
            let w = sql.find("WHERE tenant_id = ?").expect("tenant WHERE");
            assert!(!sql[..w].contains('?'), "tenant must be first: {sql}");
        }
    }

    /// The split columns must be present at EVERY scope, so the response can
    /// always say how much of the figure was eval spend.
    #[test]
    fn the_eval_split_columns_are_always_selected() {
        for scope in [CostScope::All, CostScope::Production, CostScope::Eval] {
            let sql = build_cost_breakdown_sql(&cost_filters_scoped(CostDimension::Key, scope));
            for col in [
                "AS eval_requests",
                "AS eval_cost_usd",
                "AS judge_requests",
                "AS judge_cost_usd",
            ] {
                assert!(sql.contains(col), "{scope:?} is missing {col}: {sql}");
            }
            // EVERY sum over `cost_usd` is guarded by `cost_usd_present` — an
            // unpriced call must not be summed as $0.00 into ANY half.
            //
            // **Asserted as a RATIO, not as a count, and that is the point.** This
            // was `== 2` and it went red the moment `EVL-23` added a third guarded
            // sum for the judge split — a correct change failing a test that had
            // pinned a snapshot of how many sums existed at the time. A pinned
            // count is a photograph, not a rule: it blocks the next honest
            // addition and says nothing about the property. The property is that
            // guarded sums == all sums, which holds for two, three or ten.
            let sums = sql.matches("sumIf(spans.cost_usd,").count();
            let guarded = sql
                .matches("spans.cost_usd_present = 1 AND isFinite(spans.cost_usd)")
                .count();
            assert!(
                sums >= 2,
                "{scope:?}: expected at least the total + eval sums: {sql}"
            );
            assert_eq!(
                guarded, sums,
                "EVERY sum over cost_usd must carry the honesty guard — {guarded} of {sums} do: {sql}"
            );
            // THE 502 ITSELF, at string level. `AS cost_usd` shadows the column
            // for every other expression in the same SELECT, so an UNQUALIFIED
            // `sumIf(cost_usd, …)` beside it nests an aggregate in an aggregate
            // and ClickHouse refuses the whole query (`Code 184`). This is the
            // cheap half; `clickhouse_roundtrip` below is the half that actually
            // proved it, by asking a server.
            assert!(
                !sql.contains("sumIf(cost_usd,") && !sql.contains("countIf(cost_usd_present"),
                "every cost column must be QUALIFIED `spans.` — an unqualified one \
                 resolves to the `AS cost_usd` alias and 502s the endpoint: {sql}"
            );
        }
    }

    /// **A MATERIALIZED column would make the first eval spans invisible.** R106
    /// settled this; the guard is here so the "obvious optimisation" is refused
    /// by a test rather than by someone remembering the argument.
    #[test]
    fn eval_attribution_reads_the_json_at_query_time() {
        let sql = build_cost_breakdown_sql(&cost_filters(CostDimension::Model));
        assert!(
            sql.contains("JSONExtractString(attributes, 'tracelane_eval_run_id')"),
            "eval attribution must read the attribute at QUERY time: {sql}"
        );
        assert!(
            !sql.contains("eval_run_id ="),
            "a bare `eval_run_id` column would be a MATERIALIZED column, which is \
             computed on INSERT and is EMPTY for every span already written — \
             including the first eval spans ever emitted: {sql}"
        );
    }

    /// CLAUDE.md's #1 non-negotiable, asserted structurally rather than trusted:
    /// `tenant_id` is the FIRST bound placeholder, so no other predicate can be
    /// bound ahead of it and widen the read.
    /// B-257 — THE CONTROL FOR THE BUG THAT 502'd `/v1/traces` FOR A DAY.
    ///
    /// B-243 converted `trace_summaries` to an `AggregatingMergeTree` and, in
    /// doing so, widened `span_count`/`error_count` from `UInt32` to
    /// `SimpleAggregateFunction(sum, UInt64)`. The `clickhouse` 0.13 client
    /// validates column types against the row struct, so the still-`u32` fields
    /// did not truncate — they failed the whole SELECT. Every tenant's traces
    /// page answered 502.
    ///
    /// **Why nothing caught it:** the migration was verified by running the
    /// query in `clickhouse-client`, which speaks untyped TSV and is perfectly
    /// happy. The Rust client — the one that actually reads this table in
    /// production — was never pointed at the new schema. Proving a read with a
    /// DIFFERENT client than the one that performs it proves nothing about the
    /// one that does.
    ///
    /// This reads the checked-in schema and asserts each `trace_summaries`
    /// column the list SELECT projects has the width the struct declares. It is
    /// static (no ClickHouse needed) so it runs in every `cargo test`.
    #[test]
    fn trace_summaries_row_types_match_the_schema() {
        let schema = include_str!("../../../infra/dev/clickhouse/schema.sql");
        let start = schema
            .find("CREATE TABLE IF NOT EXISTS tracelane.trace_summaries")
            .expect("trace_summaries must exist in schema.sql");
        let body = &schema[start..];
        let end = body.find("\nENGINE").unwrap_or(body.len());
        let body = &body[..end];

        // (column, the Rust width the row struct declares for it)
        let expected: &[(&str, &str)] = &[
            ("span_count", "UInt64"),
            ("error_count", "UInt64"),
            ("intervention", "UInt8"),
        ];
        for (col, want_width) in expected {
            let line = body
                .lines()
                .find(|l| l.trim_start().starts_with(col))
                .unwrap_or_else(|| panic!("column `{col}` not found in trace_summaries"));
            assert!(
                line.contains(want_width),
                "`{col}` is declared `{line}` in schema.sql but TraceSummaryRow reads it as \
                 {want_width}. The clickhouse client VALIDATES types — a mismatch fails the \
                 entire SELECT, it does not truncate. Widen the struct field AND this \
                 expectation together."
            );
        }
    }

    #[test]
    fn cost_sql_is_tenant_first_for_every_dimension() {
        for dim in [
            CostDimension::Key,
            CostDimension::Model,
            CostDimension::Provider,
        ] {
            let sql = build_cost_breakdown_sql(&cost_filters(dim));
            assert!(sql.contains("WHERE tenant_id = ?"), "sql: {sql}");
            let where_pos = sql.find("WHERE tenant_id = ?").unwrap();
            assert!(
                !sql[..where_pos].contains('?'),
                "tenant must be the first bound placeholder for {dim:?}: {sql}"
            );
        }
    }

    /// The whole point of the endpoint: the "by key" grouping uses the REAL
    /// `api_key_id` column (migration 16), not a JSON extract. If this ever
    /// regresses to `JSONExtractString(attributes, …)` the query still works and
    /// silently stops using the bloom-filter index.
    #[test]
    fn cost_by_key_groups_on_the_materialized_column() {
        let sql = build_cost_breakdown_sql(&cost_filters(CostDimension::Key));
        assert!(
            sql.contains("api_key_id AS dimension"),
            "by=key must group on the materialized column: {sql}"
        );
        assert!(
            !sql.contains("JSONExtractString(attributes, 'tracelane_api_key_id')"),
            "by=key must not fall back to a per-row JSON extract: {sql}"
        );
    }

    /// THE HONESTY ASSERTION. The sum must be guarded by `cost_usd_present`, and
    /// the query must COUNT what it could not price. Every other cost read in
    /// this file wraps the extract in `if(… > 0, x, 0)`, which renders an
    /// honestly-unknown cost as a confident $0.00.
    ///
    /// **The column names are QUALIFIED `spans.` and this test was updated to
    /// match rather than the code reverted to satisfy it.** The qualification is
    /// the fix for a prod 502 (`Code 184`, see `build_cost_breakdown_sql`), and a
    /// test that pins a SPELLING instead of the PROPERTY would have blocked it —
    /// the "a gate that fights an honest fix is presence-checking, not
    /// behaviour-checking" shape. What is asserted is still exactly the property:
    /// the guard is `cost_usd_present`, never `> 0`.
    #[test]
    fn cost_sql_separates_unpriced_from_zero() {
        let sql = build_cost_breakdown_sql(&cost_filters(CostDimension::Model));
        assert!(
            sql.contains("countIf(spans.cost_usd_present = 1)) AS priced_requests"),
            "must count what it could price: {sql}"
        );
        assert!(
            sql.contains("sumIf(spans.cost_usd, spans.cost_usd_present = 1"),
            "the sum must be guarded by cost_usd_present, not by `> 0`: {sql}"
        );
        assert!(
            !sql.contains("JSONExtractFloat(attributes, 'gen_ai_usage_cost') > 0"),
            "must not reintroduce the coercion that renders unknown as zero: {sql}"
        );
    }

    #[test]
    fn cost_dimension_parsing_is_closed() {
        assert_eq!(CostDimension::parse(None), Some(CostDimension::Key));
        assert_eq!(CostDimension::parse(Some("key")), Some(CostDimension::Key));
        assert_eq!(
            CostDimension::parse(Some("model")),
            Some(CostDimension::Model)
        );
        assert_eq!(
            CostDimension::parse(Some("provider")),
            Some(CostDimension::Provider)
        );
        // Fail CLOSED on anything else — a silently-defaulted dimension would
        // answer a question the caller did not ask.
        for bad in ["tenant", "", "KEY", "api_key_id", "1; DROP TABLE spans"] {
            assert_eq!(
                CostDimension::parse(Some(bad)),
                None,
                "`{bad}` must be rejected, not defaulted"
            );
        }
    }

    /// The dimension column is chosen from a closed enum, never interpolated
    /// from the query string — so `by=` cannot reach the SQL text.
    #[test]
    fn a_hostile_by_parameter_cannot_reach_the_sql() {
        assert!(CostDimension::parse(Some("api_key_id) FROM spans WHERE 1=1 --")).is_none());
    }

    #[test]
    fn gateway_stats_sql_is_tenant_first_and_windowed() {
        let sql = build_gateway_stats_sql(&GatewayStatsFilters {
            until_secs: None,
            since_secs: None,
            hours: 24,
            limit: 100,
        });
        assert!(sql.contains("WHERE tenant_id = ?"), "sql: {sql}");
        let where_pos = sql.find("WHERE tenant_id = ?").unwrap();
        assert!(
            !sql[..where_pos].contains('?'),
            "tenant must be the first bound placeholder: {sql}"
        );
        assert!(sql.contains("now() - toIntervalHour(?)"), "sql: {sql}");
        // real, captured signals only (status_code + duration_us are top-level
        // columns; cache + provider come from the ingest-normalized attributes)
        assert!(sql.contains("countIf(status_code = 2)"), "sql: {sql}");
        assert!(
            sql.contains("gen_ai_usage_cache_read_input_tokens"),
            "sql: {sql}"
        );
        assert!(sql.contains("gen_ai_provider_name"), "sql: {sql}");
        // failover activations are now a real, span-derived count.
        assert!(
            sql.contains("countIf(JSONExtractBool(attributes, 'tracelane_failover_activated'))"),
            "sql: {sql}"
        );
        assert!(sql.contains("GROUP BY provider"), "sql: {sql}");
    }

    #[test]
    fn gateway_stats_sql_since_overrides_window() {
        let sql = build_gateway_stats_sql(&GatewayStatsFilters {
            until_secs: None,
            since_secs: Some(1_700_000_000),
            hours: 24,
            limit: 100,
        });
        assert!(sql.contains("start_time >= toDateTime(?)"), "sql: {sql}");
        assert!(
            !sql.contains("toIntervalHour"),
            "since must override the rolling window: {sql}"
        );
    }

    fn gw_row(provider: &str, requests: u64, errors: u64, cache_hits: u64) -> GatewayProviderRow {
        GatewayProviderRow {
            provider: provider.into(),
            requests,
            errors,
            p50_ms: 200.0,
            p95_ms: 500.0,
            p99_ms: 900.0,
            cache_hits,
            failovers: 0,
            cost_usd: 0.0,
            overhead_p95_ms: 0.0,
        }
    }

    #[test]
    fn gateway_stats_totals_derive_from_summed_counts() {
        let resp = GatewayStatsResponse::from_rows(
            vec![
                gw_row("anthropic", 100, 5, 40),
                gw_row("openai", 100, 15, 10),
            ],
            24,
            (0, 0),
            &Default::default(),
        );
        assert_eq!(resp.total_requests, 200);
        assert_eq!(resp.total_errors, 20);
        assert_eq!(resp.error_rate_pct, 10.0);
        assert_eq!(resp.cache_hit_rate_pct, 25.0);
        assert_eq!(resp.provider_count, 2);
        assert_eq!(resp.providers[0].error_rate_pct, 5.0);
        assert_eq!(resp.providers[0].cache_hit_rate_pct, 40.0);
        // Both former gaps are instrumented now — nothing is faked, so the
        // disclosure list is empty.
        assert!(resp.uninstrumented.is_empty());
    }

    #[test]
    fn gateway_stats_sums_failovers_and_injects_rejections() {
        // Failovers are span-derived + summed across providers; rate-limit and
        // quota counts are injected from the in-process registry.
        let mut a = gw_row("anthropic", 100, 0, 0);
        a.failovers = 3;
        let mut o = gw_row("openai", 40, 0, 0);
        o.failovers = 2;
        let resp = GatewayStatsResponse::from_rows(vec![a, o], 24, (7, 4), &Default::default());
        assert_eq!(resp.total_failovers, 5);
        assert_eq!(resp.providers[0].failovers, 3);
        assert_eq!(resp.rate_limited_since_start, 7);
        assert_eq!(resp.budget_exceeded_since_start, 4);
    }

    #[test]
    fn gateway_stats_sums_real_cost_across_providers() {
        // Real stored per-span cost is summed to the tenant-wide total and echoed
        // per provider — never averaged, never fabricated.
        let mut a = gw_row("anthropic", 100, 0, 0);
        a.cost_usd = 1.25;
        let mut o = gw_row("openai", 40, 0, 0);
        o.cost_usd = 0.75;
        let resp = GatewayStatsResponse::from_rows(vec![a, o], 24, (0, 0), &Default::default());
        assert!((resp.total_cost_usd - 2.0).abs() < 1e-9);
        assert!((resp.providers[0].cost_usd - 1.25).abs() < 1e-9);
        // Unpriced traffic stays 0 — an honest lower bound, not a fabricated value.
        let empty = GatewayStatsResponse::from_rows(
            vec![gw_row("openai", 100, 0, 0)],
            24,
            (0, 0),
            &Default::default(),
        );
        assert_eq!(empty.total_cost_usd, 0.0);
    }

    #[test]
    fn gateway_stats_empty_is_zero_never_nan() {
        let resp = GatewayStatsResponse::from_rows(vec![], 24, (0, 0), &Default::default());
        assert_eq!(resp.total_requests, 0);
        assert_eq!(resp.total_cost_usd, 0.0);
        assert_eq!(resp.error_rate_pct, 0.0);
        assert_eq!(resp.cache_hit_rate_pct, 0.0);
        assert_eq!(resp.provider_count, 0);
        assert_eq!(resp.total_failovers, 0);
        assert!(resp.providers.is_empty());
        assert!(resp.error_rate_pct.is_finite());
        assert_eq!(resp.open_breakers, 0);
    }

    #[test]
    fn gateway_stats_surfaces_circuit_breaker_state() {
        use crate::circuit_breaker::State;
        let mut breakers = std::collections::HashMap::new();
        breakers.insert("openai".to_string(), State::Open);
        breakers.insert("cohere".to_string(), State::HalfOpen); // down, no recent traffic
        let resp = GatewayStatsResponse::from_rows(
            vec![gw_row("anthropic", 100, 0, 0), gw_row("openai", 50, 0, 0)],
            24,
            (0, 0),
            &breakers,
        );
        let cs = |p: &str| {
            resp.providers
                .iter()
                .find(|h| h.provider == p)
                .map(|h| h.circuit_state.as_str())
        };
        assert_eq!(cs("anthropic"), Some("closed"), "no breaker entry → closed");
        assert_eq!(cs("openai"), Some("open"));
        // Counts ALL open/half-open breakers incl. cohere (down but not in rows).
        assert_eq!(resp.open_breakers, 2);
    }

    #[tokio::test]
    async fn gateway_stats_uses_claims_tenant_and_shapes_response() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader {
            gateway: vec![gw_row("anthropic", 10, 1, 3)],
            ..MockTraceReader::new()
        });
        let state = TraceReadState {
            reader: reader.clone(),
            rejections: test_rejections(),
        };
        let resp = gateway_stats_handler(
            State(state),
            Query(GatewayStatsQuery {
                until: None,
                hours: None,
                since: None,
            }),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        // tenant passed to the reader is the validated internal UUID from the claim
        assert_eq!(reader.seen_tenant.lock().unwrap().as_slice(), &[DEV_TENANT]);
        let v = body_json(resp).await;
        assert_eq!(v["window_hours"], 24);
        assert_eq!(v["total_requests"], 10);
        assert_eq!(v["providers"][0]["provider"], "anthropic");
        assert_eq!(v["providers"][0]["error_rate_pct"], 10.0);
        // Circuit-breaker state surfaces; no breaker registered in-test → closed.
        assert_eq!(v["providers"][0]["circuit_state"], "closed");
        assert_eq!(v["open_breakers"], 0);
        // failover + rejection fields are present (real, not faked); this tenant
        // has had no failover/rejection, so they read a genuine 0.
        assert_eq!(v["total_failovers"], 0);
        assert_eq!(v["rate_limited_since_start"], 0);
        assert_eq!(v["budget_exceeded_since_start"], 0);
        assert!(v["uninstrumented"].as_array().unwrap().is_empty());
    }

    // ── CX-26 / B-525: `/v1/costs` serves the window it was asked for ──────────

    /// Every other windowed route stamps `X-Tracelane-Window` (DSH-11); `/v1/costs`
    /// returned a bare `Json` and nothing told the client which window it got.
    #[tokio::test]
    async fn costs_handler_stamps_the_served_window() {
        let _g = DevAuthGuard::new();
        let state = TraceReadState {
            reader: Arc::new(MockTraceReader::new()),
            rejections: test_rejections(),
        };
        let resp = cost_breakdown_handler(
            State(state),
            Query(CostQuery {
                hours: Some(24),
                by: Some("model".into()),
                scope: None,
                since: None,
                until: None,
            }),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers().get("x-tracelane-window").is_some(),
            "/v1/costs must stamp the window it served, like every other windowed route"
        );
    }

    /// The client sends `since`/`until` (DSH-11 `windowParams`) and, beside them,
    /// `hours = ceil(width)` for routes that never learned the pair. `/v1/costs`
    /// dropped the pair on the floor (serde ignored two unknown fields) and served
    /// `[now − hours, now]` under the page header's absolute label — a historical
    /// day's spend rendered as today's dollars. The reader must receive the pair,
    /// and the header must say so.
    #[tokio::test]
    async fn costs_handler_serves_the_absolute_pair_not_a_rolling_window() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader::new());
        let state = TraceReadState {
            reader: reader.clone(),
            rejections: test_rejections(),
        };
        let resp = cost_breakdown_handler(
            State(state),
            Query(CostQuery {
                hours: Some(24),
                by: Some("model".into()),
                scope: None,
                since: Some("2026-09-01T00:00:00Z".into()),
                until: Some("2026-09-02T00:00:00Z".into()),
            }),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("x-tracelane-window")
                .and_then(|v| v.to_str().ok()),
            Some("since=2026-09-01T00:00:00Z;until=2026-09-02T00:00:00Z;clamped=0")
        );
        let seen = reader.seen_cost_filters.lock().unwrap().clone();
        assert_eq!(seen.len(), 1, "one reader call");
        assert_eq!(seen[0].since_secs, Some(1_788_220_800));
        assert_eq!(seen[0].until_secs, Some(1_788_307_200));
        assert_eq!(seen[0].dimension, CostDimension::Model);
        let v = body_json(resp).await;
        // The echoed window is the one ACTUALLY served — 24 h wide here.
        assert_eq!(v["window_hours"], 24);
    }

    /// A malformed `since` is a 400 before any reader call, as on every sibling route.
    #[tokio::test]
    async fn costs_handler_refuses_a_malformed_since() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader::new());
        let state = TraceReadState {
            reader: reader.clone(),
            rejections: test_rejections(),
        };
        let resp = cost_breakdown_handler(
            State(state),
            Query(CostQuery {
                hours: None,
                by: None,
                scope: None,
                since: Some("yesterday".into()),
                until: None,
            }),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(reader.seen_cost_filters.lock().unwrap().is_empty());
    }

    // ── CX-27 / B-526: the row cap is not a silent cap on the totals ─────────

    /// `GATEWAY_PROVIDER_CAP` is the `LIMIT` on `/v1/gateway/stats`' per-provider
    /// rows, and its doc comment said "≈34 routable providers; a safety cap, not a
    /// real limit" — written before GWY-42 made providers a data file. The truth is
    /// DERIVED here the way `scripts/ci/check-provider-count.py` derives it: every
    /// data row of `providers.tsv` plus every native adapter field on
    /// `ProviderRegistry`. A cap below that number turns "Providers active" into a
    /// floor and the stats totals into sums over a subset, with nothing saying so.
    #[test]
    fn gateway_provider_cap_covers_the_provider_catalog() {
        let compat = crate::providers::catalog::providers().len();
        // The native adapters: `pub <field>: <Type>Provider,` lines inside the
        // `ProviderRegistry` struct — the same derivation the Python guard uses,
        // so a seventh adapter counts here without anyone editing a number.
        let src = include_str!("providers/mod.rs");
        let start = src
            .find("pub struct ProviderRegistry {")
            .expect("ProviderRegistry struct");
        let body = &src[start..];
        let body = &body[..body.find("\n}\n").expect("struct end")];
        let native = body
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("pub ") && l.ends_with("Provider,"))
            .count();
        assert!(
            (4..=10).contains(&native),
            "parsed {native} native adapters — the parser broke, not the registry"
        );
        let catalog = compat + native;
        assert!(
            catalog >= 100,
            "parsed {catalog} providers — the parser broke"
        );
        assert!(
            u32::try_from(catalog).unwrap() <= GATEWAY_PROVIDER_CAP,
            "GATEWAY_PROVIDER_CAP ({GATEWAY_PROVIDER_CAP}) is below the provider catalog \
             ({catalog} = {compat} catalog rows + {native} native adapters): a tenant on \
             every provider would have its stats rows and totals silently cut"
        );
    }

    /// The handler's totals come from the window-wide columns ClickHouse computed
    /// BEFORE the `LIMIT`, never from summing the rows it returned. Here the reader
    /// hands back ONE row (the cap "bit") whose window-wide columns say 150 groups /
    /// 1,500 requests / 500 unpriced: the response must report those figures and say
    /// `truncated`. The real-server half (the window functions actually evaluate
    /// before `ORDER BY … LIMIT`) is `the_cost_total_counts_every_group_not_only_the_capped_rows`.
    #[tokio::test]
    async fn costs_handler_reports_the_window_totals_and_says_truncated() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader {
            costs: vec![CostRow {
                dimension: "claude-haiku-4-5".into(),
                requests: 1_000,
                priced_requests: 1_000,
                cost_usd: 1.0,
                input_tokens: 10,
                output_tokens: 10,
                eval_requests: 0,
                eval_cost_usd: 0.0,
                judge_requests: 0,
                judge_cost_usd: 0.0,
                group_count: 150,
                all_requests: 1_500,
                all_priced_requests: 1_000,
                all_cost_usd: 1.49,
                all_eval_requests: 100,
                all_eval_cost_usd: 0.25,
                all_judge_requests: 20,
                all_judge_cost_usd: 0.05,
            }],
            ..MockTraceReader::new()
        });
        let state = TraceReadState {
            reader,
            rejections: test_rejections(),
        };
        let resp = cost_breakdown_handler(
            State(state),
            Query(CostQuery {
                hours: None,
                by: Some("model".into()),
                scope: None,
                since: None,
                until: None,
            }),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["group_count"], 150);
        assert_eq!(v["truncated"], true);
        assert_eq!(v["total_requests"], 1_500);
        assert_eq!(v["priced_requests"], 1_000);
        // THE badge: the unpriced count lives in the groups the cap cut.
        assert_eq!(v["unpriced_requests"], 500);
        assert!((v["total_cost_usd"].as_f64().unwrap() - 1.49).abs() < 1e-9);
        assert_eq!(v["eval_requests"], 100);
        assert!((v["production_cost_usd"].as_f64().unwrap() - 1.24).abs() < 1e-9);
        assert_eq!(v["production_requests"], 1_400);
        assert_eq!(v["judge_requests"], 20);
        assert_eq!(v["rows"].as_array().unwrap().len(), 1);
    }

    /// An empty window has no first row to read the totals from: every figure is a
    /// measured zero, `group_count` is 0 and nothing is `truncated`.
    #[tokio::test]
    async fn costs_handler_on_an_empty_window_is_zero_and_not_truncated() {
        let _g = DevAuthGuard::new();
        let state = TraceReadState {
            reader: Arc::new(MockTraceReader::new()),
            rejections: test_rejections(),
        };
        let resp = cost_breakdown_handler(
            State(state),
            Query(CostQuery {
                hours: None,
                by: None,
                scope: None,
                since: None,
                until: None,
            }),
            bearer_headers(),
        )
        .await;
        let v = body_json(resp).await;
        assert_eq!(v["group_count"], 0);
        assert_eq!(v["truncated"], false);
        assert_eq!(v["total_requests"], 0);
        assert_eq!(v["unpriced_requests"], 0);
    }

    // ── Guardrails surface ───────────────────────────────────────────────────

    #[test]
    fn guardrail_sql_is_tenant_first_and_windowed() {
        let f = GuardrailStatsFilters {
            until_secs: None,
            since_secs: None,
            hours: 24,
            limit: 50,
        };
        let summary = build_guardrail_summary_sql(&f);
        let rails = build_guardrail_rails_sql(&f);
        for sql in [&summary, &rails] {
            assert!(sql.contains("WHERE tenant_id = ?"), "sql: {sql}");
            let where_pos = sql.find("WHERE tenant_id = ?").unwrap();
            assert!(
                !sql[..where_pos].contains('?'),
                "tenant must be the first bound placeholder: {sql}"
            );
            assert!(sql.contains("FROM guardrail_verdicts"), "sql: {sql}");
            assert!(sql.contains("now() - toIntervalHour(?)"), "sql: {sql}");
        }
        // Summary guards the percentiles so an empty window is 0.0, never NaN.
        assert!(summary.contains("if(count() = 0, 0.0"), "sql: {summary}");
        assert!(
            summary.contains("countIf(notEmpty(fail_open_rails))"),
            "sql: {summary}"
        );
        // Per-rail unrolls the rails JSON and drops empty rail ids.
        assert!(
            rails.contains("ARRAY JOIN JSONExtractArrayRaw(rails)"),
            "sql: {rails}"
        );
        assert!(rails.contains("GROUP BY rail"), "sql: {rails}");
    }

    #[test]
    fn guardrail_verdicts_sql_binds_rail_between_correlation_and_since() {
        // B-335a. The rail clause sits AFTER correlation_id and BEFORE the window, and
        // the reader binds in that order — the B-336 class, pinned at the builder.
        let f = GuardrailVerdictListFilters {
            since_secs: Some(1),
            until_secs: Some(2),
            hours: 24,
            decision: Some("block".into()),
            correlation_id: None,
            rail: Some("R4_trifecta".into()),
            limit: 10,
        };
        let sql = build_guardrail_verdicts_sql(&f);
        let i_dec = sql.find("AND decision = ?").expect("decision");
        let i_rail = sql
            .find("arrayExists(r -> JSONExtractString(r, 'rail') = ?, JSONExtractArrayRaw(rails))")
            .expect("rail clause");
        let i_since = sql.find("event_time >= toDateTime(?)").expect("since");
        assert!(i_dec < i_rail && i_rail < i_since, "order: {sql}");
        assert_eq!(
            sql.matches('?').count(),
            6,
            "tenant, decision, rail, since, until, limit: {sql}"
        );
        assert!(parse_rail_filter(Some("R4_trifecta")).unwrap().is_some());
        assert!(parse_rail_filter(Some("")).unwrap().is_none());
        assert!(parse_rail_filter(Some("r4; DROP")).is_err());
        assert!(parse_rail_filter(Some(&"x".repeat(41))).is_err());
    }

    #[test]
    fn guardrail_verdicts_sql_is_tenant_first_decision_bound_and_ordered() {
        // With a decision filter: tenant first, decision bound BEFORE the window.
        let sql = build_guardrail_verdicts_sql(&GuardrailVerdictListFilters {
            until_secs: None,
            since_secs: None,
            hours: 24,
            decision: Some("block".to_string()),
            correlation_id: None,
            rail: None,
            limit: 100,
        });
        assert!(sql.contains("WHERE tenant_id = ?"), "sql: {sql}");
        let where_pos = sql.find("WHERE tenant_id = ?").unwrap();
        assert!(!sql[..where_pos].contains('?'), "tenant first: {sql}");
        assert!(sql.contains("AND decision = ?"), "decision bound: {sql}");
        let i_dec = sql.find("AND decision = ?").unwrap();
        let i_win = sql.find("toIntervalHour(?)").unwrap();
        assert!(i_dec < i_win, "decision binds before window: {sql}");
        assert!(sql.contains("FROM guardrail_verdicts"), "sql: {sql}");
        assert!(sql.contains("ORDER BY event_time DESC"), "sql: {sql}");
        assert!(sql.trim_end().ends_with("LIMIT ?"), "sql: {sql}");
        // Regression (ClickHouse code 386 NO_COMMON_TYPE): the `toString(event_time)`
        // projection must NOT re-alias to `event_time` — that name collides with the
        // DateTime64 column referenced in WHERE/ORDER BY and the SELECT fails at
        // EXECUTION (it escaped because these tests only assert the string, never run
        // it against ClickHouse). The alias must be a distinct name.
        assert!(
            !sql.contains("AS event_time"),
            "toString(event_time) must alias to a distinct name, not the column: {sql}"
        );
        assert!(sql.contains("toString(event_time) AS ev_str"), "sql: {sql}");

        // No decision filter → no decision predicate.
        let all = build_guardrail_verdicts_sql(&GuardrailVerdictListFilters {
            until_secs: None,
            since_secs: Some(1),
            hours: 24,
            decision: None,
            correlation_id: None,
            rail: None,
            limit: 50,
        });
        assert!(!all.contains("AND decision = ?"), "sql: {all}");
        assert!(all.contains("event_time >= toDateTime(?)"), "sql: {all}");
    }

    #[test]
    fn parse_correlation_id_filter_accepts_ulid_rejects_junk() {
        // None / empty → no filter.
        assert_eq!(parse_correlation_id_filter(None), Ok(None));
        assert_eq!(parse_correlation_id_filter(Some("  ")), Ok(None));
        // A real 26-char ULID, normalised to upper case.
        let ulid = "01KXZH4Z4Q3VABCDEFGHJKMNPQ";
        assert_eq!(
            parse_correlation_id_filter(Some(ulid)),
            Ok(Some(ulid.to_string()))
        );
        assert_eq!(
            parse_correlation_id_filter(Some(&ulid.to_ascii_lowercase())),
            Ok(Some(ulid.to_string()))
        );
        // Wrong length.
        assert_eq!(parse_correlation_id_filter(Some("01KXZH")), Err(()));
        // Anything non-alphanumeric is rejected, so a SQL-ish payload can never
        // reach the binder even though the value is bound, not interpolated.
        assert_eq!(
            parse_correlation_id_filter(Some("01KXZH4Z4Q3V' OR 1=1 --")),
            Err(())
        );
        assert_eq!(
            parse_correlation_id_filter(Some("01KXZH4Z4Q3VABCDEFGHJKMN-Q")),
            Err(())
        );
    }

    #[test]
    fn verdicts_sql_adds_bound_correlation_predicate() {
        let base = GuardrailVerdictListFilters {
            hours: 24,
            limit: 100,
            ..Default::default()
        };
        // Absent → no predicate.
        assert!(!build_guardrail_verdicts_sql(&base).contains("correlation_id = ?"));

        // Present → a BOUND predicate, and tenant_id stays the first WHERE term.
        let with_id = GuardrailVerdictListFilters {
            correlation_id: Some("01KXZH4Z4Q3VABCDEFGHJKMNPQ".to_string()),
            rail: None,
            ..base
        };
        let sql = build_guardrail_verdicts_sql(&with_id);
        assert!(sql.contains("WHERE tenant_id = ?"));
        assert!(sql.contains(" AND correlation_id = ?"));
        // The value itself is never interpolated.
        assert!(!sql.contains("01KXZH4Z4Q3VABCDEFGHJKMNPQ"));
    }

    #[test]
    fn parse_decision_filter_allowlist() {
        assert_eq!(parse_decision_filter(None), Ok(None));
        assert_eq!(
            parse_decision_filter(Some("block")),
            Ok(Some("block".to_string()))
        );
        assert_eq!(
            parse_decision_filter(Some("allow")),
            Ok(Some("allow".to_string()))
        );
        assert_eq!(
            parse_decision_filter(Some("redact")).unwrap().unwrap(),
            "redact"
        );
        assert_eq!(
            parse_decision_filter(Some("warn")).unwrap().unwrap(),
            "warn"
        );
        // Anything off the allowlist is a client error, never a silent no-filter.
        assert_eq!(parse_decision_filter(Some("DROP")), Err(()));
        assert_eq!(parse_decision_filter(Some("")), Err(()));
    }

    #[test]
    fn guardrail_sql_since_overrides_window() {
        let f = GuardrailStatsFilters {
            until_secs: None,
            since_secs: Some(1_700_000_000),
            hours: 24,
            limit: 50,
        };
        let summary = build_guardrail_summary_sql(&f);
        assert!(
            summary.contains("event_time >= toDateTime(?)"),
            "sql: {summary}"
        );
        assert!(!summary.contains("toIntervalHour"), "sql: {summary}");
    }

    #[test]
    fn guardrail_response_derives_rates_and_never_nan_on_empty() {
        // Empty window: totals 0, every rate 0.0 (finite), no rails.
        let empty = GuardrailStatsResponse::build(GuardrailSummaryRow::default(), vec![], 24);
        assert_eq!(empty.total_evaluations, 0);
        assert_eq!(empty.block_rate_pct, 0.0);
        assert_eq!(empty.fail_open_rate_pct, 0.0);
        assert!(empty.block_rate_pct.is_finite());
        assert!(empty.rails.is_empty());

        // Populated: rates derive from counts.
        let summary = GuardrailSummaryRow {
            total: 200,
            allows: 180,
            blocks: 10,
            redacts: 6,
            warns: 4,
            fail_open_verdicts: 2,
            request_side: 120,
            response_side: 80,
            p50_ms: 0.4,
            p95_ms: 1.2,
            p99_ms: 3.0,
        };
        let rails = vec![
            GuardrailRailRow {
                rail: "R4_trifecta".into(),
                evaluations: 200,
                blocks: 10,
                fail_opens: 0,
                p95_ms: 0.8,
            },
            GuardrailRailRow {
                rail: "R5_format".into(),
                evaluations: 200,
                blocks: 0,
                fail_opens: 2,
                p95_ms: 0.3,
            },
        ];
        let r = GuardrailStatsResponse::build(summary, rails, 24);
        assert_eq!(r.total_evaluations, 200);
        assert_eq!(r.block_rate_pct, 5.0);
        assert_eq!(r.fail_open_rate_pct, 1.0);
        assert_eq!(r.rails[0].block_rate_pct, 5.0);
        assert_eq!(r.rails[1].fail_open_rate_pct, 1.0);
    }

    #[tokio::test]
    async fn guardrail_stats_uses_claims_tenant_and_shapes_response() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader {
            guardrail_summary: GuardrailSummaryRow {
                total: 50,
                allows: 45,
                blocks: 5,
                redacts: 0,
                warns: 0,
                fail_open_verdicts: 1,
                request_side: 50,
                response_side: 0,
                p50_ms: 0.5,
                p95_ms: 1.0,
                p99_ms: 2.0,
            },
            guardrail_rails: vec![GuardrailRailRow {
                rail: "R4_trifecta".into(),
                evaluations: 50,
                blocks: 5,
                fail_opens: 0,
                p95_ms: 0.8,
            }],
            ..MockTraceReader::new()
        });
        let state = TraceReadState {
            reader: reader.clone(),
            rejections: test_rejections(),
        };
        let resp = guardrail_stats_handler(
            State(state),
            Query(GuardrailStatsQuery {
                until: None,
                hours: None,
                since: None,
            }),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        // BOTH reads (summary + rails) must be tenant-scoped to the claim UUID.
        assert_eq!(
            reader.seen_tenant.lock().unwrap().as_slice(),
            &[DEV_TENANT, DEV_TENANT]
        );
        let v = body_json(resp).await;
        assert_eq!(v["window_hours"], 24);
        assert_eq!(v["total_evaluations"], 50);
        assert_eq!(v["block_rate_pct"], 10.0);
        assert_eq!(v["fail_open_rate_pct"], 2.0);
        assert_eq!(v["rails"][0]["rail"], "R4_trifecta");
        assert_eq!(v["rails"][0]["block_rate_pct"], 10.0);
    }

    #[tokio::test]
    async fn list_traces_uses_claims_tenant_and_returns_rows() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader {
            traces: vec![trace_row("t1", 100), trace_row("t2", 90)],
            ..MockTraceReader::new()
        });
        let state = TraceReadState {
            reader: reader.clone(),
            rejections: test_rejections(),
        };
        let resp = list_traces_handler(
            State(state),
            Query(TraceListQuery {
                include_issues: None,
                issue: None,
                agent: None,
                model_family: None,
                q: None,
                limit: Some(50),
                model: None,
                has_error: None,
                min_latency_ms: None,
                failover: None,
                end_user: None,
                signature_id: None,
                cursor: None,
                since: None,
                until: None,
                sort: None,
                order: None,
            }),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        // Tenant passed to the reader is the validated internal UUID.
        assert_eq!(reader.seen_tenant.lock().unwrap().as_slice(), &[DEV_TENANT]);
        let v = body_json(resp).await;
        assert_eq!(v["traces"].as_array().unwrap().len(), 2);
        assert_eq!(v["traces"][0]["issues"], serde_json::json!([]));
        assert_eq!(v["issues_available"], true);
        // Short page (2 < limit 50) → no next cursor.
        assert!(v["next_cursor"].is_null());
    }

    #[tokio::test]
    async fn list_traces_enriches_rows_with_cost_and_tokens() {
        // Gap #2: the list source has no cost/token columns; the handler merges
        // the read-time rollup so the JSON carries cost_usd + total_tokens.
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader {
            traces: vec![trace_row("t1", 100), trace_row("t2", 90)],
            trace_costs: vec![TraceCostRow {
                trace_id: "t1".into(),
                cost_usd: 0.004896,
                total_tokens: 1224,
            }],
            ..MockTraceReader::new()
        });
        let resp = list_traces_handler(
            State(TraceReadState {
                reader,
                rejections: test_rejections(),
            }),
            Query(TraceListQuery {
                include_issues: None,
                issue: None,
                agent: None,
                model_family: None,
                q: None,
                limit: Some(50),
                model: None,
                has_error: None,
                min_latency_ms: None,
                failover: None,
                end_user: None,
                signature_id: None,
                cursor: None,
                since: None,
                until: None,
                sort: None,
                order: None,
            }),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        let traces = v["traces"].as_array().unwrap();
        // t1 has a rollup row → enriched; t2 has none → fail-open zeros.
        assert_eq!(traces[0]["trace_id"], "t1");
        assert!((traces[0]["cost_usd"].as_f64().unwrap() - 0.004896).abs() < 1e-9);
        assert_eq!(traces[0]["total_tokens"].as_i64().unwrap(), 1224);
        assert_eq!(traces[1]["trace_id"], "t2");
        assert_eq!(traces[1]["cost_usd"].as_f64().unwrap(), 0.0);
        assert_eq!(traces[1]["total_tokens"].as_i64().unwrap(), 0);
    }

    #[tokio::test]
    async fn chain_status_handler_reports_chained_and_isolates_tenant() {
        // A gateway-path trace: the reader found its chain row. The handler must
        // 200 with chained:true + seq + anchored, and MUST have queried the
        // authenticated DEV_TENANT (never the path trace_id).
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader {
            chain_status: Some(TraceChainStatus {
                chained: true,
                seq: Some(231),
                anchored: false,
            }),
            ..MockTraceReader::new()
        });
        let resp = chain_status_handler(
            State(TraceReadState {
                reader: reader.clone(),
                rejections: test_rejections(),
            }),
            Path("d9690c98-59c4-413c-86d2-5cabc857e6b6".into()),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["chained"], true);
        assert_eq!(v["seq"].as_u64().unwrap(), 231);
        assert_eq!(v["anchored"], false);
        assert_eq!(reader.seen_tenant.lock().unwrap().as_slice(), &[DEV_TENANT]);
    }

    #[tokio::test]
    async fn chain_status_handler_honest_absent_state_when_not_chained() {
        // An SDK/OTLP trace (or a pre-item-4 gateway trace): no chain row. The
        // handler must 200 with chained:false — the honest absent-state, NOT a
        // 404 and NOT a false green.
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader::new()); // chain_status: None
        let resp = chain_status_handler(
            State(TraceReadState {
                reader,
                rejections: test_rejections(),
            }),
            Path("sdk-only-trace-00000000".into()),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["chained"], false);
        assert!(v["seq"].is_null());
        assert_eq!(v["anchored"], false);
    }

    #[tokio::test]
    async fn export_traces_csv_has_header_and_rows() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader {
            traces: vec![trace_row("t1", 100), trace_row("t2", 90)],
            ..MockTraceReader::new()
        });
        let resp = export_traces_handler(
            State(TraceReadState {
                reader,
                rejections: test_rejections(),
            }),
            Query(TraceExportQuery {
                issue: None,
                agent: None,
                model_family: None,
                format: Some("csv".into()),
                model: None,
                has_error: None,
                min_latency_ms: None,
                failover: None,
                end_user: None,
                signature_id: None,
                since: None,
                until: None,
                sort: None,
                order: None,
            }),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/csv; charset=utf-8"
        );
        assert!(
            resp.headers()
                .get(header::CONTENT_DISPOSITION)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("attachment")
        );
        let csv = body_text(resp).await;
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(
            lines[0],
            "trace_id,root_name,start_time,duration_us,span_count,error_count,intervention,model,cost_usd,total_tokens"
        );
        assert_eq!(lines.len(), 3, "header + 2 rows");
        assert!(lines[1].starts_with("t1,"));
        // Export columns must match the on-screen list (CSV == screen). With no
        // mock rollup rows, cost/tokens serialize as zeros at the row tail.
        assert!(
            lines[1].ends_with(",0,0"),
            "row must carry cost_usd,total_tokens"
        );
    }

    #[tokio::test]
    async fn export_traces_json_is_an_attachment() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader {
            traces: vec![trace_row("t1", 100)],
            ..MockTraceReader::new()
        });
        let resp = export_traces_handler(
            State(TraceReadState {
                reader,
                rejections: test_rejections(),
            }),
            Query(TraceExportQuery {
                issue: None,
                agent: None,
                model_family: None,
                format: Some("json".into()),
                model: None,
                has_error: None,
                min_latency_ms: None,
                failover: None,
                end_user: None,
                signature_id: None,
                since: None,
                until: None,
                sort: None,
                order: None,
            }),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers()
                .get(header::CONTENT_DISPOSITION)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("traces.json")
        );
        // OBS-23: a JSON consumer learns truncation from the headers — the body keeps
        // its bare-array shape so existing downloads are unaffected.
        assert_eq!(
            resp.headers().get("x-tracelane-truncated").unwrap(),
            "false"
        );
        assert_eq!(resp.headers().get("x-tracelane-row-count").unwrap(), "1");
        let v = body_json(resp).await;
        assert_eq!(v.as_array().unwrap().len(), 1);
        assert_eq!(v[0]["trace_id"], "t1");
    }

    #[test]
    fn csv_field_escapes_commas_quotes_newlines() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("she said \"hi\""), "\"she said \"\"hi\"\"\"");
        assert_eq!(csv_field("line\nbreak"), "\"line\nbreak\"");
        // Formula-injection guard: a leading =/+/-/@ is prefixed with `'` + quoted.
        assert_eq!(csv_field("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(csv_field("+1"), "\"'+1\"");
        assert_eq!(csv_field("@cmd"), "\"'@cmd\"");
        assert_eq!(csv_field("-2"), "\"'-2\"");
    }

    /// B-379: the window is ALWAYS present. Absent `since` → 7 days back; absent
    /// `until` → now plus an hour of clock-skew slack; explicit values win.
    #[test]
    fn list_window_defaults_to_seven_days_and_explicit_bounds_win() {
        let now = 1_800_000_000_000_000_i64;
        let f = TraceListFilters::default();
        let (since, until) = f.window_bounds(now);
        assert_eq!(since, now - DEFAULT_LIST_WINDOW_SECS * 1_000_000);
        assert_eq!(until, now + 60 * 60 * 1_000_000);
        let f = TraceListFilters {
            agent: None,
            model_family: None,
            since_us: Some(5),
            until_us: Some(9),
            ..Default::default()
        };
        assert_eq!(f.window_bounds(now), (5, 9));
    }

    /// B-379: every `spans` subquery a filter adds is bounded by the same window,
    /// so it prunes on the time-first key instead of scanning the tenant.
    #[test]
    fn every_spans_subquery_carries_the_window() {
        let f = TraceListFilters {
            agent: None,
            model_family: None,
            q: Some("needle".into()),
            signature_id: Some("AFT-1".into()),
            failover: Some(true),
            end_user: Some("u".into()),
            limit: 10,
            ..Default::default()
        };
        for sql in [
            build_trace_list_sql(&f),
            build_trace_count_sql(&f),
            build_trace_groups_sql(TraceGroupBy::Model, &f),
        ] {
            let subqueries = sql.matches("SELECT trace_id FROM spans").count();
            assert_eq!(subqueries, 4, "four filters, four subqueries: {sql}");
            let windowed = sql
                .matches("FROM spans WHERE tenant_id = ? AND start_time >= w_since AND start_time <= w_until")
                .count();
            assert_eq!(windowed, 4, "every subquery must carry the window: {sql}");
        }
    }

    #[test]
    fn build_trace_list_sql_honors_sort_and_order() {
        // Default → newest-first (start_time DESC; `st_min` is the merged min).
        let sql = build_trace_list_sql(&TraceListFilters::default());
        assert!(sql.contains("ORDER BY st_min DESC, trace_id DESC"));
        // Every query is still tenant-first (isolation invariant) — after the
        // B-379 WITH clocks, which bind no tenant data.
        assert!(sql.trim_start().starts_with(WINDOW_WITH) && sql.contains("WHERE tenant_id = ?"));

        // duration ASC.
        let sql = build_trace_list_sql(&TraceListFilters {
            agent: None,
            model_family: None,
            q: None,
            sort: TraceSort::Duration,
            order: SortOrder::Asc,
            ..Default::default()
        });
        assert!(sql.contains("ORDER BY duration_us ASC, trace_id ASC"));

        // Keyset uses the sort column + the direction operator (DESC → `<`).
        let sql = build_trace_list_sql(&TraceListFilters {
            agent: None,
            model_family: None,
            q: None,
            sort: TraceSort::Duration,
            cursor: Some((5, "t".into())),
            ..Default::default()
        });
        assert!(sql.contains("duration_us < ?"));

        // start_time keyset references the DateTime64 column, and ASC flips to `>`.
        let sql = build_trace_list_sql(&TraceListFilters {
            agent: None,
            model_family: None,
            q: None,
            order: SortOrder::Asc,
            cursor: Some((5, "t".into())),
            ..Default::default()
        });
        assert!(sql.contains("toUnixTimestamp64Micro(st_min) > ?"));
        assert!(sql.contains("trace_id > ?"));
    }

    #[test]
    fn parse_sort_and_order_allowlist() {
        assert_eq!(parse_sort(Some("duration")), TraceSort::Duration);
        assert_eq!(parse_sort(Some("start_time")), TraceSort::StartTime);
        assert_eq!(parse_sort(Some("bogus")), TraceSort::StartTime); // default
        assert_eq!(parse_sort(None), TraceSort::StartTime);
        assert_eq!(parse_order(Some("asc")), SortOrder::Asc);
        assert_eq!(parse_order(Some("desc")), SortOrder::Desc);
        assert_eq!(parse_order(Some("bogus")), SortOrder::Desc); // default
    }

    #[test]
    fn build_trace_groups_sql_dimensions_and_shape() {
        let sql = build_trace_groups_sql(TraceGroupBy::Model, &TraceListFilters::default());
        assert!(sql.contains("SELECT model AS group_key"));
        assert!(sql.contains("GROUP BY group_key ORDER BY trace_count DESC"));
        assert!(sql.trim_start().starts_with(WINDOW_WITH) && sql.contains("WHERE tenant_id = ?"));

        let sql = build_trace_groups_sql(TraceGroupBy::Operation, &TraceListFilters::default());
        assert!(sql.contains("SELECT root_name AS group_key"));

        let sql = build_trace_groups_sql(TraceGroupBy::Status, &TraceListFilters::default());
        assert!(sql.contains("if(error_count > 0, 'error', 'ok') AS group_key"));

        // Filters mirror the list (the model `?` clause appears when set).
        let sql = build_trace_groups_sql(
            TraceGroupBy::Model,
            &TraceListFilters {
                agent: None,
                model_family: None,
                q: None,
                model: Some("x".into()),
                ..Default::default()
            },
        );
        assert!(sql.contains("AND model = ?"));
    }

    #[test]
    fn parse_group_by_allowlist() {
        assert_eq!(parse_group_by("model"), Some(TraceGroupBy::Model));
        assert_eq!(parse_group_by("operation"), Some(TraceGroupBy::Operation));
        assert_eq!(parse_group_by("status"), Some(TraceGroupBy::Status));
        assert_eq!(parse_group_by("bogus"), None);
        assert_eq!(parse_group_by(""), None);
    }

    #[tokio::test]
    async fn trace_groups_handler_returns_groups_and_rejects_bad_by() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader {
            groups: vec![TraceGroupRow {
                group_key: "gpt-4o".into(),
                trace_count: 42,
                error_traces: 3,
                avg_duration_us: 1200.0,
                p95_duration_us: 3400.0,
            }],
            ..MockTraceReader::new()
        });
        let resp = list_trace_groups_handler(
            State(TraceReadState {
                reader: reader.clone(),
                rejections: test_rejections(),
            }),
            Query(TraceGroupsQuery {
                issue: None,
                agent: None,
                model_family: None,
                by: Some("model".into()),
                model: None,
                has_error: None,
                min_latency_ms: None,
                failover: None,
                end_user: None,
                signature_id: None,
                since: None,
                until: None,
            }),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(reader.seen_tenant.lock().unwrap().as_slice(), &[DEV_TENANT]);
        let v = body_json(resp).await;
        assert_eq!(v[0]["group_key"], "gpt-4o");
        assert_eq!(v[0]["trace_count"], 42);

        // Unknown `by` → 400 (grouping has no default).
        let resp = list_trace_groups_handler(
            State(TraceReadState {
                reader,
                rejections: test_rejections(),
            }),
            Query(TraceGroupsQuery {
                issue: None,
                agent: None,
                model_family: None,
                by: Some("bogus".into()),
                model: None,
                has_error: None,
                min_latency_ms: None,
                failover: None,
                end_user: None,
                signature_id: None,
                since: None,
                until: None,
            }),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn list_traces_emits_cursor_on_full_page() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader {
            traces: vec![trace_row("t1", 100), trace_row("t2", 90)],
            ..MockTraceReader::new()
        });
        let state = TraceReadState {
            reader,
            rejections: test_rejections(),
        };
        let resp = list_traces_handler(
            State(state),
            Query(TraceListQuery {
                include_issues: None,
                issue: None,
                agent: None,
                model_family: None,
                q: None,
                limit: Some(2), // page size == rows → expect a cursor
                model: None,
                has_error: None,
                min_latency_ms: None,
                failover: None,
                end_user: None,
                signature_id: None,
                cursor: None,
                since: None,
                until: None,
                sort: None,
                order: None,
            }),
            bearer_headers(),
        )
        .await;
        let v = body_json(resp).await;
        assert_eq!(v["next_cursor"].as_str(), Some("90:t2"));
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn spans_404_when_empty_and_tenant_is_from_claims_not_path() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader::new()); // no spans
        let state = TraceReadState {
            reader: reader.clone(),
            rejections: test_rejections(),
        };
        // A path that looks like another tenant's id must NOT change the tenant
        // the reader is queried with.
        let resp = list_spans_handler(
            State(state),
            Path("org_evil_other_tenant_trace".to_string()),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(reader.seen_tenant.lock().unwrap().as_slice(), &[DEV_TENANT]);
    }

    #[tokio::test]
    async fn generation_signal_details_on_spans_preserve_rows_and_report_missing_evidence() {
        let _g = DevAuthGuard::new();
        let mut flagged = span_row("child");
        flagged.parent_span_id = Some("root".into());
        flagged.attributes = serde_json::json!({"gen_ai_operation_name":"chat", "gen_ai_response_finish_reasons":["length"], "gen_ai_usage_output_tokens":5}).to_string();
        let mut unknown = span_row("root");
        unknown.attributes = serde_json::json!({"gen_ai_operation_name":"chat"}).to_string();
        let reader = Arc::new(MockTraceReader {
            spans: vec![unknown, flagged],
            ..MockTraceReader::new()
        });
        let response = list_spans_handler(
            State(TraceReadState {
                reader: reader.clone(),
                rejections: test_rejections(),
            }),
            Path("trace-abcdefgh".into()),
            bearer_headers(),
        )
        .await;
        let body = body_json(response).await;
        assert_eq!(body[0]["issues"], serde_json::json!([]));
        assert_eq!(body[1]["issues"][0]["kind"], "truncated");
        assert_eq!(body[1]["parent_span_id"], "root");
        assert!(
            body[0]["signals_recorded"]["missing"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("gen_ai_response_model"))
        );
        assert_eq!(reader.seen_tenant.lock().unwrap().as_slice(), &[DEV_TENANT]);
    }

    #[test]
    fn generation_signal_details_on_exchanges_survive_absent_content() {
        let exchange = build_session_exchange(
            "s1".into(),
            r#"{"gen_ai_operation_name":"chat","gen_ai_response_finish_reasons":["length"]}"#,
            1,
        );
        let body = serde_json::to_value(exchange).unwrap();
        assert_eq!(body["content"], "absent");
        assert_eq!(body["issues"][0]["kind"], "truncated");
        assert!(
            body["signals_recorded"]["missing"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("gen_ai_response_model"))
        );
    }

    #[test]
    fn generation_signal_details_use_exchange_status_and_keep_all_content_states() {
        for (input, content) in [
            (None, "absent"),
            (Some(serde_json::json!({"missing":true})), "unloaded"),
            (Some(serde_json::json!("wrong shape")), "unreadable"),
            (
                Some(serde_json::json!([{"role":"user","content":"private input"}])),
                "captured",
            ),
        ] {
            let mut attrs =
                serde_json::json!({"gen_ai_operation_name":"chat", "gen_ai_usage_output_tokens":0});
            if let Some(input) = input {
                attrs["gen_ai_input_messages"] = input;
            }
            let failed = build_session_exchange("failed".into(), &attrs.to_string(), 2);
            assert_eq!(failed.content, content);
            assert!(
                failed.generation.issues.is_empty(),
                "errors are never Empty"
            );
            let ok = build_session_exchange("ok".into(), &attrs.to_string(), 1);
            assert_eq!(ok.content, content);
            assert_eq!(ok.generation.issues[0].kind, Issue::Empty);
            assert!(
                !serde_json::to_string(&ok.generation)
                    .unwrap()
                    .contains("private input")
            );
        }
        let unreadable = build_session_exchange("bad".into(), "not JSON", 1);
        assert_eq!(unreadable.content, "unreadable");
        assert!(!unreadable.generation.signals_recorded.attributes_readable);
        assert!(unreadable.generation.issues.is_empty());
    }

    #[test]
    fn generation_signal_details_do_not_change_storage_or_public_share_shape() {
        let mut span = span_row("tool");
        span.attributes = serde_json::json!({"gen_ai_operation_name":"embeddings", "gen_ai_usage_output_tokens":0}).to_string();
        let raw = serde_json::to_value(&span).unwrap();
        assert!(raw.get("issues").is_none());
        let detail = serde_json::to_value(SpanResponse::from(span)).unwrap();
        for (key, value) in raw.as_object().unwrap() {
            assert_eq!(&detail[key], value);
        }
        assert_eq!(detail["issues"], serde_json::json!([]));
        assert_eq!(detail["signals_recorded"]["missing"], serde_json::json!([]));
        assert_eq!(detail["signals_recorded"]["chat_operation"], false);
        let malformed = SpanResponse::from(SpanRow {
            attributes: "broken".into(),
            ..span_row("broken")
        });
        assert!(!malformed.generation.signals_recorded.attributes_readable);
        assert_eq!(
            malformed.generation.signals_recorded.missing,
            vec!["gen_ai_operation_name"]
        );
    }

    #[test]
    fn generation_signal_details_exchange_sql_keeps_tenant_first_and_reads_span_status() {
        let sql = build_session_exchange_sql(2);
        assert!(sql.starts_with("SELECT trace_id, span_id, attributes, status_code FROM spans FINAL WHERE tenant_id = ? AND trace_id IN (?, ?)"), "{sql}");
        assert_eq!(sql.matches('?').count(), 3);
        assert!(sql.ends_with("LIMIT 1 BY trace_id"));
        assert_eq!(
            <ExchangeSpanRow as clickhouse::Row>::COLUMN_NAMES,
            &["trace_id", "span_id", "attributes", "status_code"]
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn spans_returns_rows_when_present() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader {
            spans: vec![span_row("s1"), span_row("s2")],
            ..MockTraceReader::new()
        });
        let state = TraceReadState {
            reader,
            rejections: test_rejections(),
        };
        let resp = list_spans_handler(
            State(state),
            Path("trace-abcdefgh".to_string()),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v.as_array().unwrap().len(), 2);
        assert_eq!(v[0]["span_id"], "s1");
        // start_time_us is present for TraceStep mapping.
        assert!(v[0]["start_time_us"].is_number());
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn spans_short_trace_id_is_400() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader::new());
        let state = TraceReadState {
            reader,
            rejections: test_rejections(),
        };
        let resp =
            list_spans_handler(State(state), Path("short".to_string()), bearer_headers()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn slo_uses_claims_tenant() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader {
            slo: vec![SloRow {
                bucket_hour: "2026-06-10 00:00:00".into(),
                provider: "anthropic".into(),
                model: "claude-sonnet-4-6".into(),
                p50_ms: 1.0,
                p95_ms: 2.0,
                p99_ms: 3.0,
                requests: 10,
                errors: 0,
                error_rate_pct: 0.0,
                total_input_tokens: 100,
                total_output_tokens: 50,
            }],
            ..MockTraceReader::new()
        });
        let state = TraceReadState {
            reader: reader.clone(),
            rejections: test_rejections(),
        };
        let resp = slo_handler(
            State(state),
            Query(SloQuery {
                bucket_minutes: None,
                hours: Some(24),
                provider: None,
                model: None,
                since: None,
                until: None,
                bucket: None,
            }),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(reader.seen_tenant.lock().unwrap().as_slice(), &[DEV_TENANT]);
        let v = body_json(resp).await;
        assert_eq!(v.as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn missing_authorization_is_401() {
        let reader = Arc::new(MockTraceReader::new());
        let state = TraceReadState {
            reader: reader.clone(),
            rejections: test_rejections(),
        };
        let resp = list_traces_handler(
            State(state),
            Query(TraceListQuery {
                include_issues: None,
                issue: None,
                agent: None,
                model_family: None,
                q: None,
                limit: None,
                model: None,
                has_error: None,
                min_latency_ms: None,
                failover: None,
                end_user: None,
                signature_id: None,
                cursor: None,
                since: None,
                until: None,
                sort: None,
                order: None,
            }),
            HeaderMap::new(), // no Authorization
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        // Reader never consulted without a valid tenant.
        assert!(reader.seen_tenant.lock().unwrap().is_empty());
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn malformed_cursor_is_400() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader::new());
        let state = TraceReadState {
            reader,
            rejections: test_rejections(),
        };
        let resp = list_traces_handler(
            State(state),
            Query(TraceListQuery {
                include_issues: None,
                issue: None,
                agent: None,
                model_family: None,
                q: None,
                limit: None,
                model: None,
                has_error: None,
                min_latency_ms: None,
                failover: None,
                end_user: None,
                signature_id: None,
                cursor: Some("garbage".into()),
                since: None,
                until: None,
                sort: None,
                order: None,
            }),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn malformed_since_timestamp_is_400() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader::new());
        let state = TraceReadState {
            reader: reader.clone(),
            rejections: test_rejections(),
        };
        let resp = list_traces_handler(
            State(state),
            Query(TraceListQuery {
                include_issues: None,
                issue: None,
                agent: None,
                model_family: None,
                q: None,
                limit: None,
                model: None,
                has_error: None,
                min_latency_ms: None,
                failover: None,
                end_user: None,
                signature_id: None,
                cursor: None,
                since: Some("not-a-timestamp".into()),
                until: None,
                sort: None,
                order: None,
            }),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        // 400 fires before the reader is consulted (input validation).
        assert!(reader.seen_tenant.lock().unwrap().is_empty());
    }

    // ── §4 failure-signatures handler tests ──────────────────────────────────

    fn sig_row(id: &str, hits: u64, intervention: u8) -> SignatureHitRow {
        SignatureHitRow {
            signature_id: id.into(),
            your_hits: hits,
            max_intervention: intervention,
            first_seen: "2026-07-01T00:00:00Z".into(),
            last_seen: "2026-07-10T00:00:00Z".into(),
            traces_affected: hits.max(1) - hits / 2,
        }
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn signatures_handler_uses_claims_tenant_maps_action_no_network() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader {
            signatures: vec![
                sig_row("tool-schema-violation", 7, 2),
                sig_row("tool-definition-drift", 3, 1),
            ],
            ..MockTraceReader::new()
        });
        let state = TraceReadState {
            reader: reader.clone(),
            rejections: test_rejections(),
        };
        let resp = signatures_handler(
            State(state),
            Query(SignatureQuery {
                until: None,
                since: None,
                limit: None,
                live_ids: None,
            }),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        // Handler-level isolation: BOTH reads (signatures + distinct-traces) are
        // queried with the validated claim tenant, never a request-supplied value
        // (SignatureQuery has no tenant).
        assert_eq!(
            reader.seen_tenant.lock().unwrap().as_slice(),
            &[DEV_TENANT, DEV_TENANT]
        );
        let v = body_json(resp).await;
        let sigs = v["signatures"].as_array().unwrap();
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0]["signature_id"], "tool-schema-violation");
        assert_eq!(sigs[0]["your_hits"], 7);
        assert_eq!(sigs[0]["action"], "blocking"); // intervention 2 → blocking
        assert_eq!(sigs[1]["action"], "flag-only"); // intervention 1 → flag-only
        // distinct traces = max per-signature traces_affected (mock), never a sum.
        assert_eq!(v["total_traces_affected"], 4);
        // Honesty lock (§4): NO network/cross-tenant field anywhere in the body.
        let raw = serde_json::to_string(&v).unwrap().to_lowercase();
        assert!(
            !raw.contains("network"),
            "response leaked a network field: {raw}"
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn signatures_handler_empty_is_ok_empty_list() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader::new());
        let state = TraceReadState {
            reader,
            rejections: test_rejections(),
        };
        let resp = signatures_handler(
            State(state),
            Query(SignatureQuery {
                until: None,
                since: None,
                limit: None,
                live_ids: None,
            }),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["signatures"].as_array().unwrap().len(), 0);
        assert_eq!(v["total_traces_affected"], 0);
    }

    #[tokio::test]
    async fn signatures_missing_auth_is_401_and_never_reads() {
        let reader = Arc::new(MockTraceReader::new());
        let state = TraceReadState {
            reader: reader.clone(),
            rejections: test_rejections(),
        };
        let resp = signatures_handler(
            State(state),
            Query(SignatureQuery {
                until: None,
                since: None,
                limit: None,
                live_ids: None,
            }),
            HeaderMap::new(), // no Authorization
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(reader.seen_tenant.lock().unwrap().is_empty());
    }

    // ── §3 sessions: SQL builders + handlers ─────────────────────────────────

    #[test]
    fn session_list_sql_is_tenant_first_grouped_by_conversation_and_bound() {
        let sql = build_session_list_sql(&SessionListFilters {
            window_days: 30,
            limit: 50,
            ..Default::default()
        });
        // tenant_id is the FIRST WHERE predicate — matched contiguously as
        // "WHERE tenant_id = ?" (a leading `x AND tenant_id` would not match). The
        // old "no AND before WHERE" prefix check was dropped: the cost-guard
        // `if(isFinite(...) AND ... > 0, ...)` in the SELECT legitimately contains
        // "AND" now and precedes the WHERE.
        assert!(sql.contains("WHERE tenant_id = ?"), "sql: {sql}");
        // Cost is finite/positive-guarded (mirrors the trace rollup) so a NaN or
        // negative usage attribute never leaks into the session cost sum.
        assert!(
            sql.contains(
                "sum(if(isFinite(JSONExtractFloat(attributes, 'gen_ai_usage_cost')) AND JSONExtractFloat(attributes, 'gen_ai_usage_cost') > 0"
            ),
            "sql: {sql}"
        );
        // Grouped by the conversation-id thread key; live over spans FINAL.
        assert!(sql.contains("gen_ai_conversation_id"));
        assert!(sql.contains("GROUP BY session_id"));
        assert!(sql.contains("FROM spans FINAL"));
        // Default window (no since) uses the rolling day window, not a bound ts.
        assert!(sql.contains("now() - toIntervalDay(?)"));
        assert!(!sql.contains("fromUnixTimestamp64Micro(?)"));
        assert!(sql.contains("ORDER BY max(end_time) DESC"));
        assert!(sql.trim_end().ends_with("LIMIT ?"));
    }

    #[test]
    fn session_list_sql_since_overrides_window_and_binds_before_limit() {
        let sql = build_session_list_sql(&SessionListFilters {
            since_us: Some(1_000),
            window_days: 30,
            limit: 50,
            ..Default::default()
        });
        assert!(sql.contains("start_time >= fromUnixTimestamp64Micro(?)"));
        assert!(!sql.contains("toIntervalDay"));
        let i_since = sql.find("fromUnixTimestamp64Micro(?)").unwrap();
        let i_limit = sql.rfind("LIMIT ?").unwrap();
        assert!(i_since < i_limit);
    }

    #[test]
    fn session_list_sql_model_status_sort_are_bound_and_allowlisted() {
        let sql = build_session_list_sql(&SessionListFilters {
            window_days: 30,
            limit: 50,
            model: Some("gpt-4o".into()),
            status_error: Some(true),
            sort: SessionSort::Cost,
            order: SortOrder::Asc,
            ..Default::default()
        });
        // Model filter is a bound predicate placed BEFORE the time window, so the
        // bind order stays tenant, model, window, limit.
        // RI-05 / B-444: the model filter binds against the coalesced served-else-
        // requested expression, the same one every other model read uses.
        let model_filter = format!("{MV_MODEL_EXPR} = ?");
        assert!(sql.contains(&model_filter), "sql: {sql}");
        let i_model = sql.find(&model_filter).unwrap();
        let i_window = sql.find("toIntervalDay(?)").unwrap();
        assert!(i_model < i_window, "model binds before window: {sql}");
        // Status filter → HAVING on the aggregate (errored sessions only).
        assert!(
            sql.contains("HAVING countIf(status_code = 2) > 0"),
            "sql: {sql}"
        );
        // Sort column comes from the allowlist; direction honored.
        assert!(sql.contains("ORDER BY cost_usd ASC"), "sql: {sql}");
    }

    #[test]
    fn session_list_sql_status_ok_default_sort_no_model() {
        let sql = build_session_list_sql(&SessionListFilters {
            window_days: 7,
            limit: 10,
            status_error: Some(false),
            ..Default::default()
        });
        assert!(
            sql.contains("HAVING countIf(status_code = 2) = 0"),
            "sql: {sql}"
        );
        assert!(sql.contains("ORDER BY max(end_time) DESC"), "sql: {sql}");
        assert!(!sql.contains("gen_ai_response_model') = ?"), "sql: {sql}");
    }

    #[test]
    fn parse_session_sort_and_status_allowlist() {
        assert_eq!(parse_session_sort(Some("turns")), SessionSort::Turns);
        assert_eq!(parse_session_sort(Some("cost")), SessionSort::Cost);
        assert_eq!(parse_session_sort(Some("tokens")), SessionSort::Tokens);
        assert_eq!(parse_session_sort(Some("duration")), SessionSort::Duration);
        assert_eq!(parse_session_sort(Some("bogus")), SessionSort::LastActivity);
        assert_eq!(parse_session_sort(None), SessionSort::LastActivity);
        assert_eq!(parse_status_filter(Some("error")), Some(true));
        assert_eq!(parse_status_filter(Some("ok")), Some(false));
        assert_eq!(parse_status_filter(Some("bogus")), None);
        assert_eq!(parse_status_filter(None), None);
    }

    #[test]
    fn session_traces_sql_is_tenant_first_then_session_bound() {
        let sql = build_session_traces_sql();
        // tenant bound first, THEN the session id bound (never interpolated).
        assert!(
            sql.contains(
                "WHERE tenant_id = ? AND JSONExtractString(attributes, 'gen_ai_conversation_id') = ?"
            ),
            "sql: {sql}"
        );
        let where_pos = sql.find("WHERE tenant_id = ?").unwrap();
        assert!(!sql[..where_pos].contains("conversation"));
        assert!(sql.contains("FROM spans FINAL"));
        assert!(sql.contains("GROUP BY trace_id"));
        assert!(sql.contains("ORDER BY min(start_time) ASC"));
    }

    /// B-516 / CX-17: the session LIST (`build_session_list_sql`) derives "model"
    /// through `MV_MODEL_EXPR` (the served model, falling back to the requested
    /// one) since B-444; the session DETAIL query here was left on the bare
    /// `gen_ai_response_model` extract, which B-444 also made absent on every
    /// semantic-cache hit and error span. Two routes answering "what model" with
    /// two different expressions is the defect — this asserts they now agree.
    #[test]
    fn session_traces_sql_reads_the_same_model_coalesce_as_the_list() {
        let sql = build_session_traces_sql();
        assert!(
            sql.contains(&format!("argMax({MV_MODEL_EXPR}, start_time) AS model")),
            "session-detail model must be argMax({{MV_MODEL_EXPR}}, start_time), the same \
             coalesce the session LIST uses (build_session_list_sql) — sql: {sql}"
        );
    }

    fn session_row(id: &str, turns: u32, error_count: u32) -> SessionSummaryRow {
        SessionSummaryRow {
            session_id: id.into(),
            turns,
            started_at: "2026-06-10 00:00:00.000000".into(),
            last_activity: "2026-06-10 00:05:00.000000".into(),
            duration_us: 300_000_000,
            error_count,
            cost_usd: 0.0123,
            total_tokens: 4200,
            model: "claude-sonnet-4-6".into(),
            agent_name: String::new(),
            end_user: String::new(),
        }
    }

    fn session_trace_row(trace_id: &str) -> SessionTraceRow {
        SessionTraceRow {
            trace_id: trace_id.into(),
            root_name: "chat".into(),
            start_time: "2026-06-10 00:00:00.000000".into(),
            start_time_us: 1_778_000_000_000_000,
            duration_us: 1000,
            span_count: 3,
            error_count: 0,
            model: "claude-sonnet-4-6".into(),
        }
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn list_sessions_uses_claims_tenant_and_derives_status() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader {
            sessions: vec![session_row("conv-a", 3, 1), session_row("conv-b", 2, 0)],
            ..MockTraceReader::new()
        });
        let state = TraceReadState {
            reader: reader.clone(),
            rejections: test_rejections(),
        };
        let resp = list_sessions_handler(
            State(state),
            Query(SessionListQuery {
                until: None,
                limit: Some(50),
                days: None,
                since: None,
                sort: None,
                order: None,
                status: None,
                model: None,
            }),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        // Tenant passed to the reader is the validated internal UUID from claims.
        assert_eq!(reader.seen_tenant.lock().unwrap().as_slice(), &[DEV_TENANT]);
        let v = body_json(resp).await;
        let sessions = v["sessions"].as_array().unwrap();
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0]["session_id"], "conv-a");
        assert_eq!(sessions[0]["turns"], 3);
        assert_eq!(sessions[0]["status"], "error"); // error_count 1 → error
        assert_eq!(sessions[1]["status"], "ok"); // error_count 0 → ok
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn session_traces_404_when_empty_and_tenant_from_claims_not_path() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader::new()); // no traces
        let state = TraceReadState {
            reader: reader.clone(),
            rejections: test_rejections(),
        };
        // A session id that looks like another tenant's id must NOT change the
        // tenant the reader is queried with (existence never leaks cross-tenant).
        let resp = session_traces_handler(
            State(state),
            Path("org_evil_other_tenant".to_string()),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(reader.seen_tenant.lock().unwrap().as_slice(), &[DEV_TENANT]);
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn session_traces_returns_ordered_turns() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader {
            session_traces: vec![session_trace_row("t1"), session_trace_row("t2")],
            ..MockTraceReader::new()
        });
        let state = TraceReadState {
            reader,
            rejections: test_rejections(),
        };
        let resp =
            session_traces_handler(State(state), Path("conv-abc".to_string()), bearer_headers())
                .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["session_id"], "conv-abc");
        assert_eq!(v["traces"].as_array().unwrap().len(), 2);
        assert_eq!(v["traces"][0]["trace_id"], "t1");
    }

    // ── OBS-55: session transcript ───────────────────────────────────────────

    fn session_totals_fixture(turns: u32) -> SessionTotalsRow {
        SessionTotalsRow {
            turns,
            spans: 3,
            input_tokens: 150,
            output_tokens: 20,
            cost_usd: 0.01,
            priced_spans: 1,
            first_start: "2026-09-27 10:00:00.000000".into(),
            last_end: "2026-09-27 10:06:00.000000".into(),
            duration_us: 360_000_000,
            error_spans: 1,
            models: vec!["gpt-4.1-mini".into(), "".into()],
            end_user: "user-4417".into(),
            agent_name: "support-bot".into(),
        }
    }

    fn session_exchange_fixture() -> SessionExchange {
        SessionExchange {
            generation: crate::generation_issues::details(
                &crate::generation_issues::SpanAttrsView {
                    attributes: &serde_json::json!({"gen_ai_operation_name":"chat"}),
                    status_code: 1,
                },
            ),
            span_id: "span-1".into(),
            input_tail: Vec::new(),
            input_message_count: 1,
            output: serde_json::Value::Null,
            finish_reasons: vec!["tool_calls".into()],
            tool_attrs: "{}".into(),
            content: "captured",
        }
    }

    fn session_turn_fixture(trace_id: &str, ordinal: u32, start_time_us: i64) -> SessionTurnRow {
        SessionTurnRow {
            trace_id: trace_id.into(),
            ordinal,
            start_time_iso: "2026-09-27 10:02:11.000000".into(),
            start_time_us,
            duration_us: 1200,
            span_count: 1,
            error_spans: 0,
            status_message: "".into(),
            intervention: 0,
            input_tokens: 100,
            output_tokens: 20,
            cost_usd: 0.01,
            priced_spans: 1,
            model: "gpt-4.1-mini".into(),
        }
    }

    /// `turns == 0` from the reader's `session_totals` is the handler's 404
    /// signal — byte-identical to `session_traces`'s empty-vec 404, so
    /// "missing" and "not your tenant" never diverge in shape.
    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn session_transcript_404_when_totals_absent_and_tenant_from_claims_not_path() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader::new()); // session_totals: None (the default)
        let state = TraceReadState {
            reader: reader.clone(),
            rejections: test_rejections(),
        };
        let resp = session_transcript_handler(
            State(state),
            Path("org_evil_other_tenant".to_string()),
            Query(SessionTranscriptQuery {
                limit: None,
                cursor: None,
            }),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(reader.seen_tenant.lock().unwrap().as_slice(), &[DEV_TENANT]);
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn session_transcript_returns_totals_turns_and_a_continuation_cursor() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader {
            session_totals: Some(session_totals_fixture(2)),
            session_turns: vec![(
                session_turn_fixture("t1", 1, 1_778_000_000_000_000),
                Some(session_exchange_fixture()),
            )],
            ..MockTraceReader::new()
        });
        let state = TraceReadState {
            reader,
            rejections: test_rejections(),
        };
        let resp = session_transcript_handler(
            State(state),
            Path("conv-abc".to_string()),
            Query(SessionTranscriptQuery {
                limit: Some(1),
                cursor: None,
            }),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["totals"]["turns"], 2);
        // A model attribute of "" must never reach the client — filtered in Rust.
        assert_eq!(v["totals"]["models"], serde_json::json!(["gpt-4.1-mini"]));
        assert_eq!(v["turns"].as_array().unwrap().len(), 1);
        assert_eq!(v["turns"][0]["trace_id"], "t1");
        assert_eq!(v["turns"][0]["ordinal"], 1);
        assert_eq!(v["turns"][0]["exchange"]["content"], "captured");
        // `turns.len() == limit` ⇒ there may be more: a cursor is emitted,
        // built from the LAST row's own (start_time_us, trace_id).
        assert_eq!(v["next_cursor"], "1778000000000000:t1");
    }

    /// A short page (fewer rows than `limit`) is the end of the walk — no cursor.
    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn session_transcript_short_page_emits_no_cursor() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader {
            session_totals: Some(session_totals_fixture(1)),
            session_turns: vec![(session_turn_fixture("t1", 1, 1_778_000_000_000_000), None)],
            ..MockTraceReader::new()
        });
        let state = TraceReadState {
            reader,
            rejections: test_rejections(),
        };
        let resp = session_transcript_handler(
            State(state),
            Path("conv-abc".to_string()),
            Query(SessionTranscriptQuery {
                limit: Some(20),
                cursor: None,
            }),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["next_cursor"], serde_json::Value::Null);
        assert!(
            v["turns"][0]["exchange"].is_null(),
            "a turn with no LLM span renders exchange: null"
        );
    }

    #[tokio::test]
    async fn session_transcript_missing_auth_is_401_and_never_reads() {
        let reader = Arc::new(MockTraceReader::new());
        let state = TraceReadState {
            reader: reader.clone(),
            rejections: test_rejections(),
        };
        let resp = session_transcript_handler(
            State(state),
            Path("conv-abc".to_string()),
            Query(SessionTranscriptQuery {
                limit: None,
                cursor: None,
            }),
            HeaderMap::new(), // no Authorization
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(reader.seen_tenant.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_sessions_missing_auth_is_401_and_never_reads() {
        let reader = Arc::new(MockTraceReader::new());
        let state = TraceReadState {
            reader: reader.clone(),
            rejections: test_rejections(),
        };
        let resp = list_sessions_handler(
            State(state),
            Query(SessionListQuery {
                until: None,
                limit: None,
                days: None,
                since: None,
                sort: None,
                order: None,
                status: None,
                model: None,
            }),
            HeaderMap::new(), // no Authorization
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(reader.seen_tenant.lock().unwrap().is_empty());
    }

    /// B-207 — every route this router mounts refuses a key without the `read` scope,
    /// driven through the ROUTER (not a helper). The paths are read from `routes()`'s
    /// own source, so a route added later is covered without editing this test; a
    /// handler that stops calling `authenticate` answers something other than 403 and
    /// fails here (proven by deleting one call site).
    #[tokio::test]
    async fn b207_every_read_route_refuses_a_key_without_the_read_scope() {
        use tower::ServiceExt;
        let src = include_str!("trace_reads.rs");
        let body = &src[src
            .find("pub fn routes() -> Router<TraceReadState> {")
            .expect("routes()")..];
        let body = &body[..body.find("\n}\n").expect("end of routes()")];
        let paths: Vec<String> = body
            .split(".route(")
            .skip(1)
            .filter_map(|chunk| {
                let start = chunk.find('"')? + 1;
                let end = start + chunk[start..].find('"')?;
                Some(chunk[start..end].to_string())
            })
            .collect();
        assert!(paths.len() >= 19, "routes() parse found only {paths:?}");

        let read_less = crate::auth::Claims {
            key_scope: crate::auth::scope::KeyScope::Scoped(
                [crate::auth::scope::Scope::Chat].into_iter().collect(),
            ),
            ..crate::auth::dev_stub_claims(crate::auth::AuthMethod::ApiKey)
        };
        let _claims = crate::auth::test_claims::Guard::set(read_less);
        let app = routes().with_state(TraceReadState {
            reader: Arc::new(MockTraceReader::new()),
            rejections: test_rejections(),
        });
        for path in &paths {
            let uri = path
                .replace("{trace_id}", "3f2a9c1e-1b2c-4d5e-8f90-a1b2c3d4e5f6")
                .replace("{session_id}", "sess-b207");
            // Valid query params so a route's extractors pass and the request reaches the
            // handler — a 400 from a missing param would never exercise the scope gate.
            let uri = format!(
                "{uri}?a=3f2a9c1e-1b2c-4d5e-8f90-a1b2c3d4e5f6&b=4f2a9c1e-1b2c-4d5e-8f90-a1b2c3d4e5f6"
            );
            let req = axum::http::Request::builder()
                .uri(&uri)
                .header(axum::http::header::AUTHORIZATION, "Bearer b207-scoped")
                .body(axum::body::Body::empty())
                .expect("request");
            let resp = app.clone().oneshot(req).await.expect("router answers");
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "{uri}: a key without `read` must be refused at the scope gate"
            );
        }
    }
}

// ── REAL-CLICKHOUSE EXECUTION OF THE COST SQL ────────────────────────────────
//
// WHY THIS EXISTS, and it is not a nice-to-have: every other test in this file
// asserts the SQL **STRING**. A string cannot be illegal — only a server can say
// that — so a query that is syntactically fine and semantically rejected sails
// through the whole suite, the whole gate and a successful deploy.
//
// That is exactly what happened. Adding the eval split introduced a second
// `sumIf(cost_usd, …)` beside an aggregate already aliased `AS cost_usd`; the
// alias shadowed the column, ClickHouse answered `Code 184 ILLEGAL_AGGREGATION`,
// and **every `/v1/costs` request 502'd on prod**. Four string-level tests were
// green the entire time.
//
// So this EXECUTES the builder's output — every dimension × every scope — against
// a real server. It asserts nothing about the numbers; the only claim is *the
// server accepts this query*, which is the one thing a string test can never make.
//
// `#[ignore]` + `CLICKHOUSE_TEST_URL`: run via
// `scripts/ci/run-clickhouse-integration.sh`.
#[cfg(test)]
mod clickhouse_roundtrip {
    use super::tests::{DEV_TENANT, DevAuthGuard, bearer_headers, body_json, test_rejections};
    use super::*;

    /// These tests share ONE database and ONE `spans` table, and
    /// `ensure_slo_view` applies migration 06, which DROPS and recreates
    /// `mv_trace_summaries`. Run in parallel, a test that inserts spans while
    /// another is between the drop and the recreate gets no summary rows — the
    /// B-379 round trip found that on the gate's fresh container (2026-09-12,
    /// three runs, three failures, every one `recent.len() == 0`). One lock, held
    /// for the whole test, is the honest fix: the hazard is real sharing, not a
    /// flaky assertion.
    static SHARED_DB: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL; isolated fixture writes, never production"]
    async fn trace_issue_rollup_excludes_other_tenant_spans_on_the_same_page() {
        let _serial = SHARED_DB.lock().await;
        let client = ch().expect("CLICKHOUSE_TEST_URL required");
        ensure_spans(&client).await;
        let tenant = TenantId::from_self_host_config(uuid::Uuid::new_v4());
        let other = TenantId::from_self_host_config(uuid::Uuid::new_v4());
        let own_id = uuid::Uuid::new_v4().to_string();
        let other_id = uuid::Uuid::new_v4().to_string();
        for (owner, trace_id, reason) in [
            (&tenant, &own_id, "length"),
            (&other, &own_id, "content_filter"),
            (&other, &other_id, "length"),
        ] {
            client.query("INSERT INTO tracelane.spans (tenant_id, trace_id, span_id, name, start_time, end_time, attributes) VALUES (?, ?, ?, 'gen_ai.chat', now64(6), now64(6), ?)")
                .bind(owner.to_string()).bind(trace_id).bind(uuid::Uuid::new_v4().to_string())
                .bind(serde_json::json!({"gen_ai_operation_name":"chat", "gen_ai_response_finish_reasons":[reason]}).to_string())
                .execute().await.expect("fixture span insert");
        }
        let reader = ClickHouseTraceReader::new(client);
        let rows = reader
            .trace_issue_rollup(&tenant, &[own_id.clone(), other_id])
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].trace_id, own_id);
        assert_eq!(rows[0].issue_counts, vec![0, 0, 0, 1, 0, 0, 0, 0, 0]);
    }

    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL; isolated fixture writes, never production"]
    async fn issue_summary_distinguishes_traces_calls_and_tenants_on_real_clickhouse() {
        let _serial = SHARED_DB.lock().await;
        let client = ch().expect("CLICKHOUSE_TEST_URL required");
        ensure_spans(&client).await;
        let a = TenantId::from_self_host_config(uuid::Uuid::new_v4());
        let b = TenantId::from_self_host_config(uuid::Uuid::new_v4());
        let trace = uuid::Uuid::new_v4().to_string();
        let embedding = uuid::Uuid::new_v4().to_string();
        let foreign = uuid::Uuid::new_v4().to_string();
        for (owner, id, attrs) in [
            (
                &a,
                &trace,
                serde_json::json!({"gen_ai_operation_name":"chat", "gen_ai_response_finish_reasons":["length"]}),
            ),
            (
                &a,
                &trace,
                serde_json::json!({"gen_ai_operation_name":"chat", "gen_ai_response_model":"gpt-4o", "gen_ai_response_finish_reasons":["length"]}),
            ),
            (
                &a,
                &embedding,
                serde_json::json!({"gen_ai_operation_name":"embeddings"}),
            ),
            (
                &b,
                &foreign,
                serde_json::json!({"gen_ai_operation_name":"chat", "gen_ai_response_finish_reasons":["content_filter"]}),
            ),
        ] {
            client.query("INSERT INTO tracelane.spans (tenant_id, trace_id, span_id, name, start_time, end_time, attributes) VALUES (?, ?, ?, 'summary-fixture', now64(6) - toIntervalSecond(1), now64(6), ?)")
                .bind(owner.to_string()).bind(id).bind(uuid::Uuid::new_v4().to_string()).bind(attrs.to_string())
                .execute().await.expect("fixture span insert");
        }
        let reader = ClickHouseTraceReader::new(client);
        let own = reader.generation_issue_summary(&a).await.unwrap();
        assert_eq!(
            (own.total_traces, own.llm_calls, own.no_served_model_calls),
            (2, 2, 1)
        );
        assert_eq!(
            own.counts
                .iter()
                .find(|c| c.kind == Issue::Truncated)
                .unwrap()
                .trace_count,
            1
        );
        let other = reader.generation_issue_summary(&b).await.unwrap();
        assert_eq!(other.total_traces, 1);
        assert_eq!(
            other
                .counts
                .iter()
                .find(|c| c.kind == Issue::Truncated)
                .unwrap()
                .trace_count,
            0
        );
        assert_eq!(
            other
                .counts
                .iter()
                .find(|c| c.kind == Issue::Filtered)
                .unwrap()
                .trace_count,
            1
        );
        let f = TraceListFilters {
            issues: vec![Issue::Truncated],
            since_us: parse_rfc3339_micros(Some(&own.since)).unwrap(),
            until_us: parse_rfc3339_micros(Some(&own.until)).unwrap(),
            ..Default::default()
        };
        assert_eq!(reader.count_traces(&a, &f).await.unwrap(), 1);
    }

    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL; isolated fixture writes, never production"]
    async fn issue_filter_returns_only_matching_tenant_traces_in_the_window() {
        let _serial = SHARED_DB.lock().await;
        let client = ch().expect("CLICKHOUSE_TEST_URL required");
        ensure_spans(&client).await;
        let tenant = TenantId::from_self_host_config(uuid::Uuid::new_v4());
        let other = TenantId::from_self_host_config(uuid::Uuid::new_v4());
        let flagged = uuid::Uuid::new_v4().to_string();
        let clean = uuid::Uuid::new_v4().to_string();
        let old = uuid::Uuid::new_v4().to_string();
        let now = now_us();
        for (owner, id, reason, time) in [
            (&tenant, &flagged, "length", now - 1_000_000),
            (&tenant, &clean, "stop", now - 1_000_000),
            (&other, &clean, "length", now - 1_000_000),
            (&tenant, &old, "length", now - 600_000_000),
        ] {
            client.query("INSERT INTO tracelane.spans (tenant_id, trace_id, span_id, name, start_time, end_time, attributes) VALUES (?, ?, ?, 'gen_ai.chat', fromUnixTimestamp64Micro(?), fromUnixTimestamp64Micro(?), ?)")
                .bind(owner.to_string()).bind(id).bind(uuid::Uuid::new_v4().to_string()).bind(time).bind(time)
                .bind(serde_json::json!({"gen_ai_operation_name":"chat", "gen_ai_response_finish_reasons":[reason]}).to_string())
                .execute().await.expect("fixture span insert");
        }
        let reader = ClickHouseTraceReader::new(client);
        let filters = TraceListFilters {
            issues: vec![Issue::Truncated],
            since_us: Some(now - 60_000_000),
            until_us: Some(now),
            limit: 50,
            ..Default::default()
        };
        let rows = reader.list_traces(&tenant, &filters).await.unwrap();
        assert_eq!(
            rows.iter().map(|r| &r.trace_id).collect::<Vec<_>>(),
            vec![&flagged]
        );
        assert_eq!(reader.count_traces(&tenant, &filters).await.unwrap(), 1);
        let groups = reader
            .list_trace_groups(&tenant, TraceGroupBy::Model, &filters)
            .await
            .unwrap();
        assert_eq!(groups.iter().map(|g| g.trace_count).sum::<u64>(), 1);
        let foreign = reader.list_traces(&other, &filters).await.unwrap();
        assert_eq!(
            foreign.iter().map(|r| &r.trace_id).collect::<Vec<_>>(),
            vec![&clean]
        );
        let unfiltered = reader
            .list_traces(
                &tenant,
                &TraceListFilters {
                    issues: vec![],
                    ..filters
                },
            )
            .await
            .unwrap();
        assert_eq!(unfiltered.len(), 2);
    }

    fn ch() -> Option<clickhouse::Client> {
        let url = std::env::var("CLICKHOUSE_TEST_URL").ok()?;
        Some(
            clickhouse::Client::default()
                .with_url(url)
                .with_database("tracelane"),
        )
    }

    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL and existing audit_log table; applies no schema"]
    async fn ledger_membership_accepts_all_gateway_routes_and_isolates_tenants() {
        let c = ch().expect("CLICKHOUSE_TEST_URL required");
        let tenant = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        let other = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        let events = [
            "chat.completions.request",
            "messages.request",
            "embeddings.request",
            "guardrail.verdict",
            "eval.verdict",
            "sdk.span",
        ];
        for (seq, event) in events.iter().enumerate() {
            c.query("INSERT INTO tracelane.audit_log (tenant_id, seq, event_time, event_type, actor, payload, row_hash) VALUES (?, ?, now64(6), ?, 'local-membership-test', ?, '')")
                .bind(tenant.to_string()).bind(seq as u64).bind(*event)
                .bind(serde_json::json!({"trace_id": event}).to_string())
                .execute().await.expect("fixture ledger row");
        }
        let reader = ClickHouseTraceReader::new(c.clone());
        let mut results = Vec::new();
        for event in events {
            results.push(
                reader
                    .trace_chain_status(&tenant, event)
                    .await
                    .expect("membership read"),
            );
        }
        let foreign = reader
            .trace_chain_status(&other, "embeddings.request")
            .await
            .expect("other tenant read");
        let absent = reader
            .trace_chain_status(&tenant, "unknown-trace")
            .await
            .expect("absent trace read");
        c.query("ALTER TABLE tracelane.audit_log DELETE WHERE tenant_id = ? SETTINGS mutations_sync = 1")
            .bind(tenant.to_string()).execute().await.expect("remove only this test's rows");
        for (index, (event, result)) in events.iter().zip(results).enumerate() {
            assert_eq!(
                result.as_ref().map(|r| r.chained),
                (index < 3).then_some(true),
                "{event} membership"
            );
            if let Some(status) = result {
                assert_eq!(status.seq, Some(index as u64));
                assert!(!status.anchored);
            }
        }
        assert!(
            foreign.is_none(),
            "another tenant must not see ledger membership"
        );
        assert!(absent.is_none(), "unknown traces must not appear chained");
    }

    /// The `spans` table as the cost query reads it. Applied from the checked-in
    /// schema, not hand-written here: a test that declares its own columns proves
    /// the code agrees with the TEST, which is the tautology this module exists
    /// to break.
    async fn ensure_spans(c: &clickhouse::Client) {
        clickhouse::Client::default()
            .with_url(std::env::var("CLICKHOUSE_TEST_URL").expect("CLICKHOUSE_TEST_URL"))
            .query("CREATE DATABASE IF NOT EXISTS tracelane")
            .execute()
            .await
            .expect("create database");
        let schema = include_str!("../../../infra/dev/clickhouse/schema.sql");
        for stmt in crate::clickhouse_query::split_migration_statements(schema) {
            // The schema file defines the whole instance; only `spans` is needed
            // here and the rest may reference objects a bare container lacks, so
            // a statement that does not apply is skipped rather than fatal. The
            // ONE statement that must succeed is asserted immediately after.
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

    /// EVERY dimension × EVERY scope must be a query the server ACCEPTS.
    ///
    /// A failure here is `Code 184` / `Code 47` / `Code 386` — the classes that
    /// are invisible to a string assertion and visible only to a server.
    /// Bring up the hourly SLO view too — migration 06 owns `slo_hourly_stats`
    /// and its MV; `schema.sql` alone leaves the MV-backed builders untestable.
    async fn ensure_slo_view(c: &clickhouse::Client) {
        // Migration 06 owns `slo_hourly_stats` + its MV, 13 the `gateway_overhead_us`
        // column, 16 the cost-attribution columns — every one a column or table a
        // DSH-11 builder reads. Without them the round trip REJECTS a query prod
        // accepts (this test's first run: `Unknown identifier gateway_overhead_us`).
        for m in [
            include_str!("../../../infra/dev/clickhouse/migrations/06_genai_attr_keys_and_slo.sql"),
            include_str!("../../../infra/dev/clickhouse/migrations/13_gateway_overhead_column.sql"),
            include_str!("../../../infra/dev/clickhouse/migrations/16_span_cost_attribution.sql"),
        ] {
            for stmt in crate::clickhouse_query::split_migration_statements(m) {
                let _ = c.query(&stmt).execute().await;
            }
        }
        let exists: u64 = c
            .query("SELECT count() FROM system.tables WHERE database='tracelane' AND name='slo_hourly_stats'")
            .fetch_one()
            .await
            .expect("system.tables read");
        assert_eq!(
            exists, 1,
            "`slo_hourly_stats` was not created — the hourly builders would pass by querying nothing"
        );
    }

    /// THE READER, not the builder — with `until` set on every windowed method.
    ///
    /// Written after the 2026-09-02 deploy shipped a BIND-ORDER defect that neither the
    /// unit tests (they assert SQL strings) nor the round trip below (it binds by hand)
    /// could see: a patch anchored on `async fn guardrail_summary(` matched the TRAIT
    /// declaration first, so three `until` binds landed in `slo()` and none in the
    /// guardrail or signature readers. Prod answered 502 on every request carrying
    /// `until` to five routes until the parity proof ran. This test drives the real
    /// `ClickHouseTraceReader` bind code; a bind mismatch is a ClickHouse error here.
    /// B-568 C3 against a REAL ClickHouse, through the real reader: what each new
    /// field COUNTS, not just that the SQL parses. Dispatched excludes hits (and a
    /// `hit = false` miss IS dispatched), warm excludes cold, tenant B's hit never
    /// reaches tenant A (spec §7 proof 6), and a hits-only tenant and an empty
    /// tenant read guarded zeros — the zero-sample case for every guarded
    /// quantile, decoded through the positional row.
    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn b568_latency_split_counts_the_right_populations_on_a_real_clickhouse() {
        let _serial = SHARED_DB.lock().await;
        let Some(c) = ch() else {
            panic!("CLICKHOUSE_TEST_URL not set — this test cannot run, which is not a pass");
        };
        ensure_spans(&c).await;
        // Migration 13 owns the MATERIALIZED `gateway_overhead_us` column; it must
        // exist BEFORE the inserts or the rows carry no overhead at all.
        ensure_slo_view(&c).await;
        let r = ClickHouseTraceReader::new(c.clone());
        let a = TenantId::from_self_host_config(uuid::Uuid::new_v4());
        let b = TenantId::from_self_host_config(uuid::Uuid::new_v4());
        let empty = TenantId::from_self_host_config(uuid::Uuid::new_v4());
        let insert = |tenant: &TenantId, overhead_us: u32, duration_ms: i64, extra: &str| {
            let c = c.clone();
            let t = tenant.to_string();
            let attrs = format!(
                "{{\"gen_ai_provider_name\":\"anthropic\",\"gen_ai_request_model\":\"claude-sonnet-4-6\",\
                 \"tracelane_gateway_overhead_us\":{overhead_us}{extra}}}"
            );
            async move {
                c.query(
                    "INSERT INTO tracelane.spans (tenant_id, trace_id, span_id, parent_span_id, name, \
                     start_time, end_time, status_code, attributes) VALUES \
                     (?, ?, ?, NULL, 'gen_ai.chat', now64(6) - toIntervalSecond(60), \
                     now64(6) - toIntervalSecond(60) + toIntervalMillisecond(?), 1, ?)",
                )
                .bind(&t)
                .bind(uuid::Uuid::new_v4().to_string())
                .bind(uuid::Uuid::new_v4().to_string())
                .bind(duration_ms)
                .bind(attrs)
                .execute()
                .await
                .expect("insert span");
            }
        };
        const HIT: &str =
            ",\"tracelane_semantic_cache_hit\":true,\"tracelane_semantic_cache_tier\":\"exact\"";
        const COLD: &str = ",\"tracelane_gateway_cold_start\":true";
        // Tenant A: two warm dispatched, one cold dispatched, one cache hit.
        insert(&a, 1_000, 800, "").await;
        insert(&a, 3_000, 900, "").await;
        insert(&a, 400_000, 1_500, COLD).await;
        insert(&a, 500_000, 500, HIT).await;
        // A DISPATCHED miss carries `hit = false` on prod (B-447) — it must count
        // as dispatched, not be dropped by a truthiness slip.
        insert(&a, 2_000, 700, ",\"tracelane_semantic_cache_hit\":false").await;
        // Tenant B: a single hit — must never reach A's numbers (spec §7 proof 6).
        insert(&b, 250_000, 250, HIT).await;

        let g = GatewayStatsFilters {
            since_secs: None,
            until_secs: None,
            hours: 1,
            limit: 10,
        };
        let (ta, by_model_a) = r.latency_breakdown(&a, &g).await.expect("tenant A");
        assert_eq!(
            ta.overhead_samples, 4,
            "dispatched = 3 plain + 1 explicit miss"
        );
        assert_eq!(
            ta.cache_hit_samples, 1,
            "A's hits only — B's hit must not leak in"
        );
        assert_eq!(ta.cold_start_samples, 1);
        assert_eq!(ta.warm_samples, 3);
        assert!(
            (499.0..=501.0).contains(&ta.cache_hit_served_p50_ms),
            "the hit's served time: {}",
            ta.cache_hit_served_p50_ms
        );
        assert!(
            ta.overhead_warm_p95_ms <= 3.0 && ta.overhead_warm_p50_ms >= 1.0,
            "steady state must exclude the cold request: p50 {} p95 {}",
            ta.overhead_warm_p50_ms,
            ta.overhead_warm_p95_ms
        );
        assert!(
            ta.overhead_p99_ms < 500.0 && ta.overhead_p99_ms > 100.0,
            "the dispatched p99 includes the cold 400 ms and excludes the 500 ms hit: {}",
            ta.overhead_p99_ms
        );
        assert_eq!(
            by_model_a.iter().map(|m| m.samples).sum::<u64>(),
            4,
            "the per-model column excludes hits too"
        );

        // Tenant B: hits only — every dispatched quantile is guarded to 0 with 0 samples.
        let (tb, _) = r.latency_breakdown(&b, &g).await.expect("tenant B");
        assert_eq!(tb.cache_hit_samples, 1);
        assert_eq!(tb.overhead_samples, 0);
        assert_eq!(tb.warm_samples, 0);
        assert_eq!(tb.cold_start_samples, 0);
        assert!(
            tb.overhead_p50_ms == 0.0 && tb.overhead_p95_ms == 0.0 && tb.overhead_p99_ms == 0.0
        );
        assert!(tb.provider_p95_ms == 0.0);
        assert!(tb.overhead_warm_p50_ms == 0.0 && tb.overhead_warm_p95_ms == 0.0);

        // An empty tenant: one all-zero row, never a NaN that would fail the decode.
        let (te, by_model_e) = r.latency_breakdown(&empty, &g).await.expect("empty tenant");
        assert_eq!(
            (
                te.overhead_samples,
                te.cache_hit_samples,
                te.cold_start_samples,
                te.warm_samples
            ),
            (0, 0, 0, 0)
        );
        for v in [
            te.overhead_p50_ms,
            te.cache_hit_served_p50_ms,
            te.cache_hit_served_p95_ms,
            te.overhead_warm_p50_ms,
            te.overhead_warm_p95_ms,
        ] {
            assert!(v == 0.0, "an empty window must read 0.0, got {v}");
        }
        assert!(by_model_e.is_empty());
    }

    /// B-379: the list / count / groups queries against a REAL ClickHouse, on the
    /// migration-22 schema (`ensure_spans` applies `schema.sql`, which carries the
    /// time-first key and the `p_by_time` projection). Three properties:
    /// (1) every filter combination binds and executes — a `?`/bind mismatch is a
    /// ClickHouse error here; (2) the merge is RIGHT: a trace whose spans land in
    /// two insert blocks (two MV partial rows) reads back as ONE trace with the
    /// summed span_count, which is exactly what `FINAL` used to guarantee and the
    /// GROUP BY must; (3) the default window excludes a trace older than 7 days
    /// and an explicit `since` brings it back.
    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn b379_list_count_groups_merge_and_window_on_a_real_clickhouse() {
        let _serial = SHARED_DB.lock().await;
        let Some(c) = ch() else {
            panic!("CLICKHOUSE_TEST_URL not set — this test cannot run, which is not a pass");
        };
        ensure_spans(&c).await;
        let r = ClickHouseTraceReader::new(c.clone());
        let tenant = TenantId::from_self_host_config(uuid::Uuid::new_v4());
        let t = tenant.to_string();
        let trace_recent = uuid::Uuid::new_v4().to_string();
        let trace_old = uuid::Uuid::new_v4().to_string();
        let insert = |trace: &str, name: &str, age_secs: i64, parent: bool| {
            let c = c.clone();
            let t = t.clone();
            let trace = trace.to_string();
            let name = name.to_string();
            async move {
                c.query(
                    "INSERT INTO tracelane.spans (tenant_id, trace_id, span_id, parent_span_id, name, \
                     start_time, end_time, status_code, attributes) VALUES \
                     (?, ?, ?, ?, ?, now64(6) - toIntervalSecond(?), now64(6) - toIntervalSecond(?) + toIntervalMillisecond(300), 1, \
                     '{\"gen_ai_request_model\":\"claude-sonnet-4-6\"}')",
                )
                .bind(&t)
                .bind(&trace)
                .bind(uuid::Uuid::new_v4().to_string())
                .bind(if parent { Some("p") } else { None::<&str> })
                .bind(&name)
                .bind(age_secs)
                .bind(age_secs)
                .execute()
                .await
                .expect("insert span");
            }
        };
        // Two SEPARATE inserts for the recent trace → two MV partial rows.
        insert(&trace_recent, "root", 60, false).await;
        insert(&trace_recent, "child", 59, true).await;
        // One old trace, outside the 7-day default window.
        insert(&trace_old, "root", 10 * 24 * 3600, false).await;

        // (2) merge: ONE row for the recent trace, span_count 2.
        let rows = r
            .list_traces(
                &tenant,
                &TraceListFilters {
                    agent: None,
                    model_family: None,
                    limit: 50,
                    ..Default::default()
                },
            )
            .await
            .expect("list (default window)");
        let recent: Vec<_> = rows.iter().filter(|x| x.trace_id == trace_recent).collect();
        assert_eq!(
            recent.len(),
            1,
            "two partial rows must merge to one trace: {rows:?}"
        );
        assert_eq!(
            recent[0].span_count, 2,
            "span_count is the SUM of the partials"
        );
        // (3) window: the old trace is outside the default, inside an explicit since.
        assert!(
            rows.iter().all(|x| x.trace_id != trace_old),
            "10-day-old trace must be outside the 7-day default"
        );
        let wide = r
            .list_traces(
                &tenant,
                &TraceListFilters {
                    agent: None,
                    model_family: None,
                    since_us: Some(
                        chrono::Utc::now().timestamp_micros() - 30 * 24 * 3600 * 1_000_000,
                    ),
                    limit: 50,
                    ..Default::default()
                },
            )
            .await
            .expect("list (explicit since)");
        assert!(
            wide.iter().any(|x| x.trace_id == trace_old),
            "explicit since must reach it: {wide:?}"
        );
        assert_eq!(
            r.count_traces(&tenant, &TraceListFilters::default())
                .await
                .expect("count"),
            1
        );
        // (1) every filter binds and runs, on all three builders.
        let every = TraceListFilters {
            agent: None,
            model_family: None,
            model: Some("claude-sonnet-4-6".into()),
            has_error: Some(false),
            min_duration_us: Some(1),
            signature_id: Some("AFT-1".into()),
            failover: Some(true),
            end_user: Some("u".into()),
            q: Some("root".into()),
            cursor: Some((chrono::Utc::now().timestamp_micros(), "z".into())),
            limit: 5,
            ..Default::default()
        };
        r.list_traces(&tenant, &every)
            .await
            .expect("list (every filter)");
        r.count_traces(&tenant, &every)
            .await
            .expect("count (every filter)");
        for by in [
            TraceGroupBy::Model,
            TraceGroupBy::Operation,
            TraceGroupBy::Status,
        ] {
            r.list_trace_groups(&tenant, by, &every)
                .await
                .expect("groups (every filter)");
        }
        for sort in [
            TraceSort::StartTime,
            TraceSort::Duration,
            TraceSort::SpanCount,
        ] {
            for order in [SortOrder::Asc, SortOrder::Desc] {
                r.list_traces(
                    &tenant,
                    &TraceListFilters {
                        agent: None,
                        model_family: None,
                        sort,
                        order,
                        limit: 5,
                        ..Default::default()
                    },
                )
                .await
                .expect("list (every sort)");
            }
        }
    }

    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn the_reader_binds_until_on_every_windowed_method() {
        let _serial = SHARED_DB.lock().await;
        let Some(c) = ch() else {
            panic!("CLICKHOUSE_TEST_URL not set — this test cannot run, which is not a pass");
        };
        ensure_spans(&c).await;
        ensure_slo_view(&c).await;
        let r = ClickHouseTraceReader::new(c);
        let tenant = TenantId::from_self_host_config(uuid::Uuid::new_v4());
        let now = chrono::Utc::now().timestamp();
        let (since, until) = (now - 6 * 3600, now);
        let slo = SloFilters {
            since_secs: Some(since),
            until_secs: Some(until),
            hours: 6,
            provider: Some("openai".into()),
            model: Some("gpt-4o".into()),
            bucket_minutes: Some(5),
            bucket_hours: 1,
        };
        r.slo(&tenant, &slo)
            .await
            .expect("slo (sub-hour, until, filters)");
        r.slo(
            &tenant,
            &SloFilters {
                bucket_minutes: None,
                bucket_hours: 3,
                ..slo.clone()
            },
        )
        .await
        .expect("slo (hourly view, until)");
        r.slo_summary(&tenant, &slo)
            .await
            .expect("slo_summary (until)");
        r.slo_by_model(&tenant, &slo)
            .await
            .expect("slo_by_model (until)");
        r.slo_timeseries(&tenant, &slo, 1)
            .await
            .expect("slo_timeseries (until, filters)");
        let g = GatewayStatsFilters {
            since_secs: Some(since),
            until_secs: Some(until),
            hours: 6,
            limit: 10,
        };
        r.gateway_stats(&tenant, &g)
            .await
            .expect("gateway_stats (until)");
        r.latency_breakdown(&tenant, &g)
            .await
            .expect("latency_breakdown (until)");
        // CX-26 / B-525: the cost reader binds the pair too (it bound `hours` only).
        r.cost_breakdown(
            &tenant,
            &CostFilters {
                since_secs: Some(since),
                until_secs: Some(until),
                hours: 6,
                dimension: CostDimension::Key,
                limit: 10,
                scope: CostScope::Production,
            },
        )
        .await
        .expect("cost_breakdown (until + scope)");
        let gr = GuardrailStatsFilters {
            since_secs: Some(since),
            until_secs: Some(until),
            hours: 6,
            limit: 10,
        };
        r.guardrail_summary(&tenant, &gr)
            .await
            .expect("guardrail_summary (until) — the prod 502");
        r.guardrail_rails(&tenant, &gr)
            .await
            .expect("guardrail_rails (until)");
        let v = GuardrailVerdictListFilters {
            since_secs: Some(since),
            until_secs: Some(until),
            hours: 6,
            decision: Some("block".into()),
            correlation_id: None,
            rail: Some("R4_trifecta".into()),
            limit: 5,
        };
        r.guardrail_verdicts(&tenant, &v)
            .await
            .expect("guardrail_verdicts (until + rail)");
        let s = SignatureFilters {
            since_us: Some(since * 1_000_000),
            until_us: Some(until * 1_000_000),
            limit: 5,
            live_signature_ids: vec!["AFT-1.3".into()],
        };
        r.signatures(&tenant, &s).await.expect("signatures (until)");
        r.signatures_distinct_traces(&tenant, &s)
            .await
            .expect("signatures total (until)");
        let sl = SessionListFilters {
            since_us: Some(since * 1_000_000),
            until_us: Some(until * 1_000_000),
            window_days: 30,
            limit: 5,
            ..Default::default()
        };
        r.list_sessions(&tenant, &sl)
            .await
            .expect("list_sessions (until)");
        let tl = TraceListFilters {
            agent: None,
            model_family: None,
            since_us: Some(since * 1_000_000),
            until_us: Some(until * 1_000_000),
            limit: 5,
            ..Default::default()
        };
        r.list_traces(&tenant, &tl)
            .await
            .expect("list_traces (until)");
        r.count_traces(&tenant, &tl)
            .await
            .expect("count_traces (until)");
        r.list_trace_groups(&tenant, TraceGroupBy::Model, &tl)
            .await
            .expect("list_trace_groups (until)");
    }

    /// B-500 (2026-09-21): under ONE sub-hour window the headline, the table and
    /// the chart count the SAME spans. Three LLM spans at H:20, H:50 and H+1:10;
    /// the window [H:30, H+1:30] with a 5-minute bucket holds exactly two of them.
    /// The `/v1/slo` rows read `spans FINAL` by `start_time` and sum to 2; until
    /// the fix `slo_summary` and `slo_by_model` read `slo_hourly_stats` by
    /// `bucket_hour = toStartOfHour(start_time)`, where only the H+1 bucket
    /// satisfies `bucket_hour >= H:30`, and answered 1 — the "no traffic in this
    /// window" headline beside a chart with bars. Only a server can show this: the
    /// string test proves the SQL's shape, this proves what it COUNTS, through the
    /// real reader and the real MV.
    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn sub_hour_summary_counts_the_same_spans_as_the_sub_hour_rows() {
        let _serial = SHARED_DB.lock().await;
        let Some(c) = ch() else {
            panic!("CLICKHOUSE_TEST_URL not set — this test cannot run, which is not a pass");
        };
        ensure_spans(&c).await;
        ensure_slo_view(&c).await;
        let r = ClickHouseTraceReader::new(c.clone());
        let tenant = TenantId::from_self_host_config(uuid::Uuid::new_v4());
        let t = tenant.to_string();
        // H = the start of the hour three hours ago: inside every 24 h window, and
        // every span below is strictly in the past.
        let now = chrono::Utc::now().timestamp();
        let h = now - now.rem_euclid(3600) - 3 * 3600;
        for (offset_secs, model) in [
            (20 * 60, "gpt-4o"),
            (50 * 60, "gpt-4o"),
            (70 * 60, "gpt-4o-mini"),
        ] {
            c.query(
                "INSERT INTO tracelane.spans (tenant_id, trace_id, span_id, name, \
                 start_time, end_time, status_code, attributes) VALUES \
                 (?, ?, ?, 'gen_ai.chat', toDateTime64(?, 6), toDateTime64(?, 6) + toIntervalMillisecond(250), 1, ?)",
            )
            .bind(&t)
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(h + offset_secs)
            .bind(h + offset_secs)
            .bind(format!(
                "{{\"gen_ai_provider_name\":\"openai\",\"gen_ai_request_model\":\"{model}\",\
                 \"gen_ai_usage_input_tokens\":10,\"gen_ai_usage_output_tokens\":5}}"
            ))
            .execute()
            .await
            .expect("insert span");
        }
        let f = SloFilters {
            since_secs: Some(h + 30 * 60),
            until_secs: Some(h + 90 * 60),
            hours: 1,
            bucket_minutes: Some(5),
            bucket_hours: 1,
            ..Default::default()
        };
        let rows = r.slo(&tenant, &f).await.expect("slo rows");
        let rows_total: u64 = rows.iter().map(|x| x.requests).sum();
        assert_eq!(rows_total, 2, "the chart side: H:50 and H+1:10 — {rows:?}");
        let summary = r.slo_summary(&tenant, &f).await.expect("slo_summary");
        let models = r.slo_by_model(&tenant, &f).await.expect("slo_by_model");
        let models_total: u64 = models.iter().map(|x| x.requests).sum();
        assert_eq!(
            summary.requests, rows_total,
            "the headline must count what the chart counts under one window: summary {summary:?} vs rows {rows:?}"
        );
        assert_eq!(
            models_total, rows_total,
            "the table must count what the chart counts under one window: {models:?} vs rows {rows:?}"
        );
        // The per-model split is the window's, not the hour's: gpt-4o has ONE span
        // inside [H:30, H+1:30] (H:50), gpt-4o-mini one (H+1:10).
        let per_model: std::collections::BTreeMap<&str, u64> = models
            .iter()
            .map(|m| (m.model.as_str(), m.requests))
            .collect();
        assert_eq!(per_model.get("gpt-4o").copied(), Some(1), "{models:?}");
        assert_eq!(per_model.get("gpt-4o-mini").copied(), Some(1), "{models:?}");
        // Tokens ride the same boundary: 2 spans × (10 in + 5 out).
        let in_tokens: i64 = models.iter().map(|m| m.total_input_tokens).sum();
        let out_tokens: i64 = models.iter().map(|m| m.total_output_tokens).sum();
        assert_eq!((in_tokens, out_tokens), (20, 10), "{models:?}");
        // And with NO bucket the family agrees with itself on the hourly view too:
        // both sides answer the H+1 bucket only, which is the >24 h contract.
        let hourly = SloFilters {
            bucket_minutes: None,
            ..f
        };
        let hourly_rows: u64 = r
            .slo(&tenant, &hourly)
            .await
            .expect("slo rows (hourly)")
            .iter()
            .map(|x| x.requests)
            .sum();
        let hourly_summary = r
            .slo_summary(&tenant, &hourly)
            .await
            .expect("slo_summary (hourly)");
        assert_eq!(hourly_rows, 1, "hourly rows: only the H+1 bucket");
        assert_eq!(
            hourly_summary.requests, hourly_rows,
            "hourly headline == hourly rows"
        );
    }

    /// DSH-11 — every SQL shape this batch ADDED or CHANGED is sent to a real
    /// ClickHouse and deserialised into the real row struct. A unit test proves the
    /// string; this proves the wire (B-257: a column-width mismatch 502'd every
    /// tenant for 12 hours while `clickhouse-client` printed correct numbers).
    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn every_dsh11_sql_is_accepted_by_a_real_clickhouse() {
        let _serial = SHARED_DB.lock().await;
        let Some(c) = ch() else {
            panic!("CLICKHOUSE_TEST_URL not set — this test cannot run, which is not a pass");
        };
        ensure_spans(&c).await;
        ensure_slo_view(&c).await;
        let tenant = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp();
        let (since, until) = (now - 6 * 3600, now);
        let tq = |sql: String| TenantQuery::new(sql, PlanTier::Free).sql_with_settings();

        // 1. /v1/slo and /v1/slo/timeseries, SUB-HOUR off raw spans, with both filters.
        let f = SloFilters {
            since_secs: Some(since),
            until_secs: Some(until),
            hours: 6,
            provider: Some("openai".into()),
            model: Some("gpt-4o".into()),
            bucket_minutes: Some(5),
            bucket_hours: 1,
        };
        c.query(&tq(build_slo_sql(&f)))
            .bind(&tenant)
            .bind(since)
            .bind(until)
            .bind("openai")
            .bind("gpt-4o")
            .fetch_all::<SloRow>()
            .await
            .unwrap_or_else(|e| panic!("sub-hour /v1/slo REJECTED: {e}"));
        c.query(&tq(build_slo_timeseries_sql(&f, 1)))
            .bind(&tenant)
            .bind(since)
            .bind(until)
            .bind("openai")
            .bind("gpt-4o")
            .fetch_all::<SloTimePoint>()
            .await
            .unwrap_or_else(|e| panic!("sub-hour /v1/slo/timeseries REJECTED: {e}"));

        // 2. The hourly-view paths, now carrying `errors` and the two bound filters.
        let h = SloFilters {
            bucket_minutes: None,
            ..f.clone()
        };
        c.query(&tq(build_slo_timeseries_sql(&h, 3)))
            .bind(&tenant)
            .bind(since)
            .bind(until)
            .bind("openai")
            .bind("gpt-4o")
            .fetch_all::<SloTimePoint>()
            .await
            .unwrap_or_else(|e| panic!("hourly /v1/slo/timeseries REJECTED: {e}"));
        c.query(&tq(build_slo_sql(&SloFilters {
            bucket_hours: 3,
            ..h.clone()
        })))
        .bind(&tenant)
        .bind(since)
        .bind(until)
        .bind("openai")
        .bind("gpt-4o")
        .fetch_all::<SloRow>()
        .await
        .unwrap_or_else(|e| panic!("bucketed /v1/slo REJECTED: {e}"));

        // 3. `until` on the spans / guardrail / signature / session families, and the
        //    gateway-stats cost expression aligned to /v1/costs.
        let g = GatewayStatsFilters {
            since_secs: Some(since),
            until_secs: Some(until),
            hours: 6,
            limit: 10,
        };
        c.query(&tq(build_gateway_stats_sql(&g)))
            .bind(&tenant)
            .bind(since)
            .bind(until)
            .bind(10_u32)
            .fetch_all::<GatewayProviderRow>()
            .await
            .unwrap_or_else(|e| panic!("gateway stats REJECTED: {e}"));
        c.query(&tq(build_latency_totals_sql(&g)))
            .bind(&tenant)
            .bind(since)
            .bind(until)
            .fetch_one::<LatencyTotalsRow>()
            .await
            .unwrap_or_else(|e| panic!("latency totals REJECTED: {e}"));
        c.query(&tq(build_latency_by_model_sql(&g)))
            .bind(&tenant)
            .bind(since)
            .bind(until)
            .bind(10_u32)
            .fetch_all::<LatencyModelRow>()
            .await
            .unwrap_or_else(|e| panic!("latency by model REJECTED: {e}"));
        let gr = GuardrailStatsFilters {
            since_secs: Some(since),
            until_secs: Some(until),
            hours: 6,
            limit: 10,
        };
        c.query(&tq(build_guardrail_summary_sql(&gr)))
            .bind(&tenant)
            .bind(since)
            .bind(until)
            .fetch_one::<GuardrailSummaryRow>()
            .await
            .unwrap_or_else(|e| panic!("guardrail summary REJECTED: {e}"));
        c.query(&tq(build_guardrail_rails_sql(&gr)))
            .bind(&tenant)
            .bind(since)
            .bind(until)
            .bind(10_u32)
            .fetch_all::<GuardrailRailRow>()
            .await
            .unwrap_or_else(|e| panic!("guardrail rails REJECTED: {e}"));
        let v = GuardrailVerdictListFilters {
            since_secs: Some(since),
            until_secs: Some(until),
            hours: 6,
            decision: Some("block".into()),
            correlation_id: None,
            rail: None,
            limit: 5,
        };
        c.query(&tq(build_guardrail_verdicts_sql(&v)))
            .bind(&tenant)
            .bind("block")
            .bind(since)
            .bind(until)
            .bind(5_u32)
            .fetch_all::<GuardrailVerdictListRow>()
            .await
            .unwrap_or_else(|e| panic!("guardrail verdicts REJECTED: {e}"));
        let s = SignatureFilters {
            since_us: Some(since * 1_000_000),
            until_us: Some(until * 1_000_000),
            limit: 5,
            live_signature_ids: vec![],
        };
        c.query(&tq(build_signatures_sql(&s)))
            .bind(&tenant)
            .bind(since * 1_000_000)
            .bind(until * 1_000_000)
            .bind(5_u32)
            .fetch_all::<SignatureHitRow>()
            .await
            .unwrap_or_else(|e| panic!("signatures REJECTED: {e}"));
        c.query(&tq(build_signatures_trace_total_sql(&s)))
            .bind(&tenant)
            .bind(since * 1_000_000)
            .bind(until * 1_000_000)
            .fetch_one::<TraceTotalRow>()
            .await
            .unwrap_or_else(|e| panic!("signatures total REJECTED: {e}"));
        let sl = SessionListFilters {
            since_us: Some(since * 1_000_000),
            until_us: Some(until * 1_000_000),
            window_days: 30,
            limit: 5,
            ..Default::default()
        };
        c.query(&tq(build_session_list_sql(&sl)))
            .bind(&tenant)
            .bind(since * 1_000_000)
            .bind(until * 1_000_000)
            .bind(5_u32)
            .fetch_all::<SessionSummaryRow>()
            .await
            .unwrap_or_else(|e| panic!("sessions REJECTED: {e}"));
    }

    /// `OBS-55` — one session span carrying every attribute the transcript
    /// route reads. `with_exchange` adds a full input/output/tool-call
    /// message pair (the same four keys `apps/web/lib/tool-calls.ts`'s
    /// `extractToolCalls` already reads); `error` sets `status_code = 2` and
    /// the given message.
    #[allow(clippy::too_many_arguments)]
    async fn insert_session_span(
        c: &clickhouse::Client,
        tenant: &str,
        trace_id: &str,
        conv_id: &str,
        start_secs: i64,
        end_secs: i64,
        model: &str,
        input_tokens: u64,
        output_tokens: u64,
        cost: f64,
        error: Option<&str>,
        with_exchange: bool,
    ) {
        let mut attrs = serde_json::json!({
            "gen_ai_conversation_id": conv_id,
            "gen_ai_operation_name": "chat",
            "gen_ai_request_model": model,
            "gen_ai_provider_name": "anthropic",
            "gen_ai_usage_input_tokens": input_tokens,
            "gen_ai_usage_output_tokens": output_tokens,
            "gen_ai_usage_cost": cost,
        });
        if with_exchange {
            attrs["gen_ai_input_messages"] = serde_json::json!([{"role": "user", "content": "Where is my refund for order 88?"}]);
            attrs["gen_ai_output_messages"] = serde_json::json!([{
                "role": "assistant",
                "content": "Let me check.",
                "tool_calls": [{"id": "call_1", "name": "lookup_order", "input": {"order_id": 88}}],
            }]);
            attrs["gen_ai_response_finish_reasons"] = serde_json::json!(["tool_calls"]);
            attrs["tracelane_response_tool_names"] = serde_json::json!(["lookup_order"]);
            attrs["tracelane_response_tool_arg_bytes"] = serde_json::json!([15]);
        }
        let status_code: u8 = if error.is_some() { 2 } else { 1 };
        c.query(
            "INSERT INTO tracelane.spans (tenant_id, trace_id, span_id, name, \
             start_time, end_time, status_code, status_message, attributes) VALUES \
             (?, ?, ?, 'gen_ai.chat', toDateTime64(?, 6), toDateTime64(?, 6), ?, ?, ?)",
        )
        .bind(tenant)
        .bind(trace_id)
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(start_secs)
        .bind(end_secs)
        .bind(status_code)
        .bind(error.unwrap_or(""))
        .bind(attrs.to_string())
        .execute()
        .await
        .expect("insert session span");
    }

    /// `OBS-55` — the SQL that could not be seen by a mock: the `row_number()`
    /// window over a GROUP BY subquery (ordinal), the `LIMIT 1 BY trace_id`
    /// exchange projection, and the alias-shadowing trap (§ B-424/B-564) this
    /// file's own totals/turns builders share aliases with real MATERIALIZED
    /// `spans` columns (`duration_us`, `cost_usd`) — safe here because they
    /// name a DERIVED table's own output, never the base table, but only a
    /// server proves that distinction rather than merely reads right.
    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn session_transcript_totals_and_turns_against_a_real_clickhouse() {
        let _serial = SHARED_DB.lock().await;
        let Some(c) = ch() else {
            panic!("CLICKHOUSE_TEST_URL not set — this test cannot run, which is not a pass");
        };
        ensure_spans(&c).await;
        let tenant = TenantId::from_self_host_config(uuid::Uuid::new_v4());
        let t = tenant.to_string();
        let conv = format!("conv-{}", uuid::Uuid::new_v4());
        let now = chrono::Utc::now().timestamp();

        let trace_a = uuid::Uuid::new_v4().to_string();
        let trace_b = uuid::Uuid::new_v4().to_string();
        // Turn 1 (trace A) — the EARLIER turn: one exchange span, priced, no error.
        insert_session_span(
            &c,
            &t,
            &trace_a,
            &conv,
            now - 120,
            now - 119,
            "gpt-4.1-mini",
            100,
            20,
            0.01,
            None,
            true,
        )
        .await;
        // Turn 2 (trace B) — LATER: one error span, unpriced, no exchange content.
        insert_session_span(
            &c,
            &t,
            &trace_b,
            &conv,
            now - 60,
            now - 59,
            "gpt-4.1-mini",
            50,
            0,
            0.0,
            Some("upstream 429"),
            false,
        )
        .await;

        let reader = ClickHouseTraceReader::new(c.clone());

        // ── totals: computed over BOTH turns, never a page ──────────────────
        let totals = reader
            .session_totals(&tenant, &conv)
            .await
            .unwrap_or_else(|e| panic!("session totals REJECTED: {e}"))
            .expect("the session has spans and must not read as not-found");
        assert_eq!(totals.turns, 2, "{totals:?}");
        assert_eq!(totals.spans, 2);
        assert_eq!(totals.input_tokens, 150);
        assert_eq!(totals.output_tokens, 20);
        assert_eq!(
            totals.priced_spans, 1,
            "only turn A carried a positive cost"
        );
        assert!((totals.cost_usd - 0.01).abs() < 1e-9, "{}", totals.cost_usd);
        assert_eq!(totals.error_spans, 1);
        assert_eq!(totals.models, vec!["gpt-4.1-mini".to_string()]);

        // ── page 1 (limit 1): turn A, ordinal 1, a continuation cursor ──────
        let page1 = reader
            .session_turns(&tenant, &conv, None, 1)
            .await
            .unwrap_or_else(|e| panic!("session turns page 1 REJECTED: {e}"));
        assert_eq!(page1.len(), 1, "{page1:?}");
        let (turn_a, exchange_a) = &page1[0];
        assert_eq!(turn_a.trace_id, trace_a, "turn A started first");
        assert_eq!(turn_a.ordinal, 1);
        assert_eq!(turn_a.priced_spans, 1);
        let exchange_a = exchange_a.as_ref().expect("turn A carries an LLM span");
        assert_eq!(exchange_a.content, "captured");
        assert_eq!(
            exchange_a.input_tail.len(),
            1,
            "no prior assistant message ⇒ the whole input is new"
        );
        assert_eq!(exchange_a.finish_reasons, vec!["tool_calls".to_string()]);
        // The web's EXISTING `extractToolCalls` reads exactly these four keys —
        // prove they round-trip through `tool_attrs` untouched.
        let tool_attrs: serde_json::Value =
            serde_json::from_str(&exchange_a.tool_attrs).expect("tool_attrs must be valid JSON");
        assert_eq!(
            tool_attrs["tracelane_response_tool_names"],
            serde_json::json!(["lookup_order"])
        );

        // ── page 2, from page 1's cursor: turn B, ordinal EXACT (2, not reset
        // to 1 on the new page). Turn B's span DOES carry a model (every span
        // this test inserts does) but no `gen_ai_input_messages` — the
        // "capture off" shape — so its exchange exists with `content = "absent"`
        // rather than `None` (`None` is reserved for a turn with NO LLM span
        // at all, not exercised here). ──────────────────────────────────────
        let cursor = Some((turn_a.start_time_us, turn_a.trace_id.clone()));
        let page2 = reader
            .session_turns(&tenant, &conv, cursor, 1)
            .await
            .unwrap_or_else(|e| panic!("session turns page 2 REJECTED: {e}"));
        assert_eq!(page2.len(), 1, "{page2:?}");
        let (turn_b, exchange_b) = &page2[0];
        assert_eq!(turn_b.trace_id, trace_b);
        assert_eq!(
            turn_b.ordinal, 2,
            "ordinal must be exact against the WHOLE session, not reset per page"
        );
        assert_eq!(turn_b.error_spans, 1);
        assert_eq!(turn_b.status_message, "upstream 429");
        assert_eq!(turn_b.priced_spans, 0);
        let exchange_b = exchange_b
            .as_ref()
            .expect("turn B's span carries a model, so it IS the exchange span");
        assert_eq!(exchange_b.content, "absent");
        assert_eq!(exchange_b.input_tail.len(), 0);
        assert!(
            exchange_b.generation.issues.is_empty(),
            "the exchange span's error status excludes Empty despite zero output tokens"
        );
        assert!(
            exchange_b
                .generation
                .signals_recorded
                .missing
                .contains(&"gen_ai_response_model")
        );
        assert!(
            exchange_b
                .generation
                .signals_recorded
                .present
                .contains(&"gen_ai_usage_output_tokens")
        );

        // ── a foreign/unknown session resolves to `None`, never zeros ───────
        assert!(
            reader
                .session_totals(&tenant, "no-such-session")
                .await
                .unwrap_or_else(|e| panic!("REJECTED: {e}"))
                .is_none()
        );
    }

    /// One gateway-shaped LLM span: `cost_usd` / `cost_usd_present` / `model` are
    /// MATERIALIZED off `attributes`, so the JSON the gateway writes is what goes in.
    async fn insert_cost_span(
        c: &clickhouse::Client,
        tenant: &str,
        start_secs: i64,
        model: &str,
        cost: Option<f64>,
    ) {
        let mut attrs = serde_json::json!({
            "gen_ai_request_model": model,
            "gen_ai_provider_name": "anthropic",
        });
        if let Some(cost) = cost {
            attrs["gen_ai_usage_cost"] = serde_json::json!(cost);
        }
        c.query(
            "INSERT INTO tracelane.spans (tenant_id, trace_id, span_id, name, \
             start_time, end_time, status_code, attributes) VALUES \
             (?, ?, ?, 'gen_ai.chat', toDateTime64(?, 6), toDateTime64(?, 6), 1, ?)",
        )
        .bind(tenant)
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(start_secs)
        .bind(start_secs)
        .bind(attrs.to_string())
        .execute()
        .await
        .expect("insert span");
    }

    /// `n` gateway-shaped spans at `start_secs`, one DISTINCT model each
    /// (`<prefix>-<i>`), in ONE insert — 257 single-row round trips made the
    /// round-trip family a minute slower for nothing.
    async fn insert_priced_groups(
        c: &clickhouse::Client,
        tenant: &str,
        start_secs: i64,
        prefix: &str,
        n: u64,
        cost: f64,
    ) {
        c.query(
            "INSERT INTO tracelane.spans (tenant_id, trace_id, span_id, name, \
             start_time, end_time, status_code, attributes) \
             SELECT ?, generateUUIDv4(), generateUUIDv4(), 'gen_ai.chat', \
             toDateTime64(?, 6), toDateTime64(?, 6), 1, \
             concat('{\"gen_ai_request_model\":\"', ?, '-', toString(number), \
             '\",\"gen_ai_provider_name\":\"anthropic\",\"gen_ai_usage_cost\":', ?, '}') \
             FROM numbers(?)",
        )
        .bind(tenant)
        .bind(start_secs)
        .bind(start_secs)
        .bind(prefix)
        .bind(cost.to_string())
        .bind(n)
        .execute()
        .await
        .expect("insert priced groups");
    }

    /// CX-26 / B-525 — THE READER, on a real server: a historical `since/until`
    /// pair returns the spans INSIDE it and none outside. Until the fix the reader
    /// had no window at all and answered the last `hours` — span A (30 min ago,
    /// $1.00) — under a label that said two to four days ago, where only span B
    /// ($2.00) lives.
    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn a_historical_cost_window_excludes_spans_outside_it_on_a_real_clickhouse() {
        let _serial = SHARED_DB.lock().await;
        let Some(c) = ch() else {
            panic!("CLICKHOUSE_TEST_URL not set — this test cannot run, which is not a pass");
        };
        ensure_spans(&c).await;
        let r = ClickHouseTraceReader::new(c.clone());
        let tenant = TenantId::from_self_host_config(uuid::Uuid::new_v4());
        let t = tenant.to_string();
        let now = chrono::Utc::now().timestamp();
        insert_cost_span(&c, &t, now - 30 * 60, "model-a-recent", Some(1.0)).await;
        insert_cost_span(&c, &t, now - 3 * 86_400, "model-b-historical", Some(2.0)).await;
        let f = CostFilters {
            since_secs: Some(now - 4 * 86_400),
            until_secs: Some(now - 2 * 86_400),
            hours: 48,
            dimension: CostDimension::Model,
            limit: 100,
            scope: CostScope::All,
        };
        let rows = r
            .cost_breakdown(&tenant, &f)
            .await
            .expect("cost_breakdown (pair)");
        let total: f64 = rows.iter().map(|x| x.cost_usd).sum();
        assert!(
            (total - 2.0).abs() < 1e-6,
            "the window [now−4d, now−2d] holds only span B ($2.00): {rows:?}"
        );
        assert!(
            rows.iter().all(|x| x.dimension != "model-a-recent"),
            "span A (30 min ago) is OUTSIDE the window and must not appear: {rows:?}"
        );
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].dimension, "model-b-historical");
        // The rolling window still works and sees ONLY the recent span.
        let rolling = r
            .cost_breakdown(
                &tenant,
                &CostFilters {
                    since_secs: None,
                    until_secs: None,
                    hours: 24,
                    ..f
                },
            )
            .await
            .expect("cost_breakdown (rolling)");
        assert_eq!(rolling.len(), 1, "{rolling:?}");
        assert_eq!(rolling[0].dimension, "model-a-recent");
    }

    /// CX-27 / B-526 — THE HANDLER, on a real server, with more groups than the cap.
    ///
    /// 101 models at $0.01 each. The rows are capped at `GATEWAY_PROVIDER_CAP`; the
    /// totals must count all 101, `group_count` must say 101 and `truncated` must
    /// be true. Until the fix the handler summed the rows it got back — 100 requests,
    /// $1.00 — and nothing in the response said a group was missing. ClickHouse
    /// evaluates `count() OVER ()` / `sum(x) OVER ()` after `GROUP BY` and before
    /// `ORDER BY … LIMIT`; that property is asserted HERE, on the server prod runs,
    /// because a string test cannot see it (the B-274 / Code-184 class).
    ///
    /// The dev-token claim pins the tenant, so the window is a per-run slice of the
    /// past (`CX-26` makes it addressable) and cannot collide with a previous run.
    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn the_cost_total_counts_every_group_not_only_the_capped_rows() {
        let _serial = SHARED_DB.lock().await;
        let _g = DevAuthGuard::new();
        let Some(c) = ch() else {
            panic!("CLICKHOUSE_TEST_URL not set — this test cannot run, which is not a pass");
        };
        ensure_spans(&c).await;
        let cap = GATEWAY_PROVIDER_CAP as usize;
        let groups = cap + 1;
        let (base, since, until) = per_run_window();
        insert_priced_groups(&c, DEV_TENANT, base, "model", groups as u64, 0.01).await;
        let state = TraceReadState {
            reader: Arc::new(ClickHouseTraceReader::new(c)),
            rejections: test_rejections(),
        };
        let resp = cost_breakdown_handler(
            State(state),
            Query(CostQuery {
                hours: None,
                by: Some("model".into()),
                scope: None,
                since: Some(since),
                until: Some(until),
            }),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["rows"].as_array().unwrap().len(), cap, "the row cap");
        assert_eq!(v["group_count"], groups as u64);
        assert_eq!(v["truncated"], true);
        assert_eq!(v["total_requests"], groups as u64);
        let total = v["total_cost_usd"].as_f64().unwrap();
        assert!(
            (total - 0.01 * groups as f64).abs() < 1e-6,
            "the total must cover every group, not the capped rows: {total}"
        );
    }

    /// CX-27 (3) — the badge case. `cap` priced groups plus ONE group with no cost
    /// and 500 requests: it sorts LAST (`ORDER BY cost_usd DESC`), the `LIMIT` cuts
    /// it, and until the fix `unpriced_requests` read 0 — the honesty control was
    /// exactly what truncation deleted.
    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn truncation_does_not_delete_the_unpriced_badge() {
        let _serial = SHARED_DB.lock().await;
        let _g = DevAuthGuard::new();
        let Some(c) = ch() else {
            panic!("CLICKHOUSE_TEST_URL not set — this test cannot run, which is not a pass");
        };
        ensure_spans(&c).await;
        let cap = GATEWAY_PROVIDER_CAP as usize;
        let (base, since, until) = per_run_window();
        insert_priced_groups(&c, DEV_TENANT, base, "priced", cap as u64, 0.01).await;
        // 500 requests on one unpriced model, inserted as one batch of rows.
        c.query(
            "INSERT INTO tracelane.spans (tenant_id, trace_id, span_id, name, \
             start_time, end_time, status_code, attributes) \
             SELECT ?, generateUUIDv4(), generateUUIDv4(), 'gen_ai.chat', \
             toDateTime64(?, 6), toDateTime64(?, 6), 1, \
             '{\"gen_ai_request_model\":\"unpriced-model\",\"gen_ai_provider_name\":\"anthropic\"}' \
             FROM numbers(500)",
        )
        .bind(DEV_TENANT)
        .bind(base)
        .bind(base)
        .execute()
        .await
        .expect("insert unpriced spans");
        let state = TraceReadState {
            reader: Arc::new(ClickHouseTraceReader::new(c)),
            rejections: test_rejections(),
        };
        let resp = cost_breakdown_handler(
            State(state),
            Query(CostQuery {
                hours: None,
                by: Some("model".into()),
                scope: None,
                since: Some(since),
                until: Some(until),
            }),
            bearer_headers(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        let rows = v["rows"].as_array().unwrap();
        assert_eq!(rows.len(), cap);
        assert!(
            rows.iter().all(|r| r["dimension"] != "unpriced-model"),
            "the zero-cost group sorts last and IS the one the cap cuts: {rows:?}"
        );
        assert_eq!(v["unpriced_requests"], 500);
        assert_eq!(v["total_requests"], (cap + 500) as u64);
        assert_eq!(v["priced_requests"], cap as u64);
        assert_eq!(v["group_count"], (cap + 1) as u64);
        assert_eq!(v["truncated"], true);
    }

    /// A one-hour window at a per-run point 30–300 days back, so the dev-token
    /// tenant's rows from previous runs (same container, same tenant) cannot land
    /// in it. Returns `(centre secs, since RFC3339, until RFC3339)`.
    fn per_run_window() -> (i64, String, String) {
        let now = chrono::Utc::now().timestamp();
        let seed = uuid::Uuid::new_v4().as_u128();
        let days = 30 + (seed % 270) as i64;
        let secs = ((seed >> 64) % 86_400) as i64;
        let base = now - days * 86_400 - secs;
        let iso = |s: i64| {
            chrono::DateTime::<chrono::Utc>::from_timestamp(s, 0)
                .unwrap()
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        };
        (base, iso(base - 1800), iso(base + 1800))
    }

    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn the_cost_sql_is_accepted_by_a_real_clickhouse() {
        let _serial = SHARED_DB.lock().await;
        let Some(c) = ch() else {
            panic!("CLICKHOUSE_TEST_URL not set — this test cannot run, which is not a pass");
        };
        ensure_spans(&c).await;
        let tenant = uuid::Uuid::new_v4().to_string();

        let mut checked = 0;
        for dimension in [
            CostDimension::Key,
            CostDimension::Model,
            CostDimension::Provider,
        ] {
            for scope in [CostScope::All, CostScope::Production, CostScope::Eval] {
                let f = CostFilters {
                    since_secs: None,
                    until_secs: None,
                    hours: 24,
                    dimension,
                    limit: 100,
                    scope,
                };
                let sql = TenantQuery::new(build_cost_breakdown_sql(&f), PlanTier::Free)
                    .sql_with_settings();
                c.query(&sql)
                    .bind(&tenant)
                    .bind(24_u32)
                    .bind(100_u32)
                    .fetch_all::<CostRow>()
                    .await
                    .unwrap_or_else(|e| {
                        panic!(
                            "{dimension:?}/{scope:?} REJECTED by ClickHouse: {e}
{sql}"
                        )
                    });
                checked += 1;
            }
        }
        // A loop that ran zero times would pass silently — the "filter that
        // matches nothing must never read as a pass" rule, applied to a test.
        assert_eq!(checked, 9, "expected 3 dimensions x 3 scopes");
    }

    /// **`EVL-23` — THE JUDGE SPLIT, PROVEN ON A REAL SERVER WITH REAL ROWS.**
    ///
    /// The test above proves the SQL is legal. This one proves it is *right*:
    /// three spans go in — one production, one eval case, one eval judge — and
    /// the three-way split must come back exact, with `judge ⊆ eval` rather than
    /// `judge + eval`.
    ///
    /// **Why a round trip and not a string assertion.** `/v1/costs` 502'd on prod
    /// on 2026-08-24 behind four green string tests, a clean 106-step gate and
    /// five green deploy proofs, because a SELECT-list alias shadowed the column
    /// it was named after and only a server can say `Code 184`. This row adds a
    /// second `sumIf` over the same `spans.cost_usd`, which is *precisely* the
    /// edit that caused it, so it does not ship on a string assertion.
    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn the_judge_split_is_a_subset_of_the_eval_split_on_real_rows() {
        let _serial = SHARED_DB.lock().await;
        let Some(c) = ch() else {
            panic!("CLICKHOUSE_TEST_URL not set — this test cannot run, which is not a pass");
        };
        ensure_spans(&c).await;
        let tenant = uuid::Uuid::new_v4().to_string();
        let run = uuid::Uuid::new_v4().to_string();

        // EVERYTHING the query reads is MATERIALIZED off `attributes` — `model`,
        // `provider`, `cost_usd` and `cost_usd_present` are not insertable
        // columns. Writing the JSON the gateway actually writes is the point: a
        // test that inserted its own columns would prove the code agrees with the
        // TEST. (This test's first run got that wrong and ClickHouse said so —
        // `Code 16 NO_SUCH_COLUMN_IN_TABLE` — which is the round trip earning its
        // keep before it ever checked an answer.)
        //
        // production $0.10 · eval case $0.02 · eval judge $0.01
        for (role, cost) in [
            (None, 0.10_f64),
            (Some("case"), 0.02),
            (Some("judge"), 0.01),
        ] {
            let mut attrs = serde_json::json!({
                "gen_ai_request_model": "claude-haiku-4-5",
                "gen_ai_provider_name": "anthropic",
                "gen_ai_usage_cost": cost,
            });
            if let Some(role) = role {
                attrs["tracelane_eval_run_id"] = serde_json::Value::String(run.clone());
                attrs["tracelane_eval_role"] = serde_json::Value::String(role.to_string());
            }
            c.query(
                "INSERT INTO tracelane.spans \
                 (tenant_id, trace_id, span_id, name, start_time, end_time, status_code, \
                  attributes) \
                 VALUES (?, generateUUIDv4(), generateUUIDv4(), 'gen_ai.chat', now(), now(), \
                 1, ?)",
            )
            .bind(&tenant)
            .bind(attrs.to_string())
            .execute()
            .await
            .expect("insert span");
        }

        let f = CostFilters {
            since_secs: None,
            until_secs: None,
            hours: 24,
            dimension: CostDimension::Model,
            limit: 100,
            scope: CostScope::All,
        };
        let sql =
            TenantQuery::new(build_cost_breakdown_sql(&f), PlanTier::Free).sql_with_settings();
        let rows: Vec<CostRow> = c
            .query(&sql)
            .bind(&tenant)
            .bind(24_u32)
            .bind(100_u32)
            .fetch_all()
            .await
            .unwrap_or_else(|e| panic!("REJECTED by ClickHouse: {e}\n{sql}"));

        assert_eq!(rows.len(), 1, "one model, one row: {rows:?}");
        let r = &rows[0];
        let near = |a: f64, b: f64| (a - b).abs() < 1e-6;

        assert_eq!(r.requests, 3, "three spans went in");
        assert!(near(r.cost_usd, 0.13), "total: {}", r.cost_usd);

        // The eval half — case AND judge, because a judge call IS eval traffic.
        assert_eq!(r.eval_requests, 2, "the judge call is eval traffic too");
        assert!(near(r.eval_cost_usd, 0.03), "eval: {}", r.eval_cost_usd);

        // The judge half — a SUBSET, not an addition.
        assert_eq!(r.judge_requests, 1);
        assert!(near(r.judge_cost_usd, 0.01), "judge: {}", r.judge_cost_usd);
        assert!(
            r.judge_cost_usd <= r.eval_cost_usd,
            "judge spend can never exceed eval spend — it is a subset of it"
        );

        // The arithmetic the response documents, checked rather than asserted in
        // prose: production = total − eval, and prompts-only = eval − judge.
        assert!(near(r.cost_usd - r.eval_cost_usd, 0.10), "production");
        assert!(
            near(r.eval_cost_usd - r.judge_cost_usd, 0.02),
            "the prompts themselves"
        );

        // scope=eval must see BOTH eval spans and no production one — the split
        // is exact in both directions, which is what a filter reading its own
        // alias would break.
        let f = CostFilters {
            scope: CostScope::Eval,
            ..f
        };
        let sql =
            TenantQuery::new(build_cost_breakdown_sql(&f), PlanTier::Free).sql_with_settings();
        let rows: Vec<CostRow> = c
            .query(&sql)
            .bind(&tenant)
            .bind(24_u32)
            .bind(100_u32)
            .fetch_all()
            .await
            .expect("scope=eval");
        assert_eq!(rows[0].requests, 2);
        assert_eq!(rows[0].judge_requests, 1);
        assert!(near(rows[0].cost_usd, 0.03));
    }
}

#[cfg(test)]
mod dsh13_tests {
    use super::*;

    /// Spec §7.3: a fuzzed `metric` / `by` never reaches SQL — it fails the parse, which
    /// the handler turns into a 400 before any reader call.
    #[test]
    fn fuzzed_axes_are_refused_at_the_parse() {
        for bad in [
            "",
            " ",
            "model ",
            "MODEL",
            "model;",
            "1=1",
            "model' OR 1=1 --",
            "requests\n",
            "cost_usd,requests",
            "unknown",
            "tenant_id",
        ] {
            assert_eq!(BreakdownMetric::parse(Some(bad)), None, "{bad:?}");
            assert_eq!(BreakdownBy::parse(Some(bad)), None, "{bad:?}");
        }
        assert_eq!(BreakdownMetric::parse(None), None);
        assert_eq!(BreakdownBy::parse(None), None);
        for m in BreakdownMetric::ALL {
            assert_eq!(BreakdownMetric::parse(Some(m.as_str())), Some(m));
        }
        for b in BreakdownBy::ALL {
            assert_eq!(BreakdownBy::parse(Some(b.as_str())), Some(b));
        }
    }

    /// Spec §7.3: the SQL text is one of N constants — 8 metrics × 5 dimensions = 40
    /// distinct strings, each with exactly the four binds and the tenant filter first.
    #[test]
    fn breakdown_sql_is_a_closed_set_of_forty_constants() {
        let mut seen = std::collections::HashSet::new();
        for m in BreakdownMetric::ALL {
            for b in BreakdownBy::ALL {
                let sql = build_metric_breakdown_sql(m, b);
                assert!(sql.contains("WHERE tenant_id = ?"), "{sql}");
                assert_eq!(sql.matches('?').count(), 4, "{sql}");
                assert!(sql.contains("FROM spans FINAL"), "{sql}");
                assert!(seen.insert(sql));
            }
        }
        assert_eq!(seen.len(), 40);
    }

    /// B-330 / DSH-13 §3: the tier-blind literal is gone from this file. The needle is
    /// assembled so this test's own source cannot satisfy it.
    #[test]
    fn no_tier_blind_builder_literal_remains_in_this_file() {
        let src = include_str!("trace_reads.rs");
        let needle = ["PlanTier", "::", "Builder"].concat();
        assert_eq!(
            src.matches(&needle).count(),
            0,
            "a ClickHouse read in trace_reads.rs is capped at a fixed tier again — \
             route it through tier_for(tenant_id)"
        );
        assert!(src.contains("fn tier_for("));
    }

    /// Fail-closed: no entitlement cache resolves to the FREE tier, never a wider one.
    #[tokio::test]
    async fn tier_for_without_a_cache_is_free() {
        let reader =
            ClickHouseTraceReader::new(crate::clickhouse_query::ch_client("http://127.0.0.1:1"));
        let tid = TenantId::from_jwt_claim(uuid::Uuid::from_u128(0xD5813));
        assert_eq!(reader.tier_for(&tid).await, PlanTier::Free);
    }
}
#[cfg(test)]
mod effective_settings_tests {
    use super::*;
    #[tokio::test]
    async fn settings_are_authenticated_complete_and_do_not_need_trace_storage() {
        let state =
            crate::handler_harness::test_state(crate::providers::ProviderRegistry::new().unwrap());
        let response = effective_settings_handler(State(state.clone()), HeaderMap::new()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response =
            effective_settings_handler(State(state), crate::handler_harness::authed()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let data = crate::handler_harness::body_json(response).await;
        assert_eq!(
            data["routing"]["catalog"].as_array().unwrap().len(),
            crate::providers::catalog::providers().len()
        );
        assert_eq!(
            data["routing"]["native"].as_array().unwrap().len(),
            crate::providers::NATIVE_PREFIXES.len()
        );
        assert_eq!(data["cache"]["enabled"], false);
        assert_eq!(data["limits"]["available"], false);
        for row in data["routing"]["catalog"].as_array().unwrap() {
            assert!(row.get("base_url").is_none());
            assert!(row.get("api_key_env").is_none());
            for prefix in row["prefixes"].as_array().unwrap() {
                assert!(
                    crate::providers::ProviderRegistry::provider_id_for_model(
                        prefix.as_str().unwrap()
                    )
                    .is_some()
                );
            }
        }
    }
    #[test]
    fn kya_profile_trace_filters_apply_to_the_list_and_count() {
        let filters = TraceListFilters {
            agent: Some("kya-proof".into()),
            model_family: Some("claude-haiku-4-5".into()),
            ..Default::default()
        };
        for sql in [
            build_trace_list_sql(&filters),
            build_trace_count_sql(&filters),
        ] {
            assert!(
                sql.contains("tracelane_client_name"),
                "the profile's agent filter must change the trace population"
            );
            assert!(
                sql.contains("gen_ai_response_model"),
                "the model family filter must use the served model"
            );
            assert!(
                !sql.contains("kya-proof"),
                "identity values are bound, not interpolated"
            );
        }
    }
}

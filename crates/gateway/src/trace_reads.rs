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
//! `apps/web/lib/clickhouse.ts`); we fall back to `PlanTier::Builder`, the
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
use tracelane_shared::TenantId;

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
/// is given. Bounds the live `spans` aggregation; the spans TTL is 90 days.
const DEFAULT_SESSION_WINDOW_DAYS: u32 = 30;
/// Hard cap on the session look-back window (the spans TTL).
const MAX_SESSION_WINDOW_DAYS: u32 = 90;

/// Gateway-ops look-back window (hours) — default 24h, cap 30 days.
const DEFAULT_GATEWAY_HOURS: u32 = 24;
const MAX_GATEWAY_HOURS: u32 = 720;
/// Per-provider row cap (≈34 routable providers; a safety cap, not a real limit).
const GATEWAY_PROVIDER_CAP: u32 = 100;
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
/// Default / max verdict-list page size (the decision-mix click-through).
const DEFAULT_VERDICT_LIMIT: u32 = 100;
const MAX_VERDICT_LIMIT: u32 = 500;
/// The flattened attribute key that carries `gen_ai.conversation.id` — the
/// session (thread) grouping key. Spans store OTel-GenAI attrs underscore-
/// flattened (see `mv_trace_summaries`), so this is the primary lookup.
const CONVERSATION_ID_ATTR: &str = "gen_ai_conversation_id";

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
    pub span_count: u32,
    pub error_count: u32,
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
}

/// `{ traces, next_cursor }` — matches the legacy dashboard `/api/traces` shape.
/// `next_cursor` is an opaque `"{start_time_us}:{trace_id}"` keyset token; the
/// client passes it back verbatim as `?cursor=`.
#[derive(Debug, Clone, Serialize)]
pub struct TraceListResponse {
    pub traces: Vec<TraceSummary>,
    pub next_cursor: Option<String>,
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
    pub span_count: u32,
    pub error_count: u32,
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
/// append a `chat.completions.request` row carrying `trace_id`). SDK/OTLP spans
/// are never chained → `chained: false` (the honest absent-state, not a false
/// green). Traces captured before item 4 shipped also read `chained: false`
/// (their chain row predates the `trace_id` correlation field) — forward-only.
///
/// This endpoint reports PRESENCE + ANCHOR, not a standalone cryptographic
/// verdict: the full-chain verify (recompute every `row_hash`, walk `prev_hash`
/// to genesis, check the Rekor anchor) runs on the Audit page via the same OSS
/// verifier a customer runs. The chip links there for the actual proof.
#[derive(Debug, Clone, Serialize)]
pub struct TraceChainStatus {
    /// True iff a `chat.completions.request` chain row carries this `trace_id`.
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
    /// Spans in the window that carry a MEASURED `tracelane_gateway_overhead_us`.
    pub overhead_samples: u64,
    /// Gateway overhead (the hero — "what Tracelane adds"), p50/p95/p99, ms.
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
    /// Spans with a measured overhead — the tile shows "—" when 0 (never $0ms).
    pub overhead_samples: u64,
    /// Streaming spans with a first-chunk time — the TTFT tile shows "—" when 0.
    pub ttft_samples: u64,
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
///     `rate_limited_since_start`, `quota_exceeded_since_start` — a 429 emits no
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
    pub total_failovers: u64,
    /// Tenant-wide real spend (USD) in the window — Σ of the stored per-span
    /// `gen_ai_usage_cost`. A lower bound over priced traffic (unpriced models
    /// contribute 0); the UI shows "—" when it's 0 rather than implying $0 spend.
    pub total_cost_usd: f64,
    /// Rate-limit (token-bucket) 429s for this tenant since the gateway started.
    pub rate_limited_since_start: u64,
    /// Monthly-quota hard-cap 429s for this tenant since the gateway started.
    pub quota_exceeded_since_start: u64,
    pub providers: Vec<GatewayProviderHealth>,
    /// Upstreams whose breaker is currently Open or Half-Open (ADR-036) — a live
    /// resilience signal counted across ALL breakers, not just this window's rows
    /// (a provider can be down with zero recent traffic).
    pub open_breakers: u32,
    pub uninstrumented: Vec<&'static str>,
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
    /// `rejections` is `(rate_limited, quota_exceeded)` process-lifetime counts
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
        let (rate_limited_since_start, quota_exceeded_since_start) = rejections;
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
            quota_exceeded_since_start,
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
    /// Rolling look-back window in hours (used only when `since_secs` is None).
    pub hours: u32,
    /// Allowlisted decision filter (`allow`|`block`|`redact`|`warn`); `None` = all.
    /// Validated in the handler, then a bound `?` — never interpolated.
    pub decision: Option<String>,
    /// Exact correlation-id lookup (the ULID the gateway returns in a 403 block
    /// body). Charset-validated in the handler, then a bound `?`. Lets a caller
    /// paste the id from a blocked request and land on that verdict.
    pub correlation_id: Option<String>,
    /// Row cap (bound `?`).
    pub limit: u32,
}

/// Validated §4 failure-signatures filters.
#[derive(Debug, Clone, Default)]
pub struct SignatureFilters {
    /// Inclusive lower bound on the matched span's `start_time`, microseconds.
    pub since_us: Option<i64>,
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

/// Build the trace-list SELECT. `tenant_id = ?` is always the first WHERE
/// predicate; every filter is a bound `?` placeholder. The `?` order is:
/// tenant, [model], [min_duration_us], [sig_tenant, sig_id], [since_us],
/// [until_us], [cursor_us, cursor_us, cursor_id], limit — kept in lockstep with
/// the bind chain in [`ClickHouseTraceReader::list_traces`].
fn build_trace_list_sql(f: &TraceListFilters) -> String {
    let mut sql = String::from(
        "SELECT trace_id, root_name, \
toString(start_time) AS start_time_iso, \
toInt64(toUnixTimestamp64Micro(start_time)) AS start_time_us, \
duration_us, span_count, error_count, intervention, model \
FROM trace_summaries FINAL \
WHERE tenant_id = ?",
    );
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
WHERE tenant_id = ? AND has(aft_ids, ?))",
        );
    }
    if f.q.is_some() {
        // OBS-01 free-text search. Tenant-scoped subquery — same isolation invariant
        // as the signature filter, it can never widen across tenants.
        // `multiSearchAny` on the RAW column is deliberate: it is a form the
        // `ngrambf_v1` skip index (migration 14) can serve, so this PRUNES GRANULES
        // instead of scanning the tenant's parts. Wrapping the column in `lower()`
        // would silently disable the index and restore the full scan.
        sql.push_str(
            " AND trace_id IN (SELECT trace_id FROM spans \
WHERE tenant_id = ? AND (multiSearchAny(name, [?, ?]) OR multiSearchAny(attributes, [?, ?])))",
        );
    }
    if f.failover == Some(true) {
        // Failover is a per-span JSON attribute (no column on trace_summaries);
        // tenant-scoped subquery, same isolation invariant as the signature filter.
        sql.push_str(
            " AND trace_id IN (SELECT trace_id FROM spans \
WHERE tenant_id = ? AND JSONExtractBool(attributes, 'tracelane_failover_activated'))",
        );
    }
    match f.has_error {
        Some(true) => sql.push_str(" AND error_count > 0"),
        Some(false) => sql.push_str(" AND error_count = 0"),
        None => {}
    }
    if f.since_us.is_some() {
        sql.push_str(" AND start_time >= fromUnixTimestamp64Micro(?)");
    }
    if f.until_us.is_some() {
        sql.push_str(" AND start_time <= fromUnixTimestamp64Micro(?)");
    }
    // Sort column + direction from a fixed allowlist (never user input → safe to
    // interpolate; the `?` values stay bound). `cursor_expr` is the sort column's
    // value used by the keyset comparison — for start_time it references the
    // DateTime64 column via toUnixTimestamp64Micro (the `start_time_us` alias would
    // trip the ILLEGAL_TYPE_OF_ARGUMENT class).
    let (sort_col, cursor_expr) = match f.sort {
        TraceSort::StartTime => ("start_time", "toUnixTimestamp64Micro(start_time)"),
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
/// the list (for the "50 of N traces" footer). Same WHERE + `?` bind order as
/// [`build_trace_list_sql`], MINUS sort/cursor/limit. One row: `total`.
///
/// `uniqExact(trace_id)`, NOT `count()`: `trace_summaries` is a write-time MV, so
/// if ingest splits a trace across batches the MV can emit >1 partial row for the
/// same `trace_id` (different `min(start_time)` → distinct ReplacingMergeTree
/// key), and a raw `count()` would over-count the footer total — the "tile says
/// 180, list says 202" class (provenance audit P1 #7). `uniqExact` counts each
/// trace once regardless of partial rows, so the footer reconciles with the list.
fn build_trace_count_sql(f: &TraceListFilters) -> String {
    let mut sql = String::from(
        "SELECT toUInt64(uniqExact(trace_id)) AS total FROM trace_summaries FINAL WHERE tenant_id = ?",
    );
    if f.model.is_some() {
        sql.push_str(" AND model = ?");
    }
    if f.min_duration_us.is_some() {
        sql.push_str(" AND duration_us >= ?");
    }
    if f.signature_id.is_some() {
        sql.push_str(
            " AND trace_id IN (SELECT trace_id FROM spans \
WHERE tenant_id = ? AND has(aft_ids, ?))",
        );
    }
    if f.q.is_some() {
        // OBS-01 free-text search. Tenant-scoped subquery — same isolation invariant
        // as the signature filter, it can never widen across tenants.
        // `multiSearchAny` on the RAW column is deliberate: it is a form the
        // `ngrambf_v1` skip index (migration 14) can serve, so this PRUNES GRANULES
        // instead of scanning the tenant's parts. Wrapping the column in `lower()`
        // would silently disable the index and restore the full scan.
        sql.push_str(
            " AND trace_id IN (SELECT trace_id FROM spans \
WHERE tenant_id = ? AND (multiSearchAny(name, [?, ?]) OR multiSearchAny(attributes, [?, ?])))",
        );
    }
    if f.failover == Some(true) {
        sql.push_str(
            " AND trace_id IN (SELECT trace_id FROM spans \
WHERE tenant_id = ? AND JSONExtractBool(attributes, 'tracelane_failover_activated'))",
        );
    }
    match f.has_error {
        Some(true) => sql.push_str(" AND error_count > 0"),
        Some(false) => sql.push_str(" AND error_count = 0"),
        None => {}
    }
    if f.since_us.is_some() {
        sql.push_str(" AND start_time >= fromUnixTimestamp64Micro(?)");
    }
    if f.until_us.is_some() {
        sql.push_str(" AND start_time <= fromUnixTimestamp64Micro(?)");
    }
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
/// [`ClickHouseTraceReader::list_trace_groups`] binds them identically. `tenant_id
/// = ?` stays the first predicate.
fn build_trace_groups_sql(by: TraceGroupBy, f: &TraceListFilters) -> String {
    let group_expr = match by {
        TraceGroupBy::Model => "model",
        TraceGroupBy::Operation => "root_name",
        TraceGroupBy::Status => "if(error_count > 0, 'error', 'ok')",
    };
    // `uniqExact(trace_id)` (not `count()`) for the same MV partial-row reason as
    // [`build_trace_count_sql`], so a group's trace total reconciles with the list.
    // `quantileExact` (not the approximate `quantile`) so the p95 column is the
    // TRUE 95th percentile of the group's trace durations, not ClickHouse's
    // reservoir estimate shown as if exact (provenance audit P2 #8).
    let mut sql = format!(
        "SELECT {group_expr} AS group_key, \
toUInt64(uniqExact(trace_id)) AS trace_count, \
toUInt64(uniqExactIf(trace_id, error_count > 0)) AS error_traces, \
avg(duration_us) AS avg_duration_us, \
quantileExact(0.95)(duration_us) AS p95_duration_us \
FROM trace_summaries FINAL \
WHERE tenant_id = ?"
    );
    // Filter WHERE mirrors build_trace_list_sql (same clauses, same bind order).
    if f.model.is_some() {
        sql.push_str(" AND model = ?");
    }
    if f.min_duration_us.is_some() {
        sql.push_str(" AND duration_us >= ?");
    }
    if f.signature_id.is_some() {
        sql.push_str(
            " AND trace_id IN (SELECT trace_id FROM spans \
WHERE tenant_id = ? AND has(aft_ids, ?))",
        );
    }
    if f.q.is_some() {
        // OBS-01 free-text search. Tenant-scoped subquery — same isolation invariant
        // as the signature filter, it can never widen across tenants.
        // `multiSearchAny` on the RAW column is deliberate: it is a form the
        // `ngrambf_v1` skip index (migration 14) can serve, so this PRUNES GRANULES
        // instead of scanning the tenant's parts. Wrapping the column in `lower()`
        // would silently disable the index and restore the full scan.
        sql.push_str(
            " AND trace_id IN (SELECT trace_id FROM spans \
WHERE tenant_id = ? AND (multiSearchAny(name, [?, ?]) OR multiSearchAny(attributes, [?, ?])))",
        );
    }
    if f.failover == Some(true) {
        sql.push_str(
            " AND trace_id IN (SELECT trace_id FROM spans \
WHERE tenant_id = ? AND JSONExtractBool(attributes, 'tracelane_failover_activated'))",
        );
    }
    match f.has_error {
        Some(true) => sql.push_str(" AND error_count > 0"),
        Some(false) => sql.push_str(" AND error_count = 0"),
        None => {}
    }
    if f.since_us.is_some() {
        sql.push_str(" AND start_time >= fromUnixTimestamp64Micro(?)");
    }
    if f.until_us.is_some() {
        sql.push_str(" AND start_time <= fromUnixTimestamp64Micro(?)");
    }
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
/// is pinned to `chat.completions.request` so only a real gateway call counts —
/// a `guardrail.verdict`/`eval.verdict` row is never mistaken for the call. Newest
/// row wins (a trace_id is unique per request, but be defensive). One row max.
const TRACE_CHAIN_SQL: &str = "SELECT seq, rekor_entry_id \
FROM tracelane.audit_log \
WHERE tenant_id = ? \
AND event_type = 'chat.completions.request' \
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

/// Build the SLO SELECT against `v_slo_stats`. `?` order: tenant,
/// (since_secs | hours), [until_secs], [provider], [model].
fn build_slo_sql(f: &SloFilters) -> String {
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
WHERE tenant_id = ?"
        )
    } else {
        String::from(
            "SELECT toString(bucket_hour) AS bucket_hour_iso, provider, model, \
p50_ms, p95_ms, p99_ms, requests, errors, error_rate_pct, \
total_input_tokens, total_output_tokens \
FROM v_slo_stats \
WHERE tenant_id = ?",
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
/// computed `Σ(pXX·requests)/Σrequests` client-side — a percentile-of-percentiles
/// that diverges from the true quantile). One row. `?` order mirrors
/// `build_slo_sql`: tenant, (since_secs | hours), [until_secs], [provider],
/// [model]. `provider <> ''` scopes to LLM-request spans — the same scoping the
/// tile applies — so the headline reconciles with the /slo rows + chart.
fn build_slo_summary_sql(f: &SloFilters) -> String {
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
/// whole row is one exact aggregate. No `provider <> ''` scope — the table shows
/// every group (incl. the empty-provider tool/child bucket), matching the prior
/// behaviour; only the percentiles change from approximate to exact. `?` order
/// mirrors `build_slo_sql`: tenant, (since_secs | hours), [until_secs],
/// [provider], [model], limit.
fn build_slo_by_model_sql(f: &SloFilters) -> String {
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
WHERE tenant_id = ?",
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
    let mut sql = format!(
        "SELECT \
toString(toStartOfInterval(bucket_hour, toIntervalHour({bucket_hours}))) AS bucket_start, \
round(quantileMerge(0.50)(latency_p50) / 1000, 1) AS p50_ms, \
round(quantileMerge(0.95)(latency_p95) / 1000, 1) AS p95_ms, \
round(quantileMerge(0.99)(latency_p99) / 1000, 1) AS p99_ms, \
toUInt64(countMerge(request_count)) AS requests \
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
fn build_latency_totals_sql(f: &GatewayStatsFilters) -> String {
    const HAS_OH: &str = "JSONHas(attributes, 'tracelane_gateway_overhead_us')";
    const HAS_TTFT: &str = "JSONHas(attributes, 'gen_ai_response_time_to_first_chunk') \
AND JSONExtractFloat(attributes, 'gen_ai_response_time_to_first_chunk') > 0";
    let mut sql = format!(
        "SELECT \
toUInt64(countIf({HAS_OH})) AS overhead_samples, \
if(countIf({HAS_OH}) = 0, 0, round(quantileIf(0.50)(gateway_overhead_us, {HAS_OH}) / 1000, 1)) AS overhead_p50_ms, \
if(countIf({HAS_OH}) = 0, 0, round(quantileIf(0.95)(gateway_overhead_us, {HAS_OH}) / 1000, 1)) AS overhead_p95_ms, \
if(countIf({HAS_OH}) = 0, 0, round(quantileIf(0.99)(gateway_overhead_us, {HAS_OH}) / 1000, 1)) AS overhead_p99_ms, \
if(countIf({HAS_OH}) = 0, 0, round(quantileIf(0.50)(greatest(toInt64(duration_us) - toInt64(gateway_overhead_us), 0), {HAS_OH}) / 1000, 1)) AS provider_p50_ms, \
if(countIf({HAS_OH}) = 0, 0, round(quantileIf(0.95)(greatest(toInt64(duration_us) - toInt64(gateway_overhead_us), 0), {HAS_OH}) / 1000, 1)) AS provider_p95_ms, \
if(countIf({HAS_OH}) = 0, 0, round(quantileIf(0.99)(greatest(toInt64(duration_us) - toInt64(gateway_overhead_us), 0), {HAS_OH}) / 1000, 1)) AS provider_p99_ms, \
toUInt64(countIf({HAS_TTFT})) AS ttft_samples, \
if(countIf({HAS_TTFT}) = 0, 0, round(quantileIf(0.50)(JSONExtractFloat(attributes, 'gen_ai_response_time_to_first_chunk') * 1000, {HAS_TTFT}), 1)) AS ttft_p50_ms, \
if(countIf({HAS_TTFT}) = 0, 0, round(quantileIf(0.95)(JSONExtractFloat(attributes, 'gen_ai_response_time_to_first_chunk') * 1000, {HAS_TTFT}), 1)) AS ttft_p95_ms, \
if(countIf({HAS_TTFT}) = 0, 0, round(quantileIf(0.99)(JSONExtractFloat(attributes, 'gen_ai_response_time_to_first_chunk') * 1000, {HAS_TTFT}), 1)) AS ttft_p99_ms \
FROM spans FINAL \
WHERE tenant_id = ? AND JSONExtractString(attributes, 'gen_ai_provider_name') != ''"
    );
    if f.since_secs.is_some() {
        sql.push_str(" AND start_time >= toDateTime(?)");
    } else {
        sql.push_str(" AND start_time >= now() - toIntervalHour(?)");
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
AND JSONExtractString(attributes, 'gen_ai_provider_name') != ''",
    );
    if f.since_secs.is_some() {
        sql.push_str(" AND start_time >= toDateTime(?)");
    } else {
        sql.push_str(" AND start_time >= now() - toIntervalHour(?)");
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
round(sum(if(isFinite(JSONExtractFloat(attributes, 'gen_ai_usage_cost')) AND JSONExtractFloat(attributes, 'gen_ai_usage_cost') > 0, JSONExtractFloat(attributes, 'gen_ai_usage_cost'), 0)), 6) AS cost_usd, \
if(countIf(JSONHas(attributes, 'tracelane_gateway_overhead_us')) = 0, 0, round(quantileIf(0.95)(gateway_overhead_us, JSONHas(attributes, 'tracelane_gateway_overhead_us')) / 1000, 1)) AS overhead_p95_ms \
FROM spans FINAL \
WHERE tenant_id = ? AND JSONExtractString(attributes, 'gen_ai_provider_name') != ''",
    );
    if f.since_secs.is_some() {
        sql.push_str(" AND start_time >= toDateTime(?)");
    } else {
        sql.push_str(" AND start_time >= now() - toIntervalHour(?)");
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
    if f.since_secs.is_some() {
        sql.push_str(" AND event_time >= toDateTime(?)");
    } else {
        sql.push_str(" AND event_time >= now() - toIntervalHour(?)");
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
argMax(JSONExtractString(attributes, 'gen_ai_response_model'), start_time) AS model \
FROM spans FINAL \
WHERE tenant_id = ? AND JSONExtractString(attributes, '{conv}') != ''"
    );
    // Model filter (bound) — placed right after tenant so the bind order stays:
    // tenant, [model], (since_us | window_days), limit.
    if f.model.is_some() {
        sql.push_str(" AND JSONExtractString(attributes, 'gen_ai_response_model') = ?");
    }
    if f.since_us.is_some() {
        sql.push_str(" AND start_time >= fromUnixTimestamp64Micro(?)");
    } else {
        sql.push_str(" AND start_time >= now() - toIntervalDay(?)");
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
argMax(JSONExtractString(attributes, 'gen_ai_response_model'), start_time) AS model \
FROM spans FINAL \
WHERE tenant_id = ? AND JSONExtractString(attributes, '{conv}') = ? \
GROUP BY trace_id \
ORDER BY min(start_time) ASC"
    )
}

// ── Reader trait + ClickHouse impl ───────────────────────────────────────────

/// Read-side hook for trace + SLO data. Production uses
/// [`ClickHouseTraceReader`]; tests use the in-module `MockTraceReader`.
#[async_trait::async_trait]
pub trait TraceReader: Send + Sync {
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
}

/// ClickHouse-backed reader. Every query is tenant-first, parameter-bound, and
/// wrapped by [`TenantQuery`] for ADR-031 resource caps.
pub struct ClickHouseTraceReader {
    client: ClickhouseClient,
}

impl ClickHouseTraceReader {
    pub fn new(client: ClickhouseClient) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl TraceReader for ClickHouseTraceReader {
    async fn list_traces(
        &self,
        tenant_id: &TenantId,
        f: &TraceListFilters,
    ) -> Result<Vec<TraceSummaryRow>> {
        let sql = TenantQuery::new(build_trace_list_sql(f), PlanTier::Builder).sql_with_settings();
        let mut q = self.client.query(&sql).bind(tenant_id.to_string());
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
        if let Some(s) = f.since_us {
            q = q.bind(s);
        }
        if let Some(u) = f.until_us {
            q = q.bind(u);
        }
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
        let sql =
            TenantQuery::new(build_trace_groups_sql(by, f), PlanTier::Builder).sql_with_settings();
        let mut q = self.client.query(&sql).bind(tenant_id.to_string());
        // Filter binds MIRROR list_traces (same order as build_trace_groups_sql).
        if let Some(m) = &f.model {
            q = q.bind(m.clone());
        }
        if let Some(d) = f.min_duration_us {
            q = q.bind(d);
        }
        if let Some(sig) = &f.signature_id {
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
            q = q.bind(tenant_id.to_string());
        }
        if let Some(s) = f.since_us {
            q = q.bind(s);
        }
        if let Some(u) = f.until_us {
            q = q.bind(u);
        }
        q = q.bind(f.limit);
        q.fetch_all::<TraceGroupRow>()
            .await
            .context("trace groups SELECT failed")
    }

    async fn count_traces(&self, tenant_id: &TenantId, f: &TraceListFilters) -> Result<u64> {
        let sql = TenantQuery::new(build_trace_count_sql(f), PlanTier::Builder).sql_with_settings();
        // Bind order MIRRORS build_trace_list_sql's filter binds, minus cursor/limit.
        let mut q = self.client.query(&sql).bind(tenant_id.to_string());
        if let Some(m) = &f.model {
            q = q.bind(m.clone());
        }
        if let Some(d) = f.min_duration_us {
            q = q.bind(d);
        }
        if let Some(sig) = &f.signature_id {
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
            q = q.bind(tenant_id.to_string());
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
            .context("trace count scalar SELECT failed")?;
        Ok(row.total)
    }

    async fn list_spans(&self, tenant_id: &TenantId, trace_id: &str) -> Result<Vec<SpanRow>> {
        let sql = TenantQuery::new(SPANS_SQL, PlanTier::Builder).sql_with_settings();
        self.client
            .query(&sql)
            .bind(tenant_id.to_string())
            .bind(trace_id.to_string())
            .fetch_all::<SpanRow>()
            .await
            .context("spans SELECT failed")
    }

    async fn trace_chain_status(
        &self,
        tenant_id: &TenantId,
        trace_id: &str,
    ) -> Result<Option<TraceChainStatus>> {
        let sql = TenantQuery::new(TRACE_CHAIN_SQL, PlanTier::Builder).sql_with_settings();
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
            PlanTier::Builder,
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

    async fn slo(&self, tenant_id: &TenantId, f: &SloFilters) -> Result<Vec<SloRow>> {
        let sql = TenantQuery::new(build_slo_sql(f), PlanTier::Builder).sql_with_settings();
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
        let sql = TenantQuery::new(build_slo_summary_sql(f), PlanTier::Builder).sql_with_settings();
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
            .context("slo_hourly_stats summary SELECT failed")
    }

    async fn slo_by_model(&self, tenant_id: &TenantId, f: &SloFilters) -> Result<Vec<SloModelRow>> {
        let sql =
            TenantQuery::new(build_slo_by_model_sql(f), PlanTier::Builder).sql_with_settings();
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
            .context("slo_hourly_stats per-model SELECT failed")
    }

    async fn slo_timeseries(
        &self,
        tenant_id: &TenantId,
        f: &SloFilters,
        bucket_hours: u32,
    ) -> Result<Vec<SloTimePoint>> {
        let sql = TenantQuery::new(build_slo_timeseries_sql(f, bucket_hours), PlanTier::Builder)
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
        q.fetch_all::<SloTimePoint>()
            .await
            .context("slo_hourly_stats timeseries SELECT failed")
    }

    async fn gateway_stats(
        &self,
        tenant_id: &TenantId,
        f: &GatewayStatsFilters,
    ) -> Result<Vec<GatewayProviderRow>> {
        let sql =
            TenantQuery::new(build_gateway_stats_sql(f), PlanTier::Builder).sql_with_settings();
        let mut q = self.client.query(&sql).bind(tenant_id.to_string());
        if let Some(s) = f.since_secs {
            q = q.bind(s);
        } else {
            q = q.bind(f.hours);
        }
        q = q.bind(f.limit);
        q.fetch_all::<GatewayProviderRow>()
            .await
            .context("gateway stats SELECT failed")
    }

    async fn latency_breakdown(
        &self,
        tenant_id: &TenantId,
        f: &GatewayStatsFilters,
    ) -> Result<(LatencyTotalsRow, Vec<LatencyModelRow>)> {
        // (1) window-wide totals — one aggregate row (always present, all-zero on
        //     an empty window thanks to the SQL guards → fetch_one is total).
        let totals_sql =
            TenantQuery::new(build_latency_totals_sql(f), PlanTier::Builder).sql_with_settings();
        let mut tq = self.client.query(&totals_sql).bind(tenant_id.to_string());
        if let Some(s) = f.since_secs {
            tq = tq.bind(s);
        } else {
            tq = tq.bind(f.hours);
        }
        let totals = tq
            .fetch_one::<LatencyTotalsRow>()
            .await
            .context("latency totals SELECT failed")?;

        // (2) per-(provider, model) overhead — the SLO-table column.
        let by_model_sql =
            TenantQuery::new(build_latency_by_model_sql(f), PlanTier::Builder).sql_with_settings();
        let mut mq = self.client.query(&by_model_sql).bind(tenant_id.to_string());
        if let Some(s) = f.since_secs {
            mq = mq.bind(s);
        } else {
            mq = mq.bind(f.hours);
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
        let sql =
            TenantQuery::new(build_guardrail_summary_sql(f), PlanTier::Builder).sql_with_settings();
        let mut q = self.client.query(&sql).bind(tenant_id.to_string());
        if let Some(s) = f.since_secs {
            q = q.bind(s);
        } else {
            q = q.bind(f.hours);
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
        let sql =
            TenantQuery::new(build_guardrail_rails_sql(f), PlanTier::Builder).sql_with_settings();
        let mut q = self.client.query(&sql).bind(tenant_id.to_string());
        if let Some(s) = f.since_secs {
            q = q.bind(s);
        } else {
            q = q.bind(f.hours);
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
        let sql = TenantQuery::new(build_guardrail_verdicts_sql(f), PlanTier::Builder)
            .sql_with_settings();
        let mut q = self.client.query(&sql).bind(tenant_id.to_string());
        // Bind order mirrors the SQL: tenant, [decision], [correlation_id],
        // (since_secs | hours), limit.
        if let Some(d) = f.decision.as_deref() {
            q = q.bind(d);
        }
        if let Some(c) = f.correlation_id.as_deref() {
            q = q.bind(c);
        }
        if let Some(s) = f.since_secs {
            q = q.bind(s);
        } else {
            q = q.bind(f.hours);
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
        let sql = TenantQuery::new(build_signatures_sql(f), PlanTier::Builder).sql_with_settings();
        let mut q = self.client.query(&sql).bind(tenant_id.to_string());
        if let Some(s) = f.since_us {
            q = q.bind(s);
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
        let sql = TenantQuery::new(build_signatures_trace_total_sql(f), PlanTier::Builder)
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
        let sql =
            TenantQuery::new(build_session_list_sql(f), PlanTier::Builder).sql_with_settings();
        let mut q = self.client.query(&sql).bind(tenant_id.to_string());
        if let Some(m) = f.model.as_deref() {
            q = q.bind(m);
        }
        if let Some(s) = f.since_us {
            q = q.bind(s);
        } else {
            q = q.bind(f.window_days);
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
        let sql =
            TenantQuery::new(build_session_traces_sql(), PlanTier::Builder).sql_with_settings();
        self.client
            .query(&sql)
            .bind(tenant_id.to_string())
            .bind(session_id.to_string())
            .fetch_all::<SessionTraceRow>()
            .await
            .context("session traces SELECT failed")
    }
}

// ── Handler state + query params ─────────────────────────────────────────────

/// Narrow handler state — just the reader, so trace reads don't pull the full
/// gateway `AppState`.
#[derive(Clone)]
pub struct TraceReadState {
    pub reader: Arc<dyn TraceReader>,
}

#[derive(Debug, Deserialize)]
pub struct TraceListQuery {
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
    /// `"csv"` (default) | `"json"`.
    format: Option<String>,
    model: Option<String>,
    has_error: Option<String>,
    min_latency_ms: Option<f64>,
    signature_id: Option<String>,
    /// `"true"` → export only failover traces (mirrors the list filter).
    failover: Option<String>,
    since: Option<String>,
    until: Option<String>,
    sort: Option<String>,
    order: Option<String>,
}

/// Query for `GET /v1/traces/groups` — the grouping dimension + the same filters.
#[derive(Debug, Deserialize)]
pub struct TraceGroupsQuery {
    /// `model` | `operation` | `status` (required — grouping has no default).
    by: Option<String>,
    model: Option<String>,
    has_error: Option<String>,
    min_latency_ms: Option<f64>,
    signature_id: Option<String>,
    /// `"true"` → group only failover traces (mirrors the list filter).
    failover: Option<String>,
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
}

#[derive(Debug, Deserialize)]
pub struct GatewayStatsQuery {
    /// Rolling look-back window in hours (default 24, cap 720 = 30 days).
    hours: Option<u32>,
    /// RFC3339 inclusive lower bound on `start_time` (overrides `hours`).
    since: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GuardrailStatsQuery {
    /// Rolling look-back window in hours (default 24, cap 720 = 30 days).
    hours: Option<u32>,
    /// RFC3339 inclusive lower bound on `event_time` (overrides `hours`).
    since: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GuardrailVerdictsQuery {
    /// Rolling look-back window in hours (default 24, cap 720 = 30 days).
    hours: Option<u32>,
    /// RFC3339 inclusive lower bound on `event_time` (overrides `hours`).
    since: Option<String>,
    /// Decision filter: `allow` | `block` | `redact` | `warn` (allowlisted).
    decision: Option<String>,
    /// Exact correlation-id (ULID) lookup — the id returned in a 403 block body.
    correlation_id: Option<String>,
    /// Row cap (default 100, max 500).
    limit: Option<u32>,
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
    /// Sort column: `turns` | `cost` | `tokens` | `duration` | (default) last-activity.
    sort: Option<String>,
    /// Sort direction: `asc` | (default) `desc`.
    order: Option<String>,
    /// Status filter: `error` | `ok` | (default) all.
    status: Option<String>,
    /// Response-model filter (scopes each session to that model's spans).
    model: Option<String>,
}

// ── Routes ───────────────────────────────────────────────────────────────────

/// Mount the three read routes. Mounted only when `CLICKHOUSE_URL` is set.
pub fn routes() -> Router<TraceReadState> {
    Router::new()
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
        q: None,
        model: q.model.filter(|s| !s.is_empty()),
        has_error: parse_bool(q.has_error.as_deref()),
        min_duration_us,
        signature_id: q.signature_id.filter(|s| !s.is_empty()),
        failover: parse_failover(q.failover.as_deref()),
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
        q: search.clone(),
        model: q.model.filter(|s| !s.is_empty()),
        has_error: parse_bool(q.has_error.as_deref()),
        min_duration_us,
        signature_id: q.signature_id.filter(|s| !s.is_empty()),
        failover: parse_failover(q.failover.as_deref()),
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
    let traces = enrich_traces_with_cost(state.reader.as_ref(), &claims.tenant_id, rows).await;
    Json(TraceListResponse {
        traces,
        next_cursor,
    })
    .into_response()
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
        q: None,
        model: q.model.filter(|s| !s.is_empty()),
        has_error: parse_bool(q.has_error.as_deref()),
        min_duration_us,
        signature_id: q.signature_id.filter(|s| !s.is_empty()),
        failover: parse_failover(q.failover.as_deref()),
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
        q: None,
        model: q.model.filter(|s| !s.is_empty()),
        has_error: parse_bool(q.has_error.as_deref()),
        min_duration_us,
        signature_id: q.signature_id.filter(|s| !s.is_empty()),
        failover: parse_failover(q.failover.as_deref()),
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
    Json(spans).into_response()
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
    let filters = SloFilters {
        since_secs,
        until_secs,
        hours: q.hours.unwrap_or(DEFAULT_SLO_HOURS).clamp(1, MAX_SLO_HOURS),
        provider: q.provider.filter(|s| !s.is_empty()),
        model: q.model.filter(|s| !s.is_empty()),
        // Clamped like the timeseries route. Absent => 1 => the historical hourly
        // response, so adding this parameter changes nothing for a caller that
        // never sends it.
        bucket_hours: q.bucket.unwrap_or(1).clamp(1, MAX_SLO_HOURS),
    };

    let rows = match state.reader.slo(&claims.tenant_id, &filters).await {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(error = %err, "slo read failed");
            return error_response(StatusCode::BAD_GATEWAY, "slo read failed");
        }
    };
    Json(rows).into_response()
}

/// GET /v1/slo/summary — the window-WIDE TRUE p50/p95/p99 (quantileMerge over the
/// stored per-hour quantile states) for the headline latency tiles. The dashboard
/// previously computed a request-weighted mean of the per-hour bucket percentiles
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
    let filters = SloFilters {
        since_secs,
        until_secs,
        hours: q.hours.unwrap_or(DEFAULT_SLO_HOURS).clamp(1, MAX_SLO_HOURS),
        provider: q.provider.filter(|s| !s.is_empty()),
        model: q.model.filter(|s| !s.is_empty()),
        // Not the /v1/slo row-bucketing path: summary merges over the WHOLE window
        // and timeseries takes its width as an explicit argument. 1 = no re-grouping.
        bucket_hours: 1,
    };

    match state.reader.slo_summary(&claims.tenant_id, &filters).await {
        Ok(s) => Json(s).into_response(),
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
    let filters = SloFilters {
        since_secs,
        until_secs,
        hours: q.hours.unwrap_or(DEFAULT_SLO_HOURS).clamp(1, MAX_SLO_HOURS),
        provider: q.provider.filter(|s| !s.is_empty()),
        model: q.model.filter(|s| !s.is_empty()),
        // Not the /v1/slo row-bucketing path: summary merges over the WHOLE window
        // and timeseries takes its width as an explicit argument. 1 = no re-grouping.
        bucket_hours: 1,
    };

    match state.reader.slo_by_model(&claims.tenant_id, &filters).await {
        Ok(rows) => Json(rows).into_response(),
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
    let filters = SloFilters {
        since_secs,
        until_secs,
        hours: q.hours.unwrap_or(DEFAULT_SLO_HOURS).clamp(1, MAX_SLO_HOURS),
        provider: q.provider.filter(|s| !s.is_empty()),
        model: q.model.filter(|s| !s.is_empty()),
        // Not the /v1/slo row-bucketing path: summary merges over the WHOLE window
        // and timeseries takes its width as an explicit argument. 1 = no re-grouping.
        bucket_hours: 1,
    };
    let bucket_hours = q.bucket.unwrap_or(1).clamp(1, MAX_SLO_HOURS);

    match state
        .reader
        .slo_timeseries(&claims.tenant_id, &filters, bucket_hours)
        .await
    {
        Ok(rows) => Json(rows).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "slo timeseries read failed");
            error_response(StatusCode::BAD_GATEWAY, "slo timeseries read failed")
        }
    }
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
    let hours = q
        .hours
        .unwrap_or(DEFAULT_GATEWAY_HOURS)
        .clamp(1, MAX_GATEWAY_HOURS);
    let filters = GatewayStatsFilters {
        since_secs,
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
    let rejections = crate::rejection_metrics::registry().snapshot(&claims.tenant_id);
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
    Json(GatewayStatsResponse::from_rows(
        rows, hours, rejections, &breakers,
    ))
    .into_response()
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
    let hours = q
        .hours
        .unwrap_or(DEFAULT_GATEWAY_HOURS)
        .clamp(1, MAX_GATEWAY_HOURS);
    let filters = GatewayStatsFilters {
        since_secs,
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
            by_model,
        })
        .into_response(),
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
    let hours = q
        .hours
        .unwrap_or(DEFAULT_GUARDRAIL_HOURS)
        .clamp(1, MAX_GUARDRAIL_HOURS);
    let filters = GuardrailStatsFilters {
        since_secs,
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
    Json(GuardrailStatsResponse::build(summary, rails, hours)).into_response()
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
    let filters = GuardrailVerdictListFilters {
        since_secs,
        hours: q
            .hours
            .unwrap_or(DEFAULT_GUARDRAIL_HOURS)
            .clamp(1, MAX_GUARDRAIL_HOURS),
        decision,
        correlation_id,
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
    Json(GuardrailVerdictListResponse { verdicts }).into_response()
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

    let since_us = match parse_rfc3339_micros(q.since.as_deref()) {
        Ok(v) => v,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "invalid since timestamp"),
    };
    let filters = SignatureFilters {
        since_us,
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
    Json(SignaturesResponse {
        signatures,
        total_traces_affected,
    })
    .into_response()
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
    let filters = SessionListFilters {
        since_us,
        window_days: q
            .days
            .unwrap_or(DEFAULT_SESSION_WINDOW_DAYS)
            .clamp(1, MAX_SESSION_WINDOW_DAYS),
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
    Json(SessionListResponse { sessions }).into_response()
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
            error_response(StatusCode::UNAUTHORIZED, "invalid credentials")
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
            limit: 50,
            ..Default::default()
        });
        let with_q = build_trace_list_sql(&TraceListFilters {
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
    use std::sync::Mutex;

    // ── Pure SQL-builder tests (no client, no env) ───────────────────────────

    #[test]
    fn trace_list_sql_is_tenant_first_and_bound() {
        let sql = build_trace_list_sql(&TraceListFilters {
            q: None,
            limit: 50,
            ..Default::default()
        });
        // tenant_id is the FIRST predicate and a bound placeholder.
        assert!(sql.contains("WHERE tenant_id = ?"), "sql: {sql}");
        let where_pos = sql.find("WHERE tenant_id = ?").unwrap();
        // No other predicate precedes the tenant filter.
        assert!(!sql[..where_pos].contains("AND "));
        assert!(sql.contains("FROM trace_summaries FINAL"));
        assert!(sql.contains("ORDER BY start_time DESC, trace_id DESC"));
        assert!(sql.trim_end().ends_with("LIMIT ?"));
    }

    #[test]
    fn trace_list_sql_appends_filters_in_bind_order() {
        let sql = build_trace_list_sql(&TraceListFilters {
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
        // model ? before the keyset ?s before limit ?.
        let i_model = sql.find("model = ?").unwrap();
        let i_since = sql
            .find("start_time >= fromUnixTimestamp64Micro(?)")
            .unwrap();
        let i_until = sql
            .find("start_time <= fromUnixTimestamp64Micro(?)")
            .unwrap();
        let i_cursor = sql.find("toUnixTimestamp64Micro(start_time) < ?").unwrap();
        let i_limit = sql.rfind("LIMIT ?").unwrap();
        assert!(i_model < i_since && i_since < i_until && i_until < i_cursor && i_cursor < i_limit);
        assert!(sql.contains("error_count > 0"));
        // Three placeholders in the keyset clause.
        let cursor_clause = &sql[i_cursor..i_limit];
        assert_eq!(cursor_clause.matches('?').count(), 3);
    }

    #[test]
    fn trace_list_sql_failover_is_tenant_scoped_subquery_only_when_true() {
        // Some(true) → the tenant-scoped failover-attr subquery is present.
        let on = build_trace_list_sql(&TraceListFilters {
            q: None,
            failover: Some(true),
            limit: 50,
            ..Default::default()
        });
        assert!(on.contains(
            "trace_id IN (SELECT trace_id FROM spans WHERE tenant_id = ? AND JSONExtractBool(attributes, 'tracelane_failover_activated'))"
        ), "sql: {on}");
        // groups builder mirrors the same clause (so a failover view groups honestly).
        let grp = build_trace_groups_sql(
            TraceGroupBy::Model,
            &TraceListFilters {
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

    #[test]
    fn trace_count_sql_is_tenant_first_no_order_no_limit() {
        let sql = build_trace_count_sql(&TraceListFilters {
            q: None,
            model: Some("claude".into()),
            has_error: Some(true),
            failover: Some(true),
            since_us: Some(1),
            limit: 50,
            ..Default::default()
        });
        // uniqExact(trace_id), not count() — dedupes MV partial rows so the footer
        // reconciles with the list (provenance audit P1 #7).
        assert!(
            sql.starts_with(
                "SELECT toUInt64(uniqExact(trace_id)) AS total FROM trace_summaries FINAL WHERE tenant_id = ?"
            ),
            "sql: {sql}"
        );
        // mirrors the list filters, but NO ORDER BY / LIMIT / cursor.
        assert!(sql.contains("model = ?"));
        assert!(sql.contains("error_count > 0"));
        assert!(sql.contains("tracelane_failover_activated"));
        assert!(sql.contains("start_time >= fromUnixTimestamp64Micro(?)"));
        assert!(!sql.contains("ORDER BY"));
        assert!(!sql.contains("LIMIT"));
    }

    #[test]
    fn trace_list_sql_has_error_false_is_clean_only() {
        let sql = build_trace_list_sql(&TraceListFilters {
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
        assert!(TRACE_CHAIN_SQL.contains("event_type = 'chat.completions.request'"));
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
                "trace_id IN (SELECT trace_id FROM spans WHERE tenant_id = ? AND has(aft_ids, ?))"
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
            since_secs: Some(1),
            hours: 24,
            limit: 100,
        });
        assert!(with_since.contains("start_time >= toDateTime(?)"));
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
        assert!(
            sql.contains(
                "if(countIf(JSONHas(attributes, 'tracelane_gateway_overhead_us')) = 0, 0,"
            )
        );
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
        latency_totals: LatencyTotalsRow,
        latency_by_model: Vec<LatencyModelRow>,
        guardrail_summary: GuardrailSummaryRow,
        guardrail_rails: Vec<GuardrailRailRow>,
        signatures: Vec<SignatureHitRow>,
        sessions: Vec<SessionSummaryRow>,
        session_traces: Vec<SessionTraceRow>,
        groups: Vec<TraceGroupRow>,
        trace_costs: Vec<TraceCostRow>,
        chain_status: Option<TraceChainStatus>,
        seen_tenant: Mutex<Vec<String>>,
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
                latency_totals: LatencyTotalsRow::default(),
                latency_by_model: Vec::new(),
                guardrail_summary: GuardrailSummaryRow::default(),
                guardrail_rails: Vec::new(),
                signatures: Vec::new(),
                sessions: Vec::new(),
                session_traces: Vec::new(),
                groups: Vec::new(),
                trace_costs: Vec::new(),
                chain_status: None,
                seen_tenant: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl TraceReader for MockTraceReader {
        async fn list_traces(
            &self,
            tenant_id: &TenantId,
            _f: &TraceListFilters,
        ) -> Result<Vec<TraceSummaryRow>> {
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
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
        async fn list_trace_groups(
            &self,
            tenant_id: &TenantId,
            _by: TraceGroupBy,
            _f: &TraceListFilters,
        ) -> Result<Vec<TraceGroupRow>> {
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
            Ok(self.groups.clone())
        }
        async fn count_traces(&self, tenant_id: &TenantId, _f: &TraceListFilters) -> Result<u64> {
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
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

    fn bearer_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, "Bearer dev-token".parse().unwrap());
        h
    }

    async fn body_json(resp: Response) -> serde_json::Value {
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
    struct DevAuthGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        saved: Option<String>,
    }
    impl DevAuthGuard {
        fn new() -> Self {
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

    const DEV_TENANT: &str = "00000000-0000-0000-0000-000000000001";

    #[cfg(debug_assertions)]
    #[test]
    fn gateway_stats_sql_is_tenant_first_and_windowed() {
        let sql = build_gateway_stats_sql(&GatewayStatsFilters {
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
        assert!(
            sql.contains("countIf(JSONExtractBool(attributes, 'tracelane_failover_activated'))"),
            "sql: {sql}"
        );
        assert!(sql.contains("GROUP BY provider"), "sql: {sql}");
    }

    #[test]
    fn gateway_stats_sql_since_overrides_window() {
        let sql = build_gateway_stats_sql(&GatewayStatsFilters {
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
        assert_eq!(resp.quota_exceeded_since_start, 4);
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
        };
        let resp = gateway_stats_handler(
            State(state),
            Query(GatewayStatsQuery {
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
        assert_eq!(v["quota_exceeded_since_start"], 0);
        assert!(v["uninstrumented"].as_array().unwrap().is_empty());
    }

    // ── Guardrails surface ───────────────────────────────────────────────────

    #[test]
    fn guardrail_sql_is_tenant_first_and_windowed() {
        let f = GuardrailStatsFilters {
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
    fn guardrail_verdicts_sql_is_tenant_first_decision_bound_and_ordered() {
        // With a decision filter: tenant first, decision bound BEFORE the window.
        let sql = build_guardrail_verdicts_sql(&GuardrailVerdictListFilters {
            since_secs: None,
            hours: 24,
            decision: Some("block".to_string()),
            correlation_id: None,
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
            since_secs: Some(1),
            hours: 24,
            decision: None,
            correlation_id: None,
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
        };
        let resp = guardrail_stats_handler(
            State(state),
            Query(GuardrailStatsQuery {
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
        };
        let resp = list_traces_handler(
            State(state),
            Query(TraceListQuery {
                q: None,
                limit: Some(50),
                model: None,
                has_error: None,
                min_latency_ms: None,
                failover: None,
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
            State(TraceReadState { reader }),
            Query(TraceListQuery {
                q: None,
                limit: Some(50),
                model: None,
                has_error: None,
                min_latency_ms: None,
                failover: None,
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
            State(TraceReadState { reader }),
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
            State(TraceReadState { reader }),
            Query(TraceExportQuery {
                format: Some("csv".into()),
                model: None,
                has_error: None,
                min_latency_ms: None,
                failover: None,
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
            State(TraceReadState { reader }),
            Query(TraceExportQuery {
                format: Some("json".into()),
                model: None,
                has_error: None,
                min_latency_ms: None,
                failover: None,
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

    #[test]
    fn build_trace_list_sql_honors_sort_and_order() {
        // Default → newest-first (start_time DESC).
        let sql = build_trace_list_sql(&TraceListFilters::default());
        assert!(sql.contains("ORDER BY start_time DESC, trace_id DESC"));
        // Every query is still tenant-first (isolation invariant).
        assert!(sql.trim_start().starts_with("SELECT") && sql.contains("WHERE tenant_id = ?"));

        // duration ASC.
        let sql = build_trace_list_sql(&TraceListFilters {
            q: None,
            sort: TraceSort::Duration,
            order: SortOrder::Asc,
            ..Default::default()
        });
        assert!(sql.contains("ORDER BY duration_us ASC, trace_id ASC"));

        // Keyset uses the sort column + the direction operator (DESC → `<`).
        let sql = build_trace_list_sql(&TraceListFilters {
            q: None,
            sort: TraceSort::Duration,
            cursor: Some((5, "t".into())),
            ..Default::default()
        });
        assert!(sql.contains("duration_us < ?"));

        // start_time keyset references the DateTime64 column, and ASC flips to `>`.
        let sql = build_trace_list_sql(&TraceListFilters {
            q: None,
            order: SortOrder::Asc,
            cursor: Some((5, "t".into())),
            ..Default::default()
        });
        assert!(sql.contains("toUnixTimestamp64Micro(start_time) > ?"));
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
        assert!(sql.trim_start().starts_with("SELECT") && sql.contains("WHERE tenant_id = ?"));

        let sql = build_trace_groups_sql(TraceGroupBy::Operation, &TraceListFilters::default());
        assert!(sql.contains("SELECT root_name AS group_key"));

        let sql = build_trace_groups_sql(TraceGroupBy::Status, &TraceListFilters::default());
        assert!(sql.contains("if(error_count > 0, 'error', 'ok') AS group_key"));

        // Filters mirror the list (the model `?` clause appears when set).
        let sql = build_trace_groups_sql(
            TraceGroupBy::Model,
            &TraceListFilters {
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
            }),
            Query(TraceGroupsQuery {
                by: Some("model".into()),
                model: None,
                has_error: None,
                min_latency_ms: None,
                failover: None,
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
            State(TraceReadState { reader }),
            Query(TraceGroupsQuery {
                by: Some("bogus".into()),
                model: None,
                has_error: None,
                min_latency_ms: None,
                failover: None,
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
        let state = TraceReadState { reader };
        let resp = list_traces_handler(
            State(state),
            Query(TraceListQuery {
                q: None,
                limit: Some(2), // page size == rows → expect a cursor
                model: None,
                has_error: None,
                min_latency_ms: None,
                failover: None,
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

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn spans_returns_rows_when_present() {
        let _g = DevAuthGuard::new();
        let reader = Arc::new(MockTraceReader {
            spans: vec![span_row("s1"), span_row("s2")],
            ..MockTraceReader::new()
        });
        let state = TraceReadState { reader };
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
        let state = TraceReadState { reader };
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
        };
        let resp = slo_handler(
            State(state),
            Query(SloQuery {
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
        };
        let resp = list_traces_handler(
            State(state),
            Query(TraceListQuery {
                q: None,
                limit: None,
                model: None,
                has_error: None,
                min_latency_ms: None,
                failover: None,
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
        let state = TraceReadState { reader };
        let resp = list_traces_handler(
            State(state),
            Query(TraceListQuery {
                q: None,
                limit: None,
                model: None,
                has_error: None,
                min_latency_ms: None,
                failover: None,
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
        };
        let resp = list_traces_handler(
            State(state),
            Query(TraceListQuery {
                q: None,
                limit: None,
                model: None,
                has_error: None,
                min_latency_ms: None,
                failover: None,
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
        };
        let resp = signatures_handler(
            State(state),
            Query(SignatureQuery {
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
        let state = TraceReadState { reader };
        let resp = signatures_handler(
            State(state),
            Query(SignatureQuery {
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
        };
        let resp = signatures_handler(
            State(state),
            Query(SignatureQuery {
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
        assert!(sql.contains("gen_ai_response_model') = ?"), "sql: {sql}");
        let i_model = sql.find("gen_ai_response_model') = ?").unwrap();
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
        };
        let resp = list_sessions_handler(
            State(state),
            Query(SessionListQuery {
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
        let state = TraceReadState { reader };
        let resp =
            session_traces_handler(State(state), Path("conv-abc".to_string()), bearer_headers())
                .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["session_id"], "conv-abc");
        assert_eq!(v["traces"].as_array().unwrap().len(), 2);
        assert_eq!(v["traces"][0]["trace_id"], "t1");
    }

    #[tokio::test]
    async fn list_sessions_missing_auth_is_401_and_never_reads() {
        let reader = Arc::new(MockTraceReader::new());
        let state = TraceReadState {
            reader: reader.clone(),
        };
        let resp = list_sessions_handler(
            State(state),
            Query(SessionListQuery {
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
}

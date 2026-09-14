/**
 * registry — ONE definition per metric (DSH-11 §3.0).
 *
 * A metric is an id, a label, a kind, a family, a window kind, a source (the
 * gateway route and field), a numerator, a denominator, and the dedup class of
 * the table it reads. Pages render metrics BY ID and never invent a label: two
 * numbers with different definitions may not share a label, and the guard
 * (`scripts/ci/check-metric-single-source.py`) plus `registry.test.ts` refuse a
 * registry where they do. That rule is what makes "same metric + same window +
 * same tenant = same number on every page" a structural property rather than a
 * hope.
 *
 * The dedup class matters because ingest is at-least-once: `spans FINAL` and
 * `trace_summaries FINAL` collapse a redelivered span; `slo_hourly_stats`
 * (`countMerge` over the MV, which counts at insert time) does NOT, and
 * `guardrail_verdicts` is a plain MergeTree. So the SLO family's "LLM calls" and
 * the spans family's "Requests routed" are two definitions — and two labels.
 *
 * `docs/product/*.md` tables must carry every label here
 * (`scripts/ci/check-metric-docs.py` reads this file as well as `<StatCard>`).
 */

import type { MetricKind } from "./format";

export type MetricFamily =
	| "slo"
	| "spans"
	| "guardrails"
	| "signatures"
	| "traces"
	| "sessions"
	| "tools"
	| "evals"
	| "audit"
	| "gateway-process";

export type WindowKind =
	| "windowed"
	| "lifetime"
	| "process"
	| "instant"
	| "entity";

export type DedupClass =
	| "spans FINAL"
	| "trace_summaries FINAL"
	| "slo MV (not deduplicated)"
	| "guardrail_verdicts (no dedup)"
	| "online_eval_scores FINAL"
	| "audit_log FINAL"
	| "in-process"
	| "none";

export interface MetricDef {
	readonly id: string;
	/** The exact label on screen. UNIQUE across the registry. */
	readonly label: string;
	readonly kind: MetricKind;
	readonly family: MetricFamily;
	readonly window: WindowKind;
	/** `GET /v1/route · field` — the ONE source. */
	readonly source: string;
	readonly numerator: string;
	/** `null` for a count or a sum. */
	readonly denominator: string | null;
	readonly dedup: DedupClass;
	/** Plain-language expansion for the `?` affordance. */
	readonly hint?: string;
	/** Sample floor for a rate: a number, or `"target"` → `ceil(1/(1−target))`. */
	readonly floor?: number | "target";
	/** Copy for a measured zero with no sample (never `0%`, never `100%`). */
	readonly zeroCopy?: string;
}

const NO_TRAFFIC = "no traffic in this window";
const NO_VERDICTS = "no verdicts in this window";

/** `satisfies` keeps the ids literal AND checks every entry against MetricDef. */
export const METRICS = {
	// ── SLO family — slo_hourly_stats via /v1/slo*, NOT deduplicated ───────────
	llm_calls: {
		id: "llm_calls",
		label: "LLM calls",
		kind: "count",
		family: "slo",
		window: "windowed",
		source: "GET /v1/slo/summary · requests",
		numerator: "Σ countMerge(request_count) over rows with provider ≠ ''",
		denominator: null,
		dedup: "slo MV (not deduplicated)",
		hint: "Model requests — one agent run can make several. Not the trace/conversation count (see Traces). Counted by the hourly SLO view, which counts a redelivered span twice.",
		zeroCopy: NO_TRAFFIC,
	},
	error_rate: {
		id: "error_rate",
		label: "Error rate",
		kind: "percent",
		family: "slo",
		window: "windowed",
		source: "GET /v1/slo/summary · errors / requests",
		numerator: "Σ countMerge(error_count) — spans with status_code = 2",
		denominator: "Σ requests (same rows, provider ≠ '')",
		dedup: "slo MV (not deduplicated)",
		hint: "Share of LLM requests that failed, over the selected window.",
		floor: 100,
		zeroCopy: NO_TRAFFIC,
	},
	availability: {
		id: "availability",
		label: "Availability",
		kind: "percent",
		family: "slo",
		window: "windowed",
		source:
			"GET /v1/slo/summary · (requests − errors) / requests; target from tenants.plan",
		numerator: "requests − errors",
		denominator: "requests",
		dedup: "slo MV (not deduplicated)",
		hint: "Success rate over the window, judged against your plan's contracted target once the sample is large enough to resolve it.",
		floor: "target",
		zeroCopy: NO_TRAFFIC,
	},
	burn_rate: {
		id: "burn_rate",
		label: "Burn rate",
		kind: "ratio",
		family: "slo",
		window: "windowed",
		source: "derived · error_rate / (1 − target)",
		numerator: "error rate",
		denominator: "1 − target (the error budget)",
		dedup: "slo MV (not deduplicated)",
		hint: "How fast the error budget is being spent. 1.0× = exactly on pace for the window.",
		floor: "target",
		zeroCopy: NO_TRAFFIC,
	},
	budget_remaining: {
		id: "budget_remaining",
		label: "Budget remaining",
		kind: "percent",
		family: "slo",
		window: "windowed",
		source: "derived · (1 − burn_rate) × 100",
		numerator: "1 − burn rate",
		denominator: "the error budget (1 − target), through burn rate",
		dedup: "slo MV (not deduplicated)",
		floor: "target",
		zeroCopy: NO_TRAFFIC,
		hint: "Share of the error budget left, from (1 - burn rate) x 100. 100% means no budget spent yet this window.",
	},
	slo_target: {
		id: "slo_target",
		label: "SLO target (your plan)",
		kind: "percent",
		family: "slo",
		window: "lifetime",
		source: "Postgres tenants.plan → availabilityTargetForPlanKey",
		numerator: "the contracted availability target",
		denominator: null,
		dedup: "none",
		hint: "The availability your plan contracts: Team 99%, Enterprise 99.95%, everything else 99.9%.",
	},
	tokens: {
		id: "tokens",
		label: "Tokens",
		kind: "tokens",
		family: "slo",
		window: "windowed",
		source: "GET /v1/slo/models · total_input_tokens + total_output_tokens",
		numerator:
			"Σ sumMerge(input) + Σ sumMerge(output) — excludes prompt-cache read/creation tokens",
		denominator: null,
		dedup: "slo MV (not deduplicated)",
		hint: "Input + output tokens. Excludes prompt-cache read and creation tokens, so a cached workload reads low here.",
		zeroCopy: NO_TRAFFIC,
	},
	tokens_input: {
		id: "tokens_input",
		label: "Input tokens",
		kind: "tokens",
		family: "slo",
		window: "windowed",
		source: "GET /v1/slo/models · total_input_tokens",
		numerator: "Σ sumMerge(input_tokens), provider ≠ ''",
		denominator: null,
		dedup: "slo MV (not deduplicated)",
		zeroCopy: NO_TRAFFIC,
		hint: "Prompt tokens sent to providers this window. Excludes prompt-cache read/creation tokens.",
	},
	tokens_output: {
		id: "tokens_output",
		label: "Output tokens",
		kind: "tokens",
		family: "slo",
		window: "windowed",
		source: "GET /v1/slo/models · total_output_tokens",
		numerator: "Σ sumMerge(output_tokens), provider ≠ ''",
		denominator: null,
		dedup: "slo MV (not deduplicated)",
		zeroCopy: NO_TRAFFIC,
		hint: "Completion tokens returned by providers this window.",
	},
	latency_p50: {
		id: "latency_p50",
		label: "p50 latency",
		kind: "duration_ms",
		family: "slo",
		window: "windowed",
		source: "GET /v1/slo/summary · p50_ms",
		numerator:
			"quantileMerge(0.5) over the whole window — a true window percentile",
		denominator: null,
		dedup: "slo MV (not deduplicated)",
		floor: 100,
		zeroCopy: NO_TRAFFIC,
	},
	latency_p95: {
		id: "latency_p95",
		label: "p95 latency",
		kind: "duration_ms",
		family: "slo",
		window: "windowed",
		source: "GET /v1/slo/summary · p95_ms",
		numerator:
			"quantileMerge(0.95) over the whole window — never a mean of bucket percentiles",
		denominator: null,
		dedup: "slo MV (not deduplicated)",
		hint: "End-to-end p95 over the window — the true server-side quantile, not a mean of hourly percentiles.",
		floor: 100,
		zeroCopy: NO_TRAFFIC,
	},
	latency_p99: {
		id: "latency_p99",
		label: "p99 latency",
		kind: "duration_ms",
		family: "slo",
		window: "windowed",
		source: "GET /v1/slo/summary · p99_ms",
		numerator: "quantileMerge(0.99) over the whole window",
		denominator: null,
		dedup: "slo MV (not deduplicated)",
		floor: 100,
		zeroCopy: NO_TRAFFIC,
	},
	traffic_series: {
		id: "traffic_series",
		label: "Requests per bucket",
		kind: "count",
		family: "slo",
		window: "windowed",
		source: "GET /v1/slo/timeseries · requests per bucket",
		numerator:
			"countMerge per epoch-aligned bucket (≥ 1 h from the hourly view; < 1 h from spans FINAL)",
		denominator: null,
		dedup: "slo MV (not deduplicated)",
	},
	errors_series: {
		id: "errors_series",
		label: "Errors per bucket",
		kind: "count",
		family: "slo",
		window: "windowed",
		source: "GET /v1/slo/timeseries · errors per bucket",
		numerator: "countMerge(error_count) per bucket",
		denominator: null,
		dedup: "slo MV (not deduplicated)",
	},
	latency_series: {
		id: "latency_series",
		label: "Latency per bucket",
		kind: "duration_ms",
		family: "slo",
		window: "windowed",
		source: "GET /v1/slo/timeseries · p50_ms / p95_ms / p99_ms per bucket",
		numerator: "quantileMerge per bucket — a missing bucket is a gap, never 0",
		denominator: null,
		dedup: "slo MV (not deduplicated)",
	},
	traffic_by_model: {
		id: "traffic_by_model",
		label: "Requests by model",
		kind: "count",
		family: "slo",
		window: "windowed",
		source: "GET /v1/slo/models · requests per (provider, model)",
		numerator: "countMerge per (provider, model), provider ≠ ''",
		denominator: null,
		dedup: "slo MV (not deduplicated)",
		zeroCopy: NO_TRAFFIC,
	},

	// ── spans family — spans FINAL, deduplicated ───────────────────────────────
	requests_routed: {
		id: "requests_routed",
		label: "Requests routed",
		kind: "count",
		family: "spans",
		window: "windowed",
		source: "GET /v1/gateway/stats · total_requests",
		numerator: "count() over spans FINAL where gen_ai_provider_name ≠ ''",
		denominator: null,
		dedup: "spans FINAL",
		hint: "Requests the router served, counted from deduplicated spans. Differs from LLM calls on the dashboard, which the hourly SLO view counts before deduplication.",
		zeroCopy: NO_TRAFFIC,
	},
	failed_routed: {
		id: "failed_routed",
		label: "Failed",
		kind: "percent",
		family: "spans",
		window: "windowed",
		source:
			"GET /v1/gateway/stats · error_rate_pct (total_errors / total_requests)",
		numerator: "countIf(status_code = 2)",
		denominator: "Requests routed",
		dedup: "spans FINAL",
		hint: "Share of routed requests that failed, from deduplicated spans.",
		floor: 100,
		zeroCopy: NO_TRAFFIC,
	},
	cache_hit_rate: {
		id: "cache_hit_rate",
		label: "Cache hit",
		kind: "percent",
		family: "spans",
		window: "windowed",
		source: "GET /v1/gateway/stats · cache_hit_rate_pct",
		numerator: "countIf(prompt-cache read)",
		denominator: "Requests routed",
		dedup: "spans FINAL",
		hint: "Share of routed requests that read a provider prompt cache.",
		floor: 100,
		zeroCopy: NO_TRAFFIC,
	},
	spend_est: {
		id: "spend_est",
		label: "Spend (est.)",
		kind: "currency",
		family: "spans",
		window: "windowed",
		source:
			"GET /v1/gateway/stats · total_cost_usd (aligned to /v1/costs: Σ cost_usd where cost_usd_present)",
		numerator: "Σ stored per-span cost over priced spans — a lower bound",
		denominator: null,
		dedup: "spans FINAL",
		hint: "Sum of the stored per-request cost over priced traffic — a lower bound; unpriced models contribute nothing and are counted separately.",
	},
	unpriced_requests: {
		id: "unpriced_requests",
		label: "Unpriced",
		kind: "count",
		family: "spans",
		window: "windowed",
		source: "GET /v1/costs · unpriced_requests",
		numerator: "countIf(NOT cost_usd_present)",
		denominator: null,
		dedup: "spans FINAL",
	},
	overhead_p95: {
		id: "overhead_p95",
		label: "Gateway overhead p95",
		kind: "duration_ms",
		family: "spans",
		window: "windowed",
		source:
			"GET /v1/query/latency-breakdown · overhead_p95_ms (n = overhead_samples)",
		numerator:
			"quantile(0.95)(gateway_overhead_us) over spans with a measured overhead",
		denominator: null,
		dedup: "spans FINAL",
		hint: "The time Tracelane adds per request, excluding the upstream provider round-trip.",
		floor: 100,
	},
	provider_p95: {
		id: "provider_p95",
		label: "Provider p95",
		kind: "duration_ms",
		family: "spans",
		window: "windowed",
		source: "GET /v1/query/latency-breakdown · provider_p95_ms",
		numerator: "quantile(0.95)(duration − overhead) over the same spans",
		denominator: null,
		dedup: "spans FINAL",
		floor: 100,
	},
	ttft_p95: {
		id: "ttft_p95",
		label: "TTFT p95",
		kind: "duration_ms",
		family: "spans",
		window: "windowed",
		source: "GET /v1/query/latency-breakdown · ttft_p95_ms (n = ttft_samples)",
		numerator: "quantile(0.95)(time_to_first_chunk) over streaming spans",
		denominator: null,
		dedup: "spans FINAL",
		floor: 100,
	},
	providers_active: {
		id: "providers_active",
		label: "Providers active",
		kind: "count",
		family: "spans",
		window: "windowed",
		source: "GET /v1/gateway/stats · provider_count",
		numerator: "uniqExact(provider) with traffic",
		denominator: null,
		dedup: "spans FINAL",
		hint: "Distinct upstream providers that served at least one request in this window.",
	},
	failovers: {
		id: "failovers",
		label: "Failovers",
		kind: "count",
		family: "spans",
		window: "windowed",
		source: "GET /v1/gateway/stats · total_failovers",
		numerator: "countIf(served via cross-provider failover)",
		denominator: null,
		dedup: "spans FINAL",
		hint: "Requests served by a backup provider after the primary failed, over this window.",
	},
	rate_limited_since_start: {
		id: "rate_limited_since_start",
		label: "Rate-limited (since start)",
		kind: "count",
		family: "gateway-process",
		window: "process",
		source: "GET /v1/gateway/stats · rate_limited_since_start",
		numerator: "in-process token-bucket 429 counter — a 429 emits no span",
		denominator: null,
		dedup: "in-process",
		hint: "Resets when the gateway restarts; this is not a windowed number.",
	},
	budget_exceeded_since_start: {
		id: "budget_exceeded_since_start",
		label: "Budget-exceeded (since start)",
		kind: "count",
		family: "gateway-process",
		window: "process",
		source: "GET /v1/gateway/stats · budget_exceeded_since_start",
		numerator:
			"in-process budget-exceeded 429 counter (per-key/workspace USD budget)",
		denominator: null,
		dedup: "in-process",
		hint: "Resets when the gateway restarts; this is not a windowed number.",
	},
	open_breakers: {
		id: "open_breakers",
		label: "Circuit breakers",
		kind: "count",
		family: "gateway-process",
		window: "instant",
		source: "GET /v1/gateway/stats · open_breakers",
		numerator: "upstreams whose breaker is Open or Half-Open, right now",
		denominator: null,
		dedup: "in-process",
		hint: "Upstreams whose circuit breaker is Open or Half-Open right now — a live count, not windowed.",
	},

	// ── guardrails — guardrail_verdicts, plain MergeTree ──────────────────────
	verdicts: {
		id: "verdicts",
		label: "Evaluations",
		kind: "count",
		family: "guardrails",
		window: "windowed",
		source: "GET /v1/guardrails/stats · total_evaluations",
		numerator: "count() over guardrail_verdicts",
		denominator: null,
		dedup: "guardrail_verdicts (no dedup)",
		zeroCopy: NO_VERDICTS,
		hint: "Total pre-flight guardrail evaluations, request-side plus response-side, over this window.",
	},
	block_rate: {
		id: "block_rate",
		label: "Block rate",
		kind: "percent",
		family: "guardrails",
		window: "windowed",
		source:
			"GET /v1/guardrails/stats · block_rate_pct (blocks / total_evaluations)",
		numerator: "countIf(decision = 'block')",
		denominator: "Evaluations (verdicts, NOT requests)",
		dedup: "guardrail_verdicts (no dedup)",
		hint: "Share of pre-flight guardrail VERDICTS that blocked (denominator = verdicts, not requests).",
		floor: 100,
		zeroCopy: NO_VERDICTS,
	},
	fail_open_rate: {
		id: "fail_open_rate",
		label: "Fail-open rate",
		kind: "percent",
		family: "guardrails",
		window: "windowed",
		source: "GET /v1/guardrails/stats · fail_open_rate_pct",
		numerator:
			"verdicts where a rail ERRORED and the request proceeded (notEmpty(fail_open_rails))",
		denominator: "Evaluations",
		dedup: "guardrail_verdicts (no dedup)",
		hint: "Share of verdicts where a rail errored and the request proceeded anyway — the trust headline.",
		floor: 100,
		zeroCopy: NO_VERDICTS,
	},
	guardrail_overhead_p95: {
		id: "guardrail_overhead_p95",
		label: "Inline overhead (p95)",
		kind: "duration_ms",
		family: "guardrails",
		window: "windowed",
		source: "GET /v1/guardrails/stats · p95_ms",
		numerator:
			"quantile(0.95) of the rail evaluation itself, not of the request",
		denominator: null,
		dedup: "guardrail_verdicts (no dedup)",
		floor: 100,
		zeroCopy: NO_VERDICTS,
		hint: "p95 time the rail evaluation itself took, not the whole request, over this window.",
	},
	decision_mix: {
		id: "decision_mix",
		label: "Decision mix",
		kind: "count",
		family: "guardrails",
		window: "windowed",
		source: "GET /v1/guardrails/stats · allows / blocks / redacts / warns",
		numerator: "four counts that sum to Evaluations",
		denominator: null,
		dedup: "guardrail_verdicts (no dedup)",
		zeroCopy: NO_VERDICTS,
	},

	// ── signatures — spans FINAL ───────────────────────────────────────────────
	signatures_matched: {
		id: "signatures_matched",
		label: "Signatures matched",
		kind: "count",
		family: "signatures",
		window: "windowed",
		source: "GET /v1/query/signatures · live ids with ≥ 1 hit",
		numerator:
			"count of live AFT-1 signatures with at least one hit in the window",
		denominator: null,
		dedup: "spans FINAL",
		hint: "Live-detected AFT-1 failure patterns matched in the window. Roadmap entries are listed separately.",
	},
	traces_affected: {
		id: "traces_affected",
		label: "Traces affected",
		kind: "count",
		family: "signatures",
		window: "windowed",
		source: "GET /v1/query/signatures · total_traces_affected",
		numerator:
			"uniqExact(trace_id) over spans carrying a live signature — never a sum of per-signature counts",
		denominator: null,
		dedup: "spans FINAL",
		hint: "Distinct traces with at least one live failure signature — never a sum of per-signature counts.",
	},

	// ── traces — trace_summaries FINAL ────────────────────────────────────────
	traces_total: {
		id: "traces_total",
		label: "Traces",
		kind: "count",
		family: "traces",
		window: "windowed",
		source:
			"GET /v1/traces/count · total (under the list's filters, including q)",
		numerator: "uniqExact(trace_id) over trace_summaries FINAL",
		denominator: null,
		dedup: "trace_summaries FINAL",
	},

	// ── sessions — spans FINAL, list window ───────────────────────────────────
	sessions_listed: {
		id: "sessions_listed",
		label: "Sessions",
		kind: "count",
		family: "sessions",
		window: "windowed",
		source: "GET /v1/sessions · rows (capped at 50)",
		numerator: "sessions with activity in the window",
		denominator: null,
		dedup: "spans FINAL",
	},

	// ── tools — spans FINAL (B-232: no writer produces the key today) ─────────
	tool_calls: {
		id: "tool_calls",
		label: "Tool calls",
		kind: "count",
		family: "tools",
		window: "windowed",
		source: "GET /v1/query/tool-analytics · total_calls",
		numerator: "count() over spans FINAL carrying gen_ai.tool.name",
		denominator: null,
		dedup: "spans FINAL",
	},
} as const satisfies Record<string, MetricDef>;

export type MetricId = keyof typeof METRICS;

export function metric(id: MetricId): MetricDef {
	return METRICS[id];
}

/** Every definition, for the guard, the docs check and the consistency test. */
export function allMetrics(): readonly MetricDef[] {
	return Object.values(METRICS);
}

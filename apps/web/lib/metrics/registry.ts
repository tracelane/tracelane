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
 * `guardrail_verdicts` is a plain MergeTree. The SLO family reads BOTH, by
 * window (B-500, 2026-09-21): a window of 24 h or less carries a sub-hour
 * bucket and every `/v1/slo*` route then reads `spans FINAL` bounded by
 * `start_time`; wider than that, every route reads `slo_hourly_stats` bounded by
 * `bucket_hour`. The whole family switches together — the headline, the table
 * and the chart count the same spans under one window, which they did not when
 * only the two series routes carried the bucket. The SLO family's "LLM calls"
 * and the spans family's "Requests routed" stay two definitions — and two
 * labels — because the SLO scope is the MV's four-key provider derivation and
 * the spans family's is `gen_ai_provider_name` alone.
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
	| "kya"
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
	| "spans FINAL ≤ 24 h · slo MV (not deduplicated) above"
	| "guardrail_verdicts (no dedup)"
	| "online_eval_scores FINAL"
	| "audit_log FINAL"
	| "in-process"
	| "eval_run_items FINAL"
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
	kya_calls: {
		id: "kya_calls",
		label: "Calls",
		kind: "count",
		family: "kya",
		window: "windowed",
		source:
			"GET /v1/kya/identities · identities[].calls (same definition on the profile route)",
		numerator:
			"LLM-call spans with operation chat, embeddings or messages under this identity.",
		denominator: null,
		dedup: "spans FINAL",
	},

	kya_traces: {
		id: "kya_traces",
		label: "Traces with calls",
		kind: "count",
		family: "kya",
		window: "windowed",
		source:
			"GET /v1/kya/identities · identities[].traces (same definition on the profile route)",
		numerator: "uniqExact(trace_id) among those LLM-call spans.",
		denominator: null,
		dedup: "spans FINAL",
	},

	kya_tokens_in: {
		id: "kya_tokens_in",
		label: "Tokens in",
		kind: "tokens",
		family: "kya",
		window: "windowed",
		source:
			"GET /v1/kya/identities · identities[].tokens_in (same definition on the profile route)",
		numerator:
			"Sum of recorded input tokens; null when every call lacks input usage.",
		denominator: null,
		dedup: "spans FINAL",
	},

	kya_tokens_out: {
		id: "kya_tokens_out",
		label: "Tokens out",
		kind: "tokens",
		family: "kya",
		window: "windowed",
		source:
			"GET /v1/kya/identities · identities[].tokens_out (same definition on the profile route)",
		numerator:
			"Sum of recorded output tokens; null when every call lacks output usage.",
		denominator: null,
		dedup: "spans FINAL",
	},

	kya_cost: {
		id: "kya_cost",
		label: "Cost",
		kind: "currency",
		family: "kya",
		window: "windowed",
		source:
			"GET /v1/kya/identities · identities[].cost_usd (same definition on the profile route)",
		numerator:
			"Sum of cost_usd where cost_usd_present = 1; null when all calls are unpriced.",
		denominator: null,
		dedup: "spans FINAL",
	},

	kya_error_rate: {
		id: "kya_error_rate",
		label: "Call errors",
		kind: "percent",
		family: "kya",
		window: "windowed",
		source:
			"GET /v1/kya/identities · identities[].error_rate (same definition on the profile route)",
		numerator: "Calls with status_code = 2.",
		denominator: "Calls for the same identity and window.",
		dedup: "spans FINAL",
		floor: 1,
		hint: "An observed fraction of recorded calls, not a reliability forecast.",
	},

	kya_p50: {
		id: "kya_p50",
		label: "Median latency",
		kind: "duration_ms",
		family: "kya",
		window: "windowed",
		source:
			"GET /v1/kya/identities · identities[].p50_us (same definition on the profile route)",
		numerator:
			"quantiles(0.5,0.95)(duration_us), p50 converted from microseconds to milliseconds.",
		denominator: null,
		dedup: "spans FINAL",
	},

	kya_p95: {
		id: "kya_p95",
		label: "p95 call latency",
		kind: "duration_ms",
		family: "kya",
		window: "windowed",
		source:
			"GET /v1/kya/identities · identities[].p95_us (same definition on the profile route)",
		numerator:
			"quantiles(0.5,0.95)(duration_us), p95 converted from microseconds to milliseconds.",
		denominator: null,
		dedup: "spans FINAL",
	},

	kya_share: {
		id: "kya_share",
		label: "Share of workspace",
		kind: "percent",
		family: "kya",
		window: "windowed",
		source:
			"GET /v1/kya/identities · identities[].share_of_workspace (same definition on the profile route)",
		numerator: "Calls for this identity.",
		denominator:
			"All LLM calls in the same workspace and window, before the identity limit.",
		dedup: "spans FINAL",
		floor: 1,
		hint: "An observed fraction of recorded calls, not a reliability forecast.",
	},

	kya_tool_calls: {
		id: "kya_tool_calls",
		label: "Recorded tool calls",
		kind: "count",
		family: "kya",
		window: "windowed",
		source:
			"GET /v1/kya/identities · identities[].tools[].calls (same definition on the profile route)",
		numerator:
			"Occurrences in recorded response tool-name arrays and gen_ai.tool.name attributes; not offered tool definitions.",
		denominator: null,
		dedup: "spans FINAL",
	},

	// Experiment comparison: gateway computes every value; no client-side rescoring.
	experiment_case_score: {
		id: "experiment_case_score",
		label: "Case score",
		kind: "ratio",
		family: "evals",
		window: "entity",
		source:
			"GET /v1/experiments/{id}/compare \u00b7 rows[].a.score / rows[].b.score",
		numerator: "Stored case score; null means no score.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_case_latency: {
		id: "experiment_case_latency",
		label: "Case latency",
		kind: "duration_ms",
		family: "evals",
		window: "entity",
		source:
			"GET /v1/experiments/{id}/compare \u00b7 rows[].a.latency_ms / rows[].b.latency_ms",
		numerator: "Stored case execution latency in milliseconds.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_case_cost: {
		id: "experiment_case_cost",
		label: "Case cost",
		kind: "currency",
		family: "evals",
		window: "entity",
		source:
			"GET /v1/experiments/{id}/compare \u00b7 rows[].a.cost_usd / rows[].b.cost_usd",
		numerator: "Stored priced case cost; null means unpriced.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_score_delta: {
		id: "experiment_score_delta",
		label: "Case score change",
		kind: "ratio",
		family: "evals",
		window: "entity",
		source: "GET /v1/experiments/{id}/compare \u00b7 rows[].delta_score",
		numerator: "Candidate score minus baseline; null when either is unknown.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_latency_delta: {
		id: "experiment_latency_delta",
		label: "Case latency change",
		kind: "duration_ms",
		family: "evals",
		window: "entity",
		source: "GET /v1/experiments/{id}/compare \u00b7 rows[].delta_latency_ms",
		numerator:
			"Candidate latency minus baseline in milliseconds; null when a side is absent.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_latency_ratio: {
		id: "experiment_latency_ratio",
		label: "Case latency change percent",
		kind: "ratio",
		family: "evals",
		window: "entity",
		source: "GET /v1/experiments/{id}/compare \u00b7 rows[].delta_latency_pct",
		numerator:
			"100 times latency change divided by baseline latency; null at zero baseline.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_cost_delta: {
		id: "experiment_cost_delta",
		label: "Case cost change",
		kind: "currency",
		family: "evals",
		window: "entity",
		source: "GET /v1/experiments/{id}/compare \u00b7 rows[].delta_cost_usd",
		numerator:
			"Candidate priced cost minus baseline; null when either is unpriced.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_pass_rate: {
		id: "experiment_pass_rate",
		label: "Experiment pass rate",
		kind: "ratio",
		family: "evals",
		window: "entity",
		source: "GET /v1/experiments/{id}/compare \u00b7 a.pass_rate / b.pass_rate",
		numerator:
			"100 times passed divided by passed plus failed over matched cases; null if none scored.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_passed: {
		id: "experiment_passed",
		label: "Experiment cases passed",
		kind: "count",
		family: "evals",
		window: "entity",
		source: "GET /v1/experiments/{id}/compare \u00b7 a.passed / b.passed",
		numerator: "Matched cases whose stored status is passed.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_scored: {
		id: "experiment_scored",
		label: "Experiment cases scored",
		kind: "count",
		family: "evals",
		window: "entity",
		source:
			"GET /v1/experiments/{id}/compare \u00b7 a.passed + a.failed / b.passed + b.failed",
		numerator: "Matched passed plus failed cases; excludes errored.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_mean: {
		id: "experiment_mean",
		label: "Experiment mean score",
		kind: "ratio",
		family: "evals",
		window: "entity",
		source:
			"GET /v1/experiments/{id}/compare \u00b7 a.mean_score / b.mean_score",
		numerator:
			"Mean of non-null scores over matched cases; null if none scored.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_p95: {
		id: "experiment_p95",
		label: "Experiment p95 latency",
		kind: "duration_ms",
		family: "evals",
		window: "entity",
		source:
			"GET /v1/experiments/{id}/compare \u00b7 a.p95_latency_ms / b.p95_latency_ms",
		numerator:
			"Nearest-rank p95 over non-errored matched cases; null if none completed.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_cost: {
		id: "experiment_cost",
		label: "Experiment total priced cost",
		kind: "currency",
		family: "evals",
		window: "entity",
		source:
			"GET /v1/experiments/{id}/compare \u00b7 a.total_cost_usd / b.total_cost_usd",
		numerator: "Sum of known matched case costs; shown with unpriced count.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_unpriced: {
		id: "experiment_unpriced",
		label: "Experiment unpriced cases",
		kind: "count",
		family: "evals",
		window: "entity",
		source:
			"GET /v1/experiments/{id}/compare \u00b7 a.unpriced_items / b.unpriced_items",
		numerator: "Matched cases without a known price.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_matched: {
		id: "experiment_matched",
		label: "Experiment matched cases",
		kind: "count",
		family: "evals",
		window: "entity",
		source:
			"GET /v1/experiments/{id}/compare \u00b7 a.items_matched / b.items_matched",
		numerator: "Cases aligned across both arms.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_run: {
		id: "experiment_run",
		label: "Experiment cases run",
		kind: "count",
		family: "evals",
		window: "entity",
		source: "GET /v1/experiments/{id}/compare \u00b7 a.items_run / b.items_run",
		numerator: "Case rows produced by each arm, including unmatched rows.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_errored: {
		id: "experiment_errored",
		label: "Experiment errored cases",
		kind: "count",
		family: "evals",
		window: "entity",
		source: "GET /v1/experiments/{id}/compare \u00b7 a.errored / b.errored",
		numerator: "Matched cases whose stored status is errored.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_snapshot: {
		id: "experiment_snapshot",
		label: "Experiment snapshot cases",
		kind: "count",
		family: "evals",
		window: "entity",
		source: "GET /v1/experiments/{id}/compare \u00b7 item_count",
		numerator: "Case count in the shared frozen dataset snapshot.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_worse: {
		id: "experiment_worse",
		label: "Experiment worse cases",
		kind: "count",
		family: "evals",
		window: "entity",
		source: "GET /v1/experiments/{id}/compare \u00b7 regressed_count",
		numerator:
			"Cases classified regressed by gateway score threshold or pass-to-fail rule.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_better: {
		id: "experiment_better",
		label: "Experiment better cases",
		kind: "count",
		family: "evals",
		window: "entity",
		source: "GET /v1/experiments/{id}/compare \u00b7 improved_count",
		numerator:
			"Cases classified improved by gateway score threshold or fail-to-pass rule.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_unchanged: {
		id: "experiment_unchanged",
		label: "Experiment unchanged cases",
		kind: "count",
		family: "evals",
		window: "entity",
		source: "GET /v1/experiments/{id}/compare \u00b7 unchanged_count",
		numerator: "Cases classified unchanged by the gateway.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_unknown: {
		id: "experiment_unknown",
		label: "Experiment unknown cases",
		kind: "count",
		family: "evals",
		window: "entity",
		source: "GET /v1/experiments/{id}/compare \u00b7 unknown_count",
		numerator:
			"Cases with no comparison verdict because a score is unavailable.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_only_a: {
		id: "experiment_only_a",
		label: "Experiment baseline-only cases",
		kind: "count",
		family: "evals",
		window: "entity",
		source: "GET /v1/experiments/{id}/compare \u00b7 only_in_a",
		numerator: "Cases appearing only in baseline.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_only_b: {
		id: "experiment_only_b",
		label: "Experiment candidate-only cases",
		kind: "count",
		family: "evals",
		window: "entity",
		source: "GET /v1/experiments/{id}/compare \u00b7 only_in_b",
		numerator: "Cases appearing only in candidate.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_rows: {
		id: "experiment_rows",
		label: "Experiment comparison rows",
		kind: "count",
		family: "evals",
		window: "entity",
		source: "GET /v1/experiments/{id}/compare \u00b7 rows.length",
		numerator: "Total aligned and one-sided case rows.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_score_threshold: {
		id: "experiment_score_threshold",
		label: "Experiment score threshold",
		kind: "ratio",
		family: "evals",
		window: "entity",
		source:
			"GET /v1/experiments/{id}/compare \u00b7 thresholds.score_delta_min",
		numerator:
			"Gateway score-delta threshold used to classify better or worse.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_latency_threshold: {
		id: "experiment_latency_threshold",
		label: "Experiment latency threshold",
		kind: "duration_ms",
		family: "evals",
		window: "entity",
		source:
			"GET /v1/experiments/{id}/compare \u00b7 thresholds.latency_delta_min_ms",
		numerator:
			"Gateway absolute latency margin; both absolute and relative margins must be exceeded.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},
	experiment_latency_percent_threshold: {
		id: "experiment_latency_percent_threshold",
		label: "Experiment relative latency threshold",
		kind: "ratio",
		family: "evals",
		window: "entity",
		source:
			"GET /v1/experiments/{id}/compare \u00b7 thresholds.latency_delta_min_pct",
		numerator:
			"Gateway relative latency margin in percent, paired with absolute margin.",
		denominator: null,
		dedup: "eval_run_items FINAL",
	},

	// ── SLO family — /v1/slo*: spans FINAL for windows ≤ 24 h, slo_hourly_stats above ──
	llm_calls: {
		id: "llm_calls",
		label: "LLM calls",
		kind: "count",
		family: "slo",
		window: "windowed",
		source: "GET /v1/slo/summary · requests",
		numerator:
			"count() over spans FINAL (≤ 24 h) or Σ countMerge(request_count) (above), provider ≠ ''",
		denominator: null,
		dedup: "spans FINAL ≤ 24 h · slo MV (not deduplicated) above",
		hint: "Model requests — one agent run can make several. Not the trace/conversation count (see Traces). Windows of 24 hours or less are counted from the spans themselves; wider windows from the hourly SLO view, which counts a redelivered span twice.",
		zeroCopy: NO_TRAFFIC,
	},
	error_rate: {
		id: "error_rate",
		label: "Error rate",
		kind: "percent",
		family: "slo",
		window: "windowed",
		source: "GET /v1/slo/summary · errors / requests",
		numerator:
			"countIf(status_code = 2) over spans FINAL (≤ 24 h) or Σ countMerge(error_count) (above)",
		denominator: "Σ requests (same rows, provider ≠ '')",
		dedup: "spans FINAL ≤ 24 h · slo MV (not deduplicated) above",
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
		dedup: "spans FINAL ≤ 24 h · slo MV (not deduplicated) above",
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
		dedup: "spans FINAL ≤ 24 h · slo MV (not deduplicated) above",
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
		dedup: "spans FINAL ≤ 24 h · slo MV (not deduplicated) above",
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
			"Σ input + Σ output tokens (spans FINAL ≤ 24 h, sumMerge above) — excludes prompt-cache read/creation tokens",
		denominator: null,
		dedup: "spans FINAL ≤ 24 h · slo MV (not deduplicated) above",
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
		numerator:
			"Σ input tokens (spans FINAL ≤ 24 h, sumMerge above), provider ≠ ''",
		denominator: null,
		dedup: "spans FINAL ≤ 24 h · slo MV (not deduplicated) above",
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
		numerator:
			"Σ output tokens (spans FINAL ≤ 24 h, sumMerge above), provider ≠ ''",
		denominator: null,
		dedup: "spans FINAL ≤ 24 h · slo MV (not deduplicated) above",
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
			"quantile(0.5) over spans FINAL (≤ 24 h) or quantileMerge (above), over the whole window — a true window percentile",
		denominator: null,
		dedup: "spans FINAL ≤ 24 h · slo MV (not deduplicated) above",
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
			"quantile(0.95) over spans FINAL (≤ 24 h) or quantileMerge (above), over the whole window — never a mean of bucket percentiles",
		denominator: null,
		dedup: "spans FINAL ≤ 24 h · slo MV (not deduplicated) above",
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
		numerator:
			"quantile(0.99) over spans FINAL (≤ 24 h) or quantileMerge (above), over the whole window",
		denominator: null,
		dedup: "spans FINAL ≤ 24 h · slo MV (not deduplicated) above",
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
			"count() per epoch-aligned bucket over spans FINAL (≤ 24 h) or countMerge from the hourly view (above)",
		denominator: null,
		dedup: "spans FINAL ≤ 24 h · slo MV (not deduplicated) above",
	},
	errors_series: {
		id: "errors_series",
		label: "Errors per bucket",
		kind: "count",
		family: "slo",
		window: "windowed",
		source: "GET /v1/slo/timeseries · errors per bucket",
		numerator:
			"countIf(status_code = 2) per bucket (spans FINAL ≤ 24 h, countMerge above)",
		denominator: null,
		dedup: "spans FINAL ≤ 24 h · slo MV (not deduplicated) above",
	},
	latency_series: {
		id: "latency_series",
		label: "Latency per bucket",
		kind: "duration_ms",
		family: "slo",
		window: "windowed",
		source: "GET /v1/slo/timeseries · p50_ms / p95_ms / p99_ms per bucket",
		numerator:
			"quantile per bucket (spans FINAL ≤ 24 h, quantileMerge above) — a missing bucket is a gap, never 0",
		denominator: null,
		dedup: "spans FINAL ≤ 24 h · slo MV (not deduplicated) above",
	},
	traffic_by_model: {
		id: "traffic_by_model",
		label: "Requests by model",
		kind: "count",
		family: "slo",
		window: "windowed",
		source: "GET /v1/slo/models · requests per (provider, model)",
		numerator:
			"count() per (provider, model) over spans FINAL (≤ 24 h) or countMerge (above), provider ≠ ''",
		denominator: null,
		dedup: "spans FINAL ≤ 24 h · slo MV (not deduplicated) above",
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
		// B-524 (CX-25): the count is the window's TRUE total (a window function, evaluated
		// before the per-tool LIMIT); only the per-tool breakdown is capped — the response's
		// `truncated` says when the tool list was cut.
		hint: "Every tool call in the window. The per-tool breakdown lists the most-called tools up to the route's cap and says when it was cut; this total is never capped.",
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

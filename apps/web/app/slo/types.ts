/**
 * Shared SLO row shape — one per (hour, provider, model) bucket from the gateway
 * `GET /v1/slo` read over `v_slo_stats`. Lives here (not in a route handler) so
 * the RSC page, the latency aggregation, and the budget arithmetic share one type
 * without importing a Next route module.
 *
 * The former `app/api/slo/route.ts` proxy was unused — the /slo page calls
 * `gatewayGet` directly — so it was removed in the #3 /slo↔/gateway cleanup and
 * this type relocated here.
 */
export type SloRow = {
	bucket_hour: string;
	provider: string;
	model: string;
	p50_ms: number;
	p95_ms: number;
	p99_ms: number;
	requests: number;
	errors: number;
	error_rate_pct: number;
	total_input_tokens: number;
	total_output_tokens: number;
};

/** Window-wide SLO summary — the TRUE merged quantiles (GET /v1/slo/summary),
 *  distinct from the per-bucket {@link SloRow}. Used for the headline tiles so
 *  they show a real p95, not a weighted mean of per-hour percentiles (B-118 #9). */
export type SloSummary = {
	p50_ms: number;
	p95_ms: number;
	p99_ms: number;
	requests: number;
	errors: number;
};

/**
 * Per-(provider, model) window-wide SLO row (GET /v1/slo/models) with the TRUE
 * merged p50/p95/p99 (`quantileMerge`) over the whole window — NOT a client-side
 * mean of per-hour percentiles (provenance audit P2 #8). Requests/errors/tokens
 * are exact merge totals. Backs the SLO table.
 */
export type SloModelRow = {
	provider: string;
	model: string;
	p50_ms: number;
	p95_ms: number;
	p99_ms: number;
	requests: number;
	errors: number;
	error_rate_pct: number;
	total_input_tokens: number;
	total_output_tokens: number;
};

/**
 * One latency-over-time point (GET /v1/slo/timeseries) — the TRUE merged
 * p50/p95/p99 for a display bucket (`quantileMerge` over the LLM spans in the
 * bucket), replacing the chart's client-side request-weighted mean of per-hour
 * percentiles (provenance audit P2 #8). `bucket_start` is the interval start.
 */
export type SloTimePoint = {
	bucket_start: string;
	p50_ms: number;
	p95_ms: number;
	p99_ms: number;
	requests: number;
};

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

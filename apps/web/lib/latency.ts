/**
 * Latency-breakdown read — the honest "what Tracelane adds vs the LLM" split.
 *
 * Backs the three dashboard latency tiles and the SLO table's overhead column.
 * Goes through `gatewayGet` (`lib/gateway.ts`), which mints the per-user WorkOS
 * access token and forwards it as the Bearer; the gateway resolves the tenant
 * from that JWT (ADR-042) and binds `WHERE tenant_id = ?`. The dashboard never
 * binds a tenant id itself.
 *
 * Every number is a REAL captured signal over `spans`:
 *   - overhead = `gateway_overhead_us` (the time Tracelane adds, EXCLUDING the
 *     upstream provider round-trip).
 *   - provider = `duration_us − gateway_overhead_us` (the LLM, not us). The two
 *     segments SUM to total per span — no unattributed bucket.
 *   - ttft    = `gen_ai.response.time_to_first_chunk` (streaming only).
 * `*_samples` are the honesty gate: `0` means "no MEASURED overhead / no
 * streaming traffic in this window" — the tile renders "—", never a fake `0ms`.
 */

/** One per-(provider, model) overhead row — the SLO table's "our slice" column. */
export type LatencyModelRow = {
	provider: string;
	model: string;
	overhead_p95_ms: number;
	samples: number;
};

/** `GET /v1/query/latency-breakdown` response. */
export type LatencyBreakdown = {
	window_hours: number;
	overhead_p50_ms: number;
	overhead_p95_ms: number;
	overhead_p99_ms: number;
	provider_p50_ms: number;
	provider_p95_ms: number;
	provider_p99_ms: number;
	ttft_p50_ms: number;
	ttft_p95_ms: number;
	ttft_p99_ms: number;
	/** Spans with a MEASURED overhead — tiles show "—" when 0 (never fake $0ms). */
	overhead_samples: number;
	/** Streaming spans with a first-chunk time — TTFT tile shows "—" when 0. */
	ttft_samples: number;
	by_model: LatencyModelRow[];
};

// `fetchLatencyBreakdown` moved to `lib/metrics/fetch.ts` (DSH-11): one read layer, one window.

/** Build a `"provider::model" → overhead_p95_ms` lookup for the SLO table. */
export function overheadByModelKey(
	breakdown: LatencyBreakdown | null,
): Map<string, number> {
	const m = new Map<string, number>();
	if (!breakdown) return m;
	for (const row of breakdown.by_model) {
		m.set(`${row.provider}::${row.model}`, row.overhead_p95_ms);
	}
	return m;
}

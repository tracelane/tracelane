/**
 * Gateway operations read — per-provider router health for the current tenant.
 *
 * `fetchGatewayStats` backs the `/gateway` page. It goes through `gatewayGet`
 * (`lib/gateway.ts`), which mints the *per-user* WorkOS access token via
 * `requireGatewayToken()` and forwards it as the Bearer. The gateway resolves
 * that JWT's `org_id` → internal tenant UUID (ADR-042) and binds it into
 * `WHERE tenant_id = ?`, so a user only ever sees their own tenant's stats.
 *
 * only tenant signal. `GATEWAY_BEARER_TOKEN` is never read here.
 *
 * Honesty: every metric is a real, captured signal, but two windows coexist and
 * the UI labels each. Span-derived over the rolling `window_hours`: request
 * volume, error rate, latency percentiles, prompt-cache hit rate, and failover
 * activations. Process-lifetime (since the gateway started, reset on redeploy):
 * `rate_limited_since_start` / `quota_exceeded_since_start` — a 429 emits no
 * span, so those come from the gateway's in-process counters, never a fake 0.
 */

import { GatewayError, gatewayGet } from "@/lib/gateway";

/** One provider's health, as returned by `GET /v1/gateway/stats`. */
export type GatewayProviderHealth = {
	provider: string;
	requests: number;
	errors: number;
	error_rate_pct: number;
	p50_ms: number;
	p95_ms: number;
	p99_ms: number;
	cache_hits: number;
	cache_hit_rate_pct: number;
	/** Requests this provider served via cross-provider failover. */
	failovers: number;
	/** Summed real stored `gen_ai_usage_cost` (USD) for this provider — a lower
	 * bound over priced traffic, never a fabricated estimate. */
	cost_usd: number;
	/** Live circuit-breaker state: "closed" | "open" | "half_open" (ADR-036). */
	circuit_state: string;
};

/** The `GET /v1/gateway/stats` response (gateway shape). */
export type GatewayStats = {
	window_hours: number;
	total_requests: number;
	total_errors: number;
	error_rate_pct: number;
	cache_hit_rate_pct: number;
	provider_count: number;
	/** Requests served via cross-provider failover in the window (span-derived). */
	total_failovers: number;
	/** Tenant-wide real spend (USD) in the window — Σ stored per-span cost. A lower
	 * bound over priced traffic; the UI shows "—" (not $0) when it's 0. */
	total_cost_usd: number;
	/** Rate-limit 429s for this tenant since the gateway started. */
	rate_limited_since_start: number;
	/** Monthly-quota hard-cap 429s for this tenant since the gateway started. */
	quota_exceeded_since_start: number;
	providers: GatewayProviderHealth[];
	/** Upstreams whose circuit breaker is currently Open or Half-Open (ADR-036). */
	open_breakers: number;
	/** Metric names still not in the trace store (empty now; forward-compat). */
	uninstrumented: string[];
};

/**
 * Fetch per-provider gateway health for the authenticated tenant.
 *
 * Returns `null` on any `GatewayError` (gateway unreachable) so the page can
 * show its warming state — distinct from a real empty result (`provider_count
 * === 0`), which means "reachable, but no requests in the window". Any
 * non-`GatewayError` (e.g. the `NEXT_REDIRECT` from `requireGatewayToken`)
 * propagates so the auth redirect is honored.
 *
 * @param opts.hours Look-back window in hours forwarded to the gateway.
 */
export async function fetchGatewayStats(opts?: {
	hours?: number;
}): Promise<GatewayStats | null> {
	const q = new URLSearchParams();
	if (opts?.hours !== undefined) q.set("hours", String(opts.hours));
	const qs = q.toString();
	try {
		return await gatewayGet<GatewayStats>(
			`/v1/gateway/stats${qs ? `?${qs}` : ""}`,
		);
	} catch (err) {
		if (err instanceof GatewayError) return null;
		throw err;
	}
}

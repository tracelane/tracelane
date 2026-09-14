/**
 * Gateway operations read — per-provider router health for the current tenant.
 *
 * `fetchGatewayStats` backs the `/gateway` page. It goes through `gatewayGet`
 * (`lib/gateway.ts`), which mints the *per-user* WorkOS access token via
 * `requireGatewayToken()` and forwards it as the Bearer. The gateway resolves
 * that JWT's `org_id` → internal tenant UUID (ADR-042) and binds it into
 * `WHERE tenant_id = ?`, so a user only ever sees their own tenant's stats.
 *
 *  posture: the dashboard NEVER binds a tenant id itself; the JWT is the
 * only tenant signal. `GATEWAY_BEARER_TOKEN` is never read here.
 *
 * Honesty: every metric is a real, captured signal, but two windows coexist and
 * the UI labels each. Span-derived over the rolling `window_hours`: request
 * volume, error rate, latency percentiles, prompt-cache hit rate, and failover
 * activations. Process-lifetime (since the gateway started, reset on redeploy):
 * `rate_limited_since_start` / `budget_exceeded_since_start` — a 429 emits no
 * span, so those come from the gateway's in-process counters, never a fake 0.
 */

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
	/** Gateway-overhead p95 (ms) — Tracelane's own slice next to the end-to-end
	 * p95 (§ latency framing). `0` (→ "—" in the UI) when this provider has no
	 * span carrying a measured overhead. */
	overhead_p95_ms: number;
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
	/** Budget-exceeded 429s (per-key/workspace USD budget) for this tenant since the gateway started. */
	budget_exceeded_since_start: number;
	providers: GatewayProviderHealth[];
	/** Upstreams whose circuit breaker is currently Open or Half-Open (ADR-036). */
	open_breakers: number;
	/** Metric names still not in the trace store (empty now; forward-compat). */
	uninstrumented: string[];
};

// `fetchGatewayStats` moved to `lib/metrics/fetch.ts` (DSH-11): one read layer, one window.

// ── Cost attribution (GWY-43, Sprint 1 item 5) ───────────────────────────────

/** One row of the spend breakdown, as returned by `GET /v1/costs`. */
export type CostBreakdownRow = {
	/**
	 * The dimension value: an `api_keys.id`, a model string, or a provider id.
	 * EMPTY STRING when the span carries no value on this dimension — a
	 * session-authenticated request has no API key. That is not the same as
	 * "unattributed", and the UI labels it rather than hiding the row.
	 */
	dimension: string;
	requests: number;
	/** Requests in this bucket whose cost we actually know. */
	priced_requests: number;
	/** Requests we could NOT price. Never folded into `cost_usd` as zero. */
	unpriced_requests: number;
	cost_usd: number;
	input_tokens: number;
	output_tokens: number;
	/**
	 * Of the above, how much was an eval run or an experiment arm (R94).
	 * `0` here is MEASURED — every span either carries `tracelane_eval_run_id`
	 * or does not — so it is safe to render as a zero rather than as unknown.
	 */
	eval_requests: number;
	eval_cost_usd: number;
};

/** The `GET /v1/costs` response (gateway shape). */
export type CostBreakdown = {
	window_hours: number;
	by: "key" | "model" | "provider";
	total_cost_usd: number;
	total_requests: number;
	priced_requests: number;
	/**
	 * How much of the window `total_cost_usd` does NOT account for.
	 *
	 * This is the number that makes the total honest. `pricing::cost_usd`
	 * returns no value for a model whose price we do not know, and the gateway
	 * omits the attribute rather than writing 0 — but every read path used to
	 * wrap the extract in `if(… > 0, x, 0)`, so unknown arrived as a confident
	 * $0.00. Rendering this beside the total is what separates a cheap window
	 * from an unpriced one.
	 */
	unpriced_requests: number;
	/** Present only for `by=key`: when per-key attribution began. */
	attribution_begins_note: string | null;
	/** `"all"` (default) | `"production"` | `"eval"` — echoed by the gateway. */
	scope: "all" | "production" | "eval";
	/**
	 * **The R94 split.** An experiment is deliberately expensive, so its spend
	 * landing inside the customer's production figure is the worst possible
	 * number to leave conflated. The gateway reports both halves at every scope;
	 * `total_cost_usd` keeps its meaning and is DECOMPOSED rather than redefined.
	 */
	eval_cost_usd: number;
	eval_requests: number;
	production_cost_usd: number;
	production_requests: number;
	/** When eval attribution began — before R81 there was no attribute to read. */
	eval_attribution_note: string;
	rows: CostBreakdownRow[];
};

// `fetchCostBreakdown` moved to `lib/metrics/fetch.ts` (DSH-11): one read layer, one window.

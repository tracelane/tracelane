/**
 * Guardrails read — the pre-flight guardrail engine's verdicts for the current
 * tenant. Backs the `/guardrails` page.
 *
 * Goes through `gatewayGet` (`lib/gateway.ts`), which mints the *per-user* WorkOS
 * access token and forwards it; the gateway resolves the JWT's org → internal
 * tenant UUID and binds it into `WHERE tenant_id = ?`, so a user only ever sees
 * their own tenant's verdicts. `GATEWAY_BEARER_TOKEN` is never read here.
 *
 * Honesty: every field is captured on every request in `guardrail_verdicts`
 * (decision, per-rail outcomes, fail-open rails, latency). Nothing is derived or
 * fabricated — the fail-open rate is a real count, not an estimate.
 */

/** One guardrail rail's health, as returned by `GET /v1/guardrails/stats`. */
export type GuardrailRailHealth = {
	rail: string;
	evaluations: number;
	blocks: number;
	block_rate_pct: number;
	fail_opens: number;
	fail_open_rate_pct: number;
	p95_ms: number;
};

/** The `GET /v1/guardrails/stats` response (gateway shape). */
export type GuardrailStats = {
	window_hours: number;
	total_evaluations: number;
	block_rate_pct: number;
	redact_rate_pct: number;
	warn_rate_pct: number;
	/** Share of verdicts where a rail failed OPEN — the trust headline. */
	fail_open_rate_pct: number;
	fail_open_verdicts: number;
	blocks: number;
	redacts: number;
	warns: number;
	allows: number;
	request_side: number;
	response_side: number;
	p50_ms: number;
	p95_ms: number;
	p99_ms: number;
	rails: GuardrailRailHealth[];
};

// `fetchGuardrailStats` moved to `lib/metrics/fetch.ts` (DSH-11): one read layer, one window.

/** One verdict-detail row from `GET /v1/guardrails/verdicts`. */
export type GuardrailVerdict = {
	correlation_id: string;
	side: string;
	decision: string;
	/** "YYYY-MM-DD HH:MM:SS.ffffff" (ClickHouse toString). */
	event_time: string;
	total_latency_micros: number;
	/** JSON string: array of per-rail verdicts (rail, outcome, reason_code, …). */
	rails: string;
	fail_open_rails: string[];
};

// `fetchGuardrailVerdicts` moved to `lib/metrics/fetch.ts` (DSH-11): one read layer, one window.

/**
 * Guardrails read — the pre-flight guardrail engine's verdicts for the current
 * tenant. Backs the `/guardrails` page.
 *
 * Goes through `gatewayGet` (`lib/gateway.ts`), which mints the *per-user* WorkOS
 * access token and forwards it; the gateway resolves the JWT's org → internal
 * tenant UUID and binds it into `WHERE tenant_id = ?`, so a user only ever sees
 *
 * Honesty: every field is captured on every request in `guardrail_verdicts`
 * (decision, per-rail outcomes, fail-open rails, latency). Nothing is derived or
 * fabricated — the fail-open rate is a real count, not an estimate.
 */

import { GatewayError, gatewayGet } from "@/lib/gateway";

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

/**
 * Fetch guardrail-engine stats for the authenticated tenant.
 *
 * Returns `null` on any `GatewayError` (gateway unreachable) so the page can show
 * its warming state — distinct from a reachable-but-empty result
 * (`total_evaluations === 0`). Non-`GatewayError` (e.g. the `NEXT_REDIRECT` from
 * `requireGatewayToken`) propagates so the auth redirect is honored.
 *
 * @param opts.hours Look-back window in hours forwarded to the gateway.
 */
export async function fetchGuardrailStats(opts?: {
	hours?: number;
}): Promise<GuardrailStats | null> {
	const q = new URLSearchParams();
	if (opts?.hours !== undefined) q.set("hours", String(opts.hours));
	const qs = q.toString();
	try {
		return await gatewayGet<GuardrailStats>(
			`/v1/guardrails/stats${qs ? `?${qs}` : ""}`,
		);
	} catch (err) {
		if (err instanceof GatewayError) return null;
		throw err;
	}
}

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

/**
 * Fetch the verdict-detail rows behind the decision-mix counts — the honest
 * click-through for "N blocked" (a blocked verdict 403s the request pre-span,
 * so there is no trace to link to; the verdict itself is the detail).
 *
 * Returns `null` on any `GatewayError` so the page shows its warming state.
 */
export async function fetchGuardrailVerdicts(opts?: {
	hours?: number;
	decision?: string;
	limit?: number;
}): Promise<GuardrailVerdict[] | null> {
	const q = new URLSearchParams();
	if (opts?.hours !== undefined) q.set("hours", String(opts.hours));
	if (opts?.decision) q.set("decision", opts.decision);
	if (opts?.limit !== undefined) q.set("limit", String(opts.limit));
	const qs = q.toString();
	try {
		const res = await gatewayGet<{ verdicts: GuardrailVerdict[] }>(
			`/v1/guardrails/verdicts${qs ? `?${qs}` : ""}`,
		);
		return res.verdicts;
	} catch (err) {
		if (err instanceof GatewayError) return null;
		throw err;
	}
}

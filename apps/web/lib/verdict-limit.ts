/**
 * Guardrail verdict-list page-size clamp (B-335b).
 *
 * The gateway clamps `?limit=` to `[1, MAX_VERDICT_LIMIT]` itself
 * (`crates/gateway/src/trace_reads.rs::guardrail_verdicts_handler`, via
 * `DEFAULT_VERDICT_LIMIT` / `MAX_VERDICT_LIMIT`). This mirrors that cap on the
 * UI side so the page never asks for — or links to — a limit the gateway
 * would silently truncate anyway: a "show up to 500" link that actually only
 * fetched 100 would be its own small dishonesty. Pure, no gateway call.
 */

/** Verdict-list page size when `?limit=` is absent — mirrors the gateway's
 * `DEFAULT_VERDICT_LIMIT`. */
export const DEFAULT_VERDICT_LIMIT = 100;

/** The gateway's hard cap on `?limit=` for `GET /v1/guardrails/verdicts`
 * (`MAX_VERDICT_LIMIT`, trace_reads.rs). Never request or link past this. */
export const MAX_VERDICT_LIMIT = 500;

/**
 * Parse and clamp a `?limit=` search-param value to `[1, MAX_VERDICT_LIMIT]`.
 * Absent, non-numeric, non-finite or non-positive input falls back to
 * `DEFAULT_VERDICT_LIMIT` — never 0, never negative, never above the
 * gateway's cap.
 */
export function clampVerdictLimit(raw: string | undefined): number {
	if (raw === undefined) return DEFAULT_VERDICT_LIMIT;
	const n = Number.parseInt(raw, 10);
	if (!Number.isFinite(n) || n < 1) return DEFAULT_VERDICT_LIMIT;
	return Math.min(n, MAX_VERDICT_LIMIT);
}

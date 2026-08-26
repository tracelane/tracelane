/**
 * Circuit-breaker state → UI presentation for the /gateway "Circuit" column.
 *
 * Pure — no runtime deps — so it is unit-testable without the RSC page (the
 * /gateway surface had no tests). Mirrors the gateway `State::as_str` strings.
 */

/** Badge tone for a breaker state: open = danger, half_open = warn, else ok. */
export function circuitTone(state: string): "ok" | "warn" | "danger" {
	if (state === "open") return "danger";
	if (state === "half_open") return "warn";
	return "ok";
}

/** Human label for a breaker state. Unknown values fall back to "Closed". */
export function circuitLabel(state: string): string {
	if (state === "open") return "Open";
	if (state === "half_open") return "Half-open";
	return "Closed";
}

/**
 * True when the breaker is not passing traffic normally.
 *
 * It said "worth a badge", and after the P1 design pass that is no longer what
 * the page does: `/gateway` renders ONE status mark for every state (a toned dot
 * plus the word) instead of a badge for two states and bare mono text for the
 * third, so nothing calls this to decide a rendering any more. Kept — with its
 * tests — because "is this breaker healthy" is a real question about the field
 * and the next caller should not re-derive the string comparison; deleted the
 * moment it is genuinely nobody's question.
 */
export function circuitUnhealthy(state: string): boolean {
	return state === "open" || state === "half_open";
}

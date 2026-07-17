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

/** True when the breaker is not passing traffic normally (worth a badge). */
export function circuitUnhealthy(state: string): boolean {
	return state === "open" || state === "half_open";
}

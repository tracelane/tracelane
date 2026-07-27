/**
 * fmt-dur — canonical duration formatter for trace-viewer surfaces.
 *
 * One shared implementation: adaptive unit (µs → ms → s), whole for µs, 1
 * decimal for ms, 2 decimals for s. Used by WaterfallView (axis ticks + bar
 * labels), SpanInspector (duration attribute row), and TraceSummaryHeader
 * (trace-level duration stat). A single source prevents the format mismatch
 * (SpanInspector previously always showed fixed ms.toFixed(3); waterfall used
 * adaptive — the same span read differently in each panel).
 *
 * Callers: pass microseconds. Result is tabular-ready — the adaptive unit
 * keeps values a consistent character width within a common span set.
 */

/**
 * Format a duration in microseconds with adaptive unit.
 *   0–999 µs       → "Nµs"
 *   1 000–999 999  → "N.Nms"
 *   ≥ 1 000 000    → "N.NNs"
 *
 * @param us - Duration in microseconds (must be ≥ 0).
 */
export function fmtDur(us: number): string {
	if (us < 1_000) return `${us}µs`;
	if (us < 1_000_000) return `${(us / 1_000).toFixed(1)}ms`;
	return `${(us / 1_000_000).toFixed(2)}s`;
}

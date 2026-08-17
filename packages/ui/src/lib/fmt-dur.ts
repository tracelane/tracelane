/**
 * fmt-dur — the canonical duration formatter for every surface that shows one.
 *
 * ONE implementation: adaptive unit (µs → ms → s), whole for µs, 1 decimal for ms,
 * 2 decimals for s.
 *
 * WHY IT LIVES HERE AND NOT IN `apps/web`. It was written in `apps/web/lib/fmt-dur.ts`
 * to stop the waterfall and the span inspector formatting the same span differently —
 * and it did, for those two. But `TimeRuler` is in this package and cannot import from
 * the app, so an axis that terminates with the trace total had to either duplicate the
 * rules or disagree with the bar labels sitting beside it. Duplicating a formatter to
 * satisfy a package boundary is how the original mismatch happened; moving it down is
 * the fix that removes the boundary instead of working around it.
 *
 * Callers: pass MICROSECONDS.
 */

/**
 * Format a duration in microseconds with an adaptive unit.
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

/** Same rules, taking MILLISECONDS — what `TimeRuler` works in. */
export function fmtDurMs(ms: number): string {
	return fmtDur(Math.round(ms * 1000));
}

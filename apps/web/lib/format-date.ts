/**
 * Deterministic absolute-date formatting for data tables.
 *
 * `absoluteDate` renders an ISO/RFC3339 UTC timestamp as "MMM D, YYYY" using UTC
 * getters + a fixed month table — no locale (`Intl`), no relative math, no clock —
 * so it is byte-identical across the SSR/client hydration boundary AND
 * unambiguous to read (a first-seen / last-seen pair is directly comparable).
 *
 * We deliberately do NOT render "N days ago" for first/last-seen: pairing a
 * relative value with an absolute one — and the floor-vs-calendar-day gap of an
 * elapsed-time relative (Jul 11 → Jul 14 is 3 calendar days but 2.67 elapsed →
 * "2d ago") — reads as a wrong / contradictory date. See
 * runbooks/RCA-signatures-first-last-seen-dates.md.
 */

const MONTHS = [
	"Jan",
	"Feb",
	"Mar",
	"Apr",
	"May",
	"Jun",
	"Jul",
	"Aug",
	"Sep",
	"Oct",
	"Nov",
	"Dec",
] as const;

/** "2026-07-11T12:07:23Z" → "Jul 11, 2026" (UTC). "—" if unparseable/empty. */
export function absoluteDate(iso: string): string {
	if (!iso) return "—";
	const t = new Date(iso).getTime();
	if (Number.isNaN(t)) return "—";
	const d = new Date(t);
	const month = MONTHS[d.getUTCMonth()] ?? "";
	return `${month} ${d.getUTCDate()}, ${d.getUTCFullYear()}`;
}

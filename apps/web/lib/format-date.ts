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
 * "2d ago") — reads as a wrong / contradictory date (the internal
 * signatures first/last-seen-dates incident review).
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

/**
 * Parse a gateway timestamp to epoch-ms, interpreting a zone-less value as UTC.
 *
 * The gateway serialises ClickHouse `DateTime64` via `toString(start_time)`,
 * which yields a NAIVE string with no zone: `"2026-07-21 08:45:53.982997"`
 * (space separator, no `T`, no `Z`). `new Date()` parses a zone-less date-time
 * as **local** time, so on a non-UTC viewer (e.g. IST, +5:30) every gateway
 * timestamp was shifted by the viewer's offset before the UTC getters read it —
 * a trace at 08:45 UTC rendered as "03:15 UTC". It also made the SSR (UTC
 * server) and client (viewer zone) parses disagree, so the doc-claimed
 * "byte-identical across hydration" was false.
 *
 * Fix: if the value carries no zone, anchor it to UTC (`T` + `Z`) before
 * parsing. Values that already carry a zone (`…Z`, `+05:30`) and epoch-ms
 * numbers pass through untouched. Date-only strings (no time) are already
 * parsed as UTC by JS, so they're left alone. This is TZ-independent by
 * construction — the same instant on every viewer (the internal
 * naive-timestamp local-parse incident review).
 */
export function parseUtcMs(iso: string | number): number {
	if (typeof iso === "number") return iso;
	if (!iso) return Number.NaN;
	let s = iso.trim();
	const hasTime = s.includes(":");
	const hasZone = /([zZ]|[+-]\d{2}:?\d{2})$/.test(s);
	if (hasTime && !hasZone) s = `${s.replace(" ", "T")}Z`;
	return new Date(s).getTime();
}

/**
 * "2026-07-11T12:07:23Z" (or epoch ms) → "Jul 11, 2026" (UTC). "—" if
 * unparseable / empty. Accepts a number so callers holding epoch-ms (prompt
 * `updated_at_ms`, etc.) can render the same UTC date without a local-zone
 * `new Date(...).toLocaleDateString()`. Zone-less gateway strings are anchored
 * to UTC via `parseUtcMs`.
 */
export function absoluteDate(iso: string | number): string {
	if (iso === "" || iso === null || iso === undefined) return "—";
	const t = parseUtcMs(iso);
	if (Number.isNaN(t)) return "—";
	const d = new Date(t);
	const month = MONTHS[d.getUTCMonth()] ?? "";
	return `${month} ${d.getUTCDate()}, ${d.getUTCFullYear()}`;
}

/**
 * "2026-07-20T14:32:07Z" → "Jul 20, 14:32" (UTC). "—" if unparseable/empty.
 *
 * Anchors zone-less gateway strings to UTC (`parseUtcMs`) then uses UTC getters
 * exclusively, so the output is byte-identical across the SSR / client
 * hydration boundary AND identical on every viewer's zone — no
 * suppressHydrationWarning needed. Intended for the Traces table "Started
 * (UTC)" column where high-volume production timestamps need to be scannable at
 * a glance, not relative.
 */
export function formatStartedUtc(iso: string): string {
	if (!iso) return "—";
	const t = parseUtcMs(iso);
	if (Number.isNaN(t)) return "—";
	const d = new Date(t);
	const month = MONTHS[d.getUTCMonth()] ?? "";
	const day = d.getUTCDate();
	const h = String(d.getUTCHours()).padStart(2, "0");
	const min = String(d.getUTCMinutes()).padStart(2, "0");
	return `${month} ${day}, ${h}:${min}`;
}

/**
 * "2026-07-20T14:32:07Z" → "Jul 20, 2026 · 14:32 UTC". "—" if unparseable.
 *
 * The app renders ALL timestamps in UTC (the audit ledger, traces, signatures
 * and sessions are cross-region records; a viewer-local zone would make two
 * users disagree on when an event happened). This is the labeled, full
 * date+time form for list/detail rows — zone-less gateway strings are anchored
 * to UTC (`parseUtcMs`) then read with UTC getters, so it is identical across
 * the SSR/client hydration boundary and on every viewer's zone, and carries an
 * explicit "UTC" tag.
 */
export function formatDateTimeUtc(iso: string): string {
	if (!iso) return "—";
	const t = parseUtcMs(iso);
	if (Number.isNaN(t)) return "—";
	const d = new Date(t);
	const month = MONTHS[d.getUTCMonth()] ?? "";
	const h = String(d.getUTCHours()).padStart(2, "0");
	const min = String(d.getUTCMinutes()).padStart(2, "0");
	return `${month} ${d.getUTCDate()}, ${d.getUTCFullYear()} · ${h}:${min} UTC`;
}

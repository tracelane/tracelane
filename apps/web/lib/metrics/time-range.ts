/**
 * time-range — THE one time window for every metric surface (DSH-11 §3a).
 *
 * One URL grammar, one preset list, one bucket ladder, one clamp. Every page that
 * shows a windowed number parses its window here, asks the gateway for it through
 * `windowParams`, draws its buckets from `bucketGrid`, and builds every
 * drill-through href with `withWindow`. No page computes hours, buckets or a
 * `since` of its own — `scripts/ci/check-metric-single-source.py` refuses one that
 * does, because three pages each doing this arithmetic is how the dashboard came
 * to render two definitions of "requests" side by side.
 *
 * URL GRAMMAR
 *   ?range=<preset>                          rolling window ending now
 *   ?since=<ISO-8601 UTC>&until=<ISO UTC>    absolute window [since, until)
 *   ?since=<ISO>                             absolute start, ending now
 *   (nothing)                                the page's default preset
 * A preset and an absolute pair are mutually exclusive: `withWindow` writes one or
 * the other, never both, and `parseTimeRange` treats `since` as winning when both
 * are present (a stale `since` beside a fresh `range` is the bug
 * `app/traces/filter-params.ts` already fixes on the client — the picker deletes
 * the other form when it sets one).
 *
 * BUCKETS ARE EPOCH-ALIGNED, deliberately, so a shared URL draws the same bars
 * when it is reopened. The consequence is visible and is rendered rather than
 * hidden: the first and last bucket of a rolling window are PARTIAL (they cover
 * less of the axis than a full bucket), and `bucketGrid` flags them.
 *
 * Pure: `nowMs` is a parameter, never `Date.now()`, so the tests pin it and the
 * server can pass one instant to every read on a page.
 */

const MIN = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;

export const PRESETS = [
	{ value: "1h", label: "1h", hours: 1, long: "1 hour" },
	{ value: "6h", label: "6h", hours: 6, long: "6 hours" },
	{ value: "24h", label: "24h", hours: 24, long: "24 hours" },
	{ value: "7d", label: "7d", hours: 168, long: "7 days" },
	{ value: "30d", label: "30d", hours: 720, long: "30 days" },
] as const;

export type Preset = (typeof PRESETS)[number]["value"];

export function isPreset(v: string | undefined | null): v is Preset {
	return PRESETS.some((p) => p.value === v);
}

/**
 * The widest window the spans / SLO / guardrail families will serve — 720 h,
 * the gateway's `MAX_SLO_HOURS` / `MAX_GATEWAY_HOURS` / `MAX_GUARDRAIL_HOURS`
 * (`crates/gateway/src/trace_reads.rs`). The gateway clamps too; this mirror
 * exists so the UI never asks for what it will not get and can SAY it clamped.
 */
export const MAX_WINDOW_MS = 720 * HOUR;
/** `/v1/sessions` is capped in DAYS (`MAX_SESSION_WINDOW_DAYS = 90`). */
export const MAX_SESSION_WINDOW_MS = 90 * DAY;

/** Never more than this many buckets on one series — the gateway ceiling too. */
export const MAX_BUCKETS = 96;
/** The ladder a bucket may be. Nothing in between: `1.37 h` is a machine's number. */
export const BUCKET_LADDER_MS = [
	MIN,
	5 * MIN,
	10 * MIN,
	15 * MIN,
	30 * MIN,
	HOUR,
	2 * HOUR,
	3 * HOUR,
	6 * HOUR,
	12 * HOUR,
	DAY,
] as const;

/**
 * Sub-hour buckets are served from raw `spans` and only for windows this wide or
 * narrower (spec §3a.4); wider windows floor at the hourly MV's resolution.
 */
export const SUB_HOUR_MAX_WINDOW_MS = 24 * HOUR;

export interface TimeRange {
	kind: "preset" | "custom";
	/** The preset, or `null` for an absolute window. */
	preset: Preset | null;
	/** Inclusive start, epoch ms. */
	sinceMs: number;
	/** Exclusive end, epoch ms. */
	untilMs: number;
	widthMs: number;
	/** The ONE bucket width for every series drawn over this window. */
	bucketMs: number;
	/** True when the requested width exceeded the cap and `sinceMs` was moved. */
	clamped: boolean;
	/** What was asked for before clamping (equals `widthMs` when not clamped). */
	requestedWidthMs: number;
	/** True when the URL carried a window that could not be parsed — the default
	 *  preset is in effect and the page should say so. */
	invalid: boolean;
	/** "last 24 hours" · "2026-09-01 14:00 → 17:00 UTC" */
	label: string;
	/** "24h" · "custom" — for compact headings. */
	short: string;
}

export interface ParseOptions {
	defaultPreset: Preset;
	nowMs: number;
	/** Family cap. Defaults to the spans/SLO/guardrail cap. */
	maxWidthMs?: number;
	/**
	 * Floor for the bucket ladder. The SLO hourly view cannot go below an hour for
	 * windows wider than a day (§3a.4); the default applies that rule.
	 */
	bucketFloorMs?: number;
}

/** Accepts ISO-8601 (any zone; naive strings are read as UTC) or epoch ms. */
export function parseInstant(s: string | undefined | null): number | null {
	if (!s) return null;
	const t = s.trim();
	if (/^\d{10,13}$/.test(t)) {
		const n = Number(t);
		return t.length <= 10 ? n * 1000 : n;
	}
	const hasZone = /([zZ]|[+-]\d{2}:?\d{2})$/.test(t);
	const ms = Date.parse(hasZone ? t : `${t.replace(" ", "T")}Z`);
	return Number.isNaN(ms) ? null : ms;
}

/**
 * Pick the bucket for a window: the smallest ladder step that keeps the series at
 * or under `target` buckets, floored at `floorMs`, never over `MAX_BUCKETS`.
 *
 *   ≤ 1 h → 1 m (60) · ≤ 6 h → 5 m (72) · ≤ 24 h → 30 m (48) · ≤ 3 d → 1 h (72)
 *   ≤ 7 d → 3 h (56) · ≤ 30 d → 12 h (60)
 */
export function bucketFor(
	widthMs: number,
	opts: { floorMs?: number; target?: number } = {},
): number {
	const floor = opts.floorMs ?? MIN;
	const target = opts.target ?? 72;
	let chosen: number = BUCKET_LADDER_MS[BUCKET_LADDER_MS.length - 1] ?? DAY;
	for (const step of BUCKET_LADDER_MS) {
		if (step < floor) continue;
		if (widthMs / step <= target) {
			chosen = step;
			break;
		}
	}
	// A window wider than the ladder's top step × MAX_BUCKETS cannot happen under
	// the caps, but the ceiling is asserted rather than assumed.
	while (widthMs / chosen > MAX_BUCKETS) chosen *= 2;
	return chosen;
}

function presetLabel(p: Preset): string {
	return `last ${PRESETS.find((x) => x.value === p)?.long ?? p}`;
}

function fmtUtc(ms: number, withSeconds: boolean): string {
	const d = new Date(ms);
	const p = (n: number) => String(n).padStart(2, "0");
	const base = `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}`;
	return withSeconds ? `${base}:${p(d.getUTCSeconds())}` : base;
}

/** "2026-09-01 14:00 → 17:00 UTC" (same day) · "2026-08-30 00:00 → 2026-09-02 00:00 UTC". */
export function formatWindowUtc(sinceMs: number, untilMs: number): string {
	const a = new Date(sinceMs);
	const b = new Date(untilMs);
	const sameDay =
		a.getUTCFullYear() === b.getUTCFullYear() &&
		a.getUTCMonth() === b.getUTCMonth() &&
		a.getUTCDate() === b.getUTCDate();
	const secs = sinceMs % MIN !== 0 || untilMs % MIN !== 0;
	const from = fmtUtc(sinceMs, secs);
	const to = sameDay ? fmtUtc(untilMs, secs).slice(11) : fmtUtc(untilMs, secs);
	return `${from} → ${to} UTC`;
}

function build(
	kind: TimeRange["kind"],
	preset: Preset | null,
	sinceMs: number,
	untilMs: number,
	opts: ParseOptions,
	invalid: boolean,
): TimeRange {
	const maxWidth = opts.maxWidthMs ?? MAX_WINDOW_MS;
	const requestedWidthMs = untilMs - sinceMs;
	let since = sinceMs;
	let clamped = false;
	if (requestedWidthMs > maxWidth) {
		since = untilMs - maxWidth;
		clamped = true;
	}
	const widthMs = untilMs - since;
	const floor =
		opts.bucketFloorMs ?? (widthMs > SUB_HOUR_MAX_WINDOW_MS ? HOUR : MIN);
	return {
		kind,
		preset,
		sinceMs: since,
		untilMs,
		widthMs,
		bucketMs: bucketFor(widthMs, { floorMs: floor }),
		clamped,
		requestedWidthMs,
		invalid,
		label: preset ? presetLabel(preset) : formatWindowUtc(since, untilMs),
		short: preset ?? "custom",
	};
}

/**
 * Resolve a page's window from its search params. Never throws: an unparseable
 * or inverted custom window falls back to the default preset with `invalid: true`.
 */
export function parseTimeRange(
	sp: { range?: string; since?: string; until?: string },
	opts: ParseOptions,
): TimeRange {
	const fallback = (invalid: boolean): TimeRange => {
		const hours =
			PRESETS.find((p) => p.value === opts.defaultPreset)?.hours ?? 24;
		return build(
			"preset",
			opts.defaultPreset,
			opts.nowMs - hours * HOUR,
			opts.nowMs,
			opts,
			invalid,
		);
	};

	// `since` WINS over `range` — see the header. `until` without `since` is
	// meaningless and is ignored.
	if (sp.since) {
		const since = parseInstant(sp.since);
		const until = sp.until ? parseInstant(sp.until) : opts.nowMs;
		if (since === null || until === null || !(until > since)) {
			return fallback(true);
		}
		// A window in the future is a typo, not a query.
		return build(
			"custom",
			null,
			since,
			Math.min(until, opts.nowMs),
			opts,
			false,
		);
	}
	if (sp.range) {
		if (isPreset(sp.range)) {
			const hours = PRESETS.find((p) => p.value === sp.range)?.hours ?? 24;
			return build(
				"preset",
				sp.range,
				opts.nowMs - hours * HOUR,
				opts.nowMs,
				opts,
				false,
			);
		}
		return fallback(true);
	}
	return fallback(false);
}

/**
 * A LIST window that may be OFF. `range=all` (or the legacy empty string) means no
 * bound at all — the traces list's explicit "all time" opt-out. A `since`/`until`
 * pair still wins over the preset (`filter-params.ts`' rule).
 */
export function parseOptionalTimeRange(
	sp: { range?: string; since?: string; until?: string },
	opts: ParseOptions,
): TimeRange | null {
	if (!sp.since && (sp.range === "all" || sp.range === "")) return null;
	return parseTimeRange(sp, opts);
}

export interface GridBucket {
	/** Bucket start, epoch ms, aligned to `bucketMs`. */
	t: number;
	/** Bucket end (exclusive), epoch ms. */
	tEnd: number;
	/** True when the window's edge falls inside this bucket. */
	partial: boolean;
}

/**
 * The buckets a series over this window occupies, oldest first. The first bucket
 * starts at or before `sinceMs`; the last ends at or after `untilMs`. Edge buckets
 * that the window only partly covers are flagged — the chart de-emphasises them
 * and the tooltip says which part of the bucket the number covers.
 */
export function bucketGrid(
	r: Pick<TimeRange, "sinceMs" | "untilMs" | "bucketMs">,
): GridBucket[] {
	const { sinceMs, untilMs, bucketMs } = r;
	const out: GridBucket[] = [];
	let t = Math.floor(sinceMs / bucketMs) * bucketMs;
	while (t < untilMs && out.length < MAX_BUCKETS) {
		const tEnd = t + bucketMs;
		out.push({ t, tEnd, partial: t < sinceMs || tEnd > untilMs });
		t = tEnd;
	}
	return out;
}

/** Which unit the gateway's series routes take the bucket in. */
export function bucketParam(bucketMs: number): {
	name: "bucket" | "bucket_minutes";
	value: number;
} {
	return bucketMs >= HOUR
		? { name: "bucket", value: Math.round(bucketMs / HOUR) }
		: { name: "bucket_minutes", value: Math.round(bucketMs / MIN) };
}

/**
 * The gateway window params for this range — `since` + `until` as RFC3339, which
 * every windowed route parses (`parse_rfc3339_secs` / `_micros`), plus the bucket
 * when the caller draws a series. Never `hours=`: a rolling window expressed as
 * an instant is what makes the tiles and the chart agree to the millisecond.
 */
export function windowParams(
	r: Pick<TimeRange, "sinceMs" | "untilMs" | "bucketMs">,
	opts: { bucket?: boolean } = {},
): URLSearchParams {
	const q = new URLSearchParams();
	q.set("since", new Date(r.sinceMs).toISOString());
	q.set("until", new Date(r.untilMs).toISOString());
	if (opts.bucket) {
		const b = bucketParam(r.bucketMs);
		q.set(b.name, String(b.value));
	}
	return q;
}

/**
 * A drill-through href carrying THIS window. A preset stays a preset (so the
 * destination keeps rolling with the reader); a custom window is written as the
 * absolute pair. `extra` params are appended verbatim; an explicit
 * `since`/`until` in `extra` (a bucket click) overrides the range.
 */
export function withWindow(
	path: string,
	r: Pick<TimeRange, "kind" | "preset" | "sinceMs" | "untilMs">,
	extra: Record<string, string | undefined> = {},
): string {
	const q = new URLSearchParams();
	for (const [k, v] of Object.entries(extra)) {
		if (v !== undefined && v !== "" && k !== "since" && k !== "until")
			q.set(k, v);
	}
	if (extra.since) {
		q.set("since", extra.since);
		if (extra.until) q.set("until", extra.until);
	} else if (r.kind === "preset" && r.preset) {
		q.set("range", r.preset);
	} else {
		q.set("since", new Date(r.sinceMs).toISOString());
		q.set("until", new Date(r.untilMs).toISOString());
	}
	const s = q.toString();
	return s ? `${path}?${s}` : path;
}

/** The href for one bucket's traces: the bucket's own bounds, plus filters. */
export function bucketHref(
	path: string,
	b: Pick<GridBucket, "t" | "tEnd">,
	extra: Record<string, string | undefined> = {},
): string {
	return withWindow(
		path,
		{ kind: "custom", preset: null, sinceMs: b.t, untilMs: b.tEnd },
		{
			...extra,
			since: new Date(b.t).toISOString(),
			until: new Date(b.tEnd).toISOString(),
		},
	);
}

/** Human bucket width: "5 m" · "1 h" · "12 h" · "1 d". */
export function bucketLabel(bucketMs: number): string {
	if (bucketMs >= DAY) return `${Math.round(bucketMs / DAY)} d`;
	if (bucketMs >= HOUR) return `${Math.round(bucketMs / HOUR)} h`;
	return `${Math.round(bucketMs / MIN)} m`;
}

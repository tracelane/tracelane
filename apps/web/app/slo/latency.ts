/**
 * SLO time-series aggregation (backs the `<LatencyTimeline>` chart and the
 * dashboard traffic `<Lollipop>` via `buildTrafficPoints`). Pure — type-only
 * imports, no runtime deps — so it is unit-testable in isolation and carries no
 * Next route/page export constraints.
 */

import type { SloRow, SloTimePoint } from "@/app/slo/types";
import type { LatencyPoint } from "@tracelanedev/ui";

const HOUR_MS = 3_600_000;

/**
 * The window a chart is drawn over, in bucket-aligned epoch ms.
 *
 * ── WHY THIS TYPE EXISTS (R59, 2026-08-16) ───────────────────────────────────────
 * Both builders below used to derive their grid from the FIRST and LAST OBSERVED
 * bucket. That made the chart's domain a property of the DATA while the heading above
 * it — "Traffic over time — last 24 hours · UTC" — describes the QUERY. A tenant whose
 * only traffic was in the last two hours got two buckets drawn edge-to-edge across the
 * full card under a heading claiming twenty-four.
 *
 * It also hid the thing this product exists to show. With a data-derived domain, steady
 * traffic all day and a single 4am burst render IDENTICALLY: bars filling the card.
 * There is no way to tell them apart, because the axis has no fixed scale. Anchoring the
 * grid to the requested window makes "you had no traffic for twenty-two hours" visible,
 * which is information a flight recorder should be showing, not suppressing.
 *
 * The gap-fill machinery was already correct and is untouched: traffic fills a missing
 * bucket with `0` (true — no requests), latency fills it with `null` (true — nothing was
 * measured; a `0` there would claim instant responses). That zero-vs-unknown split is
 * per-series and load-bearing.
 */
export interface ChartWindow {
	/** First bucket start (epoch ms), already floored to `bucketMs`. */
	startMs: number;
	/** Last bucket start (epoch ms), already floored to `bucketMs`. */
	endMs: number;
}

/**
 * The window a `?range=` preset asks the gateway for, expressed as bucket starts.
 *
 * `nowMs` is a parameter rather than a `Date.now()` call so this stays pure and the
 * tests can pin it. Both call sites are SERVER components (`app/dashboard/page.tsx`,
 * `app/slo/page.tsx` — neither carries `"use client"`, and neither does `Lollipop` or
 * `LatencyTimeline`), so there is no client re-render and no hydration split. That is
 * the hazard the traces-list ruler had to design around, and it does not apply here.
 */
export function chartWindow(
	nowMs: number,
	hours: number,
	bucketMs: number = HOUR_MS,
): ChartWindow {
	const endMs = Math.floor(nowMs / bucketMs) * bucketMs;
	const buckets = Math.max(1, Math.round((hours * HOUR_MS) / bucketMs));
	return { startMs: endMs - (buckets - 1) * bucketMs, endMs };
}

/**
 * Map the gateway's TRUE-quantile timeseries points (GET /v1/slo/timeseries) to
 * the chart's {@link LatencyPoint} shape. Each point already IS the exact merged
 * p50/p95/p99 for its display bucket — no client re-aggregation — so this only
 * formats the UTC bucket label (via {@link bucketLabel}, same axis format as the
 * traffic chart) and renames the `*_ms` fields. Replaces {@link buildLatencyPoints}
 * for any chart wired to the timeseries endpoint (provenance audit P2 #8).
 * `bucketMs` must match the `bucket` width requested from the gateway so the
 * label granularity (hour vs day) matches the data.
 */
export function latencyPointsFromTimeseries(
	points: SloTimePoint[],
	bucketMs: number,
	window: ChartWindow,
): LatencyPoint[] {
	// The gateway returns only buckets that HAD traffic. Rebuild the contiguous grid
	// and render a missing bucket as an explicit GAP (null percentiles, never
	// interpolated). A `0` here would be a claim of instant responses; `null` is the
	// truth, and `LatencyTimeline` already draws it as a gap.
	//
	// `window` is REQUIRED, not optional, and that is the fix rather than a detail. An
	// optional window means the defect stays reachable by omission — a new caller that
	// forgets it silently gets a data-derived domain under a "last N hours" heading, and
	// nothing goes red. Required makes the honest behaviour the only behaviour.
	const byBucket = new Map<number, SloTimePoint>();
	for (const p of points) {
		const epoch = parseBucketHour(p.bucket_start);
		if (epoch == null) continue;
		byBucket.set(Math.floor(epoch / bucketMs) * bucketMs, p);
	}
	const keys = [...byBucket.keys()].sort((a, b) => a - b);
	// ZERO ROWS SHORT-CIRCUITS, DELIBERATELY, EVEN WITH A WINDOW. "No data at all" and
	// "data with gaps" are different messages and must stay so: returning 24 null
	// buckets here would render an axis and an empty plot where the caller's own
	// empty state ("No latency data yet") is the honest surface.
	if (keys.length === 0) {
		return points.map((p) => ({
			label: p.bucket_start,
			p50: p.p50_ms,
			p95: p.p95_ms,
			p99: p.p99_ms,
		}));
	}
	const { startMs: min, endMs: max } = window;
	// Defensive bound. This is 24 / 28 / 30 buckets at the shipped
	// presets, so the cap finally guards something real (a malformed bucketMs) — under
	// the old data-derived bounds it could never bind at any preset, i.e. dead code.
	const len = Math.min(Math.round((max - min) / bucketMs) + 1, 48);
	const out: LatencyPoint[] = [];
	for (let i = 0; i < len; i++) {
		const key = min + i * bucketMs;
		const p = byBucket.get(key);
		out.push(
			p
				? {
						label: bucketLabel(key, bucketMs),
						p50: p.p50_ms,
						p95: p.p95_ms,
						p99: p.p99_ms,
					}
				: {
						label: bucketLabel(key, bucketMs),
						p50: null,
						p95: null,
						p99: null,
					},
		);
	}
	return out;
}

/** One hourly traffic bucket: total requests + the errored subset. */
export interface TrafficPoint {
	/** Bucket start epoch (ms) — a stable unique key across a multi-day window. */
	t: number;
	label: string;
	requests: number;
	errors: number;
}

/**
 * Collapse the per-(hour, provider, model) SLO rows into ONE requests/errors
 * total per hour, filling the contiguous hourly grid so a quiet hour is an honest
 * zero bar (never skipped). All real counts — nothing synthesized. Returns [] when
 * no bucket timestamp parses.
 */
export function buildTrafficPoints(
	rows: SloRow[],
	bucketMs: number,
	window: ChartWindow,
): TrafficPoint[] {
	const byBucket = new Map<number, { requests: number; errors: number }>();
	for (const r of rows) {
		const epoch = parseBucketHour(r.bucket_hour);
		if (epoch == null) continue;
		const key = Math.floor(epoch / bucketMs) * bucketMs;
		const cur = byBucket.get(key) ?? { requests: 0, errors: 0 };
		cur.requests += r.requests;
		cur.errors += r.errors;
		byBucket.set(key, cur);
	}
	const keys = [...byBucket.keys()].sort((a, b) => a - b);
	// ZERO ROWS SHORT-CIRCUITS EVEN WITH A WINDOW — see the note in
	// latencyPointsFromTimeseries. "No traffic at all" is the caller's empty state;
	// 24 zero-bars would be a different, and wrong, message.
	if (keys.length === 0) return [];
	const { startMs: min, endMs: max } = window;
	const len = Math.min(Math.round((max - min) / bucketMs) + 1, 48);
	const points: TrafficPoint[] = [];
	for (let i = 0; i < len; i++) {
		const key = min + i * bucketMs;
		const acc = byBucket.get(key);
		points.push({
			t: key,
			label: bucketLabel(key, bucketMs),
			requests: acc?.requests ?? 0,
			errors: acc?.errors ?? 0,
		});
	}
	return points;
}

/** Parse a ClickHouse `bucket_hour` (ISO, or "YYYY-MM-DD HH:MM:SS") to epoch ms. */
function parseBucketHour(s: string): number | null {
	// Anchor a zone-less ClickHouse "YYYY-MM-DD HH:MM:SS" to UTC (T + Z) before
	// parsing — otherwise Date.parse reads it in the SERVER's zone and the axis
	// label shifts by that offset (the naive-timestamp class; see parseUtcMs).
	const hasZone = /([zZ]|[+-]\d{2}:?\d{2})$/.test(s);
	const t = Date.parse(hasZone ? s : `${s.replace(" ", "T")}Z`);
	return Number.isNaN(t) ? null : t;
}

/**
 * Bucket axis label. Sub-day buckets show the hour ("14:00"); day-or-wider
 * buckets show the calendar day ("7/14") so a 30-day chart reads as dates.
 */
function bucketLabel(epoch: number, bucketMs: number): string {
	const d = new Date(epoch);
	// UTC getters ONLY — the app renders every timestamp in UTC (see
	// lib/format-date.ts). Local getters here rendered the axis in the SERVER's
	// zone, silently disagreeing with the UTC times in every table.
	if (bucketMs >= 86_400_000) return `${d.getUTCMonth() + 1}/${d.getUTCDate()}`;
	return `${String(d.getUTCHours()).padStart(2, "0")}:00`;
}

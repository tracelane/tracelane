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
	bucketMs: number = HOUR_MS,
): LatencyPoint[] {
	// The gateway returns only buckets that HAD traffic. Rebuild the contiguous
	// grid from the first to the last observed bucket and render a missing
	// interior bucket as an explicit GAP (null percentiles, never interpolated) —
	// the "gaps = no traffic" honesty the old client aggregation had, kept over the
	// true-quantile data. Falls back to a raw map if no bucket_start parses.
	const byBucket = new Map<number, SloTimePoint>();
	for (const p of points) {
		const epoch = parseBucketHour(p.bucket_start);
		if (epoch == null) continue;
		byBucket.set(Math.floor(epoch / bucketMs) * bucketMs, p);
	}
	const keys = [...byBucket.keys()].sort((a, b) => a - b);
	const min = keys[0];
	const max = keys[keys.length - 1];
	if (min === undefined || max === undefined) {
		return points.map((p) => ({
			label: p.bucket_start,
			p50: p.p50_ms,
			p95: p.p95_ms,
			p99: p.p99_ms,
		}));
	}
	// Defensive bound: the widest range yields ≤30 buckets; cap guards malformed ts.
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
	bucketMs: number = HOUR_MS,
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
	const min = keys[0];
	const max = keys[keys.length - 1];
	if (min === undefined || max === undefined) return [];
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

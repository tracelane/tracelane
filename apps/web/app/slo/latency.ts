/**
 * SLO time-series aggregation (backs the `<LatencyTimeline>` and `<TrafficTimeline>`
 * charts). Pure — type-only imports, no runtime deps — so it is unit-testable in
 * isolation and carries no Next route/page export constraints.
 */

import type { SloRow } from "@/app/slo/types";
import type { LatencyPoint } from "@tracelanedev/ui";

const HOUR_MS = 3_600_000;

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
	const direct = Date.parse(s);
	if (!Number.isNaN(direct)) return direct;
	const iso = Date.parse(s.replace(" ", "T"));
	return Number.isNaN(iso) ? null : iso;
}

/**
 * Bucket axis label. Sub-day buckets show the hour ("14:00"); day-or-wider
 * buckets show the calendar day ("7/14") so a 30-day chart reads as dates.
 */
function bucketLabel(epoch: number, bucketMs: number): string {
	const d = new Date(epoch);
	if (bucketMs >= 86_400_000) return `${d.getMonth() + 1}/${d.getDate()}`;
	return `${String(d.getHours()).padStart(2, "0")}:00`;
}

/**
 * Collapse the per-(hour, provider, model) SLO rows into ONE request-weighted
 * latency point per hour, then fill the contiguous hourly grid from the first to
 * the last observed bucket so hours with no traffic become explicit gaps (null)
 * — never interpolated. Returns [] when no bucket timestamp parses.
 *
 * Weighting: each hour's pXX is Σ(pXX·requests) / Σ(requests) across that hour's
 * provider/model series (real traffic weight); an hour with rows but zero
 * requests falls back to the unweighted mean. Percentiles are not exactly
 * additive across series — this weighted mean is the same documented
 * approximation the summary table uses, applied consistently to p50/p95/p99.
 */
export function buildLatencyPoints(
	rows: SloRow[],
	bucketMs: number = HOUR_MS,
): LatencyPoint[] {
	type Acc = {
		w: number;
		w50: number;
		w95: number;
		w99: number;
		n: number;
		u50: number;
		u95: number;
		u99: number;
	};
	const byHour = new Map<number, Acc>();
	for (const r of rows) {
		const epoch = parseBucketHour(r.bucket_hour);
		if (epoch == null) continue;
		const key = Math.floor(epoch / bucketMs) * bucketMs;
		const cur = byHour.get(key) ?? {
			w: 0,
			w50: 0,
			w95: 0,
			w99: 0,
			n: 0,
			u50: 0,
			u95: 0,
			u99: 0,
		};
		const w = r.requests > 0 ? r.requests : 0;
		cur.w += w;
		cur.w50 += r.p50_ms * w;
		cur.w95 += r.p95_ms * w;
		cur.w99 += r.p99_ms * w;
		cur.n += 1;
		cur.u50 += r.p50_ms;
		cur.u95 += r.p95_ms;
		cur.u99 += r.p99_ms;
		byHour.set(key, cur);
	}

	const keys = [...byHour.keys()].sort((a, b) => a - b);
	const min = keys[0];
	const max = keys[keys.length - 1];
	if (min === undefined || max === undefined) return [];

	// Defensive bound: the widest range yields ≤30 buckets; cap guards malformed ts.
	const len = Math.min(Math.round((max - min) / bucketMs) + 1, 48);
	const points: LatencyPoint[] = [];
	for (let i = 0; i < len; i++) {
		const key = min + i * bucketMs;
		const acc = byHour.get(key);
		if (!acc) {
			points.push({
				label: bucketLabel(key, bucketMs),
				p50: null,
				p95: null,
				p99: null,
			});
			continue;
		}
		const useW = acc.w > 0;
		points.push({
			label: bucketLabel(key, bucketMs),
			p50: useW ? acc.w50 / acc.w : acc.u50 / acc.n,
			p95: useW ? acc.w95 / acc.w : acc.u95 / acc.n,
			p99: useW ? acc.w99 / acc.w : acc.u99 / acc.n,
		});
	}
	return points;
}

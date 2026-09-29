/**
 * series — shape gateway rows onto the window's bucket grid (DSH-11 §3a.3).
 *
 * Every time series on every page is built here, from `bucketGrid`, so a spark
 * in a tile, the traffic chart under it and the latency chart beside it can never
 * disagree about what a bucket is. The two honesty rules the old builders carried
 * are kept and made explicit per series:
 *
 *   · a COUNT series fills a bucket with no rows as `0` — true: nothing happened;
 *   · a QUANTILE series fills it as `null` — true: nothing was measured, and a
 *     `0 ms` there would claim instant responses. The chart draws a gap.
 *
 * "No rows at all" is a different message from "rows with gaps" and stays so:
 * `hasData` is false when nothing landed in any bucket, and the caller renders
 * its own empty state instead of a zero-bar axis.
 */

import type { SloRow, SloTimePoint } from "@/app/slo/types";
import type { MetricKind } from "./format";
import { type GridBucket, type TimeRange, bucketGrid } from "./time-range";

export type SeriesTone = "data" | "second" | "danger" | "ok" | "warn";

export interface SeriesDef {
	id: string;
	label: string;
	kind: MetricKind;
	tone?: SeriesTone;
	/** Bars (counts) or a band/tick (quantiles). */
	mark?: "bar" | "band" | "tick" | "line" | "area";
	/** `true` for counts (an empty bucket is a measured zero), `false` for quantiles. */
	fillZero: boolean;
}

export interface ChartSeries extends SeriesDef {
	values: (number | null)[];
}

export interface ChartData {
	buckets: GridBucket[];
	series: ChartSeries[];
	/** Per-bucket sample size (requests), when known — the tooltip shows `n`. */
	n?: (number | null)[];
	/** False when no bucket received a row — render the empty state, not zeros. */
	hasData: boolean;
}

/** ClickHouse `toString(DateTime)` is naive UTC; ISO with a zone passes through. */
export function parseChTime(s: string): number | null {
	const hasZone = /([zZ]|[+-]\d{2}:?\d{2})$/.test(s);
	const t = Date.parse(hasZone ? s : `${s.replace(" ", "T")}Z`);
	return Number.isNaN(t) ? null : t;
}

/** Bucket index for an instant on the grid, or -1 when outside it. */
export function bucketIndex(grid: GridBucket[], tMs: number): number {
	if (grid.length === 0) return -1;
	const first = grid[0];
	if (!first) return -1;
	const bucketMs = first.tEnd - first.t;
	const i = Math.floor((tMs - first.t) / bucketMs);
	return i >= 0 && i < grid.length ? i : -1;
}

/**
 * Fold rows onto the grid. `timeOf` reads the row's bucket start; `pick` reads
 * each series' contribution. Counts are summed; quantiles take the row's value
 * (the gateway already merged per bucket, so one row per bucket per series).
 */
export function buildSeries<R>(
	r: Pick<TimeRange, "sinceMs" | "untilMs" | "bucketMs">,
	rows: readonly R[],
	timeOf: (row: R) => number | null,
	defs: readonly SeriesDef[],
	pick: (row: R, id: string) => number | null | undefined,
	nOf?: (row: R) => number,
): ChartData {
	const buckets = bucketGrid(r);
	const values: Record<string, (number | null)[]> = {};
	for (const d of defs) values[d.id] = buckets.map(() => null);
	const n: (number | null)[] = buckets.map(() => null);
	let hasData = false;
	for (const row of rows) {
		const t = timeOf(row);
		if (t === null) continue;
		const i = bucketIndex(buckets, t);
		if (i < 0) continue;
		hasData = true;
		for (const d of defs) {
			const v = pick(row, d.id);
			if (v == null || !Number.isFinite(v)) continue;
			const cur = values[d.id]?.[i] ?? null;
			const arr = values[d.id];
			if (!arr) continue;
			arr[i] = d.fillZero ? (cur ?? 0) + v : v;
		}
		if (nOf) n[i] = (n[i] ?? 0) + nOf(row);
	}
	const series: ChartSeries[] = defs.map((d) => ({
		...d,
		values: (values[d.id] ?? []).map((v) =>
			v === null && d.fillZero && hasData ? 0 : v,
		),
	}));
	return { buckets, series, n: nOf ? n : undefined, hasData };
}

/** `SloRow`s (per bucket × provider × model) → requests / errors / tokens per bucket. */
export function sloTrafficSeries(
	r: Pick<TimeRange, "sinceMs" | "untilMs" | "bucketMs">,
	rows: readonly SloRow[],
): ChartData {
	const llm = rows.filter((x) => x.provider !== "");
	return buildSeries(
		r,
		llm,
		(x) => parseChTime(x.bucket_hour),
		[
			{
				id: "requests",
				label: "requests",
				kind: "count",
				tone: "data",
				mark: "bar",
				fillZero: true,
			},
			{
				id: "errors",
				label: "errors",
				kind: "count",
				tone: "danger",
				mark: "bar",
				fillZero: true,
			},
			{
				id: "tokens",
				label: "tokens",
				kind: "tokens",
				tone: "second",
				mark: "bar",
				fillZero: true,
			},
		],
		(x, id) =>
			id === "requests"
				? x.requests
				: id === "errors"
					? x.errors
					: x.total_input_tokens + x.total_output_tokens,
		(x) => x.requests,
	);
}

/**
 * Narrow a `ChartData` to just the named series ids, same buckets/n/hasData.
 *
 * `sloTrafficSeries` always computes all three of requests/errors/tokens
 * together (one pass over the rows), but a single-metric tile — "Requests
 * per bucket", "Errors per bucket", "Tokens" (`traffic_series` /
 * `errors_series` / `tokens` in the registry) — must plot only the ONE
 * series it was configured for. Before this, a "requests" tile plotted
 * requests+errors+tokens on one linear axis; tokens is routinely 100-1000x
 * the request count, so requests and errors both read as a flat line at
 * zero (item 7, 2026-09-27 audit).
 */
export function pickSeries(data: ChartData, ids: readonly string[]): ChartData {
	return {
		buckets: data.buckets,
		series: data.series.filter((s) => ids.includes(s.id)),
		n: data.n,
		hasData: data.hasData,
	};
}

/** `SloTimePoint`s (one merged row per bucket) → p50 / p95 / p99 per bucket. */
export function sloLatencySeries(
	r: Pick<TimeRange, "sinceMs" | "untilMs" | "bucketMs">,
	points: readonly SloTimePoint[],
): ChartData {
	return buildSeries(
		r,
		points,
		(p) => parseChTime(p.bucket_start),
		[
			{
				id: "p50",
				label: "p50",
				kind: "duration_ms",
				tone: "second",
				mark: "line",
				fillZero: false,
			},
			{
				// DSH-14 (founder 2026-09-04): quantiles draw as LINES — p95 with a
				// soft area under it — the way every latency chart a reader has seen
				// draws them. Bars stay for counts (`trafficSeries`).
				id: "p95",
				label: "p95",
				kind: "duration_ms",
				tone: "data",
				mark: "area",
				fillZero: false,
			},
			{
				id: "p99",
				label: "p99",
				kind: "duration_ms",
				tone: "second",
				mark: "line",
				fillZero: false,
			},
		],
		(p, id) => (id === "p50" ? p.p50_ms : id === "p95" ? p.p95_ms : p.p99_ms),
		(p) => p.requests,
	);
}

/**
 * `SloRow`s → error rate (%) per bucket = errors/requests × 100. B-504 / CX-05:
 * the picker offered `error_rate` as a series (the registry's `kind: "percent"`
 * promises a ratio) but no percent series existed anywhere in this file —
 * `fetchSeriesData` fell through to `sloTrafficSeries`, which draws three COUNT
 * series (requests / errors / tokens) under the "Error rate" title with no
 * ratio drawn at all.
 *
 * Folds through `sloTrafficSeries` (same LLM-only filter, same bucket sums) and
 * derives the ratio from its two count series, so this can never disagree with
 * the traffic chart about what a bucket's requests/errors are.
 *
 * `null` when a bucket had NO requests — the file's own quantile rule (:9-11):
 * a bucket nothing happened in is a GAP, not a false 0%. A bucket with
 * requests but zero errors is a true, drawn 0%.
 */
export function sloErrorRateSeries(
	r: Pick<TimeRange, "sinceMs" | "untilMs" | "bucketMs">,
	rows: readonly SloRow[],
): ChartData {
	const traffic = sloTrafficSeries(r, rows);
	const requests = traffic.series.find((s) => s.id === "requests");
	const errors = traffic.series.find((s) => s.id === "errors");
	const values = traffic.buckets.map((_, i) => {
		const req = requests?.values[i] ?? 0;
		if (!req) return null;
		const err = errors?.values[i] ?? 0;
		return (err / req) * 100;
	});
	return {
		buckets: traffic.buckets,
		series: [
			{
				id: "error_rate",
				label: "error rate",
				kind: "percent",
				tone: "danger",
				mark: "line",
				fillZero: false,
				values,
			},
		],
		n: traffic.n,
		hasData: traffic.hasData,
	};
}

/** One series' values as a spark (nulls → 0) — for `StatCard.spark`. */
export function sparkOf(data: ChartData, id: string): number[] | undefined {
	if (!data.hasData) return undefined;
	const s = data.series.find((x) => x.id === id);
	return s ? s.values.map((v) => v ?? 0) : undefined;
}

/** How many buckets carry a measurement — a chart needs at least two. */
export function drawableBuckets(data: ChartData, id: string): number {
	const s = data.series.find((x) => x.id === id);
	return s ? s.values.filter((v) => v !== null).length : 0;
}

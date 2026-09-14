import { describe, expect, it } from "vitest";
import {
	bucketIndex,
	drawableBuckets,
	parseChTime,
	sloLatencySeries,
	sloTrafficSeries,
	sparkOf,
} from "./series";
import { bucketGrid, parseTimeRange } from "./time-range";

const H = 3_600_000;
const NOW = Date.parse("2026-09-02T00:00:00Z");
const range = parseTimeRange(
	{ since: "2026-09-01T00:00:00Z", until: "2026-09-01T06:00:00Z" },
	{ defaultPreset: "24h", nowMs: NOW, bucketFloorMs: H },
);

const row = (hour: number, provider: string, requests: number, errors = 0) => ({
	bucket_hour: `2026-09-01 0${hour}:00:00`,
	provider,
	model: "m",
	p50_ms: 10,
	p95_ms: 20,
	p99_ms: 30,
	requests,
	errors,
	error_rate_pct: 0,
	total_input_tokens: requests * 10,
	total_output_tokens: requests * 5,
});

describe("series — the grid is the window, not the data", () => {
	it("a 6 h window at 1 h is six buckets whatever the rows say", () => {
		expect(range.bucketMs).toBe(H);
		const d = sloTrafficSeries(range, [
			row(1, "openai", 5),
			row(4, "openai", 7),
		]);
		expect(d.buckets).toHaveLength(6);
		const req = d.series.find((s) => s.id === "requests");
		// counts: a quiet hour is a MEASURED zero
		expect(req?.values).toEqual([0, 5, 0, 0, 7, 0]);
		expect(d.hasData).toBe(true);
		expect(d.n).toEqual([null, 5, null, null, 7, null]);
	});

	it("sums provider × model rows into one bucket and drops the non-LLM group", () => {
		const d = sloTrafficSeries(range, [
			row(2, "openai", 3, 1),
			row(2, "anthropic", 4),
			row(2, "", 99), // tool/child spans — never counted as LLM calls
		]);
		expect(d.series.find((s) => s.id === "requests")?.values[2]).toBe(7);
		expect(d.series.find((s) => s.id === "errors")?.values[2]).toBe(1);
		expect(d.series.find((s) => s.id === "tokens")?.values[2]).toBe(7 * 15);
	});

	it("no rows → hasData false and no zero bars (the caller's empty state)", () => {
		const d = sloTrafficSeries(range, []);
		expect(d.hasData).toBe(false);
		expect(d.series[0]?.values.every((v) => v === null)).toBe(true);
		expect(sparkOf(d, "requests")).toBeUndefined();
	});

	it("quantiles leave a GAP (null), never a zero", () => {
		const d = sloLatencySeries(range, [
			{
				bucket_start: "2026-09-01 01:00:00",
				p50_ms: 100,
				p95_ms: 200,
				p99_ms: 300,
				requests: 9,
			},
			{
				bucket_start: "2026-09-01 03:00:00",
				p50_ms: 110,
				p95_ms: 210,
				p99_ms: 310,
				requests: 2,
			},
		]);
		const p95 = d.series.find((s) => s.id === "p95");
		expect(p95?.values).toEqual([null, 200, null, 210, null, null]);
		expect(drawableBuckets(d, "p95")).toBe(2);
	});

	it("rows outside the window are ignored; naive ClickHouse times are UTC", () => {
		const d = sloTrafficSeries(range, [row(7, "openai", 50)]);
		expect(d.hasData).toBe(false);
		expect(parseChTime("2026-09-01 03:00:00")).toBe(
			Date.parse("2026-09-01T03:00:00Z"),
		);
		expect(parseChTime("garbage")).toBeNull();
	});

	it("bucketIndex maps an instant to its grid slot", () => {
		const g = bucketGrid(range);
		expect(bucketIndex(g, Date.parse("2026-09-01T02:59:59Z"))).toBe(2);
		expect(bucketIndex(g, Date.parse("2026-09-01T06:00:00Z"))).toBe(-1);
		expect(bucketIndex([], 0)).toBe(-1);
	});
});

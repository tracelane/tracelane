/**
 * Tests for `latencyPointsFromTimeseries` (backs the dashboard + SLO
 * `<LatencyTimeline>`).
 *
 * The gateway now returns the TRUE per-bucket merged quantiles
 * (`/v1/slo/timeseries`), so this mapper only formats the UTC axis label and
 * renames the `*_ms` fields — no client re-aggregation. Locks: (1) an
 * unparseable bucket_start falls back to the raw string label (never throws),
 * (2) the percentile values pass through verbatim, (3) day-wide buckets label as
 * a UTC calendar day, hour buckets as a UTC hour. Negative case first per
 * `.claude/rules/testing.md`.
 */

import type { SloTimePoint } from "@/app/slo/types";
import { describe, expect, it } from "vitest";
import { latencyPointsFromTimeseries } from "./latency";

const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;

function pt(over: Partial<SloTimePoint>): SloTimePoint {
	return {
		bucket_start: "2026-06-18 14:00:00",
		p50_ms: 50,
		p95_ms: 100,
		p99_ms: 200,
		requests: 5,
		...over,
	};
}

describe("latencyPointsFromTimeseries", () => {
	it("REJECT: no points → []", () => {
		expect(latencyPointsFromTimeseries([])).toEqual([]);
	});

	it("PASS-THROUGH: percentiles map verbatim (no re-aggregation)", () => {
		const pts = latencyPointsFromTimeseries(
			[pt({ p50_ms: 8, p95_ms: 10196, p99_ms: 20000 })],
			HOUR_MS,
		);
		expect(pts).toHaveLength(1);
		expect(pts[0]?.p50).toBe(8);
		expect(pts[0]?.p95).toBe(10196);
		expect(pts[0]?.p99).toBe(20000);
	});

	it("LABEL: hour buckets show the UTC hour, not the server zone", () => {
		const pts = latencyPointsFromTimeseries(
			[pt({ bucket_start: "2026-06-18 14:00:00" })],
			HOUR_MS,
		);
		expect(pts[0]?.label).toBe("14:00");
	});

	it("LABEL: day-wide buckets show the UTC calendar day", () => {
		const pts = latencyPointsFromTimeseries(
			[pt({ bucket_start: "2026-06-18 00:00:00" })],
			DAY_MS,
		);
		expect(pts[0]?.label).toBe("6/18");
	});

	it("FALLBACK: an unparseable bucket_start uses the raw string (never throws)", () => {
		const pts = latencyPointsFromTimeseries([
			pt({ bucket_start: "not-a-date" }),
		]);
		expect(pts[0]?.label).toBe("not-a-date");
		expect(pts[0]?.p95).toBe(100);
	});

	it("GAP: a missing interior bucket renders as null, never interpolated", () => {
		// Buckets 00 and 02 present, 01 absent (no traffic) — passed out of order.
		const pts = latencyPointsFromTimeseries(
			[
				pt({ bucket_start: "2026-06-18 02:00:00", p95_ms: 300 }),
				pt({ bucket_start: "2026-06-18 00:00:00", p95_ms: 100 }),
			],
			HOUR_MS,
		);
		expect(pts).toHaveLength(3); // contiguous grid 00,01,02 oldest→newest
		expect(pts[0]?.p95).toBe(100);
		expect(pts[1]?.p50).toBeNull();
		expect(pts[1]?.p95).toBeNull();
		expect(pts[1]?.p99).toBeNull();
		expect(pts[2]?.p95).toBe(300);
	});
});

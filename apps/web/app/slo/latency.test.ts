/**
 * Tests for `latencyPointsFromTimeseries` (backs the dashboard + SLO
 * `<LatencyTimeline>`).
 *
 * The gateway returns the TRUE per-bucket merged quantiles (`/v1/slo/timeseries`), so
 * this mapper only formats the UTC axis label and renames the `*_ms` fields — no client
 * re-aggregation. Negative case first per `.claude/rules/testing.md`.
 *
 * ── WHAT CHANGED IN THIS FILE, AND WHY IT IS NOT A TIDY-UP (R59, 2026-08-16) ────────
 * Several assertions here WERE THE DEFECT, WRITTEN DOWN. They are named so nobody
 * restores them believing they were coverage:
 *
 *   · `expect(pts).toHaveLength(1)` on a single input point
 *   · `expect(pts).toHaveLength(3)` with the comment
 *     "contiguous grid 00,01,02 oldest→newest"
 *   · every `pts[0]?.label` that assumed the first OUTPUT point is the first INPUT point
 *
 * Each one asserted that the chart's domain is the extent of the DATA. That is exactly
 * what made "Traffic over time — last 24 hours" a claim the chart could not support: a
 * tenant with two hours of traffic got two buckets stretched across the card under a
 * heading saying twenty-four. The tests were green the whole time, because they were
 * asserting the behaviour rather than the requirement.
 *
 * The grid is now the REQUESTED window, and these assert that instead — including the
 * case the old shape could never express: a bucket BEFORE the first observation and
 * AFTER the last one must still render, as a gap.
 */

import type { SloTimePoint } from "@/app/slo/types";
import { describe, expect, it } from "vitest";
import { chartWindow, latencyPointsFromTimeseries } from "./latency";

const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;

/** 2026-06-18 14:00:00Z — the hour every fixture below sits in. */
const T14 = Date.UTC(2026, 5, 18, 14, 0, 0);
/** A 1-hour window containing exactly that bucket, for the pass-through cases. */
const W1 = { startMs: T14, endMs: T14 };

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

describe("chartWindow", () => {
	it("spans exactly the requested hours, bucket-aligned, ending at the current bucket", () => {
		// 24h of 1h buckets = 24 buckets, so the first starts 23 hours before the last.
		const now = Date.UTC(2026, 5, 18, 14, 37, 12); // deliberately mid-bucket
		const w = chartWindow(now, 24, HOUR_MS);
		expect(w.endMs).toBe(Date.UTC(2026, 5, 18, 14, 0, 0)); // floored, not rounded up
		expect(w.startMs).toBe(Date.UTC(2026, 5, 17, 15, 0, 0));
		expect((w.endMs - w.startMs) / HOUR_MS + 1).toBe(24);
	});

	it("gives 28 buckets at 7d/6h and 30 at 30d/1d — all under the 48 cap", () => {
		const now = Date.UTC(2026, 5, 18, 14, 0, 0);
		const w7 = chartWindow(now, 168, 6 * HOUR_MS);
		const w30 = chartWindow(now, 720, DAY_MS);
		expect((w7.endMs - w7.startMs) / (6 * HOUR_MS) + 1).toBe(28);
		expect((w30.endMs - w30.startMs) / DAY_MS + 1).toBe(30);
	});

	it("is pure — nowMs is a parameter, so the same input gives the same window", () => {
		const now = Date.UTC(2026, 5, 18, 14, 37, 12);
		expect(chartWindow(now, 24, HOUR_MS)).toEqual(
			chartWindow(now, 24, HOUR_MS),
		);
	});
});

describe("latencyPointsFromTimeseries", () => {
	it("REJECT: no points → []", () => {
		expect(latencyPointsFromTimeseries([], HOUR_MS, W1)).toEqual([]);
	});

	it("ZERO ROWS SHORT-CIRCUIT: an empty window is NOT filled with nulls", () => {
		// "No data at all" and "data with gaps" must stay different messages. A 24-bucket
		// all-null series would render an axis and an empty plot where the caller's own
		// "No latency data yet" empty state is the honest surface.
		const wide = chartWindow(T14, 24, HOUR_MS);
		expect(latencyPointsFromTimeseries([], HOUR_MS, wide)).toEqual([]);
	});

	it("PASS-THROUGH: percentiles map verbatim (no re-aggregation)", () => {
		const pts = latencyPointsFromTimeseries(
			[pt({ p50_ms: 8, p95_ms: 10196, p99_ms: 20000 })],
			HOUR_MS,
			W1,
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
			W1,
		);
		expect(pts[0]?.label).toBe("14:00");
	});

	it("LABEL: day-wide buckets show the UTC calendar day", () => {
		const day = Date.UTC(2026, 5, 18, 0, 0, 0);
		const pts = latencyPointsFromTimeseries(
			[pt({ bucket_start: "2026-06-18 00:00:00" })],
			DAY_MS,
			{ startMs: day, endMs: day },
		);
		expect(pts[0]?.label).toBe("6/18");
	});

	it("FALLBACK: an unparseable bucket_start uses the raw string (never throws)", () => {
		const pts = latencyPointsFromTimeseries(
			[pt({ bucket_start: "not-a-date" })],
			HOUR_MS,
			W1,
		);
		expect(pts[0]?.label).toBe("not-a-date");
		expect(pts[0]?.p95).toBe(100);
	});

	it("GAP: a missing INTERIOR bucket renders as null, never interpolated", () => {
		// Buckets 00 and 02 present, 01 absent (no traffic) — passed out of order.
		const t0 = Date.UTC(2026, 5, 18, 0, 0, 0);
		const pts = latencyPointsFromTimeseries(
			[
				pt({ bucket_start: "2026-06-18 02:00:00", p95_ms: 300 }),
				pt({ bucket_start: "2026-06-18 00:00:00", p95_ms: 100 }),
			],
			HOUR_MS,
			{ startMs: t0, endMs: t0 + 2 * HOUR_MS },
		);
		expect(pts).toHaveLength(3);
		expect(pts[0]?.p95).toBe(100);
		expect(pts[1]?.p50).toBeNull();
		expect(pts[1]?.p95).toBeNull();
		expect(pts[1]?.p99).toBeNull();
		expect(pts[2]?.p95).toBe(300);
	});

	it("THE FIX: buckets BEFORE the first observation and AFTER the last still render", () => {
		// THE ASSERTION THE OLD SHAPE COULD NOT EXPRESS, and the reason for R59. One hour
		// of traffic inside a 24-hour window must produce 24 buckets — 23 of them gaps —
		// not one bucket stretched across the card under a "last 24 hours" heading.
		//
		// This is also the product point: with a data-derived domain, steady traffic all
		// day and a single burst render identically. Here they cannot.
		const w = chartWindow(T14, 24, HOUR_MS);
		const pts = latencyPointsFromTimeseries(
			[pt({ bucket_start: "2026-06-18 14:00:00", p95_ms: 100 })],
			HOUR_MS,
			w,
		);
		expect(pts).toHaveLength(24);
		// The single observation lands in the LAST bucket, not the first.
		expect(pts.at(-1)?.p95).toBe(100);
		expect(pts[0]?.p95).toBeNull();
		expect(pts.filter((p) => p.p95 == null)).toHaveLength(23);
	});

	it("THE FIX: the window, not the data, sets the first label", () => {
		// Under the old bounds the first label was always the first OBSERVED bucket.
		const w = chartWindow(T14, 24, HOUR_MS);
		const pts = latencyPointsFromTimeseries(
			[pt({ bucket_start: "2026-06-18 14:00:00" })],
			HOUR_MS,
			w,
		);
		expect(pts[0]?.label).toBe("15:00"); // 23h before 14:00 the next day
		expect(pts.at(-1)?.label).toBe("14:00");
	});
});

/**
 * Tests for `buildLatencyPoints` (backs the SLO `<LatencyTimeline>`).
 *
 * Locks the two honesty properties the chart depends on: (1) a missing interior
 * hour is an explicit GAP — null percentiles, never interpolated — and (2) each
 * hour's percentile is a real request-weighted mean of that hour's series, not a
 * fabricated constant. Negative cases first per `.claude/rules/testing.md`.
 */

import type { SloRow } from "@/app/slo/types";
import { describe, expect, it } from "vitest";
import { buildLatencyPoints } from "./latency";

function row(over: Partial<SloRow>): SloRow {
	return {
		bucket_hour: "2026-06-18T00:00:00Z",
		provider: "openai",
		model: "gpt-4o",
		p50_ms: 50,
		p95_ms: 100,
		p99_ms: 200,
		requests: 1,
		errors: 0,
		error_rate_pct: 0,
		total_input_tokens: 0,
		total_output_tokens: 0,
		...over,
	};
}

describe("buildLatencyPoints", () => {
	it("REJECT: no rows → []", () => {
		expect(buildLatencyPoints([])).toEqual([]);
	});

	it("REJECT: unparseable bucket_hour → [] (no fabricated axis)", () => {
		expect(buildLatencyPoints([row({ bucket_hour: "not-a-date" })])).toEqual(
			[],
		);
	});

	it("GAP: a missing interior hour renders as null, never interpolated", () => {
		// Hours 00 and 02 present, 01 absent — and passed out of order.
		const pts = buildLatencyPoints([
			row({ bucket_hour: "2026-06-18T02:00:00Z", p95_ms: 300, requests: 5 }),
			row({ bucket_hour: "2026-06-18T00:00:00Z", p95_ms: 100, requests: 5 }),
		]);
		expect(pts).toHaveLength(3); // contiguous grid 00,01,02 — oldest→newest
		expect(pts[0]?.p95).toBe(100);
		// The gap hour: all percentiles null (not a smoothed midpoint of 100↔300).
		expect(pts[1]?.p50).toBeNull();
		expect(pts[1]?.p95).toBeNull();
		expect(pts[1]?.p99).toBeNull();
		expect(pts[2]?.p95).toBe(300);
	});

	it("WEIGHT: a bucket's pXX is request-weighted across its series", () => {
		// (100ms × 10 req) + (200ms × 30 req) ÷ 40 req = 175ms — not the 150 mean.
		const pts = buildLatencyPoints([
			row({ p95_ms: 100, requests: 10 }),
			row({ p95_ms: 200, requests: 30, model: "gpt-4o-mini" }),
		]);
		expect(pts).toHaveLength(1);
		expect(pts[0]?.p95).toBe(175);
	});

	it("FALLBACK: an hour with zero requests uses the unweighted mean", () => {
		const pts = buildLatencyPoints([
			row({ p95_ms: 100, requests: 0 }),
			row({ p95_ms: 200, requests: 0, model: "gpt-4o-mini" }),
		]);
		expect(pts[0]?.p95).toBe(150);
	});
});

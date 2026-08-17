import type { SloRow } from "@/app/slo/types";
import { describe, expect, it } from "vitest";
import { buildTrafficPoints, chartWindow } from "./latency";

/**
 * ── WHAT CHANGED, AND WHY IT IS NOT A TIDY-UP (R59, 2026-08-16) ────────────────────
 * Every `toHaveLength` below WAS THE DEFECT, WRITTEN DOWN. `toHaveLength(2)` for two
 * observed hours and `toHaveLength(3)` for "contiguous grid" both asserted that the
 * chart's domain is the extent of the DATA — which is precisely what made
 * "Traffic over time — last 24 hours" a claim the chart could not support. They were
 * green throughout, because they asserted the behaviour instead of the requirement.
 *
 * The grid is now the REQUESTED window. These assert that, plus the case the old shape
 * could not express: quiet hours OUTSIDE the observed range must still render as zero
 * bars, because "you had no traffic for twenty-two hours" is the information a flight
 * recorder should show and a data-derived domain hides it.
 */

const HOUR = 3_600_000;

/** A window covering exactly the buckets a fixture observes, for the sum/label cases. */
const spanning = (startIso: string, endIso: string, bucketMs = HOUR) => ({
	startMs: Math.floor(Date.parse(startIso) / bucketMs) * bucketMs,
	endMs: Math.floor(Date.parse(endIso) / bucketMs) * bucketMs,
});

function row(p: Partial<SloRow> & { bucket_hour: string }): SloRow {
	return {
		provider: "openai",
		model: "gpt-4o",
		p50_ms: 100,
		p95_ms: 200,
		p99_ms: 300,
		requests: 0,
		errors: 0,
		error_rate_pct: 0,
		total_input_tokens: 0,
		total_output_tokens: 0,
		...p,
	};
}

describe("buildTrafficPoints", () => {
	it("sums requests/errors per hour across provider+model series", () => {
		const pts = buildTrafficPoints(
			[
				row({ bucket_hour: "2026-07-10 10:00:00", requests: 30, errors: 1 }),
				row({
					bucket_hour: "2026-07-10 10:00:00",
					model: "claude-sonnet",
					requests: 20,
					errors: 4,
				}),
				row({ bucket_hour: "2026-07-10 11:00:00", requests: 10, errors: 0 }),
			],
			HOUR,
			spanning("2026-07-10T10:00:00Z", "2026-07-10T11:00:00Z"),
		);
		expect(pts).toHaveLength(2);
		expect(pts[0]).toMatchObject({ requests: 50, errors: 5 });
		expect(pts[1]).toMatchObject({ requests: 10, errors: 0 });
	});

	it("fills quiet hours as honest zero bars (contiguous grid)", () => {
		const pts = buildTrafficPoints(
			[
				row({ bucket_hour: "2026-07-10 10:00:00", requests: 5 }),
				// skip 11:00
				row({ bucket_hour: "2026-07-10 12:00:00", requests: 7 }),
			],
			HOUR,
			spanning("2026-07-10T10:00:00Z", "2026-07-10T12:00:00Z"),
		);
		expect(pts).toHaveLength(3);
		expect(pts[1]).toMatchObject({ requests: 0, errors: 0 });
	});

	it("returns [] when no bucket timestamp parses", () => {
		expect(
			buildTrafficPoints(
				[row({ bucket_hour: "not-a-date" })],
				HOUR,
				spanning("2026-07-10T10:00:00Z", "2026-07-10T11:00:00Z"),
			),
		).toEqual([]);
	});

	it("collapses hourly rows into wider buckets (7d → 6h)", () => {
		const SIX_H = 21_600_000;
		const pts = buildTrafficPoints(
			[
				// three hours inside the same 6h bucket (00:00–06:00 UTC)
				row({ bucket_hour: "2026-07-10T00:00:00Z", requests: 4, errors: 1 }),
				row({ bucket_hour: "2026-07-10T02:00:00Z", requests: 6, errors: 0 }),
				row({ bucket_hour: "2026-07-10T05:00:00Z", requests: 5, errors: 2 }),
				// next 6h bucket
				row({ bucket_hour: "2026-07-10T07:00:00Z", requests: 9, errors: 0 }),
			],
			SIX_H,
			spanning("2026-07-10T00:00:00Z", "2026-07-10T07:00:00Z", SIX_H),
		);
		expect(pts).toHaveLength(2);
		expect(pts[0]).toMatchObject({ requests: 15, errors: 3 });
		expect(pts[1]).toMatchObject({ requests: 9, errors: 0 });
	});

	it("THE FIX: quiet hours OUTSIDE the observed range still render as zero bars", () => {
		// THE ASSERTION THE OLD SHAPE COULD NOT EXPRESS. One busy hour inside a 24-hour
		// window is 24 bars, 23 of them zero — not one bar filling the card under a
		// heading claiming twenty-four hours. This is the difference between "steady all
		// day" and "one 4am burst", which the old domain rendered identically.
		const now = Date.parse("2026-07-10T23:00:00Z");
		const pts = buildTrafficPoints(
			[row({ bucket_hour: "2026-07-10T23:00:00Z", requests: 42 })],
			HOUR,
			chartWindow(now, 24, HOUR),
		);
		expect(pts).toHaveLength(24);
		expect(pts.at(-1)).toMatchObject({ requests: 42 });
		expect(pts.filter((p) => p.requests === 0)).toHaveLength(23);
	});

	it("ZERO ROWS SHORT-CIRCUIT: an empty window is NOT filled with zero bars", () => {
		// "No traffic at all" is the caller's empty state; 24 zero bars is a different
		// and wrong message. Kept deliberately (founder ruling, R59).
		const now = Date.parse("2026-07-10T23:00:00Z");
		expect(buildTrafficPoints([], HOUR, chartWindow(now, 24, HOUR))).toEqual(
			[],
		);
	});

	it("labels day-wide buckets as calendar days (30d → 1d)", () => {
		const DAY = 86_400_000;
		const pts = buildTrafficPoints(
			[row({ bucket_hour: "2026-07-14T13:00:00Z", requests: 3 })],
			DAY,
			spanning("2026-07-14T13:00:00Z", "2026-07-14T13:00:00Z", DAY),
		);
		expect(pts).toHaveLength(1);
		expect(pts[0]?.label).toMatch(/^7\/1[45]$/); // 7/14 (or 7/15 across TZ)
	});
});

import type { SloRow } from "@/app/slo/types";
import { describe, expect, it } from "vitest";
import { buildTrafficPoints } from "./latency";

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
		const pts = buildTrafficPoints([
			row({ bucket_hour: "2026-07-10 10:00:00", requests: 30, errors: 1 }),
			row({
				bucket_hour: "2026-07-10 10:00:00",
				model: "claude-sonnet",
				requests: 20,
				errors: 4,
			}),
			row({ bucket_hour: "2026-07-10 11:00:00", requests: 10, errors: 0 }),
		]);
		expect(pts).toHaveLength(2);
		expect(pts[0]).toMatchObject({ requests: 50, errors: 5 });
		expect(pts[1]).toMatchObject({ requests: 10, errors: 0 });
	});

	it("fills quiet hours as honest zero bars (contiguous grid)", () => {
		const pts = buildTrafficPoints([
			row({ bucket_hour: "2026-07-10 10:00:00", requests: 5 }),
			// skip 11:00
			row({ bucket_hour: "2026-07-10 12:00:00", requests: 7 }),
		]);
		expect(pts).toHaveLength(3);
		expect(pts[1]).toMatchObject({ requests: 0, errors: 0 });
	});

	it("returns [] when no bucket timestamp parses", () => {
		expect(buildTrafficPoints([row({ bucket_hour: "not-a-date" })])).toEqual(
			[],
		);
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
		);
		expect(pts).toHaveLength(2);
		expect(pts[0]).toMatchObject({ requests: 15, errors: 3 });
		expect(pts[1]).toMatchObject({ requests: 9, errors: 0 });
	});

	it("labels day-wide buckets as calendar days (30d → 1d)", () => {
		const DAY = 86_400_000;
		const pts = buildTrafficPoints(
			[row({ bucket_hour: "2026-07-14T13:00:00Z", requests: 3 })],
			DAY,
		);
		expect(pts).toHaveLength(1);
		expect(pts[0]?.label).toMatch(/^7\/1[45]$/); // 7/14 (or 7/15 across TZ)
	});
});

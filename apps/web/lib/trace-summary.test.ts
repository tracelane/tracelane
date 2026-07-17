import type { Span } from "@/components/trace-viewer/types";
import { describe, expect, it } from "vitest";
import { computeTraceSummary, traceTimeBounds } from "./trace-summary";

function span(p: Partial<Span> & { span_id: string }): Span {
	return {
		parent_span_id: null,
		name: "s",
		start_time: "2026-07-10 12:00:00.000000",
		end_time: "2026-07-10 12:00:01.000000",
		start_time_us: 1_000_000,
		duration_us: 1_000_000,
		status_code: 1,
		status_message: "",
		attributes: "{}",
		aft_ids: [],
		intervention: 0,
		...p,
	};
}

describe("computeTraceSummary", () => {
	it("sums real tokens/cost and leaves absent metrics undefined (never a fabricated 0)", () => {
		const spans = [
			span({
				span_id: "a",
				start_time_us: 1_000_000,
				duration_us: 500_000,
				attributes: JSON.stringify({
					gen_ai_usage_input_tokens: 100,
					gen_ai_usage_output_tokens: 40,
					gen_ai_usage_cost: 0.002,
					gen_ai_response_model: "gpt-4o",
					gen_ai_system: "openai",
				}),
			}),
			// A span with NO usage attrs — must not zero-out the totals nor invent cost.
			span({ span_id: "b", start_time_us: 1_500_000, duration_us: 300_000 }),
		];
		const s = computeTraceSummary(spans);
		expect(s.spanCount).toBe(2);
		expect(s.inputTokens).toBe(100);
		expect(s.outputTokens).toBe(40);
		expect(s.cost).toBeCloseTo(0.002);
		expect(s.models).toEqual(["gpt-4o"]);
		expect(s.providers).toEqual(["openai"]);
	});

	it("returns undefined cost/tokens when NO span reported them", () => {
		const s = computeTraceSummary([span({ span_id: "x" })]);
		expect(s.cost).toBeUndefined();
		expect(s.inputTokens).toBeUndefined();
		expect(s.totalTokens).toBeUndefined();
	});

	it("counts errors + interventions and spans the full wall-clock window", () => {
		const spans = [
			span({
				span_id: "root",
				start_time_us: 1_000_000,
				duration_us: 2_000_000,
			}),
			span({
				span_id: "err",
				start_time_us: 2_500_000,
				duration_us: 1_000_000, // ends at 3.5s
				status_code: 2,
				intervention: 2,
			}),
		];
		const s = computeTraceSummary(spans);
		expect(s.errorCount).toBe(1);
		expect(s.interventionCount).toBe(1);
		const { startUs, endUs } = traceTimeBounds(spans);
		expect(startUs).toBe(1_000_000);
		expect(endUs).toBe(3_500_000);
		expect(s.totalDurationUs).toBe(2_500_000);
	});
});

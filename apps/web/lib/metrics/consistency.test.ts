import { describe, expect, it } from "vitest";
import { fmtPercent } from "./format";
import { sloHeadline } from "./tiles";

/**
 * Same metric + same window + same tenant = same number on every page (DSH-11 §3c).
 * The dashboard and /slo both render the SLO headline through `sloHeadline`; this
 * proves the function is deterministic over one fixture, and that the OLD page-local
 * formatting (3 dp availability, 2 dp error rate, no floor) would have DIFFERED —
 * i.e. the shared function is doing work, not merely existing.
 */
const fixture = {
	summary: { p50_ms: 100, p95_ms: 200, p99_ms: 300, requests: 70, errors: 1 },
	fallback: { requests: 70, errors: 1 },
	target: 0.999,
	unreachable: false,
};

describe("consistency — one headline for every page", () => {
	it("two pages calling with the same inputs get byte-identical strings", () => {
		const dashboard = sloHeadline(fixture);
		const slo = sloHeadline({ ...fixture });
		expect(slo.llmCalls).toBe(dashboard.llmCalls);
		expect(slo.errorRate.text).toBe(dashboard.errorRate.text);
		expect(slo.availability.text).toBe(dashboard.availability.text);
		expect(slo.budget).toEqual(dashboard.budget);
	});

	it("a planted page-local formatter DIVERGES — which is what the guard forbids", () => {
		const shared = sloHeadline(fixture);
		// The pre-DSH-11 dashboard: `budget.availabilityPct.toFixed(3)` with no floor.
		const planted = `${shared.budget.availabilityPct.toFixed(3)}%`;
		expect(planted).toBe("98.571%");
		expect(shared.availability.text).toBe("98.6%");
		expect(shared.availability.belowFloor).toBe(true);
		expect(planted).not.toBe(shared.availability.text);
	});

	it("the summary route is the source; rows are only the fallback", () => {
		const withSummary = sloHeadline({
			...fixture,
			fallback: { requests: 999, errors: 9 },
		});
		expect(withSummary.requests).toBe(70);
		expect(withSummary.fromFallback).toBe(false);
		const noSummary = sloHeadline({ ...fixture, summary: null });
		expect(noSummary.requests).toBe(70);
		expect(noSummary.fromFallback).toBe(true);
	});

	it("unreachable renders dashes, zero traffic renders no sample — never 100%", () => {
		const down = sloHeadline({ ...fixture, unreachable: true });
		expect(down.llmCalls).toBe("—");
		expect(down.availability.belowFloor).toBe(false);
		const quiet = sloHeadline({
			summary: { p50_ms: 0, p95_ms: 0, p99_ms: 0, requests: 0, errors: 0 },
			fallback: { requests: 0, errors: 0 },
			target: 0.999,
			unreachable: false,
		});
		expect(quiet.availability.noSample).toBe(true);
		expect(quiet.availability.text).toBe("—");
		expect(fmtPercent(100, { n: 0 }).text).toBe("—");
	});
});

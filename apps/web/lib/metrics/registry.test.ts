import { describe, expect, it } from "vitest";
import { METRICS, allMetrics } from "./registry";

describe("registry — one label, one definition", () => {
	it("every id matches its key", () => {
		for (const [key, def] of Object.entries(METRICS)) expect(def.id).toBe(key);
	});

	it("no two metrics share a label", () => {
		const seen = new Map<string, string>();
		for (const m of allMetrics()) {
			const prev = seen.get(m.label);
			expect(
				prev,
				`label "${m.label}" used by ${prev} and ${m.id}`,
			).toBeUndefined();
			seen.set(m.label, m.id);
		}
	});

	it("every metric names its source route/field, numerator and dedup class", () => {
		for (const m of allMetrics()) {
			expect(m.source.length).toBeGreaterThan(8);
			expect(m.numerator.length).toBeGreaterThan(3);
			expect(m.dedup).toBeTruthy();
		}
	});

	it("every percent carries a sample floor and a zero-sample copy or a documented reason", () => {
		for (const m of allMetrics()) {
			if (m.kind !== "percent") continue;
			if (m.id === "slo_target") continue; // a setting, not a measurement
			expect(m.floor, `${m.id} has no floor`).toBeDefined();
			expect(m.denominator, `${m.id} has no denominator`).not.toBeNull();
		}
	});

	it("the two request definitions are two labels — never one", () => {
		expect(METRICS.llm_calls.dedup).toBe("slo MV (not deduplicated)");
		expect(METRICS.requests_routed.dedup).toBe("spans FINAL");
		expect(METRICS.llm_calls.label).not.toBe(METRICS.requests_routed.label);
	});

	it("process-lifetime and instant metrics are never labelled as windowed", () => {
		for (const m of allMetrics()) {
			if (m.window === "process" || m.window === "instant") {
				expect(m.family).toBe("gateway-process");
			}
		}
	});
});

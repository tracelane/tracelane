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
		// B-500: the SLO family reads spans FINAL for windows ≤ 24 h and the hourly
		// view above, as ONE class — every windowed SLO metric carries it, so the
		// headline, table and chart cannot be described as reading different tables.
		expect(METRICS.llm_calls.dedup).toBe(
			"spans FINAL ≤ 24 h · slo MV (not deduplicated) above",
		);
		for (const m of allMetrics()) {
			if (m.family === "slo" && m.window === "windowed") {
				expect(m.dedup, `${m.id} dedup class`).toBe(METRICS.llm_calls.dedup);
			}
		}
		expect(METRICS.requests_routed.dedup).toBe("spans FINAL");
		expect(METRICS.llm_calls.dedup).not.toBe(METRICS.requests_routed.dedup);
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

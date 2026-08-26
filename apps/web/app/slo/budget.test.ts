/**
 * Tests for `computeSloBudget` — the /slo error-budget + burn-rate arithmetic.
 *
 * Locks the SRE math the panel depends on: burn rate = errorRate / (1 - target),
 * budget remaining = 1 - burnRate, and the tone thresholds. Negative/edge cases
 * first per `.claude/rules/testing.md` (no traffic; over budget; target=100%).
 */

import { describe, expect, it } from "vitest";
import {
	SLO_TARGET_AVAILABILITY,
	availabilityTargetForPlanKey,
	computeSloBudget,
} from "./budget";

describe("computeSloBudget", () => {
	it("no traffic → a full, untouched budget (never divide-by-zero)", () => {
		const b = computeSloBudget(0, 0);
		expect(b.availabilityPct).toBe(100);
		expect(b.errorRatePct).toBe(0);
		expect(b.burnRate).toBe(0);
		expect(b.budgetRemainingPct).toBe(100);
		expect(b.tone).toBe("ok");
	});

	it("under budget: 0.05% errors vs a 99.9% target → half the budget, 0.5× burn, ok", () => {
		const b = computeSloBudget(10_000, 5); // 0.05% error, budget = 0.1%
		expect(b.availabilityPct).toBeCloseTo(99.95, 5);
		expect(b.burnRate).toBeCloseTo(0.5, 5);
		expect(b.budgetRemainingPct).toBeCloseTo(50, 5);
		expect(b.tone).toBe("ok");
	});

	it("over pace: 0.15% errors → 1.5× burn, 50% over, warn", () => {
		// 1.5× is safely in [1, 2) — avoids the exact-1.0 float knife-edge
		// (1 - 0.999 = 0.001000…09, so a literal on-budget rate lands a hair
		// under 1.0 → still `ok`, which is correct: on-budget is not yet over).
		const b = computeSloBudget(10_000, 15); // 0.15% error, 1.5× the 0.1% budget
		expect(b.burnRate).toBeCloseTo(1.5, 5);
		expect(b.budgetRemainingPct).toBeCloseTo(-50, 5);
		expect(b.tone).toBe("warn");
	});

	it("over budget: 0.3% errors → 3.0× burn, negative remaining, error tone", () => {
		const b = computeSloBudget(10_000, 30); // 0.3% error, 3× the 0.1% budget
		expect(b.burnRate).toBeCloseTo(3, 5);
		expect(b.budgetRemainingPct).toBeCloseTo(-200, 5);
		expect(b.tone).toBe("error");
	});

	it("target=100% leaves no budget: any error is an infinite burn", () => {
		const clean = computeSloBudget(1000, 0, 1);
		expect(clean.burnRate).toBe(0);
		expect(clean.tone).toBe("ok");
		const dirty = computeSloBudget(1000, 1, 1);
		expect(dirty.burnRate).toBe(Number.POSITIVE_INFINITY);
		expect(dirty.budgetRemainingPct).toBe(Number.NEGATIVE_INFINITY);
		expect(dirty.tone).toBe("error");
	});

	it("honors a custom target (two nines widens the budget)", () => {
		// 0.5% errors vs a 99% target (1% budget) → half the budget spent.
		const b = computeSloBudget(10_000, 50, 0.99);
		expect(b.burnRate).toBeCloseTo(0.5, 5);
		expect(b.tone).toBe("ok");
	});

	it("default target is three nines", () => {
		expect(SLO_TARGET_AVAILABILITY).toBe(0.999);
	});
});

describe("availabilityTargetForPlanKey — MUST mirror the gateway", () => {
	// The authority is crates/gateway/src/alerts/checker.rs::plan_key_to_error_budget
	// (checker.rs:74-79). It states the contract as an ERROR BUDGET; this states it as an
	// AVAILABILITY TARGET. They are reciprocal, so `1 - target` must equal the gateway's
	// budget exactly. If these ever diverge, the dashboard and the alert engine disagree
	// about whether a customer is in breach — which is the bug this table was added for.
	const GATEWAY_ERROR_BUDGET: Record<string, number> = {
		team_v1: 0.01, // 99%
		enterprise_v1: 0.0005, // 99.95%
		business_v1: 0.001, // 99.9%  (the `_ =>` arm)
	};

	for (const [key, budget] of Object.entries(GATEWAY_ERROR_BUDGET)) {
		it(`${key}: 1 - target equals the gateway's ${budget}`, () => {
			const target = availabilityTargetForPlanKey(key);
			expect(1 - target).toBeCloseTo(budget, 10);
		});
	}

	it("an unknown / null / undefined key falls back to 99.9%, never to 100%", () => {
		// A 100% target makes every single error an INFINITE burn, so a wrong fallback
		// here would paint a healthy tenant as catastrophically in breach.
		for (const k of ["", "nope_v9", null, undefined]) {
			expect(availabilityTargetForPlanKey(k)).toBe(SLO_TARGET_AVAILABILITY);
			expect(availabilityTargetForPlanKey(k)).toBeLessThan(1);
		}
	});

	it("THE ORIGINAL DEFECT: a Team tenant at 0.5% errors is 0.5x burn, not 5x", () => {
		// Before the fix both surfaces passed no target, so 0.999 was used for everyone:
		// a Team tenant saw burn 5.00x and "400% over" while the alert engine — using
		// their real 99% target — computed 0.5x and stayed silent.
		const requests = 10_000;
		const errors = 50; // 0.5%
		const team = computeSloBudget(
			requests,
			errors,
			availabilityTargetForPlanKey("team_v1"),
		);
		expect(team.burnRate).toBeCloseTo(0.5, 6);
		expect(team.budgetRemainingPct).toBeCloseTo(50, 6);
		expect(team.tone).toBe("ok");

		// The old behaviour, kept as the contrast that names the defect.
		const asDefault = computeSloBudget(requests, errors);
		expect(asDefault.burnRate).toBeCloseTo(5, 6);
		expect(asDefault.tone).toBe("error");
	});

	it("THE INVERSE, which is worse: Enterprise is stricter, not looser", () => {
		// 0.04% errors against 99.95% is 0.8x burn — close to the line. Measured against
		// the 99.9% default it reads 0.4x, i.e. comfortable. Under-reporting a breach on
		// the tightest SLA is the more dangerous direction.
		const ent = computeSloBudget(
			10_000,
			4,
			availabilityTargetForPlanKey("enterprise_v1"),
		);
		expect(ent.burnRate).toBeCloseTo(0.8, 6);
		expect(computeSloBudget(10_000, 4).burnRate).toBeCloseTo(0.4, 6);
	});
});

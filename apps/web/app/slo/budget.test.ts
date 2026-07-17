/**
 * Tests for `computeSloBudget` — the /slo error-budget + burn-rate arithmetic.
 *
 * Locks the SRE math the panel depends on: burn rate = errorRate / (1 - target),
 * budget remaining = 1 - burnRate, and the tone thresholds. Negative/edge cases
 * first per `.claude/rules/testing.md` (no traffic; over budget; target=100%).
 */

import { describe, expect, it } from "vitest";
import { SLO_TARGET_AVAILABILITY, computeSloBudget } from "./budget";

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

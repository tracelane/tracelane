/**
 * SLO error-budget + burn-rate arithmetic (backs the /slo budget panel).
 *
 * Pure — no runtime deps — so it is unit-testable in isolation and rides on the
 * error rate ALREADY captured in `v_slo_stats` (zero new capture; the #3 /slo edge).
 *
 * The one config is the availability target. There is no per-tenant SLO config
 * yet, so this is the product default (three nines); when a per-tenant target
 * lands it flows in via the `target` arg. Everything else is arithmetic:
 *
 *   errorRate       = errors / requests
 *   errorBudgetRate = 1 - target                (e.g. 0.001 at 99.9%)
 *   burnRate        = errorRate / errorBudgetRate  (1.0× = spending exactly on pace)
 *   budgetRemaining = 1 - burnRate               (100% untouched, 0% spent, <0 = over budget)
 */

/** Default availability target — three nines. Per-tenant config = future work. */
export const SLO_TARGET_AVAILABILITY = 0.999;

export interface SloBudget {
	/** Target availability as a percentage, e.g. 99.9. */
	targetPct: number;
	/** Actual availability over the window, e.g. 99.95. */
	availabilityPct: number;
	/** Actual error rate over the window, as a percentage. */
	errorRatePct: number;
	/** Budget remaining over the window: 100 = untouched, 0 = spent, <0 = over budget. */
	budgetRemainingPct: number;
	/** Multiple of the sustainable error rate being spent; 1.0 = on pace, Infinity if target=100%. */
	burnRate: number;
	/** Health tone driven by burn rate: <1 ok, [1,2) warn, ≥2 error. */
	tone: "ok" | "warn" | "error";
}

/**
 * Compute the SLO error budget from raw request/error counts and an availability
 * target. No traffic → a full, untouched budget (100% available, 0× burn).
 */
export function computeSloBudget(
	totalRequests: number,
	totalErrors: number,
	target: number = SLO_TARGET_AVAILABILITY,
): SloBudget {
	const errorRate = totalRequests > 0 ? totalErrors / totalRequests : 0;
	const budgetRate = 1 - target; // allowed error fraction
	// target=100% leaves no budget: any error is an infinite burn, none is 0.
	const burnRate =
		budgetRate > 0
			? errorRate / budgetRate
			: errorRate > 0
				? Number.POSITIVE_INFINITY
				: 0;
	const budgetRemainingPct = Number.isFinite(burnRate)
		? (1 - burnRate) * 100
		: Number.NEGATIVE_INFINITY;
	const tone = burnRate >= 2 ? "error" : burnRate >= 1 ? "warn" : "ok";
	return {
		targetPct: target * 100,
		availabilityPct: (1 - errorRate) * 100,
		errorRatePct: errorRate * 100,
		budgetRemainingPct,
		burnRate,
		tone,
	};
}

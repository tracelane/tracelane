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

/** Fallback availability target — three nines. Used when the plan is unknown. */
export const SLO_TARGET_AVAILABILITY = 0.999;

/**
 * Availability target for a `plan_lookup_key`, per the ADR-020 SLAs.
 *
 * **THIS MUST MIRROR `crates/gateway/src/alerts/checker.rs::plan_key_to_error_budget`
 * (`checker.rs:74-79`), which is the authority.** It expresses the same contract as an
 * availability target rather than an error-budget fraction, so the two are reciprocal:
 * `errorBudget = 1 - target`.
 *
 * WHY THIS EXISTS. Both `/dashboard` and `/slo` called `computeSloBudget(requests, errors)`
 * with NO target, so every tenant on every plan was measured against the 99.9% default —
 * while the ALERT ENGINE measured the same tenant against its contracted plan target. The
 * two surfaces then disagreed about whether the customer was in breach:
 *
 *   A Team tenant (99% SLA) at a 0.5% error rate saw burn **5.00x** and
 *   **"400% over"** budget in danger tone, while the alert engine computed
 *   **0.5x / 50% remaining** on the same numbers and stayed correctly silent.
 *
 * The Enterprise case inverts and is worse: a 99.95% tenant was shown as comfortable
 * while genuinely burning budget, because 0.001 is a LOOSER budget than their 0.0005.
 *
 * Keys, not plan names, on purpose: the gateway keys on `plan_lookup_key` and so does
 * `plan_entitlements`. Going through `PLAN_TO_LOOKUP_KEY` keeps one vocabulary.
 */
export function availabilityTargetForPlanKey(
	planLookupKey: string | null | undefined,
): number {
	switch (planLookupKey) {
		case "team_v1":
			return 0.99; // 99%    — error budget 0.01
		case "enterprise_v1":
			return 0.9995; // 99.95% — error budget 0.0005
		default:
			// business_v1 / free / builder / unknown / missing → 99.9%, matching the
			// gateway's `_ =>` arm. An unknown key must NOT silently become 100%.
			return SLO_TARGET_AVAILABILITY;
	}
}

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

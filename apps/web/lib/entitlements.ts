/**
 * Entitlement resolution (deny-overrides-grant).
 *
 * Resolution order:
 *   1. PLAN_ENTITLEMENTS map (fallback when no Postgres row exists yet —
 *      e.g. fresh signup before workspace_entitlements is seeded). DERIVED
 *      from `apps/web/db/plans.v3.json` at import time for every BILL-01 /
 *      ADR-076 numeric field — never re-typed here (`.claude/rules/
 *      reference-tables.md`). A handful of pre-existing feature flags
 *      (full-capture, BYOK, prompt-promotion-write, …) are outside that
 *      ADR's scope and stay in the small `LEGACY_FLAGS` table below.
 *   2. plan_entitlements row keyed by `<plan>_v1`.
 *   3. workspace_entitlements row (per-tenant overrides) — every non-NULL
 *      column overrides the plan default. A FALSE here overrides a TRUE
 *      in plan_entitlements (deny-overrides-grant).
 *
 * Audit access (, founder-ratified 2026-07-03): `audit_ledger` resolves
 * from `f_audit_addon` — the SAME source the gateway export gate
 * checks. The legacy `tenants.auditEnabled` read arm is GONE; existing legacy
 * grants were migrated to `workspace_entitlements.f_audit_addon = TRUE` by
 * drizzle migration 0005. One source of truth: a tenant either has the
 * f_audit_addon grant (page renders AND export succeeds) or has neither.
 *
 * // pricing-guard: allow "Audit SKU" — stating it is NOT sold
 * **ADR-076 (2026-09-12 ruling): the Audit SKU is NOT SOLD** — spec
 * `BILL-01` §10.4 found `/v1/audit/export` is not yet a complete offline
 * evidence package (no per-record Merkle proof, no completeness attestation
 * — filed `B-392`). `audit_ledger` therefore stays FALSE by default on every
 * plan, Enterprise included: the SKU that used to flip it is off the price
 * list. Enterprise's 7-year LEDGER RETENTION (`ledger_days`, below) is a
 * separate, already-granted concept and is unaffected.
 *
 * Extracted from `app/api/entitlements/route.ts` so the seat-cap enforcement
 * in `app/api/settings/team/invite` and the GET handler share one
 * authoritative resolver. tenant_id always derives from the WorkOS session,
 * never from a request body — callers pass the resolved internal id.
 */

import { db } from "@/db";
import plansV3Json from "@/db/plans.v3.json";
import { planEntitlements, workspaceEntitlements } from "@/db/schema";
import { eq } from "drizzle-orm";

export type Plan = "free" | "builder" | "team" | "business" | "enterprise";

/** The shape of `apps/web/db/plans.v3.json` — READ-ONLY here (BILL-01 B3). */
export interface PlansV3Meters {
	ingest_usd_per_gb: number;
	hot_window_usd_per_gb_month_ladder: [number, number | null, number][];
	series_usd_per_series_month: number;
	query_usd_per_scan_unit: number;
	cold_usd_per_gb_month: number;
	eval_usd_per_judge_run: number;
	never_metered: string[];
}
export interface PlansV3Policy {
	/** B14: no annual product is sold until the founder rules its shape. */
	annual_available: boolean;
	annual_available_reason: string;
	burst_multiple_of_trailing_30d_avg: number;
	warning_thresholds_pct: number[];
	rollover: boolean;
	price_protection_months: number;
	free_idle_reclaim_days: number;
	dunning_retry_days: number[];
	dunning_data_hold_days: number;
	refund_days_base_first_cycle: number;
	enterprise_onboarding_fee_usd: number;
	prepaid_credits: [number, number][];
	prepaid_expiry_months: number;
	audit_sku: { sold: boolean; reason: string };
}
export interface PlansV3PlanRow {
	name: string;
	price_monthly_usd: number | null;
	price_annual_month_usd: number | null;
	price_from_usd: number | null;
	hot_gb_included: number | null;
	ingest_gb_included: number | null;
	series_included: number | null;
	scan_units_included: number | null;
	eval_runs_included: number | null;
	indexed_window_days: number;
	queryable_days: number;
	ledger_days: number;
	cold_archive_days: number | null;
	cold_gb_included: number | null;
	unlimited_seats: boolean;
	f_sso: boolean;
	overage_allowed: boolean;
	rate_limit_rpm: number | null;
}
export interface PlansV3 {
	meters: PlansV3Meters;
	policy: PlansV3Policy;
	plans: Record<string, PlansV3PlanRow>;
}

export const PLANS_V3 = plansV3Json as unknown as PlansV3;

export const PLAN_TO_LOOKUP_KEY: Record<Plan, string> = {
	free: "free_v1",
	builder: "builder_v1",
	team: "team_v1",
	business: "business_v1",
	enterprise: "enterprise_v1",
};

export interface Entitlements {
	plan: Plan;
	// Gateway + tracing
	gateway_35_providers: boolean;
	// Prompt promotion. `prompt_promotion_read` is TRUE on every plan, free
	// included: reading a prompt's version history is gated nowhere. The gateway
	// `history_handler` (`crates/gateway/src/prompt_routes.rs`) carries no
	// entitlement check, there is no `plan_entitlements` column for it (so it is
	// absent from `rowToOverrides`), and no code outside this map reads it.
	// Only the WRITE — promoting a version across environments — is gated (Team+).
	prompt_promotion_read: boolean;
	prompt_promotion_write: boolean;
	// Security
	byok_cmk: boolean;
	// Article-12 export (f_audit_addon, Enterprise-seeded). ADR-076: the paid SKU
	// is NOT SOLD — see the module doc above. Stays FALSE by plan default here.
	audit_ledger: boolean;
	// ADR-066: FREE, default-TRUE self-verify — SEE + verify your OWN recent
	// chain in-app. A workspace FALSE override (deny-overrides-grant) turns it
	// off. Distinct from audit_ledger (the Enterprise export).
	audit_self_verify: boolean;
	// Full-capture gate. Business + Enterprise
	// base; the Article-12 export grant (`f_audit_addon`, Enterprise-seeded) forces it (non-overridable). Tail
	// sampling otherwise. Workspace-overridable via rowToOverrides.
	f_full_capture: boolean;
	// ── ADR-076 / BILL-01 — the six-meter ruled model ─────────────────────────
	// Seats: 1 on Free; UNLIMITED on every paid tier. There is no included/max
	// ladder any more — `unlimited_seats` is the whole seat model.
	unlimited_seats: boolean;
	f_sso: boolean; // Team+ (from plans.v3.json), replaces the old saml_sso field
	// Included allowances, per calendar month, no rollover. `null` = custom
	// (Enterprise) — the UI renders "custom", never a number.
	hot_gb_included: number | null;
	ingest_gb_included: number | null;
	series_included: number | null;
	scan_units_included: number | null;
	eval_runs_included: number | null;
	// Retention/window axes (spec §0.3): the indexed (hot) window, the longer
	// queryable-history window, the audit ledger's own retention, and the cold
	// archive window on Free (`null` = complete/whole queryable history).
	indexed_window_days: number;
	queryable_days: number;
	ledger_days: number;
	cold_archive_days: number | null;
	// Free has no overage — it ages out, never bills past the allowance. Every
	// paid tier bills continuously per unit past its included allowance
	// pricing-guard: allow "hard cap" — stating there is none
	// (no rollover, no hard cap — "ingest is never blocked by billing state").
	overage_allowed: boolean;
	overflow_mode: "auto_age" | "auto_overage";
	rate_limit_rpm: number | null; // null = no limit (Enterprise)
	// Predictive-feature flags
	f_pr7_trajectory: boolean;
	f_pr8_argdrift: boolean;
	f_pr9_a2a_handoff: boolean;
	f_pr10_inline_slm_judge: boolean;
	f_pr11_slo_drift: boolean;
	f_pr12_langgraph_branch: boolean;
	f_cohort_baselines: boolean;
	// User-facing alerting (ADR-059 / migration 0012). DARK on every plan until
	// the founder flips it; a per-tenant workspace override grants early access.
	f_alerts: boolean;
	// EVL-28 online evals (migration 0030). Team+ — it samples live traffic and
	// spends from the workspace wallet, so the plan boundary is a real one.
	f_online_evals: boolean;
}

/**
 * Feature flags outside ADR-076's scope (unchanged by the six-meter ruling).
 * Kept as a small hand-typed table rather than derived from `plans.v3.json`,
 * which does not carry them.
 */
const LEGACY_FLAGS: Record<
	Plan,
	Pick<
		Entitlements,
		| "f_full_capture"
		| "byok_cmk"
		| "prompt_promotion_write"
		| "f_pr7_trajectory"
		| "f_pr8_argdrift"
		| "f_pr9_a2a_handoff"
		| "f_pr10_inline_slm_judge"
		| "f_pr11_slo_drift"
		| "f_pr12_langgraph_branch"
		| "f_cohort_baselines"
		| "f_alerts"
		| "f_online_evals"
	>
> = {
	free: {
		f_full_capture: false,
		byok_cmk: false,
		prompt_promotion_write: false,
		f_pr7_trajectory: false,
		f_pr8_argdrift: false,
		f_pr9_a2a_handoff: false,
		f_pr10_inline_slm_judge: false,
		f_pr11_slo_drift: false,
		f_pr12_langgraph_branch: false,
		f_cohort_baselines: false,
		f_alerts: false,
		f_online_evals: false,
	},
	builder: {
		f_full_capture: false,
		byok_cmk: false,
		prompt_promotion_write: false,
		f_pr7_trajectory: false,
		f_pr8_argdrift: false,
		f_pr9_a2a_handoff: false,
		f_pr10_inline_slm_judge: false,
		f_pr11_slo_drift: false,
		f_pr12_langgraph_branch: false,
		f_cohort_baselines: false,
		f_alerts: true,
		f_online_evals: false,
	},
	team: {
		f_full_capture: false,
		byok_cmk: false,
		prompt_promotion_write: true,
		f_pr7_trajectory: false,
		f_pr8_argdrift: false,
		f_pr9_a2a_handoff: false,
		f_pr10_inline_slm_judge: false,
		f_pr11_slo_drift: false,
		f_pr12_langgraph_branch: false,
		f_cohort_baselines: false,
		f_alerts: true,
		f_online_evals: true,
	},
	business: {
		f_full_capture: true,
		byok_cmk: true,
		prompt_promotion_write: true,
		f_pr7_trajectory: false,
		f_pr8_argdrift: false,
		f_pr9_a2a_handoff: false,
		f_pr10_inline_slm_judge: false,
		f_pr11_slo_drift: false,
		f_pr12_langgraph_branch: false,
		f_cohort_baselines: false,
		f_alerts: true,
		f_online_evals: true,
	},
	enterprise: {
		f_full_capture: true,
		byok_cmk: true,
		prompt_promotion_write: true,
		// Per-tenant grants flip these TRUE via workspace_entitlements when the
		// feature ships.
		f_pr7_trajectory: false,
		f_pr8_argdrift: false,
		f_pr9_a2a_handoff: false,
		f_pr10_inline_slm_judge: false,
		f_pr11_slo_drift: false,
		f_pr12_langgraph_branch: false,
		f_cohort_baselines: false, // flipped when cohort size n>=30
		f_alerts: true,
		f_online_evals: true,
	},
};

/** Build one plan's entitlement defaults from `plans.v3.json` + `LEGACY_FLAGS`. */
function buildPlanEntitlements(plan: Plan): Entitlements {
	const row = PLANS_V3.plans[PLAN_TO_LOOKUP_KEY[plan]];
	if (!row) {
		throw new Error(`plans.v3.json has no row for ${PLAN_TO_LOOKUP_KEY[plan]}`);
	}
	const legacy = LEGACY_FLAGS[plan];
	return {
		plan,
		gateway_35_providers: true,
		prompt_promotion_read: true,
		prompt_promotion_write: legacy.prompt_promotion_write,
		byok_cmk: legacy.byok_cmk,
		// pricing-guard: allow "Audit SKU" — stating it is NOT sold
		// ADR-076: the Audit SKU is not sold — see the module doc. Never TRUE by
		// plan default, on any tier including Enterprise.
		audit_ledger: false,
		audit_self_verify: true,
		f_full_capture: legacy.f_full_capture,
		unlimited_seats: row.unlimited_seats,
		f_sso: row.f_sso,
		hot_gb_included: row.hot_gb_included,
		ingest_gb_included: row.ingest_gb_included,
		series_included: row.series_included,
		scan_units_included: row.scan_units_included,
		eval_runs_included: row.eval_runs_included,
		indexed_window_days: row.indexed_window_days,
		queryable_days: row.queryable_days,
		ledger_days: row.ledger_days,
		cold_archive_days: row.cold_archive_days,
		overage_allowed: row.overage_allowed,
		overflow_mode: "auto_age",
		rate_limit_rpm: row.rate_limit_rpm,
		f_pr7_trajectory: legacy.f_pr7_trajectory,
		f_pr8_argdrift: legacy.f_pr8_argdrift,
		f_pr9_a2a_handoff: legacy.f_pr9_a2a_handoff,
		f_pr10_inline_slm_judge: legacy.f_pr10_inline_slm_judge,
		f_pr11_slo_drift: legacy.f_pr11_slo_drift,
		f_pr12_langgraph_branch: legacy.f_pr12_langgraph_branch,
		f_cohort_baselines: legacy.f_cohort_baselines,
		f_alerts: legacy.f_alerts,
		f_online_evals: legacy.f_online_evals,
	};
}

/**
 * Fallback map used when no workspace_entitlements row exists for a tenant
 * (fresh signup, OSS self-host, or before the entitlements seed lands). Once
 * the Postgres row exists it always wins. DERIVED from `plans.v3.json` at
 * import time for every ADR-076 field — see `buildPlanEntitlements` above.
 */
export const PLAN_ENTITLEMENTS: Record<Plan, Entitlements> = {
	free: buildPlanEntitlements("free"),
	builder: buildPlanEntitlements("builder"),
	team: buildPlanEntitlements("team"),
	business: buildPlanEntitlements("business"),
	enterprise: buildPlanEntitlements("enterprise"),
};

/**
 * Apply non-NULL workspace/plan overrides on top of plan defaults.
 *
 * A `null`/`undefined` override means "inherit"; any present value wins.
 * This is what makes deny-overrides-grant work: a `false` in
 * workspace_entitlements is a present value and therefore overrides a
 * `true` plan default. Drizzle returns `numeric` columns as strings, so
 * string→number coercion happens when the target field is numeric.
 */
export function mergeOverrides(
	base: Entitlements,
	overrides: Partial<Record<keyof Entitlements, unknown>>,
): Entitlements {
	const merged: Entitlements = { ...base };
	for (const k of Object.keys(overrides) as Array<keyof Entitlements>) {
		const v = overrides[k];
		if (v !== null && v !== undefined) {
			// `Entitlements` is a closed-shape interface, so cast via `unknown`
			// to write through a Record<string, unknown> view of the same object.
			const mergedAsRecord = merged as unknown as Record<string, unknown>;
			if (typeof merged[k] === "number" && typeof v === "string") {
				mergedAsRecord[k as string] = Number(v);
			} else {
				mergedAsRecord[k as string] = v;
			}
		}
	}
	return merged;
}

/** Map a plan_entitlements / workspace_entitlements row to the override shape. */
function rowToOverrides(
	row: Record<string, unknown>,
): Partial<Record<keyof Entitlements, unknown>> {
	return {
		// ── ADR-076 / BILL-01 six-meter fields ──────────────────────────────
		unlimited_seats: row.unlimitedSeats,
		f_sso: row.fSso,
		hot_gb_included: row.hotGbIncluded,
		ingest_gb_included: row.ingestGbIncluded,
		series_included: row.seriesIncluded,
		scan_units_included: row.scanUnitsIncluded,
		eval_runs_included: row.evalRunsIncluded,
		indexed_window_days: row.indexedWindowDays,
		queryable_days: row.queryableDays,
		ledger_days: row.ledgerDays,
		// cold_archive_days has no workspace override column (plan-level only).
		overage_allowed: row.overageAllowed,
		overflow_mode: row.overflowMode,
		rate_limit_rpm: row.rateLimitRpm,
		// ── pre-existing fields, unaffected by ADR-076 ──────────────────────
		f_pr7_trajectory: row.fPr7Trajectory,
		f_pr8_argdrift: row.fPr8Argdrift,
		f_pr9_a2a_handoff: row.fPr9A2aHandoff,
		f_pr10_inline_slm_judge: row.fPr10InlineSlmJudge,
		f_pr11_slo_drift: row.fPr11SloDrift,
		f_pr12_langgraph_branch: row.fPr12LanggraphBranch,
		f_cohort_baselines: row.fCohortBaselines,
		f_full_capture: row.fFullCapture,
		// Audit access resolves from f_audit_addon — the same column
		// the gateway export gate checks.
		audit_ledger: row.fAuditAddon,
		// ADR-066: free self-verify grant (default TRUE; workspace FALSE overrides).
		audit_self_verify: row.fAuditSelfverify,
		// Prompt-promotion write workflow (ADR-009 Team+).
		prompt_promotion_write: row.fPromptPromotionWrite,
		// ADR-059: alerting feature flag. DARK by default; workspace override
		// or a future plan-entitlements seed row turns it on.
		f_alerts: row.fAlerts,
		// EVL-28: online evals. Team+ by plan default; a workspace override can
		// grant or deny it, deny winning — the same shape every other flag here
		// resolves through.
		f_online_evals: row.fOnlineEvals,
	};
}

/**
 * Resolve the effective entitlements for a tenant.
 *
 * @param tenantDbId Internal `tenants.id` UUID, or `null`/`undefined` for an
 *   unseeded tenant (no Postgres row yet) — in that case only the plan-map
 *   fallback is returned.
 * @param plan The tenant's plan (from `tenants.plan`).
 * @returns Resolved, typed entitlement flags. Never throws: a Postgres error
 *   while reading the override rows falls back to the plan-map default
 *   (fail-open is correct here — entitlements are a product gate, not a
 *   security boundary; the gateway re-checks via its own cache).
 */
export async function resolveEntitlements(
	tenantDbId: string | null | undefined,
	plan: Plan,
): Promise<Entitlements> {
	let entitlements: Entitlements = { ...PLAN_ENTITLEMENTS[plan] };

	if (tenantDbId) {
		try {
			const lookupKey = PLAN_TO_LOOKUP_KEY[plan];
			const [planRow] = await db
				.select()
				.from(planEntitlements)
				.where(eq(planEntitlements.planLookupKey, lookupKey))
				.limit(1);
			if (planRow) {
				entitlements = mergeOverrides(
					entitlements,
					rowToOverrides(planRow as unknown as Record<string, unknown>),
				);
			}

			const [wsRow] = await db
				.select()
				.from(workspaceEntitlements)
				.where(eq(workspaceEntitlements.tenantId, tenantDbId))
				.limit(1);
			if (wsRow) {
				entitlements = mergeOverrides(
					entitlements,
					rowToOverrides(wsRow as unknown as Record<string, unknown>),
				);
			}
		} catch {
			// Postgres unreachable / table missing — fall through with map default.
		}
	}

	if (entitlements.audit_ledger) {
		// The export grant (f_audit_addon, Enterprise-seeded) forces full capture on the
		// audited scope — full-fidelity capture cannot tail-drop spans (the audit
		// trail must be complete). Applied AFTER the override merge so a workspace
		// `f_full_capture = false` cannot disable it while audit is active
		// (non-overridable, ADR-048 D2). ADR-076: the SKU is not sold today, so
		// this branch is dormant until a workspace override or a future ruling
		// grants it — kept because a stray manual grant must still force capture.
		entitlements.f_full_capture = true;
	}

	return entitlements;
}

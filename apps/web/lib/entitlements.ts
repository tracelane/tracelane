/**
 * Entitlement resolution (deny-overrides-grant).
 *
 * Resolution order:
 *   1. PLAN_ENTITLEMENTS map (fallback when no Postgres row exists yet —
 *      e.g. fresh signup before workspace_entitlements is seeded).
 *   2. plan_entitlements row keyed by `<plan>_v1`.
 *   3. workspace_entitlements row (per-tenant overrides) — every non-NULL
 *      column overrides the plan default. A FALSE here overrides a TRUE
 *      in plan_entitlements (deny-overrides-grant).
 *
 * checks. The legacy `tenants.auditEnabled` read arm is GONE; existing legacy
 * grants were migrated to `workspace_entitlements.f_audit_addon = TRUE` by
 * drizzle migration 0005. One source of truth: a tenant either has the
 * f_audit_addon grant (page renders AND export succeeds) or has neither.
 *
 * Extracted from `app/api/entitlements/route.ts` so the seat-cap enforcement
 * in `app/api/settings/team/invite` and the GET handler share one
 * authoritative resolver. tenant_id always derives from the WorkOS session,
 * never from a request body — callers pass the resolved internal id.
 */

import { db } from "@/db";
import { planEntitlements, workspaceEntitlements } from "@/db/schema";
import { eq } from "drizzle-orm";

export type Plan = "free" | "builder" | "team" | "business" | "enterprise";

export interface Entitlements {
	plan: Plan;
	// Gateway + tracing
	gateway_35_providers: boolean;
	traces_90_day: boolean;
	// Prompt promotion
	prompt_promotion_read: boolean;
	prompt_promotion_write: boolean;
	eval_gates: boolean;
	auto_rollback: boolean;
	canary_splits: boolean;
	// Security
	byok_cmk: boolean;
	// Paid Article-12 evidence-pack export (f_audit_addon, $999 add-on).
	audit_ledger: boolean;
	// ADR-066: FREE, default-TRUE self-verify — SEE + verify your OWN recent
	// chain in-app. A workspace FALSE override (deny-overrides-grant) turns it
	// off. Distinct from audit_ledger (the paid export).
	audit_self_verify: boolean;
	// Full-capture gate. Business + Enterprise
	// base; an active Audit SKU forces it on any tier (non-overridable). Tail
	// sampling otherwise. Workspace-overridable via rowToOverrides.
	f_full_capture: boolean;
	// Team / seats
	team_members_max: number; // -1 sentinel = unlimited
	saml_sso: boolean;
	// Seat caps + retention + overage
	seat_cap_included: number;
	seat_cap_max: number; // 0 sentinel = unlimited
	retention_days: number;
	trace_quota_monthly: number;
	gateway_quota_monthly: number;
	overage_hard_cap_multiplier: number;
	overage_price_per_10k_usd: number;
	// Predictive-feature flags
	f_pr7_trajectory: boolean;
	f_pr8_argdrift: boolean;
	f_pr9_a2a_handoff: boolean;
	f_pr10_inline_slm_judge: boolean;
	f_pr11_slo_drift: boolean;
	f_pr12_langgraph_branch: boolean;
	f_cohort_baselines: boolean;
	f_hipaa_gcp_addon: boolean;
	// User-facing alerting (ADR-059 / migration 0012). DARK on every plan until
	// the founder flips it; a per-tenant workspace override grants early access.
	f_alerts: boolean;
}

// Fallback map used when no workspace_entitlements row exists for a tenant
// (fresh signup, OSS self-host, or before the entitlements seed lands). Once
// the Postgres row exists it always wins.
export const PLAN_ENTITLEMENTS: Record<Plan, Entitlements> = {
	// Free hosted / unbilled / post-cancellation (free_v1). Matches the
	// db/seed.mjs free_v1 row: 10K quotas, 7d retention, 1 seat,
	// no overage, no audit/byok/promotion-write, all predictive flags off.
	free: {
		plan: "free",
		f_full_capture: false,
		gateway_35_providers: true,
		traces_90_day: false,
		prompt_promotion_read: false,
		prompt_promotion_write: false,
		eval_gates: false,
		auto_rollback: false,
		canary_splits: false,
		byok_cmk: false,
		audit_ledger: false,
		// ADR-066: free self-verify is ON for every plan by default.
		audit_self_verify: true,
		team_members_max: 1,
		saml_sso: false,
		seat_cap_included: 1,
		seat_cap_max: 1,
		retention_days: 7,
		trace_quota_monthly: 10_000,
		gateway_quota_monthly: 10_000,
		overage_hard_cap_multiplier: 1.0,
		overage_price_per_10k_usd: 0.0,
		f_pr7_trajectory: false,
		f_pr8_argdrift: false,
		f_pr9_a2a_handoff: false,
		f_pr10_inline_slm_judge: false,
		f_pr11_slo_drift: false,
		f_pr12_langgraph_branch: false,
		f_cohort_baselines: false,
		f_hipaa_gcp_addon: false,
		f_alerts: false,
	},
	builder: {
		plan: "builder",
		f_full_capture: false,
		gateway_35_providers: true,
		traces_90_day: true,
		prompt_promotion_read: true,
		prompt_promotion_write: false,
		eval_gates: false,
		auto_rollback: false,
		canary_splits: false,
		byok_cmk: false,
		audit_ledger: false,
		// ADR-066: free self-verify is ON for every plan by default.
		audit_self_verify: true,
		team_members_max: 1,
		saml_sso: false,
		seat_cap_included: 1,
		seat_cap_max: 1,
		retention_days: 30,
		trace_quota_monthly: 150_000,
		gateway_quota_monthly: 150_000,
		overage_hard_cap_multiplier: 5.0,
		overage_price_per_10k_usd: 1.2,
		f_pr7_trajectory: false,
		f_pr8_argdrift: false,
		f_pr9_a2a_handoff: false,
		f_pr10_inline_slm_judge: false,
		f_pr11_slo_drift: false,
		f_pr12_langgraph_branch: false,
		f_cohort_baselines: false,
		f_hipaa_gcp_addon: false,
		f_alerts: true,
	},
	team: {
		plan: "team",
		f_full_capture: false,
		gateway_35_providers: true,
		traces_90_day: true,
		prompt_promotion_read: true,
		prompt_promotion_write: true,
		eval_gates: true,
		auto_rollback: true,
		canary_splits: false,
		byok_cmk: false,
		audit_ledger: false,
		// ADR-066: free self-verify is ON for every plan by default.
		audit_self_verify: true,
		team_members_max: 10,
		saml_sso: false,
		seat_cap_included: 10,
		seat_cap_max: 25,
		retention_days: 90,
		trace_quota_monthly: 1_000_000,
		gateway_quota_monthly: 1_000_000,
		overage_hard_cap_multiplier: 5.0,
		overage_price_per_10k_usd: 1.2,
		f_pr7_trajectory: false,
		f_pr8_argdrift: false,
		f_pr9_a2a_handoff: false,
		f_pr10_inline_slm_judge: false,
		f_pr11_slo_drift: false,
		f_pr12_langgraph_branch: false,
		f_cohort_baselines: false,
		f_hipaa_gcp_addon: false,
		f_alerts: true,
	},
	business: {
		plan: "business",
		f_full_capture: true,
		gateway_35_providers: true,
		traces_90_day: true,
		prompt_promotion_read: true,
		prompt_promotion_write: true,
		eval_gates: true,
		auto_rollback: true,
		canary_splits: true,
		byok_cmk: true,
		// Audit is the $999/mo ADD-ON at every tier (ADR-020/025) — never
		// plan-bundled. Matches plan_entitlements.f_audit_addon = FALSE.
		audit_ledger: false,
		// ADR-066: free self-verify is ON for every plan by default.
		audit_self_verify: true,
		team_members_max: -1,
		saml_sso: false,
		seat_cap_included: 25,
		seat_cap_max: 50,
		retention_days: 180,
		trace_quota_monthly: 5_000_000,
		gateway_quota_monthly: 5_000_000,
		overage_hard_cap_multiplier: 5.0,
		overage_price_per_10k_usd: 1.2,
		f_pr7_trajectory: false,
		f_pr8_argdrift: false,
		f_pr9_a2a_handoff: false,
		f_pr10_inline_slm_judge: false,
		f_pr11_slo_drift: false,
		f_pr12_langgraph_branch: false,
		f_cohort_baselines: false,
		f_hipaa_gcp_addon: false,
		f_alerts: true,
	},
	enterprise: {
		plan: "enterprise",
		f_full_capture: true,
		gateway_35_providers: true,
		traces_90_day: true,
		prompt_promotion_read: true,
		prompt_promotion_write: true,
		eval_gates: true,
		auto_rollback: true,
		canary_splits: true,
		byok_cmk: true,
		// Add-on-only, same as Business (ADR-020/025).
		audit_ledger: false,
		// ADR-066: free self-verify is ON for every plan by default.
		audit_self_verify: true,
		team_members_max: -1,
		saml_sso: true,
		seat_cap_included: 0,
		seat_cap_max: 0, // unlimited
		retention_days: 365,
		trace_quota_monthly: 25_000_000,
		gateway_quota_monthly: 25_000_000,
		overage_hard_cap_multiplier: 99.0,
		overage_price_per_10k_usd: 1.0,
		// Per-tenant grants flip these TRUE via workspace_entitlements when the
		// feature ships.
		f_pr7_trajectory: false,
		f_pr8_argdrift: false,
		f_pr9_a2a_handoff: false,
		f_pr10_inline_slm_judge: false,
		f_pr11_slo_drift: false,
		f_pr12_langgraph_branch: false,
		f_cohort_baselines: false, // flipped when cohort size n>=30
		f_hipaa_gcp_addon: false, // flipped on opt-in GCP deployment +$2k/mo
		f_alerts: true,
	},
};

export const PLAN_TO_LOOKUP_KEY: Record<Plan, string> = {
	free: "free_v1",
	builder: "builder_v1",
	team: "team_v1",
	business: "business_v1",
	enterprise: "enterprise_v1",
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
		seat_cap_included: row.seatCapIncluded,
		seat_cap_max: row.seatCapMax,
		retention_days: row.retentionDays,
		trace_quota_monthly: row.traceQuotaMonthly,
		gateway_quota_monthly: row.gatewayQuotaMonthly,
		overage_hard_cap_multiplier: row.overageHardCapMultiplier,
		overage_price_per_10k_usd: row.overagePricePer10kUsd,
		f_pr7_trajectory: row.fPr7Trajectory,
		f_pr8_argdrift: row.fPr8Argdrift,
		f_pr9_a2a_handoff: row.fPr9A2aHandoff,
		f_pr10_inline_slm_judge: row.fPr10InlineSlmJudge,
		f_pr11_slo_drift: row.fPr11SloDrift,
		f_pr12_langgraph_branch: row.fPr12LanggraphBranch,
		f_cohort_baselines: row.fCohortBaselines,
		f_hipaa_gcp_addon: row.fHipaaGcpAddon,
		f_full_capture: row.fFullCapture,
		// the gateway export gate checks (one source of truth).
		audit_ledger: row.fAuditAddon,
		// ADR-066: free self-verify grant (default TRUE; workspace FALSE overrides).
		audit_self_verify: row.fAuditSelfverify,
		prompt_promotion_write: row.fPromptPromotionWrite,
		// ADR-059: alerting feature flag. DARK by default; workspace override
		// or a future plan-entitlements seed row turns it on.
		f_alerts: row.fAlerts,
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
		// An active Audit SKU (f_audit_addon grant) forces full capture on the
		// audited scope — full-fidelity capture cannot tail-drop spans (the audit
		// trail must be complete). Applied AFTER the override merge so a workspace
		// `f_full_capture = false` cannot disable it while audit is active
		// (non-overridable, ADR-048 D2).
		entitlements.f_full_capture = true;
	}

	return entitlements;
}

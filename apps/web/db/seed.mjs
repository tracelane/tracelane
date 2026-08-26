/**
 * Idempotent seed for `plan_entitlements` (pricing v2 ladder).
 *
 * Run: cd apps/web && DATABASE_URL=... pnpm db:seed
 *
 * Values are the authoritative numbers from
 * `infra/dev/postgres/migrations/09_pricing_v2_entitlements.sql` and kept in
 * sync with `crates/gateway/src/rate_limiter.rs`
 * `QuotaConfig::from_plan_tier_str`. Re-running normalises rows
 * (ON CONFLICT DO UPDATE), matching the migration's behaviour.
 *
 * SCOPE — only the 5 base plan keys are seeded. The 5 add-on/meter keys are
 * intentionally NOT seeded because there are no plan-level entitlement rows for
 * them — they are Polar meters / flag-grants, not plans:
 * - audit_addon_v1, hipaa_gcp_addon_v1 → applied as `workspace_entitlements`
 * flag overrides (f_audit_addon / f_hipaa_gcp_addon), not plan rows.
 * - overage_v1, team_extra_seat_v1, business_extra_seat_v1 → usage meters,
 * no seat/retention/quota semantics.
 * `free_v1` IS seeded (the default plan_lookup_key
 * for free/unbilled tenants, and the FK target the Polar webhook needs).
 *
 * All `f_*` PREDICTIVE flags are FALSE: PR7–PR12 and cohort baselines are
 * flipped per-tenant on rollout, never at the plan default (that grant is a
 * per-tenant flip, not a plan default).
 *
 * EXCEPTION — `f_full_capture` IS a plan-level default, like the seat caps:
 * Business + Enterprise = TRUE, every other tier FALSE. It is seeded here so a
 * re-seed normalises it; an active Audit SKU
 * still forces it TRUE per-tenant on top (resolved in lib/entitlements.ts).
 *
 * EXCEPTION — `f_prompt_promotion_write` is ALSO a plan-level default: the
 * ADR-009 tier split is locked (Team+ = TRUE, Builder read-only, Free none),
 * so it is seeded like the seat caps (; mirrors drizzle migration 0005 +
 * infra/dev migration 15).
 *
 * EXCEPTION — the four Sprint 3 eval-loop flags are plan-level defaults too, and
 * the split is founder-accepted: `f_datasets` TRUE on Builder and above (EVL-04
 * §9 Q2 — datasets are the table-stakes parity surface, and gating them at Team
 * loses the comparison before it starts), `f_experiments` / `f_online_evals` /
 * `f_annotation_queues` TRUE on Team and above, exactly like
 * `f_prompt_promotion_write`. Mirrors drizzle migration
 * `0030_evl04_dataset_entitlements.sql`, which seeds the same split so a Neon
 * that never runs this file still resolves the right tiers. Free is FALSE on all
 * four: an unseeded or absent control plane must land on the UNPRIVILEGED value
 * (`.claude/rules/tenancy.md`), which is what the column DEFAULT already gives.
 */

import { neon } from "@neondatabase/serverless";

const url = process.env.DATABASE_URL;
if (!url) {
	console.error("[seed] DATABASE_URL is not set");
	process.exit(1);
}
const sql = neon(url);

// [key, seat_incl, seat_max(0=unlimited), retention_days, trace_quota,
// gateway_quota, overage_hard_cap_multiplier, overage_price_per_10k_usd,
// f_full_capture (Business+Enterprise=true),
// f_prompt_promotion_write (Team+=true, ADR-009),
// f_audit_addon (Enterprise only),
// then the four Sprint 3 eval-loop flags (migration 0030): f_datasets
//   (Builder+), f_experiments, f_online_evals, f_annotation_queues (Team+),
// then the six gated guardrail rails (ADR-064): r2, r3_pinning, r4, r5, r6, r7.
//   Free/Builder = none · Team+ = ALL 6 gated rails (r2/r3_pinning/r4/r5/r6/r7)
//   (ADR-064 amended 2026-07-14: r2/r4 moved down from Business to Team).]
//  (2026-08-04): f_guardrail_r3_pinning and f_guardrail_r4 are TRUE on
// EVERY plan, free_v1 included. Those two rails are now UNGATED in the gateway
// (`Rail::feature()` returns None), so they run regardless of this column — the
// column is kept only so the control plane cannot contradict the binary. The
// agent-safety + basic-correctness rails (R1, R3_schema, R3_pinning,
// R4_trifecta, R8) are free everywhere; the product/quality/data-governance
// rails (R2 PII, R5 format, R6 sysprompt-leak, R7 topic) remain gated.
const PLANS = [
	[
		"free_v1",
		1,
		1,
		7,
		10000,
		10000,
		"1.0",
		"0.00",
		false,
		false,
		false, // f_audit_addon (see enterprise_v1 for why it sits here)
		// Sprint 3 eval loop (migration 0030). These four sit BETWEEN f_audit_addon
		// and the guardrail six on purpose — the drift guard reads `p.slice(-6)`.
		false, // f_datasets          (EVL-04, Builder+)
		false, // f_experiments       (EVL-02, Team+)
		false, // f_online_evals      (EVL-28, Team+)
		false, // f_annotation_queues (EVL-29, Team+)
		false,
		true,
		true,
		false,
		false,
		false,
	],
	[
		"builder_v1",
		1,
		1,
		30,
		150000,
		150000,
		"5.0",
		"1.20",
		false,
		false,
		false, // f_audit_addon (see enterprise_v1 for why it sits here)
		// Sprint 3 eval loop (migration 0030). These four sit BETWEEN f_audit_addon
		// and the guardrail six on purpose — the drift guard reads `p.slice(-6)`.
		true, // f_datasets          (EVL-04, Builder+)
		false, // f_experiments       (EVL-02, Team+)
		false, // f_online_evals      (EVL-28, Team+)
		false, // f_annotation_queues (EVL-29, Team+)
		false,
		true,
		true,
		false,
		false,
		false,
	],
	[
		"team_v1",
		10,
		25,
		90,
		1000000,
		1000000,
		"5.0",
		"1.20",
		false, // f_full_capture
		true, // f_prompt_promotion_write
		// ADR-064 amended (founder 2026-07-14): ALL 9 rails at Team+ — gr2 + gr4
		// moved down from Business so Team gets the full guardrail suite.
		false, // f_audit_addon (see enterprise_v1 for why it sits here)
		// Sprint 3 eval loop (migration 0030). These four sit BETWEEN f_audit_addon
		// and the guardrail six on purpose — the drift guard reads `p.slice(-6)`.
		true, // f_datasets          (EVL-04, Builder+)
		true, // f_experiments       (EVL-02, Team+)
		true, // f_online_evals      (EVL-28, Team+)
		true, // f_annotation_queues (EVL-29, Team+)
		true, // gr2  (R2 secrets/PII)
		true, // gr3_pinning
		true, // gr4  (R4 lethal-trifecta)
		true, // gr5
		true, // gr6
		true, // gr7
	],
	[
		"business_v1",
		25,
		50,
		180,
		5000000,
		5000000,
		"5.0",
		"1.20",
		true,
		true,
		false, // f_audit_addon (see enterprise_v1 for why it sits here)
		// Sprint 3 eval loop (migration 0030). These four sit BETWEEN f_audit_addon
		// and the guardrail six on purpose — the drift guard reads `p.slice(-6)`.
		true, // f_datasets          (EVL-04, Builder+)
		true, // f_experiments       (EVL-02, Team+)
		true, // f_online_evals      (EVL-28, Team+)
		true, // f_annotation_queues (EVL-29, Team+)
		true,
		true,
		true,
		true,
		true,
		true,
	],
	[
		"enterprise_v1",
		0,
		0,
		365,
		25000000,
		25000000,
		"99.0",
		"1.00",
		true,
		true,
		true, // f_audit_addon — ENTERPRISE ONLY (founder ruling 2026-08-14). The six
		// guardrail flags MUST remain the LAST SIX elements: the drift guard at
		// components/guardrails/rail-tier-drift.test.ts:124 reads `p.slice(-6)`.
		// Sprint 3 eval loop (migration 0030) — the four sit ABOVE the guardrail
		// six, which is what keeps the invariant just stated true.
		true, // f_datasets          (EVL-04, Builder+)
		true, // f_experiments       (EVL-02, Team+)
		true, // f_online_evals      (EVL-28, Team+)
		true, // f_annotation_queues (EVL-29, Team+)
		true,
		true,
		true,
		true,
		true,
		true,
	],
];

for (const [
	key,
	si,
	sm,
	rd,
	tq,
	gq,
	cap,
	ov,
	fc,
	ppw,
	aa,
	ds,
	exp,
	oe,
	aq,
	gr2,
	gr3p,
	gr4,
	gr5,
	gr6,
	gr7,
] of PLANS) {
	await sql`
		insert into plan_entitlements (
			plan_lookup_key, seat_cap_included, seat_cap_max, retention_days,
			trace_quota_monthly, gateway_quota_monthly,
			overage_hard_cap_multiplier, overage_price_per_10k_usd, f_full_capture,
			f_prompt_promotion_write,
			f_audit_addon,
			f_datasets, f_experiments, f_online_evals, f_annotation_queues,
			f_guardrail_r2, f_guardrail_r3_pinning, f_guardrail_r4,
			f_guardrail_r5, f_guardrail_r6, f_guardrail_r7
		) values (${key}, ${si}, ${sm}, ${rd}, ${tq}, ${gq}, ${cap}, ${ov}, ${fc}, ${ppw},
			${aa}, ${ds}, ${exp}, ${oe}, ${aq},
			${gr2}, ${gr3p}, ${gr4}, ${gr5}, ${gr6}, ${gr7})
		on conflict (plan_lookup_key) do update set
			seat_cap_included = excluded.seat_cap_included,
			seat_cap_max = excluded.seat_cap_max,
			retention_days = excluded.retention_days,
			trace_quota_monthly = excluded.trace_quota_monthly,
			gateway_quota_monthly = excluded.gateway_quota_monthly,
			overage_hard_cap_multiplier = excluded.overage_hard_cap_multiplier,
			overage_price_per_10k_usd = excluded.overage_price_per_10k_usd,
			f_full_capture = excluded.f_full_capture,
			f_prompt_promotion_write = excluded.f_prompt_promotion_write,
			f_datasets = excluded.f_datasets,
			f_experiments = excluded.f_experiments,
			f_online_evals = excluded.f_online_evals,
			f_annotation_queues = excluded.f_annotation_queues,
			f_guardrail_r2 = excluded.f_guardrail_r2,
			f_guardrail_r3_pinning = excluded.f_guardrail_r3_pinning,
			f_guardrail_r4 = excluded.f_guardrail_r4,
			f_guardrail_r5 = excluded.f_guardrail_r5,
			f_guardrail_r6 = excluded.f_guardrail_r6,
			f_guardrail_r7 = excluded.f_guardrail_r7,
			f_audit_addon = excluded.f_audit_addon,
			updated_at = now()`;
}

const rows = await sql`
	select plan_lookup_key, seat_cap_included, seat_cap_max, retention_days,
	 trace_quota_monthly, gateway_quota_monthly,
	 overage_hard_cap_multiplier, overage_price_per_10k_usd
	from plan_entitlements order by plan_lookup_key`;
console.log(
	`[seed] upserted ${PLANS.length} plan rows. plan_entitlements now:`,
);
console.log(JSON.stringify(rows, null, 2));

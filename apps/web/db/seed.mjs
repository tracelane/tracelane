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
 * // pricing-guard: allow "Audit SKU" — the seed normalises the retired flag
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

import { readFileSync } from "node:fs";

const url = process.env.DATABASE_URL;
if (!url) {
	console.error("[seed] DATABASE_URL is not set");
	process.exit(1);
}
const sql = neon(url);

// [key,
// f_full_capture (Business+Enterprise=true),
//   (the ADR-020 positional values that used to sit between `key` and this —
//   seat caps, retention_days, trace/gateway quotas, the overage multiplier and
//   per-10K price — were DROPPED with migration 0042, BILL-01 contract step;
//   every ruled number is in ./plans.v3.json, keyed, never positional),
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
			plan_lookup_key, f_full_capture,
			f_prompt_promotion_write,
			f_audit_addon,
			f_datasets, f_experiments, f_online_evals, f_annotation_queues,
			f_guardrail_r2, f_guardrail_r3_pinning, f_guardrail_r4,
			f_guardrail_r5, f_guardrail_r6, f_guardrail_r7
		) values (${key}, ${fc}, ${ppw},
			${aa}, ${ds}, ${exp}, ${oe}, ${aq},
			${gr2}, ${gr3p}, ${gr4}, ${gr5}, ${gr6}, ${gr7})
		on conflict (plan_lookup_key) do update set
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

// ── BILL-01 / ADR-076 (founder ruling 2026-09-12): pricing v3 ─────────────────────────
// The six-meter allowances, windows, seats and prices live in ./plans.v3.json — keyed by
// lookup key, NOT positional, so the guardrail drift test's `p.slice(-6)` over PLANS above
// is untouched. That JSON is the ONE source `scripts/ci/check-pricing-copy-vs-seed.py`
// compares every public figure against. Columns: migration 0040 (un-journaled, applied
// to Neon BEFORE the gateway that reads them deploys). The ADR-020 columns this seed used
// to upsert (seat caps, trace quotas, overage multiplier) were DROPPED by migration 0042
// (2026-09-14, the contract step) — nothing writes or reads them any more.
const v3 = JSON.parse(
	readFileSync(new URL("./plans.v3.json", import.meta.url), "utf8"),
);
for (const [key, p] of Object.entries(v3.plans)) {
	await sql`
		update plan_entitlements set
			price_monthly_usd = ${p.price_monthly_usd},
			price_annual_month_usd = ${p.price_annual_month_usd},
			price_from_usd = ${p.price_from_usd},
			hot_gb_included = ${p.hot_gb_included},
			ingest_gb_included = ${p.ingest_gb_included},
			series_included = ${p.series_included},
			scan_units_included = ${p.scan_units_included},
			eval_runs_included = ${p.eval_runs_included},
			indexed_window_days = ${p.indexed_window_days},
			queryable_days = ${p.queryable_days},
			ledger_days = ${p.ledger_days},
			cold_archive_days = ${p.cold_archive_days},
			cold_gb_included = ${p.cold_gb_included ?? null},
			unlimited_seats = ${p.unlimited_seats},
			f_sso = ${p.f_sso},
			overage_allowed = ${p.overage_allowed},
			rate_limit_rpm = ${p.rate_limit_rpm},
			updated_at = now()
		where plan_lookup_key = ${key}`;
}
console.log(
	`[seed] pricing v3: updated ${Object.keys(v3.plans).length} plan rows from plans.v3.json`,
);

// Reference tables (founder 2026-09-13: no hardcoded prices / limits / config — tables).
// pricing_rates: one row per (meter, band); billing_policy: one row per policy key.
const m = v3.meters;
const rateRows = [
	["ingest_gb", 0, null, m.ingest_usd_per_gb, "GB"],
	...m.hot_window_usd_per_gb_month_ladder.map(([lo, hi, usd]) => [
		"hot_gb_month",
		lo,
		hi,
		usd,
		"GB-month",
	]),
	["series", 0, null, m.series_usd_per_series_month, "series-month"],
	["scan_units", 0, null, m.query_usd_per_scan_unit, "scan-unit"],
	["cold_gb_month", 0, null, m.cold_usd_per_gb_month, "GB-month"],
	["eval_runs", 0, null, m.eval_usd_per_judge_run, "run"],
];
for (const [meter, lo, hi, usd, unit] of rateRows) {
	await sql`
		insert into pricing_rates (price_version, meter, band_lo, band_hi, usd_per_unit, unit, is_current)
		values ('v3', ${meter}, ${lo}, ${hi}, ${usd}, ${unit}, true)
		on conflict (price_version, meter, band_lo) do update set
			band_hi = excluded.band_hi, usd_per_unit = excluded.usd_per_unit,
			unit = excluded.unit, is_current = true`;
}
const pol = v3.policy;
const policyRows = {
	burst_multiple: pol.burst_multiple_of_trailing_30d_avg,
	// The gateway reads the two thresholds as SEPARATE scalar keys (rating.rs Policy);
	// the array form stays for the web app. Bare JSON scalars — a quoted string would
	// cast to "\"75\"" and fall back to the default silently.
	warn_pct_1: pol.warning_thresholds_pct[0],
	warn_pct_2: pol.warning_thresholds_pct[1],
	warn_pct: pol.warning_thresholds_pct,
	velocity_sigma: pol.velocity_sigma,
	velocity_window_days: pol.velocity_window_days,
	velocity_interval_secs: pol.velocity_interval_secs,
	rollover: pol.rollover,
	annual_available: pol.annual_available,
	price_protection_months: pol.price_protection_months,
	free_idle_reclaim_days: pol.free_idle_reclaim_days,
	dunning_retry_days: pol.dunning_retry_days,
	dunning_data_hold_days: pol.dunning_data_hold_days,
	refund_days_base_first_cycle: pol.refund_days_base_first_cycle,
	enterprise_onboarding_fee_usd: pol.enterprise_onboarding_fee_usd,
	prepaid_credits: pol.prepaid_credits,
	prepaid_expiry_months: pol.prepaid_expiry_months,
	never_metered: m.never_metered,
	audit_sku: pol.audit_sku,
};
for (const [key, value] of Object.entries(policyRows)) {
	await sql`
		insert into billing_policy (key, value) values (${key}, ${JSON.stringify(value)}::jsonb)
		on conflict (key) do update set value = excluded.value, updated_at = now()`;
}
console.log(
	`[seed] pricing v3: ${rateRows.length} pricing_rates rows + ${Object.keys(policyRows).length} billing_policy rows`,
);

const rows = await sql`
	select plan_lookup_key, price_monthly_usd, price_annual_month_usd, hot_gb_included,
	 ingest_gb_included, series_included, scan_units_included, eval_runs_included,
	 indexed_window_days, queryable_days, ledger_days, unlimited_seats, f_sso, rate_limit_rpm
	from plan_entitlements order by plan_lookup_key`;
console.log(
	`[seed] upserted ${PLANS.length} plan rows. plan_entitlements now:`,
);
console.log(JSON.stringify(rows, null, 2));

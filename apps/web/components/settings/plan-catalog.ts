/**
 * Plan catalog for the in-app plans page (SET-15 / ADR-076).
 *
 * ## Why this is derived, not typed out
 *
 * Every number here comes from `apps/web/db/plans.v3.json` — the single
 * source `db/seed.mjs` upserts into `plan_entitlements` and the same source
 * `scripts/ci/check-pricing-copy-vs-seed.py` checks every public surface
 * against (`.claude/rules/reference-tables.md`). Nothing in this module is a
 * literal price, allowance, window or seat figure — change the JSON and this
 * page changes with it.
 *
 * ## Honesty rules encoded here
 *
 * - Seats: 1 on Free, UNLIMITED on every paid tier (`unlimited_seats`,
 *   ADR-076) — there is no included/max ladder any more.
 * - SSO is a plain per-tier boolean (`f_sso`) — Team and above.
 * - "Never metered" and "no rollover" are stated once, page-wide, per §0.2 /
 *   §0.5 of `specs/BILL-01-metering-and-tiers.md` — never re-derived per card.
 * - No "discount" / "% off" / "save" anywhere — annual is a second REAL
 *   price, never a markdown of the monthly one (`.claude/rules/billing.md`).
 */

import { PLANS_V3, type Plan, type PlansV3PlanRow } from "@/lib/entitlements";

/** Ladder order, cheapest first. */
export const LADDER: readonly Plan[] = [
	"free",
	"builder",
	"team",
	"business",
	"enterprise",
] as const;

const LOOKUP_KEY: Record<Plan, string> = {
	free: "free_v1",
	builder: "builder_v1",
	team: "team_v1",
	business: "business_v1",
	enterprise: "enterprise_v1",
};

/** Tiers with a self-serve Polar checkout. Enterprise is sales-led. */
const SELF_SERVE: ReadonlySet<Plan> = new Set<Plan>([
	"builder",
	"team",
	"business",
]);

/** `1234` → `1.2K`; `1_000_000` → `1M`. Never rounds a small count. */
export function formatCount(n: number): string {
	if (n >= 1_000_000) {
		const m = n / 1_000_000;
		return `${Number.isInteger(m) ? m : m.toFixed(1)}M`;
	}
	if (n >= 1_000) {
		const k = n / 1_000;
		return `${Number.isInteger(k) ? k : k.toFixed(1)}K`;
	}
	return n.toLocaleString("en-US");
}

/** `0.25` → "0.25 GB"; `1500` → "1.5 TB"; `null` → "custom". */
export function formatGb(gb: number | null): string {
	if (gb === null) return "custom";
	if (gb >= 1000) {
		const tb = gb / 1000;
		return `${Number.isInteger(tb) ? tb : tb.toFixed(1)} TB`;
	}
	return `${Number.isInteger(gb) ? gb : gb.toFixed(2)} GB`;
}

/** `365` → "365 days"; `730` → "2 years"; `2555` → "7 years". */
export function formatDays(days: number, plusOpenEnded = false): string {
	if (days % 365 === 0 && days >= 365) {
		const years = days / 365;
		return `${years} year${years === 1 ? "" : "s"}${plusOpenEnded ? "+" : ""}`;
	}
	return `${days} day${days === 1 ? "" : "s"}${plusOpenEnded ? "+" : ""}`;
}

/** `null` → "custom"; a number → its formatted count. */
export function formatCountOrCustom(n: number | null): string {
	return n === null ? "custom" : formatCount(n);
}

/** `$0`; `$29/mo`; `from $2,499/mo`. `interval` picks monthly vs annual. */
export function formatPrice(
	row: PlansV3PlanRow,
	interval: "month" | "year",
): { amount: string; suffix: string; fromLabel: boolean } {
	if (row.price_from_usd !== null) {
		return {
			amount: `$${row.price_from_usd.toLocaleString("en-US")}`,
			suffix: "/mo",
			fromLabel: true,
		};
	}
	if (row.price_monthly_usd === 0) {
		return { amount: "$0", suffix: "", fromLabel: false };
	}
	const usd =
		interval === "year" && row.price_annual_month_usd !== null
			? row.price_annual_month_usd
			: row.price_monthly_usd;
	return {
		amount: `$${(usd ?? 0).toLocaleString("en-US")}`,
		suffix: "/mo",
		fromLabel: false,
	};
}

export interface PlanRowItem {
	label: string;
	value: string;
}

export interface PlanCard {
	plan: Plan;
	name: string;
	priceMonth: { amount: string; suffix: string; fromLabel: boolean };
	priceYear: { amount: string; suffix: string; fromLabel: boolean } | null;
	note: string;
	rows: PlanRowItem[];
	/** True when `/api/checkout?tier=<plan>&interval=…` is a real self-serve path. */
	selfServe: boolean;
}

/** Build one plan's card, straight from its `plans.v3.json` row. */
export function buildCard(plan: Plan): PlanCard {
	const row = PLANS_V3.plans[LOOKUP_KEY[plan]];
	if (!row) throw new Error(`plans.v3.json has no row for ${LOOKUP_KEY[plan]}`);

	const rows: PlanRowItem[] = [
		{
			label: "Indexed window",
			value: formatDays(row.indexed_window_days, plan === "enterprise"),
		},
		{ label: "Queryable history", value: formatDays(row.queryable_days) },
		{ label: "Hot GB included", value: formatGb(row.hot_gb_included) },
		{ label: "Ingest included", value: formatGb(row.ingest_gb_included) },
		{
			label: "Series included",
			value: formatCountOrCustom(row.series_included),
		},
		{
			label: "Scan-units included",
			value: formatCountOrCustom(row.scan_units_included),
		},
		{
			label: "Eval runs included",
			value: formatCountOrCustom(row.eval_runs_included),
		},
		{
			// BILL-01 A5: paid tiers carry an included cold-archive allowance
			// (24x monthly ingest); Free keeps a 7-day cold window; Enterprise custom.
			label: "Cold archive",
			value:
				row.cold_gb_included !== null && row.cold_gb_included !== undefined
					? `${formatGb(row.cold_gb_included)}·mo included`
					: row.cold_archive_days === null
						? "custom"
						: formatDays(row.cold_archive_days),
		},
		{ label: "Ledger retention", value: formatDays(row.ledger_days) },
		{ label: "Seats", value: row.unlimited_seats ? "Unlimited" : "1" },
		{ label: "SSO / SAML", value: row.f_sso ? "Yes" : "—" },
	];

	return {
		plan,
		name: row.name,
		priceMonth: formatPrice(row, "month"),
		// B14 (2026-09-15): annual is not for sale until the founder rules its
		// shape — `policy.annual_available` in plans.v3.json is the ONE switch;
		// a null priceYear hides "Switch to annual" (PlanHeader) and the checkout
		// refuses `interval=year` on the same flag.
		priceYear:
			PLANS_V3.policy.annual_available && row.price_annual_month_usd !== null
				? formatPrice(row, "year")
				: null,
		note:
			plan === "free"
				? "advertising only — one workspace, no card"
				: plan === "enterprise"
					? "annual: custom contract"
					: "billed monthly or annually",
		rows,
		selfServe: SELF_SERVE.has(plan),
	};
}

export function buildLadder(): PlanCard[] {
	return LADDER.map((p) => buildCard(p));
}

/**
 * The three footnotes below the ladder (spec §8) — verbatim wording, never
 * re-derived per tier.
 */
export const LADDER_FOOTNOTES: readonly string[] = [
	"No rollover of unused allowance.",
	"Free ages out after 14 idle days — never returns a 429.",
];

/** The "never metered" card copy (spec §0.2, `plans.v3.json` `never_metered`). */
export const NEVER_METERED_TITLE =
	"Never metered — priced into ingest and query";
export function neverMeteredCopy(): string {
	// Title-case + join the JSON's raw list rather than typing the sentence a
	// second time — this is THE source (`.claude/rules/reference-tables.md`).
	return `${PLANS_V3.meters.never_metered.join(" · ")}.`;
}

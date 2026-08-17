/**
 * Plan catalog for the in-app plans page (SET-15).
 *
 * ## Why this is derived, not typed out
 *
 * Every *limit* on this page is computed from `PLAN_ENTITLEMENTS`
 * (`lib/entitlements.ts`) — the same map the entitlement resolver falls back to,
 * and the same numbers `db/seed.mjs` writes into `plan_entitlements`
 * (`db/seed.mjs:61-146`, verified equal 2026-08-08). So the ladder a customer
 * reads cannot drift from the quota the gateway actually enforces: change the
 * entitlement and the page changes with it. Hardcoding "150K traces" here is how
 * copy-outruns-code bugs start.
 *
 * The ONE thing not derivable from code is money — a list price lives in Polar,
 * not in this repo — so `LIST_PRICE` is a small literal table cross-checked
 * against the canonical public price copy (`apps/docs/pricing.mdx:12-19`) and
 * against `app/settings/billing/page.tsx` PLAN_LABEL. It is labelled "list
 * price" everywhere for the same reason the billing page does: the real charge
 * comes from Polar, and this page must never read as a confirmed charge.
 *
 * ## Honesty rules encoded here
 *
 * - A feature bullet is emitted ONLY where its entitlement flag is `true`.
 *   Absence is not a claim, so a tier never advertises something the resolver
 *   would deny. (Never the inverse — "tail-sampled" as a negative bullet would
 *   be a claim about sampling behaviour this module cannot verify.)
 *   is a legacy identifier and must not reach copy.
 * - Guardrails are described as running inline at the gateway, observe-first.
 *   No "block" / "prevent" / "before it executes" framing (ADR-023 ban,
 *   re-affirmed by the ADR-055 amendment).
 * - Seat wording states the honest per-tier cap; only Enterprise is uncapped
 *   (`seat_cap_max === 0` sentinel).
 */

import {
	type Entitlements,
	PLAN_ENTITLEMENTS,
	type Plan,
} from "@/lib/entitlements";

/** Ladder order, cheapest first. Matches `apps/docs/pricing.mdx:12-18`. */
export const LADDER: readonly Plan[] = [
	"free",
	"builder",
	"team",
	"business",
	"enterprise",
] as const;

/**
 * List price per tier. The only literal in this module — money is not in the
 * entitlement map. Cross-checked against `apps/docs/pricing.mdx:12-18`.
 */
const LIST_PRICE: Record<Plan, string> = {
	free: "$0",
	builder: "$59/mo",
	team: "$249/mo",
	business: "$899/mo",
	enterprise: "From $2,999/mo",
};

const DISPLAY_NAME: Record<Plan, string> = {
	free: "Free hosted",
	builder: "Builder",
	team: "Team",
	business: "Business",
	enterprise: "Enterprise",
};

const TAGLINE: Record<Plan, string> = {
	free: "Kick the tyres. Non-commercial use.",
	builder: "One developer shipping an agent to production.",
	team: "A team sharing one workspace, one meter, one set of keys.",
	business: "Higher volume, customer-managed encryption keys.",
	// "dedicated tenancy option" is what `apps/docs/pricing.mdx:18` actually
	// carries. The billing page's old "Dedicated support SLA" bullet was not
	// backed anywhere, and sits awkwardly beside "no contractual uptime SLA".
	enterprise: "Custom volume, SSO, dedicated tenancy option.",
};

/**
 * Tiers with a self-serve Polar checkout. Enterprise is sales-led and Free is
 * the default, so neither gets a checkout button. Mirrors the UPGRADE_TARGETS
 * map in `app/settings/billing/page.tsx` — the route that actually 302s to
 * Polar (`/api/checkout`) only carries products for these three.
 */
const SELF_SERVE: ReadonlySet<Plan> = new Set<Plan>([
	"builder",
	"team",
	"business",
]);

/**
 * Gated data-governance + quality rails (R2 secrets/PII, R5 output format,
 * R6 system-prompt-leak, R7 topic policy) are Team and above — `db/seed.mjs`
 * sets gr2/gr5/gr6/gr7 TRUE only from `team_v1` onward (`db/seed.mjs:98-146`).
 * The agent-safety rails are free on EVERY plan and are stated once, page-wide,
 * rather than per card.
 */
const GOVERNANCE_RAIL_TIERS: ReadonlySet<Plan> = new Set<Plan>([
	"team",
	"business",
	"enterprise",
]);

/** `12345` → `12.3K`; `1_000_000` → `1M`. Trace quotas are always round here. */
export function formatQuota(n: number): string {
	if (n >= 1_000_000) {
		const m = n / 1_000_000;
		return `${Number.isInteger(m) ? m : m.toFixed(1)}M`;
	}
	if (n >= 1_000) {
		const k = n / 1_000;
		return `${Number.isInteger(k) ? k : k.toFixed(1)}K`;
	}
	return String(n);
}

/**
 * Seat wording from the resolved caps. `seat_cap_max === 0` is the UNLIMITED
 * sentinel (`lib/entitlements.ts`), not "zero seats" — reading it literally is
 * how a plan page tells an Enterprise customer they have no seats.
 */
export function formatSeats(included: number, max: number): string {
	if (max === 0) return "Uncapped seats";
	if (max === included) return included === 1 ? "1 seat" : `${included} seats`;
	return `${included} seats included, up to ${max}`;
}

/**
 * Overage wording from the cap multiplier + unit price. A `1.0` multiplier means
 * the quota IS the ceiling — there is no overage to bill, so saying "no overage"
 * there is the code-true statement, not a softer one.
 */
export function formatOverage(multiplier: number, pricePer10k: number): string {
	if (pricePer10k <= 0 || multiplier <= 1)
		return "No overage billing — requests return 429 past the monthly quota";
	const price = `$${pricePer10k.toFixed(2)} per 10K traces past quota`;
	if (multiplier >= 10) return `${price}, custom ceiling`;
	return `${price}, hard cap at ${multiplier}× then 429`;
}

/**
 * Feature bullets for a tier, emitted only where the entitlement is granted.
 *
 * Every bullet maps to a flag in `Entitlements`, except the governance-rail
 * line, which maps to the `f_guardrail_*` columns `db/seed.mjs` writes (they are
 * gateway-side and absent from the TS `Entitlements` shape).
 */
export function featureBullets(plan: Plan, ent: Entitlements): string[] {
	const out: string[] = ["30+-provider gateway, BYOK at 0% markup"];

	if (ent.prompt_promotion_write) {
		out.push("Prompt promotion — author and promote across environments");
	} else if (ent.prompt_promotion_read) {
		out.push("Prompt version history (read-only)");
	}
	if (GOVERNANCE_RAIL_TIERS.has(plan)) {
		out.push(
			"Data-governance and quality rails: secrets/PII, output format, system-prompt-leak, topic policy",
		);
	}
	if (ent.f_full_capture) out.push("Full-fidelity capture on every request");
	if (ent.byok_cmk) out.push("Customer-managed encryption keys (BYOK CMK)");
	if (ent.saml_sso) out.push("SAML SSO");

	return out;
}

export interface PlanCard {
	plan: Plan;
	name: string;
	price: string;
	tagline: string;
	/** e.g. "150K traces/mo" */
	traces: string;
	seats: string;
	retention: string;
	overage: string;
	features: string[];
	/** True when `/api/checkout?tier=<plan>` is a real self-serve path. */
	selfServe: boolean;
}

/**
 * Build one card. `ent` defaults to the plan's own entitlement defaults; the
 * caller passes the RESOLVED entitlements for the viewer's current plan so a
 * workspace override (a lifted seat cap, a custom quota) is shown as the
 * customer's real number instead of the generic plan default.
 */
export function buildCard(
	plan: Plan,
	ent: Entitlements = PLAN_ENTITLEMENTS[plan],
): PlanCard {
	// Enterprise volume is a FLOOR negotiated upward, not a ceiling — the "+"
	// matches the canonical price copy ("25M+ traces custom",
	// `apps/docs/pricing.mdx:17`). Every other tier's quota is exact.
	const plus = plan === "enterprise" ? "+" : "";
	return {
		plan,
		name: DISPLAY_NAME[plan],
		price: LIST_PRICE[plan],
		tagline: TAGLINE[plan],
		traces: `${formatQuota(ent.trace_quota_monthly)}${plus} traces/mo`,
		seats: formatSeats(ent.seat_cap_included, ent.seat_cap_max),
		retention: `${ent.retention_days}-day trace retention`,
		overage: formatOverage(
			ent.overage_hard_cap_multiplier,
			ent.overage_price_per_10k_usd,
		),
		features: featureBullets(plan, ent),
		selfServe: SELF_SERVE.has(plan),
	};
}

/**
 * The full ladder. `resolved` (optional) is the viewer's resolved entitlements;
 * it is applied ONLY to the card matching `currentPlan`, because a workspace
 * override says nothing about what another tier would grant.
 */
export function buildLadder(
	currentPlan?: Plan,
	resolved?: Entitlements,
): PlanCard[] {
	return LADDER.map((p) =>
		p === currentPlan && resolved ? buildCard(p, resolved) : buildCard(p),
	);
}

/**
 * True when the viewer's resolved entitlements differ from their plan's stock
 * limits — the page then says so instead of silently showing numbers that match
 * neither the plan nor the customer.
 */
export function hasCustomLimits(plan: Plan, resolved: Entitlements): boolean {
	const base = PLAN_ENTITLEMENTS[plan];
	return (
		base.trace_quota_monthly !== resolved.trace_quota_monthly ||
		base.seat_cap_included !== resolved.seat_cap_included ||
		base.seat_cap_max !== resolved.seat_cap_max ||
		base.retention_days !== resolved.retention_days
	);
}

/**
 * The Audit SKU is an ADD-ON at every tier (ADR-020/025) — never bundled into a
 * plan, which is why it is not a ladder column. Resolves from `f_audit_addon`,
 */
export const AUDIT_ADDON = {
	name: "Audit ledger",
	price: "+$999/mo",
	summary:
		"A tamper-evident record of what your agents actually did: a hash-chained entry per gateway-proxied request, batched into an RFC 6962 Merkle root and signed with your workspace's own Ed25519 key. Anchored batches carry a resolved Sigstore Rekor v2 inclusion proof on a best-effort basis.",
	scope:
		"Only calls proxied through the Tracelane gateway are chained. Spans sent straight from an SDK or an OTLP exporter are stored and queryable, but are not part of the chain.",
	verify:
		"Exports in the offline-verifier wire format — you or a third party can verify the chain and the signatures with `tlane verify --tenant-pubkey`, with no Tracelane involvement.",
} as const;

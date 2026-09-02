/**
 * SET-15 — rendered proof of the in-app plans page.
 *
 * The end state under test is *not* "a component exists". It is: a signed-in
 * customer can compare every plan INSIDE the product, see the limits the
 * gateway actually enforces for each tier, see which one is theirs, and start a
 * self-serve upgrade — without being sent to the marketing site. So these tests
 * render the real DOM (`renderToStaticMarkup`, node env — the pattern
 * `components/trace-viewer/transcript-spine-render.test.ts` established) and
 * assert what a customer would read off the screen.
 *
 * Negative cases first (`.claude/rules/testing.md`): the copy that must NOT
 * appear, and the off-product link that must NOT come back.
 */

import { type Entitlements, PLAN_ENTITLEMENTS } from "@/lib/entitlements";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// `next/link` is a client component that expects an app-router context; in the
// node env it is not the thing under test, and its contract is "renders an <a>
// carrying href". Stub exactly that so the assertion is still on a rendered
// anchor's destination.
vi.mock("next/link", () => ({
	default: ({
		href,
		children,
		...rest
	}: {
		href: string;
		children?: unknown;
		[k: string]: unknown;
	}) => createElement("a", { href, ...rest }, children as never),
}));

import { PlanLadder } from "./PlanLadder";
import { PlansLink } from "./PlansLink";
import {
	buildLadder,
	formatOverage,
	formatQuota,
	formatSeats,
	hasCustomLimits,
} from "./plan-catalog";

const h = createElement;

const renderLadder = (
	currentPlan: string | null,
	resolved?: Entitlements,
): string =>
	renderToStaticMarkup(
		h(PlanLadder, {
			cards: buildLadder(
				(currentPlan ?? undefined) as never,
				resolved as never,
			),
			currentPlan,
			customLimitsNote:
				resolved && currentPlan
					? hasCustomLimits(currentPlan as never, resolved)
					: false,
		}),
	);

// ---------------------------------------------------------------------------
// NEGATIVE — what must never appear
// ---------------------------------------------------------------------------

describe("SET-15 — the plan comparison must not leave the product", () => {
	it("the billing-page affordance points at the in-app /plans route, not the marketing site", () => {
		const html = renderToStaticMarkup(h(PlansLink, {}));
		expect(html).toContain('href="/plans"');
		// The exact regression this closes: /settings/billing used to link to
		// https://tracelane.dev/#pricing to answer "what are the other plans?".
		expect(html).not.toContain("tracelane.dev");
		expect(html).not.toContain("#pricing");
		expect(html).not.toContain("http");
	});

	it("the ladder itself never links out to marketing pricing", () => {
		const html = renderLadder("builder");
		// The sales mailto is legitimate; an http(s) hop to the marketing site is
		// the thing this feature removes.
		expect(html).not.toContain("https://tracelane.dev");
		expect(html).not.toContain("http://tracelane.dev");
		expect(html).not.toContain("#pricing");
	});
});

describe("SET-15 — honesty locks hold in the rendered copy", () => {
	const html = renderLadder("team");

	it("says tamper-EVIDENT, never tamper-proof", () => {
		expect(html).toContain("tamper-evident");
		expect(html.toLowerCase()).not.toContain("tamper-proof");
	});

	it('says "30+" providers, never the retired "35+"', () => {
		expect(html).toContain("150+-provider gateway");
		expect(html).not.toContain("35+");
		// the legacy entitlement flag NAME must not leak into copy
		expect(html).not.toContain("gateway_35_providers");
	});

	it("never claims enforcement/blocking, and never a 100% figure", () => {
		const lowered = html.toLowerCase();
		expect(lowered).not.toContain("before they execute");
		expect(lowered).not.toContain("before the tool runs");
		expect(lowered).not.toContain("prevent failures");
		expect(lowered).not.toContain("100%");
		// observe-first framing is the one that IS allowed, and is present
		expect(lowered).toContain("observe-first");
	});

	it("never offers uncapped seats below Enterprise", () => {
		for (const plan of ["free", "builder", "team", "business"] as const) {
			const seats = formatSeats(
				PLAN_ENTITLEMENTS[plan].seat_cap_included,
				PLAN_ENTITLEMENTS[plan].seat_cap_max,
			);
			expect(seats.toLowerCase()).not.toContain("uncapped");
			expect(seats.toLowerCase()).not.toContain("unlimited");
		}
		expect(
			formatSeats(
				PLAN_ENTITLEMENTS.enterprise.seat_cap_included,
				PLAN_ENTITLEMENTS.enterprise.seat_cap_max,
			),
		).toBe("Uncapped seats");
	});

	it("reads the 0 seat-cap sentinel as unlimited, never as zero seats", () => {
		expect(formatSeats(0, 0)).toBe("Uncapped seats");
		expect(formatSeats(0, 0)).not.toContain("0 seats");
	});

	it("does not advertise a feature the tier's entitlements deny", () => {
		const free = renderLadder("free");
		// Builder/Team do not carry byok_cmk; Free/Builder do not carry
		// prompt_promotion_write. Those bullets exist ONLY on granting tiers, so
		// the string count must equal the number of tiers that grant them.
		const occurrences = (s: string, needle: string) =>
			s.split(needle).length - 1;
		// byok_cmk: business + enterprise = 2
		expect(occurrences(free, "Customer-managed encryption keys")).toBe(2);
		// saml_sso: enterprise only = 1
		expect(occurrences(free, "SAML SSO")).toBe(1);
		// f_full_capture: business + enterprise = 2
		expect(occurrences(free, "Full-fidelity capture on every request")).toBe(2);
	});
});

// ---------------------------------------------------------------------------
// POSITIVE — what the customer can now read and do
// ---------------------------------------------------------------------------

describe("SET-15 — every tier is comparable in-app, at its enforced limits", () => {
	const html = renderLadder("builder");

	it("renders all five hosted tiers plus the audit add-on", () => {
		for (const name of [
			"Free hosted",
			"Builder",
			"Team",
			"Business",
			"Enterprise",
			"Audit ledger",
		]) {
			expect(html).toContain(name);
		}
	});

	it("shows the real enforced quota per tier, not marketing prose", () => {
		// These literals are the current product limits. They are asserted as
		// literals ON PURPOSE: if `PLAN_ENTITLEMENTS` (and with it the quota the
		// gateway enforces) changes, this test fails and the change has to be a
		// decision, not a drift.
		expect(html).toContain("10K traces/mo"); // free
		expect(html).toContain("150K traces/mo"); // builder
		expect(html).toContain("1M traces/mo"); // team
		expect(html).toContain("5M traces/mo"); // business
		// Enterprise volume is a negotiated floor, so it reads "25M+".
		expect(html).toContain("25M+ traces/mo"); // enterprise

		// RETENTION IS NOT PER-PLAN, AND THIS TEST USED TO ENFORCE THAT IT WAS.
		// It asserted "7-day trace retention" ... "365-day trace retention" — five
		// strings rendered from `ent.retention_days`, a value computed from the plan
		// catalog and consumed by renderers ONLY. No delete, reject or limit path
		// reads it; prod applies ONE window to every tenant, the `spans` TTL
		// (`toDate(start_time) + toIntervalDay(365)`, read from `system.tables`).
		// So the test was pinning a claim the product does not honour, which is how
		// the copy survived review: changing it broke a green test.
		expect(html).toContain("Traces kept up to 365 days");
		// And the old shape must not come back. A per-plan retention string here is
		// a customer-visible assertion of a control that has no enforcement site.
		for (const stale of [
			"7-day trace retention",
			"30-day trace retention",
			"90-day trace retention",
			"180-day trace retention",
			"365-day trace retention",
		]) {
			expect(html).not.toContain(stale);
		}

		expect(html).toContain("1 seat"); // free + builder
		expect(html).toContain("10 seats included, up to 25"); // team
		expect(html).toContain("25 seats included, up to 50"); // business
		expect(html).toContain("Uncapped seats"); // enterprise
	});

	it("states the overage terms the meter actually applies", () => {
		expect(html).toContain(
			"No overage billing — requests return 429 past the monthly quota",
		); // free: 1x cap, $0
		expect(html).toContain("$1.20 per 10K traces past quota, hard cap at 5×");
	});

	it("carries the list prices", () => {
		for (const price of [
			"$0",
			"$59/mo",
			"$249/mo",
			"$899/mo",
			"From $2,999/mo",
		])
			expect(html).toContain(price);
		expect(html).toContain("+$999/mo");
		// never presented as a confirmed charge
		expect(html).toContain("list price");
	});

	it("marks exactly one column as the viewer's current plan", () => {
		expect(html.split('data-current="true"').length - 1).toBe(1);
		expect(html).toContain('data-plan="builder" data-current="true"');
		expect(html).toContain("Current plan");
	});

	it("moves the current-plan marker with the viewer's plan", () => {
		expect(renderLadder("business")).toContain(
			'data-plan="business" data-current="true"',
		);
		expect(renderLadder("business")).not.toContain(
			'data-plan="builder" data-current="true"',
		);
	});
});

describe("SET-15 — a customer can act on the comparison without leaving", () => {
	const html = renderLadder("free");

	it("offers a self-serve checkout on every self-serve tier", () => {
		for (const tier of ["builder", "team", "business"]) {
			expect(html).toContain(`action="/api/checkout?tier=${tier}"`);
		}
	});

	it("never offers a checkout for Enterprise (sales-led) or Free", () => {
		expect(html).not.toContain('action="/api/checkout?tier=enterprise"');
		expect(html).not.toContain('action="/api/checkout?tier=free"');
		expect(html).toContain(
			"mailto:sales@tracelane.dev?subject=Tracelane%20Enterprise",
		);
	});

	it("does not offer to sell the viewer the plan they are already on", () => {
		const onTeam = renderLadder("team");
		expect(onTeam).not.toContain('action="/api/checkout?tier=team"');
		expect(onTeam).toContain('action="/api/checkout?tier=business"');
	});
});

describe("SET-15 — a workspace override is shown as the customer's real number", () => {
	const overridden: Entitlements = {
		...PLAN_ENTITLEMENTS.team,
		seat_cap_included: 40,
		seat_cap_max: 60,
		trace_quota_monthly: 3_000_000,
	};

	it("renders the override, not the stock plan default, on the current plan", () => {
		const html = renderLadder("team", overridden);
		expect(html).toContain("40 seats included, up to 60");
		expect(html).toContain("3M traces/mo");
		// the stock Team figures are gone from the Team column
		expect(html).not.toContain("10 seats included, up to 25");
	});

	it("tells the customer their limits are custom rather than silently differing", () => {
		expect(renderLadder("team", overridden)).toContain(
			"Your workspace has custom limits",
		);
	});

	it("shows no custom-limits note for a stock workspace", () => {
		expect(renderLadder("team", PLAN_ENTITLEMENTS.team)).not.toContain(
			"Your workspace has custom limits",
		);
		expect(hasCustomLimits("team", PLAN_ENTITLEMENTS.team)).toBe(false);
	});

	it("leaves the OTHER tiers on stock defaults — an override says nothing about them", () => {
		const html = renderLadder("team", overridden);
		expect(html).toContain("25 seats included, up to 50"); // business, untouched
		expect(html).toContain("150K traces/mo"); // builder, untouched
	});
});

describe("SET-15 — derivation helpers", () => {
	it("formats quotas the way a customer reads them", () => {
		expect(formatQuota(10_000)).toBe("10K");
		expect(formatQuota(150_000)).toBe("150K");
		expect(formatQuota(1_000_000)).toBe("1M");
		expect(formatQuota(25_000_000)).toBe("25M");
		expect(formatQuota(1_500_000)).toBe("1.5M");
		expect(formatQuota(900)).toBe("900");
	});

	it("calls a 1x cap what it is — no overage to bill", () => {
		expect(formatOverage(1.0, 0)).toContain("No overage billing");
		expect(formatOverage(1.0, 0)).toContain("429");
	});

	it("states the multiplier and the 429 for a real overage tier", () => {
		expect(formatOverage(5.0, 1.2)).toBe(
			"$1.20 per 10K traces past quota, hard cap at 5× then 429",
		);
	});
});

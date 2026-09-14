/**
 * SET-15 / ADR-076 — rendered proof of the in-app plans page.
 *
 * The end state under test is *not* "a component exists". It is: a signed-in
 * customer can compare every plan INSIDE the product, at the six-meter ruled
 * model's real figures, see which one is theirs, and start a self-serve
 * upgrade — without being sent to the marketing site. So these tests render
 * the real DOM (`renderToStaticMarkup`, node env) and assert what a customer
 * would read off the screen, against `PLANS_V3` (the JSON), never a literal
 * copy of it (`.claude/rules/reference-tables.md`).
 *
 * Negative cases first (`.claude/rules/testing.md`): the copy that must NOT
 * appear, and the off-product link that must NOT come back.
 */

import { PLANS_V3 } from "@/lib/entitlements";
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
	LADDER,
	LADDER_FOOTNOTES,
	buildLadder,
	formatGb,
	formatPrice,
} from "./plan-catalog";

const h = createElement;

const renderLadder = (currentPlan: string | null): string =>
	renderToStaticMarkup(h(PlanLadder, { cards: buildLadder(), currentPlan }));

// ---------------------------------------------------------------------------
// NEGATIVE — what must never appear
// ---------------------------------------------------------------------------

describe("SET-15 — the plan comparison must not leave the product", () => {
	it("the billing-page affordance points at the in-app /plans route, not the marketing site", () => {
		const html = renderToStaticMarkup(h(PlansLink, {}));
		expect(html).toContain('href="/plans"');
		expect(html).not.toContain("tracelane.dev");
		expect(html).not.toContain("#pricing");
		expect(html).not.toContain("http");
	});

	it("the ladder itself never links out to marketing pricing", () => {
		const html = renderLadder("builder");
		expect(html).not.toContain("https://tracelane.dev");
		expect(html).not.toContain("http://tracelane.dev");
		expect(html).not.toContain("#pricing");
	});
});

describe("SET-15 — honesty locks hold in the rendered copy", () => {
	const html = renderLadder("team");

	it('never says "discount", "% off" or "save" (spec BILL-01 §0.1)', () => {
		const lowered = html.toLowerCase();
		expect(lowered).not.toContain("discount");
		expect(lowered).not.toContain("% off");
		expect(lowered).not.toContain("save ");
	});

	it("Free never advertises unlimited seats; every paid tier does", () => {
		expect(renderLadder("free")).toContain('data-plan="free"');
		const freeRow = renderLadder("free");
		// Free's row block contains "1" for seats, not "Unlimited", somewhere
		// before the next tier starts.
		const freeIdx = freeRow.indexOf('data-plan="free"');
		const builderIdx = freeRow.indexOf('data-plan="builder"');
		const freeBlock = freeRow.slice(freeIdx, builderIdx);
		expect(freeBlock).not.toContain("Unlimited");
		for (const plan of ["builder", "team", "business", "enterprise"] as const) {
			expect(PLANS_V3.plans[`${plan}_v1`]?.unlimited_seats).toBe(true);
		}
	});
});

// ---------------------------------------------------------------------------
// POSITIVE — what the customer can now read and do
// ---------------------------------------------------------------------------

describe("SET-15 — every tier is comparable in-app, at the ruled model's figures", () => {
	const html = renderLadder("builder");

	it("renders all five hosted tiers", () => {
		for (const name of ["Free", "Builder", "Team", "Business", "Enterprise"]) {
			expect(html).toContain(name);
		}
	});

	it("shows the real included allowances per tier, straight from plans.v3.json", () => {
		for (const key of Object.keys(PLANS_V3.plans)) {
			const row = PLANS_V3.plans[key];
			if (!row) continue;
			expect(html).toContain(formatGb(row.hot_gb_included));
			expect(html).toContain(formatGb(row.ingest_gb_included));
		}
	});

	it("carries the monthly list prices from the JSON", () => {
		for (const plan of LADDER) {
			const row = PLANS_V3.plans[`${plan}_v1`];
			if (!row) continue;
			const price = formatPrice(row, "month");
			expect(html).toContain(price.amount);
		}
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

	it("renders the never-metered card and the three footnotes", () => {
		for (const item of PLANS_V3.meters.never_metered) {
			expect(html).toContain(item);
		}
		for (const note of LADDER_FOOTNOTES) {
			expect(html).toContain(note);
		}
	});
});

describe("SET-15 — a customer can act on the comparison without leaving", () => {
	const html = renderLadder("free");

	it("offers a self-serve checkout on every self-serve tier, carrying the interval", () => {
		for (const tier of ["builder", "team", "business"]) {
			expect(html).toContain(
				`action="/api/checkout?tier=${tier}&amp;interval=month"`,
			);
		}
	});

	it("never offers a checkout for Enterprise (sales-led) or Free", () => {
		expect(html).not.toContain('action="/api/checkout?tier=enterprise');
		expect(html).not.toContain('action="/api/checkout?tier=free');
		expect(html).toContain(
			"mailto:sales@tracelane.dev?subject=Tracelane%20Enterprise",
		);
	});

	it("does not offer to sell the viewer the plan they are already on", () => {
		const onTeam = renderLadder("team");
		expect(onTeam).not.toContain('action="/api/checkout?tier=team&');
		expect(onTeam).toContain('action="/api/checkout?tier=business&');
	});
});

describe("SET-15 — derivation helpers", () => {
	it("formats GB the way a customer reads them", () => {
		expect(formatGb(0.25)).toBe("0.25 GB");
		expect(formatGb(5)).toBe("5 GB");
		expect(formatGb(1500)).toBe("1.5 TB");
		expect(formatGb(null)).toBe("custom");
	});

	it("Enterprise reads 'from $X', every other paid tier a flat price", () => {
		const ent = PLANS_V3.plans.enterprise_v1;
		expect(ent).toBeDefined();
		if (!ent) return;
		expect(formatPrice(ent, "month").fromLabel).toBe(true);
		const builder = PLANS_V3.plans.builder_v1;
		expect(builder).toBeDefined();
		if (!builder) return;
		expect(formatPrice(builder, "month").fromLabel).toBe(false);
	});
});

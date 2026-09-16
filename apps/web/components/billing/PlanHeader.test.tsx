/**
 * BILL-02 §4 — the billing header renders ONE plan for an annual tenant, and
 * the refusal banner for every half-state (rendered markup, TRAPS §34).
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { PlanHeader } from "./PlanCard";

function render(props: Parameters<typeof PlanHeader>[0]): string {
	return renderToStaticMarkup(createElement(PlanHeader, props));
}

describe("PlanHeader — annual pair (BILL-02)", () => {
	it("P1: a healthy annual tenant sees ONE plan, 'paid through', 'usage billed monthly', no banner, no 'Switch to annual'", () => {
		const html = render({
			plan: "team",
			billingInterval: "year",
			annual: { basePeriodEnd: "2027-09-14T00:00:00Z", alert: null },
		});
		expect(html).toContain("Current plan");
		expect(html).toContain("paid through 2027-09-14");
		expect(html).toContain("usage billed monthly");
		expect(html).not.toContain("annual-pair-alert");
		expect(html).not.toContain("Switch to annual");
	});

	it.each([
		["annual_pair_usage_missing", "usage billing is still being set up"],
		["annual_pair_base_lapsed", "annual base has lapsed"],
		["annual_pair_mismatch", "do not match"],
	])(
		"refused pair (%s): the tenant is on Free and the banner names it",
		(alert, phrase) => {
			const html = render({
				plan: "free",
				billingInterval: "year",
				annual: { basePeriodEnd: "2027-09-14T00:00:00Z", alert },
			});
			expect(html).toContain('data-testid="annual-pair-alert"');
			expect(html).toContain(phrase);
			expect(html).toContain("Free plan");
		},
	);

	it("a monthly tenant is unchanged: 'billed monthly', no annual badge, no banner", () => {
		const html = render({ plan: "team", billingInterval: "month" });
		expect(html).toContain("billed monthly");
		expect(html).not.toContain("paid through");
		expect(html).not.toContain("annual-pair-alert");
	});
});

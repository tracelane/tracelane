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

	it("B-431: a cancel at period end says when the plan ENDS and that it is kept until then; nothing scheduled → no note", () => {
		const html = render({
			plan: "builder",
			billingInterval: "month",
			subscriptionEndsAt: "2026-10-19T09:08:42.465Z",
		});
		expect(html).toContain("Cancels on 2026-10-19");
		expect(html).toContain("you keep Builder until then");
		expect(html).toContain('data-testid="subscription-ends-note"');
		const none = render({ plan: "builder", billingInterval: "month" });
		expect(none).not.toContain("subscription-ends-note");
		// Free never renders a scheduled end (there is no plan to keep).
		const free = render({
			plan: "free",
			billingInterval: null,
			subscriptionEndsAt: "2026-10-19T09:08:42.465Z",
		});
		expect(free).not.toContain("subscription-ends-note");
	});

	it("a monthly tenant is unchanged: 'billed monthly', no annual badge, no banner", () => {
		const html = render({ plan: "team", billingInterval: "month" });
		expect(html).toContain("billed monthly");
		expect(html).not.toContain("paid through");
		expect(html).not.toContain("annual-pair-alert");
	});
});

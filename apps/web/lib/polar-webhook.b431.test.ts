/**
 * B-431 — found by B7 stage 2 on PROD (2026-09-19, subscription dfc2235e…):
 * a customer who cancels AT PERIOD END lost their paid plan the moment they
 * clicked, and a customer who then UNCANCELED stayed on Free.
 *
 * Polar's semantics (polar.sh/docs, webhooks): `subscription.canceled` is sent
 * when the customer cancels — the subscription STAYS `active` until
 * `ends_at` (= `current_period_end`) and `cancel_at_period_end` is true;
 * `subscription.revoked` is when access actually ends (status `canceled`);
 * `subscription.uncanceled` is the customer changing their mind.
 *
 * Our resolver matched `/canceled|revoked/` against the EVENT NAME, so both
 * `subscription.canceled` and `subscription.UNcanceled` resolved to Free.
 * Observed on prod: plan builder → cancel_at_period_end=true → tenants.plan
 * `free` at 09:11:41 with ends_at 2026-10-19; uncancel → still `free`.
 */
import { describe, expect, it } from "vitest";
import { resolvePlan } from "./polar-webhook";

describe("B-431: cancel-at-period-end keeps the paid plan until it ends", () => {
	it("subscription.canceled with status ACTIVE (cancel_at_period_end) resolves to the PAID plan, not free", () => {
		const r = resolvePlan({
			eventType: "subscription.canceled",
			status: "active",
			lookupKey: "builder_v1",
		});
		expect(r.kind).toBe("plan");
		if (r.kind === "plan") expect(r.planEnum).toBe("builder");
	});

	it("subscription.UNcanceled with status active resolves to the paid plan (the word contains 'canceled')", () => {
		const r = resolvePlan({
			eventType: "subscription.uncanceled",
			status: "active",
			lookupKey: "team_v1",
		});
		expect(r.kind).toBe("plan");
		if (r.kind === "plan") expect(r.planEnum).toBe("team");
	});

	it("subscription.revoked → free (access actually ended)", () => {
		expect(
			resolvePlan({
				eventType: "subscription.revoked",
				status: "canceled",
				lookupKey: "builder_v1",
			}).kind,
		).toBe("free");
	});

	it("a status of canceled / revoked / unpaid → free whatever the event name", () => {
		for (const status of ["canceled", "revoked", "unpaid"]) {
			expect(
				resolvePlan({
					eventType: "subscription.updated",
					status,
					lookupKey: "builder_v1",
				}).kind,
			).toBe("free");
		}
	});

	it("subscription.canceled with a NON-active status (Polar ended it in the same event) → free", () => {
		expect(
			resolvePlan({
				eventType: "subscription.canceled",
				status: "canceled",
				lookupKey: "builder_v1",
			}).kind,
		).toBe("free");
	});
});

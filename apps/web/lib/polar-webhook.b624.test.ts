/**
 * B-624 — found by the B-133 billing review (2026-11-12, High): `resolvePlan`
 * resolved a known lookup key to the PAID plan for every status except
 * canceled / revoked / unpaid. So a subscription whose first payment had not
 * succeeded (`incomplete`) or had failed for good (`incomplete_expired`)
 * granted the paid tier in Neon, while the reconciler (`classifyLive`) treats
 * those as not held. An entitlement granted on an unpaid subscription is the
 * inverted fail-direction CLAUDE.md §10 and `.claude/rules/tenancy.md` forbid.
 *
 * The rule now: only a HELD status (active, trialing, past_due — the same set
 * `classifyLive` uses) keeps the paid plan; any other KNOWN-to-be-present
 * status resolves to free. A missing status keeps the previous behaviour
 * (events without a status field are not subscription state changes).
 */
import { describe, expect, it, vi } from "vitest";
import { classifyLive, resolvePlan } from "./polar-webhook";

const ev = (
	status: string | null,
	key = "team_v1",
	eventType = "subscription.updated",
) => resolvePlan({ eventType, status, lookupKey: key });

describe("B-624: a plan is granted only on a HELD subscription status", () => {
	it("status incomplete resolves to free, never the paid plan", () => {
		expect(ev("incomplete").kind).toBe("free");
		expect(ev("incomplete", "builder_v1", "subscription.created").kind).toBe(
			"free",
		);
	});

	it("status incomplete_expired resolves to free, never the paid plan", () => {
		expect(ev("incomplete_expired").kind).toBe("free");
		expect(
			ev("incomplete_expired", "builder_v1", "subscription.created").kind,
		).toBe("free");
	});

	it("an incomplete annual half resolves to free (the pair path places it by key)", () => {
		expect(ev("incomplete", "team_v1_base_year").kind).toBe("free");
		expect(ev("incomplete", "team_v1_usage_month").kind).toBe("free");
	});

	it("an unrecognised future status resolves to free (fail closed), not the paid plan", () => {
		expect(ev("paused").kind).toBe("free");
		expect(ev("some_new_polar_status").kind).toBe("free");
	});

	it("an unrecognised status is logged once with its value; a known one is not", () => {
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		try {
			ev("paused");
			expect(warn).toHaveBeenCalledTimes(1);
			expect(String(warn.mock.calls[0]?.[1])).toBe("paused");
			warn.mockClear();
			for (const s of ["incomplete", "canceled", "active", "past_due"]) ev(s);
			ev(null);
			expect(warn).not.toHaveBeenCalled();
		} finally {
			warn.mockRestore();
		}
	});

	it("an empty-string status resolves to free, not the paid plan", () => {
		expect(ev("").kind).toBe("free");
	});

	it("status active keeps the paid plan", () => {
		const r = ev("active");
		expect(r.kind === "plan" && r.planEnum).toBe("team");
	});

	it("status trialing keeps the paid plan", () => {
		const r = ev("trialing");
		expect(r.kind === "plan" && r.planEnum).toBe("team");
	});

	it("status past_due keeps the paid plan (the webhook holds it through dunning)", () => {
		const r = ev("past_due");
		expect(r.kind === "plan" && r.planEnum).toBe("team");
	});

	it("a missing status keeps the previous behaviour: the key decides", () => {
		const r = ev(null);
		expect(r.kind).toBe("plan");
	});

	it("the resolver and the reconciler agree on every status: plan granted ⇔ subscription held", () => {
		for (const status of [
			"active",
			"trialing",
			"past_due",
			"incomplete",
			"incomplete_expired",
			"canceled",
			"revoked",
			"unpaid",
			"paused",
		]) {
			const granted = ev(status).kind === "plan";
			const held =
				classifyLive([
					{
						id: "s",
						status,
						customer_id: "c",
						product_id: "p",
						product: { metadata: { lookup_key: "team_v1" } },
					},
				]).single !== null;
			expect(granted, status).toBe(held);
		}
	});

	it("an unknown lookup key with a held status stays unknown (no plan change)", () => {
		expect(ev("active", "audit_addon_v1").kind).toBe("unknown");
	});
});

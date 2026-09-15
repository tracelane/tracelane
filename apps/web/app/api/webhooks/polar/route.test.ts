/**
 * Tests for POST /api/webhooks/polar.
 *
 * Covers: 503 when unconfigured, 401 on bad signature, 200 + plan applied on a
 * valid subscription event, 200 (no-op) on an unknown plan key, and idempotent
 * 200 on redelivery (the dedup row short-circuits before any side effect).
 *
 * The DB is mocked (makeDbMock queues one result per awaited query chain), so
 * each test scripts the exact read/write sequence the handler performs.
 */

import crypto from "node:crypto";
import { type DbMock, makeDbMock } from "@/lib/__testutils__/db-mock";
import type { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ db: null as DbMock | null }));

vi.mock("@/db", () => ({
	get db() {
		if (!h.db) throw new Error("db mock not initialised");
		return h.db.db;
	},
}));

import { POST } from "./route";

// Polar's secret is `polar_whs_<…>` and it keys the HMAC with the raw UTF-8
// bytes of the WHOLE secret string (see lib/polar-webhook.ts) — that's how
// Polar signs, so the test signs the same way (independent of our decoder).
const SECRET_ENV = "polar_whs_unit_test_do_not_use_in_prod";
const HMAC_KEY = Buffer.from(SECRET_ENV, "utf-8");
const ORG = "org_polar_test";
const TENANT_DB_ID = "11111111-2222-3333-4444-555555555555";

const SAVED = {
	secret: process.env.POLAR_WEBHOOK_SECRET,
	org: process.env.POLAR_EXPECTED_ORGANIZATION_ID,
};

function setDb(results: unknown[]): void {
	h.db = makeDbMock(results);
}

function makeReq(
	body: string,
	opts: { signedBody?: string; ts?: number } = {},
): NextRequest {
	const webhookId = "msg_test_1";
	const ts = String(opts.ts ?? Math.floor(Date.now() / 1000));
	const signed = `${webhookId}.${ts}.${opts.signedBody ?? body}`;
	const sig = `v1,${crypto.createHmac("sha256", HMAC_KEY).update(signed).digest("base64")}`;
	const headers = new Headers({
		"webhook-id": webhookId,
		"webhook-timestamp": ts,
		"webhook-signature": sig,
	});
	return { headers, text: async () => body } as unknown as NextRequest;
}

// Polar's real envelope is `{ type, timestamp, data }` — NO top-level `id`
// (the delivery id is the webhook-id header). Tests use that exact shape so the
// "200 applies plan" case doubles as the regression guard for the malformed-
// shape 400 we hit at E2E.
function subEvent(overrides: Record<string, unknown> = {}): string {
	return JSON.stringify({
		type: "subscription.created",
		timestamp: "2026-06-06T06:00:00Z",
		data: {
			id: "sub_1",
			customer_id: "cust_1",
			status: "active",
			customer: { external_id: "ten_1" },
			// Polar's Subscription has NO top-level organization_id — the org id
			// (matched by the cross-check) lives on the nested product.
			product: { organization_id: ORG, metadata: { lookup_key: "team_v1" } },
			...overrides,
		},
	});
}

describe("POST /api/webhooks/polar", () => {
	beforeEach(() => {
		process.env.POLAR_WEBHOOK_SECRET = SECRET_ENV;
		process.env.POLAR_EXPECTED_ORGANIZATION_ID = ORG;
		h.db = null;
	});
	afterEach(() => {
		if (SAVED.secret === undefined)
			Reflect.deleteProperty(process.env, "POLAR_WEBHOOK_SECRET");
		else process.env.POLAR_WEBHOOK_SECRET = SAVED.secret;
		if (SAVED.org === undefined)
			Reflect.deleteProperty(process.env, "POLAR_EXPECTED_ORGANIZATION_ID");
		else process.env.POLAR_EXPECTED_ORGANIZATION_ID = SAVED.org;
	});

	it("503 when POLAR_WEBHOOK_SECRET is unset (fails closed)", async () => {
		Reflect.deleteProperty(process.env, "POLAR_WEBHOOK_SECRET");
		const res = await POST(makeReq(subEvent()));
		expect(res.status).toBe(503);
	});

	it("401 on a bad signature", async () => {
		// Sign over a different body than we send → HMAC mismatch.
		const res = await POST(makeReq(subEvent(), { signedBody: "{}" }));
		expect(res.status).toBe(401);
	});

	it("400 on a malformed envelope (missing type) — id absence is fine, type is required", async () => {
		// A correctly-signed body with no `type`: rejected at the shape check,
		// before any DB call. (A missing top-level `id` is NOT a failure — Polar
		// omits it; the "200 applies plan" case proves that.)
		const res = await POST(
			makeReq(
				JSON.stringify({ timestamp: "t", data: { organization_id: ORG } }),
			),
		);
		expect(res.status).toBe(400);
	});

	it("200 and applies the plan on a valid subscription event", async () => {
		setDb([
			[], // dedup select → not seen
			// tenant select → found. priceProtectedUntil already set (an existing
			// paying customer) so this exercise does not also need to stub the
			// first-paid-activation reads — those get their own dedicated test.
			[{ id: "ten_1", priceProtectedUntil: new Date("2020-01-01T00:00:00Z") }],
			[], // update tenants
			[], // upsert workspace_entitlements
			[], // record webhook_events
		]);
		const res = await POST(makeReq(subEvent()));
		expect(res.status).toBe(200);
		expect(h.db?.db.update).toHaveBeenCalledTimes(1); // tenants update ran
		expect(h.db?.db.insert).toHaveBeenCalledTimes(2); // ws upsert + dedup record
		// subEvent()'s default status is "active" — dunning is explicitly cleared.
		const setArg = h.db?.setCalls[0]?.[0] as { dunningStartedAt?: unknown };
		expect(setArg?.dunningStartedAt).toBeNull();
	});

	it("ADR-076: first paid activation sets price_protected_until + price_version, read from the DB", async () => {
		setDb([
			[], // dedup select → not seen
			[{ id: "ten_1", plan: "free", priceProtectedUntil: null }], // tenant select
			[{ value: 12 }], // billing_policy.price_protection_months
			[{ priceVersion: "v3" }], // pricing_rates WHERE is_current
			[], // update tenants
			[], // upsert workspace_entitlements
			[], // record webhook_events
		]);
		const res = await POST(makeReq(subEvent()));
		expect(res.status).toBe(200);
		const setArg = h.db?.setCalls[0]?.[0] as {
			priceProtectedUntil?: Date;
			priceVersion?: string;
			billingInterval?: string;
		};
		expect(setArg?.priceVersion).toBe("v3");
		expect(setArg?.billingInterval).toBe("month");
		expect(setArg?.priceProtectedUntil).toBeInstanceOf(Date);
	});

	it("ADR-076: subscription.past_due starts the dunning clock; plan is UNCHANGED", async () => {
		setDb([
			[], // dedup select
			[
				{
					id: "ten_1",
					plan: "team",
					priceProtectedUntil: new Date("2020-01-01T00:00:00Z"),
				},
			],
			[], // update tenants
			[], // upsert workspace_entitlements
			[], // record webhook_events
		]);
		const res = await POST(
			makeReq(
				subEvent({ status: "past_due", modified_at: "2026-09-13T00:00:00Z" }),
			),
		);
		expect(res.status).toBe(200);
		const setArg = h.db?.setCalls[0]?.[0] as {
			plan?: string;
			dunningStartedAt?: Date;
		};
		expect(setArg?.plan).toBe("team"); // ingest never blocked — plan unchanged
		expect(setArg?.dunningStartedAt).toBeInstanceOf(Date);
	});

	it("ADR-076: .unpaid drops the tenant to free and sets data_hold_until from billing_policy", async () => {
		setDb([
			[], // dedup select
			[
				{
					id: "ten_1",
					plan: "team",
					priceProtectedUntil: new Date("2020-01-01T00:00:00Z"),
				},
			],
			[{ value: 30 }], // billing_policy.dunning_data_hold_days
			[], // update tenants
			[], // upsert workspace_entitlements
			[], // record webhook_events
		]);
		const res = await POST(
			makeReq(
				subEvent({ status: "unpaid", modified_at: "2026-09-13T00:00:00Z" }),
			),
		);
		expect(res.status).toBe(200);
		const setArg = h.db?.setCalls[0]?.[0] as {
			plan?: string;
			dataHoldUntil?: Date;
		};
		expect(setArg?.plan).toBe("free");
		expect(setArg?.dataHoldUntil).toBeInstanceOf(Date);
	});

	it("re-cancelling an already-free tenant does not re-arm the data-hold clock", async () => {
		setDb([
			[], // dedup select
			[
				{
					id: "ten_1",
					plan: "free",
					priceProtectedUntil: new Date("2020-01-01T00:00:00Z"),
				},
			],
			[], // update tenants (no policy read — planValue===free already)
			[], // upsert workspace_entitlements
			[], // record webhook_events
		]);
		const res = await POST(
			makeReq(
				subEvent({ status: "canceled", modified_at: "2026-09-13T00:00:00Z" }),
			),
		);
		expect(res.status).toBe(200);
		const setArg = h.db?.setCalls[0]?.[0] as { dataHoldUntil?: unknown };
		expect(setArg?.dataHoldUntil).toBeUndefined();
	});

	it("B-410: the subscription cycle (current_period_start/end) lands on the tenant", async () => {
		setDb([
			[], // dedup select
			[{ id: "ten_1", priceProtectedUntil: new Date("2020-01-01T00:00:00Z") }],
			[], // update tenants
			[], // upsert workspace_entitlements
			[], // record webhook_events
		]);
		const res = await POST(
			makeReq(
				subEvent({
					current_period_start: "2026-09-14T10:00:00Z",
					current_period_end: "2026-10-14T10:00:00Z",
				}),
			),
		);
		expect(res.status).toBe(200);
		const setArg = h.db?.setCalls[0]?.[0] as {
			currentPeriodStart?: unknown;
			currentPeriodEnd?: unknown;
		};
		expect(setArg?.currentPeriodStart).toEqual(
			new Date("2026-09-14T10:00:00Z"),
		);
		expect(setArg?.currentPeriodEnd).toEqual(new Date("2026-10-14T10:00:00Z"));
	});

	it("B-410: a malformed or absent cycle is never written as a bogus date", async () => {
		setDb([
			[],
			[{ id: "ten_1", priceProtectedUntil: new Date("2020-01-01T00:00:00Z") }],
			[],
			[],
			[],
		]);
		const res = await POST(
			makeReq(
				subEvent({
					current_period_start: "not a date",
					current_period_end: 42,
				}),
			),
		);
		expect(res.status).toBe(200);
		const setArg = h.db?.setCalls[0]?.[0] as Record<string, unknown>;
		expect("currentPeriodStart" in setArg).toBe(false);
		expect("currentPeriodEnd" in setArg).toBe(false);
	});

	it("ADR-076: an annual (_year) lookup key sets billing_interval='year'", async () => {
		setDb([
			[], // dedup select
			[{ id: "ten_1", priceProtectedUntil: new Date("2020-01-01T00:00:00Z") }],
			[], // update tenants
			[], // upsert workspace_entitlements
			[], // record webhook_events
		]);
		const res = await POST(
			makeReq(
				subEvent({
					product: {
						organization_id: ORG,
						metadata: { lookup_key: "team_v1_year" },
					},
				}),
			),
		);
		expect(res.status).toBe(200);
		const setArg = h.db?.setCalls[0]?.[0] as { billingInterval?: string };
		expect(setArg?.billingInterval).toBe("year");
	});

	// B-388. HMAC + idempotency stop the SAME delivery twice; they say nothing
	// about two DIFFERENT events out of order. This is the review's exact
	// scenario: a `canceled` applied, then a stale retried `updated` (active).
	it("B-388: a stale `updated` after a `canceled` is acked and NOT applied", async () => {
		setDb([
			[], // dedup select → not seen
			// tenant select → found, and the last APPLIED clock is the cancel's
			[
				{
					id: "ten_1",
					plan: "free",
					polarSubscriptionModifiedAt: new Date("2026-09-12T10:00:05Z"),
				},
			],
			[], // record webhook_events
		]);
		const res = await POST(
			makeReq(
				subEvent({
					id: "sub_1",
					status: "active",
					modified_at: "2026-09-12T10:00:01Z", // OLDER than the cancel
				}),
			),
		);
		expect(res.status).toBe(200);
		expect(h.db?.db.update).not.toHaveBeenCalled(); // plan NOT re-activated
		expect(h.db?.db.insert).toHaveBeenCalledTimes(1); // only the dedup record
	});

	it("B-388: a NEWER event still applies and writes its clock", async () => {
		setDb([
			[], // dedup select
			[
				{
					id: "ten_1",
					plan: "free",
					polarSubscriptionModifiedAt: new Date("2026-09-12T10:00:01Z"),
					// Already price-protected — this test is about the CLOCK, not
					// first-paid-activation, which has its own dedicated test.
					priceProtectedUntil: new Date("2020-01-01T00:00:00Z"),
				},
			],
			[], // update tenants
			[], // upsert workspace_entitlements
			[], // record webhook_events
		]);
		const res = await POST(
			makeReq(subEvent({ modified_at: "2026-09-12T10:00:05Z" })),
		);
		expect(res.status).toBe(200);
		expect(h.db?.db.update).toHaveBeenCalledTimes(1);
		const setArg = h.db?.setCalls[0]?.[0] as
			| { polarSubscriptionModifiedAt?: Date }
			| undefined;
		expect(setArg?.polarSubscriptionModifiedAt?.toISOString()).toBe(
			"2026-09-12T10:00:05.000Z",
		);
	});

	it("200 and no plan change on an unknown plan key", async () => {
		setDb([
			[], // dedup select → not seen
			[], // record webhook_events
		]);
		const res = await POST(
			makeReq(
				subEvent({
					product: {
						organization_id: ORG,
						metadata: { lookup_key: "bogus_v1" },
					},
				}),
			),
		);
		expect(res.status).toBe(200);
		expect(h.db?.db.update).not.toHaveBeenCalled(); // no tenant mutation
		expect(h.db?.db.insert).toHaveBeenCalledTimes(1); // only the dedup record
	});

	// This test used to assert the no-op: an add-on lookup_key was
	// logged loudly and granted nothing, so a $999 Audit SKU purchase unlocked
	// nothing. wired `handleAddOnChange` to actually grant f_audit_addon,
	// which removed that log line and left this test red on a clean tree — a red
	// test on the payment path. It now asserts the GRANT, which is the behaviour
	// that must never regress.
	// ADR-076 / BILL-01 §10.4 (B-392): the Audit SKU is NOT SOLD and its Polar
	// product is archived. The add-on grant path (`handleAddOnChange`, B-131) was
	// DELETED on 2026-09-14 (founder: "no old code logic should exist"), so a
	// stray `audit_addon_v1` event is a plain unknown-key no-op: acked, nothing
	// written, `f_audit_addon` untouched. Re-selling the SKU means re-adding a
	// grant path, not un-archiving a product.
	it("an archived add-on (audit_addon_v1) is a plain unknown-key no-op — no grant path exists", async () => {
		const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
		setDb([[], []]); // dedup empty, record
		const res = await POST(
			makeReq(
				subEvent({
					product: {
						organization_id: ORG,
						metadata: { lookup_key: "audit_addon_v1" },
					},
				}),
			),
		);
		expect(res.status).toBe(200);
		expect(h.db?.db.update).not.toHaveBeenCalled();
		expect(h.db?.db.insert).not.toHaveBeenCalledWith(
			expect.objectContaining({ f_audit_addon: expect.anything() }),
		);
		expect(spy).toHaveBeenCalledWith(
			"[polar-webhook] unknown lookup_key — acked, no plan change:",
			expect.anything(),
		);
		spy.mockRestore();
	});

	// ADR-076: hipaa_gcp_addon_v1 (and the two seat SKUs) are RETIRED and
	// archived in Polar (`scripts/ops/polar-sync.mjs`) — the webhook no longer
	// recognises them as add-ons at all, so a stray legacy event for one falls
	// through to the generic "unknown lookup_key" path, exactly like any other
	// key nothing maps to. This replaces the old "LOUD no-op, needs manual ops"
	// behaviour, which was specific to a SKU this ruling retires outright.
	it("a retired SKU (hipaa_gcp_addon_v1) is now a plain unknown-key no-op", async () => {
		const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
		setDb([[], []]); // dedup empty, record
		const res = await POST(
			makeReq(
				subEvent({
					product: {
						organization_id: ORG,
						metadata: { lookup_key: "hipaa_gcp_addon_v1" },
					},
				}),
			),
		);
		expect(res.status).toBe(200);
		expect(h.db?.db.update).not.toHaveBeenCalled();
		expect(spy).toHaveBeenCalledWith(
			"[polar-webhook] unknown lookup_key — acked, no plan change:",
			expect.anything(),
		);
		spy.mockRestore();
	});

	it("idempotent: redelivery of the same webhook-id is a 200 no-op", async () => {
		setDb([
			[{ eventId: "msg_test_1" }], // dedup select (keyed on webhook-id) → already seen
		]);
		const res = await POST(makeReq(subEvent()));
		expect(res.status).toBe(200);
		expect(await res.json()).toMatchObject({ duplicate: true });
		expect(h.db?.db.update).not.toHaveBeenCalled();
		expect(h.db?.db.insert).not.toHaveBeenCalled(); // no second side effect
	});

	it("200-acks a NON-UUID external_id without touching tenants (no Polar retry loop)", async () => {
		// Malformed external_id + no customer_id: an invalid UUID previously hit
		// `eq(tenants.id, <garbage>)` -> driver error -> 5xx -> endless Polar
		// redelivery. Now it is treated as absent and acked.
		const m = makeDbMock([
			[], // dedup select -> not seen
			[], // record webhook_events (after dispatch)
		]);
		h.db = m;
		const res = await POST(
			makeReq(
				subEvent({
					customer_id: null,
					customer: { external_id: "42-not-a-uuid" },
				}),
			),
		);
		expect(res.status).toBe(200);
		// Only dedup + record ran -- the tenants table was never queried.
		expect(m.cursor()).toBe(2);
	});
});

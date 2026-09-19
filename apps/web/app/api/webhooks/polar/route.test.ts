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

	// ── B-431 (B7 stage 2 on PROD, 2026-09-19) ────────────────────────────────
	// Polar: `subscription.canceled` = the customer cancelled AT PERIOD END; the
	// subscription is STILL `active` until `ends_at`. We dropped them to Free at
	// once (and `subscription.uncanceled` kept them there).
	it("B-431: subscription.canceled with status active (cancel_at_period_end) KEEPS the plan and records subscription_ends_at", async () => {
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
				subEvent({
					type: "subscription.canceled",
					status: "active",
					cancel_at_period_end: true,
					ends_at: "2026-10-19T09:08:42.465805Z",
					current_period_start: "2026-09-19T09:08:42.465805Z",
					current_period_end: "2026-10-19T09:08:42.465805Z",
					modified_at: "2026-09-19T09:11:41Z",
				}),
			),
		);
		expect(res.status).toBe(200);
		const setArg = h.db?.setCalls[0]?.[0] as {
			plan?: string;
			polarSubscriptionId?: string | null;
			subscriptionEndsAt?: Date | null;
			dataHoldUntil?: unknown;
		};
		expect(setArg?.plan).toBe("team");
		expect(setArg?.polarSubscriptionId).toBe("sub_1");
		expect(setArg?.subscriptionEndsAt?.toISOString()).toBe(
			"2026-10-19T09:08:42.465Z",
		);
		expect(setArg?.dataHoldUntil).toBeNull();
	});

	it("B-431: subscription.uncanceled (status active) keeps the plan and CLEARS the scheduled end", async () => {
		setDb([
			[],
			[
				{
					id: "ten_1",
					plan: "team",
					priceProtectedUntil: new Date("2020-01-01T00:00:00Z"),
				},
			],
			[],
			[],
			[],
		]);
		const res = await POST(
			makeReq(
				subEvent({
					type: "subscription.uncanceled",
					status: "active",
					cancel_at_period_end: false,
					ends_at: null,
					modified_at: "2026-09-19T09:12:44Z",
				}),
			),
		);
		expect(res.status).toBe(200);
		const setArg = h.db?.setCalls[0]?.[0] as {
			plan?: string;
			subscriptionEndsAt?: Date | null;
		};
		expect(setArg?.plan).toBe("team");
		expect(setArg?.subscriptionEndsAt).toBeNull();
	});

	it("B-431: subscription.revoked (status canceled) is what ends the plan — free, data held, nothing scheduled", async () => {
		setDb([
			[],
			[
				{
					id: "ten_1",
					plan: "team",
					priceProtectedUntil: new Date("2020-01-01T00:00:00Z"),
				},
			],
			[{ value: 30 }], // billing_policy.dunning_data_hold_days
			[],
			[],
			[],
		]);
		const res = await POST(
			makeReq(
				subEvent({
					type: "subscription.revoked",
					status: "canceled",
					cancel_at_period_end: false,
					ends_at: "2026-09-19T09:13:10Z",
					ended_at: "2026-09-19T09:13:10Z",
					modified_at: "2026-09-19T09:13:10Z",
				}),
			),
		);
		expect(res.status).toBe(200);
		const setArg = h.db?.setCalls[0]?.[0] as {
			plan?: string;
			subscriptionEndsAt?: Date | null;
			dataHoldUntil?: Date;
		};
		expect(setArg?.plan).toBe("free");
		expect(setArg?.subscriptionEndsAt).toBeNull();
		expect(setArg?.dataHoldUntil).toBeInstanceOf(Date);
	});

	it("B-431: a paid activation after a lapse CLEARS the data-hold clock left by the lapse", async () => {
		setDb([
			[],
			[
				{
					id: "ten_1",
					plan: "free",
					priceProtectedUntil: new Date("2020-01-01T00:00:00Z"),
					dataHoldUntil: new Date("2026-10-19T00:00:00Z"),
				},
			],
			[],
			[],
			[],
		]);
		const res = await POST(
			makeReq(
				subEvent({
					type: "subscription.active",
					status: "active",
					modified_at: "2026-09-19T09:14:08Z",
				}),
			),
		);
		expect(res.status).toBe(200);
		const setArg = h.db?.setCalls[0]?.[0] as {
			plan?: string;
			dataHoldUntil?: unknown;
		};
		expect(setArg?.plan).toBe("team");
		expect(setArg?.dataHoldUntil).toBeNull();
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

	it("BILL-02: the retired one-object `_year` key is acked with NO plan change", async () => {
		setDb([
			[], // dedup select
			[{ id: "ten_1", priceProtectedUntil: new Date("2020-01-01T00:00:00Z") }],
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
		expect(h.db?.setCalls.length ?? 0).toBe(0);
	});

	// ── BILL-02 (founder ruling B14 → option (c)): the annual PAIR ──────────
	const baseEvent = (over: Record<string, unknown> = {}) =>
		subEvent({
			id: "sub_base",
			current_period_start: "2026-09-14T00:00:00Z",
			current_period_end: "2027-09-14T00:00:00Z",
			product: {
				organization_id: ORG,
				metadata: { lookup_key: "team_v1_base_year" },
			},
			...over,
		});
	const usageEvent = (over: Record<string, unknown> = {}) =>
		subEvent({
			id: "sub_usage",
			current_period_start: "2026-09-14T00:00:00Z",
			current_period_end: "2026-10-14T00:00:00Z",
			product: {
				organization_id: ORG,
				metadata: { lookup_key: "team_v1_usage_month" },
			},
			...over,
		});
	const tenantRow = (annualPair: unknown, plan: string | null = null) => [
		{
			id: "ten_1",
			plan,
			priceProtectedUntil: new Date("2020-01-01T00:00:00Z"),
			annualPair,
		},
	];
	const pairDb = (row: unknown[], extraReads: unknown[] = []) =>
		setDb([[], row, ...extraReads, [], [], []]); // dedup, tenant, (policy reads), update, upsert, record

	it("BILL-02 P2: the BASE arrives first (usage not yet created) → plan FREE, interval year, alert usage_missing, both ids as known", async () => {
		pairDb(tenantRow(null));
		const res = await POST(makeReq(baseEvent()));
		expect(res.status).toBe(200);
		const setArg = h.db?.setCalls[0]?.[0] as Record<string, unknown>;
		expect(setArg.plan).toBe("free");
		expect(setArg.billingInterval).toBe("year");
		expect(setArg.polarBaseSubscriptionId).toBe("sub_base");
		expect(setArg.polarUsageSubscriptionId).toBeNull();
		expect(setArg.polarSubscriptionId).toBeNull();
		expect((setArg.annualPair as { alert: string }).alert).toBe(
			"annual_pair_usage_missing",
		);
		expect(setArg.currentPeriodStart).toBeNull();
	});

	it("BILL-02 P1: the USAGE half arrives for a tenant holding an active base → the tier, interval year, the USAGE cycle as the period, alert null", async () => {
		pairDb(
			tenantRow({
				base: {
					id: "sub_base",
					plan: "team",
					status: "active",
					period_end: "2027-09-14T00:00:00Z",
				},
				alert: "annual_pair_usage_missing",
			}),
			[[{ value: 12 }], [{ priceVersion: "v3" }]], // price protection reads (first paid)
		);
		const res = await POST(makeReq(usageEvent()));
		expect(res.status).toBe(200);
		const setArg = h.db?.setCalls[0]?.[0] as Record<string, unknown>;
		expect(setArg.plan).toBe("team");
		expect(setArg.billingInterval).toBe("year");
		expect(setArg.currentPeriodStart).toEqual(new Date("2026-09-14T00:00:00Z"));
		expect(setArg.currentPeriodEnd).toEqual(new Date("2026-10-14T00:00:00Z"));
		expect(setArg.polarBaseSubscriptionId).toBe("sub_base");
		expect(setArg.polarUsageSubscriptionId).toBe("sub_usage");
		expect((setArg.annualPair as { alert: unknown }).alert).toBeNull();
		// ONE update statement carries plan + period + ids + pair (B-388's guard).
		expect(h.db?.setCalls.length).toBe(1);
	});

	it("BILL-02 P3: the BASE is canceled while usage is active → plan FREE, alert base_lapsed (a $0 usage subscription alone is the tier for free)", async () => {
		pairDb(
			tenantRow(
				{
					base: { id: "sub_base", plan: "team", status: "active" },
					usage: {
						id: "sub_usage",
						plan: "team",
						status: "active",
						period_start: "2026-09-14T00:00:00Z",
						period_end: "2026-10-14T00:00:00Z",
					},
					alert: null,
				},
				"team",
			),
			[[{ value: 30 }]], // dunning_data_hold_days (drop from a paid plan)
		);
		const res = await POST(
			makeReq(baseEvent({ status: "canceled", type: "subscription.canceled" })),
		);
		expect(res.status).toBe(200);
		const setArg = h.db?.setCalls[0]?.[0] as Record<string, unknown>;
		expect(setArg.plan).toBe("free");
		expect((setArg.annualPair as { alert: string }).alert).toBe(
			"annual_pair_base_lapsed",
		);
		expect(setArg.currentPeriodStart).toBeNull();
	});

	it("BILL-02 P4: the USAGE half arrives on a different plan than the base → plan FREE, alert mismatch", async () => {
		pairDb(
			tenantRow({
				base: { id: "sub_base", plan: "team", status: "active" },
			}),
		);
		const res = await POST(
			makeReq(
				usageEvent({
					product: {
						organization_id: ORG,
						metadata: { lookup_key: "builder_v1_usage_month" },
					},
				}),
			),
		);
		expect(res.status).toBe(200);
		const setArg = h.db?.setCalls[0]?.[0] as Record<string, unknown>;
		expect(setArg.plan).toBe("free");
		expect((setArg.annualPair as { alert: string }).alert).toBe(
			"annual_pair_mismatch",
		);
	});

	it("BILL-02 P6: a MONTHLY subscription arrives for a tenant that holds a pair → plan FREE, alert mismatch, the pair kept as evidence", async () => {
		pairDb(
			tenantRow(
				{
					base: { id: "sub_base", plan: "team", status: "active" },
					usage: { id: "sub_usage", plan: "team", status: "active" },
				},
				"team",
			),
			[[{ value: 30 }]],
		);
		const res = await POST(makeReq(subEvent({ id: "sub_monthly" })));
		expect(res.status).toBe(200);
		const setArg = h.db?.setCalls[0]?.[0] as Record<string, unknown>;
		expect(setArg.plan).toBe("free");
		expect((setArg.annualPair as { alert: string; base: unknown }).alert).toBe(
			"annual_pair_mismatch",
		);
		expect((setArg.annualPair as { base: { id: string } }).base.id).toBe(
			"sub_base",
		);
	});

	it("BILL-02 P5: the base renewal goes past_due while usage is active → the tier is KEPT and dunning starts, never a refusal", async () => {
		pairDb(
			tenantRow(
				{
					base: { id: "sub_base", plan: "team", status: "active" },
					usage: {
						id: "sub_usage",
						plan: "team",
						status: "active",
						period_start: "2026-09-14T00:00:00Z",
						period_end: "2026-10-14T00:00:00Z",
					},
				},
				"team",
			),
		);
		const res = await POST(
			makeReq(baseEvent({ status: "past_due", type: "subscription.updated" })),
		);
		expect(res.status).toBe(200);
		const setArg = h.db?.setCalls[0]?.[0] as Record<string, unknown>;
		expect(setArg.plan).toBe("team");
		expect(setArg.dunningStartedAt).toBeInstanceOf(Date);
		expect((setArg.annualPair as { alert: unknown }).alert).toBeNull();
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

	// ── O4 (founder ruling 2026-09-19): SYNCHRONOUS pairing inside the webhook ──
	//
	// The half-state P2 (base paid, usage not yet created) was observed for 51 s
	// in sandbox stage 1 and "the reconciler's cadence" in prod. With a Polar
	// token on the Worker the webhook creates the usage subscription BEFORE
	// responding. The resolver stays the ONLY thing that grants: even on success
	// the tenant is written `free` until the usage half's OWN event arrives.
	describe("BILL-02 O4: synchronous pairing on the base's active event", () => {
		const SAVED_TOKEN = process.env.POLAR_WORKER_TOKEN;
		const SAVED_SANDBOX = process.env.POLAR_SANDBOX;
		type FetchCall = {
			method: string;
			url: string;
			body?: unknown;
			bearer?: string;
		};

		afterEach(() => {
			if (SAVED_TOKEN === undefined)
				Reflect.deleteProperty(process.env, "POLAR_WORKER_TOKEN");
			else process.env.POLAR_WORKER_TOKEN = SAVED_TOKEN;
			if (SAVED_SANDBOX === undefined)
				Reflect.deleteProperty(process.env, "POLAR_SANDBOX");
			else process.env.POLAR_SANDBOX = SAVED_SANDBOX;
			vi.unstubAllGlobals();
		});

		/** A fake Polar reached through global fetch — the Worker has no client injection. */
		function fakePolar(opts: {
			liveSubs?: unknown[];
			cards?: unknown[];
			postStatus?: number;
			postBody?: string;
			hang?: boolean;
		}) {
			const calls: FetchCall[] = [];
			const fetchImpl = vi.fn(
				async (url: string | URL | Request, init?: RequestInit) => {
					const u = String(url);
					const method = init?.method ?? "GET";
					calls.push({
						method,
						url: u,
						body: init?.body ? JSON.parse(String(init.body)) : undefined,
					});
					if (opts.hang) {
						return new Promise<Response>((_resolve, reject) => {
							init?.signal?.addEventListener("abort", () =>
								reject(init.signal?.reason ?? new Error("aborted")),
							);
						});
					}
					const path = new URL(u).pathname + new URL(u).search;
					if (method === "GET" && path.startsWith("/v1/subscriptions/")) {
						return new Response(
							JSON.stringify({ items: opts.liveSubs ?? [] }),
							{
								status: 200,
							},
						);
					}
					if (method === "GET" && /\/payment-methods$/.test(path)) {
						return new Response(
							JSON.stringify({
								items: opts.cards ?? [{ id: "pm_card_1", type: "card" }],
							}),
							{ status: 200 },
						);
					}
					if (method === "POST" && path === "/v1/customer-sessions/") {
						return new Response(
							JSON.stringify({ token: "polar_cst_test_session" }),
							{ status: 201 },
						);
					}
					if (method === "PATCH") {
						// B-435: the portal PATCH must carry the SESSION token, never the
						// organisation token — recorded so the test can assert it.
						const auth = String(
							(init?.headers as Record<string, string> | undefined)
								?.authorization ?? "",
						);
						const last = calls[calls.length - 1];
						if (last) last.bearer = auth.replace(/^Bearer /, "");
						return new Response(
							JSON.stringify({ default_payment_method_id: "pm_card_1" }),
							{ status: 200 },
						);
					}
					if (method === "POST" && path === "/v1/subscriptions/") {
						return new Response(
							opts.postBody ??
								JSON.stringify({ id: "sub_usage_new", status: "active" }),
							{ status: opts.postStatus ?? 201 },
						);
					}
					return new Response("unexpected", { status: 500 });
				},
			);
			vi.stubGlobal("fetch", fetchImpl);
			return { calls, fetchImpl };
		}

		/** The bound params inside a drizzle `sql` template (the record/claim writes
		 *  merge jsonb): a primitive interpolated into the tag stays a primitive chunk
		 *  and is bound as a parameter when rendered; a `Param` object carries `.value`. */
		function sqlParams(v: unknown): unknown[] {
			const chunks = (v as { queryChunks?: unknown[] })?.queryChunks ?? [];
			return chunks.flatMap((c) => {
				if (typeof c === "string") return [c];
				if (c && typeof c === "object" && c.constructor?.name === "Param")
					return [(c as { value: unknown }).value];
				return [];
			});
		}
		function pairingOf(
			setArg: Record<string, unknown>,
		): Record<string, unknown> {
			const ap = setArg.annualPair as unknown;
			if (ap && typeof ap === "object" && !("queryChunks" in ap)) {
				return ((ap as { pairing?: Record<string, unknown> }).pairing ??
					{}) as Record<string, unknown>;
			}
			const json = sqlParams(ap).find((p) => typeof p === "string") as string;
			return (JSON.parse(json) as { pairing: Record<string, unknown> }).pairing;
		}

		const liveBase = {
			id: "sub_base",
			status: "active",
			customer_id: "cust_1",
			product_id: "prod_team_base_year",
			product: { metadata: { lookup_key: "team_v1_base_year" } },
		};
		const liveUsage = {
			id: "sub_usage_existing",
			status: "active",
			customer_id: "cust_1",
			product_id: "prod_team_usage",
			current_period_start: "2026-09-14T00:00:00Z",
			current_period_end: "2026-10-14T00:00:00Z",
			product: { metadata: { lookup_key: "team_v1_usage_month" } },
		};

		/** dedup · tenant · usage product id · deadline · claim (won) · P2 write · ws upsert · record · webhook_events */
		const pairingDb = (row: unknown[], deadlineMs = 6000) =>
			setDb([
				[],
				row,
				[{ polarProductIdUsageMonth: "prod_team_usage" }],
				[{ value: deadlineMs }],
				[{ id: "ten_1" }],
				[],
				[],
				[],
				[],
			]);

		it("FALSIFICATION (token UNSET): the planted half-state is REFUSED to free with the alert — never the tier — and no Polar call is made; one line says pairing is off", async () => {
			Reflect.deleteProperty(process.env, "POLAR_WORKER_TOKEN");
			const { fetchImpl } = fakePolar({});
			const info = vi.spyOn(console, "info").mockImplementation(() => {});
			pairDb(tenantRow(null));
			const res = await POST(makeReq(baseEvent()));
			expect(res.status).toBe(200);
			expect(h.db?.setCalls.length).toBe(1);
			const setArg = h.db?.setCalls[0]?.[0] as Record<string, unknown>;
			expect(setArg.plan).toBe("free");
			expect((setArg.annualPair as { alert: string }).alert).toBe(
				"annual_pair_usage_missing",
			);
			expect(setArg.polarUsageSubscriptionId).toBeNull();
			expect(fetchImpl).not.toHaveBeenCalled();
			expect(
				info.mock.calls.some((c) => c.join(" ").includes("POLAR_WORKER_TOKEN")),
			).toBe(true);
		});

		it("FALSIFICATION (token SET, Polar refuses the POST with 422): still free + alert, 200 to Polar, the reason logged with the tenant id, the attempt recorded as failed", async () => {
			process.env.POLAR_WORKER_TOKEN = "polar_oat_worker_test";
			const { calls } = fakePolar({
				liveSubs: [liveBase],
				postStatus: 422,
				postBody: '{"detail":"customer has no payment method"}',
			});
			const error = vi.spyOn(console, "error").mockImplementation(() => {});
			pairingDb(tenantRow(null));
			const res = await POST(makeReq(baseEvent()));
			expect(res.status).toBe(200);
			// claim · P2 state · record
			expect(h.db?.setCalls.length).toBe(3);
			const p2 = h.db?.setCalls[1]?.[0] as Record<string, unknown>;
			expect(p2.plan).toBe("free");
			expect((p2.annualPair as { alert: string }).alert).toBe(
				"annual_pair_usage_missing",
			);
			expect(calls.map((c) => c.method)).toEqual([
				"GET",
				"GET",
				"POST",
				"PATCH",
				"POST",
			]);
			const record = h.db?.setCalls[2]?.[0] as Record<string, unknown>;
			expect(record.polarUsageSubscriptionId).toBeUndefined();
			const pairing = pairingOf(record);
			expect(pairing.result).toBe("failed");
			expect(String(pairing.reason)).toContain("422");
			expect(
				error.mock.calls.some(
					(c) => c.join(" ").includes("ten_1") && c.join(" ").includes("422"),
				),
			).toBe(true);
		});

		it("happy path: PATCH default card BEFORE POST usage (asserted order), the right product for the plan on the same customer, the usage id stored, plan STILL free until the usage event", async () => {
			process.env.POLAR_WORKER_TOKEN = "polar_oat_worker_test";
			const { calls } = fakePolar({ liveSubs: [liveBase] });
			pairingDb(tenantRow(null));
			const res = await POST(makeReq(baseEvent()));
			expect(res.status).toBe(200);
			expect(calls.map((c) => [c.method, new URL(c.url).pathname])).toEqual([
				["GET", "/v1/subscriptions/"],
				["GET", "/v1/customers/cust_1/payment-methods"],
				["POST", "/v1/customer-sessions/"],
				["PATCH", "/v1/customer-portal/customers/me"],
				["POST", "/v1/subscriptions/"],
			]);
			expect(
				calls.every((c) => c.url.startsWith("https://api.polar.sh/")),
			).toBe(true);
			expect(calls[2]?.body).toEqual({ customer_id: "cust_1" });
			// B-435: the default card is set THROUGH THE PORTAL, as the customer.
			expect(calls[3]?.body).toEqual({
				default_payment_method_id: "pm_card_1",
			});
			expect(calls[3]?.bearer).toBe("polar_cst_test_session");
			expect(calls[4]?.body).toEqual({
				product_id: "prod_team_usage",
				customer_id: "cust_1",
			});
			const p2 = h.db?.setCalls[1]?.[0] as Record<string, unknown>;
			expect(p2.plan).toBe("free"); // NOT the tier on our own say-so
			expect(p2.polarUsageSubscriptionId).toBeNull();
			const record = h.db?.setCalls[2]?.[0] as Record<string, unknown>;
			expect(record.polarUsageSubscriptionId).toBe("sub_usage_new");
			expect(record.plan).toBeUndefined(); // the record never touches the plan
			const pairing = pairingOf(record);
			expect(pairing.result).toBe("created");
			expect(pairing.usage_subscription_id).toBe("sub_usage_new");

			// …then the usage half's OWN `active` event arrives → P1 through the resolver.
			pairDb(
				tenantRow({
					base: {
						id: "sub_base",
						plan: "team",
						status: "active",
						period_end: "2027-09-14T00:00:00Z",
					},
					alert: "annual_pair_usage_missing",
					pairing: {
						attempted_at: "2026-09-19T00:00:00Z",
						result: "created",
						usage_subscription_id: "sub_usage_new",
					},
				}),
				[[{ value: 12 }], [{ priceVersion: "v3" }]],
			);
			const res2 = await POST(makeReq(usageEvent({ id: "sub_usage_new" })));
			expect(res2.status).toBe(200);
			const p1 = h.db?.setCalls[0]?.[0] as Record<string, unknown>;
			expect(p1.plan).toBe("team");
			expect(p1.billingInterval).toBe("year");
			expect(p1.currentPeriodStart).toEqual(new Date("2026-09-14T00:00:00Z"));
			expect(p1.currentPeriodEnd).toEqual(new Date("2026-10-14T00:00:00Z"));
			expect(p1.polarUsageSubscriptionId).toBe("sub_usage_new");
			expect((p1.annualPair as { alert: unknown }).alert).toBeNull();
		});

		it("replay (the base's `active` / `updated` after `created`): Polar already lists a held usage half → NO second POST, the existing id is stored", async () => {
			process.env.POLAR_WORKER_TOKEN = "polar_oat_worker_test";
			const { calls } = fakePolar({ liveSubs: [liveBase, liveUsage] });
			// No pairing marker on the row (the reconciler, or a lost record write)
			// — the LIVE check is what stops the duplicate.
			pairingDb(
				tenantRow({
					base: { id: "sub_base", plan: "team", status: "active" },
					alert: "annual_pair_usage_missing",
				}),
			);
			const res = await POST(
				makeReq(baseEvent({ type: "subscription.active" })),
			);
			expect(res.status).toBe(200);
			expect(calls.map((c) => c.method)).toEqual(["GET"]);
			const record = h.db?.setCalls[2]?.[0] as Record<string, unknown>;
			expect(record.polarUsageSubscriptionId).toBe("sub_usage_existing");
			expect(pairingOf(record).result).toBe("existing");
		});

		it("M1 (security review 2026-09-19): a STALE `attempting` claim (older than 10× the deadline) is re-taken and pairs; a FRESH one is not", async () => {
			process.env.POLAR_WORKER_TOKEN = "polar_oat_worker_test";
			const stale = new Date(Date.now() - 6000 * 10 - 60_000).toISOString();
			const { calls } = fakePolar({ liveSubs: [liveBase] });
			pairingDb(
				tenantRow({
					base: { id: "sub_base", plan: "team", status: "active" },
					alert: "annual_pair_usage_missing",
					pairing: { attempted_at: stale, result: "attempting" },
				}),
			);
			const res = await POST(
				makeReq(baseEvent({ type: "subscription.updated" })),
			);
			expect(res.status).toBe(200);
			expect(calls.map((c) => c.method)).toEqual([
				"GET",
				"GET",
				"POST",
				"PATCH",
				"POST",
			]);
			const record = h.db?.setCalls[2]?.[0] as Record<string, unknown>;
			expect(pairingOf(record).result).toBe("created");

			// Fresh: another delivery is pairing right now → no claim, no Polar.
			const fresh = new Date(Date.now() - 1000).toISOString();
			const b = fakePolar({ liveSubs: [liveBase] });
			setDb([
				[],
				tenantRow({
					base: { id: "sub_base", plan: "team", status: "active" },
					alert: "annual_pair_usage_missing",
					pairing: { attempted_at: fresh, result: "attempting" },
				}),
				[{ polarProductIdUsageMonth: "prod_team_usage" }],
				[{ value: 6000 }],
				[],
				[],
				[],
			]);
			const res2 = await POST(
				makeReq(baseEvent({ type: "subscription.updated" })),
			);
			expect(res2.status).toBe(200);
			expect(b.fetchImpl).not.toHaveBeenCalled();
			expect(h.db?.setCalls.length).toBe(1);
		});

		it("replay with the attempt already RECORDED on the row → zero Polar calls and no claim", async () => {
			process.env.POLAR_WORKER_TOKEN = "polar_oat_worker_test";
			const { fetchImpl } = fakePolar({ liveSubs: [liveBase, liveUsage] });
			// dedup · tenant · P2 write · ws upsert · webhook_events — no claim, no record
			setDb([
				[],
				tenantRow({
					base: { id: "sub_base", plan: "team", status: "active" },
					alert: "annual_pair_usage_missing",
					pairing: {
						attempted_at: "2026-09-19T00:00:00Z",
						result: "created",
						usage_subscription_id: "sub_usage_new",
					},
				}),
				[],
				[],
				[],
			]);
			const res = await POST(
				makeReq(baseEvent({ type: "subscription.updated" })),
			);
			expect(res.status).toBe(200);
			expect(fetchImpl).not.toHaveBeenCalled();
			expect(h.db?.setCalls.length).toBe(1);
			const p2 = h.db?.setCalls[0]?.[0] as Record<string, unknown>;
			expect(p2.plan).toBe("free");
			expect(pairingOf(p2).result).toBe("created"); // the marker survives the write
		});

		it("two deliveries in flight: the claim is LOST → no Polar call, and the P2 write carries the OTHER invocation's live marker instead of clobbering it", async () => {
			process.env.POLAR_WORKER_TOKEN = "polar_oat_worker_test";
			const { fetchImpl } = fakePolar({ liveSubs: [liveBase] });
			setDb([
				[], // dedup
				tenantRow(null), // read BEFORE the other invocation claimed
				[{ polarProductIdUsageMonth: "prod_team_usage" }],
				[{ value: 6000 }],
				[], // claim → 0 rows: someone else holds it
				[
					{
						annualPair: {
							base: { id: "sub_base", plan: "team", status: "active" },
							pairing: {
								attempted_at: "2026-09-19T00:00:01Z",
								result: "attempting",
							},
						},
					},
				], // re-read the live marker
				[], // P2 write
				[], // ws upsert
				[], // webhook_events
			]);
			const res = await POST(
				makeReq(baseEvent({ type: "subscription.active" })),
			);
			expect(res.status).toBe(200);
			expect(fetchImpl).not.toHaveBeenCalled();
			expect(h.db?.setCalls.length).toBe(2); // claim attempt + P2 write, no record
			const p2 = h.db?.setCalls[1]?.[0] as Record<string, unknown>;
			expect(pairingOf(p2).result).toBe("attempting");
		});

		it("timeout: Polar never answers → the webhook still returns 200 within the deadline, the tenant stays P2, the attempt is recorded as failed", async () => {
			process.env.POLAR_WORKER_TOKEN = "polar_oat_worker_test";
			fakePolar({ hang: true });
			const error = vi.spyOn(console, "error").mockImplementation(() => {});
			pairingDb(tenantRow(null), 50); // billing_policy.annual_pairing_deadline_ms = 50
			const started = Date.now();
			const res = await POST(makeReq(baseEvent()));
			expect(res.status).toBe(200);
			expect(Date.now() - started).toBeLessThan(2_000);
			const p2 = h.db?.setCalls[1]?.[0] as Record<string, unknown>;
			expect(p2.plan).toBe("free");
			const record = h.db?.setCalls[2]?.[0] as Record<string, unknown>;
			expect(pairingOf(record).result).toBe("failed");
			expect(error).toHaveBeenCalled();
		});

		it("POLAR_SANDBOX=1 routes every call to sandbox-api.polar.sh — the reconciler's --sandbox rule", async () => {
			process.env.POLAR_WORKER_TOKEN = "polar_oat_worker_test";
			process.env.POLAR_SANDBOX = "1";
			const { calls } = fakePolar({ liveSubs: [liveBase] });
			pairingDb(tenantRow(null));
			await POST(makeReq(baseEvent()));
			expect(calls.length).toBe(5);
			expect(
				calls.every((c) => c.url.startsWith("https://sandbox-api.polar.sh/")),
			).toBe(true);
		});

		it("the usage product id is unconfigured for the plan (seed not run) → no claim, no Polar call, P2 as today, logged", async () => {
			process.env.POLAR_WORKER_TOKEN = "polar_oat_worker_test";
			const { fetchImpl } = fakePolar({ liveSubs: [liveBase] });
			const error = vi.spyOn(console, "error").mockImplementation(() => {});
			setDb([
				[],
				tenantRow(null),
				[{ polarProductIdUsageMonth: null }],
				[], // P2 write
				[], // ws upsert
				[], // webhook_events
			]);
			const res = await POST(makeReq(baseEvent()));
			expect(res.status).toBe(200);
			expect(fetchImpl).not.toHaveBeenCalled();
			expect(h.db?.setCalls.length).toBe(1);
			expect(error).toHaveBeenCalled();
		});
	});
});

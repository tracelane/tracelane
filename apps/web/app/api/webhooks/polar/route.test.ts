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
			[{ id: "ten_1" }], // tenant select → found
			[], // update tenants
			[], // upsert workspace_entitlements
			[], // record webhook_events
		]);
		const res = await POST(makeReq(subEvent()));
		expect(res.status).toBe(200);
		expect(h.db?.db.update).toHaveBeenCalledTimes(1); // tenants update ran
		expect(h.db?.db.insert).toHaveBeenCalledTimes(2); // ws upsert + dedup record
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

	it("200 + LOUD error log on an add-on lookup_key (grant wiring is P2)", async () => {
		const spy = vi.spyOn(console, "error").mockImplementation(() => {});
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
		expect(spy).toHaveBeenCalledWith(
			expect.stringContaining("ADD-ON lookup_key received (audit_addon_v1)"),
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
});

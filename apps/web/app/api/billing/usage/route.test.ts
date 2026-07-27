/**
 * Tests for GET /api/billing/usage.
 *
 * Focus: response shape + best-effort metering. The Polar/gateway meter read
 * must degrade gracefully — a failing or non-OK meter call yields
 * `usage: null`, never a 500. Negative cases (no tenant, meter failure)
 * first per `.claude/rules/testing.md`.
 */

import { type DbMock, makeDbMock } from "@/lib/__testutils__/db-mock";
import type { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	db: null as DbMock | null,
	session: { tenantId: "org_SESSION", userId: "user_1", email: "a@b.co" },
	// Audit add-on status now comes from the REAL entitlement, not the dead
	// `tenants.auditEnabled` column (the invisible entitlement-gated UI bug class).
	auditLedger: false,
}));

vi.mock("@/db", () => ({
	get db() {
		if (!h.db) throw new Error("db mock not initialised");
		return h.db.db;
	},
}));

vi.mock("@/lib/auth", () => ({
	requireSession: vi.fn(async () => h.session),
	requireGatewayToken: vi.fn(async () => ({ token: "minted-jwt" })),
}));

vi.mock("@/lib/entitlements", () => ({
	resolveEntitlements: vi.fn(async () => ({ audit_ledger: h.auditLedger })),
}));

import { GET } from "./route";

function setDb(results: unknown[]): void {
	h.db = makeDbMock(results);
}

function req(): NextRequest {
	return {
		json: async () => ({}),
		headers: new Headers({ authorization: "Bearer session-token" }),
	} as unknown as NextRequest;
}

describe("GET /api/billing/usage", () => {
	beforeEach(() => {
		h.session = { tenantId: "org_SESSION", userId: "user_1", email: "a@b.co" };
	});
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it("FALLBACK: unknown tenant returns builder defaults with usage:null (no 500)", async () => {
		setDb([[]]); // no tenant row
		const res = await GET(req());
		expect(res.status).toBe(200);
		const json = (await res.json()) as {
			plan: string;
			auditEnabled: boolean;
			usage: unknown;
		};
		expect(json).toEqual({ plan: "free", auditEnabled: false, usage: null });
	});

	it("GRACEFUL: gateway meter non-OK (500) yields usage:null, not a crash", async () => {
		setDb([
			[{ plan: "team", auditEnabled: false, polarCustomerId: "cus_123" }],
		]);
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => ({ ok: false, status: 500 }) as unknown as Response),
		);
		const res = await GET(req());
		expect(res.status).toBe(200);
		const json = (await res.json()) as { plan: string; usage: unknown };
		expect(json.plan).toBe("team");
		expect(json.usage).toBeNull();
	});

	it("GRACEFUL: gateway fetch throwing yields usage:null, not a 500", async () => {
		setDb([
			[{ plan: "team", auditEnabled: false, polarCustomerId: "cus_123" }],
		]);
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => {
				throw new Error("ECONNREFUSED");
			}),
		);
		const res = await GET(req());
		expect(res.status).toBe(200);
		const json = (await res.json()) as { usage: unknown };
		expect(json.usage).toBeNull();
	});

	it("does NOT call the meter when the tenant has no Polar customer id", async () => {
		setDb([[{ plan: "builder", auditEnabled: false, polarCustomerId: null }]]);
		const fetchSpy = vi.fn(
			async () => ({ ok: true, json: async () => ({}) }) as unknown as Response,
		);
		vi.stubGlobal("fetch", fetchSpy);
		const res = await GET(req());
		const json = (await res.json()) as { usage: unknown };
		expect(json.usage).toBeNull();
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("HAPPY: returns the meter totals shape when the gateway responds OK", async () => {
		h.auditLedger = true;
		setDb([[{ id: "t_9", plan: "business", polarCustomerId: "cus_9" }]]);
		vi.stubGlobal(
			"fetch",
			vi.fn(
				async () =>
					({
						ok: true,
						json: async () => ({ tokens_processed: 4200, audit_anchors: 7 }),
					}) as unknown as Response,
			),
		);
		const res = await GET(req());
		const json = (await res.json()) as {
			plan: string;
			auditEnabled: boolean;
			usage: { tokens_processed: number; audit_anchors: number };
		};
		expect(json.plan).toBe("business");
		expect(json.auditEnabled).toBe(true);
		expect(json.usage).toEqual({ tokens_processed: 4200, audit_anchors: 7 });
	});

	it("reads the entitlement, NOT the dead tenants.auditEnabled column", async () => {
		// The legacy column is the trap: a tenant row can still carry
		// auditEnabled=true while the real grant (f_audit_addon) is false.
		// The API must follow the entitlement.
		h.auditLedger = false;
		setDb([
			[
				{
					id: "t_1",
					plan: "business",
					auditEnabled: true,
					polarCustomerId: null,
				},
			],
		]);
		const res = await GET({ headers: new Headers() } as never);
		const json = (await res.json()) as { auditEnabled: boolean };
		expect(json.auditEnabled).toBe(false);
	});

	it("meters with the MINTED per-user gateway JWT, never the client header", async () => {
		setDb([
			[{ plan: "team", auditEnabled: false, polarCustomerId: "cus_123" }],
		]);
		const spy = vi.fn(
			async (..._args: unknown[]) =>
				({
					ok: true,
					json: async () => ({ tokens_processed: 5, audit_anchors: 1 }),
				}) as unknown as Response,
		);
		vi.stubGlobal("fetch", spy);
		const res = await GET(req());
		expect(res.status).toBe(200);
		const init = spy.mock.calls[0]?.[1] as
			| { headers?: Record<string, string> }
			| undefined;
		expect(init?.headers?.authorization).toBe("Bearer minted-jwt");
	});
});

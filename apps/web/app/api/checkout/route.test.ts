/**
 * Tests for POST /api/checkout — in-app Polar checkout upgrade proxy.
 *
 * ADR-076: product ids come from `plan_entitlements.polar_product_id_month|
 * year` (read by tier + `?interval=`), never a `POLAR_PRODUCT_ID_<TIER>` env
 * var. Focus: the route forwards the per-user JWT as Bearer, sends the tenant
 * NEVER in the body (the gateway derives it from the JWT), and 302-redirects
 * to the REAL Polar checkout URL the gateway returns — not a 200. Never
 * echoes the upstream error body. B-140: an existing subscriber
 * (`polar_subscription_id` set) is sent to the customer portal for ANY plan
 * change instead of a second checkout. Negative cases first per
 * `.claude/rules/testing.md`. Gateway `fetch` + session + DB are mocked so
 * this unit stays off the network.
 */

import { type DbMock, makeDbMock } from "@/lib/__testutils__/db-mock";
import type { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	token: "wos_jwt_user_a",
	email: "a@example.com",
	db: null as DbMock | null,
}));

vi.mock("@/lib/auth", () => ({
	requireGatewayToken: vi.fn(async () => ({
		token: h.token,
		tenantId: "org_A",
	})),
	requireSession: vi.fn(async () => ({
		tenantId: "org_A",
		userId: "user_A",
		email: h.email,
	})),
}));

vi.mock("@/db", () => ({
	get db() {
		if (!h.db) throw new Error("db mock not initialised");
		return h.db.db;
	},
}));

import { PLANS_V3 } from "@/lib/entitlements";
import { POST } from "./route";

const fetchMock = vi.fn();

function req(tier: string, interval?: string): NextRequest {
	const qs = interval ? `tier=${tier}&interval=${interval}` : `tier=${tier}`;
	return {
		nextUrl: new URL(`http://localhost/api/checkout?${qs}`),
	} as unknown as NextRequest;
}

function setDb(results: unknown[]): void {
	h.db = makeDbMock(results);
}

function sentBody(callIndex = 0): Record<string, unknown> {
	const opts = fetchMock.mock.calls[callIndex]?.[1] as { body: string };
	return JSON.parse(opts.body) as Record<string, unknown>;
}
function sentHeaders(callIndex = 0): Record<string, string> {
	return (
		fetchMock.mock.calls[callIndex]?.[1] as { headers: Record<string, string> }
	).headers;
}

beforeEach(() => {
	h.token = "wos_jwt_user_a";
	h.email = "a@example.com";
	global.fetch = fetchMock as unknown as typeof fetch;
	fetchMock.mockReset();
});

afterEach(() => vi.unstubAllEnvs());

describe("POST /api/checkout", () => {
	it("rejects an unknown tier with 400 and never touches the DB or the gateway", async () => {
		const res = await POST(req("wizard"));
		expect(res.status).toBe(400);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("Enterprise is sales-led — never a self-serve checkout target", async () => {
		const res = await POST(req("enterprise"));
		expect(res.status).toBe(400);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("returns 501 when the tier has no configured Polar product id for this deployment", async () => {
		setDb([
			[{ polarSubscriptionId: null }], // tenant lookup: no active sub
			[{ polarProductIdMonth: null, polarProductIdYear: null }], // planEntitlements row
		]);
		const res = await POST(req("business"));
		expect(res.status).toBe(501);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("maps a gateway 5xx to 502 without leaking the upstream body", async () => {
		setDb([
			[{ polarSubscriptionId: null }],
			[
				{
					polarProductIdMonth: "polar_prod_team_uuid",
					polarProductIdYear: null,
				},
			],
		]);
		fetchMock.mockResolvedValue({
			ok: false,
			status: 500,
			json: async () => ({ error: "polar said SECRET_REQUEST_ID" }),
		});
		const res = await POST(req("team"));
		expect(res.status).toBe(502);
		const body = (await res.json()) as { error: string };
		expect(body.error).toBe("checkout unavailable");
		expect(JSON.stringify(body)).not.toContain("SECRET_REQUEST_ID");
	});

	it("302-redirects to the REAL Polar checkout URL (not a 200)", async () => {
		setDb([
			[{ polarSubscriptionId: null }],
			[
				{
					polarProductIdMonth: "polar_prod_team_uuid",
					polarProductIdYear: null,
				},
			],
		]);
		fetchMock.mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({ url: "https://polar.sh/checkout/abc123" }),
		});
		const res = await POST(req("team"));
		expect(res.status).toBe(302);
		expect(res.headers.get("location")).toBe(
			"https://polar.sh/checkout/abc123",
		);
		expect(res.status).not.toBe(200);
	});

	it("forwards the per-user JWT + product id + email; tenant never in the body", async () => {
		setDb([
			[{ polarSubscriptionId: null }],
			[
				{
					polarProductIdMonth: "polar_prod_team_uuid",
					polarProductIdYear: null,
				},
			],
		]);
		fetchMock.mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({ url: "https://polar.sh/checkout/abc123" }),
		});
		await POST(req("team"));
		const url = fetchMock.mock.calls[0]?.[0] as string;
		expect(url).toContain("/v1/billing/checkout");
		expect(sentHeaders().authorization).toBe("Bearer wos_jwt_user_a");
		const body = sentBody();
		expect(body.product_id).toBe("polar_prod_team_uuid");
		expect(body.customer_email).toBe("a@example.com");
		// The gateway resolves the tenant from the JWT — never trust a body field.
		expect(body).not.toHaveProperty("tenant_id");
		expect(body).not.toHaveProperty("tenantId");
	});

	it("B14: ?interval=year is REFUSED (400, annual_unavailable) while plans.v3.json says annual is not for sale — before any DB read or gateway call", async () => {
		// A yearly Polar product grants its meter credits once per YEAR (B-411);
		// until the founder rules the annual shape nothing annual is sold. The
		// shipped reference table carries the switch OFF.
		expect(PLANS_V3.policy.annual_available).toBe(false);
		setDb([[{ polarSubscriptionId: null }]]);
		const res = await POST(req("team", "year"));
		expect(res.status).toBe(400);
		expect(await res.json()).toEqual({
			error: "annual billing is not available yet",
			reason: "annual_unavailable",
		});
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("reads the ANNUAL product id when ?interval=year and the switch is ON", async () => {
		const spy = vi
			.spyOn(PLANS_V3.policy, "annual_available", "get")
			.mockReturnValue(true);
		try {
			setDb([
				[{ polarSubscriptionId: null, polarBaseSubscriptionId: null }],
				[
					{
						polarProductIdMonth: "polar_prod_team_month",
						polarProductIdBaseYear: "polar_prod_team_base_year",
					},
				],
			]);
			fetchMock.mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({ url: "https://polar.sh/checkout/xyz" }),
			});
			await POST(req("team", "year"));
			const body = sentBody();
			// BILL-02: annual is bought as the yearly BASE product.
			expect(body.product_id).toBe("polar_prod_team_base_year");
		} finally {
			spy.mockRestore();
		}
	});

	it("B-140: a tenant with an ACTIVE subscription is sent to the customer portal, never a second checkout", async () => {
		setDb([[{ polarSubscriptionId: "sub_existing_123" }]]);
		fetchMock.mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({ url: "https://polar.sh/portal/abc" }),
		});
		const res = await POST(req("business"));
		expect(res.status).toBe(302);
		expect(res.headers.get("location")).toBe("https://polar.sh/portal/abc");
		// Called the PORTAL endpoint, not the checkout endpoint.
		const url = fetchMock.mock.calls[0]?.[0] as string;
		expect(url).toContain("/v1/billing/portal");
		expect(url).not.toContain("/v1/billing/checkout");
	});

	it("B-140: the portal path never leaks the upstream error body either", async () => {
		setDb([[{ polarSubscriptionId: "sub_existing_123" }]]);
		fetchMock.mockResolvedValue({
			ok: false,
			status: 500,
			json: async () => ({ error: "polar said SECRET" }),
		});
		const res = await POST(req("business"));
		expect(res.status).toBe(502);
		const body = (await res.json()) as { error: string };
		expect(JSON.stringify(body)).not.toContain("SECRET");
	});
});

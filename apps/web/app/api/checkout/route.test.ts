/**
 * Tests for POST /api/checkout — in-app Polar checkout upgrade proxy.
 *
 * Focus: the route forwards the per-user JWT as Bearer, sends the tenant NEVER
 * in the body (the gateway derives it from the JWT), maps the tier to the
 * configured Polar product id, and 302-redirects to the REAL Polar checkout URL
 * the gateway returns — not a 200. Never echoes the upstream error body.
 * Negative cases first per `.claude/rules/testing.md`. Gateway `fetch` + session
 * are mocked so this unit stays off the network.
 */

import type { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	token: "wos_jwt_user_a",
	email: "a@example.com",
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

import { POST } from "./route";

const fetchMock = vi.fn();

function req(tier: string): NextRequest {
	return {
		nextUrl: new URL(`http://localhost/api/checkout?tier=${tier}`),
	} as unknown as NextRequest;
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
	vi.stubEnv("POLAR_PRODUCT_ID_TEAM", "polar_prod_team_uuid");
});

afterEach(() => vi.unstubAllEnvs());

describe("POST /api/checkout", () => {
	it("rejects an unknown tier with 400 and never calls the gateway", async () => {
		const res = await POST(req("wizard"));
		expect(res.status).toBe(400);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("returns 501 when the tier has no configured Polar product id", async () => {
		const res = await POST(req("business")); // only TEAM is stubbed
		expect(res.status).toBe(501);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("maps a gateway 5xx to 502 without leaking the upstream body", async () => {
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
		fetchMock.mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({ url: "https://polar.sh/checkout/abc123" }),
		});
		const res = await POST(req("team"));
		// The deliverable: a redirect to a real Polar URL, never a bare 200.
		expect(res.status).toBe(302);
		expect(res.headers.get("location")).toBe(
			"https://polar.sh/checkout/abc123",
		);
		expect(res.status).not.toBe(200);
	});

	it("forwards the per-user JWT + product id + email; tenant never in the body", async () => {
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
});

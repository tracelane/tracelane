/**
 * Tests for POST /api/billing/portal — Polar customer-portal proxy.
 *
 * requireGatewayToken() and forwards it as Bearer. It must NOT depend on an
 * incoming `authorization` header — the browser (BillingPortalButton) calls
 * this route with a session COOKIE, not a Bearer, so the old header-forwarding
 * code always sent no auth and every gateway call 401'd ("Manage billing" was
 * dead). Also: returns { url } on success; maps a gateway 5xx to 502 without
 * leaking the upstream body. Gateway fetch + auth mocked (off the network).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ token: "wos_jwt_user_a" }));

vi.mock("@/lib/auth", () => ({
	requireGatewayToken: vi.fn(async () => ({
		token: h.token,
		tenantId: "org_A",
	})),
}));

import { POST } from "./route";

const fetchMock = vi.fn();

function sentHeaders(callIndex = 0): Record<string, string> {
	return (
		fetchMock.mock.calls[callIndex]?.[1] as { headers: Record<string, string> }
	).headers;
}

beforeEach(() => {
	h.token = "wos_jwt_user_a";
	global.fetch = fetchMock as unknown as typeof fetch;
	fetchMock.mockReset();
	vi.stubEnv("NEXT_PUBLIC_GATEWAY_URL", "https://gateway.example");
});

afterEach(() => vi.unstubAllEnvs());

describe("POST /api/billing/portal", () => {
	it("mints the per-user JWT and forwards it as Bearer to /v1/billing/portal", async () => {
		fetchMock.mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({ url: "https://polar.sh/customer-portal/sess_1" }),
		});
		const res = await POST();
		expect(res.status).toBe(200);
		const url = fetchMock.mock.calls[0]?.[0] as string;
		expect(url).toBe("https://gateway.example/v1/billing/portal");
		// THE regression: a real Bearer minted from requireGatewayToken(), never
		// a forwarded (absent) incoming request header.
		expect(sentHeaders().authorization).toBe("Bearer wos_jwt_user_a");
		const body = (await res.json()) as { url: string };
		expect(body.url).toBe("https://polar.sh/customer-portal/sess_1");
	});

	it("maps a gateway 5xx to 502 without leaking the upstream body", async () => {
		fetchMock.mockResolvedValue({
			ok: false,
			status: 500,
			json: async () => ({ error: "polar said SECRET_REQUEST_ID" }),
		});
		const res = await POST();
		expect(res.status).toBe(502);
		const body = (await res.json()) as { error: string };
		expect(body.error).toBe("billing portal unavailable");
		expect(JSON.stringify(body)).not.toContain("SECRET_REQUEST_ID");
	});

	it("passes a gateway 4xx status through without leaking the body", async () => {
		fetchMock.mockResolvedValue({
			ok: false,
			status: 401,
			json: async () => ({ error: "unauthorized detail" }),
		});
		const res = await POST();
		expect(res.status).toBe(401);
		expect(JSON.stringify(await res.json())).not.toContain(
			"unauthorized detail",
		);
	});
});

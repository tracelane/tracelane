/**
 *
 * The route mints the per-user JWT via requireGatewayToken() and forwards it as
 * Bearer to the gateway DELETE (never a body-supplied tenant, per ADR-042 /
 * 204 passthrough, an error-status+body passthrough, and the unreachable 503.
 * Gateway fetch + auth mocked (off the network).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ token: "wos_jwt_user_a" }));

vi.mock("@/lib/auth", () => ({
	requireSession: vi.fn(async () => ({})),
	requireGatewayToken: vi.fn(async () => ({
		token: h.token,
		tenantId: "org_A",
	})),
}));

import { DELETE } from "./route";

const fetchMock = vi.fn();

function makeParams(name: string) {
	return { params: Promise.resolve({ name }) };
}

beforeEach(() => {
	h.token = "wos_jwt_user_a";
	global.fetch = fetchMock as unknown as typeof fetch;
	fetchMock.mockReset();
	vi.stubEnv("NEXT_PUBLIC_GATEWAY_URL", "https://gateway.example");
});

afterEach(() => vi.unstubAllEnvs());

describe("DELETE /api/prompts/[name]", () => {
	it("mints the per-user JWT and forwards DELETE to the gateway with the Bearer", async () => {
		fetchMock.mockResolvedValue({ status: 204, text: async () => "" });
		const res = await DELETE({} as never, makeParams("greet"));
		expect(res.status).toBe(204);
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe("https://gateway.example/v1/prompts/greet");
		expect(init.method).toBe("DELETE");
		// The tenant travels in the minted Bearer, never a request body/header.
		expect((init.headers as Record<string, string>).authorization).toBe(
			"Bearer wos_jwt_user_a",
		);
	});

	it("url-encodes the prompt name", async () => {
		fetchMock.mockResolvedValue({ status: 204, text: async () => "" });
		await DELETE({} as never, makeParams("a/b name"));
		const url = fetchMock.mock.calls[0]?.[0] as string;
		expect(url).toBe("https://gateway.example/v1/prompts/a%2Fb%20name");
	});

	it("passes a gateway error status + body through", async () => {
		fetchMock.mockResolvedValue({
			status: 500,
			text: async () => JSON.stringify({ error: "internal" }),
		});
		const res = await DELETE({} as never, makeParams("greet"));
		expect(res.status).toBe(500);
		const body = (await res.json()) as { error: string };
		expect(body.error).toBe("internal");
	});

	it("returns 503 when the gateway is unreachable", async () => {
		fetchMock.mockRejectedValue(new Error("ECONNREFUSED"));
		const res = await DELETE({} as never, makeParams("greet"));
		expect(res.status).toBe(503);
		const body = (await res.json()) as { error: string };
		expect(body.error).toBe("gateway_unreachable");
	});
});

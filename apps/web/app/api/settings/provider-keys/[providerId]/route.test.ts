/**
 * Tests for DELETE /api/settings/provider-keys/[providerId].
 *
 * The proxy forwards the Bearer token, targets the gateway revoke endpoint
 * (provider id from the URL, never a tenant), and returns 204 on success.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ token: "wos_tok", tenantId: "org_X" }));

vi.mock("@/lib/auth", () => ({
	requireGatewayToken: vi.fn(async () => ({
		token: h.token,
		tenantId: h.tenantId,
	})),
}));

import { DELETE } from "./route";

const fetchMock = vi.fn();

/**
 * `gatewayResponse` (lib/gateway.ts) re-wraps the upstream body and status,
 * so the stubbed fetch must hand it a REAL Response — this converts the
 * `{ ok, status, json }` shape these tests were written with into one.
 */
async function asResponse(fake: {
	ok?: boolean;
	status?: number;
	json?: () => Promise<unknown>;
}): Promise<Response> {
	const body = fake.json ? JSON.stringify(await fake.json()) : null;
	return new Response(body, { status: fake.status ?? (fake.ok ? 200 : 500) });
}

beforeEach(() => {
	global.fetch = (async (...args: unknown[]) =>
		asResponse(await fetchMock(...args))) as unknown as typeof fetch;
	fetchMock.mockReset();
});

describe("DELETE /api/settings/provider-keys/[providerId]", () => {
	it("forwards the revoke to the gateway and returns 204", async () => {
		fetchMock.mockResolvedValue({ ok: true, status: 204 });
		const res = await DELETE(new Request("http://local/x"), {
			params: Promise.resolve({ providerId: "anthropic" }),
		});
		expect(res.status).toBe(204);

		const [url, opts] = fetchMock.mock.calls[0] as [
			string,
			{ method: string; headers: Record<string, string> },
		];
		expect(url).toContain("/v1/byok/provider-keys/anthropic");
		expect(opts.method).toBe("DELETE");
		expect(new Headers(opts.headers).get("authorization")).toBe(
			`Bearer ${h.token}`,
		);
	});

	it("maps an upstream 5xx to 502", async () => {
		fetchMock.mockResolvedValue({ ok: false, status: 500 });
		const res = await DELETE(new Request("http://local/x"), {
			params: Promise.resolve({ providerId: "openai" }),
		});
		expect(res.status).toBe(502);
	});
});

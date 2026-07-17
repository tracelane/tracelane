/**
 * Tests for /api/settings/provider-keys (GET list, POST upload).
 *
 * Focus: the proxy forwards the WorkOS access token as Bearer, sends the
 * tenant NEVER in the body (the gateway derives it from the JWT), trims pasted
 * keys, and never echoes the upstream error body. Negative cases first per
 * `.claude/rules/testing.md`. The gateway `fetch` and the session token are
 * mocked so this unit stays off the network.
 */

import type { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	token: "wos_access_token_xyz",
	tenantId: "org_TEST",
}));

vi.mock("@/lib/auth", () => ({
	requireGatewayToken: vi.fn(async () => ({
		token: h.token,
		tenantId: h.tenantId,
	})),
}));

import { GET, POST } from "./route";

const fetchMock = vi.fn();

beforeEach(() => {
	global.fetch = fetchMock as unknown as typeof fetch;
	fetchMock.mockReset();
});

function postReq(body: unknown): NextRequest {
	return { json: async () => body } as unknown as NextRequest;
}

function sentBody(callIndex = 0): Record<string, unknown> {
	const opts = fetchMock.mock.calls[callIndex]?.[1] as { body: string };
	return JSON.parse(opts.body) as Record<string, unknown>;
}

describe("POST /api/settings/provider-keys", () => {
	it("rejects a missing/blank key with 422 and never calls the gateway", async () => {
		const res = await POST(
			postReq({ provider_id: "anthropic", plaintext: "   " }),
		);
		expect(res.status).toBe(422);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("rejects a missing provider_id with 422", async () => {
		const res = await POST(postReq({ plaintext: "sk-ant-abc" }));
		expect(res.status).toBe(422);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("maps upstream 400 to a generic message without leaking the body", async () => {
		fetchMock.mockResolvedValue({
			ok: false,
			status: 400,
			json: async () => ({ error: "unknown provider_id SECRET_LEAK" }),
		});
		const res = await POST(
			postReq({ provider_id: "bogus", plaintext: "sk-x" }),
		);
		expect(res.status).toBe(400);
		const body = (await res.json()) as { error: string };
		expect(body.error).toBe("unknown or unsupported provider");
		expect(JSON.stringify(body)).not.toContain("SECRET_LEAK");
	});

	it("maps an upstream 5xx to 502", async () => {
		fetchMock.mockResolvedValue({
			ok: false,
			status: 503,
			json: async () => ({}),
		});
		const res = await POST(
			postReq({ provider_id: "anthropic", plaintext: "sk-ant-x" }),
		);
		expect(res.status).toBe(502);
	});

	it("forwards the Bearer token + body, with NO tenant in the body", async () => {
		fetchMock.mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({ provider_id: "anthropic", last4: "tXyz" }),
		});
		const res = await POST(
			postReq({ provider_id: "anthropic", plaintext: "sk-ant-secret-xyz" }),
		);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({
			provider_id: "anthropic",
			last4: "tXyz",
		});

		const [url, opts] = fetchMock.mock.calls[0] as [
			string,
			{ headers: Record<string, string>; body: string; method: string },
		];
		expect(url).toContain("/v1/byok/provider-keys");
		expect(opts.method).toBe("POST");
		expect(opts.headers.authorization).toBe(`Bearer ${h.token}`);
		const sent = sentBody();
		expect(sent).toEqual({
			provider_id: "anthropic",
			plaintext: "sk-ant-secret-xyz",
		});
		expect(sent).not.toHaveProperty("tenant_id");
		expect(sent).not.toHaveProperty("tenantId");
	});

	it("trims a pasted key and provider id before forwarding", async () => {
		fetchMock.mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({ provider_id: "openai", last4: "abcd" }),
		});
		await POST(
			postReq({ provider_id: " openai ", plaintext: "  sk-trimmed  " }),
		);
		expect(sentBody()).toEqual({
			provider_id: "openai",
			plaintext: "sk-trimmed",
		});
	});
});

describe("GET /api/settings/provider-keys", () => {
	it("returns the gateway list and forwards the Bearer token", async () => {
		fetchMock.mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => [{ provider_id: "anthropic", last4: "ant1" }],
		});
		const res = await GET();
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual([
			{ provider_id: "anthropic", last4: "ant1" },
		]);
		const opts = fetchMock.mock.calls[0]?.[1] as {
			headers: Record<string, string>;
		};
		expect(opts.headers.authorization).toBe(`Bearer ${h.token}`);
	});

	it("maps an upstream 5xx to 502", async () => {
		fetchMock.mockResolvedValue({
			ok: false,
			status: 500,
			json: async () => ({}),
		});
		const res = await GET();
		expect(res.status).toBe(502);
	});
});

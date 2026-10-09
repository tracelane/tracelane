/**
 * `EVL-31` slice 1 — two gateway-proxy fixes:
 *
 *  1. `gatewayDelete` used to throw with the status ONLY, so a `403
 *     role_forbidden` from a delete lost `required_role` and rendered as a
 *     generic failure — the same shape every other verb already guards
 *     against.
 *  2. `gatewayPostText` sends a caller's body VERBATIM (never
 *     `JSON.stringify`d) — the import route needs this for a JSONL file,
 *     where `gatewayPost` would wrap the whole file in one quoted string.
 *
 * No real network: `global.fetch` is stubbed per test.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/auth", () => ({
	requireGatewayToken: vi.fn(async () => ({
		token: "jwt-x",
		tenantId: "org_x",
	})),
}));

// `attestationHeaders` reads the browser address from the inbound request's
// `cf-connecting-ip` via `next/headers`; pinned here so the OG-36 test below can
// prove the header rides on `gatewayResponse` (the helper the admin-plane
// proxies use). Tests that never set the secret never reach it.
vi.mock("next/headers", () => ({
	headers: async () => new Headers({ "cf-connecting-ip": "203.0.113.9" }),
}));

import { ATTESTATION_HEADER } from "./client-ip-attestation";
import { gatewayDelete, gatewayPostText, gatewayResponse } from "./gateway";

const originalFetch = global.fetch;
afterEach(() => {
	global.fetch = originalFetch;
	vi.restoreAllMocks();
});
beforeEach(() => {
	process.env.NEXT_PUBLIC_GATEWAY_URL = "http://localhost:8080";
});

describe("gatewayDelete", () => {
	it("throws GatewayError WITH the parsed error body on a non-2xx response", async () => {
		global.fetch = vi.fn(
			async () =>
				new Response(
					JSON.stringify({ error: "role_forbidden", required_role: "owner" }),
					{ status: 403 },
				),
		) as unknown as typeof fetch;

		// RED before the fix: this threw `new GatewayError(res.status, ...)`
		// with NO third argument, so `err.body` was always `null` and
		// `required_role` was lost — a caller could not render the sentence.
		await expect(gatewayDelete("/v1/datasets/ds-1")).rejects.toMatchObject({
			status: 403,
			body: { error: "role_forbidden", required_role: "owner" },
		});
	});

	it("resolves on 204 with no body", async () => {
		global.fetch = vi.fn(
			async () => new Response(null, { status: 204 }),
		) as unknown as typeof fetch;
		await expect(gatewayDelete("/v1/datasets/ds-1")).resolves.toBeUndefined();
	});
});

describe("gatewayPostText", () => {
	it("sends the body VERBATIM — never JSON.stringify'd", async () => {
		let sentBody: unknown;
		let sentContentType: string | undefined;
		global.fetch = vi.fn(async (_url, init?: RequestInit) => {
			sentBody = init?.body;
			sentContentType = (init?.headers as Record<string, string>)?.[
				"content-type"
			];
			return new Response(JSON.stringify({ added: 2 }), { status: 200 });
		}) as unknown as typeof fetch;

		const jsonl = '{"input":[{"role":"user","content":"a"}]}\n{"input":[]}\n';
		const result = await gatewayPostText<{ added: number }>(
			"/v1/datasets/ds-1/import?format=jsonl",
			jsonl,
			"application/x-ndjson",
		);

		expect(sentBody).toBe(jsonl);
		expect(sentContentType).toBe("application/x-ndjson");
		expect(result).toEqual({ added: 2 });
	});

	it("carries the error body on a non-2xx response", async () => {
		global.fetch = vi.fn(
			async () =>
				new Response(JSON.stringify({ error: "import_too_large" }), {
					status: 413,
				}),
		) as unknown as typeof fetch;

		await expect(
			gatewayPostText("/v1/datasets/ds-1/import", "x", "text/plain"),
		).rejects.toMatchObject({
			status: 413,
			body: { error: "import_too_large" },
		});
	});
});

describe("gatewayResponse — OG-36 client-IP attestation (M4)", () => {
	afterEach(() => vi.unstubAllEnvs());

	function captureHeaders(): { get: () => Headers } {
		let sent = new Headers();
		global.fetch = vi.fn(async (_url, init?: RequestInit) => {
			sent = new Headers(init?.headers);
			return new Response(null, { status: 204 });
		}) as unknown as typeof fetch;
		return { get: () => sent };
	}

	it("signs the browser address onto an admin-plane call when the secret is set", async () => {
		vi.stubEnv(
			"TRACELANE_CLIENT_IP_ATTEST_SECRET",
			"unit-test-attest-secret-do-not-use-in-prod-0123456789",
		);
		const cap = captureHeaders();
		const res = await gatewayResponse("/v1/billing/ceiling", { method: "PUT" });
		expect(res.status).toBe(204);
		expect(cap.get().get("authorization")).toBe("Bearer jwt-x");
		// v1;<ip>;<unix-s>;<hex HMAC-SHA256> — the browser's address, not the Worker's.
		expect(cap.get().get(ATTESTATION_HEADER)).toMatch(
			/^v1;203\.0\.113\.9;\d+;[0-9a-f]{64}$/,
		);
	});

	it("sends no attestation when the secret is unset (the gateway falls back to its own derivation)", async () => {
		vi.stubEnv("TRACELANE_CLIENT_IP_ATTEST_SECRET", "");
		const cap = captureHeaders();
		await gatewayResponse("/v1/billing/ceiling", { method: "PUT" });
		expect(cap.get().get("authorization")).toBe("Bearer jwt-x");
		expect(cap.get().has(ATTESTATION_HEADER)).toBe(false);
	});
});

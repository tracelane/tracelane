/**
 * GWY-53 — /api/settings/content-capture proxy. The gateway owns the owner gate and
 * the ledger write; this route must forward the token, never put a tenant in the body,
 * refuse a malformed body before the gateway, pass `audit_unavailable` through by name
 * (the toggle says "not saved"), and mask everything else. Negative cases first
 * (`.claude/rules/testing.md`).
 */
import type { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ token: "wos_access_token_xyz" }));
vi.mock("@/lib/auth", () => ({
	requireGatewayToken: vi.fn(async () => ({
		token: h.token,
		tenantId: "org_TEST",
	})),
}));

import { GET, PUT } from "./route";

const fetchMock = vi.fn();
beforeEach(() => {
	global.fetch = fetchMock as unknown as typeof fetch;
	fetchMock.mockReset();
	// The REAL `lib/gateway` helper runs (it attaches the OG-36 attestation);
	// only its base URL is pinned.
	vi.stubEnv("NEXT_PUBLIC_GATEWAY_URL", "http://gw.test");
});

const putReq = (body: unknown) =>
	({ json: async () => body }) as unknown as NextRequest;
const badJsonReq = () =>
	({
		json: async () => {
			throw new SyntaxError("bad json");
		},
	}) as unknown as NextRequest;
// A REAL Response: `gatewayResponse` re-wraps the upstream body and headers.
const upstream = (status: number, body?: unknown) =>
	new Response(body === undefined ? null : JSON.stringify(body), { status });

describe("PUT", () => {
	it("refuses a missing or non-boolean field with 400 and never calls the gateway", async () => {
		expect((await PUT(putReq({ input: true }))).status).toBe(400);
		expect((await PUT(putReq({ input: "yes", output: false }))).status).toBe(
			400,
		);
		expect((await PUT(badJsonReq())).status).toBe(400);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("forwards the token and ONLY input/output — a smuggled tenant never leaves", async () => {
		fetchMock.mockResolvedValue(
			upstream(200, { input: true, output: true, changed: true }),
		);
		const res = await PUT(
			putReq({ input: true, output: true, tenant_id: "evil" }),
		);
		expect(res.status).toBe(200);
		const [url, opts] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe("http://gw.test/v1/workspace/capture");
		expect(opts.method).toBe("PUT");
		expect(new Headers(opts.headers).get("authorization")).toBe(
			`Bearer ${h.token}`,
		);
		expect(JSON.parse(opts.body as string)).toEqual({
			input: true,
			output: true,
		});
	});

	it("passes audit_unavailable through by name so the toggle can say 'not saved'", async () => {
		fetchMock.mockResolvedValue(
			upstream(503, { error: "audit_unavailable", message: "not saved" }),
		);
		const res = await PUT(putReq({ input: true, output: false }));
		expect(res.status).toBe(503);
		expect(await res.json()).toEqual({
			error: "audit_unavailable",
			message: "not saved",
		});
	});

	it("turns a non-owner 403 into role_forbidden naming the owner", async () => {
		fetchMock.mockResolvedValue(
			upstream(403, { error: "role_forbidden", required_role: "owner" }),
		);
		const res = await PUT(putReq({ input: false, output: false }));
		expect(res.status).toBe(403);
		expect(await res.json()).toEqual({
			error: "role_forbidden",
			required_role: "owner",
		});
	});

	it("masks an upstream 500 as 502 without echoing its body", async () => {
		fetchMock.mockResolvedValue(
			upstream(500, { error: "write_failed", message: "pg: internal detail" }),
		);
		const res = await PUT(putReq({ input: true, output: true }));
		expect(res.status).toBe(502);
		expect(JSON.stringify(await res.json())).not.toContain("internal detail");
	});
});

describe("GET", () => {
	it("returns the gateway's view as-is with the token forwarded", async () => {
		const view = {
			input: false,
			output: false,
			operator_allowlisted: false,
			effective: { input: false, output: false },
			queryable_days: 30,
			max_field_bytes: 65536,
			updated_at: null,
			can_edit: true,
		};
		fetchMock.mockResolvedValue(upstream(200, view));
		const res = await GET();
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual(view);
		const [url, opts] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe("http://gw.test/v1/workspace/capture");
		expect(new Headers(opts.headers).get("authorization")).toBe(
			`Bearer ${h.token}`,
		);
	});

	it("passes no_control_plane through as a 503", async () => {
		fetchMock.mockResolvedValue(upstream(503, { error: "no_control_plane" }));
		const res = await GET();
		expect(res.status).toBe(503);
		expect((await res.json()).error).toBe("no_control_plane");
	});
});

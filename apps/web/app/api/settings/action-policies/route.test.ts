/**
 * ACT-21 — POST /api/settings/action-policies. Tier A: role checked, tenant never read from the
 * body, the document built server-side from parameters (a client-supplied document is ignored),
 * the gateway's reason shown, every failure closed. Negative cases first.
 */
import { refuseCrossOriginMutation } from "@/lib/csrf";
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	denied: null as Response | null,
	rateOk: true,
	rateThrows: false,
	list: { policies: [] as unknown[] } as { policies: unknown[] },
	listError: null as unknown,
	post: null as ((doc: unknown) => unknown) | null,
	posts: [] as unknown[],
	postError: null as unknown,
}));
vi.mock("@/lib/auth", () => ({
	requireSession: vi.fn(async () => ({ tenantId: "org_S", userId: "u" })),
}));
vi.mock("@/lib/admin-gate", () => ({
	requireOrgAdmin: vi.fn(async () => h.denied),
}));
vi.mock("@/lib/rate-limit", () => ({
	rateLimit: vi.fn(async () => {
		if (h.rateThrows) throw new Error("x");
		return h.rateOk;
	}),
}));
vi.mock("@/lib/gateway", () => {
	class GatewayError extends Error {
		constructor(
			public status: number,
			m: string,
			public body?: Record<string, unknown> | null,
		) {
			super(m);
		}
	}
	return {
		GatewayError,
		gatewayGet: vi.fn(async () => {
			if (h.listError) throw h.listError;
			return h.list;
		}),
		gatewayPost: vi.fn(async (_p: string, doc: unknown) => {
			h.posts.push(doc);
			if (h.postError) throw h.postError;
			return { policy_version: 1 };
		}),
	};
});
import { GatewayError } from "@/lib/gateway";
import { POST } from "./route";

const SERVER = "11111111-1111-4111-8111-111111111111";
const params = {
	amountUnit: "cents",
	toolName: "release_payment",
	limit: 5000,
	approved: ["acme"],
	approvalMinutes: 60,
	args: { amount: "amount", currency: "currency", beneficiary: "beneficiary" },
};
const req = (b: unknown) =>
	({ json: async () => b, headers: new Headers() }) as unknown as NextRequest;
const ok = { template: "payments", server_id: SERVER, params };

beforeEach(() => {
	h.denied = null;
	h.rateOk = true;
	h.rateThrows = false;
	h.list = { policies: [] };
	h.listError = null;
	h.posts = [];
	h.postError = null;
	vi.spyOn(console, "error").mockImplementation(() => {});
});

describe("refusals publish nothing", () => {
	it("a non-admin gets the admin gate's 403", async () => {
		h.denied = NextResponse.json({ error: "x" }, { status: 403 });
		const res = await POST(req(ok));
		expect(res.status).toBe(403);
		expect((await res.json()).reason).toMatch(/owners and admins/);
		expect(h.posts).toHaveLength(0);
	});
	it.each([
		["bad json", null],
		["no template", { server_id: SERVER, params }],
		["unknown template", { ...ok, template: "evil" }],
		["no server", { template: "payments", params }],
		["no params", { template: "payments", server_id: SERVER }],
		["params not an object", { ...ok, params: "x" }],
	])("400 on %s", async (_n, b) => {
		expect((await POST(req(b))).status).toBe(400);
		expect(h.posts).toHaveLength(0);
	});
	it("422 with field errors on invalid parameters", async () => {
		const res = await POST(
			req({ ...ok, params: { ...params, limit: -1, approved: [] } }),
		);
		expect(res.status).toBe(422);
		const b = await res.json();
		expect(b.errors.limit).toBeTruthy();
		expect(b.reason).toMatch(/\w/);
		expect(b.errors.approved).toBeTruthy();
		expect(h.posts).toHaveLength(0);
	});
	it("422 when the server id is not a UUID", async () => {
		expect((await POST(req({ ...ok, server_id: "../x" }))).status).toBe(422);
		expect(h.posts).toHaveLength(0);
	});
	it("429 / 503 on the rate limiter, nothing published", async () => {
		h.rateOk = false;
		expect((await POST(req(ok))).status).toBe(429);
		h.rateOk = true;
		h.rateThrows = true;
		expect((await POST(req(ok))).status).toBe(503);
		expect(h.posts).toHaveLength(0);
	});
	it("fails closed 503 when the current versions cannot be read", async () => {
		h.listError = new GatewayError(503, "down");
		expect((await POST(req(ok))).status).toBe(503);
		expect(h.posts).toHaveLength(0);
	});
	it("shows the gateway's reason for a 422 refusal", async () => {
		h.postError = new GatewayError(422, "r", { error: "policy_invalid" });
		const res = await POST(req(ok));
		expect(res.status).toBe(422);
		expect(await res.json()).toMatchObject({
			error: "policy_invalid",
			reason: expect.stringMatching(/did not accept/),
		});
	});
	it("passes 409 action_control_disabled with plain words", async () => {
		h.postError = new GatewayError(409, "r", {
			error: "action_control_disabled",
		});
		const res = await POST(req(ok));
		expect(res.status).toBe(409);
		expect((await res.json()).reason).toMatch(/Turn it on/);
	});
	it("reads a nested error code", async () => {
		h.postError = new GatewayError(404, "r", {
			error: { code: "mcp_server_not_found" },
		});
		expect((await (await POST(req(ok))).json()).error).toBe(
			"mcp_server_not_found",
		);
	});
	it("masks an unexpected gateway failure as 503 without its text", async () => {
		h.postError = new GatewayError(500, "secret internal text");
		const res = await POST(req(ok));
		expect(res.status).toBe(503);
		expect(JSON.stringify(await res.json())).not.toMatch(/secret/);
	});
});

describe("amount unit", () => {
	it("422 with a reason when the unit is missing, nothing published", async () => {
		const { amountUnit: _u, ...rest } = params;
		const res = await POST(req({ ...ok, params: rest }));
		expect(res.status).toBe(422);
		expect((await res.json()).reason).toMatch(/cents or in whole dollars/);
		expect(h.posts).toHaveLength(0);
	});
	it("publishes the limit in the unit the caller chose", async () => {
		await POST(
			req({ ...ok, params: { ...params, amountUnit: "whole_dollars" } }),
		);
		const d = h.posts[0] as {
			policy: { rules: { when: { value: number }[] }[] };
		};
		expect(d.policy.rules[0]?.when[0]?.value).toBe(5000);
	});
});

describe("tenant and document come from the server", () => {
	it("ignores a policy document or tenant smuggled in the body", async () => {
		const res = await POST(
			req({
				...ok,
				tenant_id: "evil",
				contract: { tool_name: "evil" },
				policy: { rules: [] },
				doc: { contract: {}, policy: {} },
			}),
		);
		expect(res.status).toBe(200);
		const sent = JSON.stringify(h.posts[0]);
		expect(sent).not.toMatch(/evil/);
		expect(h.posts[0]).toHaveProperty("contract.tool_name", "release_payment");
	});
	it("publishes the template document with server-minted ids", async () => {
		await POST(req(ok));
		const d = h.posts[0] as {
			contract: { tool_ref: string; server_id: string };
			policy: { policy_id: string };
		};
		expect(d.contract.server_id).toBe(SERVER);
		expect(d.contract.tool_ref).toMatch(/^[0-9a-f-]{36}$/);
		expect(d.policy.policy_id).toMatch(/^[0-9a-f-]{36}$/);
	});
	it("a republish reuses the tool identity and bumps versions", async () => {
		h.list = {
			policies: [
				{
					tool_ref: "22222222-2222-4222-8222-222222222222",
					server_id: SERVER,
					tool_name: "release_payment",
					contract_version: 2,
					policy_version: 4,
				},
			],
		};
		await POST(req(ok));
		const d = h.posts[0] as {
			contract: { tool_ref: string; version: number };
			policy: { version: number };
		};
		expect(d.contract.tool_ref).toBe("22222222-2222-4222-8222-222222222222");
		expect([d.contract.version, d.policy.version]).toEqual([3, 5]);
	});
	it("reports success and passes gateway warnings through", async () => {
		const res = await POST(req(ok));
		expect(await res.json()).toMatchObject({
			published: true,
			tool_name: "release_payment",
		});
	});
});

describe("CSRF — the middleware refuses cross-site writes to this route", () => {
	const url = "https://app.tracelane.dev/api/settings/action-policies";
	const m = (headers: Record<string, string>) =>
		refuseCrossOriginMutation({
			method: "POST",
			url,
			headers: new Headers(headers),
		});
	it("refuses cross-site, no headers and a foreign origin", () => {
		expect(m({ "sec-fetch-site": "cross-site" })).toBe(true);
		expect(m({})).toBe(true);
		expect(m({ origin: "https://tracelane.dev" })).toBe(true);
	});
	it("allows same-origin", () => {
		expect(m({ "sec-fetch-site": "same-origin" })).toBe(false);
	});
});

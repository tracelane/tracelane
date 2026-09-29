/**
 * Tests for /api/settings/api-keys/[keyId] — PATCH (SET-38, edit limits in
 * place) and DELETE (revoke; B-586 moved it onto the gateway).
 *
 * DELETE: the admin gate still runs first (a member/viewer must not be able to
 * kill the org's gateway ingress), and a revoke is now a gateway call — never a
 * Drizzle UPDATE, which is what left a warm key working for up to 60 s (B-586).
 *
 * PATCH: no web-side role gate — the gateway decides (it alone can check
 * `minted_by` under the row lock) and its refusal body is passed through. The
 * proxy's own job is shape: forward exactly the known fields in the gateway's
 * spelling, keep `null` as `null`, and refuse anything else. Negative first.
 */

import { NextRequest, NextResponse } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => {
	class GatewayError extends Error {
		constructor(
			public status: number,
			message: string,
			public body: Record<string, unknown> | null = null,
		) {
			super(message);
		}
	}
	return {
		gatewayPatch: vi.fn(),
		gatewayGet: vi.fn(),
		gatewayDelete: vi.fn(),
		admin: vi.fn(),
		db: vi.fn(),
		recordAdminAction: vi.fn(),
		GatewayError,
	};
});

vi.mock("@/lib/auth", () => ({
	requireSession: async () => ({
		tenantId: "org_SESSION",
		userId: "user_1",
		email: "a@b.co",
		role: "member",
	}),
}));
vi.mock("@/lib/admin-gate", () => ({ requireOrgAdmin: h.admin }));
vi.mock("@/lib/gateway", () => ({
	gatewayPatch: h.gatewayPatch,
	gatewayGet: h.gatewayGet,
	gatewayDelete: h.gatewayDelete,
	GatewayError: h.GatewayError,
}));
// Tripwires: neither route may touch Postgres or write its own audit row any more.
vi.mock("@/db", () => ({
	get db() {
		h.db();
		throw new Error("the key routes must not read or write Postgres directly");
	},
}));
vi.mock("@/lib/admin-audit", () => ({
	recordAdminAction: h.recordAdminAction,
	ipFromRequest: () => null,
}));

import { DELETE, GET, PATCH } from "./route";

const params = { params: Promise.resolve({ keyId: "key-1" }) };
const patchReq = (body: string) =>
	new NextRequest("http://localhost/api/settings/api-keys/key-1", {
		method: "PATCH",
		body,
	});
const delReq = new NextRequest("http://localhost/api/settings/api-keys/key-1", {
	method: "DELETE",
});

beforeEach(() => {
	vi.clearAllMocks();
	h.admin.mockResolvedValue(null);
	h.gatewayDelete.mockResolvedValue(undefined);
});

describe("DELETE /api/settings/api-keys/[keyId] (revoke)", () => {
	it("REJECT: a member/viewer revoke is 403 — the gateway is never called", async () => {
		h.admin.mockResolvedValue(
			NextResponse.json({ error: "owner required" }, { status: 403 }),
		);
		const res = await DELETE(delReq, params);
		expect(res.status).toBe(403);
		expect(h.gatewayDelete).not.toHaveBeenCalled();
	});

	it("REJECT: a role lookup failure fails CLOSED — the gateway is never called", async () => {
		h.admin.mockResolvedValue(
			NextResponse.json({ error: "role unavailable" }, { status: 502 }),
		);
		const res = await DELETE(delReq, params);
		expect(res.status).toBe(502);
		expect(h.gatewayDelete).not.toHaveBeenCalled();
	});

	it("HAPPY (B-586): an admin revoke goes THROUGH THE GATEWAY — no Drizzle write, no second audit row", async () => {
		const res = await DELETE(delReq, params);
		expect(res.status).toBe(204);
		expect(h.gatewayDelete).toHaveBeenCalledWith("/v1/keys/key-1");
		expect(h.db).not.toHaveBeenCalled();
		expect(h.recordAdminAction).not.toHaveBeenCalled();
	});

	it("the path id is encoded, never spliced raw into the gateway path", async () => {
		await DELETE(delReq, {
			params: Promise.resolve({ keyId: "../tenants/x" }),
		});
		expect(h.gatewayDelete).toHaveBeenCalledWith("/v1/keys/..%2Ftenants%2Fx");
	});

	it.each([
		[404, 404, "key not found or already revoked"],
		[403, 403, "Only a workspace owner can revoke API keys"],
		[500, 502, "Couldn't revoke the key — it is unchanged"],
		[503, 502, "Couldn't revoke the key — it is unchanged"],
	])(
		"maps a gateway %i to %i with an honest message",
		async (upstream, status, message) => {
			h.gatewayDelete.mockRejectedValue(
				new h.GatewayError(upstream, `gateway responded ${upstream}`),
			);
			const res = await DELETE(delReq, params);
			expect(res.status).toBe(status);
			expect((await res.json()).error).toBe(message);
		},
	);
});

describe("PATCH /api/settings/api-keys/[keyId] (edit limits)", () => {
	it.each([
		['{"tenantId":"org_OTHER","rateLimitRpm":2}', "tenantId"],
		['{"tenant_id":"x"}', "tenant_id"],
		['{"rate_limit_rpm":2}', "rate_limit_rpm"],
		['{"rawKey":"tlane_x"}', "rawKey"],
	])(
		"REJECT: an unknown field is a 400 naming it, never silently dropped (%s)",
		async (body, field) => {
			const res = await PATCH(patchReq(body), params);
			expect(res.status).toBe(400);
			expect((await res.json()).field).toBe(field);
			expect(h.gatewayPatch).not.toHaveBeenCalled();
		},
	);

	it.each(["not json", "[]", "null", '"x"', "3"])(
		"REJECT: a body that is not a JSON object is a 400 (%s)",
		async (body) => {
			const res = await PATCH(patchReq(body), params);
			expect(res.status).toBe(400);
			expect(h.gatewayPatch).not.toHaveBeenCalled();
		},
	);

	it("HAPPY: forwards exactly the sent fields in gateway spelling, null kept as null", async () => {
		const updated = { id: "key-1", changed: ["rate_limit_rpm"] };
		h.gatewayPatch.mockResolvedValue(updated);
		const res = await PATCH(
			patchReq(
				JSON.stringify({
					rateLimitRpm: 20,
					budgetUsdMonthly: null,
					scope: ["read"],
					budgetReset: "daily",
				}),
			),
			params,
		);
		expect(res.status).toBe(200);
		expect(res.headers.get("cache-control")).toBe("no-store");
		expect(await res.json()).toEqual(updated);
		expect(h.gatewayPatch).toHaveBeenCalledWith("/v1/keys/key-1", {
			rate_limit_rpm: 20,
			budget_usd_monthly: null,
			scope: ["read"],
			budget_reset: "daily",
		});
		expect(h.db).not.toHaveBeenCalled();
	});

	it("an absent field is not sent at all (absent = unchanged, not null)", async () => {
		h.gatewayPatch.mockResolvedValue({});
		await PATCH(patchReq('{"name":"ci"}'), params);
		expect(h.gatewayPatch).toHaveBeenCalledWith("/v1/keys/key-1", {
			name: "ci",
		});
	});

	it("does NOT gate on the web role: a member's edit reaches the gateway, which decides", async () => {
		h.gatewayPatch.mockResolvedValue({});
		await PATCH(patchReq('{"rateLimitRpm":5}'), params);
		expect(h.admin).not.toHaveBeenCalled();
		expect(h.gatewayPatch).toHaveBeenCalledTimes(1);
	});

	it.each([
		[
			403,
			{ error: "role_forbidden", required_role: "owner", upgrade_url: null },
		],
		[
			404,
			{ error: "not_found", message: "key not found, expired, or revoked" },
		],
		[
			409,
			{
				error: "key_retiring",
				message: "This key is being rotated. Edit its successor instead.",
			},
		],
		[
			400,
			{
				error: "invalid_field",
				field: "rate_limit_rpm",
				message: "rate_limit_rpm must be …",
			},
		],
	])("passes a gateway %i body through unchanged", async (status, body) => {
		h.gatewayPatch.mockRejectedValue(
			new h.GatewayError(status, `gateway responded ${status}`, body),
		);
		const res = await PATCH(patchReq('{"rateLimitRpm":1}'), params);
		expect(res.status).toBe(status);
		expect(await res.json()).toEqual(body);
	});

	it("a gateway 5xx is an opaque 502 that says nothing was changed", async () => {
		h.gatewayPatch.mockRejectedValue(
			new h.GatewayError(500, "gateway responded 500", {
				error: "not_saved",
				message: "internal detail",
			}),
		);
		const res = await PATCH(patchReq('{"rateLimitRpm":1}'), params);
		expect(res.status).toBe(502);
		expect((await res.json()).error).toBe(
			"Couldn't save — nothing was changed",
		);
	});
});

it("reads key spend through the tenant-authenticated gateway and preserves unknown spend", async () => {
	h.gatewayGet.mockResolvedValueOnce({
		id: "key",
		spend: { recorded_usd: null },
	});
	const result = await GET(
		new NextRequest("https://test/api/settings/api-keys/key"),
		{ params: Promise.resolve({ keyId: "key" }) },
	);
	expect(h.gatewayGet).toHaveBeenCalledWith("/v1/keys/key");
	expect((await result.json()).spend.recorded_usd).toBeNull();
	expect(result.headers.get("cache-control")).toBe("no-store");
});
it("passes a missing key through as 404 rather than an empty spend", async () => {
	h.gatewayGet.mockRejectedValueOnce(
		new h.GatewayError(404, "not found", { error: "not_found" }),
	);
	const result = await GET(
		new NextRequest("https://test/api/settings/api-keys/missing"),
		{ params: Promise.resolve({ keyId: "missing" }) },
	);
	expect(result.status).toBe(404);
});

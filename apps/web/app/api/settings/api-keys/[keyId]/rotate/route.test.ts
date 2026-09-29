import { NextRequest, NextResponse } from "next/server";
import { beforeEach, expect, it, vi } from "vitest";

const h = vi.hoisted(() => {
	class GatewayError extends Error {
		constructor(
			public status: number,
			message: string,
		) {
			super(message);
		}
	}
	return { gatewayPost: vi.fn(), admin: vi.fn(), GatewayError };
});
vi.mock("@/lib/auth", () => ({
	requireSession: async () => ({ tenantId: "org-session", userId: "owner" }),
}));
vi.mock("@/lib/admin-gate", () => ({ requireOrgAdmin: h.admin }));
vi.mock("@/lib/gateway", () => ({
	gatewayPost: h.gatewayPost,
	GatewayError: h.GatewayError,
}));
import { POST } from "./route";

const params = { params: Promise.resolve({ keyId: "old-key" }) };
const request = (body: unknown) =>
	new NextRequest("http://localhost/api/settings/api-keys/old-key/rotate", {
		method: "POST",
		body: JSON.stringify(body),
	});
beforeEach(() => {
	vi.clearAllMocks();
	h.admin.mockResolvedValue(null);
});

it("refuses a non-owner without forwarding credentials or changing keys", async () => {
	h.admin.mockResolvedValue(
		NextResponse.json({ error: "owner required" }, { status: 403 }),
	);
	expect((await POST(request({ graceHours: 2 }), params)).status).toBe(403);
	expect(h.gatewayPost).not.toHaveBeenCalled();
});
it.each([-1, 1.5, "2", null])(
	"rejects invalid grace %s",
	async (graceHours) => {
		expect((await POST(request({ graceHours }), params)).status).toBe(400);
		expect(h.gatewayPost).not.toHaveBeenCalled();
	},
);
it("rejects tenant or successor-setting injection", async () => {
	expect(
		(await POST(request({ tenant_id: "other", scope: ["admin"] }), params))
			.status,
	).toBe(400);
	expect(h.gatewayPost).not.toHaveBeenCalled();
});
it.each([{}, { graceHours: 0 }, { graceHours: 2 }])(
	"forwards only the grace window, returns the one-time result without caching",
	async (body) => {
		const result = {
			id: "new-key",
			rawKey: "tlane_unit_test_secret",
			oldKeyRevokedAt: "2030-01-01T00:00:00Z",
		};
		h.gatewayPost.mockResolvedValue(result);
		const res = await POST(request(body), params);
		expect(res.status).toBe(201);
		expect(res.headers.get("cache-control")).toBe("no-store");
		expect(await res.json()).toEqual(result);
		expect(h.gatewayPost).toHaveBeenCalledWith(
			"/v1/keys/old-key/rotate",
			"graceHours" in body ? { grace_hours: body.graceHours } : {},
		);
	},
);
it.each([400, 403, 404])("preserves gateway refusal %s", async (status) => {
	h.gatewayPost.mockRejectedValue(
		new h.GatewayError(status, "rotation refused"),
	);
	const res = await POST(request({}), params);
	expect(res.status).toBe(status);
	expect(await res.json()).toEqual({ error: "rotation refused" });
});
it("hides gateway failure details", async () => {
	h.gatewayPost.mockRejectedValue(
		new h.GatewayError(500, "internal database detail"),
	);
	const res = await POST(request({}), params);
	expect(res.status).toBe(502);
	expect(await res.json()).toEqual({ error: "Could not rotate API key" });
});

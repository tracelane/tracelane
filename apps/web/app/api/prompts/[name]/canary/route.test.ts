import { NextRequest } from "next/server";
import { beforeEach, expect, it, vi } from "vitest";
const h = vi.hoisted(() => ({ fetch: vi.fn(), audit: vi.fn() }));
vi.mock("@/lib/auth", () => ({
	requireSession: async () => ({ userId: "actor" }),
	requireGatewayToken: async () => ({ token: "user-token" }),
}));
vi.mock("@/lib/gateway", () => ({
	gatewayBaseUrl: () => "http://gateway.test",
}));
vi.mock("@/lib/admin-audit", () => ({
	ipFromRequest: () => null,
	recordAdminAction: h.audit,
}));
import { DELETE, PUT } from "./route";
beforeEach(() => {
	h.fetch.mockReset();
	h.audit.mockReset();
	vi.stubGlobal("fetch", h.fetch);
});
it("forwards saved input and user authorization, records the write, and handles empty stop", async () => {
	h.fetch
		.mockResolvedValueOnce(
			new Response(JSON.stringify({ canary_id: "saved" }), { status: 200 }),
		)
		.mockResolvedValueOnce(new Response(null, { status: 204 }));
	const response = await PUT(
		new NextRequest("http://app.test/api/prompts/a/canary", {
			method: "PUT",
			body: JSON.stringify({
				candidate_version_id: "candidate",
				candidate_percent: 17.25,
			}),
		}),
		{ params: Promise.resolve({ name: "a" }) },
	);
	expect(await response.json()).toEqual({ canary_id: "saved" });
	expect(h.fetch.mock.calls[0]?.[1].headers.authorization).toBe(
		"Bearer user-token",
	);
	expect(JSON.parse(h.fetch.mock.calls[0]?.[1].body).candidate_percent).toBe(
		17.25,
	);
	expect(h.audit).toHaveBeenCalled();
	const stopped = await DELETE(
		new NextRequest("http://app.test/api/prompts/a/canary", {
			method: "DELETE",
		}),
		{ params: Promise.resolve({ name: "a" }) },
	);
	expect(stopped.status).toBe(204);
	expect(await stopped.text()).toBe("");
});
it.each([401, 403, 423, 503])(
	"preserves gateway refusal %i",
	async (status) => {
		h.fetch.mockResolvedValue(
			new Response(JSON.stringify({ error: "refused" }), { status }),
		);
		const response = await PUT(
			new NextRequest("http://app.test/api/prompts/a/canary", {
				method: "PUT",
				body: "{}",
			}),
			{ params: Promise.resolve({ name: "a" }) },
		);
		expect(response.status).toBe(status);
		expect(await response.json()).toEqual({ error: "refused" });
	},
);

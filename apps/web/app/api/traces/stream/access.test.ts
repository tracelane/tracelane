import { __resetDeadlineCacheForTests } from "@/lib/query-deadline";
import type { NextRequest } from "next/server";
import { beforeEach, expect, it, vi } from "vitest";
const h = vi.hoisted(() => ({
	role: "admin",
	tenantId: "org_access",
	gateway: vi.fn(),
}));
vi.mock("@/lib/auth", () => ({
	requireGatewayToken: async () => ({ tenantId: h.tenantId }),
	requireSession: async () => ({ tenantId: h.tenantId, role: h.role }),
}));
vi.mock("@/lib/gateway", () => ({
	gatewayGet: h.gateway,
	forwardParams: (source: URLSearchParams, keys: string[]) =>
		new URLSearchParams([...source].filter(([key]) => keys.includes(key))),
}));
import { GET } from "./route";
const request = () =>
	({ nextUrl: new URL("http://local/api/traces/stream") }) as NextRequest;
beforeEach(() => {
	__resetDeadlineCacheForTests();
	h.gateway.mockReset();
	h.role = "admin";
	h.tenantId = "org_access";
});
it.each(["billing"])(
	"billing_role_never_receives_cached_trace_partial (%s)",
	async (role) => {
		h.gateway.mockResolvedValueOnce({
			traces: [{ trace_id: "private_cached_trace" }],
		});
		expect(await (await GET(request())).text()).toContain(
			"private_cached_trace",
		);
		h.role = role;
		h.gateway.mockRejectedValueOnce(new Error("gateway 403"));
		const response = await GET(request());
		expect(await response.text()).not.toContain("private_cached_trace");
		expect(response.status).toBe(403);
	},
);
it("authorized reader receives cached rows while its fresh query fails", async () => {
	h.gateway.mockResolvedValueOnce({
		traces: [{ trace_id: "allowed_cached_trace" }],
	});
	await (await GET(request())).text();
	h.role = "viewer";
	h.gateway.mockRejectedValueOnce(new Error("upstream unavailable"));
	const response = await GET(request());
	expect(response.status).toBe(200);
	expect(await response.text()).toContain("allowed_cached_trace");
});

import { afterEach, expect, it, vi } from "vitest";
vi.mock("@/lib/auth", () => ({
	requireGatewayToken: vi.fn(async () => ({ token: "unit-test-owner-token" })),
}));
vi.mock("@/lib/gateway", () => ({
	gatewayBaseUrl: () => "https://gateway.invalid",
}));
import { POST } from "./route";
afterEach(() => vi.unstubAllGlobals());

it.each([401, 403, 404, 409, 429, 503])(
	"preserves refusal %s without exposing upstream response material",
	async (status) => {
		const fetcher = vi.fn(
			async (_url: string, _init?: RequestInit) =>
				new Response("unit-test-secret-in-error", { status }),
		);
		vi.stubGlobal("fetch", fetcher);
		const response = await POST(
			new Request("https://app.invalid", {
				method: "POST",
				body: JSON.stringify({
					tenant_id: "other",
					plaintext: "unit-test-injected",
				}),
			}),
			{ params: Promise.resolve({ providerId: "anthropic" }) },
		);
		expect(response.status).toBe(status >= 500 ? 502 : status);
		expect(await response.text()).not.toContain("unit-test-secret");
		expect(fetcher).toHaveBeenCalledWith(
			"https://gateway.invalid/v1/provider-keys/anthropic/validate",
			expect.objectContaining({
				method: "POST",
				headers: { authorization: "Bearer unit-test-owner-token" },
			}),
		);
		expect(fetcher.mock.calls[0]?.[1]).not.toHaveProperty("body");
	},
);
it("returns the recorded verdict with no-store", async () => {
	const result = {
		status: "rejected",
		reason: "authentication_rejected",
		checked_at: "2026-09-22T12:00:00Z",
	};
	vi.stubGlobal(
		"fetch",
		vi.fn(async () => Response.json(result)),
	);
	const response = await POST(new Request("https://app.invalid"), {
		params: Promise.resolve({ providerId: "anthropic" }),
	});
	expect(await response.json()).toEqual(result);
	expect(response.headers.get("cache-control")).toBe("no-store");
});

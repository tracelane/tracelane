import { beforeEach, expect, it, vi } from "vitest";
vi.mock("@/lib/auth", () => ({ requireGatewayToken: vi.fn() }));
vi.mock("@/lib/gateway", async (original) => ({
	...(await original<typeof import("@/lib/gateway")>()),
	gatewayDelete: vi.fn(),
}));
import { GatewayError, gatewayDelete } from "@/lib/gateway";
import { DELETE } from "./route";

beforeEach(() => vi.clearAllMocks());

it("forwards to the gateway's DELETE and answers 204", async () => {
	vi.mocked(gatewayDelete).mockResolvedValue(undefined);
	const res = await DELETE(new Request("http://localhost"), {
		params: Promise.resolve({ id: "ds-1" }),
	});
	expect(res.status).toBe(204);
	expect(gatewayDelete).toHaveBeenCalledWith("/v1/datasets/ds-1");
});

it.each([403, 404, 409])(
	"preserves status and body %i (role-403-as-generic-failure)",
	async (status) => {
		const body = { error: "role_forbidden", required_role: "owner" };
		vi.mocked(gatewayDelete).mockRejectedValue(
			new GatewayError(status, "refused", body),
		);
		const res = await DELETE(new Request("http://localhost"), {
			params: Promise.resolve({ id: "ds-1" }),
		});
		expect(res.status).toBe(status);
		expect(await res.json()).toEqual(body);
	},
);

it("does not disclose upstream 5xx details", async () => {
	vi.mocked(gatewayDelete).mockRejectedValue(
		new GatewayError(500, "private", { message: "private" }),
	);
	const res = await DELETE(new Request("http://localhost"), {
		params: Promise.resolve({ id: "ds-1" }),
	});
	expect(res.status).toBe(502);
	expect(await res.text()).not.toContain("private");
});

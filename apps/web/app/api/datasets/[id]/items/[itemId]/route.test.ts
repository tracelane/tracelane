import { NextRequest } from "next/server";
import { beforeEach, expect, it, vi } from "vitest";
vi.mock("@/lib/auth", () => ({ requireGatewayToken: vi.fn() }));
vi.mock("@/lib/gateway", async (original) => ({
	...(await original<typeof import("@/lib/gateway")>()),
	gatewayPatch: vi.fn(),
	gatewayDelete: vi.fn(),
}));
import { GatewayError, gatewayDelete, gatewayPatch } from "@/lib/gateway";
import { DELETE, PATCH } from "./route";

const params = Promise.resolve({ id: "ds-1", itemId: "item-1" });
const patchReq = (body: unknown) =>
	new NextRequest("http://localhost", {
		method: "PATCH",
		body: JSON.stringify(body),
	});

beforeEach(() => vi.clearAllMocks());

it("PATCH forwards the body verbatim and answers 204", async () => {
	vi.mocked(gatewayPatch).mockResolvedValue(undefined);
	const body = { expected_output: "Refunds post in 5 days" };
	const res = await PATCH(patchReq(body), { params });
	expect(res.status).toBe(204);
	expect(gatewayPatch).toHaveBeenCalledWith(
		"/v1/datasets/ds-1/items/item-1",
		body,
	);
});

it("PATCH rejects invalid JSON before forwarding", async () => {
	const res = await PATCH(
		new NextRequest("http://localhost", { method: "PATCH", body: "{" }),
		{ params },
	);
	expect(res.status).toBe(400);
	expect(gatewayPatch).not.toHaveBeenCalled();
});

it("DELETE forwards and answers 204", async () => {
	vi.mocked(gatewayDelete).mockResolvedValue(undefined);
	const res = await DELETE(new NextRequest("http://localhost"), { params });
	expect(res.status).toBe(204);
	expect(gatewayDelete).toHaveBeenCalledWith("/v1/datasets/ds-1/items/item-1");
});

it.each([403, 404, 413])(
	"preserves status and body %i on both verbs",
	async (status) => {
		const body = { error: "expected_output_too_large" };
		vi.mocked(gatewayPatch).mockRejectedValue(
			new GatewayError(status, "refused", body),
		);
		vi.mocked(gatewayDelete).mockRejectedValue(
			new GatewayError(status, "refused", body),
		);
		for (const res of [
			await PATCH(patchReq({ expected_output: "x" }), { params }),
			await DELETE(new NextRequest("http://localhost"), { params }),
		]) {
			expect(res.status).toBe(status);
			expect(await res.json()).toEqual(body);
		}
	},
);

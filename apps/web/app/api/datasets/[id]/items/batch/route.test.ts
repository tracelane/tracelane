import { NextRequest } from "next/server";
import { beforeEach, expect, it, vi } from "vitest";
vi.mock("@/lib/auth", () => ({ requireGatewayToken: vi.fn() }));
vi.mock("@/lib/gateway", async (original) => ({
	...(await original<typeof import("@/lib/gateway")>()),
	gatewayPost: vi.fn(),
}));
import { GatewayError, gatewayPost } from "@/lib/gateway";
import { POST } from "./route";

const request = (body: unknown) =>
	new NextRequest("http://localhost", {
		method: "POST",
		body: JSON.stringify(body),
	});

beforeEach(() => vi.clearAllMocks());

it("forwards the traces array to the gateway's batch route", async () => {
	vi.mocked(gatewayPost).mockResolvedValue({
		added: 1,
		deduped: 0,
		refused_count: 0,
		refused: [],
	});
	const body = { traces: [{ trace_id: "3f2a" }] };
	const res = await POST(request(body), {
		params: Promise.resolve({ id: "ds-1" }),
	});
	expect(res.status).toBe(200);
	expect(await res.json()).toMatchObject({ added: 1 });
	expect(gatewayPost).toHaveBeenCalledWith(
		"/v1/datasets/ds-1/items/batch",
		body,
	);
});

it("rejects invalid JSON before forwarding", async () => {
	const res = await POST(
		new NextRequest("http://localhost", { method: "POST", body: "{" }),
		{ params: Promise.resolve({ id: "ds-1" }) },
	);
	expect(res.status).toBe(400);
	expect(gatewayPost).not.toHaveBeenCalled();
});

it.each([400, 403, 409, 422])(
	"preserves status and body %i",
	async (status) => {
		const body = { error: "bulk_too_large", max: 200 };
		vi.mocked(gatewayPost).mockRejectedValue(
			new GatewayError(status, "refused", body),
		);
		const res = await POST(request({ traces: [] }), {
			params: Promise.resolve({ id: "ds-1" }),
		});
		expect(res.status).toBe(status);
		expect(await res.json()).toEqual(body);
	},
);

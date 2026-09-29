import { NextRequest } from "next/server";
import { beforeEach, expect, it, vi } from "vitest";
vi.mock("@/lib/auth", () => ({ requireGatewayToken: vi.fn() }));
vi.mock("@/lib/gateway", async (original) => ({
	...(await original<typeof import("@/lib/gateway")>()),
	gatewayGet: vi.fn(),
	gatewayPost: vi.fn(),
}));
import { GatewayError, gatewayGet, gatewayPost } from "@/lib/gateway";
import { POST as add } from "./[id]/items/route";
import { GET, POST } from "./route";
const request = (body: unknown) =>
	new NextRequest("http://localhost/api/datasets", {
		method: "POST",
		body: JSON.stringify(body),
	});
beforeEach(() => vi.clearAllMocks());
it("forwards the documented trace/span body", async () => {
	vi.mocked(gatewayPost).mockResolvedValue({ item_id: "item" });
	const body = { trace_id: "trace", span_id: "span" };
	expect(
		(await add(request(body), { params: Promise.resolve({ id: "ds" }) }))
			.status,
	).toBe(201);
	expect(gatewayPost).toHaveBeenCalledWith("/v1/datasets/ds/items", body);
});
it.each([400, 401, 403, 404, 409, 422, 429])(
	"preserves status and body %i",
	async (status) => {
		const body = {
			error: "content_capture_disabled",
			message: "No content recorded",
		};
		vi.mocked(gatewayPost).mockRejectedValue(
			new GatewayError(status, "refused", body),
		);
		for (const response of [
			await POST(request({ name: "Cases" })),
			await add(request({ trace_id: "trace" }), {
				params: Promise.resolve({ id: "foreign" }),
			}),
		]) {
			expect(response.status).toBe(status);
			expect(await response.json()).toEqual(body);
		}
	},
);
it("does not disclose upstream 5xx details", async () => {
	vi.mocked(gatewayPost).mockRejectedValue(
		new GatewayError(500, "private", { message: "private" }),
	);
	const response = await POST(request({}));
	expect(response.status).toBe(502);
	expect(await response.text()).not.toContain("private");
});
it("preserves deduplication and rejects invalid JSON before forwarding", async () => {
	vi.mocked(gatewayPost).mockResolvedValue({ deduped: true });
	expect(
		(await add(request({}), { params: Promise.resolve({ id: "ds" }) })).status,
	).toBe(200);
	vi.clearAllMocks();
	expect(
		(
			await POST(
				new NextRequest("http://localhost", { method: "POST", body: "{" }),
			)
		).status,
	).toBe(400);
	expect(gatewayPost).not.toHaveBeenCalled();
});
it("only forwards supported list parameters", async () => {
	vi.mocked(gatewayGet).mockResolvedValue({ datasets: [] });
	await GET(
		new NextRequest(
			"http://localhost/api/datasets?cursor=next&tenant_id=foreign",
		),
	);
	expect(gatewayGet).toHaveBeenCalledWith("/v1/datasets?cursor=next");
});

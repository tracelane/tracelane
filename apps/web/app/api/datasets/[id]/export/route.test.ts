import { NextRequest } from "next/server";
import { beforeEach, expect, it, vi } from "vitest";
vi.mock("@/lib/auth", () => ({ requireGatewayToken: vi.fn() }));
vi.mock("@/lib/gateway", async (original) => ({
	...(await original<typeof import("@/lib/gateway")>()),
	gatewayGet: vi.fn(),
	gatewayGetText: vi.fn(),
}));
import { GatewayError, gatewayGet, gatewayGetText } from "@/lib/gateway";
import { GET } from "./route";

beforeEach(() => vi.clearAllMocks());

it("rewrites Content-Disposition to the dataset's own slug, not the gateway's generic name", async () => {
	vi.mocked(gatewayGet).mockResolvedValue({ name: "Golden Refunds!!" });
	vi.mocked(gatewayGetText).mockResolvedValue('{"input":[]}\n');
	const res = await GET(new NextRequest("http://localhost"), {
		params: Promise.resolve({ id: "ds-1" }),
	});
	expect(res.status).toBe(200);
	expect(res.headers.get("content-disposition")).toBe(
		'attachment; filename="golden-refunds.jsonl"',
	);
	expect(await res.text()).toBe('{"input":[]}\n');
	expect(gatewayGetText).toHaveBeenCalledWith(
		"/v1/datasets/ds-1/export?format=jsonl",
	);
});

it("falls back to a generic slug for a name with no ASCII alphanumerics", async () => {
	vi.mocked(gatewayGet).mockResolvedValue({ name: "!!!" });
	vi.mocked(gatewayGetText).mockResolvedValue("");
	const res = await GET(new NextRequest("http://localhost"), {
		params: Promise.resolve({ id: "ds-1" }),
	});
	expect(res.headers.get("content-disposition")).toBe(
		'attachment; filename="dataset.jsonl"',
	);
});

it("preserves a 404 for a foreign dataset id", async () => {
	vi.mocked(gatewayGet).mockRejectedValue(
		new GatewayError(404, "refused", { error: "not_found" }),
	);
	const res = await GET(new NextRequest("http://localhost"), {
		params: Promise.resolve({ id: "foreign" }),
	});
	expect(res.status).toBe(404);
});

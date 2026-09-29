import { NextRequest } from "next/server";
import { beforeEach, expect, it, vi } from "vitest";
vi.mock("@/lib/auth", () => ({ requireGatewayToken: vi.fn() }));
vi.mock("@/lib/gateway", async (original) => ({
	...(await original<typeof import("@/lib/gateway")>()),
	gatewayPostText: vi.fn(),
}));
import { GatewayError, gatewayPostText } from "@/lib/gateway";
import { POST } from "./route";

beforeEach(() => vi.clearAllMocks());

it("forwards the raw body text — never re-encoded — with format=jsonl", async () => {
	vi.mocked(gatewayPostText).mockResolvedValue({
		added: 2,
		deduped: 1,
		rejected_count: 1,
		rejected: [{ line: 4, reason: "unknown field" }],
	});
	const jsonl = '{"input":[{"role":"user","content":"a"}]}\n';
	const res = await POST(
		new NextRequest("http://localhost/api/datasets/ds-1/import", {
			method: "POST",
			headers: { "content-type": "application/x-ndjson" },
			body: jsonl,
		}),
		{ params: Promise.resolve({ id: "ds-1" }) },
	);
	expect(res.status).toBe(200);
	expect(await res.json()).toMatchObject({ added: 2, deduped: 1 });
	expect(gatewayPostText).toHaveBeenCalledWith(
		"/v1/datasets/ds-1/import?format=jsonl",
		jsonl,
		"application/x-ndjson",
	);
});

it.each([409, 413])("preserves status and body %i", async (status) => {
	const body = { error: "dataset_full", limit: 200 };
	vi.mocked(gatewayPostText).mockRejectedValue(
		new GatewayError(status, "refused", body),
	);
	const res = await POST(
		new NextRequest("http://localhost/api/datasets/ds-1/import", {
			method: "POST",
			body: "x",
		}),
		{ params: Promise.resolve({ id: "ds-1" }) },
	);
	expect(res.status).toBe(status);
	expect(await res.json()).toEqual(body);
});

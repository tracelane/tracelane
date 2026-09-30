import { beforeEach, expect, it, vi } from "vitest";
vi.mock("@/lib/auth", () => ({
	requireGatewayToken: vi.fn(async () => ({
		token: "tenant-a-token",
		tenantId: "tenant-a",
	})),
}));
import { GET } from "./route";
const fetchMock = vi.fn();
beforeEach(() => {
	vi.stubGlobal("fetch", fetchMock);
	vi.stubEnv("NEXT_PUBLIC_GATEWAY_URL", "http://gateway.test");
});
it("forwards only page ids with the authenticated token and preserves unknown/error availability", async () => {
	const body = {
		traces: [{ trace_id: "a", issues: [] }],
		issues_available: false,
		inline_limit: 3,
	};
	fetchMock.mockResolvedValue(
		new Response(JSON.stringify(body), {
			headers: { "content-type": "application/json" },
		}),
	);
	const r = await GET({
		nextUrl: new URL(
			"http://app.test/api/traces/issues/rollup?trace_ids=a,b&tenant_id=foreign",
		),
	} as never);
	expect(await r.json()).toEqual(body);
	const [url, init] = fetchMock.mock.calls[0] ?? [];
	expect(new URL(url).searchParams.get("trace_ids")).toBe("a,b");
	expect(new URL(url).searchParams.has("tenant_id")).toBe(false);
	expect(init.headers.authorization).toBe("Bearer tenant-a-token");
});
it.each([403, 500])(
	"preserves denied separately from gateway failure (%s)",
	async (status) => {
		fetchMock.mockResolvedValue(
			new Response(JSON.stringify({ error: "unavailable" }), { status }),
		);
		const r = await GET({
			nextUrl: new URL("http://app.test/api/traces/issues/rollup?trace_ids=a"),
		} as never);
		expect(r.status).toBe(status === 403 ? 403 : 502);
	},
);

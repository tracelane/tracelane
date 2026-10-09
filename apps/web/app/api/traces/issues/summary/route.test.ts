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
it("reads the summary using the session token without client-supplied scope or window", async () => {
	const body = { counts: [], total_traces: 0, window_days: 3 };
	fetchMock.mockResolvedValue(
		new Response(JSON.stringify(body), {
			headers: { "content-type": "application/json" },
		}),
	);
	expect(await (await GET()).json()).toEqual(body);
	const [url, init] = fetchMock.mock.calls[0] ?? [];
	expect(url).toBe("http://gateway.test/v1/traces/issues/summary");
	expect(init.headers.authorization).toBe("Bearer tenant-a-token");
});
it.each([403, 500])(
	"preserves denial separately from summary failure (%s)",
	async (status) => {
		fetchMock.mockResolvedValue(
			new Response(JSON.stringify({ error: "unavailable" }), { status }),
		);
		expect((await GET()).status).toBe(status === 403 ? 403 : 502);
	},
);

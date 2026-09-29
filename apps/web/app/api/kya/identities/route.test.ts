import { NextRequest } from "next/server";
import { beforeEach, expect, it, vi } from "vitest";
vi.mock("@/lib/gateway", async (original) => ({
	...(await original<typeof import("@/lib/gateway")>()),
	gatewayGet: vi.fn(),
}));
vi.mock("@/lib/auth", () => ({ requireGatewayToken: vi.fn() }));
import { GatewayError, gatewayGet } from "@/lib/gateway";
import { GET as traces } from "../../traces/route";
import { GET as profile } from "./[kind]/[key]/route";
import { GET } from "./route";
const get = vi.mocked(gatewayGet);
beforeEach(() => {
	get.mockReset();
});
it("reads the chosen kind and window without forwarding a tenant", async () => {
	get.mockResolvedValue({ identities: [{ key: "codex", calls: 1 }] });
	const r = await GET(
		new NextRequest(
			"http://local/api/kya/identities?kind=agent&window=30d&tenant_id=other",
		),
	);
	expect(r.status).toBe(200);
	expect(get).toHaveBeenCalledWith("/v1/kya/identities?kind=agent&window=30d");
	expect(await r.json()).toEqual({ identities: [{ key: "codex", calls: 1 }] });
});
it.each([403, 404, 502])("preserves the %i state", async (code) => {
	get.mockRejectedValue(new GatewayError(code, "refused"));
	expect(
		(await GET(new NextRequest("http://local/api/kya/identities"))).status,
	).toBe(code);
});
it("encodes a profile key and refuses invalid kinds", async () => {
	get.mockResolvedValue({ identities: [] });
	const req = new NextRequest(
		"http://local/api/kya/identities/agent/my%2Fagent?window=7d&tenant_id=other",
	);
	expect(
		(
			await profile(req, {
				params: Promise.resolve({ kind: "agent", key: "my/agent" }),
			})
		).status,
	).toBe(200);
	expect(get).toHaveBeenCalledWith(
		"/v1/kya/identities/agent/my%2Fagent?window=7d",
	);
	get.mockClear();
	expect(
		(
			await profile(req, {
				params: Promise.resolve({ kind: "provider", key: "x" }),
			})
		).status,
	).toBe(400);
	expect(get).not.toHaveBeenCalled();
});

it("profile filters reach the trace list without a caller tenant", async () => {
	get.mockResolvedValue({ traces: [] });
	await traces(
		new NextRequest(
			"http://local/api/traces?agent=codex&model_family=llama-3.3&tenant_id=other",
		),
	);
	expect(get).toHaveBeenCalledWith(
		"/v1/traces?agent=codex&model_family=llama-3.3",
	);
});

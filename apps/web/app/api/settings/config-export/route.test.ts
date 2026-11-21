/** The export relay: the document passes through, a 403 stays a 403, internals are masked. */
import { beforeEach, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	token: vi.fn(async () => ({ token: "t" })),
	gw: vi.fn(),
}));
vi.mock("@/lib/auth", () => ({ requireGatewayToken: h.token }));
vi.mock("@/lib/gateway", () => ({ gatewayResponse: h.gw }));

import { GET } from "./route";

const upstream = (status: number, body: unknown) =>
	new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json" },
	});

beforeEach(() => h.gw.mockReset());

it("relays the document and asks the gateway for exactly the export route", async () => {
	h.gw.mockResolvedValue(upstream(200, { schema: "tracelane.config/v1" }));
	const res = await GET();
	expect(res.status).toBe(200);
	expect(await res.json()).toEqual({ schema: "tracelane.config/v1" });
	expect(h.gw).toHaveBeenCalledWith("/v1/config/export");
	expect(res.headers.get("cache-control")).toBe("no-store");
});

it("keeps a 403, and masks any other upstream failure", async () => {
	h.gw.mockResolvedValue(
		upstream(403, { error: "role_forbidden", capability: "manage_config" }),
	);
	const forbidden = await GET();
	expect(forbidden.status).toBe(403);
	expect(await forbidden.json()).toEqual({ error: "role_forbidden" });

	h.gw.mockResolvedValue(upstream(500, { error: "boom", detail: "secret" }));
	const failed = await GET();
	expect(failed.status).toBe(502);
	expect(JSON.stringify(await failed.json())).not.toContain("secret");

	h.gw.mockResolvedValue(upstream(503, { error: "config_export_unavailable" }));
	const unavailable = await GET();
	expect(unavailable.status).toBe(503);
	expect(await unavailable.json()).toEqual({
		error: "config_export_unavailable",
	});
});

/**
 * Tests for GET /api/billing/window-breakdown — the "what's using your
 * window" proxy (spec `BILL-01` §2.6). Negative cases first.
 */

import type { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/auth", () => ({
	requireGatewayToken: vi.fn(async () => ({ token: "minted-jwt" })),
}));

import { GET } from "./route";

function req(by?: string): NextRequest {
	const qs = by ? `?by=${by}` : "";
	return {
		nextUrl: new URL(`http://localhost/api/billing/window-breakdown${qs}`),
	} as unknown as NextRequest;
}

describe("GET /api/billing/window-breakdown", () => {
	afterEach(() => vi.unstubAllGlobals());

	it("REJECT: an invalid 'by' dimension is a 400, no gateway call", async () => {
		const spy = vi.fn();
		vi.stubGlobal("fetch", spy);
		const res = await GET(req("bogus"));
		expect(res.status).toBe(400);
		expect(spy).not.toHaveBeenCalled();
	});

	it("defaults to by=project when unset", async () => {
		const spy = vi.fn(
			async (url: string) =>
				({
					ok: true,
					json: async () => ({ by: "project", rows: [], shown: 0, total: 0 }),
				}) as unknown as Response,
		);
		vi.stubGlobal("fetch", spy);
		await GET(req());
		expect(spy.mock.calls[0]?.[0]).toContain("by=project");
	});

	it("maps a gateway failure to 502, never leaking the upstream body", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => ({ ok: false, status: 500 }) as unknown as Response),
		);
		const res = await GET(req("service"));
		expect(res.status).toBe(502);
	});

	it("HAPPY: returns the breakdown rows verbatim, forwarding the minted JWT", async () => {
		const body = {
			by: "capture",
			rows: [{ label: "content-on", gb: 5, pct: 40 }],
			shown: 1,
			total: 1,
		};
		const spy = vi.fn(
			async (..._args: unknown[]) =>
				({ ok: true, json: async () => body }) as unknown as Response,
		);
		vi.stubGlobal("fetch", spy);
		const res = await GET(req("capture"));
		expect(await res.json()).toEqual(body);
		const init = spy.mock.calls[0]?.[1] as { headers?: Record<string, string> };
		expect(init.headers?.authorization).toBe("Bearer minted-jwt");
	});
});

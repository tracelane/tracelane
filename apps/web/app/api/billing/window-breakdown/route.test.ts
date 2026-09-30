/**
 * Tests for GET /api/billing/window-breakdown — the "what's using your
 * window" proxy (spec `BILL-01` §2.6). Negative cases first.
 */

import type { NextRequest } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";

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

	it("rejects project and names its replacement", async () => {
		const spy = vi.fn();
		vi.stubGlobal("fetch", spy);
		const result = await GET(req("project"));
		expect(result.status).toBe(400);
		expect((await result.json()).error).toContain("key");
		expect(spy).not.toHaveBeenCalled();
	});
	it.each(["key", "service"])(
		"forwards %s with the real gateway response shape",
		async (by) => {
			const body = {
				by,
				rows: [{ key: "checkout", bytes: 1000 }],
				total_bytes: 1000,
				truncated: false,
			};
			const spy = vi.fn(async () => ({ ok: true, json: async () => body }));
			vi.stubGlobal("fetch", spy);
			const result = await GET(req(by));
			expect(result.status).toBe(200);
			expect(await result.json()).toEqual(body);
			expect(spy.mock.calls.length).toBe(1);
		},
	);

	it("defaults to by=capture when unset", async () => {
		const spy = vi.fn(
			async (url: string) =>
				({
					ok: true,
					json: async () => ({
						by: "capture",
						rows: [],
						total_bytes: 0,
						truncated: false,
					}),
				}) as unknown as Response,
		);
		vi.stubGlobal("fetch", spy);
		await GET(req());
		expect(spy.mock.calls[0]?.[0]).toContain("by=capture");
	});

	it("maps a gateway failure to 502, never leaking the upstream body", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => ({ ok: false, status: 500 }) as unknown as Response),
		);
		const res = await GET(req("capture"));
		expect(res.status).toBe(502);
	});

	it("HAPPY: returns the breakdown rows verbatim, forwarding the minted JWT", async () => {
		const body = {
			by: "capture",
			rows: [{ key: "content", bytes: 5_000_000_000 }],
			total_bytes: 5_000_000_000,
			truncated: false,
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

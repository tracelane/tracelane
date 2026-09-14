/**
 * Tests for PUT /api/billing/ceiling — spend-ceiling proxy (spec `BILL-01`
 * §2.6, `admin` scope). Admin-gated at THIS layer too (spec §4
 * "Permission-denied"), not only at the gateway. Negative cases first.
 */

import type { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ role: "owner" as string | null }));

vi.mock("@/lib/auth", () => ({
	requireSession: vi.fn(async () => ({
		tenantId: "org_A",
		userId: "u1",
		role: h.role,
	})),
	requireGatewayToken: vi.fn(async () => ({ token: "minted-jwt" })),
	canAdmin: (role: string | null | undefined) =>
		role === "owner" || role === "admin",
}));

import { PUT } from "./route";

function req(body: unknown): NextRequest {
	return { json: async () => body } as unknown as NextRequest;
}

describe("PUT /api/billing/ceiling", () => {
	beforeEach(() => {
		h.role = "owner";
	});
	afterEach(() => vi.unstubAllGlobals());

	it("REJECT: a non-admin member is refused before touching the gateway", async () => {
		h.role = "member";
		const spy = vi.fn();
		vi.stubGlobal("fetch", spy);
		const res = await PUT(req({ usd: 500, overflow_mode: "auto_age" }));
		expect(res.status).toBe(403);
		expect(spy).not.toHaveBeenCalled();
	});

	it("REJECT: malformed body → 422", async () => {
		const res = await PUT(
			req({ usd: "five hundred", overflow_mode: "auto_age" }),
		);
		expect(res.status).toBe(422);
	});

	it("REJECT: an unknown overflow_mode → 422", async () => {
		const res = await PUT(
			req({ usd: 500, overflow_mode: "delete_everything" }),
		);
		expect(res.status).toBe(422);
	});

	it("ACCEPT: usd: null (turning the ceiling off) is valid", async () => {
		const spy = vi.fn(
			async () =>
				({
					ok: true,
					json: async () => ({ usd: null, overflow_mode: "auto_age" }),
				}) as unknown as Response,
		);
		vi.stubGlobal("fetch", spy);
		const res = await PUT(req({ usd: null, overflow_mode: "auto_age" }));
		expect(res.status).toBe(200);
	});

	it("maps a gateway failure to 502 without leaking the body", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(
				async () =>
					({
						ok: false,
						status: 500,
						json: async () => ({ error: "SECRET" }),
					}) as unknown as Response,
			),
		);
		const res = await PUT(req({ usd: 500, overflow_mode: "auto_age" }));
		expect(res.status).toBe(502);
		expect(JSON.stringify(await res.json())).not.toContain("SECRET");
	});

	it("HAPPY: forwards the body + minted JWT, returns the gateway's response", async () => {
		const spy = vi.fn(
			async (..._args: unknown[]) =>
				({
					ok: true,
					json: async () => ({ usd: 500, overflow_mode: "auto_overage" }),
				}) as unknown as Response,
		);
		vi.stubGlobal("fetch", spy);
		const res = await PUT(req({ usd: 500, overflow_mode: "auto_overage" }));
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({
			usd: 500,
			overflow_mode: "auto_overage",
		});
		const init = spy.mock.calls[0]?.[1] as {
			method?: string;
			headers?: Record<string, string>;
		};
		expect(init.method).toBe("PUT");
		expect(init.headers?.authorization).toBe("Bearer minted-jwt");
	});
});

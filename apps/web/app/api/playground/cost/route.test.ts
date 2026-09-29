/**
 * Tests for GET /api/playground/cost (`specs/EVL-03…` §2/§3 table row 3,
 * §7 proof 8). `@/lib/gateway` is mocked wholesale — never a real network
 * (`.claude/rules/testing.md`).
 */
import type { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => {
	class FakeGatewayError extends Error {
		readonly status: number;
		readonly body: Record<string, unknown> | null;
		constructor(
			status: number,
			message: string,
			body: Record<string, unknown> | null = null,
		) {
			super(message);
			this.status = status;
			this.body = body;
		}
	}
	return { gatewayGetOrNull: vi.fn(), FakeGatewayError };
});

vi.mock("@/lib/gateway", () => ({
	gatewayGetOrNull: (...args: unknown[]) =>
		h.gatewayGetOrNull(...(args as [string])),
	GatewayError: h.FakeGatewayError,
}));

import { GET } from "./route";

function req(url: string): NextRequest {
	return { nextUrl: new URL(url) } as unknown as NextRequest;
}

beforeEach(() => {
	h.gatewayGetOrNull.mockReset();
});

describe("GET /api/playground/cost", () => {
	it("400s with no trace param", async () => {
		const res = await GET(req("https://x/api/playground/cost"));
		expect(res.status).toBe(400);
	});

	it("reads the SAME /v1/traces/{id}/spans route the prefill uses", async () => {
		h.gatewayGetOrNull.mockResolvedValue([]);
		await GET(req("https://x/api/playground/cost?trace=1c2d0000"));
		expect(h.gatewayGetOrNull).toHaveBeenCalledWith(
			"/v1/traces/1c2d0000/spans",
		);
	});

	it("state=pending when the trace has not landed yet (gatewayGetOrNull → null, a 404)", async () => {
		h.gatewayGetOrNull.mockResolvedValue(null);
		const res = await GET(req("https://x/api/playground/cost?trace=abc"));
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ state: "pending" });
	});

	it("state=pending when spans exist but the gen_ai.chat span has not landed yet", async () => {
		h.gatewayGetOrNull.mockResolvedValue([
			{ name: "some.other.span", attributes: "{}" },
		]);
		const res = await GET(req("https://x/api/playground/cost?trace=abc"));
		expect(await res.json()).toEqual({ state: "pending" });
	});

	it("state=priced with cost_usd from gen_ai_usage_cost on the gen_ai.chat span", async () => {
		h.gatewayGetOrNull.mockResolvedValue([
			{
				name: "gen_ai.chat",
				attributes: JSON.stringify({ gen_ai_usage_cost: 0.0012 }),
			},
		]);
		const res = await GET(req("https://x/api/playground/cost?trace=abc"));
		expect(await res.json()).toEqual({ state: "priced", cost_usd: 0.0012 });
	});

	it("state=unpriced, NEVER $0.00, when gen_ai_usage_cost is absent for a real chat span", async () => {
		h.gatewayGetOrNull.mockResolvedValue([
			{
				name: "gen_ai.chat",
				attributes: JSON.stringify({ gen_ai_request_model: "x" }),
			},
		]);
		const res = await GET(req("https://x/api/playground/cost?trace=abc"));
		expect(await res.json()).toEqual({ state: "unpriced" });
	});

	it("passes a non-404 gateway error through with its status", async () => {
		h.gatewayGetOrNull.mockRejectedValue(
			new h.FakeGatewayError(503, "unreachable"),
		);
		const res = await GET(req("https://x/api/playground/cost?trace=abc"));
		expect(res.status).toBe(503);
	});
});

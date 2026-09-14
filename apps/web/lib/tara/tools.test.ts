/**
 * Tests for lib/tara/tools — the closed, zod-validated tool set (OBS-40 §7
 * proofs 2 and 3).
 *
 * `gatewayGet` is mocked so a test that expects "never dispatched" can prove
 * it structurally (the mock is a spy, not a real network call) rather than
 * merely asserting on the returned shape.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

// `vi.hoisted` — vitest hoists `vi.mock` factories above ALL other module
// code, including plain `const` declarations, so a factory that closes over
// a normal top-level variable throws "Cannot access before initialization".
// This is the same pattern `lib/prompts.test.ts` uses.
const { gatewayGetSpy } = vi.hoisted(() => ({
	gatewayGetSpy: vi.fn(async (_path: string) => ({ ok: true })),
}));

vi.mock("@/lib/gateway", () => ({
	gatewayGet: (path: string) => gatewayGetSpy(path),
	GatewayError: class GatewayError extends Error {
		status: number;
		constructor(status: number, message: string) {
			super(message);
			this.status = status;
		}
	},
}));

import {
	TARA_TOOLS,
	assertNoTenantIdField,
	extractTraceIdCitations,
	runTaraTool,
} from "./tools";

beforeEach(() => {
	gatewayGetSpy.mockClear();
});

describe("proof #3 — no tool schema has a tenant_id field", () => {
	it("assertNoTenantIdField does not throw over the real registry", () => {
		expect(() => assertNoTenantIdField()).not.toThrow();
	});

	it("holds for every tool individually (a future addition cannot slip one in unnoticed)", () => {
		for (const tool of TARA_TOOLS) {
			const parsed = tool.schema.safeParse({});
			// Even a schema that requires other fields must never accept
			// tenant_id as a recognised key — zod's default (non-strict) object
			// parsing does not reject unknown keys, so this asserts on the shape
			// definition itself instead of relying on that being stricter than
			// it is.
			const shape = (
				tool.schema as unknown as { shape?: Record<string, unknown> }
			).shape;
			expect(shape ? Object.hasOwn(shape, "tenant_id") : false).toBe(false);
			void parsed;
		}
	});

	it("the registry is exactly the 7 tools the spec names", () => {
		expect(TARA_TOOLS.map((t) => t.name).sort()).toEqual(
			[
				"cost_breakdown",
				"get_trace",
				"guardrail_verdicts",
				"list_sessions",
				"list_traces",
				"search_traces",
				"slo_summary",
			].sort(),
		);
	});
});

describe("proof #2 — the guard blocks before fetch", () => {
	it("refuses list_traces limit: 999999 WITHOUT calling gatewayGet", async () => {
		const result = await runTaraTool("list_traces", { limit: 999999 });
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.error.error).toBe("invalid_arguments");
		expect(gatewayGetSpy).not.toHaveBeenCalled();
	});

	it("refuses a path-traversal trace_id WITHOUT calling gatewayGet", async () => {
		const result = await runTaraTool("get_trace", {
			trace_id: "../../etc/passwd",
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.error.error).toBe("invalid_arguments");
		expect(gatewayGetSpy).not.toHaveBeenCalled();
	});

	it("refuses a trace_id that is too short WITHOUT calling gatewayGet", async () => {
		const result = await runTaraTool("get_trace", { trace_id: "abc" });
		expect(result.ok).toBe(false);
		expect(gatewayGetSpy).not.toHaveBeenCalled();
	});

	it("refuses search_traces with a 3-character query (gateway minimum is 4)", async () => {
		const result = await runTaraTool("search_traces", { q: "abc" });
		expect(result.ok).toBe(false);
		expect(gatewayGetSpy).not.toHaveBeenCalled();
	});

	it("refuses an unknown tool name WITHOUT calling gatewayGet", async () => {
		const result = await runTaraTool("delete_everything", {});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.error.error).toBe("unknown_tool");
		expect(gatewayGetSpy).not.toHaveBeenCalled();
	});

	it("DOES dispatch a valid list_traces call", async () => {
		const result = await runTaraTool("list_traces", { limit: 10 });
		expect(result.ok).toBe(true);
		expect(gatewayGetSpy).toHaveBeenCalledTimes(1);
		expect(gatewayGetSpy).toHaveBeenCalledWith(
			expect.stringContaining("/v1/traces"),
		);
	});

	it("DOES dispatch a valid get_trace call with the real trace_id in the path", async () => {
		const result = await runTaraTool("get_trace", {
			trace_id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		});
		expect(result.ok).toBe(true);
		expect(gatewayGetSpy).toHaveBeenCalledWith(
			"/v1/traces/a1b2c3d4-e5f6-7890-abcd-ef1234567890/spans",
		);
	});
});

describe("the four windowed tools route through lib/metrics/fetch.ts (specs/metrics-renovation.md §3c)", () => {
	it("cost_breakdown asks for a since/until pair, not an hours-only window, and forwards by/scope", async () => {
		const result = await runTaraTool("cost_breakdown", {
			hours: 48,
			by: "provider",
			scope: "production",
		});
		expect(result.ok).toBe(true);
		expect(gatewayGetSpy).toHaveBeenCalledTimes(1);
		const calledUrl = gatewayGetSpy.mock.calls[0]?.[0] as string;
		expect(calledUrl).toContain("/v1/costs");
		expect(calledUrl).toContain("since=");
		expect(calledUrl).toContain("until=");
		expect(calledUrl).toContain("by=provider");
		expect(calledUrl).toContain("scope=production");
	});

	it("list_sessions converts `days` into a since/until pair — no raw `days=` param reaches the gateway", async () => {
		const result = await runTaraTool("list_sessions", { days: 7, limit: 5 });
		expect(result.ok).toBe(true);
		const calledUrl = gatewayGetSpy.mock.calls[0]?.[0] as string;
		expect(calledUrl).toContain("/v1/sessions");
		expect(calledUrl).toContain("since=");
		expect(calledUrl).toContain("until=");
		expect(calledUrl).not.toContain("days=");
		expect(calledUrl).toContain("limit=5");
	});

	it("slo_summary forwards provider/model through the shared fetcher", async () => {
		const result = await runTaraTool("slo_summary", {
			hours: 6,
			provider: "anthropic",
			model: "claude-sonnet-4-6",
		});
		expect(result.ok).toBe(true);
		const calledUrl = gatewayGetSpy.mock.calls[0]?.[0] as string;
		expect(calledUrl).toContain("/v1/slo/summary");
		expect(calledUrl).toContain("provider=anthropic");
		expect(calledUrl).toContain("model=claude-sonnet-4-6");
	});

	it("guardrail_verdicts maps correlation_id/rail/decision through fetchGuardrailVerdictsFor's opts", async () => {
		const result = await runTaraTool("guardrail_verdicts", {
			hours: 24,
			decision: "block",
			correlation_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
			rail: "R4_trifecta",
		});
		expect(result.ok).toBe(true);
		const calledUrl = gatewayGetSpy.mock.calls[0]?.[0] as string;
		expect(calledUrl).toContain("/v1/guardrails/verdicts");
		expect(calledUrl).toContain("decision=block");
		expect(calledUrl).toContain("correlation_id=01ARZ3NDEKTSV4RRFFQ69G5FAV");
		expect(calledUrl).toContain("rail=R4_trifecta");
	});

	it("a gateway-unreachable read (GatewayError, swallowed by the shared fetcher's orNull) becomes a gateway_error result, not a thrown exception", async () => {
		gatewayGetSpy.mockImplementationOnce(async () => {
			const { GatewayError } = await import("@/lib/gateway");
			throw new GatewayError(503, "upstream unavailable");
		});
		const result = await runTaraTool("slo_summary", { hours: 24 });
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.error).toBe("gateway_error");
			expect(result.error).toMatchObject({ status: 502 });
		}
	});
});

describe("extractTraceIdCitations", () => {
	it("finds trace_id fields nested in an array response, deduped", () => {
		const value = {
			traces: [
				{
					trace_id: "aaaaaaaa-0000-0000-0000-000000000000",
					model: "claude-sonnet-4-6",
				},
				{
					trace_id: "bbbbbbbb-0000-0000-0000-000000000000",
					model: "claude-haiku-4-5",
				},
				{
					trace_id: "aaaaaaaa-0000-0000-0000-000000000000",
					model: "claude-sonnet-4-6",
				},
			],
		};
		const out = extractTraceIdCitations(value);
		expect(out).toHaveLength(2);
		expect(out.map((c) => c.trace_id)).toEqual([
			"aaaaaaaa-0000-0000-0000-000000000000",
			"bbbbbbbb-0000-0000-0000-000000000000",
		]);
	});

	it("returns nothing for a response with no trace_id anywhere", () => {
		expect(
			extractTraceIdCitations({ total_cost_usd: 1.2, rows: [] }),
		).toHaveLength(0);
	});
});

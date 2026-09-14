/**
 * PLT-22 — gateway-mode (Cloud tenant) trace MCP tools.
 *
 * `CLICKHOUSE_URL` is unset here, so `GatewayReader` is the reader under
 * test: every tool call is an HTTP GET against `TRACELANE_GATEWAY_URL`'s
 * existing `/v1/*` routes, authenticated with `Authorization: Bearer
 * $TRACELANE_API_KEY`. `fetch` is stubbed at the global — no real network
 * (testing.md).
 *
 * Covers the proofs from `specs/PLT-22-mcp-server-cloud-tenants.md` §7:
 *   - happy path for every tool, reading the gateway's real response shapes
 *     (`TraceListResponse`, bare `SpanRow[]`, `GuardrailVerdictListResponse`)
 *   - a non-2xx gateway response becomes an MCP tool error (`isError: true`)
 *     carrying the gateway's status + message verbatim, for 401 / 403 / 404
 *     — never an empty array
 *   - `get_span` without `trace_id` is a clear tool error (no span-by-id
 *     gateway route exists)
 *   - `explain_guardrail_block` branches on `correlation_id` vs
 *     `trace_id`+`span_id`, and refuses cleanly when neither is given
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { runWithTenant } from "../auth.js";
import { GatewayReader } from "../reader.js";
import { registerTraceTools } from "./traces.js";

type ToolHandlerResult = {
	content: Array<{ type: string; text: string }>;
	isError?: boolean;
};
type ToolHandler = (
	args: Record<string, unknown>,
) => Promise<ToolHandlerResult>;

interface RegisteredTool {
	name: string;
	description: string;
	schema: Record<string, unknown>;
	handler: ToolHandler;
}

const registered = new Map<string, RegisteredTool>();

const fakeServer = {
	tool(
		name: string,
		description: string,
		schema: RegisteredTool["schema"],
		handler: ToolHandler,
	) {
		registered.set(name, { name, description, schema, handler });
		return {};
	},
};

async function callTool(
	name: string,
	args: Record<string, unknown>,
): Promise<{ body: Record<string, unknown>; isError: boolean }> {
	const tool = registered.get(name);
	if (!tool) throw new Error(`tool ${name} not registered`);
	const res = await tool.handler(args);
	const text = res.content[0]?.text;
	if (text === undefined) throw new Error("no text content");
	return { body: JSON.parse(text), isError: res.isError === true };
}

function jsonResponse(status: number, body: unknown): Response {
	return {
		ok: status >= 200 && status < 300,
		status,
		statusText: `status ${status}`,
		json: async () => body,
	} as unknown as Response;
}

const TEST_API_KEY = "tlane_test_key_do_not_use_in_prod";

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
	registered.clear();
	vi.stubEnv("TRACELANE_GATEWAY_URL", "http://localhost:8080");
	vi.stubEnv("TRACELANE_API_KEY", TEST_API_KEY);
	fetchMock = vi.fn();
	vi.stubGlobal("fetch", fetchMock);
	// biome-ignore lint/suspicious/noExplicitAny: structural fake.
	registerTraceTools(fakeServer as any, new GatewayReader());
});

afterEach(() => {
	vi.unstubAllEnvs();
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

describe("registerTraceTools (gateway mode) registration", () => {
	it("registers the same six read-only tools as ClickHouse mode", () => {
		expect([...registered.keys()].sort()).toEqual(
			[
				"explain_guardrail_block",
				"get_span",
				"get_trace",
				"list_traces",
				"replay_trace",
				"search_traces",
			].sort(),
		);
	});
});

describe("happy path — every tool, real gateway response shapes", () => {
	it("list_traces calls GET /v1/traces with the bearer and returns the gateway rows", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(200, {
				traces: [
					{
						trace_id: "t1",
						root_name: "root",
						start_time: "2026-01-01 00:00:00.000000",
						duration_us: 100,
						span_count: 2,
						error_count: 0,
						intervention: 0,
						model: "claude-sonnet-4-6",
						cost_usd: 0.01,
						total_tokens: 42,
					},
				],
				next_cursor: null,
			}),
		);

		const { body, isError } = await callTool("list_traces", { limit: 5 });

		expect(isError).toBe(false);
		expect(body.count).toBe(1);
		expect((body.traces as Array<{ trace_id: string }>)[0]?.trace_id).toBe(
			"t1",
		);

		expect(fetchMock).toHaveBeenCalledTimes(1);
		const [url, init] = fetchMock.mock.calls[0] as [URL, RequestInit];
		expect(String(url)).toContain("/v1/traces?");
		expect(String(url)).toContain("limit=5");
		expect((init.headers as Record<string, string>).authorization).toBe(
			`Bearer ${TEST_API_KEY}`,
		);
	});

	it("list_traces omits absent filters from the query string", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(200, { traces: [], next_cursor: null }),
		);
		await callTool("list_traces", { limit: 5 });
		const [url] = fetchMock.mock.calls[0] as [URL];
		expect(String(url)).not.toContain("model=");
		expect(String(url)).not.toContain("has_error=");
	});

	it("get_trace calls GET /v1/traces/{trace_id}/spans and returns the bare span array", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(200, [
				{
					span_id: "s1",
					parent_span_id: null,
					name: "llm.chat",
					start_time: "t",
					end_time: "t2",
					duration_us: 10,
					status_code: 1,
					status_message: "",
					attributes: "{}",
					aft_ids: [],
					intervention: 0,
				},
			]),
		);

		const { body, isError } = await callTool("get_trace", {
			trace_id: "trace-1",
		});

		expect(isError).toBe(false);
		expect(body.span_count).toBe(1);
		const [url] = fetchMock.mock.calls[0] as [URL];
		expect(String(url)).toContain("/v1/traces/trace-1/spans");
	});

	it("get_span fetches the trace's spans and picks the one matching span_id", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(200, [
				{
					span_id: "s1",
					parent_span_id: null,
					name: "a",
					start_time: "t",
					end_time: "t2",
					duration_us: 1,
					status_code: 1,
					status_message: "",
					attributes: JSON.stringify({ "gen_ai.request.model": "x" }),
					aft_ids: [],
					intervention: 0,
				},
				{
					span_id: "s2",
					parent_span_id: "s1",
					name: "b",
					start_time: "t",
					end_time: "t2",
					duration_us: 1,
					status_code: 1,
					status_message: "",
					attributes: "{}",
					aft_ids: [],
					intervention: 0,
				},
			]),
		);

		const { body, isError } = await callTool("get_span", {
			trace_id: "trace-1",
			span_id: "s2",
		});

		expect(isError).toBe(false);
		expect(body.span_id).toBe("s2");
		expect(body.attributes).toEqual({});
	});

	it("search_traces calls GET /v1/traces?q= and returns trace summaries, honestly labelled", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(200, {
				traces: [
					{
						trace_id: "t9",
						root_name: "r",
						start_time: "t",
						duration_us: 1,
						span_count: 1,
						error_count: 0,
						intervention: 0,
						model: "m",
					},
				],
				next_cursor: null,
			}),
		);

		const { body, isError } = await callTool("search_traces", {
			query: "timeout",
			limit: 5,
		});

		expect(isError).toBe(false);
		expect(body.count).toBe(1);
		expect(body.traces).toBeDefined();
		// Never claims the ClickHouse-only per-span match shape.
		expect(body.matches).toBeUndefined();
		const [url] = fetchMock.mock.calls[0] as [URL];
		expect(String(url)).toContain("q=timeout");
	});

	it("replay_trace fetches spans and returns the inspection shape (no shadow exec)", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(200, [
				{
					span_id: "s1",
					parent_span_id: null,
					name: "llm.chat",
					start_time: "t",
					end_time: "t2",
					duration_us: 1,
					status_code: 1,
					status_message: "",
					attributes: JSON.stringify({ "llm.model_name": "gpt-4o" }),
					aft_ids: [],
					intervention: 0,
				},
			]),
		);

		const { body, isError } = await callTool("replay_trace", {
			trace_id: "trace-1",
			include_tool_calls: true,
		});

		expect(isError).toBe(false);
		expect(body.span_count).toBe(1);
		expect(body.replayed).toBe(false);
	});

	it("explain_guardrail_block(correlation_id) calls GET /v1/guardrails/verdicts", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(200, {
				verdicts: [
					{
						correlation_id: "01ABC",
						side: "request",
						decision: "block",
						event_time: "t",
						total_latency_micros: 100,
						rails: JSON.stringify([{ rail: "R4_trifecta", decision: "block" }]),
						fail_open_rails: [],
					},
				],
			}),
		);

		const { body, isError } = await callTool("explain_guardrail_block", {
			correlation_id: "01ABC",
		});

		expect(isError).toBe(false);
		expect((body.verdicts as unknown[]).length).toBe(1);
		const [url] = fetchMock.mock.calls[0] as [URL];
		expect(String(url)).toContain("correlation_id=01ABC");
	});

	it("explain_guardrail_block(trace_id, span_id) explains an AFT flag via the span route, same as ClickHouse mode", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(200, [
				{
					span_id: "s1",
					parent_span_id: null,
					name: "tool.call",
					start_time: "t",
					end_time: "t2",
					duration_us: 1,
					status_code: 1,
					status_message: "",
					attributes: "{}",
					aft_ids: ["AF-13"],
					intervention: 1,
				},
			]),
		);

		const { body, isError } = await callTool("explain_guardrail_block", {
			trace_id: "trace-1",
			span_id: "s1",
		});

		expect(isError).toBe(false);
		expect(body.intervention).toBe("warn");
		expect(body.aft_ids).toEqual(["AF-13"]);
		const [url] = fetchMock.mock.calls[0] as [URL];
		expect(String(url)).toContain("/v1/traces/trace-1/spans");
	});

	it("explain_guardrail_block with an empty verdict result is a filtered-empty state, not an error", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse(200, { verdicts: [] }));
		const { body, isError } = await callTool("explain_guardrail_block", {
			correlation_id: "01-nonexistent",
		});
		expect(isError).toBe(false);
		expect(body.verdicts).toEqual([]);
	});
});

describe("input errors (no gateway route exists to serve them)", () => {
	it("get_span without trace_id is a clear tool error, never an empty result", async () => {
		const { body, isError } = await callTool("get_span", { span_id: "s1" });
		expect(isError).toBe(true);
		expect(String(body.error)).toMatch(/trace_id/);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("explain_guardrail_block with neither correlation_id nor trace_id+span_id is a clear tool error", async () => {
		const { body, isError } = await callTool("explain_guardrail_block", {});
		expect(isError).toBe(true);
		expect(String(body.error)).toMatch(/correlation_id/);
		expect(fetchMock).not.toHaveBeenCalled();
	});
});

describe("a non-2xx gateway response becomes a tool error, never [] (PLT-22 proofs 2+3)", () => {
	it("401 (key rejected) is a tool error carrying the gateway message + status verbatim", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(401, { error: "invalid credentials" }),
		);
		const { body, isError } = await callTool("list_traces", { limit: 5 });
		expect(isError).toBe(true);
		expect(body.status).toBe(401);
		expect(body.error).toBe("invalid credentials");
	});

	it("403 (key lacks read scope) is a tool error carrying the gateway message verbatim", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(403, {
				error:
					"This API key is not scoped to read recorded data. It needs the `read` scope.",
			}),
		);
		const { body, isError } = await callTool("list_traces", { limit: 5 });
		expect(isError).toBe(true);
		expect(body.status).toBe(403);
		expect(body.error).toContain("read` scope");
	});

	it("404 for another tenant's trace_id is a tool error, never an empty array", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(404, { error: "trace not found" }),
		);
		const { body, isError } = await callTool("get_trace", {
			trace_id: "another-tenants-trace",
		});
		expect(isError).toBe(true);
		expect(body.status).toBe(404);
		expect(body.error).toBe("trace not found");
		expect(Array.isArray((body as { spans?: unknown }).spans)).toBe(false);
	});

	it("search_traces surfaces the gateway's 4-char minimum message verbatim", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(400, { error: "search term must be at least 4 characters" }),
		);
		const { body, isError } = await callTool("search_traces", {
			query: "ab",
			limit: 5,
		});
		expect(isError).toBe(true);
		expect(body.status).toBe(400);
		expect(body.error).toBe("search term must be at least 4 characters");
	});

	it("a network failure (fetch rejects) is a tool error, not an uncaught throw", async () => {
		fetchMock.mockRejectedValueOnce(new Error("ECONNREFUSED"));
		const { body, isError } = await callTool("list_traces", { limit: 5 });
		expect(isError).toBe(true);
		expect(String(body.error)).toMatch(/could not reach the gateway/);
	});

	it("an unset TRACELANE_API_KEY at call time is a tool error naming the missing var", async () => {
		vi.stubEnv("TRACELANE_API_KEY", "");
		const { body, isError } = await callTool("list_traces", { limit: 5 });
		expect(isError).toBe(true);
		expect(String(body.error)).toMatch(/TRACELANE_API_KEY/);
		expect(fetchMock).not.toHaveBeenCalled();
	});
});

describe("HTTP mode: the CALLER's own bearer is used, never the fixed env key (cross-tenant fix)", () => {
	it("two sequential requests with different bearers each carry their own Authorization header", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(200, { traces: [], next_cursor: null }),
		);
		await runWithTenant(
			"tenant-A",
			async () => {
				const { isError } = await callTool("list_traces", { limit: 5 });
				expect(isError).toBe(false);
			},
			"tlane_caller_A_bearer",
		);
		const [, initA] = fetchMock.mock.calls[0] as [URL, RequestInit];
		expect((initA.headers as Record<string, string>).authorization).toBe(
			"Bearer tlane_caller_A_bearer",
		);

		fetchMock.mockResolvedValueOnce(
			jsonResponse(200, { traces: [], next_cursor: null }),
		);
		await runWithTenant(
			"tenant-B",
			async () => {
				const { isError } = await callTool("list_traces", { limit: 5 });
				expect(isError).toBe(false);
			},
			"tlane_caller_B_bearer",
		);
		const [, initB] = fetchMock.mock.calls[1] as [URL, RequestInit];
		expect((initB.headers as Record<string, string>).authorization).toBe(
			"Bearer tlane_caller_B_bearer",
		);

		// Neither request used the process's fixed env key — each read as its
		// own caller's identity, which is the whole point of the fix.
		expect(
			(initA.headers as Record<string, string>).authorization,
		).not.toContain(TEST_API_KEY);
		expect(
			(initB.headers as Record<string, string>).authorization,
		).not.toContain(TEST_API_KEY);
	});

	it("an HTTP request context with no bearer bound fails closed, never falls back to the env key", async () => {
		await runWithTenant("tenant-C", async () => {
			const { body, isError } = await callTool("list_traces", { limit: 5 });
			expect(isError).toBe(true);
			expect(String(body.error)).toMatch(/no bearer/i);
		});
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("Stdio mode (no request context at all) still falls back to TRACELANE_API_KEY", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse(200, { traces: [], next_cursor: null }),
		);
		// No runWithTenant wrapper — mirrors index.ts's Stdio path, which
		// never enters the AsyncLocalStorage context at all.
		const { isError } = await callTool("list_traces", { limit: 5 });
		expect(isError).toBe(false);
		const [, init] = fetchMock.mock.calls[0] as [URL, RequestInit];
		expect((init.headers as Record<string, string>).authorization).toBe(
			`Bearer ${TEST_API_KEY}`,
		);
	});
});

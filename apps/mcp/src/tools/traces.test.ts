/**
 * Tests for the read-only, tenant-scoped trace MCP tools.
 *
 * Covers (P1-6 MCP portion):
 *   - tenant isolation: every query carries `WHERE tenant_id = {tenantId:String}`
 *     and the tenant value comes from the auth context, NEVER from a tool
 *     argument. A tool arg that tries to smuggle a `tenant_id` cannot reach
 *     the SQL (it is not in any tool's input schema and is ignored).
 *   - read-only enforcement: no tool issues a write-shaped ClickHouse command
 *     (INSERT / ALTER / DROP / DELETE / TRUNCATE / CREATE) and write-shaped
 *     tool inputs cannot mutate state — the db mock asserts query-only usage.
 *   - the two newly-implemented tools (search_traces, replay_trace) return
 *     real shapes built from mocked ClickHouse rows; the param-bound SQL and
 *     query params are asserted.
 *
 * ClickHouse is mocked at the client interface (no real network — testing.md).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// --- Mock the db + auth modules BEFORE importing the tool registrar. -------

interface CapturedQuery {
	query: string;
	query_params: Record<string, unknown>;
	format?: string;
}

const capturedQueries: CapturedQuery[] = [];
let nextRows: unknown[] = [];

/** Records of any write-shaped method being invoked on the client. */
const writeMethodCalls: string[] = [];

const fakeClient = {
	query: vi.fn(async (args: CapturedQuery) => {
		capturedQueries.push(args);
		return {
			json: async <T>() => nextRows as T[],
		};
	}),
	// Write-shaped methods the @clickhouse/client exposes. If any tool ever
	// calls these the test fails — proving read-only enforcement structurally.
	insert: vi.fn(async () => {
		writeMethodCalls.push("insert");
		return {};
	}),
	command: vi.fn(async () => {
		writeMethodCalls.push("command");
		return {};
	}),
	exec: vi.fn(async () => {
		writeMethodCalls.push("exec");
		return {};
	}),
};

vi.mock("../db.js", () => ({
	getDb: () => fakeClient,
}));

const TEST_TENANT = "tenant-from-auth-ctx-only";

vi.mock("../auth.js", () => ({
	getTenantId: () => TEST_TENANT,
}));

// --- Capture tool registrations against a lightweight fake McpServer. ------

type ToolHandler = (
	args: Record<string, unknown>,
) => Promise<{ content: Array<{ type: string; text: string }> }>;

interface RegisteredTool {
	name: string;
	description: string;
	// Raw Zod shape passed as the third arg to server.tool(...).
	schema: Record<string, { parse: (v: unknown) => unknown }>;
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

// Import after mocks are in place.
import { registerTraceTools } from "./traces.js";

beforeEach(() => {
	registered.clear();
	capturedQueries.length = 0;
	writeMethodCalls.length = 0;
	nextRows = [];
	fakeClient.query.mockClear();
	// biome-ignore lint/suspicious/noExplicitAny: structural fake.
	registerTraceTools(fakeServer as any);
});

afterEach(() => {
	vi.clearAllMocks();
});

/** Parse the single text-content payload a tool returns. */
async function callTool(
	name: string,
	args: Record<string, unknown>,
): Promise<unknown> {
	const tool = registered.get(name);
	if (!tool) throw new Error(`tool ${name} not registered`);
	const res = await tool.handler(args);
	const text = res.content[0]?.text;
	if (text === undefined) throw new Error("no text content");
	return JSON.parse(text);
}

describe("registerTraceTools registration", () => {
	it("registers the expected read-only tools", () => {
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

	it("no tool exposes a tenant_id / tenantId argument in its input schema", () => {
		for (const tool of registered.values()) {
			const keys = Object.keys(tool.schema);
			expect(keys).not.toContain("tenant_id");
			expect(keys).not.toContain("tenantId");
		}
	});
});

describe("tenant isolation", () => {
	it("every query is tenant-scoped with a param-bound tenant from auth ctx", async () => {
		nextRows = [];
		await callTool("list_traces", { limit: 5 });
		await callTool("get_trace", { trace_id: "t1" });
		await callTool("get_span", { trace_id: "t1", span_id: "s1" });
		await callTool("search_traces", { query: "boom", limit: 5 });
		await callTool("replay_trace", {
			trace_id: "t1",
			include_tool_calls: true,
		});
		await callTool("explain_guardrail_block", {
			trace_id: "t1",
			span_id: "s1",
		});

		expect(capturedQueries.length).toBe(6);
		for (const q of capturedQueries) {
			expect(q.query).toContain("WHERE tenant_id = {tenantId: String}");
			// Tenant value is the auth-context value, not anything caller-supplied.
			expect(q.query_params.tenantId).toBe(TEST_TENANT);
		}
	});

	it("a tool arg attempting to override tenant_id is ignored", async () => {
		nextRows = [];
		// Caller smuggles tenant_id / tenantId in the args. These are not in
		// any tool schema and must never reach query_params.tenantId.
		await callTool("search_traces", {
			query: "x",
			tenant_id: "attacker-tenant",
			tenantId: "attacker-tenant",
			limit: 3,
		});
		await callTool("replay_trace", {
			trace_id: "t1",
			tenant_id: "attacker-tenant",
			tenantId: "attacker-tenant",
			include_tool_calls: true,
		});

		for (const q of capturedQueries) {
			expect(q.query_params.tenantId).toBe(TEST_TENANT);
			expect(q.query_params.tenantId).not.toBe("attacker-tenant");
			// The smuggled keys must not have leaked into the bound params.
			expect(q.query_params.tenant_id).toBeUndefined();
		}
	});
});

describe("read-only enforcement", () => {
	it("no tool issues a write-shaped ClickHouse statement", async () => {
		nextRows = [];
		for (const name of registered.keys()) {
			// Provide a permissive arg bag; handlers ignore unknown keys.
			await registered.get(name)?.handler({
				limit: 5,
				trace_id: "t1",
				span_id: "s1",
				query: "q",
				include_tool_calls: true,
			});
		}

		// Structural read-only proof: never touched a write method.
		expect(writeMethodCalls).toEqual([]);
		expect(fakeClient.insert).not.toHaveBeenCalled();
		expect(fakeClient.command).not.toHaveBeenCalled();
		expect(fakeClient.exec).not.toHaveBeenCalled();

		const WRITE_RE =
			/\b(INSERT|ALTER|DROP|DELETE|TRUNCATE|CREATE|UPDATE|RENAME|ATTACH|DETACH|OPTIMIZE)\b/i;
		for (const q of capturedQueries) {
			expect(q.query).not.toMatch(WRITE_RE);
			expect(q.query.trim().toUpperCase().startsWith("SELECT")).toBe(true);
		}
	});

	it("write-shaped input on search_traces cannot mutate — query stays a SELECT", async () => {
		nextRows = [];
		// Even a query string that looks like SQL injection is parameter-bound,
		// so it lands in query_params, never spliced into the statement.
		await callTool("search_traces", {
			query: "'; DROP TABLE tracelane.spans; --",
			limit: 1,
		});
		const q = capturedQueries[0];
		expect(q).toBeDefined();
		if (!q) throw new Error("unreachable");
		// The injection payload is bound as a param (lowercased), not in SQL.
		expect(q.query).not.toContain("DROP TABLE");
		expect(q.query_params.needle).toBe("'; drop table tracelane.spans; --");
		expect(writeMethodCalls).toEqual([]);
	});
});

describe("search_traces (newly implemented)", () => {
	it("builds a param-bound, tenant-scoped grouped SELECT and maps rows", async () => {
		nextRows = [
			{
				trace_id: "trace-aaa",
				matched_spans: 3,
				first_match_time: "2026-05-29 10:00:00.000000",
				first_match_span_id: "span-1",
				first_match_name: "llm.chat",
				max_status_code: 2,
			},
		];

		const out = (await callTool("search_traces", {
			query: "Timeout",
			model_filter: "claude-sonnet-4-6",
			has_error: true,
			limit: 7,
		})) as {
			query: string;
			model_filter: string | null;
			has_error: boolean | null;
			count: number;
			matches: Array<{ trace_id: string; matched_spans: number }>;
		};

		expect(out.count).toBe(1);
		expect(out.matches[0]?.trace_id).toBe("trace-aaa");
		expect(out.matches[0]?.matched_spans).toBe(3);
		expect(out.model_filter).toBe("claude-sonnet-4-6");
		expect(out.has_error).toBe(true);

		const q = capturedQueries[0];
		expect(q).toBeDefined();
		if (!q) throw new Error("unreachable");
		expect(q.query).toContain("FROM tracelane.spans FINAL");
		expect(q.query).toContain("WHERE tenant_id = {tenantId: String}");
		expect(q.query).toContain("position(lower(name), {needle: String})");
		expect(q.query).toContain("position(lower(attributes), {needle: String})");
		expect(q.query).toContain("AND status_code = 2");
		expect(q.query).toContain("GROUP BY trace_id");
		expect(q.query).toContain("LIMIT {limit: UInt32}");
		// Search needle is bound + lowercased, model filter bound + lowercased.
		expect(q.query_params).toMatchObject({
			tenantId: TEST_TENANT,
			needle: "timeout",
			model: "claude-sonnet-4-6",
			limit: 7,
		});
	});

	it("omits optional filters and applies the non-error branch", async () => {
		nextRows = [];
		await callTool("search_traces", { query: "x", has_error: false, limit: 2 });
		const q = capturedQueries[0];
		if (!q) throw new Error("unreachable");
		expect(q.query).toContain("AND status_code != 2");
		expect(q.query).not.toContain("{model: String}");
		expect(q.query_params.model).toBeUndefined();
	});

	it("returns an empty match set (not a stub) when nothing matches", async () => {
		nextRows = [];
		const out = (await callTool("search_traces", {
			query: "nope",
			limit: 5,
		})) as {
			count: number;
			matches: unknown[];
		};
		// Critically: no `stub: true` field anywhere.
		expect(JSON.stringify(out)).not.toContain('"stub"');
		expect(out.count).toBe(0);
		expect(out.matches).toEqual([]);
	});
});

describe("replay_trace (newly implemented)", () => {
	it("fetches stored spans tenant-scoped and returns real structure (no shadow exec)", async () => {
		nextRows = [
			{
				span_id: "s-llm",
				parent_span_id: null,
				name: "llm.chat",
				start_time: "2026-05-29 10:00:00.000000",
				end_time: "2026-05-29 10:00:01.000000",
				duration_us: 1_000_000,
				status_code: 1,
				status_message: "",
				attributes: JSON.stringify({
					"gen_ai.request.model": "claude-sonnet-4-6",
				}),
				aft_ids: [],
				intervention: 0,
			},
			{
				span_id: "s-tool",
				parent_span_id: "s-llm",
				name: "tool.search",
				start_time: "2026-05-29 10:00:00.500000",
				end_time: "2026-05-29 10:00:00.900000",
				duration_us: 400_000,
				status_code: 1,
				status_message: "",
				attributes: JSON.stringify({ "tool.name": "search" }),
				aft_ids: [],
				intervention: 0,
			},
		];

		const out = (await callTool("replay_trace", {
			trace_id: "trace-xyz",
			include_tool_calls: true,
		})) as {
			trace_id: string;
			replayed: boolean;
			mode: string;
			span_count: number;
			spans: Array<{
				span_id: string;
				is_llm_span: boolean;
				attributes: unknown;
			}>;
		};

		// Honest, non-stub contract: returns stored structure, never replays.
		expect(JSON.stringify(out)).not.toContain('"stub"');
		expect(out.replayed).toBe(false);
		expect(out.mode).toBe("inspection");
		expect(out.span_count).toBe(2);
		expect(out.spans[0]?.span_id).toBe("s-llm");
		expect(out.spans[0]?.is_llm_span).toBe(true);
		// attributes parsed from JSON string into an object.
		expect(out.spans[0]?.attributes).toMatchObject({
			"gen_ai.request.model": "claude-sonnet-4-6",
		});
		expect(out.spans[1]?.is_llm_span).toBe(false);

		const q = capturedQueries[0];
		if (!q) throw new Error("unreachable");
		expect(q.query).toContain("FROM tracelane.spans FINAL");
		expect(q.query).toContain("WHERE tenant_id = {tenantId: String}");
		expect(q.query).toContain("AND trace_id = {trace_id: String}");
		expect(q.query).toContain("ORDER BY start_time ASC");
		expect(q.query_params).toMatchObject({
			tenantId: TEST_TENANT,
			trace_id: "trace-xyz",
		});
	});

	it("include_tool_calls=false filters out non-LLM spans", async () => {
		nextRows = [
			{
				span_id: "s-llm",
				parent_span_id: null,
				name: "llm.chat",
				start_time: "2026-05-29 10:00:00.000000",
				end_time: "2026-05-29 10:00:01.000000",
				duration_us: 1_000_000,
				status_code: 1,
				status_message: "",
				attributes: JSON.stringify({ "llm.model_name": "gpt-4o" }),
				aft_ids: [],
				intervention: 0,
			},
			{
				span_id: "s-tool",
				parent_span_id: "s-llm",
				name: "tool.search",
				start_time: "2026-05-29 10:00:00.500000",
				end_time: "2026-05-29 10:00:00.900000",
				duration_us: 400_000,
				status_code: 1,
				status_message: "",
				attributes: JSON.stringify({ "tool.name": "search" }),
				aft_ids: [],
				intervention: 0,
			},
		];

		const out = (await callTool("replay_trace", {
			trace_id: "trace-xyz",
			include_tool_calls: false,
		})) as { span_count: number; spans: Array<{ span_id: string }> };

		expect(out.span_count).toBe(1);
		expect(out.spans[0]?.span_id).toBe("s-llm");
	});

	it("returns an error shape (not a stub) when the trace is missing", async () => {
		nextRows = [];
		const out = (await callTool("replay_trace", {
			trace_id: "missing",
			include_tool_calls: true,
		})) as { error?: string; span_count: number };
		expect(JSON.stringify(out)).not.toContain('"stub"');
		expect(out.span_count).toBe(0);
		expect(out.error).toContain("not found");
	});
});

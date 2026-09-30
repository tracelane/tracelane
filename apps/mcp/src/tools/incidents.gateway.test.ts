/**
 * EVL-40 slice 6 — the incident MCP tools (`specs/EVL-40-incident-to-regression-pr-check.md` §2.5).
 *
 * `get_incident` and `export_regression` are gateway-mode only: they read the gateway's
 * tenant-scoped `GET /v1/traces/{id}/incident` and `GET /v1/traces/{id}/regression` routes
 * (§2.1, §2.2). `fetch` is stubbed at the global — no real network (testing.md).
 *
 * Proofs: the exact route + query each tool calls, the bearer it sends, a non-2xx becomes an
 * MCP tool error carrying the gateway's status + message (never an empty result), the export's
 * honest-limit headers are passed through, and the descriptions state the "uncertain" and
 * recorded/mocked/live rules the spec requires.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { GatewayReader } from "../reader.js";
import { registerIncidentTools } from "./incidents.js";

type ToolHandlerResult = {
	content: Array<{ type: string; text: string }>;
	isError?: boolean;
};
type ToolHandler = (
	args: Record<string, unknown>,
) => Promise<ToolHandlerResult>;

const registered = new Map<
	string,
	{ description: string; handler: ToolHandler }
>();
const fakeServer = {
	tool(
		name: string,
		description: string,
		_schema: unknown,
		handler: ToolHandler,
	) {
		registered.set(name, { description, handler });
		return {};
	},
};

async function callTool(name: string, args: Record<string, unknown>) {
	const tool = registered.get(name);
	if (!tool) throw new Error(`tool ${name} not registered`);
	const res = await tool.handler(args);
	const text = res.content[0]?.text;
	if (text === undefined) throw new Error("no text content");
	return {
		body: JSON.parse(text) as Record<string, unknown>,
		isError: res.isError === true,
	};
}

function response(
	status: number,
	body: unknown,
	headers: Record<string, string> = {},
	asText = false,
): Response {
	const h = new Headers(headers);
	return {
		ok: status >= 200 && status < 300,
		status,
		statusText: `status ${status}`,
		headers: h,
		json: async () => body,
		text: async () => (asText ? String(body) : JSON.stringify(body)),
	} as unknown as Response;
}

const TEST_API_KEY = "tlane_test_key_do_not_use_in_prod";
const TRACE = "0e57f1c7-0000-4000-8000-00000000c0de";
let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
	registered.clear();
	vi.stubEnv("TRACELANE_GATEWAY_URL", "http://localhost:8080");
	vi.stubEnv("TRACELANE_API_KEY", TEST_API_KEY);
	fetchMock = vi.fn();
	vi.stubGlobal("fetch", fetchMock);
	// biome-ignore lint/suspicious/noExplicitAny: structural fake.
	registerIncidentTools(fakeServer as any, new GatewayReader());
});

afterEach(() => {
	vi.unstubAllEnvs();
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

describe("registerIncidentTools", () => {
	it("registers exactly the two EVL-40 tools, with the honesty rules in their descriptions", () => {
		expect([...registered.keys()].sort()).toEqual([
			"export_regression",
			"get_incident",
		]);
		expect(registered.get("get_incident")?.description).toMatch(/uncertain/i);
		const exportDesc = registered.get("export_regression")?.description ?? "";
		expect(exportDesc).toMatch(/recorded/);
		expect(exportDesc).toMatch(/mocked/);
		expect(exportDesc).toMatch(/never re-executes|does not re-execute/i);
	});
});

describe("get_incident", () => {
	it("reads GET /v1/traces/{id}/incident with the bearer and returns the packet as-is", async () => {
		const packet = {
			trigger: { kind: "error_status" },
			what_happened: {},
			what_changed: { note: "no comparable good run in the window" },
			linked_spans: [],
			explanations: [],
			limits: {},
		};
		fetchMock.mockResolvedValueOnce(response(200, packet));
		const { body, isError } = await callTool("get_incident", {
			trace_id: TRACE,
		});
		expect(isError).toBe(false);
		expect(body).toEqual(packet);
		const [url, init] = fetchMock.mock.calls[0] as [URL, RequestInit];
		expect(String(url)).toBe(
			`http://localhost:8080/v1/traces/${TRACE}/incident`,
		);
		expect((init.headers as Record<string, string>).authorization).toBe(
			`Bearer ${TEST_API_KEY}`,
		);
	});

	it("turns a gateway 404 into a tool error carrying the status — never an empty packet", async () => {
		fetchMock.mockResolvedValueOnce(
			response(404, { error: "trace not found" }),
		);
		const { body, isError } = await callTool("get_incident", {
			trace_id: TRACE,
		});
		expect(isError).toBe(true);
		expect(body).toEqual({ error: "trace not found", status: 404 });
	});
});

describe("export_regression", () => {
	it("passes format + mode, returns the fixture text and the honest-limit headers", async () => {
		fetchMock.mockResolvedValueOnce(
			response(
				200,
				"description: incident regression\ntests: []\n",
				{
					"content-type": "text/yaml",
					"x-tracelane-regression-mode": "mocked",
					"x-tracelane-expected-output": "null",
				},
				true,
			),
		);
		const { body, isError } = await callTool("export_regression", {
			trace_id: TRACE,
			format: "promptfoo",
			mode: "mocked",
		});
		expect(isError).toBe(false);
		expect(body.fixture).toBe("description: incident regression\ntests: []\n");
		expect(body.format).toBe("promptfoo");
		expect(body.limits).toEqual({
			"x-tracelane-regression-mode": "mocked",
			"x-tracelane-expected-output": "null",
		});
		const [url] = fetchMock.mock.calls[0] as [URL];
		const u = new URL(String(url));
		expect(u.pathname).toBe(`/v1/traces/${TRACE}/regression`);
		expect(u.searchParams.get("format")).toBe("promptfoo");
		expect(u.searchParams.get("mode")).toBe("mocked");
	});

	it("surfaces 422 content_not_captured as a tool error with the gateway's reason", async () => {
		fetchMock.mockResolvedValueOnce(
			response(422, {
				error:
					"content_not_captured: content capture is off for this workspace",
			}),
		);
		const { body, isError } = await callTool("export_regression", {
			trace_id: TRACE,
			format: "dataset",
			mode: "recorded",
		});
		expect(isError).toBe(true);
		expect(body.status).toBe(422);
		expect(String(body.error)).toMatch(/content_not_captured/);
	});
});

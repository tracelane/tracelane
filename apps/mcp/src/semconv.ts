/**
 *
 * The MCP semconv (open-telemetry/semantic-conventions PRs #2043, #2083) landed
 * in semconv v1.39 — absent from the v1.34 baseline. These are the canonical
 * attribute keys for an MCP tool invocation.
 *
 * The MCP server has no OTel tracer wired (adding `@opentelemetry/*` is blocked
 * by the reconciliation's no-new-dependencies rule), so emission is via a
 * structured line on **stderr** — stdout is reserved for the JSON-RPC stream in
 * stdio transport, so telemetry must never go there. A collector tails stderr.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

/** `mcp.method.name` — the JSON-RPC method, e.g. `tools/call`. */
export const MCP_METHOD_NAME = "mcp.method.name";
/** `mcp.tool.name` — the invoked tool's name. */
export const MCP_TOOL_NAME = "mcp.tool.name";
/** `mcp.session.id` — session correlation id. */
export const MCP_SESSION_ID = "mcp.session.id";
/** `mcp.request.id` — JSON-RPC request id. */
export const MCP_REQUEST_ID = "mcp.request.id";

export interface McpInvocationAttributes {
	[MCP_METHOD_NAME]: string;
	[MCP_TOOL_NAME]: string;
	[MCP_SESSION_ID]?: string;
	"tracelane.tenant_id"?: string;
	"error.type"?: string;
	duration_ms?: number;
}

/**
 * Emit a v1.39 MCP-semconv invocation record to stderr. Never throws —
 * telemetry must not break a tool call.
 */
export function recordMcpInvocation(attrs: McpInvocationAttributes): void {
	try {
		process.stderr.write(
			`${JSON.stringify({ event_name: "mcp.tool.call", ...attrs })}\n`,
		);
	} catch {
		// telemetry is best-effort
	}
}

/** Generic tool-registration fn shape we wrap. */
type ToolFn = (...args: unknown[]) => unknown;

/**
 * Wrap an `McpServer` so every `.tool(name, …, handler)` registration emits the
 * v1.39 MCP semconv attributes (`mcp.method.name = "tools/call"`,
 * `mcp.tool.name`, latency, error classification) on each invocation. The
 * provider error/result body is never logged — only the structured attributes.
 *
 * Takes and returns the concrete `McpServer` (mutated in place) so callers keep
 * `.connect()` / `.close()` etc. — the `.tool` monkey-patch is done behind a
 * localized cast since the SDK's `.tool` overloads aren't expressible as a
 * single generic signature.
 *
 *   `registerTraceTools(instrumentMcpServer(server))`.
 */
export function instrumentMcpServer(server: McpServer): McpServer {
	const patchable = server as unknown as { tool: ToolFn };
	const originalTool = patchable.tool.bind(server) as ToolFn;

	patchable.tool = ((...args: unknown[]) => {
		const name = typeof args[0] === "string" ? args[0] : "unknown";
		const handlerIdx = args.length - 1;
		const handler = args[handlerIdx];

		if (typeof handler === "function") {
			const wrapped = async (...handlerArgs: unknown[]) => {
				const startedAt = Date.now();
				try {
					const result = await (handler as ToolFn)(...handlerArgs);
					recordMcpInvocation({
						[MCP_METHOD_NAME]: "tools/call",
						[MCP_TOOL_NAME]: name,
						duration_ms: Date.now() - startedAt,
					});
					return result;
				} catch (err) {
					recordMcpInvocation({
						[MCP_METHOD_NAME]: "tools/call",
						[MCP_TOOL_NAME]: name,
						"error.type": err instanceof Error ? err.name : "unknown",
						duration_ms: Date.now() - startedAt,
					});
					throw err;
				}
			};
			const newArgs = [...args];
			newArgs[handlerIdx] = wrapped;
			return originalTool(...newArgs);
		}
		return originalTool(...args);
	}) as ToolFn;

	return server;
}

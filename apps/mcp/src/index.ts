/**
 * Tracelane MCP server entry point.
 *
 * Exposes read-only tools over the MCP protocol. Tenant isolation is
 * structural — every ClickHouse query includes `WHERE tenant_id = ?`
 * where `tenant_id` comes from the bearer token (HTTP) or the trusted
 * subprocess env block (Stdio), never from tool arguments.
 *
 * Transport selection (A2):
 *
 *   - **Stdio** (default; for Claude Desktop / Cursor):
 *     ```json
 *     { "tracelane": { "command": "npx", "args": ["@tracelanedev/mcp"] } }
 *     ```
 *     Tenant ID comes from `TRACELANE_TENANT_ID` env.
 *
 *   - **Streamable HTTP** (`TRACELANE_MCP_TRANSPORT=http`):
 *     ```bash
 *     TRACELANE_MCP_TRANSPORT=http TRACELANE_MCP_PORT=8081 \
 *     TRACELANE_GATEWAY_URL=https://gateway.tracelane.dev npx @tracelanedev/mcp
 *     ```
 *     Each request must carry `Authorization: Bearer <jwt-or-tlane-key>`;
 *     tenant ID is resolved per-request via the gateway's
 *     `/v1/auth/whoami` endpoint and bound through AsyncLocalStorage.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { bootstrapStdioTenant } from "./auth.js";
import { runHttp } from "./http.js";
import { instrumentMcpServer } from "./semconv.js";
import { registerEvalTools } from "./tools/evals.js";
import { registerTraceTools } from "./tools/traces.js";

async function runStdio(): Promise<void> {
	// L3 sweep 2026-07-03: resolve TRACELANE_API_KEY -> tenant via the
	// gateway BEFORE serving (the documented stdio auth path; fail-closed
	// on a rejected key). No key -> TRACELANE_TENANT_ID fallback as before.
	await bootstrapStdioTenant();

	// Wrap so every tool invocation emits OTel MCP semconv v1.39 attributes.
	const server = instrumentMcpServer(
		new McpServer({ name: "tracelane", version: "0.1.0" }),
	);
	registerTraceTools(server);
	registerEvalTools(server);

	const transport = new StdioServerTransport();
	await server.connect(transport);

	for (const sig of ["SIGINT", "SIGTERM"] as const) {
		process.on(sig, async () => {
			await server.close();
			process.exit(0);
		});
	}
}

async function main(): Promise<void> {
	const transport = (
		process.env.TRACELANE_MCP_TRANSPORT ?? "stdio"
	).toLowerCase();
	switch (transport) {
		case "http":
		case "streamable-http":
			await runHttp();
			break;
		case "stdio":
			await runStdio();
			break;
		default:
			throw new Error(
				`Unknown TRACELANE_MCP_TRANSPORT="${transport}" (expected "stdio" or "http")`,
			);
	}
}

main().catch((err) => {
	// stderr-only structured emit. CLAUDE.md bans `console.log` in
	// committed code; for a stdio MCP server stderr is the only channel
	// that doesn't corrupt the protocol stream. Format as a single JSON
	// line so downstream tooling can parse uniformly.
	process.stderr.write(
		`${JSON.stringify({
			level: "error",
			component: "mcp",
			msg: "MCP server fatal error",
			error:
				err instanceof Error ? { message: err.message, stack: err.stack } : err,
			ts: new Date().toISOString(),
		})}\n`,
	);
	process.exit(1);
});

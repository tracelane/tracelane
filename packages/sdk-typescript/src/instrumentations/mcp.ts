/**
 * MCP (Model Context Protocol) instrumentation for Tracelane.
 *
 * Wraps MCP Client's callTool() and readResource() methods to emit OTel
 * spans. MCP is the most-attacked agent surface; these spans feed
 * Tracelane's MCP tool-description hash watcher (PP-PR1) and provide
 * the observability layer for rug-pull detection.
 *
 * @example
 * ```ts
 * import { Client } from "@modelcontextprotocol/sdk/client/index.js";
 * import { instrumentMCP } from "@tracelanedev/sdk/mcp";
 *
 * const client = new Client({ name: "my-client", version: "1.0.0" });
 * instrumentMCP(client);
 * const result = await client.callTool({ name: "my_tool", arguments: {} });
 * ```
 */

import { SpanKind, SpanStatusCode, trace } from "@opentelemetry/api";

const tracer = trace.getTracer("@tracelanedev/sdk-mcp", "0.1.0");

interface MCPClientLike {
	callTool: (...args: unknown[]) => Promise<unknown>;
	readResource?: (...args: unknown[]) => Promise<unknown>;
	listTools?: (...args: unknown[]) => Promise<unknown>;
}

/**
 * Instrument an MCP Client instance to emit OTel spans.
 *
 * @param client - An @modelcontextprotocol/sdk Client or ClientSession instance
 */
export function instrumentMCP(client: MCPClientLike): void {
	_patchCallTool(client);
	if (client.readResource) {
		_patchReadResource(
			client as MCPClientLike & {
				readResource: (...args: unknown[]) => Promise<unknown>;
			},
		);
	}
	if (client.listTools) {
		_patchListTools(
			client as MCPClientLike & {
				listTools: (...args: unknown[]) => Promise<unknown>;
			},
		);
	}
}

function _patchCallTool(client: MCPClientLike): void {
	const originalCallTool = client.callTool.bind(client);

	client.callTool = async (...args: unknown[]) => {
		const request = args[0] as Record<string, unknown> | undefined;
		const toolName =
			typeof request?.name === "string" ? request.name : "unknown";
		const argCount =
			request?.arguments && typeof request.arguments === "object"
				? Object.keys(request.arguments as object).length
				: 0;

		return tracer.startActiveSpan(
			"mcp.callTool",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "mcp",
					"mcp.tool_name": toolName,
					"mcp.argument_count": argCount,
				},
			},
			async (span) => {
				try {
					const result = (await originalCallTool(...args)) as Record<
						string,
						unknown
					>;
					const isError = Boolean(result.isError ?? false);
					span.setAttribute("mcp.is_error", isError);
					const content = result.content;
					if (Array.isArray(content)) {
						span.setAttribute("mcp.content_count", content.length);
					}
					span.setStatus({
						code: isError ? SpanStatusCode.ERROR : SpanStatusCode.OK,
						message: isError ? "MCP tool returned isError=true" : "",
					});
					return result;
				} catch (e) {
					span.recordException(e as Error);
					span.setStatus({ code: SpanStatusCode.ERROR, message: String(e) });
					throw e;
				} finally {
					span.end();
				}
			},
		);
	};
}

function _patchReadResource(
	client: MCPClientLike & {
		readResource: NonNullable<MCPClientLike["readResource"]>;
	},
): void {
	const originalReadResource = client.readResource.bind(client);

	client.readResource = async (...args: unknown[]) => {
		const request = args[0] as Record<string, unknown> | undefined;
		const uri = typeof request?.uri === "string" ? request.uri : "unknown";

		return tracer.startActiveSpan(
			"mcp.readResource",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "mcp",
					"mcp.resource_uri": uri,
				},
			},
			async (span) => {
				try {
					const result = (await originalReadResource(...args)) as Record<
						string,
						unknown
					>;
					const contents = result.contents;
					if (Array.isArray(contents)) {
						span.setAttribute("mcp.content_count", contents.length);
					}
					span.setStatus({ code: SpanStatusCode.OK });
					return result;
				} catch (e) {
					span.recordException(e as Error);
					span.setStatus({ code: SpanStatusCode.ERROR, message: String(e) });
					throw e;
				} finally {
					span.end();
				}
			},
		);
	};
}

function _patchListTools(
	client: MCPClientLike & {
		listTools: NonNullable<MCPClientLike["listTools"]>;
	},
): void {
	const originalListTools = client.listTools.bind(client);

	client.listTools = async (...args: unknown[]) => {
		return tracer.startActiveSpan(
			"mcp.listTools",
			{
				kind: SpanKind.CLIENT,
				attributes: { "gen_ai.provider.name": "mcp" },
			},
			async (span) => {
				try {
					const result = (await originalListTools(...args)) as Record<
						string,
						unknown
					>;
					const tools = result.tools;
					if (Array.isArray(tools)) {
						span.setAttribute("mcp.tools_count", tools.length);
					}
					span.setStatus({ code: SpanStatusCode.OK });
					return result;
				} catch (e) {
					span.recordException(e as Error);
					span.setStatus({ code: SpanStatusCode.ERROR, message: String(e) });
					throw e;
				} finally {
					span.end();
				}
			},
		);
	};
}

/**
 * Streamable HTTP transport bootstrap (A2).
 *
 * Companion to `index.ts`'s Stdio path. Exposes the MCP protocol over
 * HTTP for callers that don't run the server as a subprocess (web
 * clients, hosted IDEs, custom integrations).
 *
 * Auth: every request MUST carry `Authorization: Bearer <token>` where
 * `<token>` is a Tracelane JWT or an `tlane_…` API key. The token is
 * validated by the gateway's `/v1/auth/whoami` endpoint (proxy pattern
 * — keeps the JWT alg allowlist + JWKS + audience check + peppered
 * HMAC lookup in one place). Tenant ID is bound to the request via
 * `runWithTenant` so tool handlers read it through `getTenantId()`.
 *
 * No CORS-allow-all. The transport is intended for first-party agents
 * and headless integrations.
 */

import http, { type IncomingMessage, type ServerResponse } from "node:http";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { resolveBearerViaGateway, runWithTenant } from "./auth.js";
import { instrumentMcpServer } from "./semconv.js";
import { registerEvalTools } from "./tools/evals.js";
import { registerTraceTools } from "./tools/traces.js";

/** Default port when `TRACELANE_MCP_PORT` is unset. */
const DEFAULT_PORT = 8081;

/** Read + buffer the request body. Cap at 4 MiB to bound DoS surface. */
async function readBody(req: IncomingMessage): Promise<Buffer> {
	const MAX = 4 * 1024 * 1024;
	const chunks: Buffer[] = [];
	let total = 0;
	for await (const chunk of req) {
		const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
		total += buf.length;
		if (total > MAX) {
			throw new Error("body too large");
		}
		chunks.push(buf);
	}
	return Buffer.concat(chunks);
}

function send(res: ServerResponse, status: number, body: unknown): void {
	res.statusCode = status;
	res.setHeader("content-type", "application/json");
	res.end(JSON.stringify(body));
}

function extractBearer(req: IncomingMessage): string | null {
	const header = req.headers.authorization;
	if (typeof header !== "string") return null;
	if (!header.startsWith("Bearer ")) return null;
	return header.slice(7).trim() || null;
}

/**
 * Build the MCP server with the read-only tool stack. Same shape as the
 * Stdio path so the only difference is the transport.
 */
function buildServer(): McpServer {
	// Wrap so every tool invocation emits OTel MCP semconv v1.39 attributes.
	const server = instrumentMcpServer(
		new McpServer({ name: "tracelane", version: "0.1.0" }),
	);
	registerTraceTools(server);
	registerEvalTools(server);
	return server;
}

/**
 * Start the Streamable HTTP transport on `TRACELANE_MCP_PORT`.
 *
 * Per-request flow:
 *   1. Extract bearer from `Authorization` — 401 if missing.
 *   2. Call gateway `/v1/auth/whoami` to resolve tenant — 401 if invalid.
 *   3. Bind tenant via `runWithTenant`; delegate to `transport.handleRequest`.
 *   4. Each new request spins up a fresh transport (stateless mode); a
 *      future revision can flip to stateful + session IDs for streaming.
 */
export async function runHttp(): Promise<void> {
	const port =
		Number.parseInt(process.env.TRACELANE_MCP_PORT ?? "", 10) || DEFAULT_PORT;

	const server = http.createServer(async (req, res) => {
		try {
			if (req.url === "/health" && req.method === "GET") {
				send(res, 200, { status: "ok", service: "tracelane-mcp" });
				return;
			}
			if (
				req.url !== "/mcp" ||
				(req.method !== "POST" && req.method !== "GET")
			) {
				send(res, 404, { error: "not found" });
				return;
			}

			const bearer = extractBearer(req);
			if (!bearer) {
				res.setHeader("www-authenticate", 'Bearer realm="tracelane-mcp"');
				send(res, 401, { error: "missing bearer token" });
				return;
			}

			const tenantId = await resolveBearerViaGateway(bearer);
			if (!tenantId) {
				res.setHeader("www-authenticate", 'Bearer realm="tracelane-mcp"');
				send(res, 401, { error: "invalid credentials" });
				return;
			}

			let parsedBody: unknown;
			if (req.method === "POST") {
				const raw = await readBody(req);
				if (raw.length > 0) {
					// malformed JSON, not 500 (server error). The
					// outer `try` would catch the throw and convert
					// it to 500 — explicit 400 keeps probe-
					// distinguishability and matches MCP spec.
					try {
						parsedBody = JSON.parse(raw.toString("utf8"));
					} catch {
						send(res, 400, { error: "malformed JSON body" });
						return;
					}
				}
			}

			// Stateless per-request transport so concurrent callers can't
			// share sessions. Stateful mode will need a session-id-keyed
			// transport pool — V2 work.
			const transport = new StreamableHTTPServerTransport({
				sessionIdGenerator: undefined,
			});
			const mcp = buildServer();
			await mcp.connect(transport);

			await runWithTenant(tenantId, async () => {
				await transport.handleRequest(req, res, parsedBody);
			});
		} catch (err) {
			process.stderr.write(
				`${JSON.stringify({
					level: "error",
					component: "mcp",
					msg: "http handler error",
					url: req.url,
					method: req.method,
					error: err instanceof Error ? { message: err.message } : err,
					ts: new Date().toISOString(),
				})}\n`,
			);
			if (!res.headersSent) {
				send(res, 500, { error: "internal error" });
			} else {
				res.end();
			}
		}
	});

	await new Promise<void>((resolve) => server.listen(port, resolve));
	process.stderr.write(
		`${JSON.stringify({
			level: "info",
			component: "mcp",
			msg: `Streamable HTTP transport listening on :${port}`,
			ts: new Date().toISOString(),
		})}\n`,
	);

	// Graceful shutdown — give in-flight requests 5s to drain.
	for (const sig of ["SIGINT", "SIGTERM"] as const) {
		process.on(sig, () => {
			server.close(() => process.exit(0));
			setTimeout(() => process.exit(0), 5_000).unref();
		});
	}
}

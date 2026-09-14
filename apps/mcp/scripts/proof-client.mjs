#!/usr/bin/env node
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
// PLT-22 prod proof driver — spawns dist/index.js over stdio as a real MCP client
// and calls the tools the spec's §7 names. Not a test; a proof harness run by hand.
// Usage: TRACELANE_API_KEY=... TRACELANE_GATEWAY_URL=... node scripts/proof-client.mjs <tool> '<json-args>'
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const here = dirname(fileURLToPath(import.meta.url));
const [tool, argsJson = "{}"] = process.argv.slice(2);
if (!tool) {
	console.error("usage: proof-client.mjs <tool> '<json-args>'");
	process.exit(2);
}
// Gateway mode is the point of this proof: drop CLICKHOUSE_URL so the server cannot
// fall into self-host mode by accident.
const env = Object.fromEntries(
	Object.entries(process.env).filter(([k]) => k !== "CLICKHOUSE_URL"),
);
const transport = new StdioClientTransport({
	command: process.execPath,
	args: [resolve(here, "../dist/index.js")],
	env,
	stderr: "pipe",
});
const client = new Client({ name: "plt22-proof", version: "0.0.0" });
let stderr = "";
transport.stderr?.on("data", (d) => {
	stderr += d.toString();
});
try {
	await client.connect(transport);
	const res = await client.callTool({
		name: tool,
		arguments: JSON.parse(argsJson),
	});
	console.log(
		JSON.stringify(
			{ isError: res.isError ?? false, content: res.content },
			null,
			1,
		),
	);
} catch (e) {
	console.log(
		JSON.stringify({ startupError: String(e), stderr: stderr.slice(0, 600) }),
	);
	process.exitCode = 1;
} finally {
	await client.close().catch(() => {});
}

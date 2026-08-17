<!-- tracelane:classification: PUBLIC -->
# `@tracelanedev/mcp` — Tracelane MCP Server

[![npm](https://img.shields.io/badge/npm-not%20published%20yet-lightgrey?style=flat-square)](#quick-start)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](../../LICENSE)

Read-only MCP server exposing Tracelane trace data to any MCP-compatible client — Claude Desktop, Claude Code, Cursor, or any agent using the Model Context Protocol.

> **Not on npm yet — `npx @tracelanedev/mcp` still 404s, including in the config
> blocks below.** The package is wired into the release workflow and becomes
> installable when the next signed release tag carries it. Releases are bundled —
> one tag covering everything that has moved, never a tag cut for a single package
> ([VERSIONING.md, "Release cadence"](../../VERSIONING.md#release-cadence--one-tag-everything-that-moved))
> — so treat every `npx` line here as the *post-publish* form and use the
> [from-source](#self-hosting) path today. The same run submits `apps/mcp/server.json`
> to the MCP registry; the name it will be listed under is
> `io.github.tracelane/tracelane-mcp`.
>
> **It reads ClickHouse directly**, not through the gateway, so it needs ClickHouse
> credentials and runs against a self-hosted or local Tracelane stack — not against a
> hosted Cloud workspace.

## Quick start

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "tracelane": {
      "command": "npx",
      "args": ["@tracelanedev/mcp"],
      "env": {
        "TRACELANE_API_KEY": "tlane_YOUR_KEY",
        "TRACELANE_GATEWAY_URL": "https://gateway.tracelane.dev",
        "CLICKHOUSE_URL": "http://localhost:8123",
        "CLICKHOUSE_USER": "default",
        "CLICKHOUSE_PASSWORD": "…"
      }
    }
  }
}
```

### Claude Code

The same block in `.mcp.json` at the project root.

### Until it is on npm

Swap the two launch keys for a path into your clone — every `env` key is unchanged:

```json
"command": "node",
"args": ["/path/to/tracelane/apps/mcp/dist/index.js"]
```

Build it first with `pnpm install && pnpm --filter @tracelanedev/mcp build`.

The Streamable HTTP transport ships in this package (`TRACELANE_MCP_TRANSPORT=http`,
see [Transports](#transports)) — run it yourself. There is **no hosted endpoint**:
`https://mcp.tracelane.dev` does not resolve, so a `url`-style client entry has
nothing to connect to.

## Tools

| Tool | Description |
|---|---|
| `list_traces` | List recent traces for the tenant. Params: `limit` (default 20), `since` (ISO timestamp), `model` (filter by model name) |
| `get_trace` | Get all spans for a trace. Params: `trace_id` |
| `get_span` | Get full details for a span including all LLM GenAI attributes. Params: `span_id` |
| `search_traces` | Full-text search across trace root names and metadata. Params: `query`, `limit` |
| `explain_guardrail_block` | Human-readable explanation of why a request was blocked or warned. Params: `span_id` |
| `list_evals` | List every pain-point + fault-tolerance eval id and count, read from the manifest bundled at build time from `evals/`. Params: none |
| `get_eval_result` | Read a specific eval's assertions. Needs a repo checkout for the source; says so when there is none. Params: `eval_id` |
| `replay_trace` | Return a recorded trace as-is (ordered spans with LLM/tool attributes) for offline step-through. **Read-only — it does not re-execute any model or tool.** Params: `trace_id`, `include_tool_calls?` |

## Example usage in Claude

Once connected, you can ask Claude:

> "Show me the last 5 traces that had a guardrail block, and explain what fired."

> "Compare the latency of traces using claude-haiku-4-5 vs claude-sonnet-4-6 in the last hour."

> "Show me the assertions PP-G1 makes."

## Auth

**V1:** `TRACELANE_API_KEY` environment variable passed via the MCP env block. The server resolves the tenant from the API key — `tenant_id` is never accepted as a tool argument.

**V2 (roadmap):** OAuth 2.1 PKCE. The authorization server is `https://gateway.tracelane.dev/.well-known/oauth-authorization-server`. `tenant_id` extracted from JWT `organizationId` claim only.

## Transports

| Transport | How to select it | When to use |
|---|---|---|
| **Stdio** | default | Local use — Claude Desktop, Claude Code, Cursor. Zero network exposure. |
| **Streamable HTTP** | `TRACELANE_MCP_TRANSPORT=http TRACELANE_MCP_PORT=8081` | Self-run remote deployments. Every request must carry `Authorization: Bearer <jwt-or-tlane-key>`; the tenant is resolved per request through the gateway. No hosted endpoint is operated for you. |

## Security invariants

- **Read-only.** No write tools are registered — the tool surface is the eight listed above, all of which only read.
- **Tenant isolation.** Every ClickHouse query includes `WHERE tenant_id = {tenantId: String}` (parameter-bound, never string-interpolated).
- **`tenant_id` is never a tool parameter.** Stdio resolves it once at startup from `TRACELANE_API_KEY` via the gateway and refuses to start if the key is rejected; HTTP resolves it per request from the bearer token and binds it through `AsyncLocalStorage`.
- **No eval id reaches the filesystem.** `get_eval_result` looks the id up in the bundled manifest and uses the manifest's path, so a traversal string cannot name a file.
- **`TRACELANE_GATEWAY_URL` is SSRF-checked** before any bearer is sent to it: https-only outside development, tracelane.dev hosts only, private/CGNAT/IMDS ranges refused.

**Known gap — span content is returned verbatim.** There is no redaction pass over
span attributes and no untrusted-content sentinel around user text. Do not point this
server at a workspace whose spans may carry secrets you would not hand to the
connected model.

## Self-hosting

```bash
# From source, against your own stack
pnpm dev:mcp
```

No container image is published for the MCP server — `ghcr.io/tracelane/mcp` does not
exist. Run it from source or from the npm package once it ships.

## Stack

- `@modelcontextprotocol/sdk` — official MCP SDK (stdio + Streamable HTTP)
- `@clickhouse/client` — parameter-bound ClickHouse queries
- TypeScript 5.5 strict, `noUncheckedIndexedAccess: true`
- Biome for lint + format

## License

Apache 2.0 — see [LICENSE](../../LICENSE).

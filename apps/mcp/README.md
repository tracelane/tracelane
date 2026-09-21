<!-- tracelane:classification: PUBLIC -->
# `@tracelanedev/mcp` — Tracelane MCP Server

[![npm](https://img.shields.io/badge/npm-not%20published%20yet-lightgrey?style=flat-square)](#quick-start)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](../../LICENSE)

Read-only MCP server exposing Tracelane trace data to any MCP-compatible client — Claude Desktop, Claude Code, Cursor, or any agent using the Model Context Protocol.

> **On npm since 2026-09-07:** `npx @tracelanedev/mcp` installs `@tracelanedev/mcp@0.3.0`; the
> config blocks below work as written. From-source is still documented under [self-hosting](#self-hosting).
> The same run submits `apps/mcp/server.json` to the MCP registry; the name it will be listed under is `io.github.tracelane/tracelane-mcp`.

**Default mode reads through the gateway** — the same tenant-scoped `/v1/*` routes the
dashboard uses — with just `TRACELANE_API_KEY` and `TRACELANE_GATEWAY_URL`. That is the
Cloud-tenant path and needs no ClickHouse credentials. Set `CLICKHOUSE_URL` to
switch to self-host mode, reading ClickHouse directly instead — see
[Self-hosting](#self-hosting).

## Quick start

### Cloud (Tracelane-hosted tenant)

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS),
`%APPDATA%\Claude\claude_desktop_config.json` (Windows), or `.mcp.json` at your
project root for Claude Code:

```json
{
  "mcpServers": {
    "tracelane": {
      "command": "npx",
      "args": ["@tracelanedev/mcp"],
      "env": {
        "TRACELANE_API_KEY": "tlane_YOUR_KEY",
        "TRACELANE_GATEWAY_URL": "https://gateway.tracelane.dev"
      }
    }
  }
}
```

No `CLICKHOUSE_URL` — its absence is what selects gateway mode. Every read goes through
the gateway's existing tenant-scoped routes, so a key from another tenant, or one lacking
the `read` scope, gets a clear tool error rather than an empty result.

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

### Self-host (ClickHouse)

Set `CLICKHOUSE_URL` to read ClickHouse directly instead of the gateway — for a
self-hosted or local Tracelane stack:

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

`TRACELANE_GATEWAY_URL` is still needed in self-host mode — it is where
`TRACELANE_API_KEY` is validated (`/v1/auth/whoami`) even though trace reads go to
ClickHouse instead.

## Tools

| Tool | Description |
|---|---|
| `list_traces` | List recent traces for the tenant. Params: `limit` (default 20), `model_filter`, `has_error` |
| `get_trace` | Get all spans for a trace. Params: `trace_id` |
| `get_span` | Get full details for a span including all LLM GenAI attributes. Params: `span_id`, `trace_id` — **required in Cloud (gateway) mode** (no span-by-id gateway route; the span is picked out of the trace's span list), optional in self-host mode |
| `search_traces` | Free-text search across span names and attributes. Params: `query` (gateway mode requires ≥4 chars), `model_filter?`, `has_error?`, `limit`. Gateway mode returns content-filtered trace summaries; self-host mode returns per-span match detail (`matched_spans`, `first_match_*`) |
| `explain_guardrail_block` | Human-readable explanation of a guardrail signal. Self-host mode: `trace_id` + `span_id` (a detection-layer AFT flag on a recorded span). Gateway mode: EITHER `correlation_id` (from a block's 403 body, for a request blocked pre-flight with no trace) OR `trace_id` + `span_id` (same AFT-flag case, still available since spans carry the flag either way) |
| `list_evals` | List every pain-point + fault-tolerance eval id and count, read from the manifest bundled at build time from `evals/`. Params: none |
| `get_eval_result` | Read a specific eval's assertions. Needs a repo checkout for the source; says so when there is none. Params: `eval_id` |
| `replay_trace` | Return a recorded trace as-is (ordered spans with LLM/tool attributes) for offline step-through. **Read-only — it does not re-execute any model or tool.** Params: `trace_id`, `include_tool_calls?` |

## Example usage in Claude

Once connected, you can ask Claude:

> "Show me the last 5 traces that had a guardrail block, and explain what fired."

> "Compare the latency of traces using claude-haiku-4-5 vs claude-sonnet-4-6 in the last hour."

> "Show me the assertions that eval makes."

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
- **Tenant isolation.** Gateway mode: every read is a tenant-scoped gateway route (`crates/gateway/src/trace_reads.rs`) — the tenant comes from the bearer's claims server-side, this server never sends or sees a tenant id. Self-host mode: every ClickHouse query includes `WHERE tenant_id = {tenantId: String}` (parameter-bound, never string-interpolated).
- **`tenant_id` is never a tool parameter** in either mode. Stdio resolves it once at startup from `TRACELANE_API_KEY` via the gateway and refuses to start if the key is rejected; HTTP resolves it per request from the bearer token and binds it through `AsyncLocalStorage`.
- **A non-2xx gateway response is a tool error, never an empty result.** A revoked or wrong-tenant key, a key missing the `read` scope, or another tenant's trace id all read back as `isError: true` carrying the gateway's own status and message — not `[]`.
- **No eval id reaches the filesystem.** `get_eval_result` looks the id up in the bundled manifest and uses the manifest's path, so a traversal string cannot name a file.
- **`TRACELANE_GATEWAY_URL` is SSRF-checked** before any bearer is sent to it, in both modes: https-only outside development, tracelane.dev hosts only, private/CGNAT/IMDS ranges refused.

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

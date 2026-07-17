# `@tracelanedev/mcp` — Tracelane MCP Server

[![npm](https://img.shields.io/npm/v/@tracelanedev/mcp?style=flat-square)](https://www.npmjs.com/package/@tracelanedev/mcp)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](../../LICENSE)

Read-only MCP server exposing Tracelane trace data to any MCP-compatible client — Claude Desktop, Claude Code, Cursor, or any agent using the Model Context Protocol.

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
        "TRACELANE_GATEWAY_URL": "https://gateway.tracelane.dev"
      }
    }
  }
}
```

### Claude Code

```json
// .mcp.json (project root)
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

Or via Streamable HTTP (V1.5+):

```json
{
  "mcpServers": {
    "tracelane": {
      "url": "https://mcp.tracelane.dev",
      "transport": "http"
    }
  }
}
```

## Tools

| Tool | Description |
|---|---|
| `list_traces` | List recent traces for the tenant. Params: `limit` (default 20), `since` (ISO timestamp), `model` (filter by model name) |
| `get_trace` | Get all spans for a trace. Params: `trace_id` |
| `get_span` | Get full details for a span including all LLM GenAI attributes. Params: `span_id` |
| `search_traces` | Full-text search across trace root names and metadata. Params: `query`, `limit` |
| `explain_guardrail_block` | Human-readable explanation of why a request was blocked or warned. Params: `span_id` |
| `list_evals` | List all pain-point evals and their last-run status. Params: none |
| `get_eval_result` | Get the latest result for a specific eval. Params: `eval_id` |
| `replay_trace` | Re-run a trace against a different model or prompt version. Params: `trace_id`, `model?`, `prompt_version_id?` |

## Example usage in Claude

Once connected, you can ask Claude:

> "Show me the last 5 traces that had a guardrail block, and explain what fired."

> "Compare the latency of traces using claude-haiku-4-5 vs claude-sonnet-4-6 in the last hour."

> "Run the PP-G1 eval and tell me if it regressed."

## Auth

**V1:** `TRACELANE_API_KEY` environment variable passed via the MCP env block. The server resolves the tenant from the API key — `tenant_id` is never accepted as a tool argument.

**V2 (roadmap):** OAuth 2.1 PKCE. The authorization server is `https://gateway.tracelane.dev/.well-known/oauth-authorization-server`. `tenant_id` extracted from JWT `organizationId` claim only.

## Transports

| Transport | When to use |
|---|---|
| **Stdio** | Local use — Claude Desktop, Claude Code, Cursor. Zero network exposure. |
| **Streamable HTTP** | Hosted deployment at `mcp.tracelane.dev`. Multi-tenant. OAuth 2.1 PKCE auth in V2. |

## Security invariants

- **Read-only.** No write tools. The official `@modelcontextprotocol/sdk` enforces this at the transport layer.
- **Tenant isolation.** Every ClickHouse query includes `WHERE tenant_id = {tenantId: String}` (parameter-bound, never string-interpolated).
- **`tenant_id` is never a tool parameter.** It comes from the API key lookup or JWT claim.
- **No provider keys in tool responses.** The redaction layer strips `Authorization`, `x-api-key`, and bearer tokens before any span attribute surfaces through MCP.
- **Prompt-injection defence.** User-supplied span content is returned wrapped in `<UNTRUSTED_USER_DATA>` sentinels.

## Self-hosting

```bash
# From source
pnpm dev:mcp

# Docker
docker run -e TRACELANE_API_KEY=tlane_... \
           -e CLICKHOUSE_URL=http://ch.internal:8123 \
           -p 3001:3001 \
           ghcr.io/tracelane/mcp:latest
```

## Stack

- `@modelcontextprotocol/sdk` — official MCP SDK (stdio + Streamable HTTP)
- `@clickhouse/client` — parameter-bound ClickHouse queries
- TypeScript 5.5 strict, `noUncheckedIndexedAccess: true`
- Biome for lint + format

## License

Apache 2.0 — see [LICENSE](../../LICENSE).

<!-- tracelane:classification: PUBLIC -->
# Tracelane MCP Server

`@tracelanedev/mcp` exposes Tracelane's trace store and its recorded guardrail
decisions as [Model Context Protocol](https://modelcontextprotocol.io) tools.

It is read-only and tenant-scoped.

---

## Install

`@tracelanedev/mcp` is published on npm (`0.3.0`, 2026-09-07):

```bash
npx @tracelanedev/mcp
```

Or install globally:
```bash
npm install -g @tracelanedev/mcp
```

From a clone (local development):

```bash
pnpm install
pnpm --filter @tracelanedev/mcp build
node apps/mcp/dist/index.js
```

---

## Configuration (Claude Desktop)

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "tracelane": {
      "command": "npx",
      "args": ["@tracelanedev/mcp"],
      "env": {
        "TRACELANE_API_KEY": "tlane_your-key-here",
        "TRACELANE_GATEWAY_URL": "https://gateway.tracelane.dev"
      }
    }
  }
}
```

---

## Available tools

Eight tools ship (`apps/mcp/src/tools/traces.ts`, `apps/mcp/src/tools/evals.ts`):
`list_traces`, `get_trace`, `get_span`, `search_traces`, `replay_trace`,
`explain_guardrail_block`, `list_evals`, `get_eval_result`. The three below are
described in full; the reference for every tool is the
[MCP server page](https://docs.tracelane.dev/mcp-server).

### `search_traces`

Search your agent traces by free text, model, or error status.

**Parameters:**
```json
{
  "query": "string (case-insensitive substring across span names and attributes; gateway mode requires at least 4 characters)",
  "model_filter": "string (optional: restrict to spans whose attributes mention this model)",
  "has_error": "boolean (optional: restrict to error spans)",
  "limit": "integer (default: 10, max: 50)"
}
```

**Returns:** Matching traces, distinct per trace.

---

### `replay_trace`

Retrieve the stored span tree for a trace (read-only; it does not re-execute anything).

**Parameters:**
```json
{
  "trace_id": "string (UUID)"
}
```

**Returns:** Full span tree with all OTel GenAI attributes, predictive layer annotations, and audit log entries for the trace.

---

### `explain_guardrail_block`

Get a human-readable explanation of why a guardrail blocked or warned on a specific span.

**Parameters:**
```json
{
  "correlation_id": "string (optional: the id in a guardrail block's 403 response body)",
  "trace_id": "string (optional: use together with span_id, for a detection flag on a span that executed)",
  "span_id": "string (optional: use together with trace_id)"
}
```

**Returns:** Structured explanation including:
- The AFT rule that fired
- The evidence that triggered it
- The intervention taken
- How to resolve (if applicable)

---

## Security

The MCP server is read-only. It cannot:
- Modify traces or audit logs
- Change gateway configuration
- Access other tenants' data

All requests are scoped to the tenant identified by `TRACELANE_API_KEY`. The key
is validated by the gateway (`/v1/auth/whoami`) and the tenant comes from that
answer — never from a tool argument or request body.

---

## Self-hosted setup

If running Tracelane self-hosted, set `TRACELANE_GATEWAY_URL` to your gateway URL:

```bash
TRACELANE_API_KEY=tlane_your-key \
TRACELANE_GATEWAY_URL=http://localhost:8080 \
npx @tracelanedev/mcp
```

---

## Source

`apps/mcp/` — TypeScript, `@modelcontextprotocol/sdk`, tenant-scoped. Auth is a
bearer token (`tlane_*` key or JWT) resolved through the gateway's
`/v1/auth/whoami`.

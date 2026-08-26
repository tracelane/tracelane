<!-- tracelane:classification: PUBLIC -->
# Tracelane MCP Server

`@tracelanedev/mcp` exposes Tracelane's trace store and its recorded guardrail
decisions as [Model Context Protocol](https://modelcontextprotocol.io) tools.

It is read-only and tenant-scoped.

---

> **Not on npm — every `npx` line on this page returns a 404 today.**
> `@tracelanedev/mcp` is not on the registry. The package is wired into the release
> workflow and becomes installable when the next signed release tag carries it;
> releases are bundled, so that is the next tag covering everything that has moved,
> not a tag cut for this package alone. **Until then the only way to run it is from a
> clone** — see [Run it today](#run-it-today). The `npx` forms below are what to use
> *after* it is published; they are documented now so the configuration is ready, not
> because they work.

## Run it today (from a clone)

```bash
pnpm install
pnpm --filter @tracelanedev/mcp build
node apps/mcp/dist/index.js
```

Use `node /abs/path/to/apps/mcp/dist/index.js` as the `command` in any client config
below, with no `args`, in place of the `npx` form.

## Installation (once published — not yet available)

```bash
npx @tracelanedev/mcp
```

Or install globally:
```bash
npm install -g @tracelanedev/mcp
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
        "TRACELANE_GATEWAY_URL": "https://api.tracelane.dev"
      }
    }
  }
}
```

---

## Available tools

### `search_traces`

Search your agent traces by time range, model, provider, or guardrail outcome.

**Parameters:**
```json
{
  "query": "string (free-text search across span names and attributes)",
  "from": "ISO-8601 timestamp (optional, default: 1 hour ago)",
  "to": "ISO-8601 timestamp (optional, default: now)",
  "provider": "string (optional: openai | anthropic | gemini | …)",
  "model": "string (optional: model ID filter)",
  "intervention": "none | warn | block (optional)",
  "limit": "integer (default: 20, max: 100)"
}
```

**Returns:** Array of trace summaries with root span name, duration, span count, intervention status.

---

### `replay_trace`

Retrieve the full span tree for a trace, suitable for time-machine replay.

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
  "span_id": "string (UUID)",
  "aft_id": "string (optional: specific AFT rule ID, e.g. AFT-MCP-RUGPULL-001)"
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
is validated against a JWT claim — never accepted from request body.

---

## Self-hosted setup

If running Tracelane self-hosted, set `TRACELANE_GATEWAY_URL` to your gateway URL:

```bash
TRACELANE_API_KEY=tlane_your-key \
TRACELANE_GATEWAY_URL=http://localhost:8080 \
node apps/mcp/dist/index.js        # `npx @tracelanedev/mcp` once published
```

---

## Source

`apps/mcp/` — TypeScript, `@modelcontextprotocol/sdk`, tenant-scoped. Auth is a
bearer token (`tlane_*` key or JWT) resolved through the gateway's
`/v1/auth/whoami`; OAuth 2.1 PKCE is roadmap, not implemented.

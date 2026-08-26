<!-- tracelane:classification: PUBLIC -->
# @tracelanedev/sdk

[![npm](https://img.shields.io/npm/v/@tracelanedev/sdk)](https://www.npmjs.com/package/@tracelanedev/sdk)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../../LICENSE)

Instrumentation for TypeScript AI agents, built on the OpenTelemetry Node SDK.
Spans are emitted via OTLP/HTTP (JSON) to the endpoint you configure —
`https://gateway.tracelane.dev` on Tracelane Cloud, or a receiver you run.

## Install

```bash
npm install @tracelanedev/sdk
# or
pnpm add @tracelanedev/sdk
```

## Fastest path — route through the gateway (no SDK)

For Tracelane Cloud, the shortest path to your first trace needs **no SDK at
all**: point your existing client's base URL at the gateway and use your
`tlane_…` key. The gateway routes the call and captures the trace.

```typescript
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "https://gateway.tracelane.dev/v1",
  apiKey: process.env.TRACELANE_API_KEY!, // tlane_… from app.tracelane.dev
});

await client.chat.completions.create({
  model: "claude-sonnet-4-6",
  messages: [{ role: "user", content: "Hello" }],
});
// → Trace visible at https://app.tracelane.dev/traces within ~1 second
```

That captures the model call. Use this SDK when you want the **shape of your
agent** — the planner step, each tool call, the summariser — as a nested trace
rather than one span per model call. It exports OTLP to Tracelane Cloud's
gateway, a self-hosted Tracelane ingest, or your own collector (Jaeger, Tempo, …).

## Sessions — group turns into one conversation

[`/sessions`](https://app.tracelane.dev/sessions) groups traces by conversation
id. The id travels as the `x-conversation-id` request header (the gateway also
accepts `x-session-id`), and it lands on the span as `gen_ai.conversation.id`.
This SDK is what sets it — an un-sessioned call sends no session header and
carries no conversation id.

Wrap the turn and every call inside the scope joins the session:

```typescript
import { instrumentOpenAI, withSession } from "@tracelanedev/sdk";

instrumentOpenAI(client);

await withSession(conversationId, async () => {
  await client.chat.completions.create({ model: "claude-sonnet-4-6", messages });
  await client.chat.completions.create({ model: "claude-sonnet-4-6", messages: followUp });
});
// Both calls land in the same session.
```

`withSession` is backed by `AsyncLocalStorage`, so overlapping conversations in
one server process never bleed into each other. For a single-conversation script
or CLI, `setSession(id)` sets it process-wide instead, and `getSession()` reads
back whichever is active.

Auto-attach covers the four adapters that wrap a request-options argument:
`instrumentOpenAI`, `instrumentAnthropic`, `instrumentLiteLLM` and
`instrumentOpenRouter`. For every other client — including the no-SDK gateway
path above — pass the header yourself:

```typescript
import { sessionHeaders } from "@tracelanedev/sdk";

await client.chat.completions.create(
  { model: "claude-sonnet-4-6", messages },
  { headers: sessionHeaders(conversationId) },
);
```

`sessionHeaders()` with no argument returns the active session, or `{}` when
there is none, so it is always safe to spread. A header you set explicitly always
wins over the ambient session.

A session id must be non-empty visible ASCII, at most 256 characters. Anything
else throws at the call you wrote, rather than being dropped in transit and
leaving the session silently empty — and it is rejected, never truncated, because
a truncated id would split one conversation into two.

## SDK quick start (OTLP export)

Two steps: `init()` once at startup, then wrap each client with its
`instrument*` function. There is no zero-config magic in v1 — wrapping is
explicit, so what's traced is exactly what you opted in.

```typescript
import { init, instrumentAnthropic } from "@tracelanedev/sdk";
import Anthropic from "@anthropic-ai/sdk";

// 1. Initialise once. endpoint + apiKey are REQUIRED (no env-var auto-read).
init({
  endpoint: "https://gateway.tracelane.dev", // or a receiver you run
  apiKey: process.env.TRACELANE_API_KEY!,    // needs the `ingest` scope
  serviceName: "my-agent",
});

// 2. Wrap the client — instrumentAnthropic patches it in place.
const client = new Anthropic();
instrumentAnthropic(client);

// 3. Use it normally — every call now emits a span.
await client.messages.create({
  model: "claude-sonnet-4-6",
  messages: [{ role: "user", content: "Hello" }],
  max_tokens: 128,
});
```

> **Your key needs the `ingest` scope.** Keys minted before scopes existed carry
> the full API surface and work as-is. A key scoped to `chat` and `read` does
> not — the gateway answers `403 insufficient_scope` and names `ingest` in the
> body. Tick **Ingest** in **Settings → API Keys**; it is on by default for new
> keys.

### `init()` options

| Field | Required | Description |
|---|---|---|
| `endpoint` | yes | OTLP HTTP endpoint. `https://gateway.tracelane.dev` for Cloud, or a receiver you run (e.g. `http://localhost:4318`). Spans POST to `${endpoint}/v1/traces`. |
| `apiKey` | yes | Your `tlane_…` key. Sent as the `x-tracelane-api-key` header. |
| `serviceName` | no | Resource `service.name` (default `unknown-service`). |
| `sampleRate` | no | 0.0–1.0 (default 1.0 — full trace; the tail sampler decides). |

Call `shutdown()` on exit to flush pending spans (an automatic flush is also
registered on `beforeExit`).

## Streaming (v1 limitation)

Streamed calls (`stream: true`) pass through untouched and still produce a
span with model + latency, marked `tracelane.streaming = true`. Token usage
and finish reason are **not** captured for streamed responses yet — that
is not implemented. A once-per-process runtime warning says exactly this.

## Instrumented libraries

Each library has its own `instrument*(client)` function — import it from the
package root or the matching subpath. Call it once, after constructing the
client (or, for module-level libraries, after import).

| Import | Wrap with | What is traced |
|---|---|---|
| `@anthropic-ai/sdk` | `instrumentAnthropic(client)` | `messages.create`, streaming, tool use |
| `openai` | `instrumentOpenAI(client)` | `chat.completions`, `embeddings`, Responses |
| `@openai/agents` | `instrumentOpenAIAgents(...)` | agent steps, tool calls, handoffs |
| `langchain` | `instrumentLangGraph(graph)` | chains, agents, tool calls |
| `@modelcontextprotocol/sdk` | `instrumentMCP(...)` | `tool_call`, `tool_result` |
| Vercel AI SDK | `instrumentVercelAI(...)` | `generateText`, `streamText`, `generateObject` |

Full list (one export per library): `instrumentAnthropic`, `instrumentOpenAI`,
`instrumentOpenAIAsync`, `instrumentLiteLLM`, `instrumentOpenRouter`,
`instrumentLangGraph`, `instrumentOpenAIAgents`, `instrumentVercelAI`,
`instrumentMCP`, `instrumentClaudeCode`, `instrumentCursor`,
`instrumentPinecone`, `instrumentQdrant`, `instrumentComposio`,
`instrumentBrowserbase`, `instrumentE2B`, `instrumentMem0`, `instrumentLetta`,
`instrumentFirecrawl`.

> **Zero-config `autoInstrument()` is not in v1** — calling it throws with a
> pointer to this explicit API. Auto-detection is not implemented.

## Next.js App Router

Initialise in `instrumentation.ts` (runs once per server process):

```typescript
// instrumentation.ts
export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    const { init } = await import("@tracelanedev/sdk");
    init({
      endpoint: "http://localhost:4318", // an OTLP receiver you run
      apiKey: process.env.TRACELANE_API_KEY!,
      serviceName: "my-nextjs-app",
    });
  }
}
```

## Manual spans

The SDK sets up a standard OpenTelemetry tracer provider, so custom spans use
`@opentelemetry/api` directly — no Tracelane-specific wrapper:

```typescript
import { trace } from "@opentelemetry/api";

const tracer = trace.getTracer("my-agent");
const hits = await tracer.startActiveSpan("retrieval", async (span) => {
  span.setAttribute("retrieval.top_k", 10);
  const results = await vectorStore.search(query, { topK: 10 });
  span.end();
  return results;
});
```

## Design invariants

- Telemetry goes to your configured `endpoint` only — the SDK never calls home.
- Instrumentation is additive — `instrument*` patches a client in place and does
  not modify the OpenAI/Anthropic module exports.
- **Redaction** — set `TRACELANE_TRACE_CONTENT=false` to redact prompt and
  completion text from captured traces (honored on the gateway path).
- Zero runtime dependencies beyond the OpenTelemetry SDK.

## Documentation

Full docs at [docs.tracelane.dev/sdk-typescript](https://docs.tracelane.dev/sdk-typescript).

## Stack

TypeScript 5.5+ strict, Biome (lint + format), Vitest.

## License

Apache 2.0 — see [LICENSE](../../LICENSE).

# @tracelanedev/sdk

[![npm](https://img.shields.io/npm/v/@tracelanedev/sdk)](https://www.npmjs.com/package/@tracelanedev/sdk)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../../LICENSE)

Instrumentation for TypeScript AI agents, built on the OpenTelemetry Node SDK.
Spans are emitted via OTLP to your Tracelane ingest endpoint.

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

Use this SDK when you want to **export OTLP spans to an endpoint you run** — a
self-hosted Tracelane ingest, or your own OTLP collector (Jaeger, Tempo, …).

## SDK quick start (OTLP export)

Two steps: `init()` once at startup, then wrap each client with its
`instrument*` function. There is no zero-config magic in v1 — wrapping is
explicit, so what's traced is exactly what you opted in.

```typescript
import { init, instrumentAnthropic } from "@tracelanedev/sdk";
import Anthropic from "@anthropic-ai/sdk";

// 1. Initialise once. endpoint + apiKey are REQUIRED (no env-var auto-read).
//    `endpoint` is an OTLP receiver YOU can reach — your collector, or a
//    self-hosted Tracelane ingest. (Tracelane Cloud's ingest is not a public
//    OTLP endpoint — use the gateway path above for Cloud.)
init({
  endpoint: process.env.OTEL_EXPORTER_OTLP_ENDPOINT ?? "http://localhost:4318",
  apiKey: process.env.TRACELANE_API_KEY!,
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

### `init()` options

| Field | Required | Description |
|---|---|---|
| `endpoint` | yes | OTLP HTTP endpoint you can reach, e.g. `http://localhost:4318` or a self-hosted ingest. Spans POST to `${endpoint}/v1/traces`. |
| `apiKey` | yes | Your `tlane_…` key. Sent as the `x-tracelane-api-key` header. |
| `serviceName` | no | Resource `service.name` (default `unknown-service`). |
| `sampleRate` | no | 0.0–1.0 (default 1.0 — full trace; the tail sampler decides). |

Call `shutdown()` on exit to flush pending spans (an automatic flush is also
registered on `beforeExit`).

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
> pointer to this explicit API. Auto-detection lands in v1.1.

## Next.js App Router

Initialise in `instrumentation.ts` (runs once per server process):

```typescript
// instrumentation.ts
export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    const { init } = await import("@tracelanedev/sdk");
    init({
      endpoint: "https://ingest.tracelane.dev",
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

<!-- tracelane:classification: PUBLIC -->
# tracelane — Python SDK

[![PyPI](https://img.shields.io/pypi/v/tracelane)](https://pypi.org/project/tracelane/)
[![Python](https://img.shields.io/pypi/pyversions/tracelane)](https://pypi.org/project/tracelane/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../../LICENSE)

Instrumentation for Python AI agents, built on OpenTelemetry. Spans are emitted
via OTLP/HTTP (protobuf) to the endpoint you configure — `https://gateway.tracelane.dev`
on Tracelane Cloud, or a receiver you run. Instrumentation is explicit — you
choose what to wrap.

## Install

```bash
pip install tracelane
```

## Fastest path — route through the gateway (no SDK)

For Tracelane Cloud, the shortest path to your first trace needs **no SDK at
all**: point your existing client's base URL at the gateway and use your
`tlane_…` key. The gateway routes the call and captures the trace.

```python
import os
from openai import OpenAI

# The gateway is OpenAI-compatible. It mounts /v1/chat/completions and reads the
# key from the `authorization` header — an Anthropic-native client pointed here
# would POST /v1/messages with `x-api-key` and get a 404.
client = OpenAI(
    base_url="https://gateway.tracelane.dev/v1",
    api_key=os.environ["TRACELANE_API_KEY"],  # tlane_… from app.tracelane.dev
)

client.chat.completions.create(
    model="claude-sonnet-4-6",
    messages=[{"role": "user", "content": "Hello"}],
)
# → Trace visible at https://app.tracelane.dev/traces within ~1 second
```

That captures the model call. Use this SDK when you want the **shape of your
agent** — the planner step, each tool call, the summariser — as a nested trace
rather than one span per model call. It exports OTLP to Tracelane Cloud's
gateway, a self-hosted Tracelane ingest, or your own collector.

## Sessions — group turns into one conversation

[`/sessions`](https://app.tracelane.dev/sessions) groups traces by conversation
id. The id travels as the `x-conversation-id` request header (the gateway also
accepts `x-session-id`), and it lands on the span as `gen_ai.conversation.id`.
This SDK is what sets it — an un-sessioned call sends no session header and
carries no conversation id.

Wrap the turn and every call inside the block joins the session:

```python
from tracelane import instrument_openai, use_session

instrument_openai(client)

with use_session(conversation_id):
    client.chat.completions.create(model="claude-sonnet-4-6", messages=messages)
    client.chat.completions.create(model="claude-sonnet-4-6", messages=follow_up)
# Both calls land in the same session.
```

`use_session` is backed by a `ContextVar`, so overlapping conversations never
bleed into each other across asyncio tasks or threads, and the previous value is
restored on exit — including when the block raises. For a single-conversation
script, `set_session(id)` sets it without the automatic restore, and
`get_session()` reads back whichever is active.

Auto-attach covers the three adapters that forward `extra_headers`:
`instrument_openai`, `instrument_anthropic` and `instrument_openrouter`. For
every other client — including the no-SDK gateway path above — pass the header
yourself:

```python
from tracelane import session_headers

client.chat.completions.create(
    model="claude-sonnet-4-6",
    messages=messages,
    extra_headers=session_headers(conversation_id),
)
```

`session_headers()` with no argument returns the active session, or `{}` when
there is none, so it is always safe to pass. A header you set explicitly always
wins over the ambient session.

A session id must be non-empty visible ASCII, at most 256 characters. Anything
else raises at the call you wrote, rather than being dropped in transit and
leaving the session silently empty — and it is rejected, never truncated, because
a truncated id would split one conversation into two.

## SDK quick start (OTLP export)

> **Your key needs the `ingest` scope.** Keys minted before scopes existed carry
> the full API surface and work as-is. A key scoped to `chat` and `read` does
> not — the gateway answers `403 insufficient_scope` and names `ingest` in the
> body. Tick **Ingest** in **Settings → API Keys**; it is on by default for new
> keys.

Call `init()` once (endpoint + api_key are required — no env-var auto-read), then
wrap each client. Two ways to wrap:

```python
from tracelane import init, instrument_anthropic
import anthropic

init(
    endpoint="https://gateway.tracelane.dev",  # or a receiver you run
    api_key="tlane_...",  # needs the `ingest` scope
    service_name="my-agent",
)

client = anthropic.Anthropic()
instrument_anthropic(client)  # now client.messages.create() emits spans

client.messages.create(
    model="claude-sonnet-4-6",
    messages=[{"role": "user", "content": "Hello"}],
    max_tokens=128,
)
```

`init()` arguments: `endpoint` (required, an OTLP HTTP receiver you can reach),
`api_key` (required), `service_name` (default `"unknown-service"`), `sample_rate`
(default `1.0`). Call `shutdown()` on exit to flush pending spans.

### Best-effort auto-instrumentation

`auto_instrument()` wraps a **small, fixed set** of installed libraries —
`anthropic`, `openai`, `litellm`, `claude_code` (and `langgraph` is a no-op, since
graphs are user-constructed). Everything else needs an explicit `instrument_*`
call.

```python
from tracelane import init, auto_instrument

init(endpoint="http://localhost:4318", api_key="tlane_...")
auto_instrument()  # wraps installed anthropic / openai / litellm / claude_code
```

## Streaming (v1 limitation)

Streamed calls (`stream=True`) pass through untouched and still produce a
span with model + latency, marked `tracelane.streaming = True`. Token usage
and finish reason are **not** captured for streamed responses yet — that
is not implemented. A once-per-process `UserWarning` says exactly this.

## Instrumented libraries

Each library has its own `instrument_*` function — construct the object, then call
it. `auto_instrument()` covers only the four above; the rest are explicit:

**LLM providers:** `instrument_anthropic`, `instrument_openai`,
`instrument_openai_async`, `instrument_azure_openai`, `instrument_bedrock`,
`instrument_openrouter`, `instrument_vertexai`, `instrument_litellm`

**Agent frameworks:** `instrument_langchain`, `instrument_langgraph`,
`instrument_llamaindex`, `instrument_crewai`, `instrument_autogen`,
`instrument_pydantic_ai`, `instrument_openai_agents`, `instrument_magentic_one`,
`instrument_smolagents`, `instrument_haystack`

**Memory & vector:** `instrument_pinecone`, `instrument_qdrant`, `instrument_mem0`,
`instrument_letta`

**Tools & browser:** `instrument_browserbase`, `instrument_e2b`,
`instrument_firecrawl`, `instrument_composio`, `instrument_mcp`,
`instrument_claude_code`

Each activates only if the corresponding package is installed.

## Custom spans

The SDK sets up a standard OpenTelemetry tracer provider, so custom spans use the
OTel API directly:

```python
from opentelemetry import trace

tracer = trace.get_tracer("my-agent")
with tracer.start_as_current_span("retrieval") as span:
    span.set_attribute("retrieval.top_k", 10)
    results = vector_store.search(query, top_k=10)
```

## Sampling

```python
import os
from tracelane import init

init(
    endpoint="http://localhost:4318",
    api_key="tlane_...",
    sample_rate=0.1 if os.getenv("ENV") == "production" else 1.0,
)
```

## Design invariants

- Telemetry goes to your configured `endpoint` only — the SDK never calls home.
- `wrapt`-based monkey-patch; `instrument_*` wraps a client without changing your
  call sites.
- **Redaction** — set `TRACELANE_TRACE_CONTENT=false` to redact prompt and
  completion text from captured traces (honored on the gateway path).
- No dependency on `litellm` or `arize-phoenix`.

## Documentation

Full docs at [docs.tracelane.dev/sdk-python](https://docs.tracelane.dev/sdk-python).

## Stack

Python 3.12+, Pydantic v2, Ruff (lint + format), pytest + pytest-asyncio.

## License

Apache 2.0 — see [LICENSE](../../LICENSE).

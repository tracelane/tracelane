# tracelane — Python SDK

[![PyPI](https://img.shields.io/pypi/v/tracelane)](https://pypi.org/project/tracelane/)
[![Python](https://img.shields.io/pypi/pyversions/tracelane)](https://pypi.org/project/tracelane/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../../LICENSE)

Instrumentation for Python AI agents, built on OpenTelemetry. Spans are emitted
via OTLP to your Tracelane ingest endpoint. Instrumentation is explicit — you
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
from anthropic import Anthropic

client = Anthropic(
    base_url="https://gateway.tracelane.dev",
    api_key=os.environ["TRACELANE_API_KEY"],  # tlane_… from app.tracelane.dev
)

client.messages.create(
    model="claude-sonnet-4-6",
    messages=[{"role": "user", "content": "Hello"}],
    max_tokens=128,
)
# → Trace visible at https://app.tracelane.dev/traces within ~1 second
```

Use this SDK when you want to **export OTLP spans to an endpoint you run** — a
self-hosted Tracelane ingest, or your own OTLP collector. (Tracelane Cloud's
ingest is not a public OTLP endpoint — use the gateway path above for Cloud.)

## SDK quick start (OTLP export)

Call `init()` once (endpoint + api_key are required — no env-var auto-read), then
wrap each client. Two ways to wrap:

```python
from tracelane import init, instrument_anthropic
import anthropic

init(endpoint="http://localhost:4318", api_key="tlane_...", service_name="my-agent")

client = anthropic.Anthropic()
instrument_anthropic(client)   # now client.messages.create() emits spans

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
auto_instrument()   # wraps installed anthropic / openai / litellm / claude_code
```

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
- No dependency on `litellm` (CVE-2026-42208) or `arize-phoenix` (ELv2).

## Documentation

Full docs at [docs.tracelane.dev/sdk-python](https://docs.tracelane.dev/sdk-python).

## Stack

Python 3.12+, Pydantic v2, Ruff (lint + format), pytest + pytest-asyncio.

## License

Apache 2.0 — see [LICENSE](../../LICENSE).

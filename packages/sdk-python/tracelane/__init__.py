"""Tracelane Python SDK.

Instruments AI agent frameworks via wrapt monkey-patching. Spans are emitted via
OTLP HTTP to your Tracelane ingest endpoint. Instrumentation is explicit: call
``init()`` once, then either ``auto_instrument()`` (best-effort for a small set
of libraries) or the individual ``instrument_*`` functions.

Example (explicit — traces exactly what you wrap)::

    from tracelane import init, instrument_anthropic
    import anthropic

    init(
        endpoint="https://ingest.tracelane.dev",
        api_key=os.environ["TRACELANE_API_KEY"],
    )
    client = anthropic.Anthropic()
    instrument_anthropic(client)   # now client.messages.create() emits spans

Best-effort auto-instrumentation (only anthropic, openai, litellm, claude_code
that are installed; everything else needs an explicit ``instrument_*`` call)::

    from tracelane import init, auto_instrument

    init(endpoint="...", api_key="...")
    auto_instrument()
"""

import contextlib

# Individual instrument_* re-exports for explicit single-library usage
from tracelane.instrumentations.anthropic import instrument_anthropic
from tracelane.instrumentations.autogen import instrument_autogen
from tracelane.instrumentations.azure_openai import instrument_azure_openai
from tracelane.instrumentations.bedrock import instrument_bedrock
from tracelane.instrumentations.browserbase import instrument_browserbase
from tracelane.instrumentations.claude_code import instrument_claude_code
from tracelane.instrumentations.composio import instrument_composio
from tracelane.instrumentations.crewai import instrument_crewai
from tracelane.instrumentations.e2b import instrument_e2b
from tracelane.instrumentations.firecrawl import instrument_firecrawl
from tracelane.instrumentations.haystack import instrument_haystack
from tracelane.instrumentations.langchain import instrument_langchain
from tracelane.instrumentations.langgraph import instrument_langgraph
from tracelane.instrumentations.letta import instrument_letta
from tracelane.instrumentations.litellm import instrument_litellm
from tracelane.instrumentations.llamaindex import instrument_llamaindex
from tracelane.instrumentations.magentic_one import instrument_magentic_one
from tracelane.instrumentations.mcp import instrument_mcp
from tracelane.instrumentations.mem0 import instrument_mem0
from tracelane.instrumentations.openai import instrument_openai, instrument_openai_async
from tracelane.instrumentations.openai_agents import instrument_openai_agents
from tracelane.instrumentations.openrouter import instrument_openrouter
from tracelane.instrumentations.pinecone import instrument_pinecone
from tracelane.instrumentations.pydantic_ai import instrument_pydantic_ai
from tracelane.instrumentations.qdrant import instrument_qdrant
from tracelane.instrumentations.smolagents import instrument_smolagents
from tracelane.instrumentations.vertexai import instrument_vertexai
from tracelane.tracer import TracelaneConfig, init, shutdown


def auto_instrument() -> None:
    """Best-effort auto-instrumentation for a small, fixed set of libraries.

    Attempts exactly these, and only if the library is installed (missing ones
    are skipped silently): **anthropic, openai, litellm, langgraph, claude_code**.
    Of those, ``anthropic``/``openai`` are wrapped on a freshly-constructed
    default client, ``litellm``/``claude_code`` patch the module/subprocess, and
    ``langgraph`` is a **no-op here** (graphs are user-constructed — call
    ``instrument_langgraph(graph)`` yourself after compiling).

    EVERY other adapter (composio, pinecone, qdrant, mem0, letta, firecrawl,
    langchain, llamaindex, crewai, autogen, pydantic_ai, bedrock, vertexai,
    azure_openai, magentic_one, smolagents, haystack, browserbase, e2b, mcp,
    openai_agents, openrouter) is NOT touched by auto_instrument — construct the
    object and call its ``instrument_*`` function directly. Call after ``init()``.

    Example::

        from tracelane import init, auto_instrument

        init(endpoint="https://ingest.tracelane.dev", api_key="...")
        auto_instrument()   # wraps installed anthropic/openai/litellm/claude_code
    """
    _try_instrument_anthropic()
    _try_instrument_openai()
    _try_instrument_litellm()
    _try_instrument_langgraph()
    _try_instrument_claude_code()


def _try_instrument_anthropic() -> None:
    try:
        import anthropic as _anthro  # noqa: PLC0415

        client = _anthro.Anthropic()
        instrument_anthropic(client)
    except Exception:  # noqa: BLE001
        pass


def _try_instrument_openai() -> None:
    try:
        import openai as _oai  # noqa: PLC0415

        client = _oai.OpenAI()
        instrument_openai(client)
    except Exception:  # noqa: BLE001
        pass


def _try_instrument_litellm() -> None:
    try:
        instrument_litellm()
    except ImportError:
        pass
    except Exception:  # noqa: BLE001
        pass


def _try_instrument_langgraph() -> None:
    # LangGraph graphs are user-constructed, so auto-instrument is a no-op here.
    # Users call instrument_langgraph(graph) after graph compilation.
    pass


def _try_instrument_claude_code() -> None:
    # `with` is fine here — claude_code instrumentation is best-effort;
    # any exception during attach is intentionally swallowed.
    with contextlib.suppress(Exception):
        instrument_claude_code()


__all__ = [
    "init",
    "shutdown",
    "TracelaneConfig",
    "auto_instrument",
    "instrument_anthropic",
    "instrument_openai",
    "instrument_openai_async",
    "instrument_litellm",
    "instrument_openrouter",
    "instrument_langgraph",
    "instrument_openai_agents",
    "instrument_mcp",
    "instrument_claude_code",
    "instrument_pinecone",
    "instrument_qdrant",
    "instrument_composio",
    "instrument_browserbase",
    "instrument_e2b",
    "instrument_mem0",
    "instrument_letta",
    "instrument_firecrawl",
    "instrument_langchain",
    "instrument_llamaindex",
    "instrument_crewai",
    "instrument_autogen",
    "instrument_pydantic_ai",
    "instrument_bedrock",
    "instrument_vertexai",
    "instrument_azure_openai",
    "instrument_magentic_one",
    "instrument_smolagents",
    "instrument_haystack",
]
__version__ = "0.1.0"

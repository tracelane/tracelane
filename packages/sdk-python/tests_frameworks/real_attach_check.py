"""B-314 — the adapters attach to REAL framework objects, or this file is red.

The SDK's own suite (``tests/``) mocks every framework, which is how four shipped
adapters that never attached stayed green (B-312: langchain, llamaindex and
crewai all raised ``ValueError: "<X>" object has no field "<method>"`` on a real,
unmodified install, because their objects are pydantic v2 models). A stand-in
accepts ``setattr``; the real object does not.

RULES OF THIS FILE — each one is a control, not a convention:

* Every framework is imported at MODULE TOP. A missing framework is an
  ``ImportError`` at collection, which fails the job. There is deliberately no
  ``pytest.importorskip`` — a test that skips when the framework is absent is
  the B-169 fake-green shape, and the whole point here is to have ONE place
  where "the framework is not installed" cannot read as "the adapter works".
* The file name does NOT match ``test_*.py`` on purpose: the default ``pytest``
  walk from the repo root (the ``python`` CI job, ``verify-all.sh``) must not
  collect it, because those environments do not carry the frameworks. The
  dedicated ``python-frameworks`` job in ``.github/workflows/ci.yml`` names
  this file explicitly, against ``scripts/ci/requirements/python-frameworks.txt``
  (hash-pinned at the exact versions each adapter was run against on
  2026-08-31).
* Where a framework's own offline model exists, the wrapped method is CALLED
  and the emitted span asserted. Where execution needs a provider (crewai's
  ``execute_task``), attach is asserted on the real object — that attach is
  the exact line that failed in B-312.
"""

from __future__ import annotations

from typing import TypedDict

# Real frameworks — imported at module top, see the docstring.
from crewai import Agent
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage
from langgraph.graph import END, START, StateGraph
from llama_index.core.llms.mock import MockLLM
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from tracelane.instrumentations._attach import already_attached
from tracelane.instrumentations.crewai import instrument_crewai
from tracelane.instrumentations.langchain import instrument_langchain
from tracelane.instrumentations.langgraph import instrument_langgraph
from tracelane.instrumentations.llamaindex import instrument_llamaindex


def _only_span(spans: InMemorySpanExporter, name: str):
    finished = spans.get_finished_spans()
    named = [s for s in finished if s.name == name]
    assert len(named) == 1, f"expected exactly one {name!r} span, got {[s.name for s in finished]}"
    return named[0]


def test_langchain_real_chat_model_attaches_and_emits(spans: InMemorySpanExporter) -> None:
    """``GenericFakeChatModel`` IS a pydantic v2 ``BaseChatModel`` — the B-312 object."""
    model = GenericFakeChatModel(messages=iter([AIMessage(content="hi")]))
    instrument_langchain(model)  # raised ValueError before B-312's `attach`
    assert already_attached(model, "invoke")
    out = model.invoke("hello")
    assert out.content == "hi"
    span = _only_span(spans, "langchain.chat.invoke")
    assert span.attributes["gen_ai.provider.name"] == "langchain"


def test_langgraph_real_compiled_graph_attaches_and_emits(spans: InMemorySpanExporter) -> None:
    class State(TypedDict):
        x: int

    g = StateGraph(State)
    g.add_node("inc", lambda s: {"x": s["x"] + 1})
    g.add_edge(START, "inc")
    g.add_edge("inc", END)
    app = g.compile()
    instrument_langgraph(app)
    assert already_attached(app, "invoke")
    assert app.invoke({"x": 1})["x"] == 2
    _only_span(spans, "langgraph.graph.invoke")


def test_llamaindex_real_llm_attaches_and_emits(spans: InMemorySpanExporter) -> None:
    """``MockLLM`` IS a pydantic v2 ``llama_index.core.llms.LLM`` — the B-312 object."""
    llm = MockLLM(max_tokens=4)
    instrument_llamaindex(llm)
    assert already_attached(llm, "complete")
    resp = llm.complete("hello")
    assert resp.text
    span = _only_span(spans, "llamaindex.llm.complete")
    assert span.attributes["gen_ai.provider.name"] == "llamaindex"


def test_crewai_real_agent_attaches() -> None:
    """``crewai.Agent`` IS a pydantic v2 model — attach was the failing line.

    ``execute_task`` is not called: it needs a live LLM, and a network call in
    a unit job is the wrong proof. The attach on the real object is what B-312
    could never do.
    """
    agent = Agent(role="checker", goal="attach", backstory="a real crewai Agent")
    instrument_crewai(agent)
    assert already_attached(agent, "execute_task")

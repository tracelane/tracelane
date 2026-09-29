"""Real LangGraph runs through the automatic callback/exporter integration."""

import asyncio
from typing import TypedDict

import pytest
from opentelemetry import trace

from tracelane import auto_instrument

pytest.importorskip("langgraph")
pytest.importorskip("openinference.instrumentation.langchain")
from langgraph.graph import END, START, StateGraph
from openinference.instrumentation.langchain import LangChainInstrumentor


class State(TypedDict):
    value: int


def graph():
    workflow = StateGraph(State)
    workflow.add_node("increment", lambda state: {"value": state["value"] + 1})
    workflow.add_node("double", lambda state: {"value": state["value"] * 2})
    workflow.add_edge(START, "increment")
    workflow.add_edge("increment", "double")
    workflow.add_edge("double", END)
    return workflow.compile()


@pytest.fixture(autouse=True)
def reset_instrumentation():
    yield
    instrumentor = LangChainInstrumentor()
    if instrumentor.is_instrumented_by_opentelemetry:
        instrumentor.uninstrument()


@pytest.mark.parametrize("mode", ["invoke", "ainvoke", "stream", "astream"])
def test_auto_real_graph_keeps_parent_tree_and_is_idempotent(spans, capsys, mode):
    app = graph()  # Graphs compiled before auto activation also work.
    auto_instrument()
    auto_instrument()
    with trace.get_tracer(__name__).start_as_current_span("caller"):
        if mode == "invoke":
            assert app.invoke({"value": 1}) == {"value": 4}
        elif mode == "ainvoke":
            assert asyncio.run(app.ainvoke({"value": 1})) == {"value": 4}
        elif mode == "stream":
            assert len(list(app.stream({"value": 1}))) == 2
        else:

            async def consume():
                return [chunk async for chunk in app.astream({"value": 1})]

            assert len(asyncio.run(consume())) == 2
    finished = spans.get_finished_spans()
    by_name = {span.name: span for span in finished}
    assert set(by_name) == {"caller", "LangGraph", "increment", "double"}
    assert len(finished) == 4
    assert by_name["LangGraph"].parent.span_id == by_name["caller"].context.span_id
    for name in ("increment", "double"):
        assert by_name[name].parent.span_id == by_name["LangGraph"].context.span_id
    assert len({span.context.trace_id for span in finished}) == 1
    for span in finished:
        assert span.attributes.get("input.value") in (None, "__REDACTED__")
        assert span.attributes.get("output.value") in (None, "__REDACTED__")
    assert "langgraph: instrumented" in capsys.readouterr().err


def test_missing_optional_dependency_reports_manual_fallback(monkeypatch, capsys):
    import builtins

    original = builtins.__import__

    def missing(name, *args, **kwargs):
        if name == "openinference.instrumentation.langchain":
            raise ImportError("secret must not appear in diagnostic")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing)
    auto_instrument()
    diagnostic = capsys.readouterr().err
    assert "langgraph: unavailable" in diagnostic
    assert "instrument_langgraph(graph)" in diagnostic
    assert "secret" not in diagnostic


def test_attach_failure_is_visible_without_exception_secrets(monkeypatch, capsys):
    import tracelane

    def broken():
        raise RuntimeError("secret credential")

    monkeypatch.setattr(tracelane, "_try_instrument_langgraph", broken)
    auto_instrument()
    diagnostic = capsys.readouterr().err
    assert "langgraph: could not instrument (RuntimeError)" in diagnostic
    assert "instrument_langgraph(graph)" in diagnostic
    assert "secret credential" not in diagnostic

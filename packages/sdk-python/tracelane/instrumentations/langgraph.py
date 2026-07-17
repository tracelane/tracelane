"""LangGraph instrumentation for Tracelane.

Wraps LangGraph CompiledGraph.invoke and CompiledGraph.ainvoke to emit OTel
spans for agent graph execution. Captures graph name, step count, and
execution metadata. The predictive layer uses these spans to detect
stuck-loop patterns (PP-PR4).

Example::

    from langgraph.graph import StateGraph, END
    from tracelane.instrumentations.langgraph import instrument_langgraph

    workflow = StateGraph(MyState)
    # ... add nodes, edges
    app = workflow.compile()
    instrument_langgraph(app)
    result = app.invoke({"messages": [...]})
    # Span emitted for the full graph execution
"""

from __future__ import annotations

from typing import Any

from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.langgraph", "0.1.0")


def instrument_langgraph(graph: Any) -> None:
    """Wrap a compiled LangGraph graph to emit OTel spans.

    Instruments both synchronous invoke() and asynchronous ainvoke().
    The graph's name (if set) appears as langgraph.graph_name in the span.

    Args:
        graph: A langgraph.graph.CompiledGraph instance.

    Note:
        Step count is extracted from the output if the state has a
        __step__ key (common in multi-turn agent graphs).
        API keys are never captured.
    """
    graph_name = getattr(graph, "name", None) or "unknown"

    _patch_invoke(graph, graph_name)
    _patch_ainvoke(graph, graph_name)
    _patch_stream(graph, graph_name)


def _patch_invoke(graph: Any, graph_name: str) -> None:
    if not hasattr(graph, "invoke"):
        return
    original = graph.invoke

    def _patched_invoke(input: Any, config: Any = None, **kwargs: Any) -> Any:
        with _tracer.start_as_current_span(
            "langgraph.graph.invoke",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "langgraph",
                "langgraph.graph_name": graph_name,
                "langgraph.invocation_type": "invoke",
            },
        ) as span:
            try:
                result = (
                    original(input, config, **kwargs)
                    if config is not None
                    else original(input, **kwargs)
                )
                _record_result(span, result)
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    graph.invoke = _patched_invoke


def _patch_ainvoke(graph: Any, graph_name: str) -> None:
    if not hasattr(graph, "ainvoke"):
        return
    original = graph.ainvoke

    async def _patched_ainvoke(input: Any, config: Any = None, **kwargs: Any) -> Any:
        with _tracer.start_as_current_span(
            "langgraph.graph.ainvoke",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "langgraph",
                "langgraph.graph_name": graph_name,
                "langgraph.invocation_type": "ainvoke",
            },
        ) as span:
            try:
                result = await (
                    original(input, config, **kwargs)
                    if config is not None
                    else original(input, **kwargs)
                )
                _record_result(span, result)
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    graph.ainvoke = _patched_ainvoke


def _patch_stream(graph: Any, graph_name: str) -> None:
    """Wrap stream() to emit a span per chunk for stuck-loop detection."""
    if not hasattr(graph, "stream"):
        return
    original = graph.stream

    def _patched_stream(input: Any, config: Any = None, **kwargs: Any) -> Any:
        with _tracer.start_as_current_span(
            "langgraph.graph.stream",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "langgraph",
                "langgraph.graph_name": graph_name,
                "langgraph.invocation_type": "stream",
            },
        ) as span:
            try:
                gen = (
                    original(input, config, **kwargs)
                    if config is not None
                    else original(input, **kwargs)
                )
                step = 0
                for chunk in gen:
                    step += 1
                    yield chunk
                span.set_attribute("langgraph.step_count", step)
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    graph.stream = _patched_stream


def _record_result(span: Any, result: Any) -> None:
    if isinstance(result, dict):
        step = result.get("__step__")
        if step is not None:
            span.set_attribute("langgraph.step_count", int(step))
        messages = result.get("messages")
        if isinstance(messages, list):
            span.set_attribute("langgraph.messages_count", len(messages))

"""Composio instrumentation for Tracelane.

Wraps ComposioToolSet.execute_action to emit OTel spans for tool-call
operations. Composio agents generate the highest cardinality of tool-call
traces in the ecosystem — this adapter provides the visibility needed to
detect runaway tool chains and cost overruns.

Example::

    from composio_core import ComposioToolSet
    from tracelane.instrumentations.composio import instrument_composio

    toolset = ComposioToolSet()
    instrument_composio(toolset)
    result = toolset.execute_action("GITHUB_CREATE_ISSUE", {...})
    # Span emitted with composio.action and entity_id
"""

from __future__ import annotations

from typing import Any

from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.composio", "0.1.0")


def instrument_composio(toolset: Any) -> None:
    """Wrap a ComposioToolSet instance to emit OTel spans.

    Args:
        toolset: A composio_core.ComposioToolSet instance.

    Note:
        Action parameters are counted but never captured to avoid PII.
        The action name (e.g. GITHUB_CREATE_ISSUE) is captured.
    """
    if hasattr(toolset, "execute_action"):
        _patch_execute_action(toolset)
    if hasattr(toolset, "get_tools"):
        _patch_get_tools(toolset)


def _patch_execute_action(toolset: Any) -> None:
    original = toolset.execute_action

    def _patched(
        action: Any, params: Any = None, entity_id: Any = None, *args: Any, **kwargs: Any
    ) -> Any:
        param_count = len(params) if isinstance(params, dict) else 0
        with _tracer.start_as_current_span(
            "composio.execute_action",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "composio",
                "composio.action": str(action),
                "composio.entity_id": str(entity_id) if entity_id else "",
                "composio.param_count": param_count,
            },
        ) as span:
            try:
                result = original(action, params, entity_id, *args, **kwargs)
                successful = getattr(result, "successful", None)
                if successful is not None:
                    span.set_attribute("composio.successful", bool(successful))
                error = getattr(result, "error", None)
                if error:
                    span.set_attribute("composio.error_message", str(error)[:256])
                span.set_status(
                    StatusCode.OK if not error else StatusCode.ERROR,
                    str(error)[:256] if error else "",
                )
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    toolset.execute_action = _patched


def _patch_get_tools(toolset: Any) -> None:
    original = toolset.get_tools

    def _patched(*args: Any, **kwargs: Any) -> Any:
        with _tracer.start_as_current_span(
            "composio.get_tools",
            kind=SpanKind.CLIENT,
            attributes={"gen_ai.provider.name": "composio"},
        ) as span:
            try:
                result = original(*args, **kwargs)
                tool_count = len(result) if isinstance(result, list) else 0
                span.set_attribute("composio.tools_count", tool_count)
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    toolset.get_tools = _patched

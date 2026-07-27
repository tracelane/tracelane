"""Mem0 instrumentation for Tracelane.

Wraps Mem0's Memory.add and Memory.search to emit OTel spans.
Instrumenting memory operations now lets operators understand memory hit
rates and latency as a first-class observability concern, not an
afterthought.

Example::

    from mem0 import Memory
    from tracelane.instrumentations.mem0 import instrument_mem0

    memory = Memory()
    instrument_mem0(memory)
    memory.add(messages=[{"role": "user", "content": "..."}], user_id="alice")
    results = memory.search("previous conversation", user_id="alice")
    # Spans emitted with mem0.user_id and results_count
"""

from __future__ import annotations

from typing import Any

from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.mem0", "0.1.0")


def instrument_mem0(memory: Any) -> None:
    """Wrap a Mem0 Memory instance to emit OTel spans.

    Instruments add(), search(), get_all(), and delete() operations.

    Args:
        memory: A mem0.Memory or mem0ai.MemoryClient instance.

    Note:
        Message content is never captured — only user_id, message count,
        and search result count are recorded.
    """
    if hasattr(memory, "add"):
        _patch_add(memory)
    if hasattr(memory, "search"):
        _patch_search(memory)
    if hasattr(memory, "get_all"):
        _patch_get_all(memory)


def _patch_add(memory: Any) -> None:
    original = memory.add

    def _patched(messages: Any = None, *args: Any, **kwargs: Any) -> Any:
        user_id = kwargs.get("user_id", "")
        message_count = len(messages) if isinstance(messages, list) else 1
        with _tracer.start_as_current_span(
            "mem0.memory.add",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "mem0",
                "mem0.operation": "add",
                "mem0.user_id": str(user_id),
                "mem0.message_count": message_count,
            },
        ) as span:
            try:
                result = original(messages, *args, **kwargs)
                results = getattr(result, "results", None) or (
                    result if isinstance(result, list) else []
                )
                span.set_attribute("mem0.memories_added", len(results))
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    memory.add = _patched


def _patch_search(memory: Any) -> None:
    original = memory.search

    def _patched(query: Any = None, *args: Any, **kwargs: Any) -> Any:
        user_id = kwargs.get("user_id", "")
        limit = kwargs.get("limit", kwargs.get("top_k", 10))
        with _tracer.start_as_current_span(
            "mem0.memory.search",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "mem0",
                "mem0.operation": "search",
                "mem0.user_id": str(user_id),
                "mem0.limit": int(limit),
            },
        ) as span:
            try:
                result = original(query, *args, **kwargs)
                results = getattr(result, "results", None) or (
                    result if isinstance(result, list) else []
                )
                span.set_attribute("mem0.results_count", len(results))
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    memory.search = _patched


def _patch_get_all(memory: Any) -> None:
    original = memory.get_all

    def _patched(*args: Any, **kwargs: Any) -> Any:
        user_id = kwargs.get("user_id", "")
        with _tracer.start_as_current_span(
            "mem0.memory.get_all",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "mem0",
                "mem0.operation": "get_all",
                "mem0.user_id": str(user_id),
            },
        ) as span:
            try:
                result = original(*args, **kwargs)
                results = getattr(result, "results", None) or (
                    result if isinstance(result, list) else []
                )
                span.set_attribute("mem0.memories_count", len(results))
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    memory.get_all = _patched

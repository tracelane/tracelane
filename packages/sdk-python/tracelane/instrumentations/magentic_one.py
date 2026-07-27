"""Magentic-One instrumentation for Tracelane.

Wraps MagenticOneHelper.run and MagenticOneHelper.run_stream to emit OTel spans
for every multi-agent task invocation. Captures run kind (async vs streaming)
and records exceptions with full status propagation. Never captures task text,
API keys, or intermediate agent messages.

Example::

    from autogen_agentchat.agents import MagenticOneHelper
    from tracelane.instrumentations.magentic_one import instrument_magentic_one

    helper = MagenticOneHelper(...)
    instrument_magentic_one(helper)
    result = await helper.run("task")
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.magentic_one", "0.1.0")

_COMMON_ATTRS: dict[str, str] = {
    "gen_ai.provider.name": "magentic_one",
    "gen_ai.request.model": "multi-agent",
}


def instrument_magentic_one(helper_or_agent: Any) -> None:
    """Wrap a MagenticOneHelper instance to emit OTel spans on run and run_stream.

    Args:
        helper_or_agent: A MagenticOneHelper (or compatible) instance whose
            run and run_stream methods will be patched in-place.

    Note:
        Mutates the instance directly — no wrapt used for async methods.
        Task text and intermediate outputs are never captured.
    """
    _patch_run(helper_or_agent)
    _patch_run_stream(helper_or_agent)


def _patch_run(helper: Any) -> None:
    """Patch the async run() method with a tracing wrapper."""
    if not hasattr(helper, "run"):
        return

    original = helper.run

    async def _patched_run(*args: Any, **kwargs: Any) -> Any:
        with _tracer.start_as_current_span(
            "magentic_one.run",
            kind=SpanKind.CLIENT,
            attributes=_COMMON_ATTRS,
        ) as span:
            try:
                result = await original(*args, **kwargs)
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    helper.run = _patched_run


def _patch_run_stream(helper: Any) -> None:
    """Patch the async generator run_stream() method with a tracing wrapper."""
    if not hasattr(helper, "run_stream"):
        return

    original = helper.run_stream

    async def _patched_run_stream(*args: Any, **kwargs: Any) -> AsyncGenerator[Any, None]:
        with _tracer.start_as_current_span(
            "magentic_one.run_stream",
            kind=SpanKind.CLIENT,
            attributes=_COMMON_ATTRS,
        ) as span:
            try:
                async for chunk in original(*args, **kwargs):
                    yield chunk
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    helper.run_stream = _patched_run_stream

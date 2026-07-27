"""Haystack v2 instrumentation for Tracelane.

Wraps Pipeline.run (sync) and Pipeline.run_async (async) to emit OTel spans
for every pipeline invocation. The component count is extracted from the
pipeline graph at instrumentation time as a structural metadata attribute.
Never captures pipeline input values, component outputs, or API keys.

Example::

    from haystack import Pipeline
    from tracelane.instrumentations.haystack import instrument_haystack

    pipeline = Pipeline()
    instrument_haystack(pipeline)
    result = pipeline.run({"text_embedder": {"text": "hello"}})
"""

from __future__ import annotations

from typing import Any

import wrapt
from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.haystack", "0.1.0")


def instrument_haystack(pipeline: Any) -> None:
    """Wrap a Haystack v2 Pipeline instance to emit OTel spans on run and run_async.

    Instruments the synchronous run() via wrapt and the async run_async() via
    direct assignment. Component count is read from pipeline.graph.nodes at
    call time if accessible, defaulting to 0 if the attribute is absent.

    Args:
        pipeline: A haystack.Pipeline instance.

    Note:
        Mutates the pipeline in-place. Input dicts, component outputs, and any
        embedded text content are never captured in span attributes.
    """
    _patch_run(pipeline)
    _patch_run_async(pipeline)


def _component_count(pipeline: Any) -> int:
    """Return the number of components registered in the pipeline graph."""
    try:
        return len(pipeline.graph.nodes)
    except Exception:
        return 0


def _patch_run(pipeline: Any) -> None:
    """Patch Pipeline.run (sync) with a wrapt wrapper emitting a haystack.pipeline.run span."""
    if not hasattr(pipeline, "run"):
        return

    def _patched_run(wrapped: Any, instance: Any, args: Any, kwargs: Any) -> Any:
        with _tracer.start_as_current_span(
            "haystack.pipeline.run",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "haystack",
                "haystack.component_count": _component_count(instance),
            },
        ) as span:
            try:
                result = wrapped(*args, **kwargs)
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    wrapt.wrap_function_wrapper(pipeline, "run", _patched_run)


def _patch_run_async(pipeline: Any) -> None:
    """Patch Pipeline.run_async (async) with a direct-assignment tracing wrapper."""
    if not hasattr(pipeline, "run_async"):
        return

    original = pipeline.run_async

    async def _patched_run_async(*args: Any, **kwargs: Any) -> Any:
        with _tracer.start_as_current_span(
            "haystack.pipeline.run_async",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "haystack",
                "haystack.component_count": _component_count(pipeline),
            },
        ) as span:
            try:
                result = await original(*args, **kwargs)
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    pipeline.run_async = _patched_run_async

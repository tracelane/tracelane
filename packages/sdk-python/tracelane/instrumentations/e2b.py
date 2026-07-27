"""E2B instrumentation for Tracelane.

Wraps E2B Sandbox lifecycle events to emit OTel spans. Sandbox creation
and destruction are significant latency events in agent pipelines — observing
them allows operators to optimize cold-start patterns and detect runaway
sandboxes (cost overruns from un-killed sandboxes are a common pain point).

Example::

    from e2b_code_interpreter import CodeInterpreter
    from tracelane.instrumentations.e2b import instrument_e2b

    instrument_e2b(CodeInterpreter)
    sandbox = await CodeInterpreter.create(timeout=60)
    # Spans emitted for create() and kill()
"""

from __future__ import annotations

import time
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.e2b", "0.1.0")


def instrument_e2b(sandbox_cls: Any) -> None:
    """Instrument an E2B Sandbox class to emit OTel spans.

    Instruments the class-level create() static/class method and the
    instance-level kill() / close() methods.

    Args:
        sandbox_cls: An E2B Sandbox class (e.g. e2b.Sandbox,
                     e2b_code_interpreter.CodeInterpreter).

    Note:
        sandbox_id and template are captured. Execution commands
        are counted but not captured.
    """
    if hasattr(sandbox_cls, "create"):
        _patch_create(sandbox_cls)
    if hasattr(sandbox_cls, "acreate"):
        _patch_acreate(sandbox_cls)


def _patch_create(sandbox_cls: Any) -> None:
    original = sandbox_cls.create

    def _patched(*args: Any, **kwargs: Any) -> Any:
        template = kwargs.get("template", args[0] if args else "unknown")
        timeout = kwargs.get("timeout", 300)
        with _tracer.start_as_current_span(
            "e2b.sandbox.create",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "e2b",
                "e2b.template": str(template),
                "e2b.timeout_s": int(timeout),
                "e2b.operation": "create",
            },
        ) as span:
            try:
                start = time.monotonic()
                result = original(*args, **kwargs)
                duration_ms = int((time.monotonic() - start) * 1000)
                span.set_attribute("e2b.create_duration_ms", duration_ms)
                sandbox_id = getattr(result, "sandbox_id", None) or getattr(result, "id", None)
                if sandbox_id:
                    span.set_attribute("e2b.sandbox_id", str(sandbox_id))
                _patch_kill_instance(result)
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    sandbox_cls.create = _patched


def _patch_acreate(sandbox_cls: Any) -> None:
    original = sandbox_cls.acreate

    async def _async_patched(*args: Any, **kwargs: Any) -> Any:
        template = kwargs.get("template", args[0] if args else "unknown")
        timeout = kwargs.get("timeout", 300)
        with _tracer.start_as_current_span(
            "e2b.sandbox.acreate",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "e2b",
                "e2b.template": str(template),
                "e2b.timeout_s": int(timeout),
                "e2b.operation": "acreate",
            },
        ) as span:
            try:
                start = time.monotonic()
                result = await original(*args, **kwargs)
                duration_ms = int((time.monotonic() - start) * 1000)
                span.set_attribute("e2b.create_duration_ms", duration_ms)
                sandbox_id = getattr(result, "sandbox_id", None) or getattr(result, "id", None)
                if sandbox_id:
                    span.set_attribute("e2b.sandbox_id", str(sandbox_id))
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    sandbox_cls.acreate = _async_patched


def _patch_kill_instance(sandbox: Any) -> None:
    """Patch kill() and close() on a sandbox instance."""
    for method_name in ("kill", "close", "aclose"):
        original = getattr(sandbox, method_name, None)
        if original is None:
            continue

        sandbox_id = str(getattr(sandbox, "sandbox_id", None) or getattr(sandbox, "id", "") or "")

        import inspect

        if inspect.iscoroutinefunction(original):

            async def _async_kill(
                *args: Any, _orig: Any = original, _sid: str = sandbox_id, **kwargs: Any
            ) -> Any:
                with _tracer.start_as_current_span(
                    "e2b.sandbox.kill",
                    kind=SpanKind.CLIENT,
                    attributes={"gen_ai.provider.name": "e2b", "e2b.sandbox_id": _sid},
                ) as span:
                    try:
                        result = await _orig(*args, **kwargs)
                        span.set_status(StatusCode.OK)
                        return result
                    except Exception as exc:
                        span.record_exception(exc)
                        span.set_status(StatusCode.ERROR, str(exc))
                        raise

            setattr(sandbox, method_name, _async_kill)
        else:

            def _sync_kill(
                *args: Any, _orig: Any = original, _sid: str = sandbox_id, **kwargs: Any
            ) -> Any:
                with _tracer.start_as_current_span(
                    "e2b.sandbox.kill",
                    kind=SpanKind.CLIENT,
                    attributes={"gen_ai.provider.name": "e2b", "e2b.sandbox_id": _sid},
                ) as span:
                    try:
                        result = _orig(*args, **kwargs)
                        span.set_status(StatusCode.OK)
                        return result
                    except Exception as exc:
                        span.record_exception(exc)
                        span.set_status(StatusCode.ERROR, str(exc))
                        raise

            setattr(sandbox, method_name, _sync_kill)

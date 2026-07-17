"""LiteLLM SDK instrumentation for Tracelane.

Patches the module-level litellm.completion and litellm.acompletion functions
to emit OTel spans. LiteLLM is a migration-path target — customers running
LiteLLM can switch to Tracelane's gateway and keep their `litellm.completion`
call sites unchanged.

Example::

    import litellm
    from tracelane.instrumentations.litellm import instrument_litellm

    instrument_litellm()  # no client arg — patches the module
    response = litellm.completion(model="gpt-4o", messages=[...])
    # Span emitted automatically
"""

from __future__ import annotations

from typing import Any

from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.litellm", "0.1.0")


def instrument_litellm() -> None:
    """Patch the litellm module to emit OTel spans on every completion call.

    Instruments both litellm.completion (sync) and litellm.acompletion (async).
    Safe to call multiple times — subsequent calls are no-ops if already patched.

    Note:
        Patches are applied at the module level and affect all callers
        in the process. API keys are never captured.

    Raises:
        ImportError: If litellm is not installed.
    """
    import litellm  # noqa: PLC0415 (lazy import is intentional)

    _patch_sync(litellm)
    _patch_async(litellm)


_PATCHED_ATTR = "_tracelane_patched"


def _patch_sync(litellm_module: Any) -> None:
    if getattr(litellm_module.completion, _PATCHED_ATTR, False):
        return
    original = litellm_module.completion

    def _patched(*args: Any, **kwargs: Any) -> Any:
        model = kwargs.get("model", args[0] if args else "unknown")
        with _tracer.start_as_current_span(
            "litellm.completion",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "litellm",
                "gen_ai.request.model": str(model),
                "llm.model_name": str(model),
            },
        ) as span:
            try:
                result = original(*args, **kwargs)
                _record_response(span, result)
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    setattr(_patched, _PATCHED_ATTR, True)
    litellm_module.completion = _patched


def _patch_async(litellm_module: Any) -> None:
    if not hasattr(litellm_module, "acompletion"):
        return
    if getattr(litellm_module.acompletion, _PATCHED_ATTR, False):
        return
    original = litellm_module.acompletion

    async def _async_patched(*args: Any, **kwargs: Any) -> Any:
        model = kwargs.get("model", args[0] if args else "unknown")
        with _tracer.start_as_current_span(
            "litellm.acompletion",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "litellm",
                "gen_ai.request.model": str(model),
                "llm.model_name": str(model),
            },
        ) as span:
            try:
                result = await original(*args, **kwargs)
                _record_response(span, result)
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    setattr(_async_patched, _PATCHED_ATTR, True)
    litellm_module.acompletion = _async_patched


def _record_response(span: Any, result: Any) -> None:
    usage = getattr(result, "usage", None)
    if usage:
        prompt = getattr(usage, "prompt_tokens", 0) or 0
        completion = getattr(usage, "completion_tokens", 0) or 0
        span.set_attribute("gen_ai.usage.input_tokens", prompt)
        span.set_attribute("gen_ai.usage.output_tokens", completion)
        span.set_attribute("llm.token_count.prompt", prompt)
        span.set_attribute("llm.token_count.completion", completion)
    model = getattr(result, "model", None)
    if model:
        span.set_attribute("gen_ai.response.model", model)

"""OpenAI SDK instrumentation for Tracelane.

Wraps openai.OpenAI (and AsyncOpenAI) chat.completions.create to emit OTel
spans for every chat completion call. Captures model, token counts, and
latency. Never captures API keys or message content.

Example::

    import openai
    from tracelane.instrumentations.openai import instrument_openai

    client = openai.OpenAI()
    instrument_openai(client)
    # All client.chat.completions.create() calls now emit spans
"""

from __future__ import annotations

from typing import Any

from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.openai", "0.1.0")


def instrument_openai(client: Any) -> None:
    """Wrap an OpenAI client instance to emit OTel spans.

    Works with both openai.OpenAI and openai.AsyncOpenAI. The async path
    is detected by checking whether the original method is a coroutine function.

    Args:
        client: An openai.OpenAI or openai.AsyncOpenAI instance.

    Note:
        Mutates the client in-place. API keys are never captured.
        Only model, token counts, finish reason, and latency are recorded.
    """
    import inspect

    original_create = client.chat.completions.create

    if inspect.iscoroutinefunction(original_create):

        async def _async_create(*args: Any, **kwargs: Any) -> Any:
            request = kwargs if kwargs else (args[0] if args else {})
            model = (
                kwargs.get("model", "unknown")
                if isinstance(request, dict)
                else getattr(request, "model", "unknown")
            )
            with _tracer.start_as_current_span(
                "openai.chat.completions.create",
                kind=SpanKind.CLIENT,
                attributes={
                    "gen_ai.provider.name": "openai",
                    "gen_ai.request.model": model,
                    "llm.model_name": model,
                },
            ) as span:
                try:
                    result = await original_create(*args, **kwargs)
                    _record_response(span, result)
                    span.set_status(StatusCode.OK)
                    return result
                except Exception as exc:
                    span.record_exception(exc)
                    span.set_status(StatusCode.ERROR, str(exc))
                    raise

        client.chat.completions.create = _async_create
    else:

        def _sync_create(*args: Any, **kwargs: Any) -> Any:
            model = kwargs.get("model", "unknown")
            with _tracer.start_as_current_span(
                "openai.chat.completions.create",
                kind=SpanKind.CLIENT,
                attributes={
                    "gen_ai.provider.name": "openai",
                    "gen_ai.request.model": model,
                    "llm.model_name": model,
                },
            ) as span:
                try:
                    result = original_create(*args, **kwargs)
                    _record_response(span, result)
                    span.set_status(StatusCode.OK)
                    return result
                except Exception as exc:
                    span.record_exception(exc)
                    span.set_status(StatusCode.ERROR, str(exc))
                    raise

        client.chat.completions.create = _sync_create


def _record_response(span: Any, result: Any) -> None:
    """Extract token usage and finish reason from an OpenAI response."""
    usage = getattr(result, "usage", None)
    if usage:
        prompt_tokens = getattr(usage, "prompt_tokens", 0) or 0
        completion_tokens = getattr(usage, "completion_tokens", 0) or 0
        span.set_attribute("gen_ai.usage.input_tokens", prompt_tokens)
        span.set_attribute("gen_ai.usage.output_tokens", completion_tokens)
        span.set_attribute("llm.token_count.prompt", prompt_tokens)
        span.set_attribute("llm.token_count.completion", completion_tokens)
        # v1.40 prompt-cache read tokens (OpenAI nests these under
        # prompt_tokens_details.cached_tokens; no cache-creation counter).
        details = getattr(usage, "prompt_tokens_details", None)
        cached = getattr(details, "cached_tokens", None) if details else None
        if cached is not None:
            span.set_attribute("gen_ai.usage.cache_read.input_tokens", int(cached))
        # v1.41 reasoning tokens (o-series); nested under completion_tokens_details.
        c_details = getattr(usage, "completion_tokens_details", None)
        reasoning = getattr(c_details, "reasoning_tokens", None) if c_details else None
        if reasoning is not None:
            span.set_attribute("gen_ai.usage.reasoning.output_tokens", int(reasoning))

    choices = getattr(result, "choices", None) or []
    if choices:
        first = choices[0]
        finish_reason = getattr(first, "finish_reason", None)
        if finish_reason:
            span.set_attribute("gen_ai.response.finish_reason", finish_reason)

    model = getattr(result, "model", None)
    if model:
        span.set_attribute("gen_ai.response.model", model)


# Alias for symmetry with async usage patterns
instrument_openai_async = instrument_openai

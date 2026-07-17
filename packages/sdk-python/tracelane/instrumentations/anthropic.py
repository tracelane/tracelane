"""Anthropic SDK instrumentation for Tracelane.

Wraps anthropic.Anthropic.messages.create using wrapt to emit OTel spans
for every Messages API call. Never reads or logs the API key.

Example::

    import anthropic
    from tracelane.instrumentations.anthropic import instrument_anthropic

    client = anthropic.Anthropic()
    instrument_anthropic(client)
    # All client.messages.create() calls now emit spans
"""

from __future__ import annotations

import functools
from typing import Any

import wrapt
from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.anthropic", "0.1.0")


def _set_usage_attributes(span: Any, result: Any) -> None:
    """Emit OTel GenAI v1.41 token-usage attributes from an Anthropic response.

    Includes the v1.40 prompt-cache counters (``cache_read.input_tokens`` /
    ``cache_creation.input_tokens``) when the response exposes them. Each
    attribute is set only when present, mirroring the request-side guards.
    Never raises — token accounting must not break the caller's response.
    """
    usage = getattr(result, "usage", None)
    if usage is None:
        return
    input_tokens = getattr(usage, "input_tokens", None)
    if input_tokens is not None:
        span.set_attribute("gen_ai.usage.input_tokens", int(input_tokens))
    output_tokens = getattr(usage, "output_tokens", None)
    if output_tokens is not None:
        span.set_attribute("gen_ai.usage.output_tokens", int(output_tokens))
    cache_read = getattr(usage, "cache_read_input_tokens", None)
    if cache_read is not None:
        span.set_attribute("gen_ai.usage.cache_read.input_tokens", int(cache_read))
    cache_creation = getattr(usage, "cache_creation_input_tokens", None)
    if cache_creation is not None:
        span.set_attribute("gen_ai.usage.cache_creation.input_tokens", int(cache_creation))


def instrument_anthropic(client: Any) -> None:
    """Wrap an Anthropic client instance to emit OTel spans.

    Args:
        client: An anthropic.Anthropic (or AsyncAnthropic) instance.

    Note:
        This function mutates the client in-place using wrapt.
        The original create method is preserved and called as-is.
        API keys are never captured — only model/token metadata.
    """
    original_create = client.messages.create

    @functools.wraps(original_create)
    def patched_create(*args: Any, **kwargs: Any) -> Any:
        model = kwargs.get("model", args[0] if args else "unknown")
        max_tokens = kwargs.get("max_tokens", 0)

        with _tracer.start_as_current_span(
            "anthropic.messages.create",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "anthropic",
                "gen_ai.request.model": str(model),
                "llm.model_name": str(model),
                "gen_ai.request.max_tokens": int(max_tokens),
            },
        ) as span:
            try:
                result = original_create(*args, **kwargs)
                _set_usage_attributes(span, result)
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    # Use wrapt for proper descriptor protocol support
    wrapt.wrap_function_wrapper(
        client.messages,
        "create",
        lambda wrapped, instance, args, kwargs: patched_create(*args, **kwargs),
    )

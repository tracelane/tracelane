"""OpenRouter instrumentation for Tracelane.

OpenRouter exposes an OpenAI-compatible API at https://openrouter.ai/api/v1.
This adapter wraps an OpenAI client that has been pointed at OpenRouter,
overriding the gen_ai.provider.name attribute to "openrouter" and capturing the
resolved model from the response (OpenRouter may reroute to a different
provider model than requested).

Example::

    import openai
    from tracelane.instrumentations.openrouter import instrument_openrouter

    client = openai.OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=os.environ["OPENROUTER_API_KEY"],
    )
    instrument_openrouter(client)
    # chat.completions.create() calls now emit OpenRouter-tagged spans
"""

from __future__ import annotations

import inspect
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.openrouter", "0.1.0")


def instrument_openrouter(client: Any) -> None:
    """Wrap an OpenAI client pointed at OpenRouter to emit OTel spans.

    Args:
        client: An openai.OpenAI or openai.AsyncOpenAI instance with
                base_url set to https://openrouter.ai/api/v1.

    Note:
        Captures openrouter.route from the response model field, which
        reflects the actual provider model selected by OpenRouter's router.
    """
    original_create = client.chat.completions.create

    if inspect.iscoroutinefunction(original_create):

        async def _async_create(*args: Any, **kwargs: Any) -> Any:
            model = kwargs.get("model", "unknown")
            with _tracer.start_as_current_span(
                "openrouter.chat.completions.create",
                kind=SpanKind.CLIENT,
                attributes={
                    "gen_ai.provider.name": "openrouter",
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
                "openrouter.chat.completions.create",
                kind=SpanKind.CLIENT,
                attributes={
                    "gen_ai.provider.name": "openrouter",
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
    usage = getattr(result, "usage", None)
    if usage:
        prompt = getattr(usage, "prompt_tokens", 0) or 0
        completion = getattr(usage, "completion_tokens", 0) or 0
        span.set_attribute("gen_ai.usage.input_tokens", prompt)
        span.set_attribute("gen_ai.usage.output_tokens", completion)
        span.set_attribute("llm.token_count.prompt", prompt)
        span.set_attribute("llm.token_count.completion", completion)

    # OpenRouter returns the actual routed model in response.model
    routed_model = getattr(result, "model", None)
    if routed_model:
        span.set_attribute("gen_ai.response.model", routed_model)
        span.set_attribute("openrouter.route", routed_model)

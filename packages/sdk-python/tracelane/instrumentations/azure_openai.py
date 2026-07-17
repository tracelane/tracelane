"""Azure OpenAI instrumentation for Tracelane.

Wraps openai.AzureOpenAI (and AsyncAzureOpenAI) chat.completions.create to
emit OTel spans for every chat completion request routed through Azure OpenAI
Service. Shares the same attribute schema as the OpenAI adapter and adds the
Azure deployment name when provided. Never captures API keys, Azure endpoints,
or message content.

Example::

    import openai
    from tracelane.instrumentations.azure_openai import instrument_azure_openai

    client = openai.AzureOpenAI(
        azure_endpoint="https://my-resource.openai.azure.com/",
        api_version="2024-02-01",
    )
    instrument_azure_openai(client)
    # All client.chat.completions.create() calls now emit spans
"""

from __future__ import annotations

import inspect
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.azure_openai", "0.1.0")


def instrument_azure_openai(client: Any) -> None:
    """Wrap an AzureOpenAI client instance to emit OTel spans.

    Works with both openai.AzureOpenAI (sync) and openai.AsyncAzureOpenAI
    (async). The async path is detected by inspecting the original method.
    Azure deployment name is captured when passed as the ``model`` or
    ``azure_deployment`` kwarg.

    Args:
        client: An openai.AzureOpenAI or openai.AsyncAzureOpenAI instance.

    Note:
        Mutates the client in-place. Azure API keys and endpoint URLs are
        never captured — only deployment name, token counts, and finish reason.
    """
    original_create = client.chat.completions.create

    if inspect.iscoroutinefunction(original_create):

        async def _async_create(*args: Any, **kwargs: Any) -> Any:
            deployment, model = _extract_deployment(kwargs, args)
            with _tracer.start_as_current_span(
                "azure_openai.chat.completions.create",
                kind=SpanKind.CLIENT,
                attributes=_base_attrs(deployment, model),
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
            deployment, model = _extract_deployment(kwargs, args)
            with _tracer.start_as_current_span(
                "azure_openai.chat.completions.create",
                kind=SpanKind.CLIENT,
                attributes=_base_attrs(deployment, model),
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


def _extract_deployment(kwargs: dict[str, Any], args: tuple[Any, ...]) -> tuple[str, str]:
    """Return (azure_deployment, model) from kwargs, falling back to 'unknown'."""
    # azure_deployment takes precedence if callers pass it explicitly
    deployment: str = str(kwargs.get("azure_deployment") or "")
    model: str = str(kwargs.get("model") or (args[0] if args else "") or "")
    if not deployment:
        deployment = model or "unknown"
    if not model:
        model = deployment
    return deployment or "unknown", model or "unknown"


def _base_attrs(deployment: str, model: str) -> dict[str, Any]:
    return {
        "gen_ai.provider.name": "azure_openai",
        "gen_ai.request.model": model,
        "llm.model_name": model,
        "azure_openai.deployment": deployment,
    }


def _record_response(span: Any, result: Any) -> None:
    """Extract token usage and finish reason from an Azure OpenAI response."""
    usage = getattr(result, "usage", None)
    if usage:
        prompt_tokens = getattr(usage, "prompt_tokens", 0) or 0
        completion_tokens = getattr(usage, "completion_tokens", 0) or 0
        if prompt_tokens:
            span.set_attribute("gen_ai.usage.input_tokens", prompt_tokens)
        if completion_tokens:
            span.set_attribute("gen_ai.usage.output_tokens", completion_tokens)

    choices = getattr(result, "choices", None) or []
    if choices:
        finish_reason = getattr(choices[0], "finish_reason", None)
        if finish_reason:
            span.set_attribute("gen_ai.response.finish_reason", finish_reason)

    response_model = getattr(result, "model", None)
    if response_model:
        span.set_attribute("gen_ai.response.model", response_model)

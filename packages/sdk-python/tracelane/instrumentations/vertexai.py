"""Google Vertex AI instrumentation for Tracelane.

Wraps vertexai.generative_models.GenerativeModel.generate_content and its async
counterpart generate_content_async to emit OTel spans for every Gemini model
call made through the Vertex AI SDK. Captures model name, token counts from
usage_metadata, and HTTP finish reason. Never captures prompt text, service
account credentials, or raw model output.

Example::

    import vertexai
    from vertexai.generative_models import GenerativeModel
    from tracelane.instrumentations.vertexai import instrument_vertexai

    vertexai.init(project="my-project", location="us-central1")
    model = GenerativeModel("gemini-1.5-pro")
    instrument_vertexai(model)
    response = model.generate_content("Explain recursion.")
    # span emitted for vertex_ai.generate_content
"""

from __future__ import annotations

from typing import Any

import wrapt
from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.vertexai", "0.1.0")


def instrument_vertexai(model: Any) -> None:
    """Wrap a Vertex AI GenerativeModel instance to emit OTel spans.

    Instruments generate_content() (sync) and generate_content_async() (async).
    Token counts are read from response.usage_metadata which is populated by the
    Vertex AI SDK for Gemini models.

    Args:
        model: A vertexai.generative_models.GenerativeModel instance.

    Note:
        Mutates the model in-place using wrapt. GCP service account keys and
        project IDs are never captured in span attributes.
    """
    model_name = _model_name(model)
    _patch_generate_content(model, model_name)
    _patch_generate_content_async(model, model_name)


def _model_name(model: Any) -> str:
    """Extract the Gemini model name from the GenerativeModel object."""
    # Internal attribute name as of vertexai SDK 1.x
    for attr in ("_model_name", "model_name", "_model_id", "model"):
        val = getattr(model, attr, None)
        if isinstance(val, str) and val:
            # Strip any resource path prefix, keep only the model name segment
            return val.split("/")[-1] if "/" in val else val
    return "unknown"


def _record_usage(span: Any, response: Any) -> None:
    """Extract token counts from a Vertex AI GenerateContentResponse."""
    usage = getattr(response, "usage_metadata", None)
    if usage is None:
        return
    pt = getattr(usage, "prompt_token_count", None)
    ct = getattr(usage, "candidates_token_count", None)
    if pt is not None:
        span.set_attribute("gen_ai.usage.input_tokens", int(pt))
    if ct is not None:
        span.set_attribute("gen_ai.usage.output_tokens", int(ct))

    # Finish reason from first candidate
    candidates = getattr(response, "candidates", None) or []
    if candidates:
        finish = getattr(candidates[0], "finish_reason", None)
        if finish is not None:
            span.set_attribute("gen_ai.response.finish_reason", str(finish))


def _patch_generate_content(model: Any, model_name: str) -> None:
    if not hasattr(model, "generate_content"):
        return

    def _patched(wrapped: Any, instance: Any, args: Any, kwargs: Any) -> Any:
        with _tracer.start_as_current_span(
            "vertex_ai.generate_content",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "vertex_ai",
                "gen_ai.request.model": model_name,
                "llm.model_name": model_name,
            },
        ) as span:
            try:
                result = wrapped(*args, **kwargs)
                _record_usage(span, result)
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    wrapt.wrap_function_wrapper(model, "generate_content", _patched)


def _patch_generate_content_async(model: Any, model_name: str) -> None:
    if not hasattr(model, "generate_content_async"):
        return
    original = model.generate_content_async

    async def _patched_async(*args: Any, **kwargs: Any) -> Any:
        with _tracer.start_as_current_span(
            "vertex_ai.generate_content_async",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "vertex_ai",
                "gen_ai.request.model": model_name,
                "llm.model_name": model_name,
            },
        ) as span:
            try:
                result = await original(*args, **kwargs)
                _record_usage(span, result)
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    model.generate_content_async = _patched_async

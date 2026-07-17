"""LlamaIndex SDK instrumentation for Tracelane.

Wraps BaseLLM.complete, BaseLLM.chat, and their async counterparts (acomplete,
achat) to emit OTel spans for every LLM call made through a LlamaIndex LLM
instance. Captures model name, token counts, and latency. Never captures
prompt text, API keys, or raw response content.

Example::

    from llama_index.llms.openai import OpenAI
    from tracelane.instrumentations.llamaindex import instrument_llamaindex

    llm = OpenAI(model="gpt-4o")
    instrument_llamaindex(llm)
    # All llm.complete() and llm.chat() calls now emit spans
"""

from __future__ import annotations

from typing import Any

import wrapt
from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.llamaindex", "0.1.0")


def instrument_llamaindex(client: Any) -> None:
    """Wrap a LlamaIndex BaseLLM instance to emit OTel spans.

    Instruments complete(), acomplete(), chat(), and achat(). The async paths
    are patched unconditionally; if the LLM does not implement them the patch
    is a no-op.

    Args:
        client: A llama_index.core.llms.BaseLLM instance (OpenAI, Anthropic, etc.).

    Note:
        Mutates the client in-place. Token counts are read from CompletionResponse
        or ChatResponse raw metadata. API keys are never captured.
    """
    model = _model_name(client)
    _patch_complete(client, model)
    _patch_acomplete(client, model)
    _patch_chat(client, model)
    _patch_achat(client, model)


def _model_name(client: Any) -> str:
    for attr in ("model", "model_name", "model_id"):
        val = getattr(client, attr, None)
        if isinstance(val, str) and val:
            return val
    return "unknown"


def _record_usage(span: Any, response: Any) -> None:
    """Extract token counts from a CompletionResponse or ChatResponse."""
    # LlamaIndex stores raw provider response in .raw
    raw = getattr(response, "raw", None) or {}
    if isinstance(raw, dict):
        usage = raw.get("usage") or {}
        if isinstance(usage, dict):
            pt = usage.get("prompt_tokens") or usage.get("input_tokens") or 0
            ct = usage.get("completion_tokens") or usage.get("output_tokens") or 0
            if pt:
                span.set_attribute("gen_ai.usage.input_tokens", int(pt))
            if ct:
                span.set_attribute("gen_ai.usage.output_tokens", int(ct))

    # Some adapters surface additional_kwargs on the response object
    addl = getattr(response, "additional_kwargs", None) or {}
    if isinstance(addl, dict) and "usage" in addl:
        usage2 = addl["usage"] or {}
        pt2 = usage2.get("prompt_tokens") or usage2.get("input_tokens") or 0
        ct2 = usage2.get("completion_tokens") or usage2.get("output_tokens") or 0
        if pt2:
            span.set_attribute("gen_ai.usage.input_tokens", int(pt2))
        if ct2:
            span.set_attribute("gen_ai.usage.output_tokens", int(ct2))


def _patch_complete(client: Any, model: str) -> None:
    if not hasattr(client, "complete"):
        return
    original = client.complete

    def _patched(*args: Any, **kwargs: Any) -> Any:
        with _tracer.start_as_current_span(
            "llamaindex.llm.complete",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "llamaindex",
                "gen_ai.request.model": model,
                "llm.model_name": model,
            },
        ) as span:
            try:
                result = original(*args, **kwargs)
                _record_usage(span, result)
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    wrapt.wrap_function_wrapper(client, "complete", lambda w, i, a, k: _patched(*a, **k))


def _patch_acomplete(client: Any, model: str) -> None:
    if not hasattr(client, "acomplete"):
        return
    original = client.acomplete

    async def _patched(*args: Any, **kwargs: Any) -> Any:
        with _tracer.start_as_current_span(
            "llamaindex.llm.acomplete",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "llamaindex",
                "gen_ai.request.model": model,
                "llm.model_name": model,
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

    client.acomplete = _patched


def _patch_chat(client: Any, model: str) -> None:
    if not hasattr(client, "chat"):
        return
    original = client.chat

    def _patched(*args: Any, **kwargs: Any) -> Any:
        with _tracer.start_as_current_span(
            "llamaindex.llm.chat",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "llamaindex",
                "gen_ai.request.model": model,
                "llm.model_name": model,
            },
        ) as span:
            try:
                result = original(*args, **kwargs)
                _record_usage(span, result)
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    wrapt.wrap_function_wrapper(client, "chat", lambda w, i, a, k: _patched(*a, **k))


def _patch_achat(client: Any, model: str) -> None:
    if not hasattr(client, "achat"):
        return
    original = client.achat

    async def _patched(*args: Any, **kwargs: Any) -> Any:
        with _tracer.start_as_current_span(
            "llamaindex.llm.achat",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "llamaindex",
                "gen_ai.request.model": model,
                "llm.model_name": model,
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

    client.achat = _patched

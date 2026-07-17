"""LangChain SDK instrumentation for Tracelane.

Wraps BaseChatModel.invoke and BaseChatModel.__call__ using wrapt to emit
OTel spans for every LLM invocation inside a LangChain chain or standalone
chat-model call. Captures model name, token counts, and latency. Never
captures API keys, prompt content, or raw message objects.

Example::

    from langchain_openai import ChatOpenAI
    from tracelane.instrumentations.langchain import instrument_langchain

    model = ChatOpenAI(model="gpt-4o")
    instrument_langchain(model)
    # All model.invoke() and model() calls now emit spans
"""

from __future__ import annotations

import inspect
from typing import Any

import wrapt
from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.langchain", "0.1.0")


def instrument_langchain(client: Any) -> None:
    """Wrap a LangChain BaseChatModel (or LLMChain) instance to emit OTel spans.

    Instruments both the synchronous invoke() and the legacy __call__() entry
    points. If the model exposes ainvoke(), that is patched too so async chains
    are covered without a second call.

    Args:
        client: A langchain_core.language_models.BaseChatModel or LLMChain instance.

    Note:
        Mutates the client in-place. Token counts are read from AIMessage.response_metadata
        or the llm_output dict, whichever is present. API keys are never captured.
    """
    _patch_invoke(client)
    _patch_ainvoke(client)
    _patch_call(client)


def _model_name(client: Any) -> str:
    """Best-effort extraction of the model identifier from a LangChain model."""
    # ChatOpenAI / ChatAnthropic etc. expose .model_name or .model
    for attr in ("model_name", "model", "model_id"):
        val = getattr(client, attr, None)
        if isinstance(val, str) and val:
            return val
    return "unknown"


def _record_langchain_response(span: Any, result: Any) -> None:
    """Extract token usage from an AIMessage or LLMResult."""
    # AIMessage path (BaseChatModel.invoke returns AIMessage)
    meta = getattr(result, "response_metadata", None) or {}
    usage = meta.get("token_usage") or meta.get("usage") or {}
    if isinstance(usage, dict):
        prompt = usage.get("prompt_tokens") or usage.get("input_tokens") or 0
        completion = usage.get("completion_tokens") or usage.get("output_tokens") or 0
        if prompt:
            span.set_attribute("gen_ai.usage.input_tokens", int(prompt))
        if completion:
            span.set_attribute("gen_ai.usage.output_tokens", int(completion))

    # LLMResult path (generate / __call__ returns LLMResult)
    llm_output = getattr(result, "llm_output", None) or {}
    if isinstance(llm_output, dict):
        usage2 = llm_output.get("token_usage") or {}
        if isinstance(usage2, dict):
            p = usage2.get("prompt_tokens", 0) or 0
            c = usage2.get("completion_tokens", 0) or 0
            if p:
                span.set_attribute("gen_ai.usage.input_tokens", int(p))
            if c:
                span.set_attribute("gen_ai.usage.output_tokens", int(c))


def _patch_invoke(client: Any) -> None:
    if not hasattr(client, "invoke"):
        return
    original = client.invoke

    if inspect.iscoroutinefunction(original):
        return  # handled by _patch_ainvoke

    model = _model_name(client)

    def _patched_invoke(*args: Any, **kwargs: Any) -> Any:
        with _tracer.start_as_current_span(
            "langchain.chat.invoke",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "langchain",
                "gen_ai.request.model": model,
                "llm.model_name": model,
            },
        ) as span:
            try:
                result = original(*args, **kwargs)
                _record_langchain_response(span, result)
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    wrapt.wrap_function_wrapper(client, "invoke", lambda w, i, a, k: _patched_invoke(*a, **k))


def _patch_ainvoke(client: Any) -> None:
    if not hasattr(client, "ainvoke"):
        return
    original = client.ainvoke
    model = _model_name(client)

    async def _patched_ainvoke(*args: Any, **kwargs: Any) -> Any:
        with _tracer.start_as_current_span(
            "langchain.chat.ainvoke",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "langchain",
                "gen_ai.request.model": model,
                "llm.model_name": model,
            },
        ) as span:
            try:
                result = await original(*args, **kwargs)
                _record_langchain_response(span, result)
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    client.ainvoke = _patched_ainvoke


def _patch_call(client: Any) -> None:
    """Patch the legacy __call__ path used by LLMChain and older BaseLLM."""
    if not callable(client):
        return
    # Only patch if __call__ is a plain method, not the default object __call__
    # LangChain models define __call__ explicitly; we check for it on the class.
    cls = type(client)
    if "__call__" not in cls.__dict__:
        return
    original_call = client.__call__
    model = _model_name(client)

    def _patched_call(*args: Any, **kwargs: Any) -> Any:
        with _tracer.start_as_current_span(
            "langchain.chat.call",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "langchain",
                "gen_ai.request.model": model,
                "llm.model_name": model,
            },
        ) as span:
            try:
                result = original_call(*args, **kwargs)
                _record_langchain_response(span, result)
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    wrapt.wrap_function_wrapper(client, "__call__", lambda w, i, a, k: _patched_call(*a, **k))

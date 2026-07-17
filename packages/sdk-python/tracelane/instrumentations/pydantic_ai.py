"""Pydantic AI instrumentation for Tracelane.

Wraps pydantic_ai.Agent.run and Agent.run_sync to emit OTel spans for every
agent invocation. Captures model name, run kind, and token usage from the
RunResult. Never captures user prompt text, API keys, or raw model output.

Example::

    from pydantic_ai import Agent
    from tracelane.instrumentations.pydantic_ai import instrument_pydantic_ai

    agent = Agent("openai:gpt-4o", system_prompt="Be helpful.")
    instrument_pydantic_ai(agent)
    result = await agent.run("What is 2+2?")
    # span emitted for pydantic_ai.run
"""

from __future__ import annotations

from typing import Any

import wrapt
from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.pydantic_ai", "0.1.0")


def instrument_pydantic_ai(agent: Any) -> None:
    """Wrap a pydantic_ai.Agent instance to emit OTel spans.

    Instruments both the async run() and the sync run_sync() entry points.
    Token usage is extracted from RunResult.usage() if available.

    Args:
        agent: A pydantic_ai.Agent instance.

    Note:
        Mutates the agent in-place. User prompts and model replies are never
        captured in span attributes. Only structural metadata (model name,
        token counts, success/failure) is recorded.
    """
    model_name = _extract_model_name(agent)
    _patch_run(agent, model_name)
    _patch_run_sync(agent, model_name)


def _extract_model_name(agent: Any) -> str:
    """Resolve the model identifier from various agent attribute shapes."""
    # pydantic_ai.Agent stores model as a string or a Model object
    model = getattr(agent, "model", None)
    if isinstance(model, str):
        return model
    if model is not None:
        # Model object — try .model_name or str()
        name = getattr(model, "model_name", None) or getattr(model, "name", None)
        if isinstance(name, str) and name:
            return name
        return str(model)
    return "unknown"


def _record_usage(span: Any, result: Any) -> None:
    """Extract token counts from a pydantic_ai RunResult."""
    # RunResult.usage() returns a Usage dataclass with request_tokens / response_tokens
    try:
        usage = result.usage()
        if usage is not None:
            req = getattr(usage, "request_tokens", None)
            resp = getattr(usage, "response_tokens", None)
            if req is not None:
                span.set_attribute("gen_ai.usage.input_tokens", int(req))
            if resp is not None:
                span.set_attribute("gen_ai.usage.output_tokens", int(resp))
    except Exception:  # noqa: BLE001
        pass


def _patch_run(agent: Any, model_name: str) -> None:
    if not hasattr(agent, "run"):
        return
    original = agent.run

    async def _patched_run(*args: Any, **kwargs: Any) -> Any:
        with _tracer.start_as_current_span(
            "pydantic_ai.run",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "pydantic_ai",
                "gen_ai.request.model": model_name,
                "llm.model_name": model_name,
                "pydantic_ai.run_kind": "async",
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

    agent.run = _patched_run


def _patch_run_sync(agent: Any, model_name: str) -> None:
    if not hasattr(agent, "run_sync"):
        return

    def _patched_run_sync(wrapped: Any, instance: Any, args: Any, kwargs: Any) -> Any:
        with _tracer.start_as_current_span(
            "pydantic_ai.run",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "pydantic_ai",
                "gen_ai.request.model": model_name,
                "llm.model_name": model_name,
                "pydantic_ai.run_kind": "sync",
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

    wrapt.wrap_function_wrapper(agent, "run_sync", _patched_run_sync)

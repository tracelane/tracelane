"""smolagents instrumentation for Tracelane.

Wraps CodeAgent.run (and ToolCallingAgent.run) to emit OTel spans for every
synchronous agent task execution. The model identifier is extracted from the
agent's model attribute without capturing any user-supplied prompt text or
raw model output.

Example::

    from smolagents import CodeAgent, HfApiModel
    from tracelane.instrumentations.smolagents import instrument_smolagents

    model = HfApiModel("meta-llama/Meta-Llama-3.1-70B-Instruct")
    agent = CodeAgent(tools=[], model=model)
    instrument_smolagents(agent)
    result = agent.run("What is 2+2?")
"""

from __future__ import annotations

from typing import Any

import wrapt
from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.smolagents", "0.1.0")


def instrument_smolagents(agent: Any) -> None:
    """Wrap a smolagents CodeAgent or ToolCallingAgent instance to emit OTel spans.

    Instruments the synchronous run() entry point using wrapt so the original
    function signature is preserved. The model identifier is resolved from the
    agent's model attribute at instrumentation time.

    Args:
        agent: A smolagents.CodeAgent or smolagents.ToolCallingAgent instance.

    Note:
        Mutates the agent in-place using wrapt. Task prompts and agent outputs
        are never captured — only the model identifier and run outcome.
    """
    model_name = _extract_model_name(agent)
    _patch_run(agent, model_name)


def _extract_model_name(agent: Any) -> str:
    """Resolve the model identifier from a smolagents agent instance."""
    model = getattr(agent, "model", None)
    if model is None:
        return "unknown"
    model_id = getattr(model, "model_id", None)
    if isinstance(model_id, str) and model_id:
        return model_id
    return str(model)


def _patch_run(agent: Any, model_name: str) -> None:
    """Patch agent.run with a wrapt wrapper that emits a smolagents.run span."""
    if not hasattr(agent, "run"):
        return

    def _patched_run(wrapped: Any, instance: Any, args: Any, kwargs: Any) -> Any:
        with _tracer.start_as_current_span(
            "smolagents.run",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "smolagents",
                "gen_ai.request.model": model_name,
            },
        ) as span:
            try:
                result = wrapped(*args, **kwargs)
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    wrapt.wrap_function_wrapper(agent, "run", _patched_run)

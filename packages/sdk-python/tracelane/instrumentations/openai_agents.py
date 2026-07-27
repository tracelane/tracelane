"""OpenAI Agents SDK instrumentation for Tracelane.

Wraps the openai.agents Runner class to emit OTel spans for every agent
run. Captures agent name, final output length, and run metadata.
The OpenAI Agents SDK (formerly Swarm) is a common agent runtime; this
adapter instruments it without capturing keys or message content.

Example::

    from openai.agents import Agent, Runner
    from tracelane.instrumentations.openai_agents import instrument_openai_agents

    instrument_openai_agents(Runner)
    agent = Agent(name="my-agent", instructions="...")
    result = await Runner.run(agent, "hello")
    # Span emitted for the full agent run
"""

from __future__ import annotations

from typing import Any

from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.openai-agents", "0.1.0")


def instrument_openai_agents(runner_cls: Any) -> None:
    """Instrument the OpenAI Agents Runner class to emit OTel spans.

    Patches both Runner.run (async) and Runner.run_sync (sync) class methods.

    Args:
        runner_cls: The openai.agents.Runner class (not an instance).

    Note:
        The agent name (agent.name) is captured as ai.agent.name.
        Handoff chains are tracked via ai.agent.handoff_count.
    """
    _patch_run(runner_cls)
    _patch_run_sync(runner_cls)


def _patch_run(runner_cls: Any) -> None:
    if not hasattr(runner_cls, "run"):
        return
    original = runner_cls.run

    async def _patched_run(agent: Any, input: Any, *args: Any, **kwargs: Any) -> Any:
        agent_name = getattr(agent, "name", "unknown")
        with _tracer.start_as_current_span(
            "openai_agents.runner.run",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "openai-agents",
                "ai.agent.name": agent_name,
                "openai_agents.input_length": len(str(input)) if input else 0,
            },
        ) as span:
            try:
                result = await original(agent, input, *args, **kwargs)
                _record_result(span, result)
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    runner_cls.run = _patched_run


def _patch_run_sync(runner_cls: Any) -> None:
    if not hasattr(runner_cls, "run_sync"):
        return
    original = runner_cls.run_sync

    def _patched_run_sync(agent: Any, input: Any, *args: Any, **kwargs: Any) -> Any:
        agent_name = getattr(agent, "name", "unknown")
        with _tracer.start_as_current_span(
            "openai_agents.runner.run_sync",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "openai-agents",
                "ai.agent.name": agent_name,
                "openai_agents.input_length": len(str(input)) if input else 0,
            },
        ) as span:
            try:
                result = original(agent, input, *args, **kwargs)
                _record_result(span, result)
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    runner_cls.run_sync = _patched_run_sync


def _record_result(span: Any, result: Any) -> None:
    final_output = getattr(result, "final_output", None)
    if final_output is not None:
        span.set_attribute("openai_agents.output_length", len(str(final_output)))
    messages = getattr(result, "messages", None) or getattr(result, "new_messages", None)
    if isinstance(messages, list):
        span.set_attribute("openai_agents.messages_count", len(messages))
    # Handoff chains: RunResult.next_agent or multi-turn results
    next_agent = getattr(result, "next_agent", None)
    if next_agent is not None:
        span.set_attribute("ai.agent.handoff_count", 1)
        next_name = getattr(next_agent, "name", "unknown")
        span.set_attribute("ai.agent.handoff_target", next_name)

"""CrewAI instrumentation for Tracelane.

Wraps CrewAI Agent.execute_task to emit OTel spans for every task execution
within a crew. Each span carries the agent's role and the task description
identifier so Tracelane can reconstruct multi-agent collaboration traces.
Never captures tool arguments, API keys, or raw LLM output text.

Example::

    from crewai import Agent, Task
    from tracelane.instrumentations.crewai import instrument_crewai

    researcher = Agent(role="Researcher", goal="...", backstory="...")
    instrument_crewai(researcher)
    # researcher.execute_task() calls now emit crewai.task spans
"""

from __future__ import annotations

from typing import Any

import wrapt
from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.crewai", "0.1.0")


def instrument_crewai(agent: Any) -> None:
    """Wrap a CrewAI Agent instance to emit OTel spans per task execution.

    Instruments execute_task() which is the central dispatch point called by
    the Crew orchestrator for each agent step. Adds crewai.agent.role and a
    task description excerpt to every span.

    Args:
        agent: A crewai.Agent instance.

    Note:
        Mutates the agent in-place using wrapt. Tool call details and raw
        LLM responses are never captured — only execution metadata.
    """
    _patch_execute_task(agent)


def _patch_execute_task(agent: Any) -> None:
    if not hasattr(agent, "execute_task"):
        return

    role: str = getattr(agent, "role", "unknown") or "unknown"

    def _patched_execute_task(wrapped: Any, instance: Any, args: Any, kwargs: Any) -> Any:
        # First positional arg is the Task object; extract description safely
        task_obj = args[0] if args else kwargs.get("task")
        task_desc: str = "unknown"
        if task_obj is not None:
            raw_desc = getattr(task_obj, "description", None) or str(task_obj)
            # Truncate to avoid large span attributes
            task_desc = raw_desc[:120] if isinstance(raw_desc, str) else "unknown"

        with _tracer.start_as_current_span(
            "crewai.task",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "crewai",
                "crewai.agent.role": role,
                "crewai.task.description": task_desc,
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

    wrapt.wrap_function_wrapper(agent, "execute_task", _patched_execute_task)

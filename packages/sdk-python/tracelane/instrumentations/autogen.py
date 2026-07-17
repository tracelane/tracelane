"""AutoGen instrumentation for Tracelane.

Wraps ConversableAgent.generate_reply to emit OTel spans for every LLM
reply generation step in an AutoGen multi-agent conversation. Captures
agent name, sender name, and message count. Never captures message content,
API keys, or reply text.

Example::

    import autogen
    from tracelane.instrumentations.autogen import instrument_autogen

    assistant = autogen.AssistantAgent(name="assistant", llm_config={...})
    instrument_autogen(assistant)
    # assistant.generate_reply() calls now emit autogen.generate_reply spans
"""

from __future__ import annotations

from typing import Any

import wrapt
from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.autogen", "0.1.0")


def instrument_autogen(agent: Any) -> None:
    """Wrap an AutoGen ConversableAgent instance to emit OTel spans.

    Instruments generate_reply(), which is the primary method called when an
    agent must produce a reply given a conversation history. The span records
    the agent name and the count of messages passed to it.

    Args:
        agent: A autogen.ConversableAgent (or subclass) instance.

    Note:
        Mutates the agent in-place using wrapt. Message content and API keys
        are never captured — only structural metadata (agent names, counts).
    """
    _patch_generate_reply(agent)


def _patch_generate_reply(agent: Any) -> None:
    if not hasattr(agent, "generate_reply"):
        return

    agent_name: str = getattr(agent, "name", "unknown") or "unknown"

    def _patched_generate_reply(wrapped: Any, instance: Any, args: Any, kwargs: Any) -> Any:
        # generate_reply(messages=None, sender=None, ...)
        messages = kwargs.get("messages") or (args[0] if args else None)
        sender = kwargs.get("sender") or (args[1] if len(args) > 1 else None)

        message_count = len(messages) if isinstance(messages, list) else 0
        sender_name: str = getattr(sender, "name", "unknown") or "unknown"

        with _tracer.start_as_current_span(
            "autogen.generate_reply",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "autogen",
                "autogen.agent.name": agent_name,
                "autogen.sender.name": sender_name,
                "autogen.messages.count": message_count,
            },
        ) as span:
            try:
                result = wrapped(*args, **kwargs)
                # A non-None reply means the agent produced output
                span.set_attribute("autogen.reply.produced", result is not None)
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    wrapt.wrap_function_wrapper(agent, "generate_reply", _patched_generate_reply)

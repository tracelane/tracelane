"""Letta instrumentation for Tracelane.

Wraps Letta (formerly MemGPT) client's agent creation and message-sending
methods to emit OTel spans. Letta's tiered/archival memory model makes memory
observability a first-class concern — instrumenting it now provides the
groundwork for memory performance and coherence tracking.

Example::

    from letta import create_client
    from tracelane.instrumentations.letta import instrument_letta

    client = create_client()
    instrument_letta(client)
    agent = client.create_agent(name="my-agent")
    response = client.send_message(agent_id=agent.id, message="hello", role="user")
    # Spans emitted with letta.agent_id and message metadata
"""

from __future__ import annotations

from typing import Any

from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.letta", "0.1.0")


def instrument_letta(client: Any) -> None:
    """Wrap a Letta client instance to emit OTel spans.

    Instruments create_agent(), send_message(), and user_message().

    Args:
        client: A letta.client.LocalClient or letta.client.RESTClient instance.

    Note:
        Message content is never captured. Agent ID, message count,
        and response token usage (if available) are recorded.
    """
    if hasattr(client, "create_agent"):
        _patch_create_agent(client)
    if hasattr(client, "send_message"):
        _patch_send_message(client)
    if hasattr(client, "user_message"):
        _patch_user_message(client)


def _patch_create_agent(client: Any) -> None:
    original = client.create_agent

    def _patched(*args: Any, **kwargs: Any) -> Any:
        agent_name = kwargs.get("name", "unnamed")
        with _tracer.start_as_current_span(
            "letta.client.create_agent",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "letta",
                "letta.operation": "create_agent",
                "letta.agent_name": str(agent_name),
            },
        ) as span:
            try:
                result = original(*args, **kwargs)
                agent_id = getattr(result, "id", None)
                if agent_id:
                    span.set_attribute("letta.agent_id", str(agent_id))
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    client.create_agent = _patched


def _patch_send_message(client: Any) -> None:
    original = client.send_message

    def _patched(*args: Any, **kwargs: Any) -> Any:
        agent_id = kwargs.get("agent_id", args[0] if args else "unknown")
        role = kwargs.get("role", "user")
        with _tracer.start_as_current_span(
            "letta.client.send_message",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "letta",
                "letta.operation": "send_message",
                "letta.agent_id": str(agent_id),
                "letta.role": str(role),
            },
        ) as span:
            try:
                result = original(*args, **kwargs)
                messages = getattr(result, "messages", None)
                if isinstance(messages, list):
                    span.set_attribute("letta.messages_count", len(messages))
                usage = getattr(result, "usage", None)
                if usage:
                    total = getattr(usage, "total_tokens", None)
                    if total:
                        span.set_attribute("gen_ai.usage.total_tokens", int(total))
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    client.send_message = _patched


def _patch_user_message(client: Any) -> None:
    original = client.user_message

    def _patched(*args: Any, **kwargs: Any) -> Any:
        agent_id = kwargs.get("agent_id", args[0] if args else "unknown")
        with _tracer.start_as_current_span(
            "letta.client.user_message",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "letta",
                "letta.operation": "user_message",
                "letta.agent_id": str(agent_id),
            },
        ) as span:
            try:
                result = original(*args, **kwargs)
                messages = getattr(result, "messages", None)
                if isinstance(messages, list):
                    span.set_attribute("letta.messages_count", len(messages))
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    client.user_message = _patched

"""Span-emission tests for the Anthropic instrumentation.

Negative case first per `.claude/rules/testing.md` (no key/prompt leakage),
then the streaming pass-through guard: a streamed call must be marked
``tracelane.streaming`` and warned about — never recorded as a silent
token-less span.
"""

from __future__ import annotations

from typing import Any

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from tracelane.instrumentations.anthropic import instrument_anthropic

_SECRET_KEY = "sk-ant-do-not-leak-unit-test"
_SECRET_PROMPT = "highly-confidential-prompt-body-unit-test"


class _Usage:
    input_tokens = 13
    output_tokens = 5
    cache_read_input_tokens = None
    cache_creation_input_tokens = None


class _Resp:
    model = "claude-sonnet-4-6"
    usage = _Usage()


class _Messages:
    def create(self, *args: Any, **kwargs: Any) -> _Resp:
        return _Resp()


class _Client:
    def __init__(self) -> None:
        self.messages: Any = _Messages()


def _only_span(spans: InMemorySpanExporter):
    finished = spans.get_finished_spans()
    assert len(finished) == 1, f"expected exactly one span, got {len(finished)}"
    return finished[0]


def test_create_emits_span_and_never_leaks(spans: InMemorySpanExporter) -> None:
    client = _Client()
    instrument_anthropic(client)

    out = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=64,
        messages=[{"role": "user", "content": _SECRET_PROMPT}],
        api_key=_SECRET_KEY,
    )
    assert isinstance(out, _Resp)

    span = _only_span(spans)
    assert span.name == "anthropic.messages.create"
    a = span.attributes
    assert a is not None
    assert a["gen_ai.usage.input_tokens"] == 13
    assert a["gen_ai.usage.output_tokens"] == 5
    blob = repr(a)
    assert _SECRET_KEY not in blob, "API key must never reach a span attribute"
    assert _SECRET_PROMPT not in blob, "prompt content must never reach a span"


def test_streaming_call_is_marked_and_warned_never_zero(
    spans: InMemorySpanExporter, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tracelane.instrumentations import _streaming

    monkeypatch.setattr(_streaming, "_warned", False)

    class _StreamStandIn:
        """Stand-in for the Anthropic stream object — no usage attribute."""

    class _StreamingMessages:
        def create(self, *args: Any, **kwargs: Any) -> Any:
            return _StreamStandIn()

    client = _Client()
    client.messages = _StreamingMessages()
    instrument_anthropic(client)

    with pytest.warns(UserWarning, match="stream"):
        out = client.messages.create(model="claude-sonnet-4-6", max_tokens=64, stream=True)
    # The stream object passes through untouched.
    assert isinstance(out, _StreamStandIn)

    span = _only_span(spans)
    a = span.attributes
    assert a is not None
    assert a["tracelane.streaming"] is True
    # Usage attributes must be ABSENT — never a fake zero.
    assert "gen_ai.usage.input_tokens" not in a
    assert "gen_ai.usage.output_tokens" not in a

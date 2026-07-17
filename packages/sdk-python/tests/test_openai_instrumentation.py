"""Span-emission tests for the OpenAI instrumentation.

Negative case first per `.claude/rules/testing.md`: the span must NOT carry
the API key or the prompt content (Tracelane never captures either). Then the
positive assertions on the OTel-GenAI attributes.

Uses a hand-rolled fake OpenAI client so no `openai` install is required — the
adapter only touches `client.chat.completions.create`.
"""

from __future__ import annotations

import contextlib
from typing import Any

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from tracelane.instrumentations.openai import (
    instrument_openai,
    instrument_openai_async,
)

_SECRET_KEY = "sk-do-not-leak-unit-test"
_SECRET_PROMPT = "highly-confidential-prompt-body-unit-test"


class _Usage:
    prompt_tokens = 11
    completion_tokens = 7
    total_tokens = 18
    prompt_tokens_details = None
    completion_tokens_details = None


class _Choice:
    finish_reason = "stop"


class _Resp:
    model = "gpt-4o-mini-2024-07-18"
    usage = _Usage()
    choices = [_Choice()]


class _SyncCompletions:
    def create(self, *args: Any, **kwargs: Any) -> _Resp:
        return _Resp()


class _AsyncCompletions:
    async def create(self, *args: Any, **kwargs: Any) -> _Resp:
        return _Resp()


class _Chat:
    def __init__(self, completions: Any) -> None:
        self.completions = completions


class _SyncClient:
    def __init__(self) -> None:
        self.chat = _Chat(_SyncCompletions())


class _AsyncClient:
    def __init__(self) -> None:
        self.chat = _Chat(_AsyncCompletions())


def _only_span(spans: InMemorySpanExporter):
    finished = spans.get_finished_spans()
    assert len(finished) == 1, f"expected exactly one span, got {len(finished)}"
    return finished[0]


def test_sync_create_emits_genai_span(spans: InMemorySpanExporter) -> None:
    client = _SyncClient()
    instrument_openai(client)

    out = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": _SECRET_PROMPT}],
        api_key=_SECRET_KEY,
    )
    assert isinstance(out, _Resp)

    span = _only_span(spans)
    assert span.name == "openai.chat.completions.create"
    a = span.attributes
    assert a["gen_ai.provider.name"] == "openai"
    assert a["gen_ai.request.model"] == "gpt-4o-mini"
    assert a["gen_ai.usage.input_tokens"] == 11
    assert a["gen_ai.usage.output_tokens"] == 7
    assert a["gen_ai.response.finish_reason"] == "stop"
    assert a["gen_ai.response.model"] == "gpt-4o-mini-2024-07-18"


def test_span_never_leaks_key_or_prompt(spans: InMemorySpanExporter) -> None:
    client = _SyncClient()
    instrument_openai(client)
    client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": _SECRET_PROMPT}],
        api_key=_SECRET_KEY,
    )
    blob = repr(_only_span(spans).attributes)
    assert _SECRET_KEY not in blob, "API key must never reach a span attribute"
    assert _SECRET_PROMPT not in blob, "prompt content must never reach a span"


@pytest.mark.asyncio
async def test_async_create_emits_genai_span(spans: InMemorySpanExporter) -> None:
    client = _AsyncClient()
    # The alias must behave identically and detect the coroutine method.
    instrument_openai_async(client)

    out = await client.chat.completions.create(model="gpt-4o", messages=[])
    assert isinstance(out, _Resp)

    span = _only_span(spans)
    assert span.name == "openai.chat.completions.create"
    assert span.attributes["gen_ai.request.model"] == "gpt-4o"
    assert span.attributes["gen_ai.usage.output_tokens"] == 7


def test_exception_in_call_records_error_status(spans: InMemorySpanExporter) -> None:
    class _Boom:
        def create(self, *args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("upstream 500")

    client = _SyncClient()
    client.chat.completions = _Boom()
    instrument_openai(client)

    with contextlib.suppress(RuntimeError):
        client.chat.completions.create(model="gpt-4o-mini")

    span = _only_span(spans)
    # StatusCode.ERROR == 2; the span must record the failure, not swallow it.
    assert span.status.status_code.value == 2

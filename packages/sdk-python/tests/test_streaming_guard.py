"""Streaming-guard rollout tests for the OpenAI-compatible adapters
(openrouter, azure_openai, litellm). Same contract as the openai/anthropic
tests: a ``stream=True`` call passes the stream object through untouched,
marks the span ``tracelane.streaming``, and NEVER records token counts.
"""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from tracelane.instrumentations import _streaming
from tracelane.instrumentations.azure_openai import instrument_azure_openai
from tracelane.instrumentations.openrouter import instrument_openrouter


class _StreamStandIn:
    """Stand-in for a provider stream object — no usage attribute."""


def _chat_client() -> Any:
    completions = types.SimpleNamespace(
        create=lambda *a, **k: _StreamStandIn(),
    )
    return types.SimpleNamespace(chat=types.SimpleNamespace(completions=completions))


def _only_span(spans: InMemorySpanExporter):
    finished = spans.get_finished_spans()
    assert len(finished) == 1, f"expected exactly one span, got {len(finished)}"
    return finished[0]


def _assert_marked(spans: InMemorySpanExporter) -> None:
    a = _only_span(spans).attributes
    assert a is not None
    assert a["tracelane.streaming"] is True
    # Usage attributes must be ABSENT — never a fake zero.
    assert "gen_ai.usage.input_tokens" not in a
    assert "gen_ai.usage.output_tokens" not in a


@pytest.mark.parametrize(
    "instrument",
    [instrument_openrouter, instrument_azure_openai],
    ids=["openrouter", "azure_openai"],
)
def test_openai_compatible_adapters_guard_streaming(
    spans: InMemorySpanExporter,
    monkeypatch: pytest.MonkeyPatch,
    instrument: Any,
) -> None:
    monkeypatch.setattr(_streaming, "_warned", False)
    client = _chat_client()
    instrument(client)

    with pytest.warns(UserWarning, match="stream"):
        out = client.chat.completions.create(model="m", stream=True)
    assert isinstance(out, _StreamStandIn)  # passed through untouched
    _assert_marked(spans)


def test_litellm_module_patch_guards_streaming(
    spans: InMemorySpanExporter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_streaming, "_warned", False)

    async def _acompletion(*args: Any, **kwargs: Any) -> Any:
        return _StreamStandIn()

    fake = types.ModuleType("litellm")
    fake.completion = lambda *a, **k: _StreamStandIn()  # type: ignore[attr-defined]
    fake.acompletion = _acompletion  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "litellm", fake)

    from tracelane.instrumentations.litellm import instrument_litellm

    instrument_litellm()

    with pytest.warns(UserWarning, match="stream"):
        out = fake.completion(model="m", stream=True)
    assert isinstance(out, _StreamStandIn)
    _assert_marked(spans)

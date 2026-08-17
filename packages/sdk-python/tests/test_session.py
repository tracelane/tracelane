"""Session correlation — proved on the wire, not at the function boundary.

The end state this feature owes a user is: "the HTTP request my client sends to
the Tracelane gateway carries ``x-conversation-id``, so ``/sessions`` groups my
turns." So every acceptance test here drives a real ``http.server`` on loopback
and asserts on the headers that server actually received. Asserting that a helper
returned the right dict would prove nothing — the read path was already built;
only the wire was missing.

``openai`` / ``anthropic`` are optional extras and are NOT installed by CI, so the
client stand-in here reproduces the one step those SDKs take with ``extra_headers``:
merge it into the outgoing request. Everything downstream of that is real HTTP.

Negative cases come first, per .claude/rules/testing.md.
"""

from __future__ import annotations

import asyncio
import json
import threading
import urllib.request
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from tracelane.instrumentations.anthropic import instrument_anthropic
from tracelane.instrumentations.openai import instrument_openai
from tracelane.instrumentations.openrouter import instrument_openrouter
from tracelane.session import (
    CONVERSATION_ID_ATTRIBUTE,
    CONVERSATION_ID_HEADER,
    MAX_SESSION_ID_LENGTH,
    get_session,
    normalize_session_id,
    session_headers,
    set_session,
    use_session,
)

_BODY = json.dumps(
    {
        "id": "chatcmpl-test",
        "model": "claude-sonnet-4-6",
        "choices": [{"finish_reason": "stop"}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 1},
    }
).encode()


class _Recorder:
    """A loopback origin that records the headers of every request it answers."""

    def __init__(self) -> None:
        self.received: list[dict[str, str]] = []
        received = self.received

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
                length = int(self.headers.get("content-length", "0"))
                self.rfile.read(length)
                received.append({k.lower(): v for k, v in self.headers.items()})
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(_BODY)))
                self.end_headers()
                self.wfile.write(_BODY)

            def log_message(self, *args: Any) -> None:
                pass  # keep the test output clean

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[0], self._server.server_address[1]
        return f"http://{host}:{port}/v1/chat/completions"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def only(self) -> dict[str, str]:
        assert len(self.received) == 1, self.received
        return self.received[0]


def _post(url: str, headers: dict[str, str]) -> None:
    """Send a real request, exactly as a vendor SDK would with these headers."""
    request = urllib.request.Request(  # noqa: S310 - loopback test server
        url, data=b"{}", headers={"content-type": "application/json", **headers}
    )
    with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310
        response.read()


class _WireClient:
    """Stands in for ``openai.OpenAI`` / ``anthropic.Anthropic``.

    Reproduces the single step those SDKs take with ``extra_headers`` — merge it
    into the outgoing request — and then performs a REAL HTTP request, so the
    assertions below run against bytes a server received.
    """

    def __init__(self, url: str) -> None:
        outer = self

        class _Endpoint:
            def create(self, **kwargs: Any) -> dict[str, Any]:
                _post(outer.url, dict(kwargs.get("extra_headers") or {}))
                return {"usage": {}, "choices": []}

        class _Chat:
            def __init__(self) -> None:
                self.completions = _Endpoint()

        self.url = url
        self.chat = _Chat()
        self.messages = _Endpoint()


@pytest.fixture
def recorder() -> Iterator[_Recorder]:
    rec = _Recorder()
    try:
        yield rec
    finally:
        rec.close()


@pytest.fixture(autouse=True)
def _clear_session() -> Iterator[None]:
    # A leaked session would silently taint every later test.
    yield
    set_session(None)


# The `spans` fixture comes from tests/conftest.py — OTel forbids overriding the
# global tracer provider, so there is exactly one, installed once at import.


# --------------------------------------------------------------------------
# Must reject — before anything reaches the wire.
# --------------------------------------------------------------------------


def test_rejects_empty_and_whitespace_only_id() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        normalize_session_id("")
    with pytest.raises(ValueError, match="must not be empty"):
        normalize_session_id("   ")


def test_rejects_over_long_id_rather_than_truncating() -> None:
    too_long = "s" * (MAX_SESSION_ID_LENGTH + 1)
    with pytest.raises(ValueError, match="at most 256 characters"):
        normalize_session_id(too_long)
    # A truncated id is a WRONG id — it would split one conversation in two.
    with pytest.raises(ValueError, match="truncated"):
        normalize_session_id(too_long)


def test_rejects_crlf_so_header_injection_is_unrepresentable() -> None:
    with pytest.raises(ValueError, match="visible ASCII"):
        normalize_session_id("sess-1\r\nx-admin: true")
    with pytest.raises(ValueError, match="visible ASCII"):
        normalize_session_id("sess\r1")
    with pytest.raises(ValueError, match="visible ASCII"):
        normalize_session_id("sess\t1")
    # A trailing newline is a file-read artifact, so it is trimmed — but the
    # result must be clean, never smuggled through.
    assert normalize_session_id("sess-1\n") == "sess-1"


def test_rejects_non_ascii_which_the_gateway_would_drop_silently() -> None:
    with pytest.raises(ValueError, match="visible ASCII"):
        normalize_session_id("séssion-1")
    with pytest.raises(ValueError, match="visible ASCII"):
        normalize_session_id("会話-1")
    # The error must say WHY, so the developer does not just retry.
    with pytest.raises(ValueError, match="silently"):
        normalize_session_id("séssion-1")


def test_rejects_a_non_string_id() -> None:
    with pytest.raises(TypeError, match="must be a str"):
        normalize_session_id(42)  # type: ignore[arg-type]


def test_rejection_happens_at_the_call_site_not_inside_the_request() -> None:
    entered = False
    with pytest.raises(ValueError, match="visible ASCII"), use_session("bad\rid"):
        entered = True
    assert entered is False
    with pytest.raises(ValueError, match="visible ASCII"):
        session_headers("bad\rid")
    with pytest.raises(ValueError, match="visible ASCII"):
        set_session("bad\rid")
    # A rejected set_session must not have taken effect.
    assert get_session() is None


def test_accepts_a_realistic_id_and_one_exactly_at_the_cap() -> None:
    assert normalize_session_id("  sess_2026-08-08/42  ") == "sess_2026-08-08/42"
    at_cap = "s" * MAX_SESSION_ID_LENGTH
    assert normalize_session_id(at_cap) == at_cap


# --------------------------------------------------------------------------
# Must accept — the header reaches a real HTTP server.
# --------------------------------------------------------------------------


def test_instrumented_openai_client_sends_the_header(recorder: _Recorder) -> None:
    client = _WireClient(recorder.base_url)
    instrument_openai(client)

    with use_session("sess-observable-1"):
        client.chat.completions.create(model="claude-sonnet-4-6", messages=[])

    assert recorder.only()[CONVERSATION_ID_HEADER] == "sess-observable-1"


def test_instrumented_openai_client_sends_no_header_without_a_session(
    recorder: _Recorder,
) -> None:
    client = _WireClient(recorder.base_url)
    instrument_openai(client)

    client.chat.completions.create(model="claude-sonnet-4-6", messages=[])

    headers = recorder.only()
    assert CONVERSATION_ID_HEADER not in headers
    assert "x-session-id" not in headers


def test_instrumented_anthropic_client_sends_the_header(recorder: _Recorder) -> None:
    client = _WireClient(recorder.base_url)
    instrument_anthropic(client)

    with use_session("sess-anthropic-1"):
        client.messages.create(model="claude-sonnet-4-6", max_tokens=16, messages=[])

    assert recorder.only()[CONVERSATION_ID_HEADER] == "sess-anthropic-1"


def test_instrumented_anthropic_client_sends_no_header_without_a_session(
    recorder: _Recorder,
) -> None:
    client = _WireClient(recorder.base_url)
    instrument_anthropic(client)

    client.messages.create(model="claude-sonnet-4-6", max_tokens=16, messages=[])

    assert CONVERSATION_ID_HEADER not in recorder.only()


# Every adapter that wraps an OpenAI-shaped `chat.completions.create` must attach
# the session — otherwise "the SDK sets it" is true for one import path and
# quietly false for the others.
@pytest.mark.parametrize(
    "instrument", [instrument_openai, instrument_openrouter], ids=["openai", "openrouter"]
)
def test_every_openai_shaped_adapter_attaches_the_session(
    recorder: _Recorder, instrument: Any
) -> None:
    client = _WireClient(recorder.base_url)
    instrument(client)

    with use_session("sess-adapter"):
        client.chat.completions.create(model="claude-sonnet-4-6", messages=[])
    client.chat.completions.create(model="claude-sonnet-4-6", messages=[])

    assert len(recorder.received) == 2
    assert recorder.received[0][CONVERSATION_ID_HEADER] == "sess-adapter"
    assert CONVERSATION_ID_HEADER not in recorder.received[1]


def test_explicit_extra_headers_win_over_the_ambient_session(recorder: _Recorder) -> None:
    client = _WireClient(recorder.base_url)
    instrument_openai(client)
    set_session("sess-ambient")

    client.chat.completions.create(
        model="claude-sonnet-4-6",
        messages=[],
        extra_headers={"X-Conversation-Id": "sess-explicit"},
    )

    # Case-insensitive: the ambient value must not be added alongside.
    assert recorder.only()[CONVERSATION_ID_HEADER] == "sess-explicit"


def test_caller_headers_it_did_not_set_are_preserved(recorder: _Recorder) -> None:
    client = _WireClient(recorder.base_url)
    instrument_openai(client)

    with use_session("sess-merge"):
        client.chat.completions.create(
            model="claude-sonnet-4-6",
            messages=[],
            extra_headers={"x-agent-id": "agent-7"},
        )

    headers = recorder.only()
    assert headers[CONVERSATION_ID_HEADER] == "sess-merge"
    assert headers["x-agent-id"] == "agent-7"


def test_session_headers_puts_an_uninstrumented_client_into_a_session(
    recorder: _Recorder,
) -> None:
    # No instrument_*() call at all — the quickstart's hosted path.
    _post(recorder.base_url, session_headers("sess-plain"))
    assert recorder.only()[CONVERSATION_ID_HEADER] == "sess-plain"


def test_session_headers_is_empty_and_harmless_with_no_session(recorder: _Recorder) -> None:
    assert session_headers() == {}
    _post(recorder.base_url, session_headers())
    assert CONVERSATION_ID_HEADER not in recorder.only()


# --------------------------------------------------------------------------
# Isolation — overlapping conversations must not bleed.
# --------------------------------------------------------------------------


def test_threads_do_not_share_a_session(recorder: _Recorder) -> None:
    client = _WireClient(recorder.base_url)
    instrument_openai(client)

    def call(session_id: str) -> None:
        with use_session(session_id):
            client.chat.completions.create(model="claude-sonnet-4-6", messages=[])

    threads = [threading.Thread(target=call, args=(f"sess-t{i}",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    sent = sorted(h[CONVERSATION_ID_HEADER] for h in recorder.received)
    assert sent == ["sess-t0", "sess-t1", "sess-t2", "sess-t3"]


def test_concurrent_asyncio_tasks_do_not_share_a_session(recorder: _Recorder) -> None:
    client = _WireClient(recorder.base_url)
    instrument_openai(client)

    async def call(session_id: str) -> None:
        with use_session(session_id):
            await asyncio.sleep(0)  # force a real task switch mid-session
            client.chat.completions.create(model="claude-sonnet-4-6", messages=[])

    async def main() -> None:
        await asyncio.gather(call("sess-alpha"), call("sess-beta"))

    asyncio.run(main())

    sent = sorted(h[CONVERSATION_ID_HEADER] for h in recorder.received)
    assert sent == ["sess-alpha", "sess-beta"]


def test_use_session_restores_the_previous_value_even_on_error() -> None:
    set_session("sess-outer")
    with pytest.raises(RuntimeError), use_session("sess-inner"):
        assert get_session() == "sess-inner"
        raise RuntimeError("boom")
    assert get_session() == "sess-outer"
    set_session(None)
    assert get_session() is None


# --------------------------------------------------------------------------
# OTLP path — the same id lands on the span.
# --------------------------------------------------------------------------


def test_span_carries_the_conversation_id(recorder: _Recorder, spans: InMemorySpanExporter) -> None:
    client = _WireClient(recorder.base_url)
    instrument_openai(client)

    with use_session("sess-otlp-1"):
        client.chat.completions.create(model="claude-sonnet-4-6", messages=[])

    finished = spans.get_finished_spans()
    assert len(finished) == 1
    assert finished[0].attributes is not None
    assert finished[0].attributes[CONVERSATION_ID_ATTRIBUTE] == "sess-otlp-1"


def test_span_omits_the_attribute_when_no_session_is_active(
    recorder: _Recorder, spans: InMemorySpanExporter
) -> None:
    client = _WireClient(recorder.base_url)
    instrument_openai(client)

    client.chat.completions.create(model="claude-sonnet-4-6", messages=[])

    finished = spans.get_finished_spans()
    assert len(finished) == 1
    assert finished[0].attributes is not None
    # Absent, never an empty string — an empty id would group traces wrongly.
    assert CONVERSATION_ID_ATTRIBUTE not in finished[0].attributes

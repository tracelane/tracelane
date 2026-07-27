"""Browserbase instrumentation for Tracelane.

Wraps Browserbase session lifecycle methods to emit OTel spans.
Browser-agent traces are the noisiest in agent pipelines — DOM mutations,
CAPTCHA detections, and navigation events all need observability context.
These spans feed the browser stuck-loop predictor (PP-PR4, PP-PR5).

Example::

    from browserbase import Browserbase
    from tracelane.instrumentations.browserbase import instrument_browserbase

    bb = Browserbase(api_key=os.environ["BROWSERBASE_API_KEY"])
    instrument_browserbase(bb)
    session = bb.sessions.create(project_id="...", browser_settings={})
    # Span emitted with browserbase.session_id and project_id
"""

from __future__ import annotations

from typing import Any

from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.browserbase", "0.1.0")


def instrument_browserbase(client: Any) -> None:
    """Wrap a Browserbase client to emit OTel spans for session operations.

    Args:
        client: A browserbase.Browserbase instance.

    Note:
        Session IDs are captured for correlation with browser event traces.
        No page content or credentials are captured.
    """
    sessions = getattr(client, "sessions", None)
    if sessions is not None:
        if hasattr(sessions, "create"):
            _patch_sessions_create(sessions)
        if hasattr(sessions, "retrieve"):
            _patch_sessions_retrieve(sessions)
    # Also handle direct create_session if present (older SDK versions)
    if hasattr(client, "create_session"):
        _patch_create_session_direct(client)


def _patch_sessions_create(sessions: Any) -> None:
    original = sessions.create

    def _patched(*args: Any, **kwargs: Any) -> Any:
        project_id = kwargs.get("project_id", "")
        with _tracer.start_as_current_span(
            "browserbase.sessions.create",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "browserbase",
                "browserbase.project_id": str(project_id),
                "browserbase.operation": "create_session",
            },
        ) as span:
            try:
                result = original(*args, **kwargs)
                session_id = getattr(result, "id", None) or getattr(result, "session_id", None)
                if session_id:
                    span.set_attribute("browserbase.session_id", str(session_id))
                region = getattr(result, "region", None)
                if region:
                    span.set_attribute("browserbase.region", str(region))
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    sessions.create = _patched


def _patch_sessions_retrieve(sessions: Any) -> None:
    original = sessions.retrieve

    def _patched(session_id: Any, *args: Any, **kwargs: Any) -> Any:
        with _tracer.start_as_current_span(
            "browserbase.sessions.retrieve",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "browserbase",
                "browserbase.session_id": str(session_id),
                "browserbase.operation": "retrieve_session",
            },
        ) as span:
            try:
                result = original(session_id, *args, **kwargs)
                status = getattr(result, "status", None)
                if status:
                    span.set_attribute("browserbase.session_status", str(status))
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    sessions.retrieve = _patched


def _patch_create_session_direct(client: Any) -> None:
    original = client.create_session

    def _patched(*args: Any, **kwargs: Any) -> Any:
        with _tracer.start_as_current_span(
            "browserbase.create_session",
            kind=SpanKind.CLIENT,
            attributes={"gen_ai.provider.name": "browserbase"},
        ) as span:
            try:
                result = original(*args, **kwargs)
                session_id = getattr(result, "id", None) or (
                    result if isinstance(result, str) else None
                )
                if session_id:
                    span.set_attribute("browserbase.session_id", str(session_id))
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    client.create_session = _patched

"""Session (conversation) correlation for the Tracelane gateway.

``/sessions`` groups traces by ``gen_ai.conversation.id``. There are exactly two
ways that id reaches Tracelane, and this module populates both:

1. **Gateway path** — an ``x-conversation-id`` request header on the call to
   ``https://<gateway>/v1/chat/completions``. The gateway reads that header
   (falling back to ``x-session-id``) and stamps it onto the span it records.
2. **OTLP path** — the ``gen_ai.conversation.id`` span attribute, which the
   ingest OTLP decoder maps onto the same column.

Until this module existed the read side was built but nothing in either SDK
could set the id, so ``/sessions`` stayed empty for every SDK user.

Scoped to one conversation turn (safe under concurrency — backed by a
``ContextVar``, so each asyncio task and thread gets its own value)::

    from tracelane import use_session

    with use_session("sess-42"):
        client.chat.completions.create(model="claude-sonnet-4-6", messages=msgs)

No instrumentation — hand the header to any OpenAI-compatible client::

    from tracelane import session_headers

    client.chat.completions.create(
        model="claude-sonnet-4-6",
        messages=msgs,
        extra_headers=session_headers("sess-42"),
    )
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

#: The header the gateway reads first.
#: Source of truth: ``crates/gateway/src/server.rs:959-963``.
CONVERSATION_ID_HEADER = "x-conversation-id"

#: The alias the gateway falls back to when :data:`CONVERSATION_ID_HEADER` is absent.
SESSION_ID_HEADER = "x-session-id"

#: The OTel span attribute the ingest OTLP decoder maps to the same column.
CONVERSATION_ID_ATTRIBUTE = "gen_ai.conversation.id"

#: Max length of a session id, in unicode scalar values.
#:
#: Mirrors the gateway's cap on the sibling customer-supplied
#: ``x-business-reference`` header (``crates/shared/src/span.rs``), so a value
#: this SDK accepts is a value the recorder stores. Over-long ids are rejected,
#: never truncated — a truncated id is a *wrong* id, and would silently split one
#: conversation into two.
MAX_SESSION_ID_LENGTH = 256

# Header names that mean "a session id is already set", compared lowercased.
_SESSION_HEADER_NAMES = frozenset({CONVERSATION_ID_HEADER, SESSION_ID_HEADER})

_current_session: ContextVar[str | None] = ContextVar("tracelane_session_id", default=None)


def normalize_session_id(raw: str) -> str:
    """Validate and canonicalise a session id.

    Fails **CLOSED**: an id the gateway could not carry on the wire raises here,
    at the call the developer wrote, rather than being dropped in transit and
    leaving ``/sessions`` mysteriously empty.

    Args:
        raw: The candidate id. Surrounding whitespace is trimmed.

    Returns:
        The trimmed id.

    Raises:
        TypeError: If ``raw`` is not a ``str``.
        ValueError: If the id is empty, longer than :data:`MAX_SESSION_ID_LENGTH`,
            or contains a character outside visible ASCII — which is exactly the
            set ``HeaderValue::to_str()`` accepts gateway-side, and which also
            makes CR/LF header injection unrepresentable.
    """
    if not isinstance(raw, str):
        raise TypeError(f"Tracelane session id must be a str, received {type(raw).__name__}")
    trimmed = raw.strip()
    if not trimmed:
        raise ValueError("Tracelane session id must not be empty")
    if len(trimmed) > MAX_SESSION_ID_LENGTH:
        raise ValueError(
            f"Tracelane session id must be at most {MAX_SESSION_ID_LENGTH} characters, "
            f"received {len(trimmed)} — ids are rejected rather than truncated, "
            "because a truncated id is a wrong id"
        )
    for ch in trimmed:
        if not (0x20 <= ord(ch) <= 0x7E):
            raise ValueError(
                "Tracelane session id must be visible ASCII (U+0020..U+007E); "
                f"found U+{ord(ch):04X}. The gateway drops header values outside "
                "that range, so the session would be lost silently."
            )
    return trimmed


@contextmanager
def use_session(session_id: str) -> Iterator[str]:
    """Run the enclosed block with ``session_id`` as the active session.

    Backed by a ``ContextVar``, so concurrent conversations never bleed into each
    other across asyncio tasks or threads. The previous value is restored on exit,
    including when the block raises.

    Args:
        session_id: The conversation id. Validated by :func:`normalize_session_id`.

    Yields:
        The normalised session id.

    Raises:
        TypeError: If ``session_id`` is not a ``str``. Fails CLOSED, before the block runs.
        ValueError: If ``session_id`` is not wire-safe. Fails CLOSED, before the block runs.
    """
    normalized = normalize_session_id(session_id)
    token = _current_session.set(normalized)
    try:
        yield normalized
    finally:
        _current_session.reset(token)


def set_session(session_id: str | None) -> None:
    """Set the active session id for the current context.

    Prefer :func:`use_session` when conversations overlap — this sets the value
    without an automatic restore. Pass ``None`` to clear it.

    Args:
        session_id: The conversation id, or ``None`` to clear.

    Raises:
        TypeError: If a non-``None`` ``session_id`` is not a ``str``. Fails CLOSED.
        ValueError: If a non-``None`` ``session_id`` is not wire-safe. Fails CLOSED —
            a rejected id leaves the previous value untouched.
    """
    _current_session.set(None if session_id is None else normalize_session_id(session_id))


def get_session() -> str | None:
    """The session id that would be attached to a call made right now.

    Returns:
        The active conversation id, or ``None`` when no session is active.
    """
    return _current_session.get()


def session_headers(session_id: str | None = None) -> dict[str, str]:
    """The request headers that put a call into a session.

    Hand these to any OpenAI-compatible client as ``extra_headers`` — no
    Tracelane instrumentation required. Returns an empty dict when no session is
    active, so it is always safe to pass.

    Args:
        session_id: An explicit id; defaults to the currently active session.

    Returns:
        ``{"x-conversation-id": id}``, or ``{}`` when no session is active.

    Raises:
        TypeError: If an explicit ``session_id`` is not a ``str``. Fails CLOSED.
        ValueError: If an explicit ``session_id`` is not wire-safe. Fails CLOSED.
    """
    resolved = get_session() if session_id is None else normalize_session_id(session_id)
    return {} if resolved is None else {CONVERSATION_ID_HEADER: resolved}


def merge_session_header(existing: Any, session_id: str) -> dict[str, str] | None:
    """Merge the session header into a call's existing ``extra_headers``.

    Fails **OPEN**: observability must never break the caller's LLM call, so an
    unrecognised header shape yields ``None`` (leave the request alone) rather
    than raising. The span attribute still carries the session in that case.

    An explicitly-supplied ``x-conversation-id``/``x-session-id`` always wins over
    the ambient session — the developer said what they meant.

    Args:
        existing: Whatever the caller passed as ``extra_headers``.
        session_id: The already-validated active session id.

    Returns:
        The merged header mapping, or ``None`` to leave ``existing`` untouched.
    """
    if existing is None:
        merged: dict[str, str] = {}
    elif isinstance(existing, Mapping):
        merged = {str(k): v for k, v in existing.items()}
    else:
        return None
    if any(name.lower() in _SESSION_HEADER_NAMES for name in merged):
        return None
    merged[CONVERSATION_ID_HEADER] = session_id
    return merged


def apply_session_to_kwargs(kwargs: dict[str, Any]) -> str | None:
    """Attach the active session to an instrumented ``create(**kwargs)`` call.

    Mutates ``kwargs`` in place, setting ``extra_headers``. A no-op when no
    session is active, so an un-sessioned call reaches the vendor SDK byte-identical
    to an uninstrumented one.

    Args:
        kwargs: The keyword arguments of the wrapped ``create`` call.

    Returns:
        The active session id, for stamping onto the span, or ``None``.
    """
    session_id = get_session()
    if session_id is None:
        return None
    merged = merge_session_header(kwargs.get("extra_headers"), session_id)
    if merged is not None:
        kwargs["extra_headers"] = merged
    return session_id

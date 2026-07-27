"""Streaming-call guard shared by the LLM instrumentations.

Token-usage capture for streamed responses lands in v1.1. Until then a
streamed call must never be recorded silently as a token-less span that
looks like a broken integration: the span is marked
``tracelane.streaming = True`` (so the platform can distinguish "no usage
because streaming" from "no usage because bug") and a once-per-process
``UserWarning`` tells the developer exactly what is and is not captured.
"""

from __future__ import annotations

import warnings
from typing import Any

_warned = False


def mark_streaming_call(span: Any, provider: str) -> None:
    """Mark ``span`` as a streamed call and warn once per process.

    The wrapped response object is never touched — consuming the stream to
    count tokens would alter caller-visible behavior.

    Args:
        span: The active span for the streamed call.
        provider: Instrumentation name for the warning text (e.g. ``"openai"``).
    """
    global _warned
    span.set_attribute("tracelane.streaming", True)
    if _warned:
        return
    _warned = True
    warnings.warn(
        f"tracelane: {provider} stream=True detected — token usage and finish "
        "reason are not captured for streamed calls yet (planned for v1.1). "
        "Spans still record model and latency, marked tracelane.streaming=True.",
        UserWarning,
        stacklevel=3,
    )

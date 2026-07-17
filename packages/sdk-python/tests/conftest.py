"""Shared pytest fixtures for the Tracelane Python SDK tests.

Wires a real OpenTelemetry `TracerProvider` backed by an in-memory exporter
so adapter tests can assert on the spans their instrumentations emit, without
any network or a live ingest receiver (per `.claude/rules/testing.md`).

The provider is installed once at import (OTel forbids overriding the global
provider). Every adapter's module-level `trace.get_tracer(...)` resolves to it
because OTel hands out a lazy `ProxyTracer` until a provider is set.
"""

from __future__ import annotations

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

_EXPORTER = InMemorySpanExporter()


def _install_provider_once() -> None:
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(_EXPORTER))
    # First writer wins; if some import already set a provider this is a no-op,
    # which is fine — the exporter is what we read from.
    trace.set_tracer_provider(provider)


_install_provider_once()


@pytest.fixture
def spans() -> InMemorySpanExporter:
    """Per-test handle on the in-memory span exporter, cleared before + after."""
    _EXPORTER.clear()
    yield _EXPORTER
    _EXPORTER.clear()

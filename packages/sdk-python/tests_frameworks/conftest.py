"""OTel provider for the real-framework attach checks (B-314).

Same in-memory exporter as ``tests/conftest.py`` — duplicated rather than
imported so this directory stands alone: it is run by ONE dedicated CI job
with the real frameworks installed, never by the default ``pytest`` walk.
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
_PROVIDER = TracerProvider()
_PROVIDER.add_span_processor(SimpleSpanProcessor(_EXPORTER))
trace.set_tracer_provider(_PROVIDER)


@pytest.fixture
def spans() -> InMemorySpanExporter:
    _EXPORTER.clear()
    yield _EXPORTER
    _EXPORTER.clear()

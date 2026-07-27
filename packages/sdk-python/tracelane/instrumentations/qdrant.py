"""Qdrant instrumentation for Tracelane.

Wraps QdrantClient.search and QdrantClient.upsert to emit OTel spans.
Qdrant is Rust-native + Apache 2.0 — a natural companion to Tracelane's
stack. These spans enrich the full agent trace with vector retrieval context.

Example::

    from qdrant_client import QdrantClient
    from tracelane.instrumentations.qdrant import instrument_qdrant

    client = QdrantClient(url="http://localhost:6333")
    instrument_qdrant(client)
    results = client.search(collection_name="docs", query_vector=[...], limit=5)
    # Span emitted with qdrant.results_count and collection name
"""

from __future__ import annotations

from typing import Any

from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.qdrant", "0.1.0")


def instrument_qdrant(client: Any) -> None:
    """Wrap a QdrantClient instance to emit OTel spans.

    Instruments search(), upsert(), and delete() operations.

    Args:
        client: A qdrant_client.QdrantClient instance.

    Note:
        Vector values are never captured. Collection name, limit,
        and result count are recorded.
    """
    if hasattr(client, "search"):
        _patch_search(client)
    if hasattr(client, "upsert"):
        _patch_upsert(client)
    if hasattr(client, "query_points"):
        _patch_query_points(client)


def _patch_search(client: Any) -> None:
    original = client.search

    def _patched(*args: Any, **kwargs: Any) -> Any:
        collection = kwargs.get("collection_name", args[0] if args else "unknown")
        limit = kwargs.get("limit", 10)
        with _tracer.start_as_current_span(
            "qdrant.search",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "qdrant",
                "db.system": "qdrant",
                "db.operation.name": "search",
                "db.collection.name": str(collection),
                "qdrant.limit": int(limit),
            },
        ) as span:
            try:
                results = original(*args, **kwargs)
                count = len(results) if isinstance(results, list) else 0
                span.set_attribute("qdrant.results_count", count)
                span.set_status(StatusCode.OK)
                return results
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    client.search = _patched


def _patch_upsert(client: Any) -> None:
    original = client.upsert

    def _patched(*args: Any, **kwargs: Any) -> Any:
        collection = kwargs.get("collection_name", args[0] if args else "unknown")
        points = kwargs.get("points", args[1] if len(args) > 1 else [])
        point_count = len(points) if isinstance(points, list) else 0
        with _tracer.start_as_current_span(
            "qdrant.upsert",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "qdrant",
                "db.system": "qdrant",
                "db.operation.name": "upsert",
                "db.collection.name": str(collection),
                "qdrant.upsert_count": point_count,
            },
        ) as span:
            try:
                result = original(*args, **kwargs)
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    client.upsert = _patched


def _patch_query_points(client: Any) -> None:
    original = client.query_points

    def _patched(*args: Any, **kwargs: Any) -> Any:
        collection = kwargs.get("collection_name", args[0] if args else "unknown")
        limit = kwargs.get("limit", 10)
        with _tracer.start_as_current_span(
            "qdrant.query_points",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "qdrant",
                "db.system": "qdrant",
                "db.operation.name": "query_points",
                "db.collection.name": str(collection),
                "qdrant.limit": int(limit),
            },
        ) as span:
            try:
                result = original(*args, **kwargs)
                points = getattr(result, "points", None) or []
                span.set_attribute("qdrant.results_count", len(points))
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    client.query_points = _patched

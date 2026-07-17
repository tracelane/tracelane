"""Pinecone instrumentation for Tracelane.

Wraps Pinecone Index.query and Index.upsert to emit OTel spans enriched with
retrieval metadata. RAG retrieval is one of the highest-cost operations in
agent pipelines — these spans let operators track embedding quality,
match rates, and retrieval latency as part of the full agent trace.

Example::

    import pinecone
    from tracelane.instrumentations.pinecone import instrument_pinecone

    pc = pinecone.Pinecone(api_key=os.environ["PINECONE_API_KEY"])
    index = pc.Index("my-index")
    instrument_pinecone(index)
    results = index.query(vector=[...], top_k=5)
    # Span emitted with pinecone.top_k and pinecone.matches_count
"""

from __future__ import annotations

from typing import Any

from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.pinecone", "0.1.0")


def instrument_pinecone(index: Any) -> None:
    """Wrap a Pinecone Index instance to emit OTel spans.

    Args:
        index: A pinecone.Index instance (from Pinecone v3+ client).

    Note:
        Vector values are never captured. Only top_k, match count,
        namespace, and index name are recorded.
    """
    if hasattr(index, "query"):
        _patch_query(index)
    if hasattr(index, "upsert"):
        _patch_upsert(index)
    if hasattr(index, "delete"):
        _patch_delete(index)


def _patch_query(index: Any) -> None:
    original = index.query
    index_name = getattr(index, "_config", None)
    index_name = getattr(index_name, "host", None) or "unknown"

    def _patched(*args: Any, **kwargs: Any) -> Any:
        top_k = kwargs.get("top_k", args[1] if len(args) > 1 else 10)
        namespace = kwargs.get("namespace", "")
        with _tracer.start_as_current_span(
            "pinecone.index.query",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "pinecone",
                "db.system": "pinecone",
                "db.operation.name": "query",
                "pinecone.top_k": int(top_k),
                "pinecone.namespace": str(namespace),
            },
        ) as span:
            try:
                result = original(*args, **kwargs)
                matches = getattr(result, "matches", None) or []
                span.set_attribute("pinecone.matches_count", len(matches))
                if matches:
                    scores = [getattr(m, "score", 0.0) for m in matches]
                    if scores:
                        span.set_attribute("pinecone.top_score", max(scores))
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    index.query = _patched


def _patch_upsert(index: Any) -> None:
    original = index.upsert

    def _patched(*args: Any, **kwargs: Any) -> Any:
        vectors = kwargs.get("vectors", args[0] if args else [])
        vector_count = len(vectors) if isinstance(vectors, list) else 0
        namespace = kwargs.get("namespace", "")
        with _tracer.start_as_current_span(
            "pinecone.index.upsert",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "pinecone",
                "db.system": "pinecone",
                "db.operation.name": "upsert",
                "pinecone.upsert_count": vector_count,
                "pinecone.namespace": str(namespace),
            },
        ) as span:
            try:
                result = original(*args, **kwargs)
                upserted = getattr(result, "upserted_count", None)
                if upserted is not None:
                    span.set_attribute("pinecone.upserted_count", int(upserted))
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    index.upsert = _patched


def _patch_delete(index: Any) -> None:
    original = index.delete

    def _patched(*args: Any, **kwargs: Any) -> Any:
        with _tracer.start_as_current_span(
            "pinecone.index.delete",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "pinecone",
                "db.system": "pinecone",
                "db.operation.name": "delete",
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

    index.delete = _patched

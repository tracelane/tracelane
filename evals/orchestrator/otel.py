"""
OTLP span emission for eval results.

Every eval result is emitted as an OpenTelemetry span so it appears in
the Tracelane trace viewer linked to the agent state graph. This is what
allows "eval result → trace" drill-down in the dashboard.

Span attributes follow OpenInference semconv where applicable.
"""

from __future__ import annotations

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

_tracer: trace.Tracer | None = None


def init_otel(endpoint: str | None = None) -> None:
    """Initialise OTLP exporter. No-op if endpoint is not configured."""
    global _tracer

    if endpoint is None:
        import os

        endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")

    if endpoint is None:
        _tracer = trace.get_tracer("tracelane.evals")
        return

    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

    provider = TracerProvider(
        resource=Resource.create({"service.name": "tracelane-evals"}),
    )
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    trace.set_tracer_provider(provider)
    _tracer = trace.get_tracer("tracelane.evals")


def emit_eval_span(result: EvalResult) -> None:  # noqa: F821
    """Emit a single eval result as an OTLP span."""
    tracer = _tracer or trace.get_tracer("tracelane.evals")

    with tracer.start_as_current_span(f"eval/{result.id}") as span:
        span.set_attribute("tracelane.eval.id", result.id)
        span.set_attribute("tracelane.eval.name", result.name)
        span.set_attribute("tracelane.eval.status", result.status.value)
        span.set_attribute("tracelane.eval.framework", result.framework)
        span.set_attribute("tracelane.eval.duration_ms", result.duration_ms)

        if result.score is not None:
            span.set_attribute("tracelane.eval.score", result.score)
        if result.threshold is not None:
            span.set_attribute("tracelane.eval.threshold", result.threshold)
        if result.pain_point_id:
            span.set_attribute("tracelane.eval.pain_point_id", result.pain_point_id)
        if result.aft_id:
            span.set_attribute("tracelane.eval.aft_id", result.aft_id)
        if result.reason:
            span.set_attribute("tracelane.eval.reason", result.reason)

        if result.status in ("fail", "error"):
            span.set_status(trace.StatusCode.ERROR, result.reason or "eval failed")

#!/usr/bin/env python3
"""Emit one OTLP span to the ingest receiver for the e2e smoke (punchlist #4).

Uses the real OpenTelemetry OTLP/HTTP exporter — the same machinery the
Tracelane Python SDK wraps — so the span is encoded and shipped exactly as a
production agent would ship it. The tenant is carried as the resource
attribute `tracelane.tenant_id`, which the ingest receiver resolves in its
debug/plaintext mode (production uses the SPIFFE-attested peer identity).

Usage: send_span.py <otlp-endpoint> <tenant-uuid>
"""

import sys

from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor


def main() -> int:
    endpoint = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:4318"
    tenant = (
        sys.argv[2] if len(sys.argv) > 2 else "00000000-0000-0000-0000-0000000000ab"
    )

    resource = Resource.create(
        {"service.name": "tracelane-smoke", "tracelane.tenant_id": tenant}
    )
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(
        SimpleSpanProcessor(OTLPSpanExporter(endpoint=f"{endpoint}/v1/traces"))
    )
    tracer = provider.get_tracer("tracelane-smoke")

    with tracer.start_as_current_span("smoke.llm.chat") as span:
        span.set_attribute("gen_ai.provider.name", "smoke")
        span.set_attribute("gen_ai.request.model", "smoke-model")

    # Force-flush + shut down so the span is exported before we exit.
    provider.shutdown()
    print(f"emitted smoke span for tenant {tenant} -> {endpoint}/v1/traces")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""OTel tracer initialisation for the Tracelane Python SDK.

Never calls home from the SDK — all telemetry goes to the configured
endpoint only. API keys are never captured in span attributes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

_provider: TracerProvider | None = None


@dataclass
class TracelaneConfig:
    """Configuration for the Tracelane SDK."""

    endpoint: str
    """OTLP endpoint, e.g. https://ingest.tracelane.dev or http://localhost:4318"""

    api_key: str
    """Tracelane API key for tenant authentication."""

    service_name: str = "unknown-service"
    """Service name for OTel resource attribution."""

    sample_rate: float = 1.0
    """Sampling ratio 0.0–1.0. Default 1.0 (full trace; tail sampler decides)."""

    extra_resource_attributes: dict[str, str] = field(default_factory=dict)
    """Additional OTel resource attributes to attach to all spans."""


def init(
    endpoint: str,
    api_key: str,
    service_name: str = "unknown-service",
    sample_rate: float = 1.0,
    auto_instrument: bool = False,
) -> None:
    """Initialise the Tracelane OTel SDK.

    Must be called before any instrumented code runs.
    Safe to call multiple times — subsequent calls are no-ops.

    Args:
        endpoint: OTLP endpoint URL (no trailing slash).
        api_key: Tracelane tenant API key.
        service_name: OTel service.name resource attribute.
        sample_rate: Head sampling rate (0.0–1.0). Tail sampler applies after.
        auto_instrument: If True, auto-instrument all installed AI libraries
            after SDK init. Equivalent to calling auto_instrument() manually.
    """
    global _provider
    if _provider is not None:
        return

    resource = Resource.create({"service.name": service_name})

    exporter = OTLPSpanExporter(
        endpoint=f"{endpoint}/v1/traces",
        headers={"x-tracelane-api-key": api_key},
    )

    _provider = TracerProvider(resource=resource)
    _provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(_provider)

    if auto_instrument:
        from tracelane import auto_instrument as _auto  # noqa: PLC0415

        _auto()


def shutdown() -> None:
    """Flush pending spans and shut down the OTel SDK.

    Call at application shutdown to ensure all spans are exported.
    """
    global _provider
    if _provider is not None:
        _provider.shutdown()
        _provider = None

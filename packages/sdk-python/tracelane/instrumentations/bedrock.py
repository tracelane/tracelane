"""AWS Bedrock instrumentation for Tracelane.

Wraps the boto3 bedrock-runtime client's invoke_model method to emit OTel
spans for every synchronous model invocation. Captures model ID, HTTP status
code, and token usage from the response body when available. Never captures
request body content, AWS credentials, or raw model output.

Example::

    import boto3
    from tracelane.instrumentations.bedrock import instrument_bedrock

    client = boto3.client("bedrock-runtime", region_name="us-east-1")
    instrument_bedrock(client)
    # All client.invoke_model() calls now emit spans
"""

from __future__ import annotations

import json
from typing import Any

import wrapt
from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.bedrock", "0.1.0")


def instrument_bedrock(client: Any) -> None:
    """Wrap a boto3 bedrock-runtime client to emit OTel spans.

    Instruments invoke_model() — the synchronous single-turn API. Token usage
    is parsed from the JSON response body if the provider includes it (Anthropic
    Claude on Bedrock exposes usage.input_tokens / usage.output_tokens; Amazon
    Titan exposes inputTextTokenCount / outputTokenCount).

    Args:
        client: A boto3 client created with service_name="bedrock-runtime".

    Note:
        Mutates the client in-place using wrapt. AWS credentials are never
        captured — only the modelId, HTTP status, and token counts.
    """
    _patch_invoke_model(client)
    _patch_invoke_model_with_response_stream(client)


def _record_bedrock_usage(span: Any, response: Any) -> None:
    """Parse token usage from a Bedrock response dict."""
    # HTTP status
    http_meta = response.get("ResponseMetadata", {})
    http_status = http_meta.get("HTTPStatusCode")
    if http_status is not None:
        span.set_attribute("http.status_code", int(http_status))

    # Parse body — it's a StreamingBody; read() then parse JSON
    body = response.get("body")
    if body is None:
        return
    try:
        raw = body.read() if hasattr(body, "read") else body
        data = json.loads(raw) if isinstance(raw, bytes | str) else {}
    except Exception:  # noqa: BLE001
        return

    # Anthropic Claude on Bedrock
    usage = data.get("usage") or {}
    if isinstance(usage, dict):
        pt = usage.get("input_tokens") or 0
        ct = usage.get("output_tokens") or 0
        if pt:
            span.set_attribute("gen_ai.usage.input_tokens", int(pt))
        if ct:
            span.set_attribute("gen_ai.usage.output_tokens", int(ct))

    # Amazon Titan
    pt2 = data.get("inputTextTokenCount") or 0
    if not pt2:
        results = data.get("results") or []
        ct2 = sum(r.get("tokenCount", 0) for r in results if isinstance(r, dict))
    else:
        ct2 = sum(
            r.get("tokenCount", 0) for r in (data.get("results") or []) if isinstance(r, dict)
        )
    if pt2:
        span.set_attribute("gen_ai.usage.input_tokens", int(pt2))
    if ct2:
        span.set_attribute("gen_ai.usage.output_tokens", int(ct2))


def _patch_invoke_model(client: Any) -> None:
    if not hasattr(client, "invoke_model"):
        return

    def _patched(wrapped: Any, instance: Any, args: Any, kwargs: Any) -> Any:
        model_id: str = str(kwargs.get("modelId") or (args[0] if args else "unknown"))

        with _tracer.start_as_current_span(
            "aws_bedrock.invoke_model",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "aws_bedrock",
                "gen_ai.request.model": model_id,
                "llm.model_name": model_id,
                "aws.bedrock.model_id": model_id,
            },
        ) as span:
            try:
                result = wrapped(*args, **kwargs)
                _record_bedrock_usage(span, result)
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    wrapt.wrap_function_wrapper(client, "invoke_model", _patched)


def _patch_invoke_model_with_response_stream(client: Any) -> None:
    """Patch the streaming variant; emits a span for the request initiation."""
    if not hasattr(client, "invoke_model_with_response_stream"):
        return

    def _patched(wrapped: Any, instance: Any, args: Any, kwargs: Any) -> Any:
        model_id: str = str(kwargs.get("modelId") or (args[0] if args else "unknown"))

        with _tracer.start_as_current_span(
            "aws_bedrock.invoke_model_with_response_stream",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "aws_bedrock",
                "gen_ai.request.model": model_id,
                "llm.model_name": model_id,
                "aws.bedrock.model_id": model_id,
                "aws.bedrock.streaming": True,
            },
        ) as span:
            try:
                result = wrapped(*args, **kwargs)
                http_meta = result.get("ResponseMetadata", {})
                http_status = http_meta.get("HTTPStatusCode")
                if http_status is not None:
                    span.set_attribute("http.status_code", int(http_status))
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    wrapt.wrap_function_wrapper(client, "invoke_model_with_response_stream", _patched)

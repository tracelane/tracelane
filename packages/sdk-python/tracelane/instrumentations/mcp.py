"""MCP (Model Context Protocol) instrumentation for Tracelane.

Wraps MCP client's call_tool and read_resource methods to emit OTel spans.
MCP is the most-attacked agent surface (rug-pull detection, PR1 guardrail)
and the most under-built observability layer. This adapter provides
the foundation for Tracelane's MCP hash watcher (PP-PR1).

Example::

    from mcp import Client
    from tracelane.instrumentations.mcp import instrument_mcp

    client = Client()
    instrument_mcp(client)
    result = await client.call_tool("my_tool", {"arg": "value"})
    # Span emitted with mcp.tool_name and argument count
"""

from __future__ import annotations

from typing import Any

from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.mcp", "0.1.0")


def instrument_mcp(client: Any) -> None:
    """Wrap an MCP Client instance to emit OTel spans.

    Instruments call_tool() and read_resource() if present.

    Args:
        client: An mcp.Client or mcp.ClientSession instance.

    Note:
        Tool arguments are counted but never captured as span attributes
        to avoid inadvertent PII capture. The tool name is captured.
    """
    if hasattr(client, "call_tool"):
        _patch_call_tool(client)
    if hasattr(client, "read_resource"):
        _patch_read_resource(client)


def _patch_call_tool(client: Any) -> None:
    original = client.call_tool

    async def _patched(tool_name: Any, arguments: Any = None, **kwargs: Any) -> Any:
        arg_count = len(arguments) if isinstance(arguments, dict) else 0
        with _tracer.start_as_current_span(
            "mcp.call_tool",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "mcp",
                "mcp.tool_name": str(tool_name),
                "mcp.argument_count": arg_count,
            },
        ) as span:
            try:
                result = await original(tool_name, arguments, **kwargs)
                is_error = getattr(result, "isError", False)
                span.set_attribute("mcp.is_error", bool(is_error))
                content = getattr(result, "content", None)
                if isinstance(content, list):
                    span.set_attribute("mcp.content_count", len(content))
                span.set_status(StatusCode.ERROR if is_error else StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    client.call_tool = _patched


def _patch_read_resource(client: Any) -> None:
    original = client.read_resource

    async def _patched(uri: Any, **kwargs: Any) -> Any:
        with _tracer.start_as_current_span(
            "mcp.read_resource",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "mcp",
                "mcp.resource_uri": str(uri),
            },
        ) as span:
            try:
                result = await original(uri, **kwargs)
                contents = getattr(result, "contents", None)
                if isinstance(contents, list):
                    span.set_attribute("mcp.content_count", len(contents))
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    client.read_resource = _patched

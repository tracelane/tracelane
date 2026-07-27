"""Firecrawl instrumentation for Tracelane.

Wraps FirecrawlApp.scrape_url and FirecrawlApp.crawl_url to emit OTel spans.
Firecrawl spans are the cost-overrun surface for document-ingestion agents
— a single unconstrained crawl can run up thousands of pages. These spans
enable scrape-quality scoring and cost attribution at the page level.

Example::

    from firecrawl import FirecrawlApp
    from tracelane.instrumentations.firecrawl import instrument_firecrawl

    app = FirecrawlApp(api_key=os.environ["FIRECRAWL_API_KEY"])
    instrument_firecrawl(app)
    result = app.scrape_url("https://example.com")
    # Span emitted with firecrawl.url and firecrawl.success
"""

from __future__ import annotations

from typing import Any

from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.firecrawl", "0.1.0")


def instrument_firecrawl(app: Any) -> None:
    """Wrap a FirecrawlApp instance to emit OTel spans.

    Instruments scrape_url(), crawl_url(), and search() operations.

    Args:
        app: A firecrawl.FirecrawlApp instance.

    Note:
        URL is captured; page content is never captured.
        Pages-crawled count and success flag are recorded for cost attribution.
    """
    if hasattr(app, "scrape_url"):
        _patch_scrape_url(app)
    if hasattr(app, "crawl_url"):
        _patch_crawl_url(app)
    if hasattr(app, "search"):
        _patch_search(app)


def _patch_scrape_url(app: Any) -> None:
    original = app.scrape_url

    def _patched(url: Any = None, *args: Any, **kwargs: Any) -> Any:
        with _tracer.start_as_current_span(
            "firecrawl.scrape_url",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "firecrawl",
                "firecrawl.operation": "scrape_url",
                "firecrawl.url": str(url) if url else "",
            },
        ) as span:
            try:
                result = original(url, *args, **kwargs)
                success = getattr(result, "success", True)
                span.set_attribute("firecrawl.success", bool(success))
                content = getattr(result, "markdown", None) or getattr(result, "content", None)
                if content:
                    span.set_attribute("firecrawl.content_length", len(str(content)))
                span.set_status(
                    StatusCode.OK if success else StatusCode.ERROR,
                    "" if success else "scrape failed",
                )
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    app.scrape_url = _patched


def _patch_crawl_url(app: Any) -> None:
    original = app.crawl_url

    def _patched(url: Any = None, *args: Any, **kwargs: Any) -> Any:
        params = kwargs.get("params", args[0] if args else {})
        limit = (params or {}).get("limit", 100) if isinstance(params, dict) else 100
        with _tracer.start_as_current_span(
            "firecrawl.crawl_url",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "firecrawl",
                "firecrawl.operation": "crawl_url",
                "firecrawl.url": str(url) if url else "",
                "firecrawl.limit": int(limit),
            },
        ) as span:
            try:
                result = original(url, *args, **kwargs)
                success = getattr(result, "success", True)
                span.set_attribute("firecrawl.success", bool(success))
                data = getattr(result, "data", None)
                if isinstance(data, list):
                    span.set_attribute("firecrawl.pages_crawled", len(data))
                span.set_status(
                    StatusCode.OK if success else StatusCode.ERROR,
                    "" if success else "crawl failed",
                )
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    app.crawl_url = _patched


def _patch_search(app: Any) -> None:
    original = app.search

    def _patched(query: Any = None, *args: Any, **kwargs: Any) -> Any:
        with _tracer.start_as_current_span(
            "firecrawl.search",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "firecrawl",
                "firecrawl.operation": "search",
            },
        ) as span:
            try:
                result = original(query, *args, **kwargs)
                data = getattr(result, "data", None)
                if isinstance(data, list):
                    span.set_attribute("firecrawl.results_count", len(data))
                span.set_status(StatusCode.OK)
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    app.search = _patched

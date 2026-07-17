/**
 * Firecrawl instrumentation for Tracelane.
 *
 * Wraps FirecrawlApp scrapeUrl() and crawlUrl() to emit OTel spans.
 * Firecrawl spans are the cost-overrun surface for document-ingestion agents
 * — unconstrained crawls can consume thousands of pages and dollars.
 * These spans enable cost attribution and scrape-quality scoring.
 *
 * @example
 * ```ts
 * import FirecrawlApp from "@mendable/firecrawl-js";
 * import { instrumentFirecrawl } from "@tracelanedev/sdk/firecrawl";
 *
 * const app = new FirecrawlApp({ apiKey: process.env.FIRECRAWL_API_KEY! });
 * instrumentFirecrawl(app);
 * const result = await app.scrapeUrl("https://example.com");
 * ```
 */

import { SpanKind, SpanStatusCode, trace } from "@opentelemetry/api";

const tracer = trace.getTracer("@tracelanedev/sdk-firecrawl", "0.1.0");

interface FirecrawlAppLike {
	scrapeUrl: (...args: unknown[]) => Promise<unknown>;
	crawlUrl?: (...args: unknown[]) => Promise<unknown>;
	search?: (...args: unknown[]) => Promise<unknown>;
}

/**
 * Instrument a FirecrawlApp instance to emit OTel spans.
 *
 * @param app - A @mendable/firecrawl-js FirecrawlApp instance
 */
export function instrumentFirecrawl(app: FirecrawlAppLike): void {
	_patchScrapeUrl(app);
	if (app.crawlUrl) {
		_patchCrawlUrl(
			app as Required<Pick<FirecrawlAppLike, "crawlUrl">> & FirecrawlAppLike,
		);
	}
	if (app.search) {
		_patchSearch(
			app as Required<Pick<FirecrawlAppLike, "search">> & FirecrawlAppLike,
		);
	}
}

function _patchScrapeUrl(app: FirecrawlAppLike): void {
	const originalScrapeUrl = app.scrapeUrl.bind(app);

	app.scrapeUrl = async (...args: unknown[]) => {
		const url = String(args[0] ?? "");

		return tracer.startActiveSpan(
			"firecrawl.scrapeUrl",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "firecrawl",
					"firecrawl.operation": "scrapeUrl",
					"firecrawl.url": url,
				},
			},
			async (span) => {
				try {
					const result = (await originalScrapeUrl(...args)) as Record<
						string,
						unknown
					>;
					const success = Boolean(result.success ?? true);
					span.setAttribute("firecrawl.success", success);
					const content = result.markdown ?? result.content;
					if (typeof content === "string") {
						span.setAttribute("firecrawl.content_length", content.length);
					}
					span.setStatus({
						code: success ? SpanStatusCode.OK : SpanStatusCode.ERROR,
						message: success ? "" : "scrape failed",
					});
					return result;
				} catch (e) {
					span.recordException(e as Error);
					span.setStatus({ code: SpanStatusCode.ERROR, message: String(e) });
					throw e;
				} finally {
					span.end();
				}
			},
		);
	};
}

function _patchCrawlUrl(app: {
	crawlUrl: (...args: unknown[]) => Promise<unknown>;
}): void {
	const originalCrawlUrl = app.crawlUrl.bind(app);

	app.crawlUrl = async (...args: unknown[]) => {
		const url = String(args[0] ?? "");
		const opts = args[1] as Record<string, unknown> | undefined;
		const crawlerOpts = opts?.crawlerOptions as
			| Record<string, unknown>
			| undefined;
		const limit = Number(opts?.limit ?? crawlerOpts?.limit ?? 100);

		return tracer.startActiveSpan(
			"firecrawl.crawlUrl",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "firecrawl",
					"firecrawl.operation": "crawlUrl",
					"firecrawl.url": url,
					"firecrawl.limit": limit,
				},
			},
			async (span) => {
				try {
					const result = (await originalCrawlUrl(...args)) as Record<
						string,
						unknown
					>;
					const success = Boolean(result.success ?? true);
					span.setAttribute("firecrawl.success", success);
					const data = result.data;
					if (Array.isArray(data)) {
						span.setAttribute("firecrawl.pages_crawled", data.length);
					}
					span.setStatus({
						code: success ? SpanStatusCode.OK : SpanStatusCode.ERROR,
						message: success ? "" : "crawl failed",
					});
					return result;
				} catch (e) {
					span.recordException(e as Error);
					span.setStatus({ code: SpanStatusCode.ERROR, message: String(e) });
					throw e;
				} finally {
					span.end();
				}
			},
		);
	};
}

function _patchSearch(app: {
	search: (...args: unknown[]) => Promise<unknown>;
}): void {
	const originalSearch = app.search.bind(app);

	app.search = async (...args: unknown[]) => {
		return tracer.startActiveSpan(
			"firecrawl.search",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "firecrawl",
					"firecrawl.operation": "search",
				},
			},
			async (span) => {
				try {
					const result = (await originalSearch(...args)) as Record<
						string,
						unknown
					>;
					const data = result.data;
					if (Array.isArray(data)) {
						span.setAttribute("firecrawl.results_count", data.length);
					}
					span.setStatus({ code: SpanStatusCode.OK });
					return result;
				} catch (e) {
					span.recordException(e as Error);
					span.setStatus({ code: SpanStatusCode.ERROR, message: String(e) });
					throw e;
				} finally {
					span.end();
				}
			},
		);
	};
}

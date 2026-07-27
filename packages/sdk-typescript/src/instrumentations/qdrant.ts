/**
 * Qdrant instrumentation for Tracelane.
 *
 * Wraps QdrantClient search() and upsert() to emit OTel spans.
 * Qdrant is Rust-native and Apache 2.0 — the natural vector DB companion
 * to Tracelane's stack. These spans enrich the agent trace with vector
 * retrieval context for RAG quality analysis.
 *
 * @example
 * ```ts
 * import { QdrantClient } from "@qdrant/js-client-rest";
 * import { instrumentQdrant } from "@tracelanedev/sdk/qdrant";
 *
 * const client = new QdrantClient({ url: "http://localhost:6333" });
 * instrumentQdrant(client);
 * const results = await client.search("my-collection", { vector: [...], limit: 5 });
 * ```
 */

import { SpanKind, SpanStatusCode, trace } from "@opentelemetry/api";

const tracer = trace.getTracer("@tracelanedev/sdk-qdrant", "0.1.0");

interface QdrantClientLike {
	search: (...args: unknown[]) => Promise<unknown>;
	upsert?: (...args: unknown[]) => Promise<unknown>;
	query?: (...args: unknown[]) => Promise<unknown>;
}

/**
 * Instrument a QdrantClient instance to emit OTel spans.
 *
 * @param client - A @qdrant/js-client-rest QdrantClient instance
 */
export function instrumentQdrant(client: QdrantClientLike): void {
	_patchSearch(client);
	if (client.upsert) {
		_patchUpsert(
			client as Required<Pick<QdrantClientLike, "upsert">> & QdrantClientLike,
		);
	}
	if (client.query) {
		_patchQuery(
			client as Required<Pick<QdrantClientLike, "query">> & QdrantClientLike,
		);
	}
}

function _patchSearch(client: QdrantClientLike): void {
	const originalSearch = client.search.bind(client);

	client.search = async (...args: unknown[]) => {
		const collectionName = String(args[0] ?? "unknown");
		const opts = args[1] as Record<string, unknown> | undefined;
		const limit = Number(opts?.limit ?? 10);

		return tracer.startActiveSpan(
			"qdrant.search",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "qdrant",
					"db.system": "qdrant",
					"db.operation.name": "search",
					"db.collection.name": collectionName,
					"qdrant.limit": limit,
				},
			},
			async (span) => {
				try {
					const results = (await originalSearch(...args)) as unknown[];
					const count = Array.isArray(results) ? results.length : 0;
					span.setAttribute("qdrant.results_count", count);
					span.setStatus({ code: SpanStatusCode.OK });
					return results;
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

function _patchUpsert(client: {
	upsert: (...args: unknown[]) => Promise<unknown>;
}): void {
	const originalUpsert = client.upsert.bind(client);

	client.upsert = async (...args: unknown[]) => {
		const collectionName = String(args[0] ?? "unknown");
		const body = args[1] as Record<string, unknown> | undefined;
		const points = body?.points;
		const pointCount = Array.isArray(points) ? points.length : 0;

		return tracer.startActiveSpan(
			"qdrant.upsert",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "qdrant",
					"db.system": "qdrant",
					"db.operation.name": "upsert",
					"db.collection.name": collectionName,
					"qdrant.upsert_count": pointCount,
				},
			},
			async (span) => {
				try {
					const result = await originalUpsert(...args);
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

function _patchQuery(client: {
	query: (...args: unknown[]) => Promise<unknown>;
}): void {
	const originalQuery = client.query.bind(client);

	client.query = async (...args: unknown[]) => {
		const collectionName = String(args[0] ?? "unknown");

		return tracer.startActiveSpan(
			"qdrant.query",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "qdrant",
					"db.system": "qdrant",
					"db.operation.name": "query",
					"db.collection.name": collectionName,
				},
			},
			async (span) => {
				try {
					const result = (await originalQuery(...args)) as Record<
						string,
						unknown
					>;
					const points = result.points;
					if (Array.isArray(points)) {
						span.setAttribute("qdrant.results_count", points.length);
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

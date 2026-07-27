/**
 * Pinecone instrumentation for Tracelane.
 *
 * Wraps Pinecone Index query() and upsert() to emit OTel spans enriched with
 * retrieval metadata. RAG retrieval spans let operators correlate embedding
 * quality, match scores, and retrieval latency with downstream LLM quality.
 *
 * @example
 * ```ts
 * import { Pinecone } from "@pinecone-database/pinecone";
 * import { instrumentPinecone } from "@tracelanedev/sdk/pinecone";
 *
 * const pc = new Pinecone({ apiKey: process.env.PINECONE_API_KEY! });
 * const index = pc.index("my-index");
 * instrumentPinecone(index);
 * const results = await index.query({ vector: [...], topK: 5 });
 * ```
 */

import { SpanKind, SpanStatusCode, trace } from "@opentelemetry/api";

const tracer = trace.getTracer("@tracelanedev/sdk-pinecone", "0.1.0");

interface PineconeIndexLike {
	query: (...args: unknown[]) => Promise<unknown>;
	upsert?: (...args: unknown[]) => Promise<unknown>;
	deleteOne?: (...args: unknown[]) => Promise<unknown>;
	deleteMany?: (...args: unknown[]) => Promise<unknown>;
}

/**
 * Instrument a Pinecone Index instance to emit OTel spans.
 *
 * @param index - A @pinecone-database/pinecone Index instance
 */
export function instrumentPinecone(index: PineconeIndexLike): void {
	_patchQuery(index);
	if (index.upsert) {
		_patchUpsert(index as Required<PineconeIndexLike>);
	}
}

function _patchQuery(index: PineconeIndexLike): void {
	const originalQuery = index.query.bind(index);

	index.query = async (...args: unknown[]) => {
		const opts = args[0] as Record<string, unknown> | undefined;
		const topK = Number(opts?.topK ?? 10);
		const namespace = String(opts?.namespace ?? "");

		return tracer.startActiveSpan(
			"pinecone.index.query",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "pinecone",
					"db.system": "pinecone",
					"db.operation.name": "query",
					"pinecone.top_k": topK,
					"pinecone.namespace": namespace,
				},
			},
			async (span) => {
				try {
					const result = (await originalQuery(...args)) as Record<
						string,
						unknown
					>;
					const matches = result.matches;
					if (Array.isArray(matches)) {
						span.setAttribute("pinecone.matches_count", matches.length);
						const scores = matches
							.map((m) => (m as Record<string, unknown>).score)
							.filter((s): s is number => typeof s === "number");
						if (scores.length > 0) {
							span.setAttribute("pinecone.top_score", Math.max(...scores));
						}
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

function _patchUpsert(index: {
	upsert: (...args: unknown[]) => Promise<unknown>;
}): void {
	const originalUpsert = index.upsert.bind(index);

	index.upsert = async (...args: unknown[]) => {
		const vectors = args[0];
		const vectorCount = Array.isArray(vectors) ? vectors.length : 0;

		return tracer.startActiveSpan(
			"pinecone.index.upsert",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "pinecone",
					"db.system": "pinecone",
					"db.operation.name": "upsert",
					"pinecone.upsert_count": vectorCount,
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

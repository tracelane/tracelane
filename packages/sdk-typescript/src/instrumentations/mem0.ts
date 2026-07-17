/**
 * Mem0 instrumentation for Tracelane.
 *
 * Wraps Mem0 MemoryClient add() and search() to emit OTel spans.
 * establishes the observability baseline for memory hit rates, staleness
 * detection, and memory-augmented agent quality analysis.
 *
 * @example
 * ```ts
 * import { MemoryClient } from "mem0ai";
 * import { instrumentMem0 } from "@tracelanedev/sdk/mem0";
 *
 * const client = new MemoryClient({ apiKey: process.env.MEM0_API_KEY! });
 * instrumentMem0(client);
 * await client.add([{ role: "user", content: "..." }], { user_id: "alice" });
 * ```
 */

import { SpanKind, SpanStatusCode, trace } from "@opentelemetry/api";

const tracer = trace.getTracer("@tracelanedev/sdk-mem0", "0.1.0");

interface Mem0ClientLike {
	add: (...args: unknown[]) => Promise<unknown>;
	search: (...args: unknown[]) => Promise<unknown>;
	getAll?: (...args: unknown[]) => Promise<unknown>;
}

/**
 * Instrument a Mem0 MemoryClient instance to emit OTel spans.
 *
 * @param client - A mem0ai MemoryClient instance
 */
export function instrumentMem0(client: Mem0ClientLike): void {
	_patchAdd(client);
	_patchSearch(client);
	if (client.getAll) {
		_patchGetAll(
			client as Required<Pick<Mem0ClientLike, "getAll">> & Mem0ClientLike,
		);
	}
}

function _patchAdd(client: Mem0ClientLike): void {
	const originalAdd = client.add.bind(client);

	client.add = async (...args: unknown[]) => {
		const messages = args[0];
		const opts = args[1] as Record<string, unknown> | undefined;
		const userId = String(opts?.user_id ?? "");
		const messageCount = Array.isArray(messages) ? messages.length : 1;

		return tracer.startActiveSpan(
			"mem0.memory.add",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "mem0",
					"mem0.operation": "add",
					"mem0.user_id": userId,
					"mem0.message_count": messageCount,
				},
			},
			async (span) => {
				try {
					const result = (await originalAdd(...args)) as Record<
						string,
						unknown
					>;
					const results = result.results;
					if (Array.isArray(results)) {
						span.setAttribute("mem0.memories_added", results.length);
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

function _patchSearch(client: Mem0ClientLike): void {
	const originalSearch = client.search.bind(client);

	client.search = async (...args: unknown[]) => {
		const opts = args[1] as Record<string, unknown> | undefined;
		const userId = String(opts?.user_id ?? "");
		const limit = Number(opts?.limit ?? opts?.top_k ?? 10);

		return tracer.startActiveSpan(
			"mem0.memory.search",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "mem0",
					"mem0.operation": "search",
					"mem0.user_id": userId,
					"mem0.limit": limit,
				},
			},
			async (span) => {
				try {
					const result = (await originalSearch(...args)) as Record<
						string,
						unknown
					>;
					const results = result.results ?? result;
					if (Array.isArray(results)) {
						span.setAttribute("mem0.results_count", results.length);
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

function _patchGetAll(client: {
	getAll: (...args: unknown[]) => Promise<unknown>;
}): void {
	const originalGetAll = client.getAll.bind(client);

	client.getAll = async (...args: unknown[]) => {
		const opts = args[0] as Record<string, unknown> | undefined;
		const userId = String(opts?.user_id ?? "");

		return tracer.startActiveSpan(
			"mem0.memory.getAll",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "mem0",
					"mem0.operation": "getAll",
					"mem0.user_id": userId,
				},
			},
			async (span) => {
				try {
					const result = (await originalGetAll(...args)) as Record<
						string,
						unknown
					>;
					const results = result.results ?? result;
					if (Array.isArray(results)) {
						span.setAttribute("mem0.memories_count", results.length);
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

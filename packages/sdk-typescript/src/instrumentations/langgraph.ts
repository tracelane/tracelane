/**
 * LangGraph JS instrumentation for Tracelane.
 *
 * Wraps compiled LangGraph graphs' invoke(), ainvoke(), and stream() methods
 * to emit OTel spans for agent graph execution. Captures graph name, step
 * count, and message count. These spans feed Tracelane's stuck-loop
 * predictor (PP-PR4).
 *
 * @example
 * ```ts
 * import { StateGraph } from "@langchain/langgraph";
 * import { instrumentLangGraph } from "@tracelanedev/sdk/langgraph";
 *
 * const graph = new StateGraph(MyAnnotation).addNode(...).compile();
 * instrumentLangGraph(graph);
 * const result = await graph.invoke({ messages: [...] });
 * ```
 */

import { SpanKind, SpanStatusCode, trace } from "@opentelemetry/api";

const tracer = trace.getTracer("@tracelanedev/sdk-langgraph", "0.1.0");

interface LangGraphLike {
	invoke: (...args: unknown[]) => Promise<unknown>;
	stream?: (...args: unknown[]) => AsyncIterable<unknown>;
	name?: string;
}

/**
 * Instrument a compiled LangGraph graph to emit OTel spans.
 *
 * @param graph - A compiled LangGraph graph instance (CompiledStateGraph or similar)
 */
export function instrumentLangGraph(graph: LangGraphLike): void {
	const graphName = graph.name ?? "unknown";

	_patchInvoke(graph, graphName);
	if (graph.stream) {
		_patchStream(
			graph as LangGraphLike & {
				stream: (...args: unknown[]) => AsyncIterable<unknown>;
			},
			graphName,
		);
	}
}

function _patchInvoke(graph: LangGraphLike, graphName: string): void {
	const originalInvoke = graph.invoke.bind(graph);

	graph.invoke = async (...args: unknown[]) => {
		return tracer.startActiveSpan(
			"langgraph.graph.invoke",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "langgraph",
					"langgraph.graph_name": graphName,
					"langgraph.invocation_type": "invoke",
				},
			},
			async (span) => {
				try {
					const result = (await originalInvoke(...args)) as Record<
						string,
						unknown
					>;
					_recordResult(span, result);
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

function _patchStream(
	graph: LangGraphLike & { stream: NonNullable<LangGraphLike["stream"]> },
	graphName: string,
): void {
	const originalStream = graph.stream.bind(graph);

	graph.stream = async function* (...args: unknown[]) {
		const span = tracer.startSpan("langgraph.graph.stream", {
			kind: SpanKind.CLIENT,
			attributes: {
				"gen_ai.provider.name": "langgraph",
				"langgraph.graph_name": graphName,
				"langgraph.invocation_type": "stream",
			},
		});
		let stepCount = 0;
		try {
			for await (const chunk of originalStream(...args)) {
				stepCount++;
				yield chunk;
			}
			span.setAttribute("langgraph.step_count", stepCount);
			span.setStatus({ code: SpanStatusCode.OK });
		} catch (e) {
			span.recordException(e as Error);
			span.setStatus({ code: SpanStatusCode.ERROR, message: String(e) });
			throw e;
		} finally {
			span.end();
		}
	};
}

function _recordResult(
	span: ReturnType<typeof tracer.startSpan>,
	result: Record<string, unknown>,
): void {
	const step = result.__step__;
	if (typeof step === "number") {
		span.setAttribute("langgraph.step_count", step);
	}
	const messages = result.messages;
	if (Array.isArray(messages)) {
		span.setAttribute("langgraph.messages_count", messages.length);
	}
}

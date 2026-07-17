/**
 * LangChain JS instrumentation for Tracelane.
 *
 * Wraps BaseChatModel.invoke (and the optional ainvoke alias) to emit OTel
 * spans for every LangChain chat-model invocation. Captures model name,
 * token counts from response_metadata, and latency. Never captures API keys,
 * prompt messages, or raw reply content.
 *
 * @example
 * ```ts
 * import { ChatOpenAI } from "@langchain/openai";
 * import { instrumentLangChain } from "@tracelanedev/sdk/langchain";
 *
 * const model = new ChatOpenAI({ model: "gpt-4o" });
 * instrumentLangChain(model);
 * // All model.invoke() calls now emit langchain.chat.invoke spans
 * ```
 */

import { SpanKind, SpanStatusCode, trace } from "@opentelemetry/api";

const tracer = trace.getTracer("@tracelanedev/sdk-langchain", "0.1.0");

/** Minimal structural type covering BaseChatModel and LLMChain objects. */
interface LangChainModelLike {
	invoke: (...args: unknown[]) => Promise<unknown>;
	/** Optional — exposed on most LangChain chat model classes. */
	modelName?: string;
	/** Alternate attribute used by some providers (e.g. @langchain/anthropic). */
	model?: string;
}

/**
 * Instrument a LangChain chat model (or chain) instance to emit OTel spans.
 *
 * @param model - A BaseChatModel or LLMChain instance with an invoke() method.
 */
export function instrumentLangChain(model: LangChainModelLike): void {
	const modelName = _resolveModelName(model);
	_patchInvoke(model, modelName);
}

function _resolveModelName(model: LangChainModelLike): string {
	if (typeof model.modelName === "string" && model.modelName) {
		return model.modelName;
	}
	if (typeof model.model === "string" && model.model) {
		return model.model;
	}
	return "unknown";
}

function _patchInvoke(model: LangChainModelLike, modelName: string): void {
	const originalInvoke = model.invoke.bind(model);

	model.invoke = async (...args: unknown[]) => {
		return tracer.startActiveSpan(
			"langchain.chat.invoke",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "langchain",
					"gen_ai.request.model": modelName,
					"llm.model_name": modelName,
				},
			},
			async (span) => {
				try {
					const result = await originalInvoke(...args);
					_recordUsage(span, result);
					span.setStatus({ code: SpanStatusCode.OK });
					return result;
				} catch (err) {
					span.recordException(err as Error);
					span.setStatus({
						code: SpanStatusCode.ERROR,
						message: err instanceof Error ? err.message : String(err),
					});
					throw err;
				} finally {
					span.end();
				}
			},
		);
	};
}

function _recordUsage(
	span: ReturnType<typeof tracer.startSpan>,
	result: unknown,
): void {
	if (result === null || typeof result !== "object") {
		return;
	}

	// AIMessage path: result.response_metadata.tokenUsage or result.usage_metadata
	const res = result as Record<string, unknown>;

	const responseMeta = res.response_metadata;
	if (responseMeta !== null && typeof responseMeta === "object") {
		const meta = responseMeta as Record<string, unknown>;
		const tokenUsage = (meta.tokenUsage ?? meta.token_usage) as
			| Record<string, unknown>
			| undefined;
		if (tokenUsage && typeof tokenUsage === "object") {
			const prompt =
				(tokenUsage.promptTokens as number | undefined) ??
				(tokenUsage.prompt_tokens as number | undefined);
			const completion =
				(tokenUsage.completionTokens as number | undefined) ??
				(tokenUsage.completion_tokens as number | undefined);
			if (typeof prompt === "number") {
				span.setAttribute("gen_ai.usage.input_tokens", prompt);
			}
			if (typeof completion === "number") {
				span.setAttribute("gen_ai.usage.output_tokens", completion);
			}
		}
	}

	// Alternate path: result.usage_metadata (LangChain >= 0.2 AIMessage)
	const usageMeta = res.usage_metadata as Record<string, unknown> | undefined;
	if (usageMeta && typeof usageMeta === "object") {
		const inputT = usageMeta.input_tokens as number | undefined;
		const outputT = usageMeta.output_tokens as number | undefined;
		if (typeof inputT === "number") {
			span.setAttribute("gen_ai.usage.input_tokens", inputT);
		}
		if (typeof outputT === "number") {
			span.setAttribute("gen_ai.usage.output_tokens", outputT);
		}
	}
}

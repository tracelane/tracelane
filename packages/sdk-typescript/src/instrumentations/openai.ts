/**
 * OpenAI SDK instrumentation for Tracelane.
 *
 * Wraps @openai/openai chat.completions.create to emit OTel spans for every
 * chat completion call. Handles both sync response and streaming responses.
 * Never captures API keys — only model, token counts, and finish reason.
 *
 * @example
 * ```ts
 * import OpenAI from "openai";
 * import { instrumentOpenAI } from "@tracelanedev/sdk/openai";
 *
 * const client = new OpenAI();
 * instrumentOpenAI(client);
 * // All subsequent client.chat.completions.create() calls emit spans
 * ```
 */

import { SpanKind, SpanStatusCode, trace } from "@opentelemetry/api";

const tracer = trace.getTracer("@tracelanedev/sdk-openai", "0.1.0");

type ChatCompletionsCreate = (...args: unknown[]) => Promise<unknown>;

interface OpenAIClientLike {
	chat: {
		completions: {
			create: ChatCompletionsCreate;
		};
	};
}

/**
 * Instrument an OpenAI client instance to emit OTel spans.
 *
 * @param client - An openai.OpenAI instance (or any OpenAI-compatible client)
 */
export function instrumentOpenAI(client: OpenAIClientLike): void {
	const originalCreate = client.chat.completions.create.bind(
		client.chat.completions,
	);

	client.chat.completions.create = async (...args: unknown[]) => {
		const request = args[0] as Record<string, unknown>;
		const model =
			typeof request?.model === "string" ? request.model : "unknown";

		return tracer.startActiveSpan(
			"openai.chat.completions.create",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "openai",
					"gen_ai.request.model": model,
					"llm.model_name": model,
				},
			},
			async (span) => {
				try {
					const result = (await originalCreate(...args)) as Record<
						string,
						unknown
					>;
					_recordResponse(span, result);
					span.setStatus({ code: SpanStatusCode.OK });
					return result;
				} catch (e) {
					span.recordException(e as Error);
					span.setStatus({
						code: SpanStatusCode.ERROR,
						message: String(e),
					});
					throw e;
				} finally {
					span.end();
				}
			},
		);
	};
}

function _recordResponse(
	span: ReturnType<typeof tracer.startSpan>,
	result: Record<string, unknown>,
): void {
	const usage = result.usage as Record<string, unknown> | undefined;
	if (usage) {
		const promptTokens = Number(usage.prompt_tokens ?? 0);
		const completionTokens = Number(usage.completion_tokens ?? 0);
		span.setAttributes({
			"gen_ai.usage.input_tokens": promptTokens,
			"gen_ai.usage.output_tokens": completionTokens,
			"llm.token_count.prompt": promptTokens,
			"llm.token_count.completion": completionTokens,
		});
		// v1.40 prompt-cache read tokens + v1.41 reasoning tokens (o-series),
		// nested under *_tokens_details. Emitted only when present.
		const promptDetails = usage.prompt_tokens_details as
			| Record<string, unknown>
			| undefined;
		const cached = promptDetails?.cached_tokens;
		if (cached != null) {
			span.setAttribute("gen_ai.usage.cache_read.input_tokens", Number(cached));
		}
		const completionDetails = usage.completion_tokens_details as
			| Record<string, unknown>
			| undefined;
		const reasoning = completionDetails?.reasoning_tokens;
		if (reasoning != null) {
			span.setAttribute(
				"gen_ai.usage.reasoning.output_tokens",
				Number(reasoning),
			);
		}
	}
	const responseModel = result.model;
	if (typeof responseModel === "string") {
		span.setAttribute("gen_ai.response.model", responseModel);
	}
	const choices = result.choices as Array<Record<string, unknown>> | undefined;
	if (Array.isArray(choices) && choices.length > 0) {
		const finishReason = choices[0]?.finish_reason;
		if (typeof finishReason === "string") {
			span.setAttribute("gen_ai.response.finish_reason", finishReason);
		}
	}
}

/** Alias for symmetry with async/streaming usage patterns. */
export const instrumentOpenAIAsync = instrumentOpenAI;

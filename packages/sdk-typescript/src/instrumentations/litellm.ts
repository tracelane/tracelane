/**
 * LiteLLM-compatible client instrumentation for Tracelane.
 *
 * LiteLLM exposes an OpenAI-compatible API. This adapter wraps any
 * OpenAI-compatible client that is being used as a LiteLLM proxy,
 * overriding gen_ai.provider.name to "litellm" so spans are correctly attributed.
 *
 * @example
 * ```ts
 * import OpenAI from "openai";
 * import { instrumentLiteLLM } from "@tracelanedev/sdk/litellm";
 *
 * const client = new OpenAI({
 *   baseURL: "http://localhost:4000",  // LiteLLM proxy
 *   apiKey: process.env.LITELLM_API_KEY!,
 * });
 * instrumentLiteLLM(client);
 * ```
 */

import { SpanKind, SpanStatusCode, trace } from "@opentelemetry/api";

const tracer = trace.getTracer("@tracelanedev/sdk-litellm", "0.1.0");

interface LiteLLMClientLike {
	chat: {
		completions: {
			create: (...args: unknown[]) => Promise<unknown>;
		};
	};
}

/**
 * Instrument an OpenAI-compatible client pointed at a LiteLLM proxy.
 *
 * @param client - An OpenAI client instance with baseURL pointing to LiteLLM
 */
export function instrumentLiteLLM(client: LiteLLMClientLike): void {
	const originalCreate = client.chat.completions.create.bind(
		client.chat.completions,
	);

	client.chat.completions.create = async (...args: unknown[]) => {
		const request = args[0] as Record<string, unknown>;
		const model =
			typeof request?.model === "string" ? request.model : "unknown";

		return tracer.startActiveSpan(
			"litellm.chat.completions.create",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "litellm",
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
					_recordTokenUsage(span, result);
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

function _recordTokenUsage(
	span: ReturnType<typeof tracer.startSpan>,
	result: Record<string, unknown>,
): void {
	const usage = result.usage as Record<string, unknown> | undefined;
	if (usage) {
		span.setAttributes({
			"gen_ai.usage.input_tokens": Number(usage.prompt_tokens ?? 0),
			"gen_ai.usage.output_tokens": Number(usage.completion_tokens ?? 0),
		});
	}
	if (typeof result.model === "string") {
		span.setAttribute("gen_ai.response.model", result.model);
	}
}

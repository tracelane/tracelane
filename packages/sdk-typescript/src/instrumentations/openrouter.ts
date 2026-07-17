/**
 * OpenRouter instrumentation for Tracelane.
 *
 * OpenRouter uses the OpenAI SDK with a different base URL. This adapter
 * tags spans with gen_ai.provider.name = "openrouter" and captures the routed
 * model from the response (OpenRouter may select a different model
 * than the one requested via its routing logic).
 *
 * @example
 * ```ts
 * import OpenAI from "openai";
 * import { instrumentOpenRouter } from "@tracelanedev/sdk/openrouter";
 *
 * const client = new OpenAI({
 *   baseURL: "https://openrouter.ai/api/v1",
 *   apiKey: process.env.OPENROUTER_API_KEY!,
 * });
 * instrumentOpenRouter(client);
 * ```
 */

import { SpanKind, SpanStatusCode, trace } from "@opentelemetry/api";

const tracer = trace.getTracer("@tracelanedev/sdk-openrouter", "0.1.0");

interface OpenRouterClientLike {
	chat: {
		completions: {
			create: (...args: unknown[]) => Promise<unknown>;
		};
	};
}

/**
 * Instrument an OpenAI client pointed at OpenRouter.
 *
 * @param client - An OpenAI client with baseURL = https://openrouter.ai/api/v1
 */
export function instrumentOpenRouter(client: OpenRouterClientLike): void {
	const originalCreate = client.chat.completions.create.bind(
		client.chat.completions,
	);

	client.chat.completions.create = async (...args: unknown[]) => {
		const request = args[0] as Record<string, unknown>;
		const requestedModel =
			typeof request?.model === "string" ? request.model : "unknown";

		return tracer.startActiveSpan(
			"openrouter.chat.completions.create",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "openrouter",
					"gen_ai.request.model": requestedModel,
					"llm.model_name": requestedModel,
				},
			},
			async (span) => {
				try {
					const result = (await originalCreate(...args)) as Record<
						string,
						unknown
					>;
					const usage = result.usage as Record<string, unknown> | undefined;
					if (usage) {
						span.setAttributes({
							"gen_ai.usage.input_tokens": Number(usage.prompt_tokens ?? 0),
							"gen_ai.usage.output_tokens": Number(
								usage.completion_tokens ?? 0,
							),
						});
					}
					// OpenRouter returns the actual routed model in response.model
					if (typeof result.model === "string") {
						span.setAttributes({
							"gen_ai.response.model": result.model,
							"openrouter.route": result.model,
						});
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

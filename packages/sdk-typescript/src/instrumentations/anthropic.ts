/**
 * Anthropic SDK instrumentation for Tracelane.
 *
 * Wraps @anthropic-ai/sdk to emit OTel spans for every Messages API call.
 * Uses monkey-patching to avoid requiring changes to user code.
 * Never reads or logs API keys — only captures model/token/latency metadata.
 *
 * @example
 * ```ts
 * import Anthropic from "@anthropic-ai/sdk";
 * import { instrumentAnthropic } from "@tracelanedev/sdk/anthropic";
 *
 * const client = new Anthropic();
 * instrumentAnthropic(client);
 * // All subsequent client.messages.create() calls emit spans
 * ```
 */

import { type Span, SpanKind, SpanStatusCode, trace } from "@opentelemetry/api";

const tracer = trace.getTracer("@tracelanedev/sdk-anthropic", "0.1.0");

/**
 * Emit OTel GenAI v1.41 token-usage attributes from an Anthropic response,
 * including the v1.40 prompt-cache counters when present. Never throws —
 * token accounting must not break the caller's response.
 */
function setUsageAttributes(span: Span, result: Record<string, unknown>): void {
	const usage = result.usage as Record<string, unknown> | undefined;
	if (!usage) {
		return;
	}
	const inputTokens = usage.input_tokens;
	if (inputTokens != null) {
		span.setAttribute("gen_ai.usage.input_tokens", Number(inputTokens));
	}
	const outputTokens = usage.output_tokens;
	if (outputTokens != null) {
		span.setAttribute("gen_ai.usage.output_tokens", Number(outputTokens));
	}
	const cacheRead = usage.cache_read_input_tokens;
	if (cacheRead != null) {
		span.setAttribute(
			"gen_ai.usage.cache_read.input_tokens",
			Number(cacheRead),
		);
	}
	const cacheCreation = usage.cache_creation_input_tokens;
	if (cacheCreation != null) {
		span.setAttribute(
			"gen_ai.usage.cache_creation.input_tokens",
			Number(cacheCreation),
		);
	}
}

/**
 * Instrument an Anthropic client instance to emit OTel spans.
 *
 * @param client - An @anthropic-ai/sdk Anthropic instance
 */
export function instrumentAnthropic(client: {
	messages: {
		create: (...args: unknown[]) => Promise<unknown>;
	};
}): void {
	const originalCreate = client.messages.create.bind(client.messages);

	client.messages.create = async (...args: unknown[]) => {
		const request = args[0] as Record<string, unknown>;
		const model =
			typeof request?.model === "string" ? request.model : "unknown";

		return tracer.startActiveSpan(
			"anthropic.messages.create",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "anthropic",
					"gen_ai.request.model": model,
					"llm.model_name": model,
				},
			},
			async (span) => {
				try {
					const result = await originalCreate(...args);
					setUsageAttributes(span, result as Record<string, unknown>);
					span.setStatus({ code: SpanStatusCode.OK });
					return result;
				} catch (err) {
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

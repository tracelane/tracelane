/**
 * Claude Code harness instrumentation for Tracelane.
 *
 * Instruments Claude Code SDK or harness API calls to emit OTel spans.
 * This is the highest-value harness adapter — it lets teams route their
 * AI-assisted development sessions through the same observability stack
 * monitoring their production agents.
 *
 * Works with any object exposing a `run(prompt, options?)` method,
 * matching the Claude Code SDK's ClaudeCode.run() signature.
 *
 * @example
 * ```ts
 * import { ClaudeCode } from "@anthropic-ai/claude-code";
 * import { instrumentClaudeCode } from "@tracelanedev/sdk/claude_code";
 *
 * const client = new ClaudeCode();
 * instrumentClaudeCode(client);
 * const result = await client.run("Refactor this function");
 * ```
 */

import { SpanKind, SpanStatusCode, trace } from "@opentelemetry/api";

const tracer = trace.getTracer("@tracelanedev/sdk-claude-code", "0.1.0");

interface ClaudeCodeClientLike {
	run: (...args: unknown[]) => Promise<unknown>;
}

/**
 * Instrument a Claude Code client to emit OTel spans.
 *
 * @param client - An object with a run() method (ClaudeCode SDK instance)
 */
export function instrumentClaudeCode(client: ClaudeCodeClientLike): void {
	const originalRun = client.run.bind(client);

	client.run = async (...args: unknown[]) => {
		const prompt = args[0];
		const options = args[1] as Record<string, unknown> | undefined;
		const model =
			typeof options?.model === "string" ? options.model : "claude-sonnet-4-6";
		const promptLength = typeof prompt === "string" ? prompt.length : 0;

		return tracer.startActiveSpan(
			"claude_code.run",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "claude-code",
					"gen_ai.request.model": model,
					"claude_code.prompt_length": promptLength,
				},
			},
			async (span) => {
				try {
					const result = (await originalRun(...args)) as Record<
						string,
						unknown
					>;
					const inputTokens = result.input_tokens ?? result.inputTokens;
					const outputTokens = result.output_tokens ?? result.outputTokens;
					if (typeof inputTokens === "number") {
						span.setAttributes({
							"gen_ai.usage.input_tokens": inputTokens,
							"claude_code.input_tokens": inputTokens,
						});
					}
					if (typeof outputTokens === "number") {
						span.setAttributes({
							"gen_ai.usage.output_tokens": outputTokens,
							"claude_code.output_tokens": outputTokens,
						});
					}
					const resultModel = result.model;
					if (typeof resultModel === "string") {
						span.setAttribute("gen_ai.response.model", resultModel);
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

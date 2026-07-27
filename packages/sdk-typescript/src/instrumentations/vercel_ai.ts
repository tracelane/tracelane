/**
 * Vercel AI SDK instrumentation for Tracelane.
 *
 * Wraps the Vercel AI SDK module-level functions (generateText, streamText,
 * generateObject) to emit OTel spans. Vercel AI SDK has the largest Next.js
 * install base, making this the highest-reach TypeScript adapter.
 *
 * @example
 * ```ts
 * import * as ai from "ai";
 * import { instrumentVercelAI } from "@tracelanedev/sdk/vercel_ai";
 *
 * instrumentVercelAI(ai);
 * const { text } = await ai.generateText({
 *   model: openai("gpt-4o"),
 *   prompt: "Hello",
 * });
 * ```
 */

import { SpanKind, SpanStatusCode, trace } from "@opentelemetry/api";

const tracer = trace.getTracer("@tracelanedev/sdk-vercel-ai", "0.1.0");

interface VercelAIModule {
	generateText: (...args: unknown[]) => Promise<unknown>;
	streamText?: (...args: unknown[]) => unknown;
	generateObject?: (...args: unknown[]) => Promise<unknown>;
}

/**
 * Instrument the Vercel AI SDK module to emit OTel spans.
 *
 * Mutates the module object in-place, wrapping generateText, streamText,
 * and generateObject. Pass the imported `ai` module directly.
 *
 * @param aiModule - The imported `ai` (Vercel AI SDK) module object
 */
export function instrumentVercelAI(aiModule: VercelAIModule): void {
	_patchGenerateText(aiModule);
	if (aiModule.generateObject) {
		_patchGenerateObject(
			aiModule as VercelAIModule & {
				generateObject: (...args: unknown[]) => Promise<unknown>;
			},
		);
	}
	if (aiModule.streamText) {
		_patchStreamText(
			aiModule as VercelAIModule & {
				streamText: (...args: unknown[]) => unknown;
			},
		);
	}
}

function _extractModel(args: unknown[]): string {
	const opts = args[0] as Record<string, unknown> | undefined;
	if (!opts) return "unknown";
	const model = opts.model as Record<string, unknown> | undefined;
	if (!model) return "unknown";
	return String(model.modelId ?? model.specificationVersion ?? "unknown");
}

function _patchGenerateText(aiModule: VercelAIModule): void {
	const original = aiModule.generateText.bind(aiModule);

	aiModule.generateText = async (...args: unknown[]) => {
		const model = _extractModel(args);
		return tracer.startActiveSpan(
			"vercel_ai.generateText",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "vercel-ai",
					"gen_ai.request.model": model,
					"llm.model_name": model,
					"vercel_ai.operation": "generateText",
				},
			},
			async (span) => {
				try {
					const result = (await original(...args)) as Record<string, unknown>;
					_recordUsage(span, result);
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

function _patchGenerateObject(
	aiModule: VercelAIModule & {
		generateObject: NonNullable<VercelAIModule["generateObject"]>;
	},
): void {
	const original = aiModule.generateObject.bind(aiModule);

	aiModule.generateObject = async (...args: unknown[]) => {
		const model = _extractModel(args);
		return tracer.startActiveSpan(
			"vercel_ai.generateObject",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "vercel-ai",
					"gen_ai.request.model": model,
					"llm.model_name": model,
					"vercel_ai.operation": "generateObject",
				},
			},
			async (span) => {
				try {
					const result = (await original(...args)) as Record<string, unknown>;
					_recordUsage(span, result);
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

function _patchStreamText(
	aiModule: VercelAIModule & {
		streamText: NonNullable<VercelAIModule["streamText"]>;
	},
): void {
	const original = aiModule.streamText.bind(aiModule);

	aiModule.streamText = (...args: unknown[]) => {
		const model = _extractModel(args);
		const span = tracer.startSpan("vercel_ai.streamText", {
			kind: SpanKind.CLIENT,
			attributes: {
				"gen_ai.provider.name": "vercel-ai",
				"gen_ai.request.model": model,
				"llm.model_name": model,
				"vercel_ai.operation": "streamText",
			},
		});
		try {
			const result = original(...args) as Record<string, unknown>;
			// streamText returns a StreamTextResult — attach a then-handler to end span
			if (
				result &&
				typeof (result as { fullStream?: unknown }).fullStream !== "undefined"
			) {
				span.setStatus({ code: SpanStatusCode.OK });
			}
			span.end();
			return result;
		} catch (e) {
			span.recordException(e as Error);
			span.setStatus({ code: SpanStatusCode.ERROR, message: String(e) });
			span.end();
			throw e;
		}
	};
}

function _recordUsage(
	span: ReturnType<typeof tracer.startSpan>,
	result: Record<string, unknown>,
): void {
	const usage = result.usage as Record<string, unknown> | undefined;
	if (usage) {
		span.setAttributes({
			"gen_ai.usage.input_tokens": Number(
				usage.promptTokens ?? usage.prompt_tokens ?? 0,
			),
			"gen_ai.usage.output_tokens": Number(
				usage.completionTokens ?? usage.completion_tokens ?? 0,
			),
		});
	}
}

/**
 * Cursor Agent instrumentation for Tracelane.
 *
 * Wraps Cursor's completion API to emit OTel spans. Cursor is the largest
 * paid AI coding agent — instrumenting it provides visibility into coding
 * agent workflows alongside production agent traces.
 *
 * Works with any client exposing complete() or chat.completions.create(),
 * which covers both Cursor's internal API shape and OpenAI-compatible
 * clients used to interface with Cursor's backend.
 *
 * @example
 * ```ts
 * import { instrumentCursor } from "@tracelanedev/sdk/cursor";
 *
 * // If using an OpenAI-compatible client pointed at Cursor:
 * instrumentCursor(cursorClient);
 * ```
 */

import { SpanKind, SpanStatusCode, trace } from "@opentelemetry/api";

const tracer = trace.getTracer("@tracelanedev/sdk-cursor", "0.1.0");

interface CursorClientLike {
	complete?: (...args: unknown[]) => Promise<unknown>;
	chat?: {
		completions?: {
			create: (...args: unknown[]) => Promise<unknown>;
		};
	};
}

/**
 * Instrument a Cursor client to emit OTel spans.
 *
 * Instruments whichever API method is present: complete() or
 * chat.completions.create().
 *
 * @param client - A Cursor client or OpenAI-compatible client for Cursor
 */
export function instrumentCursor(client: CursorClientLike): void {
	if (client.complete) {
		_patchComplete(client as Required<Pick<CursorClientLike, "complete">>);
	} else if (client.chat?.completions?.create) {
		_patchChatCompletions(
			client as {
				chat: {
					completions: { create: (...args: unknown[]) => Promise<unknown> };
				};
			},
		);
	}
}

function _patchComplete(client: {
	complete: (...args: unknown[]) => Promise<unknown>;
}): void {
	const originalComplete = client.complete.bind(client);

	client.complete = async (...args: unknown[]) => {
		const opts = args[0] as Record<string, unknown> | undefined;
		const model = typeof opts?.model === "string" ? opts.model : "cursor";

		return tracer.startActiveSpan(
			"cursor.complete",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "cursor",
					"gen_ai.request.model": model,
					"llm.model_name": model,
				},
			},
			async (span) => {
				try {
					const result = (await originalComplete(...args)) as Record<
						string,
						unknown
					>;
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

function _patchChatCompletions(client: {
	chat: { completions: { create: (...args: unknown[]) => Promise<unknown> } };
}): void {
	const originalCreate = client.chat.completions.create.bind(
		client.chat.completions,
	);

	client.chat.completions.create = async (...args: unknown[]) => {
		const req = args[0] as Record<string, unknown> | undefined;
		const model = typeof req?.model === "string" ? req.model : "cursor";

		return tracer.startActiveSpan(
			"cursor.chat.completions.create",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "cursor",
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

function _recordUsage(
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
}

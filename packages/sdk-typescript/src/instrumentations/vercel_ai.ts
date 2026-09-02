/**
 * Vercel AI SDK integration for Tracelane — B-313.
 *
 * **The Vercel AI SDK is not OpenTelemetry-native.** As of `ai@7` the package
 * has no `@opentelemetry/api` dependency and never calls `getTracer`, so
 * `experimental_telemetry: { isEnabled: true }` emits **zero** OTel spans on its
 * own. Measured against `ai@7.0.85`: a control span in the same harness was
 * captured and the SDK's were not. That is why the exporter-config recipe which
 * covers LangChain, LangGraph, LlamaIndex and CrewAI does not reach this one.
 *
 * Instead `ai@7` ships its own integration API — `registerTelemetry()` — with
 * lifecycle callbacks. This module maps those onto OTel spans, which yields the
 * agent structure the OTel-native frameworks give for free:
 *
 *     ai.generateText                 (root)
 *     ├── ai.step 0
 *     │   ├── ai.languageModelCall
 *     │   └── ai.toolCall lookup
 *     └── ai.step 1
 *         └── ai.languageModelCall
 *
 * @example
 * ```ts
 * import { registerTelemetry } from "ai";
 * import { tracelaneTelemetry } from "@tracelanedev/sdk/vercel_ai";
 *
 * registerTelemetry(tracelaneTelemetry());
 *
 * await generateText({
 *   model,
 *   prompt: "…",
 *   experimental_telemetry: { isEnabled: true }, // required by the AI SDK
 * });
 * ```
 *
 * **Correlation, and why a stack would be wrong:** every callback for one
 * operation carries the same `callId` — measured, it is per-operation and NOT
 * per-model-call — and steps within it are sequential, keyed by `stepNumber`.
 * Concurrent `generateText` calls interleave their callbacks, so state is keyed
 * by `callId` and parents are set EXPLICITLY through the OTel context rather
 * than relying on the ambient one, which the AI SDK makes no promise about.
 */

import {
	type Context,
	type Span,
	SpanKind,
	SpanStatusCode,
	context as otelContext,
	trace,
} from "@opentelemetry/api";

const tracer = trace.getTracer("@tracelanedev/sdk-vercel-ai");

/** The subset of the AI SDK event shapes this integration reads. */
interface OperationStart {
	callId?: string;
	operationId?: string;
	provider?: string;
	modelId?: string;
	functionId?: string;
}
interface StepEvent {
	callId?: string;
	stepNumber?: number;
}
interface ModelCallStart {
	callId?: string;
	provider?: string;
	modelId?: string;
}
interface ModelCallEnd {
	callId?: string;
	finishReason?: { unified?: string } | string;
	usage?: { inputTokens?: number; outputTokens?: number };
}
interface ToolEvent {
	callId?: string;
	toolCall?: { toolName?: string; toolCallId?: string };
	toolExecutionMs?: number;
}
interface ErrorEvent {
	callId?: string;
	error?: unknown;
}

/** Live spans for one in-flight operation, keyed by its `callId`. */
interface OperationState {
	root: Span;
	rootCtx: Context;
	step?: Span;
	stepCtx?: Context;
	modelCall?: Span;
	tools: Map<string, Span>;
}

function unifiedFinishReason(
	reason: ModelCallEnd["finishReason"],
): string | undefined {
	return typeof reason === "string" ? reason : reason?.unified;
}

function endSpan(span: Span | undefined, err?: unknown): void {
	if (!span) return;
	if (err !== undefined) {
		span.recordException(err as Error);
		span.setStatus({ code: SpanStatusCode.ERROR, message: String(err) });
	} else {
		span.setStatus({ code: SpanStatusCode.OK });
	}
	span.end();
}

/**
 * Build a Tracelane telemetry integration for the AI SDK's `registerTelemetry()`.
 *
 * Register once at process start. Operations are tracked independently by
 * `callId`, so concurrent calls do not interfere.
 */
export function tracelaneTelemetry(): Record<string, (event: never) => void> {
	const live = new Map<string, OperationState>();

	/** The tightest currently-open context for an operation. */
	const parentCtx = (state: OperationState): Context =>
		state.stepCtx ?? state.rootCtx;

	const closeAll = (callId: string, err?: unknown): void => {
		const state = live.get(callId);
		if (!state) return;
		for (const span of state.tools.values()) endSpan(span, err);
		endSpan(state.modelCall, err);
		endSpan(state.step, err);
		endSpan(state.root, err);
		live.delete(callId);
	};

	const handlers = {
		onStart(event: OperationStart): void {
			const callId = event.callId;
			if (!callId || live.has(callId)) return;
			const name = event.operationId ?? "ai.generateText";
			const root = tracer.startSpan(name, {
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": event.provider ?? "vercel-ai",
					"gen_ai.request.model": event.modelId ?? "unknown",
					"vercel_ai.operation": name,
					...(event.functionId
						? { "vercel_ai.function_id": event.functionId }
						: {}),
				},
			});
			live.set(callId, {
				root,
				rootCtx: trace.setSpan(otelContext.active(), root),
				tools: new Map(),
			});
		},

		onStepStart(event: StepEvent): void {
			const state = event.callId ? live.get(event.callId) : undefined;
			if (!state) return;
			const step = tracer.startSpan(
				`ai.step ${event.stepNumber ?? 0}`,
				{
					kind: SpanKind.INTERNAL,
					attributes: { "vercel_ai.step_number": event.stepNumber ?? 0 },
				},
				state.rootCtx,
			);
			state.step = step;
			state.stepCtx = trace.setSpan(state.rootCtx, step);
		},

		onLanguageModelCallStart(event: ModelCallStart): void {
			const state = event.callId ? live.get(event.callId) : undefined;
			if (!state) return;
			state.modelCall = tracer.startSpan(
				"ai.languageModelCall",
				{
					kind: SpanKind.CLIENT,
					attributes: {
						"gen_ai.provider.name": event.provider ?? "vercel-ai",
						"gen_ai.request.model": event.modelId ?? "unknown",
					},
				},
				parentCtx(state),
			);
		},

		onLanguageModelCallEnd(event: ModelCallEnd): void {
			const state = event.callId ? live.get(event.callId) : undefined;
			const span = state?.modelCall;
			if (!state || !span) return;
			const finish = unifiedFinishReason(event.finishReason);
			if (finish) span.setAttribute("gen_ai.response.finish_reason", finish);
			if (typeof event.usage?.inputTokens === "number")
				span.setAttribute("gen_ai.usage.input_tokens", event.usage.inputTokens);
			if (typeof event.usage?.outputTokens === "number")
				span.setAttribute(
					"gen_ai.usage.output_tokens",
					event.usage.outputTokens,
				);
			endSpan(span);
			state.modelCall = undefined;
		},

		onToolExecutionStart(event: ToolEvent): void {
			const state = event.callId ? live.get(event.callId) : undefined;
			const toolCallId = event.toolCall?.toolCallId;
			if (!state || !toolCallId) return;
			const toolName = event.toolCall?.toolName ?? "unknown";
			state.tools.set(
				toolCallId,
				tracer.startSpan(
					`ai.toolCall ${toolName}`,
					{
						kind: SpanKind.INTERNAL,
						attributes: {
							"gen_ai.tool.name": toolName,
							"gen_ai.tool.call.id": toolCallId,
						},
					},
					parentCtx(state),
				),
			);
		},

		onToolExecutionEnd(event: ToolEvent): void {
			const state = event.callId ? live.get(event.callId) : undefined;
			const toolCallId = event.toolCall?.toolCallId;
			if (!state || !toolCallId) return;
			const span = state.tools.get(toolCallId);
			if (typeof event.toolExecutionMs === "number")
				span?.setAttribute(
					"vercel_ai.tool_execution_ms",
					event.toolExecutionMs,
				);
			endSpan(span);
			state.tools.delete(toolCallId);
		},

		onStepEnd(event: StepEvent): void {
			const state = event.callId ? live.get(event.callId) : undefined;
			if (!state) return;
			endSpan(state.step);
			state.step = undefined;
			state.stepCtx = undefined;
		},

		// `onEnd` closes the operation — NOT `onFinish`, which does not fire for
		// generateText. Measured against ai@7.0.85; getting this wrong leaks the
		// root span and the trace never completes.
		onEnd(event: StepEvent): void {
			if (event.callId) closeAll(event.callId);
		},

		onAbort(event: StepEvent): void {
			if (event.callId) closeAll(event.callId, "aborted");
		},

		onError(event: ErrorEvent): void {
			if (event?.callId) closeAll(event.callId, event.error ?? "unknown error");
		},
	};

	return handlers as unknown as Record<string, (event: never) => void>;
}

/** The module shape the legacy patch mutates. */
interface VercelAIModule {
	generateText: (...args: unknown[]) => Promise<unknown>;
	streamText?: (...args: unknown[]) => unknown;
	generateObject?: (...args: unknown[]) => Promise<unknown>;
}

function extractModel(args: unknown[]): string {
	const opts = args[0] as Record<string, unknown> | undefined;
	const model = opts?.model as Record<string, unknown> | undefined;
	return model
		? String(model.modelId ?? model.specificationVersion ?? "unknown")
		: "unknown";
}

function recordUsage(span: Span, result: Record<string, unknown>): void {
	const usage = result.usage as Record<string, unknown> | undefined;
	if (!usage) return;
	// `inputTokens`/`outputTokens` are the ai@7 names; the `prompt*` forms are
	// what ai@4-era releases sent, kept so this legacy path keeps reporting what
	// it always did.
	//
	// An ABSENT count is left unset rather than written as 0 — a zero would
	// assert "the model used no tokens" when the truth is "the SDK did not tell
	// us", and those two must not render the same.
	const input = usage.inputTokens ?? usage.promptTokens ?? usage.prompt_tokens;
	const output =
		usage.outputTokens ?? usage.completionTokens ?? usage.completion_tokens;
	if (typeof input === "number")
		span.setAttribute("gen_ai.usage.input_tokens", input);
	if (typeof output === "number")
		span.setAttribute("gen_ai.usage.output_tokens", output);
}

/**
 * Can this module object be mutated at all?
 *
 * A self-assignment is a no-op on a CommonJS `require()` result and **throws**
 * on an ES module namespace, whose `[[Set]]` always fails. That is the only
 * reliable discriminator: the property descriptors are identical for both
 * (`writable: true, configurable: false`), so checking them tells you nothing.
 */
function isMutableModule(aiModule: VercelAIModule): boolean {
	const record = aiModule as unknown as Record<string, unknown>;
	// `Reflect.set` RETURNS false where a plain assignment would throw, so this
	// probes writability without an exception and without mutating anything —
	// the value written is the one already there.
	return Reflect.set(record, "generateText", record.generateText);
}

let deprecationWarned = false;

function wrapOperation(
	aiModule: Record<string, unknown>,
	key: string,
	spanName: string,
): void {
	const existing = aiModule[key] as ((...a: unknown[]) => unknown) & {
		__tracelane_wrapped__?: boolean;
	};
	// Instrumenting the same module twice previously produced TWO spans for one
	// call. This marker makes a second attach a no-op, matching the Python SDK.
	if (existing?.__tracelane_wrapped__) return;
	const original = existing.bind(aiModule);
	aiModule[key] = async (...args: unknown[]) => {
		const model = extractModel(args);
		return tracer.startActiveSpan(
			spanName,
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "vercel-ai",
					"gen_ai.request.model": model,
					"llm.model_name": model,
					"vercel_ai.operation": key,
				},
			},
			async (span: Span) => {
				try {
					const result = (await original(...args)) as Record<string, unknown>;
					recordUsage(span, result);
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
	(aiModule[key] as { __tracelane_wrapped__?: boolean }).__tracelane_wrapped__ =
		true;
}

/**
 * @deprecated Use {@link tracelaneTelemetry} with the AI SDK's `registerTelemetry()`.
 *
 * **Still works under CommonJS, and deliberately so.** A `require("ai")` result
 * is a mutable object, so this patch succeeds there and captures the LLM leg —
 * flat, one span per call, no steps and no tool calls. Removing it would take
 * working capture away from a CJS user who upgraded for an unrelated reason,
 * at a moment we chose rather than they did.
 *
 * **Throws under ESM**, because an ES module namespace is read-only and this
 * could never have worked there. A silent no-op would be worse than an error:
 * it would report success and capture nothing.
 *
 * Moving to {@link tracelaneTelemetry} upgrades you from the LLM leg to the
 * full agent structure — a span per step, per model call and per tool call.
 */
export function instrumentVercelAI(aiModule: VercelAIModule): void {
	if (!isMutableModule(aiModule)) {
		throw new Error(
			"instrumentVercelAI() cannot patch an ES module namespace — it is read-only, " +
				'so this never worked under `import * as ai from "ai"`. Use the AI SDK\'s ' +
				"own telemetry API instead, which also captures steps and tool calls:\n" +
				'  import { registerTelemetry } from "ai";\n' +
				'  import { tracelaneTelemetry } from "@tracelanedev/sdk/vercel_ai";\n' +
				"  registerTelemetry(tracelaneTelemetry());\n" +
				"Then pass experimental_telemetry: { isEnabled: true } to generateText/streamText.",
		);
	}

	if (!deprecationWarned) {
		deprecationWarned = true;
		console.warn(
			"[tracelane] instrumentVercelAI() is deprecated and captures the LLM call only — " +
				"one flat span per call, with no steps and no tool calls. Switch to " +
				"registerTelemetry(tracelaneTelemetry()) from @tracelanedev/sdk/vercel_ai to get " +
				"the full agent structure: a span per step, per model call and per tool call. " +
				"This path keeps working; nothing breaks if you migrate later.",
		);
	}

	const record = aiModule as unknown as Record<string, unknown>;
	wrapOperation(record, "generateText", "vercel_ai.generateText");
	if (typeof record.generateObject === "function")
		wrapOperation(record, "generateObject", "vercel_ai.generateObject");
	if (typeof record.streamText === "function")
		wrapOperation(record, "streamText", "vercel_ai.streamText");
}

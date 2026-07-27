/**
 * Streaming-call guard shared by the LLM instrumentations.
 *
 * Token-usage capture for streamed responses lands in v1.1. Until then a
 * streamed call must never be recorded silently as a token-less span that
 * looks like a broken integration: the span is marked
 * `tracelane.streaming = true` (so the platform can distinguish "no usage
 * because streaming" from "no usage because bug") and a once-per-process
 * warning tells the developer exactly what is and is not captured.
 */

import type { Span } from "@opentelemetry/api";

let warned = false;

/**
 * Mark a span as a streamed call and warn (once per process) that token
 * usage is not captured for streamed responses yet.
 *
 * The wrapped response object is never touched — consuming the stream to
 * count tokens would alter caller-visible behavior.
 *
 * @param span - The active span for the streamed call.
 * @param provider - Instrumentation name for the warning text (e.g. "openai").
 */
export function markStreamingCall(span: Span, provider: string): void {
	span.setAttribute("tracelane.streaming", true);
	if (warned) return;
	warned = true;
	const msg = `[tracelane] ${provider}: stream:true detected — token usage and finish reason are not captured for streamed calls yet (planned for v1.1). Spans still record model and latency, marked tracelane.streaming=true.`;
	if (
		typeof process !== "undefined" &&
		typeof process.emitWarning === "function"
	) {
		process.emitWarning(msg);
	} else {
		console.warn(msg);
	}
}

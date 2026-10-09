/**
 * Tool-call naming and counting. OBS-61 supersedes the deleted detectToolLoop:
 * equality and thresholds now come from the gateway fingerprint reader.
 *
 * Called from TraceSummaryHeader (RSC + client bundle) and the unit test.
 * No DOM, no async, no side effects — safe in any environment.
 *
 * Callers: TraceSummaryHeader.tsx, tool-loop.test.ts.
 */

import type { Span } from "@/components/trace-viewer/types";

/**
 * Extract the tool name from a span if it is a tool-call span, else return null.
 *
 * A span is a tool call when:
 *  - `gen_ai.tool.name` (or its underscore-flattened stored form
 *    `gen_ai_tool_name`) is a non-empty string in the attributes JSON, OR
 *  - `span.name === "tool.call"` (legacy/catch-all span name).
 *
 * @param span - Any Span from the trace.
 * @returns Tool name string on a tool call span; null otherwise.
 */
export function toolCallName(span: Span): string | null {
	try {
		const attrs = JSON.parse(span.attributes) as Record<string, unknown>;
		const name = attrs["gen_ai.tool.name"] ?? attrs.gen_ai_tool_name;
		if (typeof name === "string" && name.length > 0) return name;
	} catch {
		// unparseable attributes — not a tool call
	}
	// Fallback: legacy span named "tool.call" with no gen_ai.tool.name attr.
	if (span.name === "tool.call") return span.name;
	return null;
}

/**
 * Count the number of tool-call spans in the trace.
 *
 * @param spans - Full span set for the trace.
 * @returns Number of spans that are tool calls (0 when none).
 */
export function countToolCallSpans(spans: Span[]): number {
	let n = 0;
	for (const span of spans) {
		if (toolCallName(span) !== null) n++;
	}
	return n;
}

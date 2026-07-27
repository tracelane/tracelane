/**
 * tool-loop — pure helpers for tool-call detection and agent loop detection.
 *
 * Called from TraceSummaryHeader (RSC + client bundle) and the unit test.
 * No DOM, no async, no side effects — safe in any environment.
 *
 * Callers: TraceSummaryHeader.tsx, tool-loop.test.ts.
 * Key invariants: detectToolLoop NEVER fires on < 3 tool-call spans; it checks
 * exact (tool, arguments) repetition first, then falls back to name-only counting
 * so a tool called with different args doesn't false-positive at count 3.
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

/**
 * Detect a likely agent loop in the trace.
 *
 * Heuristic (priority order):
 *  1. The exact `(tool_name, arguments_json)` pair repeats ≥ 3 times
 *     (agent retrying the same call with identical inputs).
 *  2. The same `tool_name` repeats ≥ 3 times regardless of arguments
 *     (agent spinning on the same tool, possibly with different inputs).
 *
 * Argument keys probed (in order): `gen_ai.tool.call.arguments`,
 * `gen_ai_tool_call_arguments`, `tool_input`, `tool_parameters`.
 *
 * @param spans - Full span set for the trace.
 * @returns `{ toolName, count }` when a loop is detected; null otherwise.
 *   Never returns a result when fewer than 3 tool-call spans exist.
 */
export function detectToolLoop(
	spans: Span[],
): { toolName: string; count: number } | null {
	const nameCounts = new Map<string, number>();
	// Key = "<toolName>::<argsJSON>" → exact-repeat count.
	const argCounts = new Map<string, number>();

	for (const span of spans) {
		let name: string | null = null;
		let argsKey: string | undefined;

		try {
			const attrs = JSON.parse(span.attributes) as Record<string, unknown>;
			const toolName = attrs["gen_ai.tool.name"] ?? attrs.gen_ai_tool_name;
			if (typeof toolName === "string" && toolName.length > 0) {
				name = toolName;
				const args =
					attrs["gen_ai.tool.call.arguments"] ??
					attrs.gen_ai_tool_call_arguments ??
					attrs.tool_input ??
					attrs.tool_parameters;
				if (args !== undefined) {
					argsKey = typeof args === "string" ? args : JSON.stringify(args);
				}
			}
		} catch {
			// Unparseable attributes — skip.
		}

		// Legacy span name fallback (no attrs).
		if (name === null && span.name === "tool.call") {
			name = span.name;
		}

		if (name !== null) {
			nameCounts.set(name, (nameCounts.get(name) ?? 0) + 1);
			if (argsKey !== undefined) {
				const key = `${name}::${argsKey}`;
				argCounts.set(key, (argCounts.get(key) ?? 0) + 1);
			}
		}
	}

	// Priority 1: exact (tool, args) repetition ≥ 3.
	for (const [key, count] of argCounts) {
		if (count >= 3) {
			const sep = key.indexOf("::");
			const toolName = sep !== -1 ? key.slice(0, sep) : key;
			return { toolName, count };
		}
	}

	// Priority 2: tool name repetition ≥ 3.
	for (const [toolName, count] of nameCounts) {
		if (count >= 3) {
			return { toolName, count };
		}
	}

	return null;
}

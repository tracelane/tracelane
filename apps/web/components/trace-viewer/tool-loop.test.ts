import type { Span } from "@/components/trace-viewer/types";
import { countToolCallSpans, toolCallName } from "@/lib/tool-loop";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { TraceSummaryHeader } from "./TraceSummaryHeader";

function makeToolSpan(toolName: string, args?: string): Span {
	const attrs: Record<string, unknown> = { "gen_ai.tool.name": toolName };
	if (args !== undefined) attrs["gen_ai.tool.call.arguments"] = args;
	return {
		span_id: `span-${toolName}-${Math.random().toString(36).slice(2)}`,
		parent_span_id: null,
		name: "llm.tool_call",
		start_time: "2026-01-01T00:00:00Z",
		end_time: "2026-01-01T00:00:01Z",
		duration_us: 100_000,
		status_code: 1,
		status_message: "",
		attributes: JSON.stringify(attrs),
		aft_ids: [],
		intervention: 0,
	};
}

it("same-name different-argument calls never invent a loop in the header", () => {
	const spans = [
		makeToolSpan("search", '{"q":"a"}'),
		makeToolSpan("search", '{"q":"b"}'),
		makeToolSpan("search", '{"q":"c"}'),
	];
	expect(
		renderToStaticMarkup(createElement(TraceSummaryHeader, { spans })),
	).not.toContain("status-loop");
	expect(
		renderToStaticMarkup(createElement(TraceSummaryHeader, { spans })),
	).not.toContain("pre-flight");
	expect(countToolCallSpans(spans)).toBe(3);
});
it("keeps legacy tool counting without deciding equality", () => {
	const s = makeToolSpan("search");
	expect(toolCallName(s)).toBe("search");
	expect(countToolCallSpans([{ ...s, name: "chat", attributes: "{}" }])).toBe(
		0,
	);
});

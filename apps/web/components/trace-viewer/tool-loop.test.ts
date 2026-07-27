import type { Span } from "@/components/trace-viewer/types";
import { detectToolLoop } from "@/lib/tool-loop";
import { describe, expect, it } from "vitest";

/**
 * Unit tests for the agent loop-detection heuristic.
 * "A 200 is not proof" (CLAUDE.md) — we assert the rendered shape (returned
 * value) not just reachability. The CRITICAL contract: no false-positive at
 * < 3 repeats; fires correctly at ≥ 3.
 */

/** Minimal Span fixture — only the fields detectToolLoop reads. */
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

describe("detectToolLoop — fires at 3 repeats, not at 2", () => {
	it("returns null for 2 calls of the same tool (no false-positive)", () => {
		const spans = [makeToolSpan("search_web"), makeToolSpan("search_web")];
		expect(detectToolLoop(spans)).toBeNull();
	});

	it("fires and returns the repeated tool name + count=3 at 3 calls", () => {
		const spans = [
			makeToolSpan("search_web"),
			makeToolSpan("search_web"),
			makeToolSpan("search_web"),
		];
		const result = detectToolLoop(spans);
		expect(result).not.toBeNull();
		expect(result?.toolName).toBe("search_web");
		expect(result?.count).toBe(3);
	});

	it("does not fire when different tools each appear fewer than 3 times", () => {
		const spans = [
			makeToolSpan("read_file"),
			makeToolSpan("write_file"),
			makeToolSpan("read_file"),
			makeToolSpan("list_dir"),
			makeToolSpan("write_file"),
		];
		expect(detectToolLoop(spans)).toBeNull();
	});

	it("detects exact (tool, args) repetition ≥ 3 independently of name count", () => {
		// Only 3 spans total but the same (tool, args) pair exactly.
		const spans = [
			makeToolSpan("send_email", '{"to":"a@b.com"}'),
			makeToolSpan("send_email", '{"to":"a@b.com"}'),
			makeToolSpan("send_email", '{"to":"a@b.com"}'),
		];
		const result = detectToolLoop(spans);
		expect(result).not.toBeNull();
		expect(result?.toolName).toBe("send_email");
	});

	it("returns null when no tool-call spans are present", () => {
		const spans: Span[] = [
			{
				span_id: "s1",
				parent_span_id: null,
				name: "llm.chat",
				start_time: "2026-01-01T00:00:00Z",
				end_time: "2026-01-01T00:00:01Z",
				duration_us: 100_000,
				status_code: 1,
				status_message: "",
				attributes: JSON.stringify({ "gen_ai.system": "openai" }),
				aft_ids: [],
				intervention: 0,
			},
		];
		expect(detectToolLoop(spans)).toBeNull();
	});
});

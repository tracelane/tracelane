// @vitest-environment jsdom
/**
 * `OBS-50` proof 2 — the Tool calls section renders for a span that called a tool
 * and does NOT render for one that did not; missing arguments are described
 * and shows the byte size; a captured argument renders pretty-printed.
 */
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { SpanInspector } from "./SpanInspector";
import type { Span } from "./types";

function span(attributes: Record<string, unknown>): Span {
	return {
		span_id: "s1",
		parent_span_id: null,
		name: "gen_ai.chat",
		start_time: "2026-09-20 03:00:00",
		end_time: "2026-09-20 03:00:01",
		duration_us: 1_420_000,
		status_code: 1,
		status_message: "",
		attributes: JSON.stringify(attributes),
		aft_ids: [],
		intervention: 0,
	} as Span;
}

afterEach(cleanup);

describe("SpanInspector — Tool calls (OBS-50)", () => {
	it("missing arguments: shows byte size without claiming capture is off", () => {
		render(
			<SpanInspector
				span={span({
					gen_ai_request_model: "claude-haiku-4-5",
					tracelane_response_tool_names: ["get_weather"],
					tracelane_response_tool_arg_bytes: [212],
					gen_ai_response_finish_reasons: ["tool_calls"],
				})}
			/>,
		);
		const section = screen.getByTestId("tool-calls");
		expect(section).toHaveTextContent("Tool calls (1)");
		expect(section).toHaveTextContent("get_weather");
		expect(section).toHaveTextContent("0.2 KiB");
		expect(section).toHaveTextContent("arguments not recorded");
		expect(section).not.toHaveTextContent("content capture is off");
		expect(section).toHaveTextContent("turn ended on the tool call");
	});

	it("content ON: the captured arguments render, pretty-printed", () => {
		render(
			<SpanInspector
				span={span({
					tracelane_response_tool_names: ["get_weather"],
					tracelane_response_tool_arg_bytes: [16],
					gen_ai_output_messages: [
						{
							role: "assistant",
							content: "",
							tool_calls: [
								{ id: "c1", name: "get_weather", input: { city: "Paris" } },
							],
						},
					],
				})}
			/>,
		);
		const section = screen.getByTestId("tool-calls");
		expect(section).toHaveTextContent('"city": "Paris"');
		expect(section).not.toHaveTextContent("not captured");
	});

	it("no tool call: no section at all — the inspector is unchanged", () => {
		render(
			<SpanInspector
				span={span({
					gen_ai_request_model: "claude-haiku-4-5",
					gen_ai_response_finish_reasons: ["stop"],
				})}
			/>,
		);
		expect(screen.queryByTestId("tool-calls")).toBeNull();
	});

	it("flattened tracelane_* keys render under Tracelane, not Other (the grouping fix)", () => {
		render(
			<SpanInspector
				span={span({
					tracelane_dispatch_attempts: [
						{ attempt: 0, outcome: "error", status: 429 },
					],
				})}
			/>,
		);
		expect(screen.getByText("Tracelane")).toBeInTheDocument();
		expect(screen.queryByText("Other")).toBeNull();
	});
});

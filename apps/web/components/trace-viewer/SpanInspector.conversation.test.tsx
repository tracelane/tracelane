// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { SpanInspector } from "./SpanInspector";
import type { Span } from "./types";

const span = (attrs: Record<string, unknown>, intervention = 0): Span => ({
	span_id: "s1",
	parent_span_id: null,
	name: "chat",
	start_time: "2026-09-30 12:00:00",
	end_time: "2026-09-30 12:00:01",
	duration_us: 1_000_000,
	status_code: 1,
	status_message: "",
	attributes: JSON.stringify({ gen_ai_request_model: "gpt-4o", ...attrs }),
	aft_ids: [],
	intervention,
});
afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

it("renders one span's messages as conversation text with omission disclosure", () => {
	render(
		<SpanInspector
			span={span({
				gen_ai_system_instructions: "You are a helper.",
				gen_ai_input_messages: [
					{ role: "user", content: "[REDACTED:email] needs an update" },
				],
				gen_ai_output_messages: [
					{ role: "assistant", content: "The order shipped." },
				],
				tracelane_input_messages_omitted: 2,
			})}
		/>,
	);
	const panel = within(screen.getByRole("region", { name: "Conversation" }));
	expect(panel.getByText("You are a helper.")).toBeInTheDocument();
	expect(
		panel.getByText("[REDACTED:email] needs an update"),
	).toBeInTheDocument();
	expect(panel.getByText("The order shipped.")).toBeInTheDocument();
	expect(
		panel.getByText(/Showing the newest 1 of 3 messages recorded/),
	).toBeInTheDocument();
});

it("separates blocked, unloaded and unreadable from absent text", () => {
	const { rerender } = render(
		<SpanInspector
			span={span(
				{ gen_ai_input_messages: [{ role: "user", content: "hello" }] },
				2,
			)}
		/>,
	);
	expect(screen.getByText(/Blocked by a guardrail/)).toBeInTheDocument();
	rerender(
		<SpanInspector
			span={span({ gen_ai_input_messages: { $ref: "blob", missing: true } })}
		/>,
	);
	expect(
		screen.getByText(/Stored text could not be loaded/),
	).toBeInTheDocument();
	rerender(
		<SpanInspector span={span({ gen_ai_input_messages: { bad: "shape" } })} />,
	);
	expect(
		screen.getByText(/Recorded in a shape this view cannot read/),
	).toBeInTheDocument();
});

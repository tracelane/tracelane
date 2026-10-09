// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { SpanInspector } from "./SpanInspector";
import type { Span } from "./types";

const span = (attributes: Record<string, unknown>): Span => ({
	span_id: "s1",
	parent_span_id: null,
	name: "chat",
	start_time: "2026-09-30 12:00:00",
	end_time: "2026-09-30 12:00:01",
	duration_us: 1_000_000,
	status_code: 1,
	status_message: "",
	attributes: JSON.stringify(attributes),
	aft_ids: [],
	intervention: 0,
});
afterEach(cleanup);

it("shows request settings, truncated tool names and unevaluated policy honestly", () => {
	render(
		<SpanInspector
			span={span({
				gen_ai_request_temperature: 0.2,
				gen_ai_request_max_tokens: 512,
				tracelane_request_tool_count: 57,
				tracelane_request_tool_names: Array.from(
					{ length: 32 },
					(_, i) => `tool-${i}`,
				),
				tracelane_request_tool_definitions_hash: "abc123",
			})}
			toolPreviewLimit={10}
			previousToolHash="different"
		/>,
	);
	expect(screen.getByText("Request config")).toBeInTheDocument();
	expect(
		screen.getByText(/showing 10 of 32 recorded.*57 offered/i),
	).toBeInTheDocument();
	expect(screen.getByText(/Not evaluated/)).toBeInTheDocument();
	expect(
		screen.getByText(/tool set CHANGED since the previous call/),
	).toBeInTheDocument();
	expect(screen.getByText(/Tracelane does not record:/)).toBeInTheDocument();
});

it("does not call an absent misconfiguration check healthy", () => {
	render(<SpanInspector span={span({ gen_ai_request_temperature: 0 })} />);
	expect(screen.getByText(/Not evaluated/)).toBeInTheDocument();
	expect(screen.queryByText(/healthy/i)).toBeNull();
});

// @vitest-environment jsdom
import {
	cleanup,
	fireEvent,
	render,
	screen,
	within,
} from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { SpanInspector } from "./SpanInspector";
import { TraceDetailView } from "./TraceDetailView";
import type { Span } from "./types";
afterEach(cleanup);
function span(id: string, parent: string | null, issue = false): Span {
	return {
		span_id: id,
		parent_span_id: parent,
		name: id,
		start_time: "2026-09-29T00:00:00Z",
		end_time: "2026-09-29T00:00:01Z",
		duration_us: 1000000,
		status_code: 1,
		status_message: "",
		attributes: JSON.stringify({
			gen_ai_operation_name: "chat",
			gen_ai_request_model: "gpt-4o",
		}),
		aft_ids: [],
		intervention: 0,
		issues: issue
			? [
					{
						kind: "truncated",
						severity: "warn",
						detail: "gen_ai_response_finish_reasons contains length",
						affected_spans: 1,
					},
				]
			: [],
		signals_recorded: {
			attributes_readable: true,
			chat_operation: true,
			present: ["gen_ai_operation_name"],
			missing: ["gen_ai_response_model", "gen_ai_usage_output_tokens"],
		},
	} as Span;
}
it("puts an issue on its child row, rolls it up as one of three spans, and preserves collapse", () => {
	const { container } = render(
		<TraceDetailView
			traceId="trace"
			spans={[
				span("root", null),
				span("flagged-child", "root", true),
				span("clean-child", "root"),
			]}
		/>,
	);
	expect(screen.getByText("1 of 3 spans")).toBeTruthy();
	const child = container.querySelector(
		'[data-span-row="flagged-child"]',
	) as HTMLElement;
	expect(within(child).getByText("Truncated")).toBeTruthy();
	expect(
		container.querySelector('[data-span-row="clean-child"]')?.textContent,
	).not.toContain("Truncated");
	fireEvent.click(screen.getByRole("button", { name: "flagged-child" }));
	expect(screen.getByText("Generation issues")).toBeTruthy();
	expect(screen.getByText(/Not recorded:.*gen_ai_response_model/)).toBeTruthy();
	fireEvent.click(screen.getByRole("button", { name: "Collapse" }));
	expect(container.querySelector('[data-span-row="flagged-child"]')).toBeNull();
	expect(screen.getByText("1 of 3 spans")).toBeTruthy();
});
it("states missing signals without calling an unjudged span healthy, and leaves public shapes alone", () => {
	const row = span("unknown", null);
	const { rerender, container } = render(<SpanInspector span={row} />);
	expect(screen.getByText("Signals recorded")).toBeTruthy();
	expect(screen.getByText(/Not recorded:.*gen_ai_response_model/)).toBeTruthy();
	expect(container.textContent).not.toMatch(/healthy|all clear/i);
	const { issues, signals_recorded, ...publicRow } = row as Span & {
		issues: unknown;
		signals_recorded: unknown;
	};
	rerender(<SpanInspector span={publicRow} />);
	expect(screen.queryByText("Generation issues")).toBeNull();
});
it("shows a reported dated snapshot without inventing a swap or inferring a missing response model", () => {
	const row = span("snapshot", null);
	row.attributes = JSON.stringify({
		gen_ai_operation_name: "chat",
		gen_ai_request_model: "gpt-4o",
		gen_ai_response_model: "gpt-4o-2024-08-06",
		tracelane_model_substitution: "provider",
	});
	const { rerender } = render(<SpanInspector span={row} />);
	expect(screen.getByText(/Resolved to snapshot/).textContent).toContain(
		"gpt-4o-2024-08-06",
	);
	expect(screen.queryByText("Model swapped")).toBeNull();
	row.attributes = JSON.stringify({ gen_ai_request_model: "gpt-4o" });
	rerender(<SpanInspector span={{ ...row }} />);
	expect(screen.queryByText(/Resolved to snapshot/)).toBeNull();
});

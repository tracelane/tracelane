// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { TraceList, type TraceSummary } from "./TraceList";
afterEach(cleanup);
const traces: TraceSummary[] = Array.from({ length: 3 }, (_, i) => ({
	trace_id: `trace${i}`,
	root_name: i === 2 ? "third" : "chat",
	model: "model",
	start_time: "2026-09-28 10:00:00",
	duration_us: 1000,
	span_count: 1,
	error_count: 0,
	intervention: 0,
	cost_usd: 0,
	total_tokens: 1,
}));
it("selects ranges, preserves hidden selections and enables compare only for two", () => {
	render(<TraceList traces={traces} selectable selectionMax={3} />);
	fireEvent.click(screen.getByLabelText("Select trace0"));
	expect(
		(screen.getByRole("button", { name: "Compare" }) as HTMLButtonElement)
			.disabled,
	).toBe(true);
	fireEvent.click(screen.getByLabelText("Select trace1"));
	expect(
		(screen.getByRole("button", { name: "Compare" }) as HTMLButtonElement)
			.disabled,
	).toBe(false);
	fireEvent.click(screen.getByLabelText("Select trace2"), { shiftKey: true });
	expect(screen.getByText("3 selected")).toBeTruthy();
	fireEvent.change(screen.getByLabelText("Narrow the loaded traces"), {
		target: { value: "third" },
	});
	expect(screen.getByText("(2 hidden by the filter)")).toBeTruthy();
	fireEvent.click(screen.getByLabelText("Select all on page"));
	expect(screen.getByText("2 selected")).toBeTruthy();
});
it("does not allow live selection and refuses over-cap selection", () => {
	const view = render(<TraceList traces={traces} />);
	expect(screen.queryByRole("checkbox")).toBeNull();
	view.rerender(<TraceList traces={traces} selectable selectionMax={1} />);
	fireEvent.click(screen.getByLabelText("Select trace0"));
	fireEvent.click(screen.getByLabelText("Select trace1"));
	expect(screen.getByText("1 selected")).toBeTruthy();
	expect(screen.getByRole("alert").textContent).toContain("Up to 1 at once");
});

import { selectedTraceCsv, traceExportFields } from "./TraceBulkBar";
it("exports only selected rows with the gateway header and RFC-4180 quoting", () => {
	if (!traces[1]) throw new Error("Missing fixture row");
	const csv = selectedTraceCsv([
		{ ...traces[1], root_name: 'line 1, "quote"\nline 2' },
	]);
	expect(csv.split("\n")[0]).toBe(
		"trace_id,root_name,start_time,duration_us,span_count,error_count,intervention,model,cost_usd,total_tokens",
	);
	expect(csv).toContain('"line 1, ""quote""\nline 2"');
	expect(csv).not.toContain("trace0");
	expect(traceExportFields).toHaveLength(10);
});

it.each([
	['=HYPERLINK("http://x","y")', '"\'=HYPERLINK(""http://x"",""y"")"'],
	["+1", '"\'+1"'],
	["-2", '"\'-2"'],
	["@a", '"\'@a"'],
])(
	"neutralises spreadsheet formulas exactly like the gateway: %s",
	(value, escaped) => {
		const row = traces[0];
		if (!row) throw new Error("Missing fixture");
		expect(selectedTraceCsv([{ ...row, root_name: value, model: value }])).toBe(
			`${traceExportFields.join(",")}\ntrace0,${escaped},2026-09-28 10:00:00,1000,1,0,0,${escaped},0,1\n`,
		);
	},
);
it("puts all bulk actions in one bar", () => {
	render(
		<TraceList
			traces={traces}
			selectable
			selectionMax={3}
			viewerRole="owner"
		/>,
	);
	fireEvent.click(screen.getByLabelText("Select trace0"));
	const bar = screen.getByLabelText("Selected trace actions");
	for (const name of [
		"Flag selected",
		"Add selected to dataset",
		"Compare",
		"Copy links",
		"Export selected",
	])
		expect(bar.contains(screen.getByRole("button", { name }))).toBe(true);
});
it("matches the gateway export fixture byte for byte, including LF termination", () => {
	const rows: TraceSummary[] = ["t1", "t2"].map((trace_id) => ({
		trace_id,
		root_name: "root",
		start_time: "2026-06-10 00:00:00.000000",
		duration_us: 1000,
		span_count: 3,
		error_count: 0,
		intervention: 0,
		model: "claude-sonnet-4-6",
		cost_usd: 0,
		total_tokens: 0,
	}));
	expect(selectedTraceCsv(rows)).toBe(
		"trace_id,root_name,start_time,duration_us,span_count,error_count,intervention,model,cost_usd,total_tokens\nt1,root,2026-06-10 00:00:00.000000,1000,3,0,0,claude-sonnet-4-6,0,0\nt2,root,2026-06-10 00:00:00.000000,1000,3,0,0,claude-sonnet-4-6,0,0\n",
	);
});

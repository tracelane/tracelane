import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { LoopEvidenceView, type LoopResponse } from "./LoopEvidence";
const data: LoopResponse = {
	min_repeats: 3,
	window_secs: 300,
	total_instances: 1,
	truncated: false,
	tool_calls: 3,
	unfingerprinted_tool_calls: 2,
	instances: [
		{
			group_kind: "session",
			group_id: "session",
			tool: "search",
			instance_id: "test-instance",
			first_call_index: 1,
			calls: 3,
			first_at: "2026-09-30T00:00:00Z",
			last_at: "2026-09-30T00:00:02Z",
			trace_ids: ["trace"],
			span_ids: ["s"],
			repeat_cost_usd: null,
			repeat_unpriced: 2,
			repeat_output_tokens: 0,
		},
	],
};
it("shows server evidence and unknown spend without inventing free repeats", () => {
	const html = renderToStaticMarkup(
		<LoopEvidenceView
			data={data}
			spans={[]}
			traceId="trace"
			onSelectSpan={() => {}}
		/>,
	);
	expect(html).toContain("Repeated tool call · search ×3");
	expect(html).toContain("Spend on the repeats: —");
	expect(html).toContain("2 unpriced");
	expect(html).toContain("without a fingerprint key");
	expect(html).not.toContain("$0.00");
});
it("no calls is distinct from a detected loop", () => {
	const html = renderToStaticMarkup(
		<LoopEvidenceView
			data={{
				...data,
				instances: [],
				total_instances: 0,
				tool_calls: 0,
				unfingerprinted_tool_calls: 0,
			}}
			spans={[]}
			traceId="trace"
			onSelectSpan={() => {}}
		/>,
	);
	expect(html).toContain("No tool calls in this range.");
	expect(html).not.toContain("Repeated tool call ·");
});
it("uses the server call position without fingerprints, including same-name calls", () => {
	const original = data.instances[0];
	if (!original) throw new Error("missing loop fixture");
	const instance = {
		...original,
		instance_id: "opaque-response-id",
		first_call_index: 2,
	};
	const span = {
		span_id: "s",
		attributes: JSON.stringify({
			tracelane_response_tool_names: ["search", "search"],
			gen_ai_output_messages: [
				{
					tool_calls: [
						{ name: "search", input: { query: "wrong" } },
						{ name: "search", input: { query: "right" } },
					],
				},
			],
		}),
	} as import("./types").Span;
	const html = renderToStaticMarkup(
		<LoopEvidenceView
			data={{ ...data, instances: [instance] }}
			spans={[span]}
			traceId="trace"
			onSelectSpan={() => {}}
		/>,
	);
	expect(html).toContain("right");
	expect(html).not.toContain("wrong");
});

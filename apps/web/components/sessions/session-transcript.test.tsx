import type { SessionTranscriptResponse } from "@/lib/sessions";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { SessionTranscript } from "./SessionTranscript";
const data: SessionTranscriptResponse = {
	totals: {
		turns: 45,
		spans: 45,
		input_tokens: 400,
		output_tokens: 200,
		cost_usd: null,
		priced_spans: 0,
		first_start: "2026-09-28 10:00:00",
		last_end: "2026-09-28 11:00:00",
		duration_us: 3600000000,
		error_spans: 1,
		models: ["test-model"],
		end_user: "user",
		agent_name: "agent",
	},
	capture: { workspace_policy: "off" },
	turns: [
		{
			trace_id: "trace",
			ordinal: 21,
			start_time: "2026-09-28 10:00:00",
			duration_us: 1000,
			span_count: 3,
			error_spans: 1,
			status_message: "Upstream error",
			intervention: 2,
			input_tokens: 10,
			output_tokens: 0,
			cost_usd: null,
			model: "test-model",
			exchange: {
				span_id: "span",
				input_tail: [],
				input_message_count: 4,
				output: [],
				finish_reasons: ["tool_calls"],
				tool_attrs: JSON.stringify({
					tracelane_response_tool_names: ["lookup"],
					tracelane_response_tool_arg_bytes: [212],
				}),
				content: "absent",
			},
		},
	],
	next_cursor: "next",
};
it("renders metadata and tools with capture off; totals come from the whole session", () => {
	const html = renderToStaticMarkup(
		<SessionTranscript
			data={data}
			sessionId="session"
			viewerRole="viewer"
			userId="user"
		/>,
	);
	expect(html).toContain(
		"Prompt and response text are not recorded for this workspace.",
	);
	expect(html).toContain("0.2 KiB");
	expect(html).toContain("lookup");
	expect(html).toContain("Showing turns 21–21 of 45");
	expect(html.toLowerCase()).toContain("whole recorded session");
	expect(html).toContain("2 more steps");
	expect(html).not.toContain("$0.00");
});
it("shows SDK text despite capture off and distinguishes unloaded content", () => {
	const turn = data.turns[0];
	if (!turn?.exchange) throw new Error("fixture");
	const captured = {
		...data,
		turns: [
			{
				...turn,
				exchange: {
					...turn.exchange,
					content: "captured" as const,
					input_tail: [{ role: "user", content: "Where is my refund?" }],
					output: [{ role: "assistant", content: "Checking…[truncated]" }],
				},
			},
		],
	};
	const html = renderToStaticMarkup(
		<SessionTranscript
			data={captured}
			sessionId="s"
			viewerRole="owner"
			userId="u"
		/>,
	);
	expect(html).toContain("Where is my refund?");
	expect(html).toContain("Truncated when recorded");
	expect(html).not.toContain(
		"Prompt and response text are not recorded for this workspace.",
	);
	const unloaded = {
		...data,
		capture: { workspace_policy: "on" as const },
		turns: [
			{
				...turn,
				intervention: 0,
				exchange: { ...turn.exchange, content: "unloaded" as const },
			},
		],
	};
	expect(
		renderToStaticMarkup(
			<SessionTranscript
				data={unloaded}
				sessionId="s"
				viewerRole="owner"
				userId="u"
			/>,
		),
	).toContain("Text is stored but could not be loaded");
});

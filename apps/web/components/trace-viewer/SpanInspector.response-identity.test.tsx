// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
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
	attributes: JSON.stringify({ gen_ai_request_model: "gpt-4o", ...attributes }),
	aft_ids: [],
	intervention: 0,
	caps: { tool_names: 32, logprob_tokens: 2048 },
});
afterEach(cleanup);

it("shows provider response identity and the bounded logprob summary", () => {
	render(
		<SpanInspector
			span={span({
				gen_ai_response_id: "chatcmpl-123",
				gen_ai_response_model: "gpt-4o-2024-08-06",
				"openai.response.system_fingerprint": "fp_abc",
				gen_ai_response_finish_reasons: ["stop"],
				tracelane_response_logprob_mean: Math.log(0.5),
				tracelane_response_logprob_min: Math.log(0.1),
				tracelane_response_logprob_token_count: 2048,
			})}
		/>,
	);
	expect(screen.getByText("Response identity")).toBeInTheDocument();
	const panel = within(
		screen.getByRole("region", { name: "Response identity" }),
	);
	expect(panel.getByText("chatcmpl-123")).toBeInTheDocument();
	expect(
		screen.getByRole("button", { name: "Copy response ID" }),
	).toBeInTheDocument();
	expect(panel.getByText("fp_abc")).toBeInTheDocument();
	expect(screen.getByText(/first 2,048 tokens only/)).toBeInTheDocument();
	expect(
		screen.getByText(/average token probability.*50%/i),
	).toBeInTheDocument();
});

it("does not imply an absent logprob sample is zero confidence", () => {
	render(
		<SpanInspector span={span({ gen_ai_response_model: "claude-sonnet-4" })} />,
	);
	expect(screen.getByText(/No logprobs recorded/)).toBeInTheDocument();
	expect(screen.queryByText(/0%/)).toBeNull();
});

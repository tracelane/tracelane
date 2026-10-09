// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { SpanInspector } from "./SpanInspector";
import type { Span } from "./types";

const base: Span = {
	span_id: "s1",
	parent_span_id: null,
	name: "chat",
	start_time: "2026-09-30 12:00:00",
	end_time: "2026-09-30 12:00:01",
	duration_us: 1_000_000,
	status_code: 1,
	status_message: "",
	attributes: JSON.stringify({ gen_ai_request_model: "claude-sonnet-4-6" }),
	aft_ids: [],
	intervention: 0,
};
const bucket = {
	uncached_input: 1234,
	cache_read: 300,
	cache_write: 12,
	reasoning: 7,
	output: 50,
};
afterEach(cleanup);

it("shows five exclusive buckets and their measured cost", () => {
	render(
		<SpanInspector
			span={{
				...base,
				usage: {
					convention: "exclusive",
					buckets: bucket,
					bucket_cost_usd: {
						uncached_input: 0.0037,
						cache_read: 0.00009,
						cache_write: 0.000045,
						reasoning: 0.000105,
						output: 0.00075,
					},
					billed_tokens: 1603,
					cost_usd: 0.00469,
					cost_origin: "computed",
					estimated: false,
					input_tokens: 1234,
					output_tokens: 57,
					cache_read_tokens: 300,
					cache_write_tokens: 12,
					reasoning_tokens: 7,
				},
			}}
		/>,
	);
	expect(screen.getByText("Token usage and cost")).toBeInTheDocument();
	expect(screen.getByText("Uncached input")).toBeInTheDocument();
	expect(screen.getByText("Cache read")).toBeInTheDocument();
	expect(screen.getByText("Cache write")).toBeInTheDocument();
	expect(screen.getByText("Reasoning")).toBeInTheDocument();
	expect(screen.getByText("Output (excl. reasoning)")).toBeInTheDocument();
	expect(
		screen.getByText(/Computed from the price catalog/),
	).toBeInTheDocument();
	expect(screen.getByText(/\$0\.000045/)).toBeInTheDocument();
});

it("keeps unknown, provider-reported and unpriced states separate", () => {
	const usage = {
		convention: "unknown" as const,
		buckets: null,
		bucket_cost_usd: null,
		billed_tokens: null,
		cost_usd: 0.4,
		cost_origin: "provider_reported" as const,
		estimated: true,
		input_tokens: 1534,
		output_tokens: 57,
		cache_read_tokens: 300,
		cache_write_tokens: null,
		reasoning_tokens: null,
	};
	const { rerender } = render(<SpanInspector span={{ ...base, usage }} />);
	expect(
		screen.getByText(/cannot tell whether input includes cache reads/),
	).toBeInTheDocument();
	expect(
		screen.getByText(/Cost as reported by the provider/),
	).toBeInTheDocument();
	expect(screen.queryByText("Uncached input")).toBeNull();
	rerender(
		<SpanInspector
			span={{
				...base,
				usage: {
					...usage,
					cost_usd: null,
					cost_origin: "unpriced",
					estimated: false,
				},
			}}
		/>,
	);
	expect(
		screen.getByText(/No price recorded for this model/),
	).toBeInTheDocument();
});

it("shows missing sub-counts and inconsistent arithmetic without a fabricated total", () => {
	const usage = {
		convention: "exclusive" as const,
		buckets: bucket,
		bucket_cost_usd: null,
		billed_tokens: 1603,
		cost_usd: 0.00469,
		cost_origin: "computed" as const,
		estimated: false,
		input_tokens: 1234,
		output_tokens: 57,
		cache_read_tokens: null,
		cache_write_tokens: null,
		reasoning_tokens: null,
	};
	const { rerender } = render(<SpanInspector span={{ ...base, usage }} />);
	expect(screen.getByText("Output (incl. any reasoning)")).toBeInTheDocument();
	expect(screen.getAllByText("not reported").length).toBeGreaterThan(0);
	expect(screen.queryByText("Billed tokens")).toBeNull();
	rerender(
		<SpanInspector
			span={{
				...base,
				usage: { ...usage, buckets: null, billed_tokens: null },
			}}
		/>,
	);
	expect(screen.getByText(/Counts are inconsistent/)).toBeInTheDocument();
});

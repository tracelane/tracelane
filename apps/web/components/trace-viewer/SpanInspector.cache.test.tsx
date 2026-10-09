// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
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
	attributes: JSON.stringify({
		gen_ai_request_model: "claude-sonnet-4-6",
		...attributes,
	}),
	aft_ids: [],
	intervention: 0,
});
afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

it("distinguishes cache not enabled, miss, exact and semantic hit", () => {
	const { rerender } = render(<SpanInspector span={span({})} />);
	expect(
		screen.getByText("Response cache not enabled for this request"),
	).toBeInTheDocument();
	rerender(
		<SpanInspector span={span({ tracelane_semantic_cache_hit: false })} />,
	);
	expect(screen.getByText("Consulted — miss")).toBeInTheDocument();
	rerender(
		<SpanInspector
			span={span({
				tracelane_semantic_cache_hit: true,
				tracelane_semantic_cache_tier: "exact",
				tracelane_semantic_cache_similarity: 0.99,
			})}
		/>,
	);
	expect(screen.getByText("Served from cache")).toBeInTheDocument();
	expect(screen.queryByText(/Similarity:/)).toBeNull();
	rerender(
		<SpanInspector
			span={span({
				tracelane_semantic_cache_hit: true,
				tracelane_semantic_cache_tier: "semantic",
				tracelane_semantic_cache_similarity: 0.91,
				tracelane_semantic_cache_cost_saved_usd: 0.25,
			})}
		/>,
	);
	expect(screen.getByText(/Similarity: 0.91/)).toBeInTheDocument();
	expect(screen.getByText(/Saved \$0.25/)).toBeInTheDocument();
});

it("shows a source trace that has aged out as no longer retained", async () => {
	vi.stubGlobal(
		"fetch",
		vi.fn().mockResolvedValue(new Response(null, { status: 404 })),
	);
	render(
		<SpanInspector
			span={span({
				tracelane_semantic_cache_hit: true,
				tracelane_semantic_cache_source_trace_id:
					"11111111-2222-3333-4444-555555555555",
			})}
		/>,
	);
	expect(
		await screen.findByText("source trace no longer retained"),
	).toBeInTheDocument();
});

const invalidTraceIds = [
	".",
	"..",
	"../settings",
	"bad/id",
	"%2e%2e",
	"javascript:alert(1)",
	"abcd",
	"g".repeat(32),
	"a".repeat(33),
	`${"a".repeat(32)}\n`,
];
it.each(invalidTraceIds)(
	"does not link or fetch invalid cache source %j",
	(traceId) => {
		const fetch = vi.fn();
		vi.stubGlobal("fetch", fetch);
		render(
			<SpanInspector
				span={span({
					tracelane_semantic_cache_hit: true,
					tracelane_semantic_cache_source_trace_id: traceId,
				})}
			/>,
		);
		expect(screen.queryByRole("link", { name: "Source trace" })).toBeNull();
		expect(fetch).not.toHaveBeenCalledWith(
			expect.stringMatching(/^\/api\/traces\//),
			expect.anything(),
		);
	},
);
it.each([
	"11111111-2222-3333-4444-555555555555",
	"ABCDEF0123456789abcdef0123456789",
])("links and checks valid cache source %s", async (traceId) => {
	const fetch = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
	vi.stubGlobal("fetch", fetch);
	render(
		<SpanInspector
			span={span({
				tracelane_semantic_cache_hit: true,
				tracelane_semantic_cache_source_trace_id: traceId,
			})}
		/>,
	);
	expect(screen.getByRole("link", { name: "Source trace" })).toHaveAttribute(
		"href",
		`/traces/${traceId}`,
	);
	await waitFor(() =>
		expect(fetch).toHaveBeenCalledWith(
			`/api/traces/${traceId}/spans`,
			expect.anything(),
		),
	);
});

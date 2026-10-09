// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SpanInspector } from "./SpanInspector";
import type { Span } from "./types";

const span = (attributes: Record<string, unknown>): Span => ({
	span_id: "s1",
	parent_span_id: null,
	name: "agent",
	start_time: "2026-09-30 12:04:00",
	end_time: "2026-09-30 12:04:01",
	duration_us: 1_000_000,
	status_code: 2,
	status_message: "",
	attributes: JSON.stringify(attributes),
	aft_ids: [],
	intervention: 0,
});
afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

describe("OTLP span details", () => {
	it("distinguishes withheld content from content the producer never sent", () => {
		const { rerender } = render(
			<SpanInspector span={span({ tracelane_content_withheld: ["input"] })} />,
		);
		expect(screen.getByText(/Prompt text not recorded/)).toBeInTheDocument();
		expect(screen.queryByText("Output")).toBeNull();
		rerender(<SpanInspector span={span({})} />);
		expect(screen.queryByText(/Prompt text not recorded/)).toBeNull();
	});

	it("links owners to capture settings and keeps redaction markers visible", async () => {
		vi.stubGlobal(
			"fetch",
			vi
				.fn()
				.mockImplementation(() =>
					Promise.resolve(Response.json({ can_edit: true })),
				),
		);
		render(
			<SpanInspector
				span={span({
					tracelane_content_withheld: ["output"],
					input_value: "[REDACTED:email]",
				})}
			/>,
		);
		expect(screen.getAllByText("[REDACTED:email]").length).toBeGreaterThan(0);
		expect(screen.getByText(/Response text not recorded/)).toBeInTheDocument();
		expect(
			await screen.findByRole("link", {
				name: "Change in Settings → Workspace",
			}),
		).toHaveAttribute("href", "/settings/workspace");
	});

	it("shows resource, exception, retrieval, events, links and dropped attributes", () => {
		render(
			<SpanInspector
				span={span({
					service_name: "checkout",
					service_version: "1.4.2",
					deployment_environment: "prod",
					exception_type: "ValueError",
					exception_message: "bad index",
					tracelane_retrieval_documents: [{ id: "doc-17", score: 0.82 }],
					tracelane_events: [
						{ name: "exception", time_unix_us: 1_000_000, attributes: {} },
					],
					tracelane_links: [{ trace_id: "t1", span_id: "s2" }],
					tracelane_attrs_dropped: { count: 8, reasons: { cap: 8 } },
				})}
			/>,
		);
		expect(screen.getByText(/checkout.*1.4.2.*prod/)).toBeInTheDocument();
		expect(screen.getByText(/Exception: ValueError/)).toBeInTheDocument();
		expect(screen.getAllByText(/doc-17.*0.82/).length).toBeGreaterThan(0);
		expect(screen.getByText("Events (1)")).toBeInTheDocument();
		expect(screen.getByText("Links (1)")).toBeInTheDocument();
		expect(screen.getByText("8 attributes not kept")).toBeInTheDocument();
	});
});

it.each([
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
])("does not link invalid OTLP trace id %j", (traceId) => {
	render(
		<SpanInspector
			span={span({ tracelane_links: [{ trace_id: traceId, span_id: "s2" }] })}
		/>,
	);
	expect(screen.queryByRole("link", { name: traceId })).toBeNull();
});
it.each([
	"11111111-2222-3333-4444-555555555555",
	"ABCDEF0123456789abcdef0123456789",
])("links valid OTLP trace id %s", (traceId) => {
	render(
		<SpanInspector
			span={span({ tracelane_links: [{ trace_id: traceId, span_id: "s2" }] })}
		/>,
	);
	expect(screen.getByRole("link", { name: traceId })).toHaveAttribute(
		"href",
		`/traces/${traceId}`,
	);
});

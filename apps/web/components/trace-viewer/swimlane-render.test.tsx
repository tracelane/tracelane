import { traceTimeBounds } from "@/lib/trace-summary";
import { computeVisibleRows } from "@/lib/trace-tree";
import { computeLanes } from "@/lib/trace/lanes";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { SwimlaneView } from "./SwimlaneView";
import { TraceDetailView } from "./TraceDetailView";
import { WaterfallView } from "./WaterfallView";
import type { Span } from "./types";

/**
 * OBS-49 proofs #3 and #4 (spec §7): render parity between Tree and Lanes, a
 * single-span/single-lane trace, and the Failures-only "N hidden" count.
 *
 * Same convention as `waterfall-render.test.tsx`: `renderToStaticMarkup` in
 * node, asserting the real markup rather than presence alone — a bar in the
 * wrong place is still a bar.
 */

const h = createElement;

function span(over: Partial<Span> & { span_id: string }): Span {
	return {
		parent_span_id: over.parent_span_id ?? null,
		name: over.name ?? "gen_ai.chat",
		start_time: "2026-08-15 10:00:00.000000",
		start_time_us: over.start_time_us ?? 0,
		duration_us: over.duration_us ?? 1_000,
		status_code: over.status_code ?? 0,
		status_message: over.status_message ?? "",
		attributes: over.attributes ?? "{}",
		aft_ids: over.aft_ids ?? [],
		intervention: over.intervention ?? 0,
		...over,
	} as Span;
}

/** Pulls `left:N%` / `width:N%` off the FIRST bar following a given
 * `data-span-row="id"` marker in a rendered HTML string — the same
 * inline-style pair both views resolve from `barGeometry`. */
function barStyle(
	html: string,
	spanId: string,
): { left: string; width: string } {
	const marker = `data-span-row="${spanId}"`;
	const at = html.indexOf(marker);
	if (at === -1) throw new Error(`${spanId} not found in rendered HTML`);
	const rowHtml = html.slice(at, at + 2000);
	const left = rowHtml.match(/left:(\d+(?:\.\d+)?)%/);
	const width = rowHtml.match(/width:(\d+(?:\.\d+)?)%/);
	const leftPct = left?.[1];
	const widthPct = width?.[1];
	if (leftPct === undefined || widthPct === undefined) {
		throw new Error(`no left/width style found near ${spanId}`);
	}
	return { left: leftPct, width: widthPct };
}

describe("OBS-49 proof #3 — render parity between Tree (Waterfall) and Lanes", () => {
	// No agent attributes anywhere → every span resolves to the ONE "main"
	// lane, so the same three spans appear in both views and the ONLY thing
	// under test is whether the two components resolve identical geometry.
	const spans = [
		span({ span_id: "root", start_time_us: 0, duration_us: 1_000_000 }),
		span({
			span_id: "child-a",
			parent_span_id: "root",
			start_time_us: 100_000,
			duration_us: 200_000,
		}),
		span({
			span_id: "child-b",
			parent_span_id: "root",
			start_time_us: 400_000,
			duration_us: 500_000,
			status_code: 2,
		}),
	];
	const bounds = traceTimeBounds(spans);
	const startUs = bounds.startUs;
	const totalUs = Math.max(0, bounds.endUs - bounds.startUs);

	const rows = computeVisibleRows(spans, {
		collapsed: new Set(),
		query: "",
	});
	const lanes = computeLanes(spans);

	const waterfallHtml = renderToStaticMarkup(
		h(WaterfallView, {
			rows,
			startUs,
			totalUs,
			onSelectSpan: () => {},
			onToggleCollapse: () => {},
		}),
	);
	const lanesHtml = renderToStaticMarkup(
		h(SwimlaneView, {
			lanes,
			startUs,
			totalUs,
			onSelectSpan: () => {},
		}),
	);

	it("renders the same number of span bars in both views", () => {
		const waterfallCount = (waterfallHtml.match(/data-span-row="/g) ?? [])
			.length;
		const lanesCount = (lanesHtml.match(/data-span-row="/g) ?? []).length;
		expect(waterfallCount).toBe(spans.length);
		expect(lanesCount).toBe(spans.length);
	});

	it.each(spans.map((s) => s.span_id))(
		"positions %s identically (left/width) in both views",
		(spanId) => {
			expect(barStyle(lanesHtml, spanId)).toEqual(
				barStyle(waterfallHtml, spanId),
			);
		},
	);
});

describe("OBS-49 proof #4 — a single-span trace degenerates to one lane, not a bug", () => {
	const html = renderToStaticMarkup(
		h(TraceDetailView, { spans: [span({ span_id: "solo" })] }),
	);

	it("carries the degenerate-trace tooltip on the Lanes option", () => {
		expect(html).toContain("One agent in this trace");
	});

	it("does not crash and still renders the Failures-only control", () => {
		expect(html).toContain("Failures only");
	});
});

describe("OBS-49 — Failures-only shows an honest hidden count, never silently", () => {
	const spans = [
		span({ span_id: "ok-1", status_code: 0 }),
		span({ span_id: "ok-2", status_code: 0 }),
		span({ span_id: "bad", status_code: 2 }),
	];

	it("a clean trace (zero errors) still renders the toggle, reachable at 0", () => {
		const clean = [span({ span_id: "only-ok", status_code: 0 })];
		const html = renderToStaticMarkup(h(TraceDetailView, { spans: clean }));
		expect(html).toContain("Failures only");
		expect(html).toContain("(0)");
	});

	it("renders the real error total next to the toggle", () => {
		const html = renderToStaticMarkup(h(TraceDetailView, { spans }));
		expect(html).toContain("(1)");
	});
});

describe("OBS-49 regression — the lane card is not its own sticky scroll container", () => {
	// A lane card that carries `overflow-hidden` becomes the NEAREST scrolling
	// ancestor for its own `position: sticky` header (CSS Overflow spec) even
	// though the card itself never scrolls. That makes the header permanently
	// evaluate as "stuck", painted `top-6` below its own top — overlapping the
	// first row(s), which stay at the position ordinary flow already reserved
	// for them. Pin the markup shape that keeps this fixed: the sticky header
	// carries its own corner rounding (no longer borrowed from a clipping
	// parent), and the card that contains it does not.
	const spans = [
		span({
			span_id: "solo-agent-span",
			attributes: JSON.stringify({ "gen_ai.agent.name": "researcher" }),
		}),
	];
	const lanes = computeLanes(spans);
	const html = renderToStaticMarkup(
		h(SwimlaneView, {
			lanes,
			startUs: 0,
			totalUs: 1_000_000,
			onSelectSpan: () => {},
		}),
	);

	it("the sticky lane header carries its own rounded-t-md", () => {
		const headerAt = html.indexOf("sticky top-6");
		expect(headerAt).toBeGreaterThan(-1);
		const headerTag = html.slice(Math.max(0, headerAt - 200), headerAt + 250);
		expect(headerTag).toContain("rounded-t-md");
	});

	it("the lane card wrapping the sticky header does not carry overflow-hidden", () => {
		const headerAt = html.indexOf("sticky top-6");
		const cardOpenAt = html.lastIndexOf("surface-card", headerAt);
		const cardTag = html.slice(cardOpenAt, headerAt);
		expect(cardTag).not.toContain("overflow-hidden");
	});
});

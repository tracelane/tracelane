import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { WaterfallView } from "./WaterfallView";
import type { Span } from "./types";

/**
 * WaterfallView rendered-shape tests — THE FIRST ONES THIS COMPONENT HAS EVER HAD.
 *
 * Read that again, because it is the finding. The waterfall is the DEFAULT trace view
 * (`TraceDetailView` opens on `useState<ViewMode>("waterfall")`), and nothing asserted
 * its markup: no unit test imported it, and the e2e trace-detail suite locates spans by
 * `[role="treeitem"], ol li` — selectors sourced from the TranscriptSpine, which is the
 * view behind the toggle. WaterfallView emits no `<ol>`, no `<li>` and no `treeitem`,
 * so every e2e assertion about "the spans" has been running against a view the user is
 * not looking at. Playwright is `continue-on-error` in CI, so that stayed invisible.
 *
 * These assert geometry, not presence — a bar in the wrong place is still a bar.
 */

const h = createElement;

function span(over: Partial<Span> & { span_id: string }): Span {
	return {
		trace_id: "t1",
		parent_span_id: null,
		name: over.name ?? "gen_ai.chat",
		start_time: "2026-08-15 10:00:00.000000",
		start_time_us: over.start_time_us ?? 0,
		duration_us: over.duration_us ?? 1_000,
		status_code: over.status_code ?? 0,
		attributes: over.attributes ?? {},
		aft_ids: [],
		intervention: 0,
		...over,
	} as Span;
}

const rows = (spans: Span[]) =>
	spans.map((s, i) => ({
		span: s,
		depth: i === 0 ? 0 : 1,
		hasChildren: i === 0 && spans.length > 1,
		collapsed: false,
	}));

const render = (spans: Span[], startUs: number, totalUs: number): string =>
	renderToStaticMarkup(
		h(WaterfallView, {
			// biome-ignore lint/suspicious/noExplicitAny: VisibleRow is structural here.
			rows: rows(spans) as any,
			startUs,
			totalUs,
			onSelectSpan: () => {},
			onToggleCollapse: () => {},
		}),
	);

describe("WaterfallView — the axis is ADR-074 §7's ruler, not a local one", () => {
	const base = 1_760_000_000_000_000; // epoch µs
	const spans = [
		span({ span_id: "a", start_time_us: base, duration_us: 1_400_000 }),
		span({
			span_id: "b",
			name: "tool.call",
			start_time_us: base + 200_000,
			duration_us: 300_000,
		}),
	];
	const html = render(spans, base, 1_400_000);

	it("renders the shared TimeRuler, identified by its own data attribute", () => {
		expect(html).toContain("data-time-ruler");
	});

	it("labels the axis in ELAPSED time", () => {
		expect(html).toContain("Elapsed time axis");
		expect(html).not.toContain("Time axis, UTC");
	});

	it("stays elapsed for a trace of a MINUTE OR MORE — where `mode` is load-bearing", () => {
		// THIS is the fixture that makes `mode="relative"` matter, and the 1.4s one
		// above does not: TimeRuler auto-switches to relative only UNDER 60s, so a
		// long-running agent trace with `mode` omitted falls through to wall-clock
		// formatting of startMs=0 and renders 00:00:00 / 00:15:00 / … — the UTC clock
		// of 1 January 1970, stamped across the axis.
		//
		// Written after the first version of this test passed with `mode` deleted.
		const long = render(
			[span({ span_id: "L", start_time_us: base, duration_us: 90_000_000 })],
			base,
			90_000_000, // 90s
		);
		expect(long).toContain("Elapsed time axis");
		expect(long).not.toContain("Time axis, UTC");
		expect(long).not.toMatch(/>\d\d:\d\d:\d\d</);
		expect(long).toContain("90.00s");
	});

	it("treats totalUs as MICROseconds — a unit slip makes the axis 1000x wrong", () => {
		// `endMs={totalUs / 1000}` is the only correct conversion. Dropping the divide
		// turns a 1.4s trace into a 1,400s axis and every bar into a sliver. Asserted on
		// the ruler's own sentence, for the reason given above.
		expect(html).toContain("Elapsed time axis, 1.40s total");
		expect(html).not.toContain("1400.00s");
	});

	it("states the trace total exactly, matching the duration label on the bar", () => {
		// 1.4s. Both must be fmtDur's string — the axis end and the bar label sit
		// millimetres apart and disagreeing there is the tell of two formatters.
		//
		// SCOPED TO THE RULER ON PURPOSE. A bare `toContain("1.40s")` passes even with
		// the axis 1000x wrong, because the BAR carries its own "1.40s" label three
		// elements away. The first version of this test did exactly that and survived
		// its own mutation. The ruler's sr-only sentence is the one string only the
		// axis can produce.
		expect(html).toContain("Elapsed time axis, 1.40s total");
		expect(html).toContain("1.40s");
	});

	it("draws no axis at all for a zero-duration trace rather than inventing one", () => {
		// Previously every tick collapsed onto 0% and the axis read "0µs" five times.
		const flat = render([span({ span_id: "z", duration_us: 0 })], base, 0);
		expect(flat).not.toContain("font-mono");
	});
});

describe("WaterfallView — bar geometry is the real offset and duration", () => {
	const base = 1_760_000_000_000_000;
	const spans = [
		span({ span_id: "a", start_time_us: base, duration_us: 1_400_000 }),
		span({
			span_id: "b",
			start_time_us: base + 350_000,
			duration_us: 700_000,
		}),
	];
	const html = render(spans, base, 1_400_000);

	it("positions a child bar at its true fraction of the trace window", () => {
		// 350ms into 1400ms = 25%; 700ms of 1400ms = 50%.
		expect(html).toContain("left:25%");
		expect(html).toContain("width:50%");
	});

	it("keeps the root bar at the origin, full width", () => {
		expect(html).toContain("left:0%");
		expect(html).toContain("width:100%");
	});

	it("marks an errored span with the danger token, and says so in text too", () => {
		const withErr = render(
			[span({ span_id: "e", duration_us: 1_000_000, status_code: 2 })],
			base,
			1_000_000,
		);
		expect(withErr).toContain("bg-danger");
		expect(withErr).toContain("error"); // the title text, never colour alone
	});
});

describe("WaterfallView — the ruler shares the bars' grid column", () => {
	it("puts the ruler in the SAME 2fr/3fr track the bars resolve against", () => {
		const base = 1_760_000_000_000_000;
		const html = render(
			[span({ span_id: "a", duration_us: 500_000, start_time_us: base })],
			base,
			500_000,
		);
		// Header and rows must declare byte-identical tracks and padding, or every
		// tick is offset from the bar it describes. This is the whole reason the
		// ruler is a direct grid child with no wrapper.
		const tracks = html.match(/grid-cols-\[minmax\(0,2fr\)_3fr\]/g) ?? [];
		expect(tracks.length).toBeGreaterThanOrEqual(2);
		const rulerAt = html.indexOf("data-time-ruler");
		const headerAt = html.indexOf("grid-cols-[minmax(0,2fr)_3fr]");
		expect(rulerAt).toBeGreaterThan(headerAt);
	});
});

describe("WaterfallView — the e2e span hook (the DEFAULT view must be selectable)", () => {
	const base = 1_760_000_000_000_000;
	const spans = [
		span({ span_id: "root", start_time_us: base, duration_us: 900_000 }),
		span({
			span_id: "child",
			name: "tool.call",
			start_time_us: base + 100_000,
			duration_us: 200_000,
		}),
	];
	const html = render(spans, base, 900_000);

	it("emits one [data-span-row] per span, carrying the span_id", () => {
		// This attribute is the ONLY stable hook the e2e suite has on the default
		// view. `traceDetail().spanNodes` in e2e/fixtures/selectors.ts selects it;
		// dropping it silently returns that suite to asserting against the
		// TranscriptSpine, which is the view behind the toggle.
		const rowCount = (html.match(/data-span-row="/g) ?? []).length;
		expect(rowCount).toBe(2);
		expect(html).toContain('data-span-row="root"');
		expect(html).toContain('data-span-row="child"');
	});

	it("still emits none of the TranscriptSpine selectors — the two views are distinct", () => {
		// The reason a single locator has to cover both: these are genuinely
		// different markup, so a spine-only selector matches nothing here. If this
		// ever starts failing, the views have converged and the selector union in
		// e2e/fixtures/selectors.ts should be revisited rather than widened again.
		expect(html).not.toContain('role="treeitem"');
		expect(html).not.toContain("<ol");
		expect(html).not.toContain("<li");
	});
});

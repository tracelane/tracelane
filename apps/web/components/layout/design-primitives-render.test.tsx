/**
 * Rendered-shape proofs for the ADR-074 primitives.
 *
 * Every assertion runs against `renderToStaticMarkup` of the real component — the markup
 * a customer receives — not against the props that went in. `docs/reference/TRAPS.md` §34
 * was earned here by a suite that tested a pure helper and was read as covering the
 * component; these are deliberately the other kind.
 *
 * What is asserted is BEHAVIOUR the design system depends on, not styling:
 *  · bars are discrete marks, so a zero bucket is a visible zero and never a gap
 *  · colour is DATA — a semantic tone reaches the fill, and emphasis is opacity not hue
 *  · a row of tiles aligns, which is a structural property (`h-full`), not a look
 *  · the ledger chip states a RANGE, never a per-trace verified claim (§9 honesty lock)
 */

import {
	BarChart,
	LedgerSeqChip,
	StatCard,
	StatGrid,
	TimeRuler,
} from "@tracelanedev/ui";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

const html = (el: Parameters<typeof renderToStaticMarkup>[0]) =>
	renderToStaticMarkup(el);

describe("BarChart — discrete marks, colour is data", () => {
	const data = [
		{ label: "00", value: 10 },
		{ label: "01", value: 0 },
		{ label: "02", value: 5 },
	];

	it("renders one rect per bucket INCLUDING the zero one", () => {
		const out = html(createElement(BarChart, { data, label: "Requests" }));
		// 3 bar rects. A zero bucket that rendered nothing would be indistinguishable
		// from a missing bucket, which is the exact thing bars exist to separate.
		expect((out.match(/<rect/g) ?? []).length).toBe(3);
		expect(out).toContain('height="0"');
	});

	it("never draws a bar taller than the plot for a flat-zero series", () => {
		const flat = [
			{ label: "a", value: 0 },
			{ label: "b", value: 0 },
		];
		const out = html(createElement(BarChart, { data: flat, label: "Empty" }));
		// Guarding the divisor is what stops 0/0 painting full-height bars.
		expect(out).not.toMatch(/height="13[0-9]"/);
	});

	it("puts a semantic tone on the fill only where the datum carries one", () => {
		const out = html(
			createElement(BarChart, {
				label: "Errors",
				data: [
					{ label: "a", value: 3 },
					{ label: "b", value: 1, tone: "danger" as const },
				],
			}),
		);
		expect(out).toContain("fill-danger");
		expect(out).toContain("fill-info"); // the default: neutral data
	});

	it("emphasises by WEIGHT, not hue — so it survives monochrome", () => {
		const out = html(
			createElement(BarChart, { data, label: "R", highlight: 0 }),
		);
		expect(out).toContain("opacity-100");
		expect(out).toContain("opacity-70");
	});

	it("names itself for a screen reader and states an empty range honestly", () => {
		expect(
			html(createElement(BarChart, { data, label: "Requests" })),
		).toContain('aria-label="Requests"');
		expect(
			html(createElement(BarChart, { data: [], label: "Requests" })),
		).toContain("No data in this range");
	});
});

describe("StatCard / StatGrid — a row of tiles aligns", () => {
	it("makes every tile full-height so values share a baseline", () => {
		// `h-full` + the grid's `items-stretch` is the whole alignment mechanism. A tile
		// without a sub-line used to float its value while its neighbour sat low.
		const out = html(
			createElement(StatCard, { label: "Traces", value: "1,204" }),
		);
		expect(out).toContain("h-full");
	});

	it("reserves the sub-line box even when there is no sub-line", () => {
		const withSub = html(
			createElement(StatCard, { label: "A", value: "1", sub: "of 10" }),
		);
		const without = html(createElement(StatCard, { label: "A", value: "1" }));
		expect(withSub).toContain("of 10");
		// The reserved box is aria-hidden — it holds height without lying to a reader.
		expect(without).toContain('aria-hidden="true"');
	});

	it("renders a delta with a direction glyph AND a sign, never colour alone", () => {
		const out = html(
			createElement(StatCard, {
				label: "p95",
				value: "412ms",
				delta: {
					value: "+8%",
					direction: "up" as const,
					tone: "danger" as const,
				},
			}),
		);
		expect(out).toContain("+8%");
		expect(out).toContain("▲");
	});

	it("draws the micro series as BARS", () => {
		const out = html(
			createElement(StatCard, {
				label: "Traffic",
				value: "9",
				spark: [1, 4, 2, 8],
			}),
		);
		expect((out.match(/<rect/g) ?? []).length).toBe(4);
	});

	it("the INVERSE card paints its value in ink-inverse, never action", () => {
		// Ink on ink. `text-action` was correct while --action was lava; ADR-074 remapped
		// it to the ink family, and --surface-inverse is ALSO ink — so in LIGHT theme the
		// error-budget burn rate rendered #0d0d0d on #0d0d0d, a 1:1 ratio, invisible.
		// Dark was fine, which is exactly why it shipped: the bug only existed in one
		// theme, and the theme it broke was the DEFAULT one.
		const out = html(
			createElement(StatCard, {
				label: "Error budget",
				value: "70.75×",
				variant: "inverse" as const,
			}),
		);
		expect(out).toContain("bg-surface-inverse");
		expect(out).toContain("text-ink-inverse");
		expect(
			out,
			"an inverse card painting its value in text-action is invisible in light theme",
		).not.toMatch(/class="[^"]*\btext-action\b/);
		expect(out).toContain("70.75×");
	});

	it("groups tiles under a small-caps label and stretches the row", () => {
		// JSX here on purpose: biome forbids passing `children` as a prop, and
		// `StatGridProps` requires it, so the createElement form cannot satisfy both.
		const out = html(
			<StatGrid title="Traffic">
				<StatCard label="A" value="1" />
			</StatGrid>,
		);
		expect(out).toContain("Traffic");
		expect(out).toContain("items-stretch");
	});
});

describe("TimeRuler — labelled majors, silent minors", () => {
	const start = Date.UTC(2026, 7, 15, 10, 0, 0);

	it("labels major ticks and draws minors WITHOUT labels", () => {
		const out = html(
			createElement(TimeRuler, { startMs: start, endMs: start + 3_600_000 }),
		);
		// Majors carry a mono timestamp; minors are bare 1px divs. If minors were
		// labelled the axis would become the noise §7 exists to prevent.
		const labels = out.match(/font-mono/g) ?? [];
		const minors = out.match(/h-1 w-px/g) ?? [];
		expect(labels.length).toBeGreaterThan(0);
		expect(minors.length).toBeGreaterThan(labels.length);
	});

	it("renders UTC for absolute windows and elapsed for short ones", () => {
		expect(
			html(
				createElement(TimeRuler, { startMs: start, endMs: start + 3_600_000 }),
			),
		).toContain("Time axis, UTC");
		// A sub-minute window is always relative — wall-clock seconds are unreadable there.
		expect(
			html(createElement(TimeRuler, { startMs: start, endMs: start + 5_000 })),
		).toContain("Elapsed time axis");
	});

	it("renders nothing for an inverted window instead of inventing an axis", () => {
		const out = html(
			createElement(TimeRuler, { startMs: start, endMs: start - 1 }),
		);
		expect(out).not.toContain("font-mono");
	});
});

describe("LedgerSeqChip — a RANGE, never a per-trace verified claim", () => {
	it("states the sequence range and says workspace, not trace", () => {
		const out = html(createElement(LedgerSeqChip, { from: 15700, to: 15799 }));
		expect(out).toContain("15700");
		expect(out).toContain("15799");
		expect(out).toContain("workspace");
	});

	it("never claims verification and never spends verify-green", () => {
		// ADR-074 §9 + the honesty locks: the chain is PER-TENANT, so a per-trace
		// "verified" chip would be a claim the data does not support (B-241/B-249).
		const out = html(createElement(LedgerSeqChip, { from: 1, to: 2 }));
		expect(out.toLowerCase()).not.toContain("verified");
		expect(out).not.toContain("text-ok");
		expect(out).not.toContain("seal");
	});
});

/**
 * DSH-13 / founder screenshot 2026-09-07: a dashboard stat tile stretches to the
 * tallest tile in its grid row, and `StatCard`'s default `mt-auto` then pushed the
 * number to the very bottom of a mostly-empty card sitting beside a 480px chart.
 *
 * `valueAlign` is the scoped opt-out. Both directions are asserted, because the
 * DEFAULT is load-bearing too: it is what gives a row of KPI tiles one shared
 * baseline, and silently losing it would be a different regression.
 *
 * Server-rendered to a string rather than mounted: this suite runs in vitest's
 * `node` environment (`vitest.config.ts`), the same shape as
 * `segmented-control-render.test.tsx`.
 */
import { StatCard } from "@tracelanedev/ui";
import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

/** The markup of the element that wraps the value. */
function valueBlockClasses(align?: "baseline" | "top"): string {
	const html = renderToStaticMarkup(
		h(StatCard, { label: "Requests", value: "4,821", valueAlign: align }),
	);
	// The value block is the last <div> opened before the value text.
	const idx = html.indexOf("4,821");
	expect(idx).toBeGreaterThan(-1);
	const before = html.slice(0, idx);
	const open = before.lastIndexOf("<div");
	return before.slice(open, before.indexOf(">", open) + 1);
}

describe("StatCard valueAlign", () => {
	it("defaults to a bottom-pushed value, so a KPI row shares one baseline", () => {
		expect(
			renderToStaticMarkup(h(StatCard, { label: "Requests", value: "4,821" })),
		).toContain("mt-auto");
	});

	it("valueAlign='top' drops mt-auto, for a tile stretched by a taller neighbour", () => {
		expect(
			renderToStaticMarkup(
				h(StatCard, { label: "Requests", value: "4,821", valueAlign: "top" }),
			),
		).not.toContain("mt-auto");
	});

	it("valueAlign='baseline' is explicit-equals-default, not a third behaviour", () => {
		expect(valueBlockClasses("baseline")).toBe(valueBlockClasses(undefined));
	});
});

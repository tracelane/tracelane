import { TimeRuler } from "@tracelanedev/ui";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

/**
 * TimeRuler GEOMETRY — the tests that were missing, and whose absence is why a
 * component shipped built, unit-tested, exported and broken (ADR-074 §7).
 *
 * THE POINT OF THIS FILE, stated so it is not weakened later. The pre-existing
 * TimeRuler tests assert `minors.length > labels.length` by counting occurrences of
 * the substring `h-1 w-px` in the markup. That count was correct the whole time the
 * minors were rendering stacked on top of their own majors at 1/600th of their
 * intended offset — because a mark in the wrong place is still a mark in the string.
 *
 * A probe that counts marks cannot tell a ruler from a smear. Every assertion below
 * reads a POSITION.
 *
 * Each `describe` names the defect it would have caught. They are written so that
 * reverting the fix turns them red — that is the only property that makes them
 * evidence (CLAUDE.md §1).
 */

const h = createElement;
const render = (p: Parameters<typeof TimeRuler>[0]): string =>
	renderToStaticMarkup(h(TimeRuler, p));

/** Inline `left:N%` values, in document order, for elements matching a class marker. */
function leftsOf(html: string, marker: string): number[] {
	const out: number[] = [];
	// Each mark is one <div ...> tag; find the tags carrying the marker class and read
	// their inline left. React emits `style="left:12.5%"` in static markup.
	for (const tag of html.match(/<div[^>]*>/g) ?? []) {
		if (!tag.includes(marker)) continue;
		const m = tag.match(/left:\s*([0-9.]+)%/);
		if (m?.[1] !== undefined) out.push(Number(m[1]));
	}
	return out;
}

/** Major ticks are the 1.5-unit marks; their wrapper carries the position. */
const majorLefts = (html: string): number[] => {
	const out: number[] = [];
	// The wrapper is `<div class="absolute top-0" style="left:N%">` and its first child
	// is the h-1.5 tick. Read the wrappers by matching the pair in source order.
	for (const m of html.matchAll(
		/<div class="absolute top-0" style="left:([0-9.]+)%">/g,
	)) {
		if (m[1] !== undefined) out.push(Number(m[1]));
	}
	return out;
};
const minorLefts = (html: string): number[] => leftsOf(html, "h-1 w-px");

describe("TimeRuler — defect 1: minors must sit BETWEEN majors, across the whole axis", () => {
	// A 1.4s waterfall window: step snaps to 250ms, so majors land every 17.86%.
	const html = render({ startMs: 0, endMs: 1400, mode: "relative" });

	it("spreads minors across the axis, not into the first 15%", () => {
		const minors = minorLefts(html);
		expect(minors.length).toBeGreaterThan(0);
		// THE DISCRIMINATOR. Before the fix every minor's inline left was computed as a
		// fraction of the STEP, not of the span — so for this window the only three
		// values emitted were 4.46 / 8.93 / 13.39, repeated once per major, and the
		// largest was 13.39. Any implementation that positions minors against the ruler
		// puts one past three-quarters of the way along.
		expect(Math.max(...minors)).toBeGreaterThan(75);
	});

	it("puts exactly minorPerMajor minors strictly between each pair of majors", () => {
		const majors = majorLefts(html);
		const minors = minorLefts(html);
		expect(majors.length).toBeGreaterThan(2);
		for (let i = 0; i < majors.length - 1; i += 1) {
			const lo = majors[i];
			const hi = majors[i + 1];
			if (lo === undefined || hi === undefined) continue;
			const between = minors.filter((p) => p > lo + 1e-9 && p < hi - 1e-9);
			// 3 is the default minorPerMajor (quarter divisions). The last gap is the
			// exact-total tick, which sits closer than a full step, so it may hold fewer.
			if (i < majors.length - 2) expect(between).toHaveLength(3);
			else expect(between.length).toBeLessThanOrEqual(3);
		}
	});

	it("emits no duplicate minor positions — the old build repeated one triple per major", () => {
		const minors = minorLefts(html);
		expect(new Set(minors.map((p) => p.toFixed(4))).size).toBe(minors.length);
	});
});

describe("TimeRuler — defect 2: an edge tick keeps its true position", () => {
	// Absolute mode, sized so a nice-step major lands strictly inside the outer 4%
	// band. Step snaps to 10s; a 61.224s window puts the 60s major at 98.0%.
	// `start` is aligned to the step so the first major is at 0 and the arithmetic
	// below is exact rather than dependent on where the hour falls.
	const start = Math.ceil(Date.UTC(2026, 7, 15, 10, 0, 0) / 10_000) * 10_000;
	const html = render({ startMs: start, endMs: start + 61_224 });

	it("positions every tick with an inline left, never by snapping it to the edge", () => {
		const majors = majorLefts(html);
		// One `left:` wrapper per labelled tick. Before the fix, any major outside
		// 4%..96% was emitted as `style="right:0"` and carried no left at all — so the
		// wrapper count fell below the label count and the tick physically moved.
		const labels = (html.match(/font-mono/g) ?? []).length;
		expect(majors).toHaveLength(labels);
	});

	it("keeps a >96% tick at its real fraction, not at 100%", () => {
		const majors = majorLefts(html);
		const nearEdge = majors.filter((p) => p > 96);
		expect(nearEdge.length).toBeGreaterThan(0);
		// It must be the true value, not rounded out to the container edge.
		for (const p of nearEdge) expect(p).toBeLessThan(100);
	});
});

describe("TimeRuler — defect 3: a relative axis states the exact total", () => {
	it("terminates with the true window length, not the last nice step", () => {
		// 1.4s: the last 250ms major is 1250ms @ 89.3%. The axis must still say 1.40s.
		const html = render({ startMs: 0, endMs: 1400, mode: "relative" });
		expect(html).toContain("1.40s");
		expect(majorLefts(html)).toContain(100);
	});

	it("does NOT stamp an exact DURATION on an absolute axis", () => {
		// There the window end is normally 'now'; a duration total on it is noise. A
		// nice-step major MAY legitimately land on 100% (a round hour over an hour
		// window does), so the discriminator is the label's grammar, not its position:
		// every label on an absolute axis is a wall clock.
		const start = Date.UTC(2026, 7, 15, 10, 0, 0);
		const html = render({ startMs: start, endMs: start + 3_600_000 });
		const labels = [...html.matchAll(/font-mono[^>]*>([^<]+)</g)].map(
			([, t]) => t,
		);
		expect(labels.length).toBeGreaterThan(2);
		for (const l of labels) expect(l).toMatch(/^\d{2}:\d{2}(:\d{2})?$/);
		expect(html).toContain("Time axis, UTC");
	});
});

describe("TimeRuler — defect 4: sub-millisecond windows are the COMMON case", () => {
	// B-208: gateway-proxied traffic is single-span and gateway overhead is ~4.6ms, so
	// a waterfall over one gateway call is a sub-10ms window. Before the fix NICE_STEPS
	// began at 1ms and this rendered exactly one tick labelled "0ms".
	it("labels an 800µs window in microseconds, with more than one tick", () => {
		const html = render({ startMs: 0, endMs: 0.8, mode: "relative" });
		const labels = (html.match(/font-mono/g) ?? []).length;
		expect(labels).toBeGreaterThan(2);
		expect(html).toContain("µs");
		expect(html).toContain("800µs"); // the exact total
	});

	it("states the true total of a 4.6ms window, not the last whole millisecond", () => {
		// The nice-step majors here are 0/1/2/3/4ms — correct and readable. What was
		// missing is the endpoint: the axis used to stop at 4ms @ 87%, losing the one
		// number the reader came for. The terminal label must be fmtDur's exact string
		// so it matches the bar label rendered beside it, character for character.
		const html = render({ startMs: 0, endMs: 4.6, mode: "relative" });
		expect(html).toContain("4.6ms");
		expect((html.match(/font-mono/g) ?? []).length).toBeGreaterThan(2);
	});
});

describe("TimeRuler — relative mode ignores startMs for tick generation", () => {
	it("gives identical labels whether the caller passes 0 or a real epoch", () => {
		// The old build snapped `first` to absolute-epoch multiples and then subtracted
		// startMs, so passing a real epoch with mode="relative" produced labels like
		// 127ms / 377ms / 627ms. A caller should not have to know to pass 0.
		const fromZero = render({ startMs: 0, endMs: 1400, mode: "relative" });
		const epoch = Date.UTC(2026, 7, 15, 10, 0, 0) + 123;
		const fromEpoch = render({
			startMs: epoch,
			endMs: epoch + 1400,
			mode: "relative",
		});
		expect(fromEpoch).toBe(fromZero);
	});
});

describe("TimeRuler — the degenerate window still refuses to invent an axis", () => {
	it("renders an empty aria-hidden box for a zero span", () => {
		const html = render({ startMs: 5, endMs: 5, mode: "relative" });
		expect(html).not.toContain("font-mono");
		expect(html).toContain('aria-hidden="true"');
	});
});

describe("TimeRuler — label DENSITY (the overlapping-axis defect, 2026-08-17)", () => {
	const DAY = 86_400_000;
	const base = Date.UTC(2026, 6, 19);
	// Count the LABEL spans by their type size — the only 9.5px text the ruler emits.
	const labels = (html: string) => (html.match(/9\.5px/g) ?? []).length;

	it("a 30-day window renders a handful of labels, not one per day", () => {
		// THE BUG: NICE_STEPS stopped at one day and niceStep RETURNED that cap for any
		// larger span, so a 30d dashboard axis drew 30 `DD/MM` labels into ~500px and a
		// ~200px table column — an unreadable smear. Labels do not wrap or ellipsize.
		const html = render({
			startMs: base,
			endMs: base + 30 * DAY,
			mode: "absolute",
		});
		const n = labels(html);
		expect(n).toBeGreaterThan(1);
		expect(n).toBeLessThanOrEqual(7); // default ticks=6 -> cap 7
	});

	it("honours a narrow container's tick budget at 30 days", () => {
		// /traces passes ticks={4} because its Timeline column is ~200px. Before the fix
		// that hint was inert: the step it implied did not exist in the table.
		const html = render({
			startMs: base,
			endMs: base + 30 * DAY,
			mode: "absolute",
			ticks: 4,
		});
		expect(labels(html)).toBeLessThanOrEqual(5);
	});

	it("a ONE-YEAR window stays bounded — the fallback degrades resolution, not count", () => {
		// The old fallback clamped to the largest step, so the label count grew without
		// bound as the span grew. 365 daily labels was reachable.
		const html = render({
			startMs: base,
			endMs: base + 365 * DAY,
			mode: "absolute",
		});
		expect(labels(html)).toBeLessThanOrEqual(7);
	});
});

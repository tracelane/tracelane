import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { TraceList, type TraceSummary } from "./TraceList";

/**
 * TraceList TIMELINE COLUMN — rendered-shape tests (ADR-074 §7).
 *
 * Nothing rendered this component before today: grepping every `*.test.*` and `*.spec.*`
 * for `TraceList` returned zero hits. The only coverage was Playwright, which is
 * `skipIfNoAuth`-gated AND `continue-on-error` in CI, so it is not a gate.
 *
 * WHAT THESE LOCK, and why each one is here rather than being obvious:
 *  · the axis window comes from the ROWS, never from `?range=` — the page requests the
 *    newest 25 rows inside the URL window, so the two can differ by 30x
 *  · timestamps parse as UTC, not local — the gateway sends a zone-less string and
 *    `new Date()` on it shifts per viewer, a bug that already shipped once
 *  · the column disappears rather than drawing a zero-width axis
 *  · no `Date.now()` anywhere, so server and client render identically
 */

const h = createElement;

// `TraceList` calls useRouter for the row click. renderToStaticMarkup never fires it,
// but the hook must resolve — the app-router mock returns a no-op router.
vi.mock("next/navigation", () => ({
	useRouter: () => ({ push: () => {} }),
}));

function trace(
	over: Partial<TraceSummary> & { trace_id: string },
): TraceSummary {
	return {
		root_name: over.root_name ?? "gen_ai.chat",
		start_time: over.start_time ?? "2026-08-15 10:00:00.000000",
		duration_us: over.duration_us ?? 1_000_000,
		span_count: over.span_count ?? 1,
		error_count: over.error_count ?? 0,
		intervention: 0,
		model: over.model ?? "gpt-4o",
		cost_usd: over.cost_usd ?? 0,
		total_tokens: over.total_tokens ?? 0,
		...over,
	};
}

const render = (traces: TraceSummary[]) =>
	renderToStaticMarkup(h(TraceList, { traces }));

describe("TraceList — the timeline column gives the ruler something to align to", () => {
	// Four traces over a 40s window: 10:00:00, 10:00:10, 10:00:20, 10:00:30 (+10s each).
	const traces = [
		trace({ trace_id: "a", start_time: "2026-08-15 10:00:00.000000" }),
		trace({ trace_id: "b", start_time: "2026-08-15 10:00:10.000000" }),
		trace({ trace_id: "c", start_time: "2026-08-15 10:00:20.000000" }),
		trace({ trace_id: "d", start_time: "2026-08-15 10:00:30.000000" }),
	];
	const html = render(traces);

	it("renders the shared TimeRuler, not a bespoke axis", () => {
		expect(html).toContain("data-time-ruler");
	});

	it("positions each bar at its true fraction of the window the ROWS span", () => {
		// Window = first start (10:00:00) .. last end (10:00:31) = 31 000ms.
		// Bar starts: 0 / 10 000 / 20 000 / 30 000 ms -> 0% / 32.26% / 64.52% / 96.77%.
		expect(html).toContain("left:0%");
		expect(html).toMatch(/left:32\.2[0-9]*%/);
		expect(html).toMatch(/left:64\.5[0-9]*%/);
		expect(html).toMatch(/left:96\.7[0-9]*%/);
	});

	it("sizes each bar by its real duration, not by a fixed slot", () => {
		// 1 000 000µs = 1 000ms of a 31 000ms window = 3.23%.
		expect(html).toMatch(/width:3\.2[0-9]*%/);
	});

	it("puts the ruler INSIDE the timeline column, so both share one box", () => {
		// A <div> is invalid inside <thead>/<tr>; the only lawful in-table mount that
		// tracks the bars is the column's own <th>. Assert the ruler sits between the
		// <th> that opens the column and the </th> that closes it.
		const th = html.indexOf('<th class="w-[26%]');
		expect(th).toBeGreaterThan(-1);
		const ruler = html.indexOf("data-time-ruler");
		const close = html.indexOf("</th>", th);
		expect(ruler).toBeGreaterThan(th);
		expect(ruler).toBeLessThan(close);
	});

	it("marks an errored trace on the bar AND keeps the word in the status cell", () => {
		const withErr = render([
			trace({ trace_id: "a" }),
			trace({
				trace_id: "e",
				error_count: 2,
				start_time: "2026-08-15 10:00:05.000000",
			}),
		]);
		expect(withErr).toContain("bg-danger");
		expect(withErr).toContain("2 errors"); // never colour alone
	});
});

describe("TraceList — the window is the ROWS', never the URL range", () => {
	it("scales to the rendered rows even when they span seconds", () => {
		// The page's default `?range` is one hour. If the axis used that, four traces
		// two seconds apart would all pile into the first 0.06% of the column. The
		// rightmost bar must instead reach the far end.
		const html = render([
			trace({ trace_id: "a", start_time: "2026-08-15 10:00:00.000000" }),
			trace({ trace_id: "b", start_time: "2026-08-15 10:00:02.000000" }),
		]);
		const lefts = [...html.matchAll(/left:([0-9.]+)%/g)].map((m) =>
			Number(m[1]),
		);
		expect(Math.max(...lefts)).toBeGreaterThan(60);
	});
});

describe("TraceList — UTC parsing, not the viewer's zone", () => {
	/**
	 * HOW THIS TEST HAD TO CHANGE, because the first version was not a test.
	 *
	 * It originally re-rendered under `process.env.TZ = "Asia/Kolkata"` and asserted the
	 * markup was unchanged. It passed with `parseUtcMs` swapped for `new Date()` — for
	 * TWO independent reasons, and both are worth knowing:
	 *
	 *  1. V8 caches the zone at first use, so assigning `process.env.TZ` mid-process does
	 *     not change `Date`. The probe was not varying what it claimed to vary.
	 *  2. Even if it had, the BAR GEOMETRY is invariant to it. The window is derived from
	 *     the same rows, so a uniform parse shift cancels out of every percentage. Local
	 *     parsing does not move the bars at all.
	 *
	 * So the geometry cannot detect this class, and pretending otherwise is worse than
	 * not testing it. What CAN: the ruler's absolute labels are wall-clock, and a
	 * locally-parsed window puts them hours away from the truth. The suite is run under
	 * `TZ=Asia/Kolkata` in the falsification pass, where local parsing shifts these by
	 * 5h30m and the assertion fails.
	 */
	it("labels the axis with the true UTC wall clock, whatever zone the viewer is in", () => {
		// A 10-minute window, so the ruler is in ABSOLUTE mode and emits HH:MM labels.
		const traces = [
			trace({ trace_id: "a", start_time: "2026-08-15 10:00:00.000000" }),
			trace({ trace_id: "b", start_time: "2026-08-15 10:10:00.000000" }),
		];
		const html = render(traces);
		expect(html).toContain("Time axis, UTC");
		// 10:00 and 10:10 UTC are inside the window; under IST-local parsing the same
		// strings become 04:30/04:40 UTC and these labels disappear entirely.
		expect(html).toContain(">10:0");
		expect(html).toContain(">10:1");
	});
});

describe("TraceList — the column is omitted rather than drawn flat", () => {
	it("renders no ruler and no bars when the rows span no measurable time", () => {
		// One instantaneous trace: there is no window, so there is no axis. Drawing one
		// would assert a scale that does not exist.
		const html = render([trace({ trace_id: "a", duration_us: 0 })]);
		expect(html).not.toContain("data-time-ruler");
		expect(html).not.toContain('<th class="w-[26%]');
	});

	it("still renders every other column so the table is not degraded", () => {
		const html = render([trace({ trace_id: "a", duration_us: 0 })]);
		expect(html).toContain("Operation");
		expect(html).toContain("Duration");
		expect(html).toContain("Started (UTC)");
	});
});

import { cn } from "../lib/cn";
import { fmtDurMs } from "../lib/fmt-dur";

/**
 * TimeRuler — the product's signature: ONE precision time axis, used identically
 * everywhere (ADR-074 §7).
 *
 * WHY THIS IS THE SIGNATURE AND NOT DECORATION. Everything in this product is
 * time-indexed — traces, spans, sessions, every dashboard series — and today each
 * surface invents its own treatment: the waterfall has one tick style, the traces list
 * another, the charts a third. A reader crossing three screens re-learns the axis three
 * times. One ruler, drawn the same way at every scale, is what makes the app feel like
 * an instrument rather than a set of pages that happen to share a palette.
 *
 * THE FORM, and every part of it is load-bearing:
 *  · hairline ticks — 1px, non-scaling, so the axis stays crisp at any container width
 *  · MAJOR ticks are labelled; MINOR ticks are drawn and never labelled. Labelling every
 *    tick is what turns an axis into noise, and it is the most common way a precise
 *    instrument is made to look cheap.
 *  · monospace, tabular timestamps — so digits sit in the same column as the eye tracks
 *    across, and a label never jitters as the value changes
 *  · `ink-3` for the rule, `ink-2` for labels — the axis must recede behind the data.
 *    An axis that competes with its own series is the tell of a chart nobody had to read.
 *
 * Colour: none. The ruler is chrome (§1) — a coloured axis would spend the one signal
 * this design system reserves for meaning.
 *
 * ── FOUR DEFECTS FIXED 2026-08-16, BEFORE THIS WAS PLACED ON ANY SCREEN ───────────
 * This component shipped built, unit-tested and exported, and did not work. It reached
 * that state because its test counts SUBSTRINGS and never checks a POSITION — the exact
 * shape of probe that cannot tell a working ruler from a broken one. Recorded here
 * rather than in a commit message, because the next person to add a tick will otherwise
 * reintroduce them:
 *
 *  1. MINORS RENDERED AT 1/600th OF THEIR POSITION. Minors were children of the
 *     per-major wrapper and positioned in `%`. That wrapper's only in-flow child is a
 *     1px tick div, and absolutely-positioned children do not contribute to shrink-to-fit
 *     width — so the wrapper was 1px wide and every minor percentage resolved against
 *     1px. Measured in headless Chromium at a 600px container: minors landed at
 *     0.031 / 0.078 / 0.125px instead of 26.8 / 53.6 / 80.3px. They were stacked
 *     invisibly on their own major. The percentages were doubly wrong — computed as a
 *     fraction of the whole span but applied inside a box already offset to the major.
 *     FIX: minors are siblings of majors, positioned against the ruler root by the same
 *     `pct()` every other mark uses. ONE coordinate system, which is the invariant.
 *
 *  2. EDGE ANCHORING MOVED THE TICK, NOT THE LABEL. The `left < 4 / left > 96` ternary
 *     sat on the wrapper containing the tick mark, so a major at 98.4% was redrawn at
 *     100% — ~10px of misalignment at a 600px column, against bars whose positions are
 *     exact. An axis that lies about position is worse than no axis.
 *     FIX: the tick keeps its true `left`; only the LABEL is translated inward.
 *
 *  3. THE WINDOW TOTAL WAS NEVER LABELLED. Majors stopped at the last nice-step below
 *     `endMs`, so a 1.4s window ended at `1250ms @ 89.3%` and the final 11% of the axis
 *     carried nothing. On a waterfall, "how long did this take" is the whole question.
 *     FIX: a relative axis always terminates with a labelled tick carrying the EXACT
 *     total. An absolute axis does not — there the end is usually "now", and stamping a
 *     wall clock on it is noise, not information.
 *
 *  4. NO SUB-MILLISECOND RESOLUTION, WHICH COLLIDED WITH THE COMMONEST REAL TRACE.
 *     `NICE_STEPS` began at 1ms and the finest label was `${Math.round(ms)}ms`, so an
 *     800µs window rendered exactly ONE tick labelled `0ms`. Gateway-proxied traffic is
 *     single-span (B-208) and the gateway's own overhead is ~4.6ms, so windows in this
 *     band are the normal case, not an edge case.
 *     FIX: steps continue down to 1µs and labels render µs below a 1ms step.
 */

export interface TimeRulerProps {
	/** Window start (ms epoch) in `absolute` mode; ignored for tick generation in
	 *  `relative` mode, where the axis is elapsed time from the window start. */
	startMs: number;
	/** Window end (ms epoch). Must be > startMs. */
	endMs: number;
	/** Target number of MAJOR (labelled) ticks. Actual count snaps to a nice interval. */
	ticks?: number;
	/** Minor ticks drawn between each pair of majors. Default 3 (quarter divisions). */
	minorPerMajor?: number;
	/**
	 * `absolute` renders wall-clock (UTC, always labelled as such — the repo standard);
	 * `relative` renders elapsed time from the window start, which is what a waterfall
	 * needs. `auto` (the default) picks relative under a minute, where wall-clock
	 * seconds are unreadable.
	 *
	 * AN EXPLICIT MODE WINS. `auto` used to be the only behaviour and it was welded on:
	 * `relative = mode === "relative" || span < 60_000` silently overrode a caller that
	 * asked for `absolute`. That matters on a LIST, where the frame must not change with
	 * the data — a traces list whose axis reads wall-clock at five minutes and elapsed
	 * at fifty seconds is two different instruments wearing one design.
	 *
	 * In `relative` mode `startMs` does NOT shift the labels: ticks are generated in
	 * elapsed space from 0. That is deliberate — the previous build snapped `first` to
	 * absolute-epoch multiples and then subtracted `startMs`, so passing a real epoch
	 * with `mode="relative"` produced labels like `127ms · 377ms · 627ms`. A caller
	 * should not have to know to pass `startMs={0}` to get elapsed time.
	 */
	mode?: "absolute" | "relative" | "auto";
	className?: string;
}

/** Human-readable step sizes, in ms. The axis snaps to one of these — never to a raw
 *  `span / n`, which produces labels like `1.37s` and reads as a machine's arithmetic.
 *  Sub-millisecond entries are NOT decoration: see defect 4 above. */
const DAY = 86_400_000;
const NICE_STEPS = [
	0.001,
	0.002,
	0.005,
	0.01,
	0.025,
	0.05,
	0.1,
	0.25,
	0.5,
	1,
	2,
	5,
	10,
	25,
	50,
	100,
	250,
	500,
	1_000,
	2_000,
	5_000,
	10_000,
	15_000,
	30_000,
	60_000,
	120_000,
	300_000,
	600_000,
	900_000,
	1_800_000,
	3_600_000,
	7_200_000,
	21_600_000,
	43_200_000,
	DAY,
	// MULTI-DAY STEPS. Their absence is what produced the overlapping axis: the table
	// stopped at one day, and the fallback below RETURNED that cap, so a 30-day span
	// asked for 6 ticks and got a 1-day step — THIRTY `DD/MM` labels crammed into a
	// ~500px chart and a ~200px table column. The `ticks` prop could not help, because
	// the step it requested did not exist. 2d/5d/7d/14d/30d keep a month at 4-6 labels.
	2 * DAY,
	5 * DAY,
	7 * DAY,
	14 * DAY,
	30 * DAY,
	60 * DAY,
	90 * DAY,
	180 * DAY,
	365 * DAY,
];

function niceStep(span: number, target: number): number {
	const raw = span / Math.max(target, 1);
	for (const s of NICE_STEPS) if (s >= raw) return s;
	// Past the table (multi-year), round UP to a whole number of years rather than
	// clamping. Clamping to the largest step is what silently produced hundreds of
	// labels — a fallback must degrade the RESOLUTION, never the label count.
	return Math.ceil(raw / (365 * DAY)) * 365 * DAY;
}

/** Elapsed formatting. Unit-consistent within a ruler so labels stay comparable —
 *  the STEP chooses the unit, not the value, or a single axis mixes three units the
 *  way the hand-rolled waterfall axis did (`0µs · 350.0ms · 700.0ms · 1.05s`). */
function fmtRelative(ms: number, step: number): string {
	if (step < 1) return `${Math.round(ms * 1_000)}µs`;
	if (step < 1_000) return `${Math.round(ms)}ms`;
	if (step < 60_000) {
		const s = ms / 1_000;
		return `${step < 10_000 ? s.toFixed(1) : Math.round(s)}s`;
	}
	const m = Math.floor(ms / 60_000);
	const s = Math.round((ms % 60_000) / 1_000);
	return s === 0 ? `${m}m` : `${m}m${String(s).padStart(2, "0")}`;
}

/** UTC wall clock. The repo standard is UTC everywhere, always labelled (never local). */
function fmtAbsolute(ms: number, step: number): string {
	const d = new Date(ms);
	const hh = String(d.getUTCHours()).padStart(2, "0");
	const mm = String(d.getUTCMinutes()).padStart(2, "0");
	if (step >= 86_400_000) {
		return `${String(d.getUTCDate()).padStart(2, "0")}/${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
	}
	if (step >= 60_000) return `${hh}:${mm}`;
	return `${hh}:${mm}:${String(d.getUTCSeconds()).padStart(2, "0")}`;
}

/** One labelled tick. `pos` is a percentage of the ruler's own width, 0..100. */
interface Major {
	pos: number;
	label: string;
}

export function TimeRuler({
	startMs,
	endMs,
	ticks = 6,
	minorPerMajor = 3,
	mode = "auto",
	className,
}: TimeRulerProps) {
	const span = endMs - startMs;
	if (!(span > 0)) {
		// A zero or inverted window is a caller bug, not something to render creatively.
		return <div className={cn("h-6", className)} aria-hidden="true" />;
	}

	const relative = mode === "relative" || (mode === "auto" && span < 60_000);
	const step = niceStep(span, ticks);
	const pct = (elapsed: number) => (elapsed / span) * 100;

	// Majors and minors are generated in ELAPSED space and positioned against the ruler
	// root — one coordinate system for every mark on the axis (defect 1).
	const majors: Major[] = [];
	const minorPos: number[] = [];

	// Where the first nice-step tick falls, as elapsed ms from the window start.
	// Relative: always 0. Absolute: the first step-multiple of wall-clock inside
	// the window, so labels land on round times rather than on the window edge.
	const firstElapsed = relative
		? 0
		: Math.ceil(startMs / step) * step - startMs;

	for (let e = firstElapsed; e <= span; e += step) {
		majors.push({
			pos: pct(e),
			label: relative ? fmtRelative(e, step) : fmtAbsolute(startMs + e, step),
		});
		for (let k = 1; k <= minorPerMajor; k += 1) {
			const me = e + (step * k) / (minorPerMajor + 1);
			if (me < span) minorPos.push(pct(me));
		}
	}

	// HARD CAP — the belt to niceStep's braces. niceStep now returns a step that WILL
	// land near `ticks` majors, but it is arithmetic over a step table: an awkward span
	// can still overshoot (a 29-day window against a 7-day step yields 5, a 31-day one
	// yields 6). This guarantees the label count regardless of what the table returns,
	// because the failure mode is not cosmetic — labels do not wrap or ellipsize, they
	// overprint into an unreadable smear, and the axis is worse than no axis at all.
	// Keeps first and last, thins evenly between. Minors are left alone: they carry no
	// text, so they cannot collide.
	const maxMajors = Math.max(2, ticks + 1);
	if (majors.length > maxMajors) {
		const keepEvery = Math.ceil(majors.length / maxMajors);
		const thinned = majors.filter(
			(_, i) => i % keepEvery === 0 || i === majors.length - 1,
		);
		majors.length = 0;
		majors.push(...thinned);
	}

	// A relative axis always terminates with the EXACT total (defect 3). A nice-step
	// major sitting within 5% of the end is dropped so the two do not collide — the
	// exact value is the more useful of the pair, so it is the one that survives.
	if (relative) {
		while (majors.length > 0 && (majors.at(-1)?.pos ?? 0) > 95) majors.pop();
		majors.push({ pos: 100, label: fmtDurMs(span) });
	}

	return (
		<div
			className={cn("relative h-6 select-none", className)}
			role="presentation"
			data-time-ruler
		>
			{/* The rule itself — one hairline, full width. */}
			<div className="absolute inset-x-0 top-0 h-px bg-line-2" />

			{/* MINOR ticks — drawn, never labelled (§7). Siblings of the majors, so they
			    share the ruler's coordinate system rather than a 1px wrapper's. */}
			{minorPos.map((p) => (
				<div
					key={`m${p}`}
					className="absolute top-0 h-1 w-px bg-line-2"
					style={{ left: `${p}%` }}
					aria-hidden="true"
				/>
			))}

			{majors.map((m) => {
				// The TICK always sits at its true position. Only the LABEL is pulled
				// inward at the edges, so it cannot clip the container (defect 2).
				const anchor =
					m.pos < 4
						? "left-0"
						: m.pos > 96
							? "right-0"
							: "-translate-x-1/2 left-0";
				return (
					<div
						key={`M${m.pos}-${m.label}`}
						className="absolute top-0"
						style={{ left: `${m.pos}%` }}
					>
						<div className="h-1.5 w-px bg-ink-3" />
						<span
							className={cn(
								"absolute top-2 whitespace-nowrap font-mono text-[9.5px] text-ink-2",
								anchor,
							)}
							style={{ fontVariantNumeric: "tabular-nums" }}
						>
							{m.label}
						</span>
					</div>
				);
			})}

			{relative && (
				<span className="sr-only">
					Elapsed time axis, {fmtDurMs(span)} total
				</span>
			)}
			{!relative && <span className="sr-only">Time axis, UTC</span>}
		</div>
	);
}

/**
 * LedgerSeqChip — the moat, made visible at the CORRECT SCOPE (ADR-074 §7).
 *
 * Renders the tenant's audit-ledger sequence range wherever a trace appears:
 * `▸ 15700–15799`, mono, `ink-faint`, no colour.
 *
 * THE SCOPE IS THE WHOLE POINT, and it is a correctness constraint rather than a design
 * one. The audit chain is PER-TENANT, so a per-TRACE "verified ✓" chip would be a claim
 * the data does not support — ADR-074 §9 and the honesty locks forbid it, and it is
 * exactly the collapsed-state defect that produced B-241/B-249. A range says "this trace
 * sits inside a signed span of the ledger", which is true, useful, and checkable.
 *
 * Deliberately quiet: `ink-faint`, no fill, no verify-green. Verify-green stays reserved
 * for a verification that actually ran.
 *
 * NOT PLACED ANYWHERE YET, AND THAT IS DELIBERATE — 2026-08-16. No gateway endpoint
 * returns a tenant-scope seq range: `/v1/traces/{id}/chain` gives ONE per-trace seq,
 * `/v1/audit/summary` aggregates min/max on `event_time` not `seq` and is gated on the
 * PAID Audit add-on (2 entitlement rows fleet-wide, B-249), and `/v1/audit/self-verify`
 * loads the OLDEST rows (`ORDER BY seq ASC LIMIT ?`) so a range derived from it
 * understates and freezes as the ledger grows. Rendering this chip from any of those
 * would put a confident number on screen that the data does not support — the shape
 * B-249 already cost us once. It stays unplaced until the range is a real field.
 */
export function LedgerSeqChip({
	from,
	to,
	className,
}: { from: number | string; to: number | string; className?: string }) {
	return (
		<span
			className={cn(
				"inline-flex items-center gap-1 font-mono text-[10px] text-ink-3 leading-none",
				className,
			)}
			style={{ fontVariantNumeric: "tabular-nums" }}
			title={`Audit ledger sequence ${from}–${to} for this workspace`}
		>
			<span aria-hidden="true">▸</span>
			{from}–{to}
		</span>
	);
}

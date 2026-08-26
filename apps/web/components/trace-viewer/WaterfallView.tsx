"use client";

/**
 * WaterfallView — the span timeline (Gantt/waterfall), the observability-standard
 * "at a glance" view: each span is a horizontal bar positioned by its real start
 * offset and sized by its real duration, indented by tree depth, colored by span
 * kind, red on error. This is the default trace view — instantly readable where
 * the transcript-spine (kept behind the toggle) is a narrative.
 *
 * Geometry is 100% real: offset = spanStart − traceStart, width = duration_us,
 * both in microseconds from the gateway. No timing is inferred or padded (a min
 * bar width only guarantees sub-pixel spans stay visible; the number beside the
 * bar is always the true duration).
 */

import { inferSpanKind } from "@/lib/span-kind";
import { spanStartUs } from "@/lib/trace-summary";
import type { VisibleRow } from "@/lib/trace-tree";
import {
	SPAN_KIND_MARK,
	type SpanKind,
	TimeRuler,
	cn,
	fmtDur,
} from "@tracelanedev/ui";

/**
 * The span-kind mark, re-exported from the design system.
 *
 * IT USED TO BE A SECOND COPY OF THE RAMP, DECLARED HERE, and that duplication is
 * what this change removes. `packages/ui`'s transcript spine marks the same six kinds
 * for the same reason; two maps encoding one idea drifted the moment the palette moved
 * (the spine's `llm` step was still an alpha of the retired violet, which composited
 * to within a few points of its own `unknown` step). The map, and the reasoning for
 * every step in it, now live at `SPAN_KIND_MARK` in
 * `packages/ui/src/signature/TranscriptSpine.tsx`.
 *
 * The name is kept as an alias because `TraceDetailView`'s legend imports `KIND_BAR`
 * from this module, and renaming a working import is churn this pass does not need.
 */
export const KIND_BAR = SPAN_KIND_MARK;

export function WaterfallView({
	rows,
	startUs,
	totalUs,
	selectedId,
	onSelectSpan,
	onToggleCollapse,
}: {
	rows: VisibleRow[];
	startUs: number;
	totalUs: number;
	selectedId?: string;
	onSelectSpan: (id: string) => void;
	onToggleCollapse: (id: string) => void;
}) {
	return (
		<div className="text-sm">
			{/*
			 * Time axis header — ADR-074 §7's ONE ruler, in the same 2fr/3fr grid as the
			 * rows so the ticks and the bars share a coordinate system.
			 *
			 * TimeRuler must be the DIRECT second grid child, with no wrapper carrying
			 * padding: the bars below resolve their `left`/`width` percentages against
			 * their own second-cell box, and any padding here would shift every tick
			 * relative to the bar it describes.
			 *
			 * `startMs={0}` + `mode="relative"` is the only correct call for a waterfall.
			 * The axis is ELAPSED time from the trace start — `totalUs` is already an
			 * elapsed span, not an epoch — and `mode` is required rather than left to the
			 * under-60s auto-switch, because a trace of a minute or more would otherwise
			 * fall through to wall-clock formatting and render the UTC epoch.
			 *
			 * The header's own `border-b` is gone: the ruler draws the rule now, and
			 * carrying both put two horizontal lines under the same axis.
			 */}
			<div className="sticky top-0 z-10 grid grid-cols-[minmax(0,2fr)_3fr] items-start gap-2 bg-bg pb-1.5 pr-2">
				{/*
				 * `h-6 border-t` mirrors the ruler's own box and its hairline, so the rule
				 * reads as ONE line across the whole header instead of stopping where the
				 * timeline column starts. The header's old full-width `border-b` is gone —
				 * the ruler already draws a rule, and carrying both put two horizontal
				 * lines under the same axis.
				 */}
				<span className="block h-6 border-line border-t pt-1.5 pl-1 t-metric-label">
					Span
				</span>
				<TimeRuler startMs={0} endMs={totalUs / 1000} mode="relative" />
			</div>

			<div className="mt-1 space-y-px">
				{rows.map((row) => {
					const s = row.span;
					const kind = inferSpanKind(s.attributes);
					const isError = s.status_code === 2;
					const offsetUs = Math.max(0, spanStartUs(s) - startUs);
					const leftPct = totalUs > 0 ? (offsetUs / totalUs) * 100 : 0;
					const rawWidth = totalUs > 0 ? (s.duration_us / totalUs) * 100 : 100;
					// Clamp so a near-zero span is still visible and a bar never overruns.
					const widthPct = Math.min(Math.max(rawWidth, 0.5), 100 - leftPct);
					const selected = s.span_id === selectedId;
					// Guide rail count capped at 8 (same cap as indent).
					const guideCount = Math.min(row.depth, 8);

					return (
						<div
							key={s.span_id}
							// The ONLY stable hook on a waterfall span row. This view is the
							// DEFAULT (TraceDetailView: useState<ViewMode>("waterfall")), but the
							// e2e span locator was built from TranscriptSpine — `[role="treeitem"],
							// ol li` — and the waterfall emits none of those. So every e2e
							// assertion "about the spans" was querying the view the user is NOT
							// looking at, and Playwright is continue-on-error, so it stayed
							// invisible. Selected by `traceDetail().spanNodes` in
							// e2e/fixtures/selectors.ts; a rendered-shape test pins it so the
							// attribute cannot be dropped silently.
							data-span-row={s.span_id}
							// Row states, and the ordering is the point: HOVER is
							// `--surface-hover` (the role that exists for a row on a card) and
							// SELECTED is `--surface-3` (the declared press/active step, one
							// louder than hover). Selected used to be `--surface-2`; in DARK
							// that token (#1c1d20) is QUIETER than `--surface-hover` (#202125),
							// so hovering any other row out-shouted the row you had selected.
							className={cn(
								"group grid grid-cols-[minmax(0,2fr)_3fr] items-center gap-2 rounded-md pr-2 transition-colors",
								selected ? "bg-surface-3" : "hover:bg-surface-hover",
							)}
						>
							{/* Tree cell: depth guide rails · indent · disclosure · kind dot · name. */}
							<div
								className="relative flex min-w-0 items-center gap-1.5 py-1"
								// Cap indent so a very deep tree keeps the name readable
								// (the title tooltip still carries the full name).
								style={{ paddingLeft: `${guideCount * 14 + 4}px` }}
							>
								{/* Faint vertical guide rails — one per ancestor level, so deeply
								    nested spans stay traceable even when the parent row is off-screen.
								    Positioned at the center of each 14px indent step. */}
								{guideCount > 0 &&
									Array.from({ length: guideCount }, (_, i) => {
										// Use the CSS left-offset as the key — stable, unique per rail.
										const leftPx = i * 14 + 11;
										return (
											<span
												key={`guide-${leftPx}`}
												className="pointer-events-none absolute inset-y-0 w-px bg-line"
												style={{ left: `${leftPx}px` }}
												aria-hidden
											/>
										);
									})}

								{row.hasChildren ? (
									<button
										type="button"
										onClick={() => onToggleCollapse(s.span_id)}
										aria-label={row.collapsed ? "Expand" : "Collapse"}
										aria-expanded={!row.collapsed}
										className="grid h-4 w-4 shrink-0 place-items-center rounded text-2xs leading-none text-ink-3 hover:bg-surface-2 hover:text-ink focus-visible:outline-2 focus-visible:outline-focus-ring focus-visible:outline-offset-2"
									>
										{row.collapsed ? "▶" : "▼"}
									</button>
								) : (
									<span className="h-4 w-4 shrink-0" aria-hidden />
								)}
								<span
									className={cn(
										"h-2 w-2 shrink-0 rounded-full",
										KIND_BAR[kind],
										isError && "ring-2 ring-danger",
									)}
									aria-hidden
								/>
								<button
									type="button"
									onClick={() => onSelectSpan(s.span_id)}
									className="truncate text-left text-sm text-ink hover:text-ink-2 focus-visible:outline-2 focus-visible:outline-focus-ring focus-visible:outline-offset-2"
									title={s.name}
								>
									{s.name}
								</button>
							</div>

							{/* Timeline cell: the bar, positioned by real offset/width. */}
							<button
								type="button"
								onClick={() => onSelectSpan(s.span_id)}
								className="relative flex h-6 items-center focus-visible:outline-2 focus-visible:outline-focus-ring focus-visible:outline-offset-2 rounded-sm"
								title={`start +${fmtDur(offsetUs)} · ${fmtDur(s.duration_us)}${isError ? " · error" : ""}`}
							>
								{/* faint baseline so empty rows still read as a track */}
								<span className="absolute inset-x-0 top-1/2 h-px -translate-y-1/2 bg-line/60" />
								<span
									className={cn(
										"absolute top-1/2 h-2.5 -translate-y-1/2 rounded-sm",
										isError ? "bg-danger" : KIND_BAR[kind],
										!isError && "opacity-85",
									)}
									style={{ left: `${leftPct}%`, width: `${widthPct}%` }}
								/>
								<span
									// Opaque chip so the exact duration stays legible even when a
									// long bar reaches the right edge underneath it.
									className="absolute right-1 rounded bg-bg px-1 text-2xs tabular-nums text-ink-2"
								>
									{fmtDur(s.duration_us)}
								</span>
							</button>
						</div>
					);
				})}
			</div>
		</div>
	);
}

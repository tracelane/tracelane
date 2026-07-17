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

import { fmtDur } from "@/lib/fmt-dur";
import { inferSpanKind } from "@/lib/span-kind";
import { spanStartUs } from "@/lib/trace-summary";
import type { VisibleRow } from "@/lib/trace-tree";
import { type SpanKind, cn } from "@tracelanedev/ui";

/** Bar fill by kind — matches the transcript-spine node pins (one palette).
 * ADR-053 discipline: Lava (--accent) is CTA-only and Verify-green (--ok/--seal)
 * is provenance-only, so span kinds use the one free data hue (violet --info, the
 * AI-call family: tool bold, llm faint) + neutral ink for structure. The kind text
 * label always accompanies the color — never colour alone. Errors override to red. */
export const KIND_BAR: Record<SpanKind, string> = {
	agent: "bg-ink-2",
	tool: "bg-info",
	llm: "bg-info/50",
	retrieval: "bg-ink-3",
	chain: "bg-ink-3",
	unknown: "bg-ink-3",
};

/** Axis tick positions (fraction 0..1). Four segments reads clean at any width. */
const TICKS = [0, 0.25, 0.5, 0.75, 1] as const;

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
	const span = (t: number) => (totalUs > 0 ? totalUs * t : 0);

	return (
		<div className="text-sm">
			{/* Time axis header — aligned to the same 2fr/3fr grid as the rows. */}
			<div className="sticky top-0 z-10 grid grid-cols-[minmax(0,2fr)_3fr] items-center gap-2 border-b border-line bg-bg pb-1.5 pr-2">
				<span className="pl-1 text-[10px] font-semibold uppercase tracking-wide text-ink-3">
					Span
				</span>
				<div className="relative h-4">
					{TICKS.map((t) => (
						<span
							key={t}
							className="absolute top-0 -translate-x-1/2 whitespace-nowrap text-[10px] tabular-nums text-ink-3 first:translate-x-0 last:-translate-x-full"
							style={{ left: `${t * 100}%` }}
						>
							{fmtDur(span(t))}
						</span>
					))}
				</div>
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
							className={cn(
								"group grid grid-cols-[minmax(0,2fr)_3fr] items-center gap-2 rounded-md pr-2 transition-colors",
								selected ? "bg-surface-2" : "hover:bg-surface-2/40",
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
										className="grid h-4 w-4 shrink-0 place-items-center rounded text-[9px] text-ink-3 hover:bg-surface-2 hover:text-ink focus-visible:outline-2 focus-visible:outline-seal focus-visible:outline-offset-1"
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
									className="truncate text-left text-[13px] text-ink hover:text-ink-2 focus-visible:outline-2 focus-visible:outline-seal focus-visible:outline-offset-1"
									title={s.name}
								>
									{s.name}
								</button>
							</div>

							{/* Timeline cell: the bar, positioned by real offset/width. */}
							<button
								type="button"
								onClick={() => onSelectSpan(s.span_id)}
								className="relative flex h-6 items-center focus-visible:outline-2 focus-visible:outline-seal focus-visible:outline-offset-1 rounded-sm"
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
									className="absolute right-1 rounded bg-bg px-1 text-[11px] tabular-nums text-ink-2"
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

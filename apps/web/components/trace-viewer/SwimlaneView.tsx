"use client";

/**
 * SwimlaneView — the multi-agent projection of a trace (OBS-49): one row group
 * per agent lane instead of one row per span-tree position. Same 2fr/3fr grid
 * and the ONE shared `TimeRuler` as {@link WaterfallView} (ADR-074 §7), and
 * bars positioned by the SAME `barGeometry` helper — the property that makes
 * "render parity" between the two views true by construction rather than by a
 * second copy of the formula that could drift.
 *
 * Lanes are computed by `lib/trace/lanes.ts`, entirely client-side from span
 * attributes — no ClickHouse column, no schema change (spec §6).
 *
 * On today's single-span/single-agent prod traffic this degenerates to one
 * lane with one bar. That is correct, not a bug: the caller passes a tooltip
 * onto the view-mode control saying so ("one agent in this trace") rather
 * than this component inventing extra agents that were never observed.
 */

import { inferSpanKind } from "@/lib/span-kind";
import { barGeometry } from "@/lib/trace-summary";
import type { Lane } from "@/lib/trace/lanes";
import { laneStats } from "@/lib/trace/lanes";
import { SPAN_KIND_MARK, TimeRuler, cn, fmtDur } from "@tracelanedev/ui";
import { useState } from "react";

/** Lanes beyond this many collapse into an expandable "+N more agents" row
 * (spec §5). */
const LANE_CAP = 12;

function LaneRow({
	lane,
	startUs,
	totalUs,
	selectedId,
	onSelectSpan,
	handoffFromLabel,
}: {
	lane: Lane;
	startUs: number;
	totalUs: number;
	selectedId?: string;
	onSelectSpan: (id: string) => void;
	handoffFromLabel?: string;
}) {
	const stats = laneStats(lane);
	// Chronological within the lane — the bars read left-to-right in the order
	// the agent actually did the work, independent of tree-traversal order.
	const spans = [...lane.spans].sort((a, b) => {
		const sa = a.start_time_us ?? Date.parse(a.start_time) * 1000;
		const sb = b.start_time_us ?? Date.parse(b.start_time) * 1000;
		return sa - sb;
	});

	return (
		// NOTE: no `overflow-hidden` here (there used to be one). Per the CSS
		// Overflow spec `overflow: hidden` makes an element its OWN nearest
		// scrolling ancestor — a scrollport, even one that never gets a
		// scrollbar — and that is what `position: sticky` below resolves its
		// `top` offset against. This card's scrollport can never actually
		// scroll (its scrollTop is pinned at 0; its height is DEFINED by its
		// own content), so the header was permanently evaluated as "stuck" and
		// painted shifted down by its `top-6` offset from the CARD's own top —
		// while the row list below stayed at the ordinary document-flow position
		// already reserved for it, so the header visually overlapped the first one
		// or two rows of every lane short enough for that shift to reach them.
		// Removing `overflow-hidden` restores the real scrolling ancestor — the
		// page's `overflow-auto` region in TraceDetailView — so the header only
		// sticks once THAT actually scrolls, which was always the intent.
		<div className="surface-card rounded-md border border-line">
			{/* Sticky lane header: agent label · span count · error count ·
			    active window. `rounded-t-md` replaces the corner-clipping the
			    removed `overflow-hidden` used to do for free — this is the
			    only child that paints flush to the card's top edge. */}
			<div className="sticky top-6 z-[5] flex items-center gap-1.5 rounded-t-md border-line border-b bg-canvas-sunken px-3 py-1.5 text-xs">
				<span className="truncate font-medium text-ink">{lane.label}</span>
				<span className="text-ink-3" aria-hidden>
					·
				</span>
				<span className="tabular-nums text-ink-2">
					{stats.spanCount} {stats.spanCount === 1 ? "span" : "spans"}
				</span>
				<span className="text-ink-3" aria-hidden>
					·
				</span>
				<span
					className={cn(
						"tabular-nums",
						stats.errorCount > 0 ? "text-danger-ink" : "text-ink-2",
					)}
				>
					{stats.errorCount} {stats.errorCount === 1 ? "error" : "errors"}
				</span>
				<span className="text-ink-3" aria-hidden>
					·
				</span>
				<span className="tabular-nums text-ink-2">
					{fmtDur(stats.durationUs)}
				</span>
			</div>

			{/* Hand-off connector: a `parent_agent_id` on some span in this lane named
			    another lane that exists in this trace (spec §2). Rendered as a plain
			    text marker rather than a drawn line between blocks — it says the same
			    thing ("this agent was handed the work by that one") without inventing
			    layout geometry the spec never asked for. */}
			{handoffFromLabel && (
				<div className="border-line border-b bg-canvas-sunken/50 px-3 py-1 text-2xs text-ink-3">
					<span aria-hidden>⤷</span> hand-off from {handoffFromLabel}
				</div>
			)}

			<div className="space-y-px p-2">
				{spans.map((s) => {
					const kind = inferSpanKind(s.attributes);
					const isError = s.status_code === 2;
					const { leftPct, widthPct } = barGeometry(s, startUs, totalUs);
					const selected = s.span_id === selectedId;
					return (
						<div
							key={s.span_id}
							data-span-row={s.span_id}
							data-lane-key={lane.key}
							className={cn(
								"grid grid-cols-[minmax(0,2fr)_3fr] items-center gap-2 rounded-md pr-2 transition-colors",
								selected ? "bg-surface-3" : "hover:bg-surface-hover",
							)}
						>
							<div className="flex min-w-0 items-center gap-1.5 py-1 pl-2">
								<span
									className={cn(
										"h-2 w-2 shrink-0 rounded-full",
										SPAN_KIND_MARK[kind],
										isError && "ring-2 ring-danger",
									)}
									aria-hidden
								/>
								<button
									type="button"
									onClick={() => onSelectSpan(s.span_id)}
									className="truncate text-left text-ink text-sm hover:text-ink-2 focus-visible:outline-2 focus-visible:outline-focus-ring focus-visible:outline-offset-2"
									title={s.name}
								>
									{s.name}
								</button>
							</div>
							<button
								type="button"
								onClick={() => onSelectSpan(s.span_id)}
								className="relative flex h-6 items-center rounded-sm focus-visible:outline-2 focus-visible:outline-focus-ring focus-visible:outline-offset-2"
								title={`${fmtDur(s.duration_us)}${isError ? " · error" : ""}`}
							>
								<span className="-translate-y-1/2 absolute inset-x-0 top-1/2 h-px bg-line/60" />
								<span
									className={cn(
										"-translate-y-1/2 absolute top-1/2 h-2.5 rounded-sm",
										isError ? "bg-danger" : SPAN_KIND_MARK[kind],
										!isError && "opacity-85",
									)}
									style={{ left: `${leftPct}%`, width: `${widthPct}%` }}
								/>
								<span className="absolute right-1 rounded bg-bg px-1 text-2xs text-ink-2 tabular-nums">
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

export function SwimlaneView({
	lanes,
	startUs,
	totalUs,
	selectedId,
	onSelectSpan,
}: {
	lanes: Lane[];
	startUs: number;
	totalUs: number;
	selectedId?: string;
	onSelectSpan: (id: string) => void;
}) {
	const [expanded, setExpanded] = useState(false);
	const visible = expanded ? lanes : lanes.slice(0, LANE_CAP);
	const overflow = lanes.length - visible.length;
	const byKey = new Map(lanes.map((l) => [l.key, l]));

	return (
		<div className="text-sm">
			{/* Same ADR-074 §7 ruler, same 2fr/3fr grid track as WaterfallView, so the
			    ticks line up with the bars below regardless of which view is showing. */}
			<div className="sticky top-0 z-10 grid grid-cols-[minmax(0,2fr)_3fr] items-start gap-2 bg-bg pb-1.5 pr-2">
				<span className="block h-6 border-line border-t pt-1.5 pl-1 t-metric-label">
					Agent
				</span>
				<TimeRuler startMs={0} endMs={totalUs / 1000} mode="relative" />
			</div>

			<div className="mt-1 space-y-2">
				{visible.map((lane) => (
					<LaneRow
						key={lane.key}
						lane={lane}
						startUs={startUs}
						totalUs={totalUs}
						selectedId={selectedId}
						onSelectSpan={onSelectSpan}
						handoffFromLabel={
							lane.handoffFromKey
								? byKey.get(lane.handoffFromKey)?.label
								: undefined
						}
					/>
				))}
				{overflow > 0 && (
					<button
						type="button"
						onClick={() => setExpanded(true)}
						className="w-full rounded-md border border-line border-dashed px-3 py-2 text-center text-ink-2 text-xs hover:bg-surface-hover"
					>
						+{overflow} more {overflow === 1 ? "agent" : "agents"}
					</button>
				)}
			</div>
		</div>
	);
}

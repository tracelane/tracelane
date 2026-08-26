"use client";

/**
 * TraceDetailView — the trace summary header + span view + inspector.
 *
 * Top: `TraceSummaryHeader` (real rollups — duration, spans, errors, tokens,
 * cost, models). Left: the span view in one of two modes —
 *   • Waterfall (default): the timeline/Gantt — instantly readable, standard
 *     observability view; bars positioned by real start offset + duration.
 *   • Transcript: the transcript-with-a-spine (design-system §3.1, the
 *     differentiator) — hash-chain thread, color-coded kind pins, seen-before glow.
 * Both share the same collapse/search/selection state. Right: SpanInspector for
 * the selected span. Client component (view mode + selection + collapse + search).
 */

import { aftLabel } from "@/lib/aft-labels";
import { inferSpanKind } from "@/lib/span-kind";
import { traceTimeBounds } from "@/lib/trace-summary";
import {
	type VisibleRow,
	collapsibleIds,
	computeVisibleRows,
	isErrorSpan,
} from "@/lib/trace-tree";
import {
	Button,
	SegmentedControl,
	type SpanKind,
	type SpanNode,
	TranscriptSpine,
	cn,
} from "@tracelanedev/ui";
import { useCallback, useMemo, useState } from "react";
import { SpanInspector } from "./SpanInspector";
import { TraceSummaryHeader } from "./TraceSummaryHeader";
import { KIND_BAR } from "./WaterfallView";
import { WaterfallView } from "./WaterfallView";
import type { Span } from "./types";

type ViewMode = "waterfall" | "transcript";

const VIEW_OPTIONS = [
	{ value: "waterfall", label: "Waterfall" },
	{ value: "transcript", label: "Transcript" },
] as const satisfies ReadonlyArray<{ value: ViewMode; label: string }>;

/** Human label for each span kind — shown in the toolbar legend. */
const KIND_LABEL: Record<SpanKind, string> = {
	agent: "Agent",
	tool: "Tool",
	llm: "LLM",
	retrieval: "Retrieval",
	chain: "Chain",
	unknown: "Other",
};

function toNode(row: VisibleRow, hitCounts?: Record<string, number>): SpanNode {
	const s = row.span;
	const matched = s.aft_ids[0];
	// OBS-33: the badge reads "SEEN N×", which a user reads as "my workspace has hit
	// this signature N times". `hits` carries that number, sourced from the gateway's
	// per-tenant `your_hits` aggregate. It is NOT `s.aft_ids.length` — that is how many
	// DIFFERENT signatures matched this one span, which is a different quantity and was
	// almost always 1, so the badge read "SEEN 1×" for a signature the tenant had hit
	// hundreds of times.
	const hits = matched ? hitCounts?.[matched] : undefined;
	return {
		id: s.span_id,
		name: s.name,
		kind: inferSpanKind(s.attributes),
		durationMs: Math.round(s.duration_us / 1000),
		status: s.status_code === 2 ? "error" : "ok",
		// matched failure-signature (AFT) → the inline seen-before glow (per-tenant
		// hits; cross-customer network is V1.1). "View signature →" deep-links to
		// the §4 Failure Signatures page (now built — no longer a dead link).
		// label = human name from AFT-1 spec; title = "id: label" tooltip on hover.
		signature: matched
			? {
					// Undefined until the per-tenant aggregate loads. The badge renders
					// the label without a count rather than showing a wrong one — an
					// invented number is worse than an absent one on a trust surface.
					count: hits,
					label: aftLabel(matched),
					href: "/signatures",
					title: `${matched}: ${aftLabel(matched)}`,
				}
			: undefined,
		depth: row.depth,
		hasChildren: row.hasChildren,
		collapsed: row.collapsed,
	};
}

export function TraceDetailView({
	spans,
	hitCounts,
}: {
	spans: Span[];
	/**
	 * OBS-33 — per-tenant `your_hits` per signature id, resolved SERVER-side by the
	 * page and passed down. Undefined when the aggregate was unavailable; the badge
	 * then renders without a count rather than substituting a wrong one.
	 */
	hitCounts?: Record<string, number>;
}) {
	const [selectedId, setSelectedId] = useState<string | null>(null);
	const [collapsed, setCollapsed] = useState<Set<string>>(() => new Set());
	const [query, setQuery] = useState("");
	const [errorsOnly, setErrorsOnly] = useState(false);
	const [view, setView] = useState<ViewMode>("waterfall");

	const errorCount = useMemo(() => spans.filter(isErrorSpan).length, [spans]);
	const rows = useMemo(
		() => computeVisibleRows(spans, { collapsed, query, errorsOnly }),
		[spans, collapsed, query, errorsOnly],
	);
	const nodes = useMemo(
		() => rows.map((r) => toNode(r, hitCounts)),
		[rows, hitCounts],
	);
	// Axis bounds from ALL spans (not just visible) so collapsing never rescales.
	const bounds = useMemo(() => traceTimeBounds(spans), [spans]);
	const selectedSpan = useMemo(
		() => spans.find((s) => s.span_id === selectedId) ?? null,
		[spans, selectedId],
	);

	// Span-kind legend — only show kinds actually present in the visible rows,
	// and only when more than one kind is used (a single-kind trace needs no legend).
	const usedKinds = useMemo(() => {
		const seen = new Set<SpanKind>();
		for (const row of rows) {
			seen.add(inferSpanKind(row.span.attributes));
		}
		return [...seen];
	}, [rows]);
	const showLegend = usedKinds.length > 1;

	const toggleCollapse = useCallback((id: string) => {
		setCollapsed((prev) => {
			const next = new Set(prev);
			if (next.has(id)) next.delete(id);
			else next.add(id);
			return next;
		});
	}, []);

	return (
		<div className="space-y-4">
			<TraceSummaryHeader spans={spans} />
			<div className="flex flex-col gap-4 md:h-[calc(100vh-320px)] md:min-h-[400px] md:flex-row">
				{/* The span-view panel is a card, so it takes `--radius-card` from
				    `.surface-card` rather than the 12px `rounded-xl` it used to hardcode —
				    a bordered panel with padding and content is exactly what that class is
				    for, and hardcoding a radius is how a card drifts off the system. The
				    fill was `bg-surface`: a 40%-opaque white over an unknown parent is
				    off-white on the canvas and a grey smear inside a dark card, i.e. not a
				    colour anyone chose. It is the card surface now. */}
				<div className="surface-card flex flex-1 flex-col overflow-hidden border border-line bg-surface">
					<div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-2">
						{/*
						 * View toggle — Waterfall (readable default) | Transcript (spine).
						 *
						 * It was `role="tablist"` / `role="tab"` / `aria-selected` over two
						 * plain buttons, which claimed the ARIA tab contract without
						 * implementing either half: no roving tabindex (both buttons take
						 * Tab) and no `aria-controls` onto a `role="tabpanel"` (the two
						 * views render as siblings below, neither of them a tabpanel). The
						 * primitive announces `role="group"` with the SAME accessible name
						 * and `aria-pressed` on the chosen option — a weaker claim that
						 * the markup actually keeps.
						 */}
						<SegmentedControl
							label="Span view"
							value={view}
							options={VIEW_OPTIONS}
							onChange={setView}
						/>
						<input
							type="search"
							value={query}
							onChange={(e) => setQuery(e.target.value)}
							placeholder="Search spans…"
							aria-label="Search spans"
							className="w-full max-w-xs rounded-sm border border-line bg-surface px-3 py-1.5 text-xs text-ink placeholder:text-ink-3 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
						/>
						{errorCount > 0 && (
							<button
								type="button"
								onClick={() => setErrorsOnly((v) => !v)}
								aria-pressed={errorsOnly}
								title="Show only error spans and the path down to them"
								className={cn(
									"flex shrink-0 items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors focus-visible:outline-2 focus-visible:outline-focus-ring focus-visible:outline-offset-2",
									errorsOnly
										? "border-danger/40 bg-danger-soft text-danger-ink"
										: "border-line text-ink-2 hover:bg-surface-2 hover:text-ink",
								)}
							>
								<span
									aria-hidden
									className="h-1.5 w-1.5 rounded-full bg-danger"
								/>
								<span className="tabular-nums">{errorCount}</span>
								{errorCount === 1 ? "error" : "errors"}
							</button>
						)}

						{/* Compact span-kind legend — only shown when ≥ 2 kinds are visible.
						    Marks match the waterfall bars exactly (the same KIND_BAR map, imported
						    rather than restated). Each entry is a dot on the monochrome VALUE ramp
						    plus its small-caps label, so the label carries the meaning and the dot
						    only ranks it — the marks are no longer hues to be told apart. */}
						{showLegend && (
							<div
								className="flex items-center gap-3 t-metric-label"
								aria-label="Span kind legend"
							>
								{usedKinds.map((kind) => (
									<span key={kind} className="flex items-center gap-1">
										<span
											className={cn("h-1.5 w-1.5 rounded-full", KIND_BAR[kind])}
											aria-hidden
										/>
										{KIND_LABEL[kind]}
									</span>
								))}
							</div>
						)}

						<div className="ml-auto flex items-center gap-1.5">
							<Button
								type="button"
								variant="ghost"
								size="sm"
								onClick={() => setCollapsed(new Set())}
							>
								Expand all
							</Button>
							<Button
								type="button"
								variant="ghost"
								size="sm"
								onClick={() => setCollapsed(new Set(collapsibleIds(spans)))}
							>
								Collapse all
							</Button>
						</div>
					</div>
					<div className="flex-1 overflow-auto p-4">
						{rows.length === 0 ? (
							<div className="flex h-full min-h-32 flex-col items-center justify-center gap-1 text-center">
								<p className="text-sm font-medium text-ink">
									{errorsOnly
										? "No error spans match"
										: "No spans match your search"}
								</p>
								<p className="text-xs text-ink-2">
									{errorsOnly
										? "Every span in this trace completed without an error status."
										: "Try a different term, or clear the filters."}
								</p>
								{(query || errorsOnly) && (
									<Button
										type="button"
										variant="ghost"
										size="sm"
										className="mt-1"
										onClick={() => {
											setQuery("");
											setErrorsOnly(false);
										}}
									>
										Clear filters
									</Button>
								)}
							</div>
						) : view === "waterfall" ? (
							<WaterfallView
								rows={rows}
								startUs={bounds.startUs}
								totalUs={Math.max(0, bounds.endUs - bounds.startUs)}
								selectedId={selectedId ?? undefined}
								onSelectSpan={setSelectedId}
								onToggleCollapse={toggleCollapse}
							/>
						) : (
							<TranscriptSpine
								spans={nodes}
								selectedId={selectedId ?? undefined}
								onSelectSpan={setSelectedId}
								onToggleCollapse={toggleCollapse}
							/>
						)}
					</div>
				</div>
				{/* The inspector is the second card in the pair; same radius source as the
				    panel beside it, so the two read as one instrument. Its header band is
				    `--canvas-sunken`, the declared role for a strip that sits UNDER the
				    card surface — it was `bg-surface-2`, a half-strength well over the
				    card, which is a value that changes with whatever is behind it. */}
				<div className="surface-card flex w-full flex-col overflow-hidden border border-line bg-surface md:w-[480px] md:flex-shrink-0">
					<div className="border-b border-line bg-canvas-sunken px-4 py-3">
						<h2 className="text-sm font-semibold text-ink">Span Inspector</h2>
					</div>
					<SpanInspector span={selectedSpan} />
				</div>
			</div>
		</div>
	);
}

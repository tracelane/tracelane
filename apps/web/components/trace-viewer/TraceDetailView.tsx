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

/** Human label for each span kind — shown in the toolbar legend. */
const KIND_LABEL: Record<SpanKind, string> = {
	agent: "Agent",
	tool: "Tool",
	llm: "LLM",
	retrieval: "Retrieval",
	chain: "Chain",
	unknown: "Other",
};

function toNode(row: VisibleRow): SpanNode {
	const s = row.span;
	const matched = s.aft_ids[0];
	return {
		id: s.span_id,
		name: s.name,
		kind: inferSpanKind(s.attributes),
		durationMs: Math.round(s.duration_us / 1000),
		status: s.status_code === 2 ? "error" : "ok",
		// matched failure-signature (AFT) → the inline seen-before glow (per-tenant
		// the §4 Failure Signatures page (now built — no longer a dead link).
		// label = human name from AFT-1 spec; title = "id: label" tooltip on hover.
		signature: matched
			? {
					count: s.aft_ids.length,
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

export function TraceDetailView({ spans }: { spans: Span[] }) {
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
	const nodes = useMemo(() => rows.map(toNode), [rows]);
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
				<div className="flex flex-1 flex-col overflow-hidden rounded-xl border border-line bg-surface/40">
					<div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-2">
						{/* View toggle — Waterfall (readable default) | Transcript (spine). */}
						<div
							role="tablist"
							aria-label="Span view"
							className="flex items-center rounded-md border border-line p-0.5"
						>
							{(
								[
									["waterfall", "Waterfall"],
									["transcript", "Transcript"],
								] as const
							).map(([mode, label]) => (
								<button
									key={mode}
									type="button"
									role="tab"
									aria-selected={view === mode}
									onClick={() => setView(mode)}
									className={cn(
										"rounded px-2.5 py-1 text-xs font-medium transition-colors focus-visible:outline-2 focus-visible:outline-seal focus-visible:outline-offset-1",
										view === mode
											? "bg-surface-2 text-ink"
											: "text-ink-2 hover:text-ink",
									)}
								>
									{label}
								</button>
							))}
						</div>
						<input
							type="search"
							value={query}
							onChange={(e) => setQuery(e.target.value)}
							placeholder="Search spans…"
							aria-label="Search spans"
							className="w-full max-w-xs rounded-md border border-line bg-surface px-3 py-1.5 text-xs text-ink outline-none placeholder:text-ink-3 focus-visible:ring-2 focus-visible:ring-seal"
						/>
						{errorCount > 0 && (
							<button
								type="button"
								onClick={() => setErrorsOnly((v) => !v)}
								aria-pressed={errorsOnly}
								title="Show only error spans and the path down to them"
								className={cn(
									"flex shrink-0 items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors focus-visible:outline-2 focus-visible:outline-seal focus-visible:outline-offset-1",
									errorsOnly
										? "border-danger/40 bg-danger-soft text-danger"
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
						    Colors match the waterfall bars exactly (KIND_BAR). Each entry is a
						    colored dot + uppercase label (never color alone). */}
						{showLegend && (
							<div
								className="flex items-center gap-3 text-[10px] font-semibold uppercase tracking-wide text-ink-3"
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
				<div className="flex w-full flex-col overflow-hidden rounded-xl border border-line bg-surface md:w-[480px] md:flex-shrink-0">
					<div className="border-b border-line bg-surface-2/50 px-4 py-3">
						<h2 className="text-sm font-semibold text-ink">Span Inspector</h2>
					</div>
					<SpanInspector span={selectedSpan} />
				</div>
			</div>
		</div>
	);
}

import type { KeyboardEvent } from "react";
import { cn } from "../lib/cn";
import { ProvenanceChip } from "./HashChainThread";
import { SeenBeforeSignal } from "./SeenBeforeSignal";

// `unknown` is explicit: when a span's kind can't be inferred with confidence we
// render it neutral rather than guess (a misattributed kind is worse than less
// detail). Error attribution is independent of kind (it's status-driven).
export type SpanKind =
	| "agent"
	| "tool"
	| "llm"
	| "retrieval"
	| "chain"
	| "unknown";

export interface SpanNode {
	id: string;
	name: string;
	kind: SpanKind;
	durationMs: number;
	status: "ok" | "error";
	/** matched failure signature → renders the inline seen-before glow. */
	signature?: {
		/** Per-tenant hits. Optional: absent until resolved — see SeenBeforeSignal. */
		count?: number;
		label: string;
		href?: string;
		/** Native browser tooltip shown on hover — AFT-1 id + human label. */
		title?: string;
	};
	/** tree depth (0 = root) → indentation. Omit/0 keeps the flat narrative. */
	depth?: number;
	/** has child spans → renders the expand/collapse disclosure + aria-expanded. */
	hasChildren?: boolean;
	/** the node's collapse state (only meaningful when `hasChildren`). */
	collapsed?: boolean;
}

/**
 * THE span-kind value ramp — ONE map, exported, spent by every surface that marks a
 * span by kind (the transcript spine's dots here, the waterfall's bars in
 * `apps/web/components/trace-viewer/WaterfallView.tsx`).
 *
 * IT WAS TWO MAPS, AND THEY DRIFTED THE MOMENT THE PALETTE MOVED. Both encoded the
 * same idea and neither knew about the other, so the 2026-08-22 swap fixed one and
 * left the other holding a broken step: the spine had `llm: "bg-info/50"`, and once
 * `--info` was retargeted from violet to `--chart-primary` that alpha composited to
 * ~#8d8e90 — a hair off `--ink-3` #828280. Six kinds, five distinguishable marks,
 * and no test could see it because both classes were present and correct in the DOM.
 * A shared concept with two definitions is a drift generator; this is the fix, and
 * the duplicate is deleted rather than re-synced.
 *
 * WHY VALUE AND NOT HUE. `--ok`/`--seal` are provenance-only and the action roles are
 * CTA-only, so a span KIND — which is neither a state nor an action — must separate on
 * the neutral ramp. Under P0.11 there is no free data hue left to group `tool` and
 * `llm` into a family, and that is deliberate.
 *
 * THREE STEPS, NOT FOUR, AND `--ink-3` IS THE FLOOR ON PURPOSE. `--line-2` was the
 * obvious fourth step and is where `unknown` would have landed — but `inferSpanKind`
 * returns "unknown" whenever no strong attribute signal is present, so on real
 * traces it is the MOST COMMON kind. A ramp that puts the most common kind at hairline
 * value renders the typical trace as ghost marks. `--ink-3` is the system's declared UI
 * floor (3.85:1 light / 3.74:1 dark) and is where the readable end of a ramp stops.
 *
 * Kinds sharing a step is not new and not a defect: every consumer renders a text
 * label beside the mark, so colour is never the only carrier, and errors override to
 * `--danger` — the one place a span mark is coloured at all.
 */
export const SPAN_KIND_MARK: Record<SpanKind, string> = {
	tool: "bg-chart-primary",
	llm: "bg-ink-2",
	agent: "bg-ink-3",
	retrieval: "bg-ink-3",
	chain: "bg-ink-3",
	unknown: "bg-ink-3",
};

export interface TranscriptSpineProps {
	spans: SpanNode[];
	/**
	 * A REAL per-trace cryptographic chain verdict (recompute + walk to genesis +
	 * anchor). Drives BOTH the "Verified · chain ✓" chip AND the spine rail colour:
	 * green (--seal, the provenance thread) ONLY when `true`, neutral otherwise.
	 * Omit unless the caller actually computed the verdict — a green rail on an
	 * unverified trace is a per-trace-verified overclaim (honesty lock). Presence in
	 * the ledger (`chained`) is NOT a verdict; the full verify runs on the Audit page.
	 */
	verified?: boolean;
	/** id of the selected span (highlights its node). */
	selectedId?: string;
	/** when provided, nodes become selectable (→ open the span inspector). */
	onSelectSpan?: (id: string) => void;
	/** when provided, parent nodes get an expand/collapse disclosure (tree mode). */
	onToggleCollapse?: (id: string) => void;
	className?: string;
}

/**
 * Transcript-with-a-spine (trace detail) — replaces the generic waterfall
 * (the design-system spec §3.1/§3.2). The run reads TOP-TO-BOTTOM as a narrative;
 * a vertical timeline spine on the left (Verify-green ONLY when `verified` is a
 * real chain verdict — neutral otherwise, never green ungated),
 * color-coded span-kind node pins, error nodes ringed red, a latency bar per
 * step, and the inline seen-before glow where a signature matches.
 *
 * In-house component (design system). Spans may be supplied flat
 * (chronological) or pre-shaped into a hierarchy by the caller: pass `depth` /
 * `hasChildren` / `collapsed` on each `SpanNode` to render an ARIA tree with
 * indentation and expand/collapse. The span-tree is reconstructed from
 * `parent_span_id` in `apps/web/lib/trace-tree.ts` — our own code over our
 * canonical `gen_ai_*` columns; no third-party viewer dependency.
 */
export function TranscriptSpine({
	spans,
	verified,
	selectedId,
	onSelectSpan,
	onToggleCollapse,
	className,
}: TranscriptSpineProps) {
	const maxMs = Math.max(1, ...spans.map((s) => s.durationMs));
	const hasError = spans.some((s) => s.status === "error");
	// Tree mode kicks in only when the caller pre-shapes hierarchy (depth set on
	// any node); otherwise we render the original flat chronological narrative.
	const isTree = spans.some((s) => (s.depth ?? 0) > 0 || s.hasChildren);

	return (
		<div className={cn("relative", className)}>
			{/* header: error-propagation badge + provenance chip */}
			{(hasError || verified !== undefined) && (
				<div className="mb-3 flex items-center gap-2">
					{hasError && (
						<span className="inline-flex items-center gap-1 rounded-md bg-danger-soft px-1.5 py-0.5 text-2xs font-semibold text-danger-ink">
							▲ error inside
						</span>
					)}
					{verified !== undefined && <ProvenanceChip verified={verified} />}
				</div>
			)}

			<div className="relative pl-6">
				{/* the spine — a 2px rail down the left. Verify-green (--seal, the
				    provenance thread) ONLY when the trace's chain is actually verified;
				    neutral otherwise, so an unverified trace never wears a provenance
				    colour it didn't earn (honesty lock — never green ungated). */}
				<span
					aria-hidden
					className={cn(
						"absolute bottom-2 left-2 top-2 border-l-2",
						verified === true ? "border-seal" : "border-line-2",
					)}
				/>
				<ol
					className="space-y-2"
					role={isTree ? "tree" : undefined}
					aria-label={isTree ? "Trace spans" : undefined}
				>
					{spans.map((s) => {
						const selected = selectedId === s.id;
						const interactive = Boolean(onSelectSpan);
						const depth = s.depth ?? 0;
						const hasChildren = s.hasChildren ?? false;
						const collapsed = s.collapsed ?? false;
						const canToggle = hasChildren && Boolean(onToggleCollapse);
						const onKeyDown =
							interactive || canToggle
								? (e: KeyboardEvent) => {
										if (interactive && (e.key === "Enter" || e.key === " ")) {
											e.preventDefault();
											onSelectSpan?.(s.id);
										} else if (
											canToggle &&
											e.key === "ArrowRight" &&
											collapsed
										) {
											e.preventDefault();
											onToggleCollapse?.(s.id);
										} else if (
											canToggle &&
											e.key === "ArrowLeft" &&
											!collapsed
										) {
											e.preventDefault();
											onToggleCollapse?.(s.id);
										}
									}
								: undefined;
						return (
							<li
								key={s.id}
								className="relative"
								role={isTree ? "treeitem" : undefined}
								aria-level={isTree ? depth + 1 : undefined}
								aria-selected={interactive ? selected : undefined}
								aria-expanded={hasChildren ? !collapsed : undefined}
							>
								{/* node pin on the spine, color-coded by kind; error → red ring */}
								<span
									aria-hidden
									className={cn(
										"absolute top-3 h-2 w-2 rounded-full ring-2 ring-bg",
										"-left-[19px]",
										SPAN_KIND_MARK[s.kind],
										s.status === "error" && "ring-danger",
									)}
								/>
								{/* role=button (not <button>) so the inner seen-before link stays valid */}
								<div
									role={interactive ? "button" : undefined}
									tabIndex={interactive ? 0 : undefined}
									onClick={interactive ? () => onSelectSpan?.(s.id) : undefined}
									onKeyDown={onKeyDown}
									style={depth > 0 ? { marginLeft: depth * 16 } : undefined}
									className={cn(
										"rounded-lg border px-3 py-2 transition-colors",
										s.status === "error"
											? "border-danger/40 bg-danger-soft/30"
											: "border-line bg-surface",
										interactive &&
											"cursor-pointer hover:border-action-line/60 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring",
										selected && "bg-action-soft/40 ring-2 ring-action-line",
									)}
								>
									<div className="flex items-center justify-between gap-3">
										<span className="flex min-w-0 items-center gap-1.5">
											{isTree && (
												<Disclosure
													hasChildren={hasChildren}
													collapsed={collapsed}
													canToggle={canToggle}
													onToggle={() => onToggleCollapse?.(s.id)}
												/>
											)}
											<span className="truncate text-sm font-medium text-ink">
												{s.name}
											</span>
										</span>
										<span className="shrink-0 font-mono text-2xs tabular-nums text-ink-2">
											{s.durationMs}&nbsp;ms
										</span>
									</div>
									{/* Latency bar — `.bar-data` on a `--surface-2` track.
										The class was `.bar-lava` and this comment described a
										"lava-gradient magnitude fill"; BOTH the gradient and the
										colour are gone as of 2026-08-22. `.bar-data` is a FLAT
										`--chart-primary` fill — one material for every proportion
										bar in the app — because P0 spends colour on meaning and a
										gradient on a magnitude bar encodes nothing that the bar's
										own length does not already say. */}
									<div className="mt-1 h-1 rounded-full bg-surface-2">
										<div
											className="h-1 rounded-full bar-data"
											style={{ width: `${(s.durationMs / maxMs) * 100}%` }}
										/>
									</div>
									{s.signature && (
										<div className="mt-1.5">
											<SeenBeforeSignal
												count={s.signature.count}
												signatureLabel={s.signature.label}
												href={s.signature.href}
												title={s.signature.title}
											/>
										</div>
									)}
								</div>
							</li>
						);
					})}
				</ol>
			</div>
		</div>
	);
}

/**
 * Expand/collapse disclosure for a tree node. Renders an interactive triangle
 * when toggling is wired, a static triangle when it isn't, and an aligned spacer
 * for leaves (so names line up). Tree mode only — never shown in the flat view.
 */
function Disclosure({
	hasChildren,
	collapsed,
	canToggle,
	onToggle,
}: {
	hasChildren: boolean;
	collapsed: boolean;
	canToggle: boolean;
	onToggle: () => void;
}) {
	if (!hasChildren) {
		return <span aria-hidden className="inline-block h-4 w-4 shrink-0" />;
	}
	if (!canToggle) {
		return (
			<span
				aria-hidden
				className="grid h-4 w-4 shrink-0 place-items-center text-2xs leading-none text-ink-3"
			>
				{collapsed ? "▶" : "▼"}
			</span>
		);
	}
	return (
		<button
			type="button"
			aria-label={collapsed ? "Expand span" : "Collapse span"}
			onClick={(e) => {
				e.stopPropagation();
				onToggle();
			}}
			className="grid h-4 w-4 shrink-0 place-items-center rounded text-ink-3 hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
		>
			<span aria-hidden className="text-2xs">
				{collapsed ? "▶" : "▼"}
			</span>
		</button>
	);
}

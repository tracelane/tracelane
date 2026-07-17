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
		count: number;
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

// span-kind colours (consistent everywhere). ADR-053 discipline: Lava (--accent)
// is CTA-only and Verify-green (--ok/--seal) is provenance-only, so span kinds use
// the one free data hue (violet --info, the AI-call family: tool bold, llm faint) +
// neutral ink for structure. The kind label always accompanies the colour — never
// colour alone. Error nodes are ringed red.
const KIND_DOT: Record<SpanKind, string> = {
	agent: "bg-ink-2",
	tool: "bg-info",
	llm: "bg-info/50",
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
 * In-house component (Neon design system). Spans may be supplied flat
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
						<span className="inline-flex items-center gap-1 rounded-md bg-danger-soft px-1.5 py-0.5 text-[11px] font-semibold text-danger">
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
										KIND_DOT[s.kind],
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
										"rounded-lg border px-3 py-2 outline-none transition-colors",
										s.status === "error"
											? "border-danger/40 bg-danger-soft/30"
											: "border-line bg-surface",
										interactive &&
											"cursor-pointer hover:border-accent-line/60 focus-visible:ring-2 focus-visible:ring-accent-ink",
										selected && "bg-accent-soft/40 ring-2 ring-accent-line",
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
											<span className="truncate text-[13px] font-medium text-ink">
												{s.name}
											</span>
										</span>
										<span className="shrink-0 font-mono text-[11px] tabular-nums text-ink-2">
											{s.durationMs}&nbsp;ms
										</span>
									</div>
									{/* latency bar — neutral magnitude fill (ADR-053: Lava is
										CTA-only, never a decorative data-bar). */}
									<div className="mt-1 h-1 rounded-full bg-surface-2">
										<div
											className="h-1 rounded-full bg-ink-3"
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
				className="grid h-4 w-4 shrink-0 place-items-center text-[9px] text-ink-3"
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
			className="grid h-4 w-4 shrink-0 place-items-center rounded text-ink-3 outline-none hover:text-ink focus-visible:ring-2 focus-visible:ring-accent-ink"
		>
			<span aria-hidden className="text-[9px]">
				{collapsed ? "▶" : "▼"}
			</span>
		</button>
	);
}

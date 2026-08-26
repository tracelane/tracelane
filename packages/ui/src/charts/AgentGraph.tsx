import { cn } from "../lib/cn";

/**
 * AgentGraph — agent → tools → models topology. Nodes sized by real usage; edges
 * schematic.
 *
 * ── ⚠ THIS COMPONENT IS EXPORTED AND RENDERED NOWHERE. THAT IS A DECISION. ───
 * Documented 2026-08-22 after a git/docs investigation, because nothing at HEAD said
 * so and the next reader would otherwise either delete it as dead or "restore" it
 * believing it was dropped by accident.
 *
 * IT HAD A CALLER AND LOST IT — not forgotten. Built `97035423` (2026-07-26 05:57
 * UTC) alongside `RequestFlow` and `ModelDonut` to match a founder screenshot
 * (`:8576`), live at `97035423:apps/web/app/dashboard/page.tsx:41` +
 * `:669`, and deployed the same day. Removed **2 h 26 min later** by `3a3cc2ae`
 * (08:23 UTC), whose commit message gives the reason verbatim:
 *
 *     "Dropped Model-breakdown donut (kept the Traffic-by-model table)
 *      + Agent execution (redundant nodes, schematic edges)."
 *
 * Founder authority is recorded twice — `:8559` (session header: *"drop
 * agent, hunt duplicates"*) and `:8565` (*"agent-execution dropped (nodes duplicated
 * donut+tool-table; edges schematic)"*). `git log -S'<AgentGraph'` returns exactly
 * two commits, the adder and the remover, so nothing has re-added it. The export in
 * `index.ts` was simply never withdrawn with the card.
 *
 * NOT BLOCKED ON DATA. `/v1/query/tool-analytics` is still fetched by the dashboard.
 * The sibling proves the point: `ModelDonut` was cut by the SAME sentence and
 * re-wired 26 days later in `40b69596` (DSH-08) — a sweep whose whole purpose was
 * rewiring built-but-unused charts. It picked up the donut and passed over this.
 *
 * TO SHIP IT, TWO THINGS MUST CHANGE, and only one of them has:
 *   1. Redundancy — SPENT. The donut got its own home in DSH-08, so this no longer
 *      duplicates the model breakdown and the tool table.
 *   2. Honesty — NOT SPENT, and it is the blocker. "Edges schematic" means the
 *      agent→tool→model links are DRAWN, not MEASURED:
 *      `crates/gateway/src/tool_analytics.rs` returns per-tool aggregates
 *      (calls / errors / p95_ms) with no model association at all. Until a read
 *      exists that can say which model called which tool, every edge here is a
 *      claim the data does not support — which is the one thing this product does
 *      not get to draw.
 *
 * THE DOCSTRING ANCHOR THAT USED TO BE HERE WAS FALSE. It cited
 * `docs/design/tracelane-app-full.html "agent execution"`; that string appears
 * **zero** times in that file, at HEAD and in `0273fd33` which added it — wrong at
 * birth. `check-spec-anchors.py` only scans `specs/`, so source docstring anchors
 * are ungated; that gap is why it survived.
 */

export interface AgentGraphNode {
	/** Stable unique key (e.g. `provider::model`); falls back to `label`. */
	id?: string;
	/** Tool or model name. */
	label: string;
	/** Real usage weight (calls / requests) — sizes the node dot. */
	weight?: number;
	/** Optional click-through (plain anchor). */
	href?: string;
}

export interface AgentGraphProps {
	/** Top tools by call volume (caller slices; ≤4 renders cleanly). */
	tools: AgentGraphNode[];
	/** Top models by request volume (caller slices; ≤3 renders cleanly). */
	models: AgentGraphNode[];
	className?: string;
	ariaLabel?: string;
}

const AGENT_X = 12;
const TOOL_X = 50;
const MODEL_X = 88;
const GRAPH_H = 150;

/** Evenly-spaced node y-centers within a padded band. */
function ys(n: number): number[] {
	if (n <= 0) return [];
	const top = 12;
	const span = 68; // 12%..80% of the graph band
	return Array.from({ length: n }, (_, j) => top + ((j + 0.5) / n) * span);
}

/** Dot diameter (px) from a usage weight, relative to the column max. */
function dotPx(weight: number | undefined, max: number): number {
	if (!weight || max <= 0) return 9;
	return 8 + Math.round((weight / max) * 8); // 8..16
}

export function AgentGraph({
	tools,
	models,
	className,
	ariaLabel,
}: AgentGraphProps) {
	const toolY = ys(tools.length);
	const modelY = ys(models.length);
	const toolMax = Math.max(0, ...tools.map((t) => t.weight ?? 0));
	const modelMax = Math.max(0, ...models.map((m) => m.weight ?? 0));

	// Edge set: agent→tool, then tool→model (faint bipartite). When there are no
	// tools, connect agent→model directly so the topology still reads.
	const edges: { x1: number; y1: number; x2: number; y2: number }[] = [];
	for (const ty of toolY)
		edges.push({ x1: AGENT_X, y1: 50, x2: TOOL_X, y2: ty });
	if (toolY.length > 0) {
		for (const ty of toolY)
			for (const my of modelY)
				edges.push({ x1: TOOL_X, y1: ty, x2: MODEL_X, y2: my });
	} else {
		for (const my of modelY)
			edges.push({ x1: AGENT_X, y1: 50, x2: MODEL_X, y2: my });
	}

	const dot = (
		x: number,
		y: number,
		size: number,
		color: string,
		label: string,
	) => (
		<span
			key={`${label}-${x}-${y}`}
			className="absolute -translate-x-1/2 -translate-y-1/2 rounded-full ring-2 ring-surface"
			style={{
				left: `${x}%`,
				top: `${y}%`,
				width: size,
				height: size,
				background: color,
			}}
			title={label}
		/>
	);

	const legendRow = (title: string, nodes: AgentGraphNode[], color: string) =>
		nodes.length > 0 ? (
			<div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-2xs text-ink-3">
				<span className="font-medium text-ink-2">{title}</span>
				{nodes.map((n) => {
					const inner = (
						<span
							key={n.id ?? n.label}
							className="inline-flex items-center gap-1"
						>
							<span
								className="h-1.5 w-1.5 shrink-0 rounded-full"
								style={{ background: color }}
							/>
							<span className="max-w-[120px] truncate font-mono text-ink-2">
								{n.label}
							</span>
						</span>
					);
					return n.href ? (
						<a
							key={n.id ?? n.label}
							href={n.href}
							className="rounded hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
						>
							{inner}
						</a>
					) : (
						<span key={n.id ?? n.label}>{inner}</span>
					);
				})}
			</div>
		) : null;

	return (
		<div className={cn("flex w-full flex-col gap-2", className)}>
			<div
				className="relative w-full"
				style={{ height: GRAPH_H }}
				role="img"
				aria-label={ariaLabel ?? "agent topology: agent, tools and models"}
			>
				{/* edges (behind) */}
				<svg
					viewBox="0 0 100 100"
					preserveAspectRatio="none"
					className="absolute inset-0 h-full w-full"
					aria-hidden="true"
				>
					{edges.map((e) => (
						<line
							key={`${e.x1}-${e.y1}-${e.x2}-${e.y2}`}
							x1={e.x1}
							y1={e.y1}
							x2={e.x2}
							y2={e.y2}
							stroke="var(--line-2)"
							strokeWidth={0.5}
							vectorEffect="non-scaling-stroke"
						/>
					))}
				</svg>

				{/* nodes */}
				{dot(AGENT_X, 50, 15, "var(--ink)", "agent")}
				{tools.map((t, j) =>
					dot(
						TOOL_X,
						toolY[j] ?? 50,
						dotPx(t.weight, toolMax),
						"var(--chart-primary)",
						t.label,
					),
				)}
				{models.map((m, k) =>
					dot(
						MODEL_X,
						modelY[k] ?? 50,
						dotPx(m.weight, modelMax),
						"var(--chart-secondary)",
						m.label,
					),
				)}

				{/* column captions */}
				<span
					/* design-constraint-ok: label positioned by the same pixel scale as the marks it labels — the ramp floor would overlap the neighbouring tick */
					className="absolute -translate-x-1/2 text-[9px] font-medium uppercase tracking-wide text-ink-3"
					style={{ left: `${AGENT_X}%`, top: "88%" }}
				>
					agent
				</span>
				<span
					/* design-constraint-ok: label positioned by the same pixel scale as the marks it labels — the ramp floor would overlap the neighbouring tick */
					className="absolute -translate-x-1/2 text-[9px] font-medium uppercase tracking-wide text-ink-3"
					style={{ left: `${TOOL_X}%`, top: "88%" }}
				>
					tools
				</span>
				<span
					/* design-constraint-ok: label positioned by the same pixel scale as the marks it labels — the ramp floor would overlap the neighbouring tick */
					className="absolute -translate-x-1/2 text-[9px] font-medium uppercase tracking-wide text-ink-3"
					style={{ left: `${MODEL_X}%`, top: "88%" }}
				>
					models
				</span>
			</div>

			{/* legend — dot → name, with drill-through */}
			<div className="space-y-1">
				{legendRow("Tools", tools, "var(--chart-primary)")}
				{legendRow("Models", models, "var(--chart-secondary)")}
			</div>
		</div>
	);
}

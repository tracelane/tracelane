/**
 * trace-tree — OTLP span normalization for the transcript-spine viewer.
 *
 * Reconstructs the span hierarchy from `parent_span_id`, computes the visible
 * (collapse-aware) row list, runs span search with ancestor reveal, and pulls
 * the structured `gen_ai.*` summary out of the raw attribute JSON. Implemented
 * in-house over our canonical `gen_ai_*` columns — no third-party viewer code.
 *
 * Callers: `components/trace-viewer/TraceDetailView.tsx` (tree + search state) and
 * `components/trace-viewer/SpanInspector.tsx` (`extractGenAi`).
 *
 * Invariants: pure and deterministic — no DOM, no clock, no network. Every span
 * surfaces exactly once even under orphaned parents or parent cycles. Token
 * counts come only from real attributes; cost is NEVER synthesized here.
 */

import type { Span } from "@/components/trace-viewer/types";

/** A span plus its reconstructed children and tree depth (0 = root). */
export interface SpanTreeNode {
	span: Span;
	depth: number;
	children: SpanTreeNode[];
}

/** A flattened, render-ready row: depth for indentation, collapse/disclosure state. */
export interface VisibleRow {
	span: Span;
	depth: number;
	hasChildren: boolean;
	collapsed: boolean;
}

/** Structured `gen_ai` summary. All fields optional — absent attrs stay absent. */
export interface GenAiSummary {
	system?: string;
	model?: string;
	operation?: string;
	inputTokens?: number;
	outputTokens?: number;
	/** input + output (or an explicit total-tokens attr); a real count, never a cost. */
	totalTokens?: number;
	/**
	 * Real per-span cost in USD — the stored `gen_ai_usage_cost`, which the
	 * gateway derives from the model price catalog (`crates/gateway/src/pricing.rs`)
	 * or a provider-reported cost. Read as-stored; NEVER derived or fabricated
	 * here. Absent when the model isn't priced and the provider reported none.
	 */
	cost?: number;
}

/**
 * Stable sibling order: chronological by `start_time`, `span_id` as tiebreak.
 * Unparseable timestamps fall back to `span_id` so order stays deterministic.
 */
function compareSiblings(a: Span, b: Span): number {
	const ta = Date.parse(a.start_time);
	const tb = Date.parse(b.start_time);
	if (Number.isFinite(ta) && Number.isFinite(tb) && ta !== tb) return ta - tb;
	if (a.span_id < b.span_id) return -1;
	if (a.span_id > b.span_id) return 1;
	return 0;
}

/**
 * Build the span forest from a flat span list.
 *
 * Roots are spans with a null/self/dangling parent. Siblings are ordered by
 * {@link compareSiblings}. Cycle-safe: a child already on the ancestor path is
 * skipped, and any span reachable only inside a parentless cycle is surfaced as
 * its own root so nothing is dropped.
 *
 * @returns root nodes in chronological order.
 */
export function buildSpanTree(spans: Span[]): SpanTreeNode[] {
	const byId = new Map<string, Span>();
	for (const s of spans) byId.set(s.span_id, s);

	const childrenByParent = new Map<string, Span[]>();
	const roots: Span[] = [];
	for (const s of spans) {
		const parentId = s.parent_span_id;
		if (parentId && parentId !== s.span_id && byId.has(parentId)) {
			const list = childrenByParent.get(parentId);
			if (list) list.push(s);
			else childrenByParent.set(parentId, [s]);
		} else {
			// null parent, self-parent, or orphan (parent outside the set) → root.
			roots.push(s);
		}
	}

	const reached = new Set<string>();

	// Explicit-stack DFS rather than native recursion: a degenerate 10K-deep
	// chain would otherwise blow the call stack (RangeError). Each frame carries
	// the node being built and the ancestor-path set used as the cycle guard;
	// children are appended in sorted order so the output is identical to the
	// previous recursive build.
	const growTree = (rootSpan: Span): SpanTreeNode => {
		const root: SpanTreeNode = { span: rootSpan, depth: 0, children: [] };
		reached.add(rootSpan.span_id);
		const stack: Array<{ node: SpanTreeNode; onPath: Set<string> }> = [
			{ node: root, onPath: new Set([rootSpan.span_id]) },
		];
		while (stack.length > 0) {
			const frame = stack.pop();
			if (!frame) break;
			const { node, onPath } = frame;
			const kids = (childrenByParent.get(node.span.span_id) ?? [])
				.filter((c) => !onPath.has(c.span_id)) // cycle guard
				.sort(compareSiblings);
			for (const kidSpan of kids) {
				reached.add(kidSpan.span_id);
				const child: SpanTreeNode = {
					span: kidSpan,
					depth: node.depth + 1,
					children: [],
				};
				node.children.push(child);
				const childPath = new Set(onPath);
				childPath.add(kidSpan.span_id);
				stack.push({ node: child, onPath: childPath });
			}
		}
		return root;
	};

	const out = roots.sort(compareSiblings).map((r) => growTree(r));

	// Spans only reachable inside a parentless cycle would otherwise vanish —
	// surface the lowest-id member as a root (cycle guard breaks the loop).
	for (const s of [...spans].sort(compareSiblings)) {
		if (!reached.has(s.span_id)) out.push(growTree(s));
	}
	return out;
}

/**
 * Pre-order flatten honoring collapse state: a collapsed node is emitted but its
 * descendants are skipped. Used for the default (non-search) render.
 */
export function flattenVisible(
	roots: SpanTreeNode[],
	collapsed: Set<string>,
): VisibleRow[] {
	const rows: VisibleRow[] = [];
	// Explicit-stack pre-order walk (no recursion → no stack overflow on deep
	// traces). Children are pushed reversed so they pop in chronological order,
	// preserving the previous recursive emit order.
	const stack: SpanTreeNode[] = [...roots].reverse();
	while (stack.length > 0) {
		const node = stack.pop();
		if (!node) break;
		const isCollapsed = collapsed.has(node.span.span_id);
		rows.push({
			span: node.span,
			depth: node.depth,
			hasChildren: node.children.length > 0,
			collapsed: isCollapsed,
		});
		if (!isCollapsed) {
			for (const c of [...node.children].reverse()) stack.push(c);
		}
	}
	return rows;
}

/**
 * Case-insensitive match on span name, span id, or resolved model. An empty
 * query matches everything (the no-filter case).
 */
export function matchesQuery(span: Span, query: string): boolean {
	const q = query.trim().toLowerCase();
	if (q === "") return true;
	if (span.name.toLowerCase().includes(q)) return true;
	if (span.span_id.toLowerCase().includes(q)) return true;
	const model = extractGenAi(span.attributes).model;
	return model?.toLowerCase().includes(q) ?? false;
}

/** A span with an error status (OTLP `STATUS_CODE_ERROR` = 2). */
export function isErrorSpan(span: Span): boolean {
	return span.status_code === 2;
}

/** Ids matching `pred`, plus each match's ancestor path up to its root (so the
 * path stays revealable). Generic over the predicate so search and the
 * errors-only filter share one ancestor-reveal walk. */
function visibleIdsMatching(
	spans: Span[],
	pred: (s: Span) => boolean,
): Set<string> {
	const byId = new Map<string, Span>();
	const parentOf = new Map<string, string | null>();
	for (const s of spans) {
		byId.set(s.span_id, s);
		parentOf.set(s.span_id, s.parent_span_id);
	}
	const visible = new Set<string>();
	for (const s of spans) {
		if (!pred(s)) continue;
		let cur: string | null | undefined = s.span_id;
		const guard = new Set<string>();
		while (cur && byId.has(cur) && !guard.has(cur)) {
			visible.add(cur);
			guard.add(cur);
			cur = parentOf.get(cur) ?? null;
		}
	}
	return visible;
}

/**
 * The rows the viewer should render for a given collapse/query/filter state.
 *
 * No query and no filter → {@link flattenVisible} honoring `collapsed`. With a
 * query and/or `errorsOnly` → only spans matching every active filter and their
 * ancestors, force-expanded so every hit is on screen. `errorsOnly` reveals just
 * the error spans and the path down to them — the fast answer to "where's the
 * error" in a deep trace.
 */
export function computeVisibleRows(
	spans: Span[],
	opts: { collapsed: Set<string>; query: string; errorsOnly?: boolean },
): VisibleRow[] {
	const roots = buildSpanTree(spans);
	const q = opts.query.trim();
	const errorsOnly = opts.errorsOnly ?? false;
	if (q === "" && !errorsOnly) return flattenVisible(roots, opts.collapsed);

	const visible = visibleIdsMatching(
		spans,
		(s) => (q === "" || matchesQuery(s, q)) && (!errorsOnly || isErrorSpan(s)),
	);
	const rows: VisibleRow[] = [];
	// Explicit-stack pre-order walk (no recursion → no stack overflow on deep
	// traces). A node not in `visible` is skipped along with its subtree (matches
	// the previous early-return); in-view children are pushed reversed so they
	// pop in chronological order.
	const stack: SpanTreeNode[] = [...roots].reverse();
	while (stack.length > 0) {
		const node = stack.pop();
		if (!node) break;
		if (!visible.has(node.span.span_id)) continue;
		const childrenInView = node.children.filter((c) =>
			visible.has(c.span.span_id),
		);
		rows.push({
			span: node.span,
			depth: node.depth,
			hasChildren: childrenInView.length > 0,
			collapsed: false, // force-expanded during search
		});
		for (const c of [...childrenInView].reverse()) stack.push(c);
	}
	return rows;
}

/** All span ids that have at least one child — the set "Collapse all" should hold. */
export function collapsibleIds(spans: Span[]): string[] {
	const parents = new Set<string>();
	const ids = new Set(spans.map((s) => s.span_id));
	for (const s of spans) {
		const p = s.parent_span_id;
		if (p && p !== s.span_id && ids.has(p)) parents.add(p);
	}
	return [...parents];
}

/** Coerce an attribute value to a finite number, or undefined. Never invents a value. */
function toFiniteNumber(v: unknown): number | undefined {
	if (typeof v === "number") return Number.isFinite(v) ? v : undefined;
	if (typeof v === "string" && v.trim() !== "") {
		const n = Number(v);
		return Number.isFinite(n) ? n : undefined;
	}
	return undefined;
}

/**
 * Extract the structured `gen_ai` summary from a span's attribute JSON.
 *
 * The stored form is **underscore-flattened** `gen_ai_*` (ADR-043; ingest
 * normalises incoming dotted OTLP keys to underscore). We read underscore keys
 * first and fall back to the dotted OTel form for any un-normalised straggler
 * (older/seed spans, raw OTLP). `totalTokens` is input+output of REAL counts (or
 * an explicit total). `cost` is the stored `gen_ai_usage_cost` read as-is — never
 * derived or fabricated here (the gateway computes it from the price catalog).
 * Returns `{}` on unparseable input.
 */
export function extractGenAi(attributesJson: string): GenAiSummary {
	let attrs: Record<string, unknown>;
	try {
		const parsed: unknown = JSON.parse(attributesJson);
		attrs =
			parsed && typeof parsed === "object"
				? (parsed as Record<string, unknown>)
				: {};
	} catch {
		return {};
	}

	// First non-empty value across candidate keys (underscore stored form first,
	// dotted OTel form as fallback).
	const str = (...keys: string[]): string | undefined => {
		for (const k of keys) {
			const v = attrs[k];
			if (typeof v === "string" && v !== "") return v;
		}
		return undefined;
	};
	const num = (...keys: string[]): number | undefined => {
		for (const k of keys) {
			const n = toFiniteNumber(attrs[k]);
			if (n !== undefined) return n;
		}
		return undefined;
	};

	const inputTokens = num(
		"gen_ai_usage_input_tokens",
		"gen_ai.usage.input_tokens",
	);
	const outputTokens = num(
		"gen_ai_usage_output_tokens",
		"gen_ai.usage.output_tokens",
	);
	const totalTokens =
		num("gen_ai_usage_total_tokens", "gen_ai.usage.total_tokens") ??
		(inputTokens !== undefined && outputTokens !== undefined
			? inputTokens + outputTokens
			: undefined);

	const summary: GenAiSummary = {
		system: str(
			"gen_ai_system",
			"gen_ai.system",
			"gen_ai_provider_name",
			"gen_ai.provider.name",
		),
		model: str(
			"gen_ai_response_model",
			"gen_ai.response.model",
			"gen_ai_request_model",
			"gen_ai.request.model",
		),
		operation: str("gen_ai_operation_name", "gen_ai.operation.name"),
		inputTokens,
		outputTokens,
		totalTokens,
	};
	// Only attach `cost` when a real stored value exists — absent stays absent
	// (no fabricated 0). Kept off the object literal so `"cost" in summary` is
	// false when there is no cost, matching the token fields' contract.
	const cost = num("gen_ai_usage_cost", "gen_ai.usage.cost");
	if (cost !== undefined) summary.cost = cost;
	return summary;
}

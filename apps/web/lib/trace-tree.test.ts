import type { Span } from "@/components/trace-viewer/types";
import { describe, expect, it } from "vitest";
import {
	type SpanTreeNode,
	buildSpanTree,
	collapsibleIds,
	computeVisibleRows,
	extractGenAi,
	flattenVisible,
	isErrorSpan,
	matchesQuery,
} from "./trace-tree";

/** Minimal span factory — only set what a test cares about. */
function span(p: Partial<Span> & { span_id: string }): Span {
	return {
		span_id: p.span_id,
		parent_span_id: p.parent_span_id ?? null,
		name: p.name ?? p.span_id,
		start_time: p.start_time ?? "2026-06-19T00:00:00.000Z",
		end_time: p.end_time ?? "2026-06-19T00:00:01.000Z",
		duration_us: p.duration_us ?? 1000,
		status_code: p.status_code ?? 1,
		status_message: p.status_message ?? "",
		attributes: p.attributes ?? "{}",
		aft_ids: p.aft_ids ?? [],
		intervention: p.intervention ?? 0,
	};
}

const J = (o: unknown) => JSON.stringify(o);

describe("computeVisibleRows — errorsOnly filter", () => {
	// root → [errNode → leaf(error)], and an ok sibling subtree that must vanish.
	const tree = [
		span({ span_id: "root" }),
		span({ span_id: "ok-branch", parent_span_id: "root" }),
		span({ span_id: "ok-leaf", parent_span_id: "ok-branch" }),
		span({ span_id: "err-branch", parent_span_id: "root" }),
		span({ span_id: "err-leaf", parent_span_id: "err-branch", status_code: 2 }),
	];

	it("reveals only error spans and the ancestor path down to them", () => {
		const ids = computeVisibleRows(tree, {
			collapsed: new Set(),
			query: "",
			errorsOnly: true,
		}).map((r) => r.span.span_id);
		expect(ids).toContain("err-leaf");
		expect(ids).toContain("err-branch"); // ancestor revealed
		expect(ids).toContain("root"); // ancestor revealed
		expect(ids).not.toContain("ok-branch"); // ok subtree hidden
		expect(ids).not.toContain("ok-leaf");
	});

	it("returns nothing when the trace has no error spans", () => {
		const clean = tree.filter((s) => s.status_code !== 2);
		const rows = computeVisibleRows(clean, {
			collapsed: new Set(),
			query: "",
			errorsOnly: true,
		});
		expect(rows).toHaveLength(0);
	});

	it("errorsOnly composes with search (both predicates apply)", () => {
		const withErr = [
			span({ span_id: "root" }),
			span({ span_id: "err-a", parent_span_id: "root", status_code: 2 }),
			span({ span_id: "keep-me", parent_span_id: "root", status_code: 2 }),
		];
		const ids = computeVisibleRows(withErr, {
			collapsed: new Set(),
			query: "keep",
			errorsOnly: true,
		}).map((r) => r.span.span_id);
		expect(ids).toContain("keep-me");
		expect(ids).not.toContain("err-a"); // error, but doesn't match the query
	});

	it("isErrorSpan is exactly status_code === 2", () => {
		expect(isErrorSpan(span({ span_id: "x", status_code: 2 }))).toBe(true);
		expect(isErrorSpan(span({ span_id: "y", status_code: 1 }))).toBe(false);
		expect(isErrorSpan(span({ span_id: "z", status_code: 0 }))).toBe(false);
	});
});

describe("buildSpanTree — hierarchy reconstruction", () => {
	it("nests children under their parent by parent_span_id", () => {
		const spans = [
			span({ span_id: "root" }),
			span({ span_id: "child", parent_span_id: "root" }),
			span({ span_id: "grandchild", parent_span_id: "child" }),
		];
		const tree = buildSpanTree(spans);
		expect(tree).toHaveLength(1);
		expect(tree[0]?.span.span_id).toBe("root");
		expect(tree[0]?.depth).toBe(0);
		expect(tree[0]?.children[0]?.span.span_id).toBe("child");
		expect(tree[0]?.children[0]?.depth).toBe(1);
		expect(tree[0]?.children[0]?.children[0]?.span.span_id).toBe("grandchild");
		expect(tree[0]?.children[0]?.children[0]?.depth).toBe(2);
	});

	it("treats a null parent and an orphan (parent outside the set) as roots", () => {
		const spans = [
			span({ span_id: "a" }), // null parent → root
			span({ span_id: "b", parent_span_id: "missing" }), // dangling parent → root
		];
		const tree = buildSpanTree(spans);
		expect(tree.map((n) => n.span.span_id).sort()).toEqual(["a", "b"]);
		expect(tree.every((n) => n.depth === 0)).toBe(true);
	});

	it("orders siblings chronologically, span_id as tiebreak", () => {
		const spans = [
			span({ span_id: "root" }),
			span({
				span_id: "late",
				parent_span_id: "root",
				start_time: "2026-06-19T00:00:05.000Z",
			}),
			span({
				span_id: "early",
				parent_span_id: "root",
				start_time: "2026-06-19T00:00:01.000Z",
			}),
		];
		const kids = buildSpanTree(spans)[0]?.children.map((c) => c.span.span_id);
		expect(kids).toEqual(["early", "late"]);
	});

	it("does not drop spans caught in a parentless cycle", () => {
		// a → b → a, neither has an external root.
		const spans = [
			span({ span_id: "a", parent_span_id: "b" }),
			span({ span_id: "b", parent_span_id: "a" }),
		];
		const ids = flattenVisible(buildSpanTree(spans), new Set()).map(
			(r) => r.span.span_id,
		);
		expect(ids.sort()).toEqual(["a", "b"]);
	});

	it("ignores a self-referential parent", () => {
		const tree = buildSpanTree([span({ span_id: "x", parent_span_id: "x" })]);
		expect(tree).toHaveLength(1);
		expect(tree[0]?.children).toHaveLength(0);
	});
});

describe("deep traces — explicit-stack walks never overflow", () => {
	// A degenerate 10K-span single-parent chain: s0 ← s1 ← s2 ← … ← s9999.
	// The previous recursive buildSpanTree / flattenVisible / computeVisibleRows
	// walks recursed once per level and blew the call stack here.
	const N = 10_000;
	function deepChain(): Span[] {
		const spans: Span[] = [];
		for (let i = 0; i < N; i++) {
			spans.push(
				span({
					span_id: `s${i}`,
					parent_span_id: i === 0 ? null : `s${i - 1}`,
				}),
			);
		}
		return spans;
	}

	it("buildSpanTree builds a 10K-deep chain without a stack overflow", () => {
		const tree = buildSpanTree(deepChain());
		expect(tree).toHaveLength(1); // single root
		// Descend iteratively to the deepest node; the chain must be N deep.
		let node: SpanTreeNode | undefined = tree[0];
		let depth = 0;
		while (node) {
			expect(node.depth).toBe(depth);
			depth++;
			node = node.children[0];
		}
		expect(depth).toBe(N);
	});

	it("flattenVisible renders all 10K rows without a stack overflow", () => {
		const rows = flattenVisible(buildSpanTree(deepChain()), new Set());
		expect(rows).toHaveLength(N);
		expect(rows[0]?.depth).toBe(0);
		expect(rows[N - 1]?.depth).toBe(N - 1);
	});

	it("computeVisibleRows handles a 10K-deep trace for no-query and search", () => {
		const spans = deepChain();
		const all = computeVisibleRows(spans, { collapsed: new Set(), query: "" });
		expect(all).toHaveLength(N);
		// Searching the deepest span reveals its full ancestor path (all N rows).
		const search = computeVisibleRows(spans, {
			collapsed: new Set(),
			query: `s${N - 1}`,
		});
		expect(search).toHaveLength(N);
		expect(search[N - 1]?.span.span_id).toBe(`s${N - 1}`);
	});
});

describe("flattenVisible — collapse-aware flatten", () => {
	const spans = [
		span({ span_id: "root" }),
		span({ span_id: "child", parent_span_id: "root" }),
		span({ span_id: "leaf", parent_span_id: "child" }),
	];

	it("emits every node when nothing is collapsed", () => {
		const rows = flattenVisible(buildSpanTree(spans), new Set());
		expect(rows.map((r) => r.span.span_id)).toEqual(["root", "child", "leaf"]);
		expect(rows[0]?.hasChildren).toBe(true);
		expect(rows[2]?.hasChildren).toBe(false);
	});

	it("hides descendants of a collapsed node but keeps the node itself", () => {
		const rows = flattenVisible(buildSpanTree(spans), new Set(["child"]));
		expect(rows.map((r) => r.span.span_id)).toEqual(["root", "child"]);
		expect(rows.find((r) => r.span.span_id === "child")?.collapsed).toBe(true);
	});
});

describe("matchesQuery", () => {
	const s = span({
		span_id: "abc123",
		name: "llm.chat",
		attributes: J({ "gen_ai.request.model": "claude-sonnet-4-6" }),
	});

	it("empty query matches everything", () => {
		expect(matchesQuery(s, "")).toBe(true);
		expect(matchesQuery(s, "   ")).toBe(true);
	});
	it("matches on name, id, and model, case-insensitively", () => {
		expect(matchesQuery(s, "CHAT")).toBe(true);
		expect(matchesQuery(s, "abc1")).toBe(true);
		expect(matchesQuery(s, "sonnet")).toBe(true);
	});
	it("does not match unrelated text", () => {
		expect(matchesQuery(s, "retrieval")).toBe(false);
	});
});

describe("computeVisibleRows — search reveals matches + ancestors", () => {
	const spans = [
		span({ span_id: "root", name: "agent.run" }),
		span({ span_id: "mid", parent_span_id: "root", name: "llm.chat" }),
		span({ span_id: "hit", parent_span_id: "mid", name: "tool.search" }),
		span({ span_id: "other", parent_span_id: "root", name: "llm.embed" }),
	];

	it("no query honors collapsed state", () => {
		const rows = computeVisibleRows(spans, {
			collapsed: new Set(["mid"]),
			query: "",
		});
		expect(rows.map((r) => r.span.span_id)).toEqual(["root", "mid", "other"]);
	});

	it("query keeps only the match plus its ancestor path, force-expanded", () => {
		const rows = computeVisibleRows(spans, {
			collapsed: new Set(["mid", "root"]), // collapse is ignored during search
			query: "tool.search",
		});
		expect(rows.map((r) => r.span.span_id)).toEqual(["root", "mid", "hit"]);
		expect(rows.every((r) => r.collapsed === false)).toBe(true);
		// "other" is not on the path to the match → hidden
		expect(rows.find((r) => r.span.span_id === "other")).toBeUndefined();
	});
});

describe("collapsibleIds", () => {
	it("returns only spans that have children", () => {
		const spans = [
			span({ span_id: "root" }),
			span({ span_id: "child", parent_span_id: "root" }),
			span({ span_id: "leaf", parent_span_id: "child" }),
		];
		expect(collapsibleIds(spans).sort()).toEqual(["child", "root"]);
	});
});

describe("extractGenAi — underscore-stored form + dotted fallback, real cost", () => {
	it("pulls model, tokens, and derives a real total", () => {
		const g = extractGenAi(
			J({
				"gen_ai.system": "openai",
				"gen_ai.request.model": "gpt-4o",
				"gen_ai.operation.name": "chat",
				"gen_ai.usage.input_tokens": 120,
				"gen_ai.usage.output_tokens": 64,
			}),
		);
		expect(g).toMatchObject({
			system: "openai",
			model: "gpt-4o",
			operation: "chat",
			inputTokens: 120,
			outputTokens: 64,
			totalTokens: 184,
		});
	});

	it("prefers response.model and provider.name fallbacks", () => {
		const g = extractGenAi(
			J({
				"gen_ai.provider.name": "anthropic",
				"gen_ai.response.model": "claude-sonnet-4-6",
			}),
		);
		expect(g.system).toBe("anthropic");
		expect(g.model).toBe("claude-sonnet-4-6");
	});

	it("honors an explicit total_tokens over the sum", () => {
		const g = extractGenAi(
			J({
				"gen_ai.usage.input_tokens": 10,
				"gen_ai.usage.output_tokens": 20,
				"gen_ai.usage.total_tokens": 99,
			}),
		);
		expect(g.totalTokens).toBe(99);
	});

	it("omits tokens entirely when absent (never fabricates a 0)", () => {
		const g = extractGenAi(J({ "gen_ai.request.model": "gpt-4o" }));
		expect(g.inputTokens).toBeUndefined();
		expect(g.outputTokens).toBeUndefined();
		expect(g.totalTokens).toBeUndefined();
	});

	it("coerces stringified token counts", () => {
		const g = extractGenAi(
			J({
				"gen_ai.usage.input_tokens": "42",
				"gen_ai.usage.output_tokens": "8",
			}),
		);
		expect(g.inputTokens).toBe(42);
		expect(g.totalTokens).toBe(50);
	});

	it("returns {} on unparseable attributes", () => {
		expect(extractGenAi("not json")).toEqual({});
	});

	it("reads the underscore-flattened stored form (ADR-043)", () => {
		// Real spans store gen_ai_* underscore keys (ingest normalises OTLP).
		const g = extractGenAi(
			J({
				gen_ai_system: "anthropic",
				gen_ai_request_model: "claude-sonnet-4-6",
				gen_ai_operation_name: "chat",
				gen_ai_usage_input_tokens: 1000,
				gen_ai_usage_output_tokens: 500,
				gen_ai_usage_cost: 0.0105,
			}),
		);
		expect(g).toMatchObject({
			system: "anthropic",
			model: "claude-sonnet-4-6",
			operation: "chat",
			inputTokens: 1000,
			outputTokens: 500,
			totalTokens: 1500,
			cost: 0.0105,
		});
	});

	it("emits the real stored cost when present (underscore or dotted key)", () => {
		expect(extractGenAi(J({ gen_ai_usage_cost: 0.42 })).cost).toBe(0.42);
		expect(extractGenAi(J({ "gen_ai.usage.cost": 0.42 })).cost).toBe(0.42);
	});

	it("omits cost when absent — never a fabricated 0", () => {
		const g = extractGenAi(J({ gen_ai_usage_input_tokens: 100 }));
		expect("cost" in g).toBe(false);
		expect(g.cost).toBeUndefined();
	});
});

import { type SpanNode, TranscriptSpine } from "@tracelanedev/ui";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

/**
 * Rendered-shape tests for the transcript spine. renderToStaticMarkup produces a
 * static HTML string in the node env (no jsdom/browser needed), so we assert the
 * real DOM the viewer emits — ARIA tree roles, indentation, disclosures, and that
 * flat mode is byte-for-byte the original narrative (parity).
 */

const h = createElement;
const noop = () => {};

const render = (spans: SpanNode[]): string =>
	renderToStaticMarkup(
		h(TranscriptSpine, { spans, onSelectSpan: noop, onToggleCollapse: noop }),
	);

describe("TranscriptSpine — flat mode parity", () => {
	const flat: SpanNode[] = [
		{
			id: "a",
			name: "agent.run",
			kind: "agent",
			durationMs: 100,
			status: "ok",
		},
		{
			id: "b",
			name: "llm.chat",
			kind: "llm",
			durationMs: 50,
			status: "error",
		},
	];

	it("renders a plain list, NOT an ARIA tree, when no hierarchy is supplied", () => {
		const html = render(flat);
		expect(html).not.toContain('role="tree"');
		expect(html).not.toContain('role="treeitem"');
		// no disclosure triangles in the flat narrative
		expect(html).not.toContain("▼");
		expect(html).not.toContain("▶");
	});

	it("preserves the existing visuals: names, error ring, latency bars", () => {
		const html = render(flat);
		expect(html).toContain("agent.run");
		expect(html).toContain("llm.chat");
		expect(html).toContain("ring-danger"); // error node ringed red
		expect(html).toContain("width:100%"); // longest span fills the bar
		expect(html).toContain("width:50%");
	});

	it("renders the seen-before signal when a signature matches", () => {
		const html = render([
			{
				id: "s",
				name: "tool.call",
				kind: "tool",
				durationMs: 10,
				status: "ok",
				signature: { count: 2, label: "Tool-definition drift" },
			},
		]);
		expect(html).toContain("SEEN 2×");
		expect(html).toContain("Tool-definition drift");
	});
});

describe("TranscriptSpine — tree mode (hierarchy supplied)", () => {
	const tree: SpanNode[] = [
		{
			id: "root",
			name: "agent.run",
			kind: "agent",
			durationMs: 100,
			status: "ok",
			depth: 0,
			hasChildren: true,
			collapsed: false,
		},
		{
			id: "child",
			name: "llm.chat",
			kind: "llm",
			durationMs: 40,
			status: "ok",
			depth: 1,
			hasChildren: false,
		},
	];

	it("emits ARIA tree roles with levels and expanded state", () => {
		const html = render(tree);
		expect(html).toContain('role="tree"');
		expect(html).toContain('role="treeitem"');
		expect(html).toContain('aria-level="1"');
		expect(html).toContain('aria-level="2"');
		expect(html).toContain('aria-expanded="true"');
	});

	it("indents children by depth and shows an expand/collapse disclosure", () => {
		const html = render(tree);
		expect(html).toContain("margin-left:16px"); // depth 1 → 16px
		expect(html).toContain("▼"); // expanded parent
		expect(html).toContain('aria-label="Collapse span"');
	});

	it("a collapsed parent flips the disclosure + aria-expanded", () => {
		const collapsed: SpanNode[] = [
			{
				id: "root",
				name: "agent.run",
				kind: "agent",
				durationMs: 100,
				status: "ok",
				depth: 0,
				hasChildren: true,
				collapsed: true,
			},
		];
		const html = render(collapsed);
		expect(html).toContain('aria-expanded="false"');
		expect(html).toContain("▶");
		expect(html).toContain('aria-label="Expand span"');
	});
});

describe("TranscriptSpine — 10-span render proof (full visual language)", () => {
	// A realistic agent run: 10 spans, 3 levels deep, every span-kind, one error,
	// one matched failure signature. This proves the WHOLE the design-system spec
	// §3.1/§3.2 visual language renders for a non-trivial trace — not just that a
	// proof" rule applied to the viewer: assert the rendered shape, not reachability).
	const TEN_SPANS: SpanNode[] = [
		{
			id: "1",
			name: "agent.run",
			kind: "agent",
			durationMs: 1200,
			status: "ok",
			depth: 0,
			hasChildren: true,
		},
		{
			id: "2",
			name: "llm.plan",
			kind: "llm",
			durationMs: 300,
			status: "ok",
			depth: 1,
			hasChildren: true,
		},
		{
			id: "3",
			name: "llm.chat",
			kind: "llm",
			durationMs: 250,
			status: "ok",
			depth: 2,
		},
		{
			id: "4",
			name: "tool.search",
			kind: "tool",
			durationMs: 400,
			status: "ok",
			depth: 1,
			hasChildren: true,
		},
		{
			id: "5",
			name: "retrieval.embed",
			kind: "retrieval",
			durationMs: 80,
			status: "ok",
			depth: 2,
		},
		{
			id: "6",
			name: "retrieval.vector_query",
			kind: "retrieval",
			durationMs: 120,
			status: "ok",
			depth: 2,
			signature: {
				count: 3,
				label: "Tool-definition drift",
				href: "/signatures",
			},
		},
		{
			id: "7",
			name: "tool.write_file",
			kind: "tool",
			durationMs: 60,
			status: "error",
			depth: 1,
		},
		{
			id: "8",
			name: "mcp.invoke",
			kind: "tool",
			durationMs: 500,
			status: "ok",
			depth: 1,
			hasChildren: true,
		},
		{
			id: "9",
			name: "llm.summarize",
			kind: "llm",
			durationMs: 200,
			status: "ok",
			depth: 2,
		},
		{
			id: "10",
			name: "agent.finalize",
			kind: "unknown",
			durationMs: 40,
			status: "ok",
			depth: 1,
		},
	];

	const count = (html: string, needle: string): number =>
		html.split(needle).length - 1;

	it("renders all 10 spans as ARIA tree items across 3 levels", () => {
		const html = render(TEN_SPANS);
		expect(html).toContain('role="tree"');
		expect(count(html, 'role="treeitem"')).toBe(10);
		// depth 0/1/2 → aria-level 1/2/3 (the three nesting levels are all present)
		expect(html).toContain('aria-level="1"');
		expect(html).toContain('aria-level="2"');
		expect(html).toContain('aria-level="3"');
	});

	it("color-codes every span kind from the design tokens (never hardcoded hex)", () => {
		const html = render(TEN_SPANS);
		// ADR-053 discipline: Lava (--accent) is CTA-only and Verify-green
		// (--ok/--seal) is provenance-only, so span kinds use the one free data
		// hue (violet --info: tool bold, llm faint) + neutral ink for structure.
		expect(html).toContain("bg-ink-2"); // agent → neutral (structure)
		expect(html).toContain("bg-info/50"); // llm → faint violet (AI-call family)
		expect(html).toContain("bg-info"); // tool → violet (the trajectory)
		expect(html).toContain("bg-ink-3"); // retrieval / unknown → muted
		// Lava and Verify-green must NOT be used as a decorative span-kind fill.
		expect(html).not.toContain("bg-accent-ink");
		expect(html).not.toContain("bg-ok");
		// no raw hex leaked into the markup (tokens-only rule, CLAUDE.md)
		expect(html).not.toMatch(/#[0-9a-fA-F]{6}/);
	});

	it("rings the error span red and flags error-inside at the top", () => {
		const html = render(TEN_SPANS);
		expect(html).toContain("ring-danger"); // tool.write_file errored
		expect(html).toContain("▲ error inside"); // propagation badge
		expect(html).toContain("tool.write_file");
	});

	it("draws a NEUTRAL 2px rail by default — never green ungated (honesty lock)", () => {
		// render() supplies no `verified`, matching live TraceDetailView. The rail
		// must NOT be Verify-green without a real chain verdict — a green provenance
		// thread on an unverified trace is the per-trace-verified overclaim.
		const html = render(TEN_SPANS);
		expect(html).toContain("border-l-2");
		expect(html).toContain("border-line-2");
		expect(html).not.toContain("border-seal");
	});

	it("renders the inline seen-before glow on the matched signature", () => {
		const html = render(TEN_SPANS);
		expect(html).toContain("SEEN 3×");
		expect(html).toContain("Tool-definition drift");
		expect(html).toContain("View signature →");
	});

	it("scales latency bars to the longest span (1200ms → 100%)", () => {
		const html = render(TEN_SPANS);
		expect(html).toContain("width:100%"); // agent.run, the max
		expect(html).toContain("width:25%"); // llm.plan 300/1200
	});

	it("renders the names top-to-bottom as a narrative", () => {
		const html = render(TEN_SPANS);
		for (const name of [
			"agent.run",
			"llm.chat",
			"tool.search",
			"mcp.invoke",
			"agent.finalize",
		]) {
			expect(html).toContain(name);
		}
	});

	// reflects the `verified` prop. The per-tenant audit chain (audit_log) is NOT
	// per-trace, so live TraceDetailView omits `verified` (no chip) rather than
	// fabricate per-trace integrity — these tests prove the component renders each
	// state correctly when a real verify result IS supplied (e.g. the Audit page).
	const renderVerified = (verified: boolean | undefined): string =>
		renderToStaticMarkup(
			h(TranscriptSpine, {
				spans: TEN_SPANS,
				verified,
				onSelectSpan: noop,
				onToggleCollapse: noop,
			}),
		);

	it("shows 'Verified · chain ✓' AND the green rail ONLY when verified=true", () => {
		const html = renderVerified(true);
		expect(html).toContain("Verified · chain ✓");
		// the Verify-green provenance rail is earned only by a true verdict
		expect(html).toContain("border-seal");
	});

	it("shows 'Chain unverified' and a NEUTRAL rail when verified=false", () => {
		const html = renderVerified(false);
		expect(html).toContain("Chain unverified");
		expect(html).not.toContain("Verified · chain ✓");
		expect(html).toContain("border-line-2");
		expect(html).not.toContain("border-seal");
	});

	it("shows NO provenance chip when verified is omitted (honest default — no fabricated claim)", () => {
		const html = renderVerified(undefined);
		expect(html).not.toContain("Verified · chain ✓");
		expect(html).not.toContain("Chain unverified");
	});
});

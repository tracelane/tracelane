// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, expect, it, vi } from "vitest";
vi.mock("@/lib/auth", () => ({ requireGatewayToken: vi.fn() }));
vi.mock("@/lib/gateway", async (original) => ({
	...(await original<typeof import("@/lib/gateway")>()),
	gatewayGet: vi.fn(),
}));
import { gatewayGet } from "@/lib/gateway";
import Compare from "./compare/page";
import Page from "./page";
afterEach(cleanup);
const arm = (id: string) => ({
	arm_id: id,
	arm_label: id,
	ordinal: 0,
	eval_run_id: `run-${id}`,
	prompt_version_id: "prompt",
	model: "model",
	status: "passed",
	pass_rate: 100,
	passed: 2,
	failed: 0,
	errored: 0,
	mean_score: 1,
	p95_latency_ms: 320,
	total_cost_usd: 0.03,
	unpriced_items: 0,
	items_run: 2,
	items_matched: 2,
});
const side = (score: number | null, latency: number, cost: number | null) => ({
	case_name: "Case",
	status: "passed",
	score,
	latency_ms: latency,
	cost_usd: cost,
	output: "hello",
	output_truncated: false,
	error: null,
});
const row = (id: string, verdict: string) => ({
	dataset_item_id: id,
	item_ordinal: 0,
	label: id,
	a: side(1, 120, 0.01),
	b: side(verdict === "regressed" ? 0.5 : 1, 320, 0.02),
	delta_score: verdict === "regressed" ? -0.5 : 0,
	delta_latency_ms: 200,
	delta_latency_pct: 166.7,
	delta_cost_usd: 0.01,
	delta_cost_pct: 100,
	latency_slower: true,
	latency_faster: false,
	cost_higher: true,
	cost_lower: false,
	verdict,
});
const fixture = (rows: unknown[]) => ({
	experiment_id: "exp",
	name: "Comparison",
	dataset_id: "dataset",
	snapshot_id: "snapshot",
	item_count: 2,
	a: arm("a"),
	b: arm("b"),
	rows,
	summary: "Compare candidate with baseline",
	thresholds: {
		score_delta_min: 0.1,
		latency_delta_min_ms: 10,
		latency_delta_min_pct: 5,
		cost_delta_min_usd: 0.001,
		cost_delta_min_pct: 5,
	},
	regressed_count: 1,
	improved_count: 0,
	unchanged_count: 1,
	unknown_count: 0,
	only_in_a: 0,
	only_in_b: 0,
});
it("offers all finished runs as a baseline and candidate", async () => {
	vi.mocked(gatewayGet).mockResolvedValue({
		name: "Experiment",
		dataset_id: "dataset",
		snapshot_id: "snapshot",
		created_at_ms: 0,
		item_count: 2,
		arms: [arm("a"), arm("b"), arm("c")],
		comparable: true,
	});
	render(await Page({ params: Promise.resolve({ experimentId: "exp" }) }));
	fireEvent.change(screen.getByLabelText("Baseline run"), {
		target: { value: "c" },
	});
	fireEvent.change(screen.getByLabelText("Candidate run"), {
		target: { value: "a" },
	});
	expect(
		screen.getByRole("link", { name: "Compare runs" }).getAttribute("href"),
	).toBe("/experiments/exp/compare?a=c&b=a");
});
it("renders the gateway regression first with both measured sides", async () => {
	vi.mocked(gatewayGet).mockResolvedValue(
		fixture([row("Regression", "regressed"), row("Stable", "unchanged")]),
	);
	const html = renderToStaticMarkup(
		await Compare({
			params: Promise.resolve({ experimentId: "exp" }),
			searchParams: Promise.resolve({ a: "a", b: "b" }),
		}),
	);
	expect(html.indexOf("Regression")).toBeLessThan(html.indexOf("Stable"));
	for (const s of [
		"worse",
		"120.0ms",
		"320.0ms",
		"$0.0100",
		"$0.0200",
		"Baseline",
		"Candidate",
	])
		expect(html).toContain(s);
});
it("identical run values stay unchanged and unknown costs never become zero", async () => {
	const r = row("Identical", "unchanged");
	r.b = r.a;
	r.a.cost_usd = null;
	r.delta_cost_usd = null as never;
	r.delta_cost_pct = null as never;
	r.delta_latency_ms = 0;
	r.delta_latency_pct = 0;
	r.latency_slower = false;
	r.cost_higher = false;
	vi.mocked(gatewayGet).mockResolvedValue(fixture([r]));
	const html = renderToStaticMarkup(
		await Compare({
			params: Promise.resolve({ experimentId: "exp" }),
			searchParams: Promise.resolve({ a: "a", b: "b" }),
		}),
	);
	expect(html).toContain("· unchanged");
	expect(html).not.toContain("$0.0000");
});
it("refuses comparing a run with itself and excludes running arms", async () => {
	vi.mocked(gatewayGet).mockResolvedValue({
		name: "Experiment",
		dataset_id: "dataset",
		snapshot_id: "snapshot",
		created_at_ms: 0,
		item_count: 2,
		arms: [arm("a"), arm("b"), { ...arm("running"), status: "running" }],
		comparable: false,
	});
	render(await Page({ params: Promise.resolve({ experimentId: "exp" }) }));
	expect(screen.queryByRole("option", { name: /run-running/ })).toBeNull();
	fireEvent.change(screen.getByLabelText("Candidate run"), {
		target: { value: "a" },
	});
	expect(screen.queryByRole("link", { name: "Compare runs" })).toBeNull();
	expect(screen.getByText("Choose two different runs.")).toBeTruthy();
});

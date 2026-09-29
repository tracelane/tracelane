import { renderToStaticMarkup } from "react-dom/server";
import { expect, it, vi } from "vitest";
vi.mock("@/lib/auth", () => ({ requireGatewayToken: vi.fn() }));
vi.mock("@/lib/gateway", async (original) => ({
	...(await original<typeof import("@/lib/gateway")>()),
	gatewayGet: vi.fn(),
}));
import Page from "@/app/experiments/[experimentId]/compare/page";
import { gatewayGet } from "@/lib/gateway";
it("renders malformed judge output as errored with no score", async () => {
	const arm = {
		arm_id: "a",
		arm_label: "Judge",
		model: "model",
		status: "errored",
		items_run: 1,
		items_matched: 1,
		pass_rate: null,
		mean_score: null,
		p95_latency_ms: null,
		total_cost_usd: 0.01,
		unpriced_items: 0,
		errored: 1,
	};
	const side = {
		case_name: "Case",
		status: "errored",
		score: null,
		latency_ms: 123,
		cost_usd: 0.01,
		output: "",
		output_truncated: false,
		error: "Judge output failed schema validation",
	};
	vi.mocked(gatewayGet).mockResolvedValue({
		name: "Judge comparison",
		dataset_id: "dataset",
		snapshot_id: "snapshot",
		item_count: 1,
		a: arm,
		b: { ...arm, arm_id: "b" },
		summary: "Cannot score malformed judge output",
		thresholds: {
			score_delta_min: 0.1,
			latency_delta_min_ms: 10,
			latency_delta_min_pct: 5,
		},
		rows: [
			{
				dataset_item_id: "item",
				item_ordinal: 0,
				label: "Case",
				a: side,
				b: side,
				delta_score: null,
				delta_latency_ms: null,
				delta_latency_pct: null,
				delta_cost_usd: null,
				verdict: "unknown",
			},
		],
		regressed_count: 0,
		improved_count: 0,
		unchanged_count: 0,
		unknown_count: 1,
		only_in_a: 0,
		only_in_b: 0,
	});
	const html = renderToStaticMarkup(
		await Page({
			params: Promise.resolve({ experimentId: "exp" }),
			searchParams: Promise.resolve({ a: "a", b: "b" }),
		}),
	);
	expect(html).toContain("A errored: Judge output failed schema validation");
	expect(html).toContain("B errored: Judge output failed schema validation");
	expect(html).not.toContain(">0.00<");
	expect(html).toContain(">—</span>");
});

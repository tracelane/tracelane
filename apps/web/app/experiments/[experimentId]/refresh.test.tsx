import { renderToStaticMarkup } from "react-dom/server";
import { expect, it, vi } from "vitest";
vi.mock("@/lib/gateway", () => ({
	gatewayGet: async () => ({
		name: "In progress",
		dataset_id: "dataset",
		snapshot_id: "snapshot",
		item_count: 10,
		status: "running",
		created_at_ms: 1,
		arms: [],
	}),
	GatewayError: class extends Error {},
}));
import Page from "./page";
it("offers a real navigation that rereads this experiment without inventing progress", async () => {
	const html = renderToStaticMarkup(
		await Page({ params: Promise.resolve({ experimentId: "experiment" }) }),
	);
	expect(html).toContain('href="/experiments/experiment"');
	expect(html).toContain("Refresh results");
	expect(html).toContain("running");
});

import reference from "@/db/plans.v3.json";
vi.mock("@/lib/list-page-settings", async () => {
	const { default: source } = await import("@/db/plans.v3.json");
	return {
		getListPageSettings: async () => ({
			sizes: source.policy.web_list_page_sizes,
			defaulted: false,
		}),
	};
});
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, expect, it, vi } from "vitest";
const h = vi.hoisted(() => {
	class GatewayError extends Error {
		constructor(public status: number) {
			super(String(status));
		}
	}
	return { gatewayGet: vi.fn(), GatewayError };
});
vi.mock("@/lib/gateway", () => h);
vi.mock("@/components/experiments/NewExperimentDialog", () => ({
	NewExperimentDialog: () => <button type="button">New experiment</button>,
}));
import Page from "./page";
const row = (name: string) => ({
	experiment_id: name,
	name,
	dataset_id: "dataset",
	arms: 2,
	item_count: 4,
	status: "complete",
	created_at_ms: 1,
});
beforeEach(() => {
	h.gatewayGet.mockReset();
});
const render = async (cursor?: string) =>
	renderToStaticMarkup(
		await Page({ searchParams: Promise.resolve({ cursor }) }),
	);
function setup(experiments: unknown[], next_cursor: string | null) {
	h.gatewayGet.mockImplementation(async (path: string) =>
		path.startsWith("/v1/experiments?")
			? { experiments, next_cursor }
			: path.startsWith("/v1/datasets?")
				? { datasets: [] }
				: [],
	);
}
it("follows an opaque next cursor to the second page without losing its bytes", async () => {
	setup([row("First")], "opaque+/=cursor");
	const first = await render();
	expect(first).toContain('href="/experiments?cursor=opaque%2B%2F%3Dcursor"');
	setup([row("Second")], null);
	const second = await render("opaque+/=cursor");
	expect(h.gatewayGet).toHaveBeenCalledWith(
		`/v1/experiments?limit=${reference.policy.web_list_page_sizes.experiments}&cursor=opaque%2B%2F%3Dcursor`,
	);
	expect(second).toContain("Second");
	expect(second).toContain("First page");
	expect(second).not.toContain("Next page");
	expect(second).not.toContain("of 1");
	expect(second).toContain("Showing 1 on this page");
});
it("distinguishes a later empty page from a workspace with no experiments", async () => {
	setup([], null);
	const html = await render("later");
	expect(html).toContain("No experiments on this page");
	expect(html).toContain("First page");
	expect(html).not.toContain("No experiments yet");
});
it("has no next control when the initial page is final", async () => {
	setup([], null);
	const html = await render();
	expect(html).toContain("No experiments yet");
	expect(html).not.toContain("Next page");
});
it("offers a retry of the failed cursor without rendering empty data", async () => {
	h.gatewayGet.mockRejectedValue(new h.GatewayError(503));
	const html = await render("later");
	expect(html).toContain("Couldn&#x27;t load experiments");
	expect(html).toContain('href="/experiments?cursor=later"');
	expect(html).toContain("First page");
	expect(html).not.toContain("No experiments yet");
});

vi.mock("@/lib/auth", () => ({
	requireGatewayToken: vi.fn(),
	requireSession: async () => ({ role: "owner" }),
	canAdmin: (role: string) => role === "owner",
}));
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
vi.mock("./DatasetAction", () => ({
	DatasetAction: () => <button type="button">New dataset</button>,
}));
import Page from "./page";
const row = (name: string) => ({
	dataset_id: name,
	name,
	description: "",
	items: null,
	with_reference: null,
	from_traces: null,
	created_at_ms: 1,
});
beforeEach(() => {
	h.gatewayGet.mockReset();
});
const render = async (cursor?: string) =>
	renderToStaticMarkup(
		await Page({ searchParams: Promise.resolve({ cursor }) }),
	);
it("follows the encoded cursor and preserves unknown item counts", async () => {
	h.gatewayGet.mockResolvedValue({
		datasets: [row("First")],
		next_cursor: "opaque+/=cursor",
		total: null,
	});
	expect(await render()).toContain(
		'href="/datasets?cursor=opaque%2B%2F%3Dcursor"',
	);
	h.gatewayGet.mockResolvedValue({
		datasets: [row("Second")],
		next_cursor: null,
		total: null,
	});
	const html = await render("opaque+/=cursor");
	expect(h.gatewayGet).toHaveBeenLastCalledWith(
		`/v1/datasets?limit=${reference.policy.web_list_page_sizes.datasets}&cursor=opaque%2B%2F%3Dcursor`,
	);
	expect(html).toContain("Second");
	expect(html).toContain("—");
	expect(html).toContain("Showing 1 on this page");
	expect(html).not.toContain("of 1");
	expect(html).toContain("First page");
	expect(html).not.toContain("Next page");
});
it("offers recovery on a valid cursor that reaches an empty final page", async () => {
	h.gatewayGet.mockResolvedValue({
		datasets: [],
		next_cursor: null,
		total: 100,
	});
	const html = await render("last");
	expect(html).toContain("No datasets on this page");
	expect(html).toContain("First page");
	expect(html).not.toContain("No datasets yet");
});
it("retains the current cursor on read failure", async () => {
	h.gatewayGet.mockRejectedValue(new h.GatewayError(503));
	const html = await render("later");
	expect(html).toContain("Couldn&#x27;t load datasets");
	expect(html).toContain('href="/datasets?cursor=later"');
	expect(html).toContain("First page");
	expect(html).not.toContain("No datasets yet");
});

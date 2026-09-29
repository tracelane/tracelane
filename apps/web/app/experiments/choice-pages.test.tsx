import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, expect, it, vi } from "vitest";
const h = vi.hoisted(() => ({
	gatewayGet: vi.fn(),
	dialog: vi.fn(),
	settings: {
		sizes: { experiments: 37, datasets: 42, experiment_datasets: 13 },
		defaulted: false,
	},
}));
vi.mock("@/lib/auth", () => ({
	requireSession: async () => ({ role: "owner", userId: "test-owner" }),
	canAdmin: (role: string) => role === "owner",
}));
vi.mock("next/navigation", () => ({
	useRouter: () => ({ refresh: vi.fn(), push: vi.fn() }),
}));
vi.mock("@/lib/gateway", () => ({
	gatewayGet: h.gatewayGet,
	GatewayError: class extends Error {},
}));
vi.mock("@/lib/list-page-settings", () => ({
	getListPageSettings: async () => h.settings,
}));
vi.mock("@/components/experiments/NewExperimentDialog", () => ({
	NewExperimentDialog: (props: unknown) => {
		h.dialog(props);
		return <button type="button">New experiment</button>;
	},
}));
vi.mock("@/app/datasets/DatasetAction", () => ({ DatasetAction: () => null }));
import DatasetsPage from "../datasets/page";
import ExperimentsPage from "./page";
beforeEach(() => {
	h.gatewayGet.mockReset();
	h.dialog.mockReset();
	h.settings.defaulted = false;
	h.gatewayGet.mockImplementation(async (path: string) =>
		path.startsWith("/v1/experiments?")
			? { experiments: [], next_cursor: "exp-next" }
			: path.startsWith("/v1/datasets?")
				? {
						datasets: [
							{
								dataset_id: "choice",
								name: "Choice",
								items: 1,
								created_at_ms: 1,
								with_reference: null,
								from_traces: null,
							},
						],
						next_cursor: "choice+/=",
					}
				: [{ name: "prompt", active: [] }],
	);
});
it("reads all three page sizes from reference settings", async () => {
	await ExperimentsPage({ searchParams: Promise.resolve({}) });
	await DatasetsPage({ searchParams: Promise.resolve({}) });
	expect(h.gatewayGet).toHaveBeenCalledWith("/v1/experiments?limit=37");
	expect(h.gatewayGet).toHaveBeenCalledWith("/v1/datasets?limit=13");
	expect(h.gatewayGet).toHaveBeenCalledWith("/v1/datasets?limit=42");
});
it("reveals selector overflow and preserves the experiment cursor", async () => {
	const html = renderToStaticMarkup(
		await ExperimentsPage({
			searchParams: Promise.resolve({ cursor: "exp+/=" }),
		}),
	);
	expect(html).toContain("Next dataset choices");
	expect(html).toContain("Dataset choices: 1 on this page");
	expect(html).toContain(
		'href="/experiments?cursor=exp%2B%2F%3D&amp;dataset_cursor=choice%2B%2F%3D"',
	);
});
it("follows a choice cursor, preserves it on experiment paging, and recovers from empty choices", async () => {
	h.gatewayGet.mockImplementation(async (path: string) =>
		path.startsWith("/v1/experiments?")
			? { experiments: [], next_cursor: "next-exp" }
			: path.startsWith("/v1/datasets?")
				? { datasets: [], next_cursor: null }
				: [],
	);
	const html = renderToStaticMarkup(
		await ExperimentsPage({
			searchParams: Promise.resolve({
				cursor: "exp",
				dataset_cursor: "choice+/=",
			}),
		}),
	);
	expect(h.gatewayGet).toHaveBeenCalledWith(
		"/v1/datasets?limit=13&cursor=choice%2B%2F%3D",
	);
	expect(html).toContain("First dataset choices");
	expect(html).toContain(
		'href="/experiments?cursor=next-exp&amp;dataset_cursor=choice%2B%2F%3D"',
	);
	expect(html).not.toContain("Create a dataset first");
});
it("discloses unavailable reference data without hiding rows", async () => {
	h.settings.defaulted = true;
	const html = renderToStaticMarkup(
		await DatasetsPage({ searchParams: Promise.resolve({}) }),
	);
	expect(html).toContain("List settings unavailable.");
	expect(html).not.toContain("reviewed default");
	expect(html).toContain("Choice");
});

vi.mock("@/lib/list-page-settings", () => ({
	getListPageSettings: async () => ({
		sizes: { dataset_items: 50, datasets: 50 },
		defaulted: false,
	}),
}));
vi.mock("@/lib/auth", () => ({
	requireGatewayToken: vi.fn(),
	requireSession: async () => ({ role: "owner" }),
	canAdmin: (role: string) => role === "owner",
}));
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, expect, it, vi } from "vitest";

vi.mock("@/lib/gateway", async (original) => ({
	...(await original<typeof import("@/lib/gateway")>()),
	gatewayGet: vi.fn(),
}));
import { GatewayError, gatewayGet } from "@/lib/gateway";
import Loading from "./loading";
import Page from "./page";
beforeEach(() => {
	vi.resetAllMocks();
	// Optional prompt choices loaded by the existing experiment action.
	vi.mocked(gatewayGet).mockResolvedValue([]);
});
it("renders stored input, reference, and trace provenance", async () => {
	vi.mocked(gatewayGet)
		.mockResolvedValueOnce({ name: "Support", description: "Review cases" })
		.mockResolvedValueOnce({
			items: [
				{
					item_id: "item",
					name: "Greeting",
					input: [{ role: "user", content: "Hello" }],
					expected_output: "Welcome",
					source_trace_id: "trace",
					source_span_id: "span",
				},
				{
					item_id: "missing",
					name: "Missing",
					input: [],
					expected_output: null,
					expected_output_reason: "output_not_captured",
					source_trace_id: null,
				},
			],
			next_cursor: "next",
		});
	const html = renderToStaticMarkup(
		await Page({ params: Promise.resolve({ id: "ds" }) }),
	);
	for (const text of [
		"Hello",
		"Welcome",
		"/traces/trace",
		"Output not captured",
		"Next page",
	])
		expect(html).toContain(text);
});
it("renders empty and loading states", async () => {
	vi.mocked(gatewayGet)
		.mockResolvedValueOnce({ name: "Empty" })
		.mockResolvedValueOnce({ items: [], next_cursor: null });
	expect(
		renderToStaticMarkup(await Page({ params: Promise.resolve({ id: "ds" }) })),
	).toContain("No cases yet");
	expect(renderToStaticMarkup(<Loading />)).toContain("Loading dataset");
});
it.each([404, 502])(
	"renders a read failure distinctly from empty (%s)",
	async (status) => {
		vi.mocked(gatewayGet).mockRejectedValue(new GatewayError(status, "failed"));
		const html = renderToStaticMarkup(
			await Page({ params: Promise.resolve({ id: "ds" }) }),
		);
		expect(html).toContain('role="alert"');
		expect(html).not.toContain("No cases yet");
	},
);

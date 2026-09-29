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
const h = vi.hoisted(() => {
	class GatewayError extends Error {
		constructor(public status: number) {
			super(String(status));
		}
	}
	return { gatewayGet: vi.fn(), dialog: vi.fn(), GatewayError };
});
vi.mock("@/lib/gateway", () => ({
	gatewayGet: h.gatewayGet,
	GatewayError: h.GatewayError,
}));
vi.mock("@/components/experiments/NewExperimentDialog", () => ({
	NewExperimentDialog: (props: { disabledReason: string | null }) => {
		h.dialog(props);
		return (
			<div>
				<button type="button" disabled={props.disabledReason !== null}>
					New experiment
				</button>
				{props.disabledReason}
			</div>
		);
	},
}));
import Page from "./page";
beforeEach(() => {
	h.gatewayGet.mockReset();
	h.dialog.mockReset();
});
function setup(
	promptFailure: boolean | number = false,
	prompts: unknown[] = [{ name: "assistant", active: [] }],
) {
	h.gatewayGet.mockImplementation(async (path: string) => {
		if (path === "/v1/prompts") {
			if (typeof promptFailure === "number")
				throw new h.GatewayError(promptFailure);
			if (promptFailure) throw new Error("offline");
			return prompts;
		}
		if (path.includes("/items?"))
			return {
				items: [
					{
						item_id: "case",
						name: "Existing case",
						input: [],
						expected_output: "Reference",
						source_trace_id: null,
					},
				],
				next_cursor: null,
			};
		return { name: "Chosen dataset", description: "Description", items: 12 };
	});
}
it("uses the current dataset in the existing experiment creation workflow", async () => {
	setup();
	const html = renderToStaticMarkup(
		await Page({ params: Promise.resolve({ id: "chosen" }) }),
	);
	expect(html).toContain("New experiment");
	expect(h.dialog).toHaveBeenCalledWith(
		expect.objectContaining({
			datasets: [{ dataset_id: "chosen", name: "Chosen dataset", items: 12 }],
			disabledReason: null,
		}),
	);
	expect(html).toContain('href="/review"');
});
it("preserves cases when prompt choices cannot be loaded", async () => {
	setup(true);
	const html = renderToStaticMarkup(
		await Page({ params: Promise.resolve({ id: "chosen" }) }),
	);
	expect(html).toContain("Existing case");
	expect(html).toContain("Couldn&#x27;t load prompts");
	expect(h.dialog).toHaveBeenCalledWith(
		expect.objectContaining({ disabledReason: expect.any(String) }),
	);
});
it("explains an empty prompt list without claiming the read failed", async () => {
	setup(false, []);
	const html = renderToStaticMarkup(
		await Page({ params: Promise.resolve({ id: "chosen" }) }),
	);
	expect(html).toContain("Create a prompt first");
	expect(html).not.toContain("Couldn&#x27;t load prompts");
});

it.each([
	[401, "Sign in to continue"],
	[403, "Access denied"],
	[503, "Couldn&#x27;t load prompts"],
])(
	"preserves prompt read status %i without hiding cases",
	async (status, message) => {
		setup(status as number);
		const html = renderToStaticMarkup(
			await Page({ params: Promise.resolve({ id: "chosen" }) }),
		);
		expect(html).toContain(message);
		expect(html).toContain("Existing case");
		expect(h.dialog).toHaveBeenCalledWith(
			expect.objectContaining({
				disabledReason: expect.any(String),
				prompts: [],
			}),
		);
		if (status === 401) expect(html).toContain('href="/sign-in"');
		if (status === 401 || status === 403)
			expect(html).not.toContain("Couldn&#x27;t load prompts");
	},
);

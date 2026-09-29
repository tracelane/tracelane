import { TurnActions } from "@/components/sessions/TurnActions";
import { BulkTraceWrites } from "@/components/trace-viewer/BulkTraceWrites";
// @vitest-environment jsdom
import {
	cleanup,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { DatasetAction } from "./DatasetAction";
const json = (data: unknown, status = 200) =>
	new Response(JSON.stringify(data), {
		status,
		headers: { "content-type": "application/json" },
	});
let capture: () => Promise<Response>;
const fetcher = vi.fn(async (url: string, init?: RequestInit) => {
	if (url === "/api/settings/content-capture") return capture();
	if (url.endsWith("/annotations")) return json([]);
	if (init?.method === "POST")
		return json(
			{
				error: "content_capture_disabled",
				message: "Gateway refused copying.",
			},
			422,
		);
	if (url === "/api/datasets")
		return json({ datasets: [{ dataset_id: "ds", name: "Support" }] });
	return json({ items: 0, limits: { items_max: 10 } });
});
beforeEach(() => {
	fetcher.mockClear();
	capture = async () => json({ effective: { input: false, output: true } });
	vi.stubGlobal("fetch", fetcher);
	HTMLDialogElement.prototype.showModal = function () {
		this.open = true;
	};
	HTMLDialogElement.prototype.close = function () {
		this.open = false;
	};
});
afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});
async function choose() {
	fireEvent.click(screen.getByRole("button", { name: "Add to dataset" }));
	await screen.findByRole("option", { name: "Support" });
	fireEvent.change(screen.getByLabelText("Dataset"), {
		target: { value: "ds" },
	});
}
for (const spanId of [undefined, "span"])
	it(`explains input capture off before saving ${spanId ? "a span" : "a trace"} and demotes the trigger`, async () => {
		render(<DatasetAction traceId="trace" spanId={spanId} primary />);
		await choose();
		expect(
			await screen.findByText("This workspace does not record prompt content."),
		).toBeTruthy();
		expect(
			screen
				.getByRole("link", { name: "Settings → Workspace" })
				.getAttribute("href"),
		).toBe("/settings/workspace");
		expect(
			(screen.getByRole("button", { name: "Save case" }) as HTMLButtonElement)
				.disabled,
		).toBe(true);
		expect(
			screen.getByRole("button", { name: "Add to dataset" }).className,
		).not.toContain("bg-selected");
		const form = screen
			.getByRole("button", { name: "Save case" })
			.closest("form");
		if (!form) throw new Error("Missing dataset form");
		fireEvent.submit(form);
		expect(fetcher.mock.calls.some(([, init]) => init?.method === "POST")).toBe(
			false,
		);
	});
for (const state of ["failed", "malformed", "on"])
	it(`keeps saving possible when capture is ${state}`, async () => {
		capture =
			state === "failed"
				? async () => json({}, 503)
				: state === "malformed"
					? async () => json({ input: false })
					: async () => json({ effective: { input: true, output: false } });
		render(<DatasetAction traceId="trace" spanId="span" primary />);
		await choose();
		await waitFor(() =>
			expect(
				(screen.getByRole("button", { name: "Save case" }) as HTMLButtonElement)
					.disabled,
			).toBe(false),
		);
		expect(
			screen.queryByText("This workspace does not record prompt content."),
		).toBeNull();
		fireEvent.click(screen.getByRole("button", { name: "Save case" }));
		expect((await screen.findByRole("alert")).textContent).toBe(
			"Gateway refused copying.",
		);
	});
it("lets the session turn open the capture explanation even with no recorded text", async () => {
	render(
		<TurnActions
			traceId="trace"
			spanId="span"
			viewerRole="owner"
			userId="u"
			canCopyContent={false}
		/>,
	);
	fireEvent.click(screen.getByRole("button", { name: "Turn actions" }));
	fireEvent.click(
		screen.getByRole("menuitem", { name: "Flag, share or add to dataset" }),
	);
	await choose();
	expect(
		await screen.findByText("This workspace does not record prompt content."),
	).toBeTruthy();
	expect(
		(screen.getByRole("button", { name: "Save case" }) as HTMLButtonElement)
			.disabled,
	).toBe(true);
});
for (const off of [true, false])
	it(`bulk add ${off ? "blocks known off" : "allows unknown then displays gateway refusal"}`, async () => {
		if (!off)
			capture = async () => {
				throw new Error("offline");
			};
		render(
			<BulkTraceWrites
				ids={["trace"]}
				viewerRole="owner"
				onSelection={vi.fn()}
				onBusy={vi.fn()}
			/>,
		);
		fireEvent.click(
			screen.getByRole("button", { name: "Add selected to dataset" }),
		);
		await screen.findByRole("option", { name: "Support" });
		fireEvent.change(screen.getByRole("combobox"), { target: { value: "ds" } });
		await screen.findByText(/10 slots left/);
		expect(
			(screen.getByRole("button", { name: "Add traces" }) as HTMLButtonElement)
				.disabled,
		).toBe(off);
		if (off) {
			expect(
				screen.getByRole("link", { name: "Settings → Workspace" }),
			).toBeTruthy();
			expect(
				fetcher.mock.calls.some(([, init]) => init?.method === "POST"),
			).toBe(false);
		} else {
			fireEvent.click(screen.getByRole("button", { name: "Add traces" }));
			expect((await screen.findByRole("alert")).textContent).toContain(
				"does not record prompt text",
			);
		}
	});

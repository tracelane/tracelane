// @vitest-environment jsdom
import {
	cleanup,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { BulkTraceWrites } from "./BulkTraceWrites";
afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});
Object.defineProperty(HTMLDialogElement.prototype, "showModal", {
	configurable: true,
	value: function () {
		this.setAttribute("open", "");
	},
});
Object.defineProperty(HTMLDialogElement.prototype, "close", {
	configurable: true,
	value: function () {
		this.removeAttribute("open");
	},
});
const json = (data: unknown, status = 200) =>
	new Response(JSON.stringify(data), {
		status,
		headers: { "content-type": "application/json" },
	});
it("keeps a persistent flag result and narrows to precisely the refusals", async () => {
	const fetch = vi.fn().mockResolvedValue(
		json({
			written: 1,
			refused: [{ trace_id: "b", reason: "invalid_trace_id" }],
		}),
	);
	vi.stubGlobal("fetch", fetch);
	const narrow = vi.fn();
	render(
		<BulkTraceWrites
			ids={["a", "b"]}
			viewerRole="member"
			onSelection={narrow}
			onBusy={vi.fn()}
		/>,
	);
	fireEvent.click(screen.getByRole("button", { name: "Flag selected" }));
	fireEvent.click(screen.getByRole("button", { name: "Apply flag" }));
	await screen.findByText("Flagged 1 · Refused 1");
	expect(narrow).toHaveBeenCalledWith(["b"]);
	expect(screen.getByRole("link", { name: "b" }).getAttribute("href")).toBe(
		"/traces/b",
	);
});
it("shows dataset headroom and preserves selection on capture refusal", async () => {
	const fetch = vi
		.fn()
		.mockImplementation(async (url: string, _init?: RequestInit) =>
			url === "/api/datasets"
				? json({ datasets: [{ dataset_id: "d", name: "Golden" }] })
				: url === "/api/datasets/d"
					? json({ items: 2, limits: { items_max: 10 } })
					: json({ error: "content_capture_required" }, 422),
		);
	vi.stubGlobal("fetch", fetch);
	const narrow = vi.fn();
	render(
		<BulkTraceWrites
			ids={["a", "b"]}
			viewerRole="owner"
			onSelection={narrow}
			onBusy={vi.fn()}
		/>,
	);
	fireEvent.click(
		screen.getByRole("button", { name: "Add selected to dataset" }),
	);
	await screen.findByText("Golden");
	fireEvent.change(screen.getByLabelText("Dataset"), {
		target: { value: "d" },
	});
	await screen.findByText("2 selected · 8 slots left");
	fireEvent.click(screen.getByRole("button", { name: "Add traces" }));
	await screen.findByText(
		"Nothing was added — this workspace does not record prompt text",
	);
	expect(narrow).not.toHaveBeenCalled();
	expect(
		JSON.parse(
			fetch.mock.calls.find((c) => c[0].endsWith("/items/batch"))?.[1]
				?.body as string,
		),
	).toEqual({ traces: [{ trace_id: "a" }, { trace_id: "b" }] });
});
it("gates write actions for viewers while still explaining them", () => {
	render(
		<BulkTraceWrites
			ids={["a"]}
			viewerRole="viewer"
			onSelection={vi.fn()}
			onBusy={vi.fn()}
		/>,
	);
	expect(
		(screen.getByRole("button", { name: "Flag selected" }) as HTMLButtonElement)
			.disabled,
	).toBe(true);
	expect(
		(
			screen.getByRole("button", {
				name: "Add selected to dataset",
			}) as HTMLButtonElement
		).disabled,
	).toBe(true);
});
it.each([
	["invalid_trace_id", "This trace ID is invalid."],
	["not_found", "This trace or span was not found in this workspace."],
	["span_has_no_content", "No prompt text was recorded for this span."],
	[
		"ambiguous_span",
		"This trace has several LLM calls. Open the trace and choose one.",
	],
	["span_content_unreadable", "The recorded content could not be read."],
	[
		"item_too_large",
		"The recorded content exceeds the dataset item size limit.",
	],
	[
		"unavailable",
		"This trace could not be processed. Retry or open the trace for details.",
	],
])("explains the per-trace refusal %s", async (reason, message) => {
	vi.stubGlobal(
		"fetch",
		vi
			.fn()
			.mockResolvedValue(
				json({ written: 0, refused: [{ trace_id: "a", reason }] }),
			),
	);
	render(
		<BulkTraceWrites
			ids={["a"]}
			viewerRole="member"
			onSelection={vi.fn()}
			onBusy={vi.fn()}
		/>,
	);
	fireEvent.click(screen.getByRole("button", { name: "Flag selected" }));
	fireEvent.click(screen.getByRole("button", { name: "Apply flag" }));
	await screen.findByText(message, { exact: false });
	if (reason === "unavailable")
		expect(screen.getByText("Code: unavailable")).toBeTruthy();
});
it.each([
	[
		400,
		"bulk_too_large",
		"Too many traces selected — the limit is 1. Reduce the selection and retry.",
	],
	[
		503,
		"bulk_limit_unavailable",
		"The selection limit is unavailable. Nothing was changed. Retry shortly.",
	],
])(
	"explains a %s %s refusal and keeps selection",
	async (status, error, message) => {
		vi.stubGlobal(
			"fetch",
			vi.fn().mockResolvedValue(json({ error, max: 1 }, status)),
		);
		const narrow = vi.fn();
		render(
			<BulkTraceWrites
				ids={["a", "b"]}
				viewerRole="member"
				onSelection={narrow}
				onBusy={vi.fn()}
			/>,
		);
		fireEvent.click(screen.getByRole("button", { name: "Flag selected" }));
		fireEvent.click(screen.getByRole("button", { name: "Apply flag" }));
		expect((await screen.findByRole("alert")).textContent).toBe(message);
		expect(narrow).not.toHaveBeenCalled();
	},
);

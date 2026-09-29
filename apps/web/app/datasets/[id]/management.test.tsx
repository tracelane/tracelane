// @vitest-environment jsdom
import {
	cleanup,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { DeleteDatasetButton } from "./DeleteDatasetButton";
import { ItemRowActions } from "./ItemRowActions";
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
const limits = {
	items_max: 200,
	import_bytes_max: 5242880,
	item_input_bytes_max: 65536,
	expected_output_bytes_max: 8,
	metadata_bytes_max: 8192,
};
it("edits metadata and refuses an over-limit reference without a request", async () => {
	const fetch = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
	vi.stubGlobal("fetch", fetch);
	render(
		<ItemRowActions
			datasetId="ds"
			itemId="item"
			expectedOutput="old"
			metadata={{}}
			input={[]}
			limits={limits}
			canWrite
		/>,
	);
	fireEvent.click(screen.getByRole("button", { name: "Edit case" }));
	fireEvent.change(screen.getByLabelText("Expected output"), {
		target: { value: "much too long" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Save" }));
	expect(fetch).not.toHaveBeenCalled();
	fireEvent.change(screen.getByLabelText("Expected output"), {
		target: { value: "new" },
	});
	fireEvent.change(screen.getByLabelText("Metadata JSON"), {
		target: { value: '{"tag":"gold"}' },
	});
	fireEvent.click(screen.getByRole("button", { name: "Save" }));
	await waitFor(() => expect(fetch).toHaveBeenCalledOnce());
	expect(JSON.parse(fetch.mock.calls[0]?.[1].body)).toEqual({
		expected_output: "new",
		metadata: { tag: "gold" },
	});
});
it("disables member edits and requires an exact name before deleting a dataset", async () => {
	const fetch = vi.fn().mockResolvedValue(
		new Response(
			JSON.stringify({
				queues: [{ id: "q", name: "Review", default_dataset_id: "ds" }],
			}),
			{ headers: { "content-type": "application/json" } },
		),
	);
	vi.stubGlobal("fetch", fetch);
	const view = render(
		<ItemRowActions
			datasetId="ds"
			itemId="item"
			expectedOutput="old"
			canWrite={false}
		/>,
	);
	expect(
		(screen.getByRole("button", { name: "Edit case" }) as HTMLButtonElement)
			.disabled,
	).toBe(true);
	view.unmount();
	render(<DeleteDatasetButton datasetId="ds" datasetName="Golden" canWrite />);
	fireEvent.click(screen.getByRole("button", { name: "Delete dataset" }));
	await screen.findByText("Review");
	fireEvent.change(screen.getByLabelText("Confirmation name"), {
		target: { value: "golden" },
	});
	expect(
		(screen.getByRole("button", { name: "Delete" }) as HTMLButtonElement)
			.disabled,
	).toBe(true);
	expect(fetch).toHaveBeenCalledTimes(1);
});

import { ImportJsonlForm } from "./ImportJsonlForm";
import { NewCaseForm } from "./NewCaseForm";
it("preflights JSONL headroom and reports rejected lines persistently", async () => {
	const fetch = vi.fn().mockResolvedValue(
		new Response(
			JSON.stringify({
				added: 1,
				deduped: 1,
				rejected_count: 1,
				rejected: [{ line: 3, reason: "Unknown field" }],
			}),
			{ headers: { "content-type": "application/json" } },
		),
	);
	vi.stubGlobal("fetch", fetch);
	render(
		<ImportJsonlForm datasetId="ds" limits={limits} items={197} canWrite />,
	);
	fireEvent.click(screen.getByRole("button", { name: "Import JSONL" }));
	const file = (text: string) => ({
		name: "cases.jsonl",
		size: text.length,
		text: async () => text,
	});
	fireEvent.change(screen.getByLabelText("JSONL file"), {
		target: { files: [file("{}\n{}\n{}\n{}")] },
	});
	await screen.findByText(/Nothing was imported/);
	expect(
		(screen.getByRole("button", { name: "Import" }) as HTMLButtonElement)
			.disabled,
	).toBe(true);
	expect(fetch).not.toHaveBeenCalled();
	fireEvent.change(screen.getByLabelText("JSONL file"), {
		target: { files: [file("{}\n{}\n{}")] },
	});
	await screen.findByText(/3 non-blank lines/);
	fireEvent.click(screen.getByRole("button", { name: "Import" }));
	await screen.findByText("Line 3: Unknown field");
	expect(
		screen.getByText("Added 1 · Already present 1 · Rejected 1"),
	).toBeTruthy();
	expect(screen.getByText("Download rejected lines")).toBeTruthy();
});
it("creates a handwritten case through one-line import and explains deduplication", async () => {
	const fetch = vi.fn().mockResolvedValue(
		new Response(
			JSON.stringify({
				added: 0,
				deduped: 1,
				rejected_count: 0,
				rejected: [],
			}),
			{ headers: { "content-type": "application/json" } },
		),
	);
	vi.stubGlobal("fetch", fetch);
	render(<NewCaseForm datasetId="ds" limits={limits} canWrite />);
	fireEvent.click(screen.getByRole("button", { name: "New case" }));
	fireEvent.change(screen.getByLabelText("Input messages JSON"), {
		target: { value: '[{"role":"user","content":"hello"}]' },
	});
	fireEvent.click(screen.getByText("Add case"));
	await screen.findByText("No change — an identical case already exists");
	expect(fetch.mock.calls[0]?.[0]).toBe("/api/datasets/ds/import?format=jsonl");
	expect(JSON.parse(fetch.mock.calls[0]?.[1].body).input[0].content).toBe(
		"hello",
	);
});
it("deletes only after the exact dataset name is confirmed", async () => {
	const fetch = vi
		.fn()
		.mockImplementation(
			async (_url: string, init?: RequestInit) =>
				new Response(
					JSON.stringify(init?.method === "DELETE" ? {} : { queues: [] }),
					{ headers: { "content-type": "application/json" } },
				),
		);
	vi.stubGlobal("fetch", fetch);
	render(<DeleteDatasetButton datasetId="ds" datasetName="Golden" canWrite />);
	fireEvent.click(screen.getByRole("button", { name: "Delete dataset" }));
	await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));
	fireEvent.change(screen.getByLabelText("Confirmation name"), {
		target: { value: "Golden" },
	});
	expect(
		(screen.getByRole("button", { name: "Delete" }) as HTMLButtonElement)
			.disabled,
	).toBe(false);
	fireEvent.click(screen.getByRole("button", { name: "Delete" }));
	await waitFor(() =>
		expect(fetch).toHaveBeenCalledWith(
			"/api/datasets/ds",
			expect.objectContaining({ method: "DELETE" }),
		),
	);
});
it("strips a UTF-8 BOM before counting and sending JSONL", async () => {
	const fetch = vi.fn().mockResolvedValue(
		new Response(
			JSON.stringify({
				added: 1,
				deduped: 0,
				rejected_count: 0,
				rejected: [],
			}),
			{ headers: { "content-type": "application/json" } },
		),
	);
	vi.stubGlobal("fetch", fetch);
	render(<ImportJsonlForm datasetId="ds" limits={limits} items={0} canWrite />);
	fireEvent.click(screen.getByRole("button", { name: "Import JSONL" }));
	fireEvent.change(screen.getByLabelText("JSONL file"), {
		target: {
			files: [{ name: "bom.jsonl", size: 6, text: async () => "\uFEFF{}\n" }],
		},
	});
	await screen.findByText(/1 non-blank lines/);
	fireEvent.click(screen.getByRole("button", { name: "Import" }));
	await waitFor(() =>
		expect(fetch).toHaveBeenCalledWith(
			"/api/datasets/ds/import?format=jsonl",
			expect.objectContaining({ body: "{}\n" }),
		),
	);
});
import { DatasetItems } from "./DatasetItems";
it("shows the last user message first with raw input behind a disclosure", () => {
	render(
		<DatasetItems
			datasetId="d"
			canWrite={false}
			items={[
				{
					item_id: "i",
					name: "Case",
					input: [
						{ role: "user", content: "First question" },
						{ role: "assistant", content: "First answer" },
						{ role: "user", content: "Latest question" },
					],
					expected_output: null,
					source_trace_id: null,
					source_span_id: "",
				},
			]}
		/>,
	);
	const cell = screen.getByText("Latest question");
	expect(cell.tagName).not.toBe("PRE");
	expect(screen.getByText("Raw").closest("details")?.open).toBe(false);
	expect(screen.getAllByTestId("case-message")[0]?.textContent).toContain(
		"Latest question",
	);
});

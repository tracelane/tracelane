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
const fetcher = vi.fn();
beforeEach(() => {
	vi.stubGlobal("fetch", (path: string, init?: RequestInit) =>
		path === "/api/settings/content-capture"
			? Promise.resolve(response({ effective: { input: true } }))
			: fetcher(path, init),
	);
	fetcher.mockReset();
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
const response = (body: unknown, status = 200) =>
	new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json" },
	});
it("with a span_id, saves through the single-item route and links the dataset", async () => {
	fetcher
		.mockResolvedValueOnce(
			response({
				datasets: [{ dataset_id: "ds", name: "Support" }],
				next_cursor: null,
			}),
		)
		.mockResolvedValueOnce(response({ item_id: "item" }, 201));
	render(<DatasetAction traceId="trace" spanId="span-1" />);
	fireEvent.click(screen.getByRole("button", { name: "Add to dataset" }));
	await screen.findByRole("option", { name: "Support" });
	fireEvent.change(screen.getByLabelText("Dataset"), {
		target: { value: "ds" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Save case" }));
	expect(
		(await screen.findByRole("link", { name: "Support" })).getAttribute("href"),
	).toBe("/datasets/ds");
	const [path, init] = fetcher.mock.calls[1] ?? [];
	expect(path).toBe("/api/datasets/ds/items");
	expect(JSON.parse(init.body)).toEqual({
		trace_id: "trace",
		span_id: "span-1",
	});
});
// `OBS-56` S4 / B-582: with NO span_id (the trace-header case), the button
// must call the BATCH route so the gateway resolves the span server-side —
// the single-item route requires span_id and this shape used to 400
// `span_id_required` every time, which is why the header button was removed.
it("with no span_id, saves through the batch route and links the dataset", async () => {
	fetcher
		.mockResolvedValueOnce(
			response({
				datasets: [{ dataset_id: "ds", name: "Support" }],
				next_cursor: null,
			}),
		)
		.mockResolvedValueOnce(
			response({ added: 1, deduped: 0, refused_count: 0, refused: [] }),
		);
	render(<DatasetAction traceId="trace" />);
	fireEvent.click(screen.getByRole("button", { name: "Add to dataset" }));
	await screen.findByRole("option", { name: "Support" });
	fireEvent.change(screen.getByLabelText("Dataset"), {
		target: { value: "ds" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Save case" }));
	expect(
		(await screen.findByRole("link", { name: "Support" })).getAttribute("href"),
	).toBe("/datasets/ds");
	const [path, init] = fetcher.mock.calls[1] ?? [];
	expect(path).toBe("/api/datasets/ds/items/batch");
	expect(JSON.parse(init.body)).toEqual({
		traces: [{ trace_id: "trace" }],
	});
});
it("with no span_id, a batch refusal (ambiguous_span) renders and does not link", async () => {
	fetcher
		.mockResolvedValueOnce(
			response({
				datasets: [{ dataset_id: "ds", name: "Support" }],
				next_cursor: null,
			}),
		)
		.mockResolvedValueOnce(
			response({
				added: 0,
				deduped: 0,
				refused_count: 1,
				refused: [
					{
						trace_id: "trace",
						reason: "ambiguous_span",
						message:
							"This trace has 2 LLM calls — add it from the trace page and pick one.",
					},
				],
			}),
		);
	render(<DatasetAction traceId="trace" />);
	fireEvent.click(screen.getByRole("button", { name: "Add to dataset" }));
	await screen.findByRole("option", { name: "Support" });
	fireEvent.change(screen.getByLabelText("Dataset"), {
		target: { value: "ds" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Save case" }));
	expect((await screen.findByRole("alert")).textContent).toBe(
		"This trace has 2 LLM calls — add it from the trace page and pick one.",
	);
	expect(screen.queryByRole("link", { name: "Support" })).toBeNull();
});
it("creates inline, renders the gateway 422, and retries without recreating", async () => {
	fetcher
		.mockResolvedValueOnce(response({ datasets: [], next_cursor: null }))
		.mockResolvedValueOnce(response({ dataset_id: "new" }, 201))
		.mockResolvedValueOnce(
			response(
				{
					error: "content_capture_disabled",
					message: "This workspace does not record prompt content.",
				},
				422,
			),
		)
		.mockResolvedValueOnce(response({ item_id: "item" }, 201));
	// Real request shape: the gateway builds an item from ONE span and refuses
	// trace-only adds (span_id_required) — the old trace-only render encoded B-582.
	render(<DatasetAction traceId="trace" spanId="span" />);
	fireEvent.click(screen.getByRole("button", { name: "Add to dataset" }));
	await waitFor(() =>
		expect(screen.queryByText("Loading datasets…")).toBeNull(),
	);
	fireEvent.change(screen.getByLabelText("Dataset name"), {
		target: { value: "Cases" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Save case" }));
	expect((await screen.findByRole("alert")).textContent).toBe(
		"This workspace does not record prompt content.",
	);
	fireEvent.click(screen.getByRole("button", { name: "Save case" }));
	await screen.findByRole("link", { name: "Cases" });
	expect(
		fetcher.mock.calls.filter(([p]) => p === "/api/datasets"),
	).toHaveLength(2);
	expect(JSON.parse(fetcher.mock.calls[1]?.[1].body)).toEqual({
		name: "Cases",
	});
});
it("creates from the datasets page", async () => {
	fetcher.mockResolvedValueOnce(response({ dataset_id: "new" }, 201));
	render(<DatasetAction />);
	fireEvent.click(screen.getByRole("button", { name: "New dataset" }));
	fireEvent.change(screen.getByLabelText("Dataset name"), {
		target: { value: "Cases" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Create dataset" }));
	expect(
		(await screen.findByRole("link", { name: "Cases" })).getAttribute("href"),
	).toBe("/datasets/new");
});

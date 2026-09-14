// @vitest-environment jsdom
/**
 * `EVL-29` — component tests for the per-row archive/un-archive action.
 */

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ refresh: vi.fn() }));
vi.mock("next/navigation", () => ({
	useRouter: () => ({ refresh: h.refresh }),
}));

import type { AnnotationQueue } from "@/app/api/annotation-queues/shared";
import { QueueRow, confirmArchiveMessage } from "./QueueRow";

function queue(overrides: Partial<AnnotationQueue> = {}): AnnotationQueue {
	return {
		id: "q-1",
		name: "Low-score support replies",
		filter: { source: { kind: "trace_error" }, window_hours: 168 },
		rubric: [],
		default_dataset_id: "ds-1",
		expected_output_field: "expected_answer",
		created_by: "e2e@tracelane.test",
		created_at: "2026-09-01T00:00:00Z",
		updated_at: "2026-09-01T00:00:00Z",
		...overrides,
	};
}

function renderRow(q: AnnotationQueue) {
	return render(
		<table>
			<tbody>
				<QueueRow queue={q} sourceLabel="Errored traces" />
			</tbody>
		</table>,
	);
}

afterEach(cleanup);
beforeEach(() => {
	h.refresh.mockClear();
	vi.unstubAllGlobals();
});

describe("confirmArchiveMessage", () => {
	it("names the queue and states the effect, in both directions", () => {
		expect(confirmArchiveMessage("My Q", true)).toContain('"My Q"');
		expect(confirmArchiveMessage("My Q", true)).toMatch(/archive/i);
		expect(confirmArchiveMessage("My Q", false)).toMatch(/un-archive/i);
	});
});

describe("QueueRow — archive/un-archive", () => {
	it("does nothing if the confirm is dismissed", () => {
		vi.spyOn(window, "confirm").mockReturnValue(false);
		const fetchMock = vi.fn();
		vi.stubGlobal("fetch", fetchMock);

		renderRow(queue());
		fireEvent.click(screen.getByRole("button", { name: "Archive" }));

		expect(fetchMock).not.toHaveBeenCalled();
		expect(screen.getByRole("button", { name: "Archive" })).toBeInTheDocument();
	});

	it("archives optimistically, PATCHes {archived:true}, and refreshes on success", async () => {
		vi.spyOn(window, "confirm").mockReturnValue(true);
		const fetchMock = vi
			.fn()
			.mockResolvedValue({ ok: true, json: async () => ({}) });
		vi.stubGlobal("fetch", fetchMock);

		renderRow(queue());
		fireEvent.click(screen.getByRole("button", { name: "Archive" }));

		// Optimistic: the row already reads "archived" before the PATCH resolves.
		expect(screen.getByText(/\(archived\)/)).toBeInTheDocument();
		expect(
			screen.queryByRole("link", { name: "Low-score support replies" }),
		).not.toBeInTheDocument();

		await screen.findByRole("button", { name: "Un-archive" });
		expect(fetchMock).toHaveBeenCalledWith(
			"/api/annotation-queues/q-1",
			expect.objectContaining({
				method: "PATCH",
				body: JSON.stringify({ archived: true }),
			}),
		);
		expect(h.refresh).toHaveBeenCalledTimes(1);
	});

	it("rolls back the optimistic update and renders the server error on failure", async () => {
		vi.spyOn(window, "confirm").mockReturnValue(true);
		const fetchMock = vi.fn().mockResolvedValue({
			ok: false,
			status: 502,
			json: async () => ({ message: "Could not update the queue." }),
		});
		vi.stubGlobal("fetch", fetchMock);

		renderRow(queue());
		fireEvent.click(screen.getByRole("button", { name: "Archive" }));

		const error = await screen.findByText("Could not update the queue.");
		expect(error).toBeInTheDocument();
		// Rolled back: the row is active again, not archived.
		expect(screen.getByRole("button", { name: "Archive" })).toBeInTheDocument();
		expect(
			screen.getByRole("link", { name: "Low-score support replies" }),
		).toBeInTheDocument();
		expect(h.refresh).not.toHaveBeenCalled();
	});

	it("un-archives an already-archived queue with {archived:false}", async () => {
		vi.spyOn(window, "confirm").mockReturnValue(true);
		const fetchMock = vi
			.fn()
			.mockResolvedValue({ ok: true, json: async () => ({}) });
		vi.stubGlobal("fetch", fetchMock);

		renderRow(queue({ archived_at: "2026-08-01T00:00:00Z" }));
		fireEvent.click(screen.getByRole("button", { name: "Un-archive" }));

		await screen.findByRole("button", { name: "Archive" });
		expect(fetchMock).toHaveBeenCalledWith(
			"/api/annotation-queues/q-1",
			expect.objectContaining({
				method: "PATCH",
				body: JSON.stringify({ archived: false }),
			}),
		);
	});
});

import type { QueueItem } from "@/app/api/annotation-queues/[queueId]/items/route";
import type { AnnotationQueue } from "@/app/api/annotation-queues/shared";
// @vitest-environment jsdom
/**
 * Item 6 — the review form used to (a) default the verdict to "bad" and let
 * a reviewer submit without ever touching it, (b) never validate required
 * rubric fields client-side, (c) always show a built-in Note box even when
 * the rubric already has its own free-text field, and (d) have no way to
 * move past a candidate without writing a review. Each is proven separately.
 */
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { ReviewPanel } from "./ReviewPanel";

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

function queue(overrides: Partial<AnnotationQueue> = {}): AnnotationQueue {
	return {
		id: "q1",
		name: "Test queue",
		filter: { source: { kind: "needs_review" }, window_hours: 24 },
		rubric: [
			{ key: "answer", label: "Correct answer", type: "text", required: true },
		],
		default_dataset_id: "ds1",
		expected_output_field: "answer",
		created_by: "user_a",
		created_at: "2026-09-01T00:00:00Z",
		updated_at: "2026-09-01T00:00:00Z",
		...overrides,
	};
}

const item: QueueItem = {
	trace_id: "trace-1",
	span_id: "span-1",
	occurred_at: "2026-09-27T00:00:00Z",
};

function mountPanel(q: AnnotationQueue = queue()) {
	return render(
		<ReviewPanel
			queue={q}
			items={[item]}
			scanTruncated={false}
			scanExhausted={false}
		/>,
	);
}

it("defaults the verdict to unset and disables submit until one is chosen", () => {
	mountPanel();
	const select = screen.getByLabelText("Verdict") as HTMLSelectElement;
	expect(select.value).toBe("");
	const submit = screen.getByText(
		"Submit review and create the graded case",
	) as HTMLButtonElement;
	expect(submit.disabled).toBe(true);

	fireEvent.change(select, { target: { value: "good" } });
	fireEvent.change(screen.getByLabelText(/Correct answer/), {
		target: { value: "42" },
	});
	expect(submit.disabled).toBe(false);
});

it("refuses to submit a required rubric field left blank, without a round trip", async () => {
	const fetchMock = vi.fn();
	vi.stubGlobal("fetch", fetchMock);
	mountPanel();

	fireEvent.change(screen.getByLabelText("Verdict"), {
		target: { value: "good" },
	});
	// Required "Correct answer" text field left blank.
	fireEvent.click(screen.getByText("Submit review and create the graded case"));

	expect(await screen.findByText("Correct answer is required.")).toBeTruthy();
	expect(fetchMock).not.toHaveBeenCalled();
});

it("hides the built-in Note when the rubric already has a free-text field", () => {
	mountPanel(queue()); // rubric has a "text" field
	expect(screen.queryByLabelText("Note")).toBeNull();
});

it("shows the built-in Note when the rubric has no free-text field", () => {
	mountPanel(
		queue({
			rubric: [
				{
					key: "score",
					label: "Score",
					type: "score",
					required: true,
					min: 0,
					max: 1,
				},
			],
			expected_output_field: "score",
		}),
	);
	expect(screen.getByLabelText("Note")).toBeTruthy();
});

it("Skip advances to the next candidate without writing anything", () => {
	const fetchMock = vi.fn();
	vi.stubGlobal("fetch", fetchMock);
	const items: QueueItem[] = [
		{ ...item, trace_id: "trace-1" },
		{ ...item, trace_id: "trace-2" },
	];
	render(
		<ReviewPanel
			queue={queue()}
			items={items}
			scanTruncated={false}
			scanExhausted={false}
		/>,
	);
	expect(screen.getByText("Candidate 1 of 2")).toBeTruthy();
	fireEvent.click(screen.getByText("Skip"));
	expect(screen.getByText("Candidate 2 of 2")).toBeTruthy();
	expect(fetchMock).not.toHaveBeenCalled();
});

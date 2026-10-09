import { classifyTraceFetchError, noMatchCopy } from "@/app/traces/empty-state";
import { nextIssueFilterParams } from "@/app/traces/filter-params";
import { ISSUE_LABELS, type IssueChip } from "@/lib/generation-issues";
// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { IssueChips } from "./IssueChip";
afterEach(cleanup);
const issues = Object.keys(ISSUE_LABELS).map((kind) => ({
	kind,
	severity: "info",
	detail: `recorded field ${kind}`,
	affected_spans: 1,
})) as IssueChip[];
it("renders every recorded kind, exposes overflow, and omits empty evidence", () => {
	const { container, rerender } = render(
		<IssueChips issues={issues} inlineLimit={3} />,
	);
	expect(container.querySelectorAll("details")).toHaveLength(1);
	expect(screen.getByText("+6")).toBeTruthy();
	expect(container.querySelector("details")?.open).toBe(false);
	fireEvent.click(screen.getByText("+6"));
	expect(container.querySelector("details")?.open).toBe(true);
	for (const label of Object.values(ISSUE_LABELS))
		expect(screen.getAllByText(label).length).toBeGreaterThan(0);
	const first = screen.getAllByText("Model swapped")[0];
	if (!first) throw new Error("missing model chip");
	fireEvent.focus(first);
	expect(screen.getByRole("tooltip").textContent).toContain(
		"recorded field model_swapped",
	);
	rerender(<IssueChips issues={[]} inlineLimit={3} />);
	expect(container.textContent).toBe("");
});
it("adds/removes OR filters while retaining windows and resetting pagination", () => {
	const start = new URLSearchParams(
		"issue=truncated&cursor=old&since=2026-09-01&until=2026-09-02&model=gpt-4o",
	);
	const added = new URLSearchParams(nextIssueFilterParams(start, "filtered"));
	expect(added.get("issue")).toBe("truncated,filtered");
	expect(added.get("since")).toBe("2026-09-01");
	expect(added.get("model")).toBe("gpt-4o");
	expect(added.has("cursor")).toBe(false);
	expect(
		new URLSearchParams(nextIssueFilterParams(added, "truncated")).get("issue"),
	).toBe("filtered");
});
it("separates empty filtered evidence from denied and invalid reads", () => {
	expect(noMatchCopy(undefined, "truncated").title).toBe(
		"No traces in this window have Hit token limit.",
	);
	expect(
		classifyTraceFetchError({ status: 403, message: "denied", body: null })
			.kind,
	).toBe("forbidden");
	expect(
		classifyTraceFetchError({
			status: 400,
			message: "bad",
			body: { error: "unknown_issue", allowed: ["truncated"] },
		}),
	).toEqual({ kind: "rejected", message: "Unknown issue. Allowed: truncated" });
});

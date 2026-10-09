// @vitest-environment jsdom
import { ApiError, apiFetch } from "@/lib/api-fetch";
import { ISSUE_LABELS } from "@/lib/generation-issues";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { GenerationIssues } from "./GenerationIssues";
vi.mock("@/lib/api-fetch", async (original) => ({
	...(await original<typeof import("@/lib/api-fetch")>()),
	apiFetch: vi.fn(),
}));
afterEach(() => {
	cleanup();
	vi.resetAllMocks();
});
const summary = {
	total_traces: 12,
	llm_calls: 18,
	no_served_model_calls: 3,
	no_finish_reason_calls: 5,
	gateway_signal_calls: 0,
	content_capture: false,
	window_days: 3,
	since: "2026-09-27T12:00:00Z",
	until: "2026-09-30T12:00:00Z",
	as_of: "2026-09-30T12:00:00Z",
	counts: Object.keys(ISSUE_LABELS).map((kind) => ({
		kind,
		trace_count: kind === "truncated" ? 2 : kind === "capture_trimmed" ? 1 : 0,
	})),
};
it("shows recorded counts, unknown evidence and current capture separately, and links the exact cached window", async () => {
	vi.mocked(apiFetch).mockResolvedValue(summary);
	render(<GenerationIssues />);
	expect(
		await screen.findByText("Generation issues · last 3 days"),
	).toBeTruthy();
	expect(screen.getByText("of 12 traces")).toBeTruthy();
	expect(screen.getByText("3 calls recorded no served model")).toBeTruthy();
	expect(screen.getByText("5 calls recorded no finish reason")).toBeTruthy();
	expect(screen.getByText(/as of .*UTC/)).toBeTruthy();
	expect(screen.getByText("Content capture is currently off")).toBeTruthy();
	expect(screen.getByText("No gateway signals recorded")).toBeTruthy();
	const truncated = screen.getByRole("link", {
		name: "Hit token limit: 2 traces",
	});
	const url = new URL(truncated.getAttribute("href") ?? "", "http://app.test");
	expect([...url.searchParams]).toEqual([
		["issue", "truncated"],
		["since", summary.since],
		["until", summary.until],
	]);
	expect(
		screen.getByRole("link", { name: "Capture trimmed: 1 traces" }),
	).toBeTruthy();
	expect(
		screen.getByRole("link", { name: "Model swapped: 0 traces" }),
	).toBeTruthy();
});
it("shows skeleton tiles before the read and a distinct never-had-data state", async () => {
	let resolve!: (value: typeof summary) => void;
	vi.mocked(apiFetch).mockImplementation(
		() =>
			new Promise((r) => {
				resolve = r as typeof resolve;
			}),
	);
	render(<GenerationIssues />);
	expect(
		screen.getByRole("status", { name: "Loading generation issues" }).children,
	).toHaveLength(9);
	expect(screen.queryByRole("link")).toBeNull();
	resolve({ ...summary, total_traces: 0, counts: [] });
	expect(
		await screen.findByText(
			"No traces in the last 3 days yet — chips appear as calls are recorded.",
		),
	).toBeTruthy();
	expect(screen.queryByRole("link")).toBeNull();
});
it.each([403, 502])(
	"renders denial distinctly and allows retry after a failed read (%s)",
	async (status) => {
		vi.mocked(apiFetch)
			.mockRejectedValueOnce(new ApiError(status))
			.mockResolvedValueOnce(summary);
		render(<GenerationIssues />);
		if (status === 403) {
			expect(
				await screen.findByText("You don't have access to trace data"),
			).toBeTruthy();
			expect(screen.queryByRole("button")).toBeNull();
		} else {
			fireEvent.click(
				await screen.findByRole("button", { name: "Couldn't load — retry" }),
			);
			expect(await screen.findByText("of 12 traces")).toBeTruthy();
		}
	},
);

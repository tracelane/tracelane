import { ApiError, apiFetch } from "@/lib/api-fetch";
import type { IssueRollup } from "@/lib/generation-issues";
// @vitest-environment jsdom
import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { useIssueRollup } from "./IssueChip";
vi.mock("@/lib/api-fetch", async (original) => ({
	...(await original<typeof import("@/lib/api-fetch")>()),
	apiFetch: vi.fn(),
}));
afterEach(() => {
	cleanup();
	vi.resetAllMocks();
});
it("leaves badges absent while loading, cancels old pages, and attaches only the current result", async () => {
	let oldResolve!: (value: IssueRollup) => void;
	const ready: IssueRollup = {
		traces: [{ trace_id: "new", issues: [] }],
		issues_available: true,
		inline_limit: 3,
	};
	vi.mocked(apiFetch)
		.mockImplementationOnce(
			() =>
				new Promise((resolve) => {
					oldResolve = resolve as typeof oldResolve;
				}),
		)
		.mockResolvedValueOnce(ready);
	const { result, rerender } = renderHook(
		({ ids }) => useIssueRollup(ids, true),
		{ initialProps: { ids: "old" } },
	);
	expect(result.current).toEqual({ data: undefined, error: undefined });
	rerender({ ids: "new" });
	await waitFor(() => expect(result.current.data).toEqual(ready));
	expect(vi.mocked(apiFetch).mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
	await act(async () =>
		oldResolve({ ...ready, traces: [{ trace_id: "old", issues: [] }] }),
	);
	expect(result.current.data).toEqual(ready);
});
it.each([false, 403, 502] as const)(
	"distinguishes unavailable and forbidden badges (%s)",
	async (kind) => {
		if (kind === false)
			vi.mocked(apiFetch).mockResolvedValue({
				traces: [],
				issues_available: false,
				inline_limit: 3,
			});
		else vi.mocked(apiFetch).mockRejectedValue(new ApiError(kind));
		const { result } = renderHook(() => useIssueRollup("row", true));
		await waitFor(() =>
			expect(result.current.error).toBe(
				kind === 403
					? "You don't have access to trace data"
					: "Generation-issue badges are unavailable right now; the list is complete.",
			),
		);
		expect(result.current.data).toBeUndefined();
	},
);

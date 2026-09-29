// @vitest-environment jsdom
import {
	cleanup,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
const h = vi.hoisted(() => ({ refresh: vi.fn() }));
vi.mock("next/navigation", () => ({
	useRouter: () => ({ refresh: h.refresh }),
}));
import { CanaryPanel } from "./CanaryPanel";
afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
	h.refresh.mockClear();
});
it("saves the explicit ratio, stops the split, and refreshes persisted state", async () => {
	const fetch = vi
		.fn()
		.mockResolvedValueOnce(
			new Response("{}", {
				status: 200,
				headers: { "content-type": "application/json" },
			}),
		)
		.mockResolvedValueOnce(new Response(null, { status: 204 }));
	vi.stubGlobal("fetch", fetch);
	render(
		<CanaryPanel
			promptName="proof"
			candidateVersionId="candidate"
			initial={{
				canary_id: "split",
				stable_version_id: "stable",
				candidate_version_id: "candidate",
				candidate_percent: 17.25,
			}}
			readStatus={200}
		/>,
	);
	fireEvent.change(
		screen.getByLabelText("Candidate percentage of prompt resolutions"),
		{ target: { value: "33.5" } },
	);
	fireEvent.click(screen.getByText("Update canary"));
	await waitFor(() => expect(screen.getByText("Canary saved.")).toBeTruthy());
	expect(JSON.parse(fetch.mock.calls[0]?.[1].body)).toEqual({
		candidate_version_id: "candidate",
		candidate_percent: 33.5,
	});
	fireEvent.click(screen.getByText("Stop canary"));
	await waitFor(() => expect(screen.getByText("Canary stopped.")).toBeTruthy());
	expect(fetch.mock.calls[1]?.[1].method).toBe("DELETE");
	expect(h.refresh).toHaveBeenCalledTimes(2);
});
it.each([401, 403, 503])(
	"does not claim a failed save succeeded (%i)",
	async (status) => {
		vi.stubGlobal(
			"fetch",
			vi.fn().mockImplementation(
				async () =>
					new Response(JSON.stringify({ error: "store unavailable" }), {
						status,
						headers: { "content-type": "application/json" },
					}),
			),
		);
		render(
			<CanaryPanel
				promptName="proof"
				candidateVersionId="candidate"
				initial={null}
				readStatus={200}
			/>,
		);
		fireEvent.change(
			screen.getByLabelText("Candidate percentage of prompt resolutions"),
			{ target: { value: "25" } },
		);
		fireEvent.click(screen.getByText("Start canary"));
		await waitFor(() => expect(h.refresh).toHaveBeenCalled());
		expect(screen.queryByText("Canary saved.")).toBeNull();
		expect(screen.getByRole("status").textContent).toMatch(
			status === 401
				? /Sign in/
				: status === 403
					? /Access denied/
					: /store unavailable/,
		);
	},
);

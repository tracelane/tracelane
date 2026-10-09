import { ApiError, apiFetch, apiFetchRaw } from "@/lib/api-fetch";
// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
	cleanup,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { type IncidentPacket, IncidentPanel } from "./IncidentPanel";
vi.mock("@/lib/api-fetch", async (original) => {
	const actual = await original<typeof import("@/lib/api-fetch")>();
	return { ...actual, apiFetch: vi.fn(), apiFetchRaw: vi.fn() };
});
const packet: IncidentPacket = {
	trigger: [{ kind: "error", span_id: "failed" }],
	what_happened: { trace_id: "trace", span_id: "failed" },
	what_changed: {
		good_trace_id: "good",
		note: null,
		prompt_version: "prompt version: not linked",
		fields: [
			{
				field: "deployment_environment",
				good: "staging",
				failing: "prod",
				changed: true,
			},
		],
	},
	linked_spans: [{ trace_id: "trace", span_id: "failed" }],
	explanations: {
		note: null,
		items: [
			{
				what: "Recorded field changed; its effect is uncertain",
				confidence: "uncertain",
				evidence: [
					{ field: "deployment_environment", good: "staging", failing: "prod" },
				],
			},
		],
	},
	limits: {
		incident_last_good_lookback_hours: 168,
		outcome_reason_max_bytes: 2000,
		export_permission: "allowed",
		can_record_outcome: true,
	},
};
let data = structuredClone(packet);
function mount() {
	const client = new QueryClient({
		defaultOptions: { queries: { retry: false } },
	});
	render(
		<QueryClientProvider client={client}>
			<IncidentPanel traceId="trace" />
		</QueryClientProvider>,
	);
	return client;
}
beforeEach(() => {
	data = structuredClone(packet);
	vi.mocked(apiFetch).mockImplementation(async (url) =>
		url.includes("/incident") ? data : { outcome: null },
	);
});
afterEach(() => {
	cleanup();
	vi.clearAllMocks();
});
it("renders evidence, uncertainty and the selected-span link", async () => {
	mount();
	expect(
		await screen.findByRole("heading", { name: "Incident packet" }),
	).toBeTruthy();
	expect(await screen.findByText("uncertain", { exact: true })).toBeTruthy();
	expect(
		screen.getByRole("link", { name: "failed" }).getAttribute("href"),
	).toBe("/traces/trace?span=failed");
	expect(screen.queryByText(/Cost per successful/)).toBeNull();
});
it("states there is no comparable good run and hides forbidden export and writes", async () => {
	data.what_changed.note = "no comparable good run in the window";
	data.what_changed.good_trace_id = null;
	data.limits.export_permission = "forbidden";
	data.limits.can_record_outcome = false;
	mount();
	expect(
		await screen.findByText("no comparable good run in the window"),
	).toBeTruthy();
	expect(screen.queryByRole("button", { name: "Export fixture" })).toBeNull();
	expect(screen.queryByRole("button", { name: "Record success" })).toBeNull();
});
it("writes the chosen outcome and reason through the real client seam", async () => {
	mount();
	fireEvent.change(await screen.findByLabelText(/Reason/), {
		target: { value: "wrong answer" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Record failure" }));
	await waitFor(() =>
		expect(vi.mocked(apiFetch)).toHaveBeenCalledWith(
			"/api/outcomes",
			expect.objectContaining({
				method: "POST",
				body: JSON.stringify({
					subject_kind: "trace",
					subject_id: "trace",
					result: "failure",
					reason: "wrong answer",
					source: "web",
				}),
			}),
		),
	);
	expect(await screen.findByRole("status")).toHaveProperty(
		"textContent",
		"Outcome recorded: failure.",
	);
});
it("keeps the packet visible when an export reports content not captured", async () => {
	vi.mocked(apiFetchRaw).mockResolvedValue(
		new Response(JSON.stringify({ code: "content_not_captured" }), {
			status: 422,
		}),
	);
	mount();
	fireEvent.click(
		await screen.findByRole("button", { name: "Export fixture" }),
	);
	expect(await screen.findByRole("alert")).toHaveProperty(
		"textContent",
		"Content not captured. This trace has no readable recorded input to export.",
	);
	expect(screen.getByText("uncertain", { exact: true })).toBeTruthy();
});
it("renders permission errors with a retry rather than an empty packet", async () => {
	vi.mocked(apiFetch).mockRejectedValue(new ApiError(403));
	mount();
	expect(
		await screen.findByRole("button", { name: "Retry incident" }),
	).toBeTruthy();
	expect(screen.queryByText("no failing signal recorded")).toBeNull();
});

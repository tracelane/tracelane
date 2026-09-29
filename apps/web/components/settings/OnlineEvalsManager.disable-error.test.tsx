// @vitest-environment jsdom
/**
 * A failed Disable must be LOUD. Before this fix, the `disable` mutation had
 * no `onError` and nothing rendered `disable.isError` — a failed Disable was
 * silent and the only signal was the badge, which does not change until the
 * server confirms (so it kept saying "sampling" with no explanation).
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
	cleanup,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { OnlineEvalsManager } from "./OnlineEvalsManager";

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

const POLICY = {
	policy: {
		id: "p1",
		enabled: true,
		rubric_kind: "builtin",
		rubric: "answers_the_question",
		judge_model: "claude-haiku-4-5-20251001",
		sample_rate: 0.01,
		judge_budget_usd_monthly: 25,
		created_at: "2026-09-01T00:00:00Z",
		updated_at: "2026-09-01T00:00:00Z",
	},
	max_sample_rate: 0.1,
	built_in_rubrics: ["answers_the_question"],
};

function jsonRes(body: unknown, status = 200) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json" },
	});
}

function mount() {
	const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
		const method = init?.method ?? "GET";
		if (method === "DELETE") {
			return jsonRes({ error: "gateway unavailable" }, 503);
		}
		if (url.includes("/summary")) {
			return jsonRes({
				window_hours: 24,
				configured_sample_rate: 0.01,
				enabled: true,
				achieved_sample_rate: null,
				eligible_spans: 0,
				sampled_traces: 0,
				scored: 0,
				errored: 0,
				mean_score: null,
				judge_cost_usd: null,
				judge_budget_usd_monthly: 25,
			});
		}
		if (url.includes("/scores")) {
			return jsonRes({ scores: [] });
		}
		return jsonRes(POLICY);
	});
	vi.stubGlobal("fetch", fetchMock);
	const client = new QueryClient({
		defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
	});
	render(
		<QueryClientProvider client={client}>
			<OnlineEvalsManager />
		</QueryClientProvider>,
	);
	return fetchMock;
}

it("renders the Disable failure and leaves the badge saying sampling", async () => {
	mount();
	const disableButton = await screen.findByText("Disable");
	fireEvent.click(disableButton);

	// The failure must be visible, not silent.
	await waitFor(() =>
		expect(screen.getByRole("alert").textContent).toMatch(
			/gateway unavailable/,
		),
	);
	// The badge must NOT flip to "disabled" on a failed call — only a
	// server-confirmed state change may change it.
	expect(screen.getByText("Sampling")).toBeTruthy();
	expect(screen.queryByText("Disabled")).toBeNull();
});

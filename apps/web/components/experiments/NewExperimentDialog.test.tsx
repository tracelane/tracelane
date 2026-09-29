// @vitest-environment jsdom
import {
	cleanup,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { NewExperimentDialog } from "./NewExperimentDialog";
const fetcher = vi.fn();
beforeEach(() => {
	fetcher.mockReset();
	vi.stubGlobal("fetch", fetcher);
});
afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});
function open() {
	render(
		<NewExperimentDialog
			datasets={[{ dataset_id: "ds", name: "Cases", items: 2 }]}
			prompts={[{ name: "Support", active: [] }]}
			disabledReason={null}
		/>,
	);
	fireEvent.click(screen.getByRole("button", { name: "+ New experiment" }));
	fireEvent.change(screen.getByLabelText("Name"), {
		target: { value: "Trial" },
	});
}
function kind(value: string) {
	fireEvent.change(screen.getByLabelText("Scorer 1 kind"), {
		target: { value },
	});
}
function mockResponses(status = 202) {
	fetcher.mockImplementation(
		async (path: string) =>
			new Response(
				JSON.stringify(
					path.startsWith("/api/prompts")
						? {
								prompt_version_id: path.includes("production")
									? "prod"
									: "stage",
							}
						: status === 202
							? { experiment_id: "exp" }
							: {
									error: "entitlement_required",
									message:
										"Judges require this workspace to have judge access.",
								},
				),
				{ status: path.startsWith("/api/prompts") ? 200 : status },
			),
	);
}
it("offers judge and character bounds", () => {
	open();
	expect(screen.getByRole("option", { name: "llm_judge" })).toBeTruthy();
	expect(screen.getByRole("option", { name: "length_bounds" })).toBeTruthy();
});
it("sends a built-in rubric, judging model and threshold with metering explained", async () => {
	mockResponses();
	open();
	kind("llm_judge");
	fireEvent.change(screen.getByLabelText("Scorer 1 judging model"), {
		target: { value: "gpt-4o-mini" },
	});
	fireEvent.change(screen.getByLabelText("Scorer 1 minimum score"), {
		target: { value: "0.7" },
	});
	expect(screen.getByText(/eval_runs/)).toBeTruthy();
	fireEvent.click(screen.getByRole("button", { name: "Run experiment" }));
	await waitFor(() =>
		expect(fetcher.mock.calls.some(([p]) => p === "/api/experiments")).toBe(
			true,
		),
	);
	expect(
		JSON.parse(
			fetcher.mock.calls.find(([p]) => p === "/api/experiments")?.[1].body,
		).assertions,
	).toEqual([
		{
			kind: "llm_judge",
			rubric: { source: "built_in", name: "answers_the_question" },
			model: "gpt-4o-mini",
			min_score: 0.7,
		},
	]);
});
it("sends character bounds and accepts a zero minimum", async () => {
	mockResponses();
	open();
	kind("length_bounds");
	fireEvent.change(screen.getByLabelText("Scorer 1 minimum characters"), {
		target: { value: "0" },
	});
	fireEvent.change(screen.getByLabelText("Scorer 1 maximum characters"), {
		target: { value: "80" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Run experiment" }));
	await waitFor(() =>
		expect(fetcher.mock.calls.some(([p]) => p === "/api/experiments")).toBe(
			true,
		),
	);
	expect(
		JSON.parse(
			fetcher.mock.calls.find(([p]) => p === "/api/experiments")?.[1].body,
		).assertions,
	).toEqual([{ kind: "length_bounds", min_chars: 0, max_chars: 80 }]);
});
it("refuses inverted bounds instead of silently dropping the scorer", async () => {
	mockResponses();
	open();
	kind("length_bounds");
	fireEvent.change(screen.getByLabelText("Scorer 1 minimum characters"), {
		target: { value: "90" },
	});
	fireEvent.change(screen.getByLabelText("Scorer 1 maximum characters"), {
		target: { value: "80" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Run experiment" }));
	expect(await screen.findByText(/minimum cannot exceed/)).toBeTruthy();
	expect(fetcher.mock.calls.some(([p]) => p === "/api/experiments")).toBe(
		false,
	);
});
it("renders the gateway judge entitlement refusal", async () => {
	mockResponses(403);
	open();
	kind("llm_judge");
	fireEvent.change(screen.getByLabelText("Scorer 1 minimum score"), {
		target: { value: "0.7" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Run experiment" }));
	expect(
		await screen.findByText(
			"Judges require this workspace to have judge access.",
		),
	).toBeTruthy();
});
it("resolves a workspace rubric prompt before sending its version", async () => {
	mockResponses();
	open();
	kind("llm_judge");
	fireEvent.change(screen.getByLabelText("Scorer 1 rubric"), {
		target: { value: "prompt_version" },
	});
	fireEvent.change(screen.getByLabelText("Scorer 1 minimum score"), {
		target: { value: "0" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Run experiment" }));
	await waitFor(() =>
		expect(fetcher.mock.calls.some(([p]) => p === "/api/experiments")).toBe(
			true,
		),
	);
	expect(
		JSON.parse(
			fetcher.mock.calls.find(([p]) => p === "/api/experiments")?.[1].body,
		).assertions,
	).toEqual([
		{
			kind: "llm_judge",
			rubric: { source: "prompt_version", prompt_version_id: "prod" },
			min_score: 0,
		},
	]);
});
it.each(["", "-0.1", "1.1"])(
	"rejects missing or out-of-range judge score %s",
	async (value) => {
		mockResponses();
		open();
		kind("llm_judge");
		fireEvent.change(screen.getByLabelText("Scorer 1 minimum score"), {
			target: { value },
		});
		fireEvent.click(screen.getByRole("button", { name: "Run experiment" }));
		expect(
			await screen.findByText("Judge minimum score must be between 0 and 1."),
		).toBeTruthy();
		expect(fetcher.mock.calls.some(([p]) => p === "/api/experiments")).toBe(
			false,
		);
	},
);

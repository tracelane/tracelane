import reference from "@/db/plans.v3.json";
// @vitest-environment jsdom
import {
	cleanup,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { PlaygroundForm } from "./PlaygroundForm";
afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
	localStorage.clear();
});
Object.defineProperty(HTMLDialogElement.prototype, "showModal", {
	configurable: true,
	value: function () {
		this.setAttribute("open", "");
	},
});
Object.defineProperty(HTMLDialogElement.prototype, "close", {
	configurable: true,
	value: function () {
		this.removeAttribute("open");
	},
});
const limits = reference.policy.playground_limits;
it("runs multiple message/model columns and keeps a failed column beside a success", async () => {
	const fetch = vi.fn().mockImplementation(
		async (url: string, _init?: RequestInit) =>
			new Response(
				JSON.stringify(
					url.includes("/cost?")
						? { state: "unpriced" }
						: {
								columns: [
									{
										ok: true,
										status: 200,
										trace_id: "a",
										latency_ms: 25,
										response: {
											content: "Success answer",
											model: "a",
											usage: { prompt_tokens: 4, completion_tokens: 0 },
											tool_calls: [],
											finish_reason: "stop",
										},
									},
									{
										ok: false,
										status: 402,
										trace_id: "b",
										latency_ms: 2,
										error: {
											error: "budget_exceeded",
											message: "Budget exceeded",
										},
									},
								],
							},
				),
				{ headers: { "content-type": "application/json" } },
			),
	);
	vi.stubGlobal("fetch", fetch);
	render(
		<PlaygroundForm
			models={[{ value: "a", label: "A" }]}
			limits={limits}
			canRun
			canSave
		/>,
	);
	fireEvent.change(screen.getByLabelText("Message 1"), {
		target: { value: "Hello {{name}}" },
	});
	fireEvent.click(screen.getByText("Add message"));
	fireEvent.change(screen.getByLabelText("Message 2"), {
		target: { value: "Second" },
	});
	fireEvent.click(screen.getByText("Add model"));
	fireEvent.change(screen.getByLabelText("Model 2"), {
		target: { value: "b" },
	});
	expect(
		(screen.getByRole("button", { name: "Run all" }) as HTMLButtonElement)
			.disabled,
	).toBe(true);
	fireEvent.change(screen.getByLabelText("Variable name"), {
		target: { value: "World" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Run all" }));
	await screen.findByText("Success answer");
	expect(screen.getByText(/"message": "Budget exceeded"/)).toBeTruthy();
	const call = fetch.mock.calls.find((c) => c[0] === "/api/playground");
	expect(JSON.parse(call?.[1]?.body as string).columns).toHaveLength(2);
	expect(JSON.parse(call?.[1]?.body as string).messages).toHaveLength(2);
	await screen.findByText("Unpriced model");
});
it("blocks viewer runs and saves only the unrendered system prompt", async () => {
	const fetch = vi.fn().mockResolvedValue(
		new Response(JSON.stringify({ version_number: 7 }), {
			status: 201,
			headers: { "content-type": "application/json" },
		}),
	);
	vi.stubGlobal("fetch", fetch);
	render(
		<PlaygroundForm
			models={[{ value: "a", label: "A" }]}
			limits={limits}
			canRun={false}
			canSave
		/>,
	);
	expect(
		(screen.getByRole("button", { name: "Run all" }) as HTMLButtonElement)
			.disabled,
	).toBe(true);
	fireEvent.change(screen.getByLabelText("System prompt"), {
		target: { value: "Be kind to {{name}}" },
	});
	fireEvent.click(
		screen.getByRole("button", { name: "Save as prompt version" }),
	);
	fireEvent.change(screen.getByLabelText("Prompt name"), {
		target: { value: "assistant" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Save version" }));
	await screen.findByText("Saved v7");
	expect(JSON.parse(fetch.mock.calls[0]?.[1]?.body)).toEqual({
		content: "Be kind to {{name}}",
		model_pin: "a",
		template_variables: ["name"],
	});
});

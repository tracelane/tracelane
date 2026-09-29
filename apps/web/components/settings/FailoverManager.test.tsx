// @vitest-environment jsdom
/** GWY-52 §4 states, rendered: default chain, own chain, read-only, error ≠ empty, save body, refusal. */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
	cleanup,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { FailoverManager } from "./FailoverManager";

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

function mount(handler: (url: string, init?: RequestInit) => Response) {
	const f = vi.fn(async (url: string, init?: RequestInit) =>
		handler(url, init),
	);
	vi.stubGlobal("fetch", f);
	const client = new QueryClient({
		defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
	});
	render(
		<QueryClientProvider client={client}>
			<FailoverManager operatorChain={["claude-x", "gpt-y"]} />
		</QueryClientProvider>,
	);
	return f;
}

it("no chain of its own: says the default chain is used", async () => {
	mount(() =>
		Response.json({ enabled: false, models: [], max: 5, can_edit: true }),
	);
	expect(
		await screen.findByText(/Using the default chain: claude-x → gpt-y/),
	).toBeTruthy();
	expect(screen.getByTestId("failover-count").textContent).toBe("0 of 5");
});

it("an owner turns it on, adds a model, and saves exactly that", async () => {
	const f = mount((_u, init) =>
		init?.method === "PUT"
			? Response.json({ enabled: true, models: ["gpt-4o-mini"] })
			: Response.json({ enabled: false, models: [], max: 5, can_edit: true }),
	);
	await screen.findByText(/Using the default chain/);
	fireEvent.click(screen.getByRole("checkbox"));
	fireEvent.change(screen.getByLabelText("Add a fallback model"), {
		target: { value: "gpt-4o-mini" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Add" }));
	fireEvent.click(screen.getByRole("button", { name: "Save failover" }));
	await waitFor(() =>
		expect(
			f.mock.calls.some(
				([, i]) => (i as RequestInit | undefined)?.method === "PUT",
			),
		).toBe(true),
	);
	const put = f.mock.calls.find(
		([, i]) => (i as RequestInit | undefined)?.method === "PUT",
	);
	expect(JSON.parse((put?.[1] as RequestInit).body as string)).toEqual({
		enabled: true,
		models: ["gpt-4o-mini"],
	});
});

it("a non-owner sees it read-only", async () => {
	mount(() =>
		Response.json({
			enabled: true,
			models: [{ model: "gpt-4o-mini", provider: "openai" }],
			max: 5,
			can_edit: false,
		}),
	);
	expect(await screen.findByText("gpt-4o-mini")).toBeTruthy();
	expect((screen.getByRole("checkbox") as HTMLInputElement).disabled).toBe(
		true,
	);
	expect(screen.queryByRole("button", { name: "Save failover" })).toBeNull();
});

it("a read failure is an error with retry, never the default-chain text", async () => {
	mount(() => Response.json({ error: "x" }, { status: 502 }));
	expect(await screen.findByRole("alert")).toBeTruthy();
	expect(screen.queryByText(/Using the default chain/)).toBeNull();
});

it("a refused save shows the reason", async () => {
	mount((_u, init) =>
		init?.method === "PUT"
			? Response.json({ error: "unroutable_model" }, { status: 400 })
			: Response.json({ enabled: false, models: [], max: 5, can_edit: true }),
	);
	await screen.findByText(/Using the default chain/);
	fireEvent.click(screen.getByRole("checkbox"));
	fireEvent.click(screen.getByRole("button", { name: "Save failover" }));
	expect(
		await screen.findByText(/does not route to any provider/),
	).toBeTruthy();
});

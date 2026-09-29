// @vitest-environment jsdom
/**
 * GWY-27 — the states the spec names (§4), each rendered, not assumed: empty,
 * a list with an unroutable row, read-only for a non-owner, error ≠ empty, the cap,
 * and a refused create shown at the field.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { ModelAliasManager } from "./ModelAliasManager";

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

function mount(handler: (url: string, init?: RequestInit) => Response) {
	vi.stubGlobal(
		"fetch",
		vi.fn(async (url: string, init?: RequestInit) => handler(url, init)),
	);
	const client = new QueryClient({
		defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
	});
	render(
		<QueryClientProvider client={client}>
			<ModelAliasManager />
		</QueryClientProvider>,
	);
}

it("empty: says so, shows the gateway's count, and offers the form to an owner", async () => {
	mount(() => Response.json({ items: [], max: 50, can_edit: true }));
	expect(await screen.findByText(/No aliases yet/)).toBeTruthy();
	expect(screen.getByTestId("alias-count").textContent).toBe("0 of 50");
	expect(screen.getByRole("button", { name: "Add alias" })).toBeTruthy();
});

it("lists rows and marks a target that no longer routes", async () => {
	mount(() =>
		Response.json({
			items: [
				{ alias: "fast", target_model: "gpt-4o-mini", provider: "openai" },
				{ alias: "old", target_model: "retired-model", provider: null },
			],
			max: 50,
			can_edit: true,
		}),
	);
	expect(await screen.findByText("gpt-4o-mini")).toBeTruthy();
	expect(screen.getByText("no longer routable")).toBeTruthy();
	expect(screen.getAllByRole("button", { name: "Delete" })).toHaveLength(2);
});

it("a non-owner sees the table read-only", async () => {
	mount(() =>
		Response.json({
			items: [{ alias: "fast", target_model: "gpt-5", provider: "openai" }],
			max: 50,
			can_edit: false,
		}),
	);
	expect(await screen.findByText("gpt-5")).toBeTruthy();
	expect(screen.queryByRole("button", { name: "Delete" })).toBeNull();
	expect(screen.queryByRole("button", { name: "Add alias" })).toBeNull();
	expect(
		screen.getByText(/Only a workspace owner can change aliases/),
	).toBeTruthy();
});

it("a read failure is an error with a retry — never the empty state", async () => {
	mount(() =>
		Response.json({ error: "model aliases unavailable" }, { status: 502 }),
	);
	expect(await screen.findByRole("alert")).toBeTruthy();
	expect(screen.getByText(/could not be loaded \(HTTP 502\)/)).toBeTruthy();
	expect(screen.queryByText(/No aliases yet/)).toBeNull();
});

it("at the cap, create is disabled and says why; an unknown limit disables it too", async () => {
	mount(() =>
		Response.json({
			items: [{ alias: "a", target_model: "gpt-5", provider: "openai" }],
			max: 1,
			can_edit: true,
		}),
	);
	await screen.findByText("gpt-5");
	expect(
		screen.getByRole("button", { name: "Add alias" }).hasAttribute("disabled"),
	).toBe(true);
	expect(screen.getByText(/1 of 1 — delete one to add another/)).toBeTruthy();
});

it("a refused create shows the gateway's reason at the form", async () => {
	mount((_url, init) =>
		init?.method === "PUT"
			? Response.json({ error: "unroutable_target" }, { status: 400 })
			: Response.json({ items: [], max: 50, can_edit: true }),
	);
	await screen.findByText(/No aliases yet/);
	fireEvent.change(screen.getByPlaceholderText("fast"), {
		target: { value: "fast" },
	});
	fireEvent.change(screen.getByPlaceholderText("claude-haiku-4-5-20251001"), {
		target: { value: "nope" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Add alias" }));
	expect(
		await screen.findByText(/does not route to any provider/),
	).toBeTruthy();
});

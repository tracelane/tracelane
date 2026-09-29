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
import { ApiKeyManager } from "./ApiKeyManager";

beforeEach(() => {
	Object.defineProperty(HTMLDialogElement.prototype, "showModal", {
		configurable: true,
		value(this: HTMLDialogElement) {
			this.open = true;
		},
	});
	Object.defineProperty(HTMLDialogElement.prototype, "close", {
		configurable: true,
		value(this: HTMLDialogElement) {
			this.open = false;
		},
	});
});
afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

it("rotates with a chosen grace window and reveals the successor only until dismissed", async () => {
	const key = {
		id: "key-old",
		name: "Production",
		keyPrefix: "old123",
		createdAt: "2026-09-01T00:00:00Z",
		lastUsedAt: null,
		scope: ["read"],
		expiresAt: null,
	};
	const fetcher = vi.fn(async (url: string, init?: RequestInit) => {
		if (url.endsWith("/rotation-policy"))
			return Response.json({ graceHours: 24 });
		if (init?.method === "POST")
			return Response.json(
				{
					...key,
					id: "key-new",
					rawKey: "tlane_unit_test_successor",
					oldKeyRevokedAt: "2026-09-23T00:00:00Z",
				},
				{ status: 201 },
			);
		return Response.json([key]);
	});
	vi.stubGlobal("fetch", fetcher);
	const client = new QueryClient({
		defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
	});
	render(
		<QueryClientProvider client={client}>
			<ApiKeyManager viewer={{ role: "owner", userId: "user_owner" }} />
		</QueryClientProvider>,
	);
	fireEvent.click(await screen.findByRole("button", { name: "Rotate" }));
	const grace = await screen.findByLabelText("Grace period (hours)");
	await waitFor(() => expect((grace as HTMLInputElement).value).toBe("24"));
	fireEvent.change(grace, { target: { value: "2" } });
	fireEvent.click(screen.getByRole("button", { name: "Rotate key" }));
	await screen.findByText("tlane_unit_test_successor");
	expect(screen.getByText(/Sep 23, 2026 · 00:00 UTC/)).toBeTruthy();
	expect(fetcher).toHaveBeenCalledWith(
		"/api/settings/api-keys/key-old/rotate",
		expect.objectContaining({
			method: "POST",
			body: JSON.stringify({ graceHours: 2 }),
		}),
	);
	fireEvent.click(screen.getByRole("button", { name: "I've saved it" }));
	expect(screen.queryByText("tlane_unit_test_successor")).toBeNull();
	client.clear();
});

it("keeps the rotation dialog open with a readable refusal and no successor", async () => {
	vi.stubGlobal(
		"fetch",
		vi.fn(async (url: string, init?: RequestInit) => {
			if (url.endsWith("/rotation-policy"))
				return Response.json({ graceHours: 24 });
			if (init?.method === "POST")
				return Response.json(
					{ error: "workspace owner required" },
					{ status: 403 },
				);
			return Response.json([
				{
					id: "old",
					name: "Production",
					keyPrefix: "test01",
					createdAt: "2026-09-01T00:00:00Z",
					lastUsedAt: null,
					scope: ["read"],
				},
			]);
		}),
	);
	const client = new QueryClient({
		defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
	});
	render(
		<QueryClientProvider client={client}>
			<ApiKeyManager viewer={{ role: "owner", userId: "user_owner" }} />
		</QueryClientProvider>,
	);
	fireEvent.click(await screen.findByRole("button", { name: /^Rotate$/ }));
	await waitFor(() =>
		expect(
			(screen.getByLabelText("Grace period (hours)") as HTMLInputElement).value,
		).toBe("24"),
	);
	fireEvent.click(screen.getByRole("button", { name: "Rotate key" }));
	expect((await screen.findByRole("alert")).textContent).toContain(
		"workspace owner required",
	);
	expect(screen.queryByText("Copy now — shown once")).toBeNull();
	client.clear();
});

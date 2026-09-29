// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
	act,
	cleanup,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { afterEach, beforeAll, expect, it, vi } from "vitest";
import { ProviderKeyManager } from "./ProviderKeyManager";

beforeAll(() => {
	Object.defineProperty(HTMLDialogElement.prototype, "showModal", {
		configurable: true,
		value: function (this: HTMLDialogElement) {
			this.setAttribute("open", "");
		},
	});
	Object.defineProperty(HTMLDialogElement.prototype, "close", {
		configurable: true,
		value: function (this: HTMLDialogElement) {
			this.removeAttribute("open");
		},
	});
});

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

it("shows saved UTC separately from validation and records a requested check", async () => {
	const row = {
		provider_id: "anthropic",
		last4: "test",
		saved_at: "2026-09-20T10:00:00Z",
		last_validation: null,
		last_rejected_at: "2026-09-21T11:00:00Z",
		rejection_history_available: true,
	};
	const fetcher = vi.fn(async (_url: string, init?: RequestInit) =>
		init?.method === "POST"
			? Response.json({
					status: "valid",
					saved_at: "2026-09-20T10:00:00Z",
					reason: "authenticated",
					checked_at: "2026-09-22T12:00:00Z",
				})
			: Response.json([row]),
	);
	vi.stubGlobal("fetch", fetcher);
	const client = new QueryClient({
		defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
	});
	render(
		<QueryClientProvider client={client}>
			<ProviderKeyManager canManage />
		</QueryClientProvider>,
	);
	expect(
		await screen.findByText(/Saved Sep 20, 2026 · 10:00 UTC/),
	).toBeTruthy();
	expect(
		screen.getByText(/Last rejected Sep 21, 2026 · 11:00 UTC/),
	).toBeTruthy();
	expect(screen.getByText(/Not validated/)).toBeTruthy();
	fireEvent.click(screen.getByRole("button", { name: "Validate now" }));
	expect(
		await screen.findByText(/Valid Sep 22, 2026 · 12:00 UTC/),
	).toBeTruthy();
	expect(fetcher).toHaveBeenCalledWith(
		"/api/settings/provider-keys/anthropic/validate",
		expect.objectContaining({ method: "POST" }),
	);
	client.clear();
});

it("keeps missing validation and unavailable rejection history explicit", async () => {
	vi.stubGlobal(
		"fetch",
		vi.fn(async () =>
			Response.json([
				{
					provider_id: "anthropic",
					last4: "test",
					saved_at: "2026-09-20T10:00:00Z",
					last_validation: null,
					last_rejected_at: null,
					rejection_history_available: false,
				},
			]),
		),
	);
	const client = new QueryClient({
		defaultOptions: { queries: { retry: false } },
	});
	render(
		<QueryClientProvider client={client}>
			<ProviderKeyManager canManage />
		</QueryClientProvider>,
	);
	expect(await screen.findByText(/Rejection history unavailable/)).toBeTruthy();
	expect(screen.queryByText(/^Valid /)).toBeNull();
	client.clear();
});

it("does not attach a completed check to a replacement saved during the request", async () => {
	const old = {
		provider_id: "anthropic",
		last4: "test",
		saved_at: "2026-09-20T10:00:00Z",
		last_validation: null,
	};
	let finish: (response: Response) => void = () => {
		throw new Error("request not started");
	};
	vi.stubGlobal(
		"fetch",
		vi.fn(async (_url: string, init?: RequestInit) =>
			init?.method === "POST"
				? new Promise<Response>((resolve) => {
						finish = resolve;
					})
				: Response.json([old]),
		),
	);
	const client = new QueryClient({
		defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
	});
	render(
		<QueryClientProvider client={client}>
			<ProviderKeyManager canManage />
		</QueryClientProvider>,
	);
	fireEvent.click(await screen.findByRole("button", { name: "Validate now" }));
	await screen.findByRole("button", { name: "Validating…" });
	act(() => {
		client.setQueryData(
			["provider-keys"],
			[{ ...old, last4: "next", saved_at: "2026-09-22T12:01:00Z" }],
		);
	});
	await act(async () => {
		finish(
			Response.json({
				status: "valid",
				saved_at: "2026-09-20T10:00:00Z",
				reason: "authenticated",
				checked_at: "2026-09-22T12:00:00Z",
			}),
		);
	});
	await waitFor(() =>
		expect(
			(
				screen.getByRole("button", {
					name: "Validate now",
				}) as HTMLButtonElement
			).disabled,
		).toBe(false),
	);
	expect(screen.queryByText(/^Valid /)).toBeNull();
	expect(screen.getByText("Not validated")).toBeTruthy();
	client.clear();
});

it("explains public catalogs and Bedrock's absent tenant credential", async () => {
	vi.stubGlobal(
		"fetch",
		vi.fn(async () =>
			Response.json([
				{
					provider_id: "openrouter",
					last4: "test",
					saved_at: "2026-09-20T10:00:00Z",
					last_validation: {
						status: "cannot_validate",
						reason: "public_catalog",
						checked_at: "2026-09-22T12:00:00Z",
					},
				},
				{
					provider_id: "bedrock",
					last4: "test",
					saved_at: "2026-09-20T10:00:00Z",
					last_validation: null,
					last_rejected_at: "2026-09-22T11:59:00Z",
				},
			]),
		),
	);
	const client = new QueryClient({
		defaultOptions: { queries: { retry: false } },
	});
	render(
		<QueryClientProvider client={client}>
			<ProviderKeyManager canManage />
		</QueryClientProvider>,
	);
	expect(
		await screen.findByText(
			/Cannot validate .*public model catalog accepts invalid credentials/,
		),
	).toBeTruthy();
	expect(screen.getByText(/No tenant credential to validate/)).toBeTruthy();
	expect(screen.queryByText(/Last rejected/)).toBeNull();
	expect(screen.queryByText(/unsupported/i)).toBeNull();
	client.clear();
});

it("does not ask for an unused Bedrock API key", async () => {
	vi.stubGlobal(
		"fetch",
		vi.fn(async () => Response.json([])),
	);
	const client = new QueryClient({
		defaultOptions: { queries: { retry: false } },
	});
	render(
		<QueryClientProvider client={client}>
			<ProviderKeyManager canManage />
		</QueryClientProvider>,
	);
	fireEvent.click(
		await screen.findByRole("button", { name: /Add provider key/ }),
	);
	fireEvent.change(screen.getByLabelText("Provider"), {
		target: { value: "bedrock" },
	});
	expect(
		screen.getByText(/No tenant credential to validate. Bedrock uses/),
	).toBeTruthy();
	expect(screen.queryByLabelText("API key")).toBeNull();
	expect(
		(screen.getByRole("button", { name: "Save key" }) as HTMLButtonElement)
			.disabled,
	).toBe(true);
	client.clear();
});

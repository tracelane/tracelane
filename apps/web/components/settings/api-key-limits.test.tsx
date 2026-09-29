// @vitest-environment jsdom
/**
 * SET-38 B3 / B6 on the key list:
 *   - `canEditKeyLimits` — the "who may edit this key's limits" rule the edit
 *     drawer (B4) will use. It must mirror the gateway's `key_editor`, and fail
 *     CLOSED on anything it does not recognise. Must-reject beside must-accept.
 *   - Revoke — the confirm copy says what the code now does ("on its next
 *     request", B-586), never the old "within 60 seconds", and the click reaches
 *     the proxy as a DELETE.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
	cleanup,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	ApiKeyManager,
	type ApiKeyRow,
	canEditKeyLimits,
} from "./ApiKeyManager";

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

const row = (mintedBy: string | null): ApiKeyRow => ({
	id: "key-1",
	name: "ci-nightly",
	keyPrefix: "ab12cd",
	createdAt: "2026-09-01T00:00:00Z",
	lastUsedAt: null,
	mintedBy,
	scope: ["chat"],
});

describe("canEditKeyLimits (SET-38 §2)", () => {
	it.each([
		["owner", "someone-else"],
		["admin", "someone-else"],
		["owner", null],
	])("ACCEPT: an %s may edit any key (minted by %s)", (role, mintedBy) => {
		expect(canEditKeyLimits({ role, userId: "me" }, row(mintedBy))).toBe(true);
	});

	it("ACCEPT: a member may edit a key THEY minted", () => {
		expect(canEditKeyLimits({ role: "member", userId: "me" }, row("me"))).toBe(
			true,
		);
	});

	it.each([
		["member", "someone-else"],
		["member", null],
		["viewer", "me"],
		[null, "me"],
		["", "me"],
		["Owner", "me"],
		["superuser", "me"],
	])("REJECT: a %s may not edit a key minted by %s", (role, mintedBy) => {
		expect(
			canEditKeyLimits(
				{ role: role as string | null, userId: "me" },
				row(mintedBy),
			),
		).toBe(false);
	});
});

describe("Revoke (B-586)", () => {
	it("confirms with the honest copy and sends a DELETE to the proxy", async () => {
		const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
		const fetcher = vi.fn(async (_url: string, init?: RequestInit) => {
			if (init?.method === "DELETE") return new Response(null, { status: 204 });
			return Response.json([row("me")]);
		});
		vi.stubGlobal("fetch", fetcher);
		const client = new QueryClient({
			defaultOptions: {
				queries: { retry: false },
				mutations: { retry: false },
			},
		});
		render(
			<QueryClientProvider client={client}>
				<ApiKeyManager viewer={{ role: "owner", userId: "me" }} />
			</QueryClientProvider>,
		);
		fireEvent.click(await screen.findByRole("button", { name: "Revoke" }));
		const text = confirm.mock.calls[0]?.[0] ?? "";
		expect(text).toContain("stops working on its next request");
		expect(text).not.toContain("60 seconds");
		await waitFor(() =>
			expect(fetcher).toHaveBeenCalledWith(
				"/api/settings/api-keys/key-1",
				expect.objectContaining({ method: "DELETE" }),
			),
		);
		client.clear();
	});

	it("a refused revoke shows the proxy's reason, not a bare status", async () => {
		vi.spyOn(window, "confirm").mockReturnValue(true);
		vi.stubGlobal(
			"fetch",
			vi.fn(async (_url: string, init?: RequestInit) => {
				if (init?.method === "DELETE")
					return Response.json(
						{ error: "Only a workspace owner can revoke API keys" },
						{ status: 403 },
					);
				return Response.json([row("me")]);
			}),
		);
		const client = new QueryClient({
			defaultOptions: {
				queries: { retry: false },
				mutations: { retry: false },
			},
		});
		render(
			<QueryClientProvider client={client}>
				<ApiKeyManager viewer={{ role: "member", userId: "me" }} />
			</QueryClientProvider>,
		);
		fireEvent.click(await screen.findByRole("button", { name: "Revoke" }));
		expect((await screen.findByRole("alert")).textContent).toContain(
			"Only a workspace owner can revoke API keys",
		);
		client.clear();
	});
});

describe("Limits label follows the budget's reset window (B-586 half 2)", () => {
	it.each([
		["daily", "$50.00/day"],
		["weekly", "$50.00/week"],
		["monthly", "$50.00/mo"],
	] as const)("a %s budget reads %s", async (budgetReset, text) => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () =>
				Response.json([{ ...row("me"), budgetUsdMonthly: "50", budgetReset }]),
			),
		);
		const client = new QueryClient({
			defaultOptions: { queries: { retry: false } },
		});
		render(
			<QueryClientProvider client={client}>
				<ApiKeyManager viewer={{ role: "owner", userId: "me" }} />
			</QueryClientProvider>,
		);
		expect(
			await screen.findByText(new RegExp(text.replace("$", "\\$"))),
		).toBeTruthy();
		if (budgetReset !== "monthly") {
			expect(screen.queryByText(/\/mo\b/)).toBeNull();
		}
	});
});

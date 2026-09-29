// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { TeamManager } from "./TeamManager";

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

it.each([
	["role_forbidden", 403, /Only a current owner can change team members/],
	["last_owner_protected", 409, /Keep at least one owner/],
	["membership_change_unavailable", 503, /Refresh the team before retrying/],
] as const)("explains a refused removal: %s", async (error, status, copy) => {
	vi.stubGlobal("confirm", () => true);
	vi.stubGlobal(
		"fetch",
		vi.fn(async (url: string, init?: RequestInit) => {
			if (init?.method === "DELETE")
				return Response.json({ error }, { status });
			return Response.json(
				url.endsWith("invitations")
					? []
					: [
							{
								id: "other",
								userId: "other",
								email: "other@example.invalid",
								name: "Other owner",
								role: "owner",
								joinedAt: "2026-09-22T00:00:00Z",
							},
						],
			);
		}),
	);
	const client = new QueryClient({
		defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
	});
	render(
		<QueryClientProvider client={client}>
			<TeamManager membersMax={5} currentUserId="self" canManage />
		</QueryClientProvider>,
	);
	fireEvent.click(await screen.findByRole("button", { name: "Remove" }));
	expect(await screen.findByText(copy)).toBeTruthy();
	client.clear();
});

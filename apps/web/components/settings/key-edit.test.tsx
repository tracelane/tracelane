// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
	cleanup,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { ApiKeyManager } from "./ApiKeyManager";
afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
	window.history.replaceState(null, "", "/");
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
const row = {
	id: "key",
	name: "Production",
	keyPrefix: "tlane_test",
	scope: null,
	createdAt: "2026-01-01T00:00:00Z",
	lastUsedAt: null,
	budgetUsdMonthly: 20,
	budgetReset: "monthly",
	rateLimitRpm: 10,
	expiresAt: null,
	velocityBreaker: false,
	mintedBy: "me",
};
function setup(role = "owner") {
	const fetch = vi.fn().mockImplementation(
		async (url: string, init?: RequestInit) =>
			new Response(
				JSON.stringify(
					init?.method === "PATCH"
						? {
								...row,
								budgetUsdMonthly: null,
								changed: ["budget_usd_monthly"],
							}
						: url.endsWith("/key")
							? {
									...row,
									spend: {
										window: "month",
										window_starts_at: "2026-09-01T00:00:00Z",
										recorded_usd: 12.4,
									},
								}
							: [row],
				),
				{ headers: { "content-type": "application/json" } },
			),
	);
	vi.stubGlobal("fetch", fetch);
	const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
	render(
		<QueryClientProvider client={qc}>
			<ApiKeyManager viewer={{ role, userId: "me" }} />
		</QueryClientProvider>,
	);
	return fetch;
}
it("opens from the spend link and sends only changed fields, preserving legacy scope", async () => {
	window.history.replaceState(null, "", "/?key=key");
	const fetch = setup();
	await screen.findByRole("dialog");
	await screen.findByText(/Recorded spend this month/);
	fireEvent.change(screen.getByLabelText("Budget USD"), {
		target: { value: "" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Save limits" }));
	await waitFor(() =>
		expect(fetch.mock.calls.some((c) => c[1]?.method === "PATCH")).toBe(true),
	);
	const call = fetch.mock.calls.find((c) => c[1]?.method === "PATCH");
	expect(JSON.parse(call?.[1]?.body as string)).toEqual({
		budgetUsdMonthly: null,
	});
	await screen.findByText(/Limits updated/);
});
it("does not offer editing to a viewer", async () => {
	setup("viewer");
	await screen.findByText("Production");
	expect(screen.queryByRole("button", { name: "Edit limits" })).toBeNull();
});

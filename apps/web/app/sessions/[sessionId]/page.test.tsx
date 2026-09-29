import { expect, it, vi } from "vitest";
vi.mock("@/lib/auth", () => ({
	requireSession: async () => ({ role: "viewer", userId: "user" }),
}));
vi.mock("@/lib/list-page-settings", () => ({
	getListPageSettings: async () => ({
		sizes: { session_turns: 20 },
		defaulted: false,
	}),
}));
vi.mock("@/lib/sessions", () => ({ fetchSessionTranscript: vi.fn() }));
vi.mock("@/lib/gateway", () => ({
	GatewayError: class extends Error {
		constructor(public status: number) {
			super(String(status));
		}
	},
}));
import { fetchSessionTranscript } from "@/lib/sessions";
import Page from "./page";
it("keeps unknown/foreign sessions as not-found and real failures as errors", async () => {
	vi.mocked(fetchSessionTranscript).mockResolvedValueOnce(null);
	await expect(
		Page({ params: Promise.resolve({ sessionId: "foreign" }) }),
	).rejects.toThrow("not_found");
	vi.mocked(fetchSessionTranscript).mockRejectedValueOnce(
		new Error("Unavailable"),
	);
	await expect(
		Page({ params: Promise.resolve({ sessionId: "s" }) }),
	).rejects.toThrow("Unavailable");
});
it("passes the cursor and reference page size to the transcript read", async () => {
	vi.mocked(fetchSessionTranscript).mockResolvedValueOnce(null);
	await expect(
		Page({
			params: Promise.resolve({ sessionId: "s" }),
			searchParams: Promise.resolve({ cursor: "opaque" }),
		}),
	).rejects.toThrow();
	expect(fetchSessionTranscript).toHaveBeenLastCalledWith("s", {
		limit: 20,
		cursor: "opaque",
	});
});

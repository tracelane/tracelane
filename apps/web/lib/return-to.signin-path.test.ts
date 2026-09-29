/** signInPath: the page from AuthKit's `x-url` header rides to /sign-in; APIs and garbage do not. */
import { describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ url: null as string | null }));
vi.mock("next/headers", () => ({
	headers: async () => new Headers(h.url ? { "x-url": h.url } : {}),
}));

import { signInPath } from "./return-to";

describe("signInPath", () => {
	it("carries the page the expired request was for", async () => {
		h.url = "https://app.tracelane.dev/traces?model=gpt-4o";
		expect(await signInPath()).toBe(
			"/sign-in?returnTo=%2Ftraces%3Fmodel%3Dgpt-4o",
		);
	});
	it("never resumes an API route", async () => {
		h.url = "https://app.tracelane.dev/api/settings/model-aliases";
		expect(await signInPath()).toBe("/sign-in");
	});
	it("no header → plain /sign-in", async () => {
		h.url = null;
		expect(await signInPath()).toBe("/sign-in");
	});
});

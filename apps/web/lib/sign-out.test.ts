import { readFileSync } from "node:fs";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { signOutNow } from "./sign-out";
const assign = vi.fn();
beforeEach(() => vi.stubGlobal("window", { location: { assign } }));
afterEach(() => vi.unstubAllGlobals());
it("sign_out_now_navigates_to_logout_url", async () => {
	const fetcher = vi
		.fn()
		.mockResolvedValue(
			Response.json({ logout_url: "https://api.workos.com/logout" }),
		);
	vi.stubGlobal("fetch", fetcher);
	await signOutNow();
	expect(fetcher).toHaveBeenCalledWith("/sign-out", {
		method: "POST",
		credentials: "same-origin",
		cache: "no-store",
	});
	expect(assign).toHaveBeenCalledWith("https://api.workos.com/logout");
});
it("failed_post_does_not_navigate", async () => {
	vi.stubGlobal(
		"fetch",
		vi.fn().mockResolvedValue(new Response(null, { status: 403 })),
	);
	await expect(signOutNow()).rejects.toThrow();
	expect(assign).not.toHaveBeenCalled();
});
it("network_failure_does_not_navigate", async () => {
	vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network")));
	await expect(signOutNow()).rejects.toThrow();
	expect(assign).not.toHaveBeenCalled();
});
it("malformed_url_does_not_navigate", async () => {
	vi.stubGlobal(
		"fetch",
		vi
			.fn()
			.mockResolvedValue(Response.json({ logout_url: "javascript:alert(1)" })),
	);
	await expect(signOutNow()).rejects.toThrow();
	expect(assign).not.toHaveBeenCalled();
});
it("no_get_sign_out_callers_remain", () => {
	for (const p of [
		"components/layout/AccountMenu.tsx",
		"components/settings/ProfileManager.tsx",
		"components/settings/EmailChangeForm.tsx",
		"app/organization-deleted/page.tsx",
	]) {
		const src = readFileSync(new URL(`../${p}`, import.meta.url), "utf8");
		expect(src).not.toMatch(/href=["']\/sign-out|assign\(["']\/sign-out/);
	}
});

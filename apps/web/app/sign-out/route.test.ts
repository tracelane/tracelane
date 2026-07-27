/**
 * Tests for /sign-out.
 *
 * signOut() (the SDK) owns clearing the session/PKCE cookies and the WorkOS
 * logout redirect; that is exercised by the SDK's own suite. Here we assert OUR
 * route invokes it exactly once with the correct absolute `returnTo` to
 * /sign-in (and a relative fallback when the redirect-URI env is unset).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	signOut: vi.fn(async (_opts: { returnTo?: string }) => undefined),
}));

vi.mock("@workos-inc/authkit-nextjs", () => ({ signOut: h.signOut }));

import { GET } from "./route";

describe("/sign-out", () => {
	const ORIG = process.env.NEXT_PUBLIC_WORKOS_REDIRECT_URI;

	beforeEach(() => h.signOut.mockClear());
	afterEach(() => {
		if (ORIG === undefined) {
			Reflect.deleteProperty(process.env, "NEXT_PUBLIC_WORKOS_REDIRECT_URI");
		} else {
			process.env.NEXT_PUBLIC_WORKOS_REDIRECT_URI = ORIG;
		}
	});

	it("signs out with an absolute returnTo to /sign-in derived from the redirect URI", async () => {
		process.env.NEXT_PUBLIC_WORKOS_REDIRECT_URI =
			"https://tracelane-app.vercel.app/auth/callback";
		await GET();
		expect(h.signOut).toHaveBeenCalledTimes(1);
		expect(h.signOut).toHaveBeenCalledWith({
			returnTo: "https://tracelane-app.vercel.app/sign-in",
		});
	});

	it("falls back to a relative /sign-in when the redirect-URI env is unset", async () => {
		Reflect.deleteProperty(process.env, "NEXT_PUBLIC_WORKOS_REDIRECT_URI");
		await GET();
		expect(h.signOut).toHaveBeenCalledWith({ returnTo: "/sign-in" });
	});
});

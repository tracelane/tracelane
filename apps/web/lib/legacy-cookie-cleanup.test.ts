import { describe, expect, it } from "vitest";
import { legacyCookieCleanup } from "./legacy-cookie-cleanup";

// Founder ruling #1 (2026-09-28): the session cookie is now host-only on
// app.tracelane.dev. A browser that signed in before still carries the old
// `Domain=.tracelane.dev` copy beside the new one, and AuthKit's sign-out only clears
// the host-only one — so the old cookie (sent to docs / site / gateway) would linger.
describe("legacyCookieCleanup", () => {
	it("expires the .tracelane.dev copy of a wos-* cookie that arrives twice", () => {
		const out = legacyCookieCleanup(
			"a=1; wos-session=old; wos-session=new; b=2",
		);
		expect(out).toEqual([
			"wos-session=; Domain=.tracelane.dev; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax",
		]);
	});
	it("does nothing when every cookie name is unique (the normal case)", () => {
		expect(
			legacyCookieCleanup("wos-session=new; wos-auth-verifier-x=v"),
		).toEqual([]);
		expect(legacyCookieCleanup(null)).toEqual([]);
	});
	it("never touches a duplicated cookie that is not ours", () => {
		expect(legacyCookieCleanup("theme=a; theme=b")).toEqual([]);
	});
});

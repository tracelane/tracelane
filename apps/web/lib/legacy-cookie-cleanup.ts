/**
 * One-time cleanup after the session cookie became host-only (founder ruling #1,
 * 2026-09-28: `WORKOS_COOKIE_DOMAIN` deleted, so AuthKit no longer sets
 * `Domain=.tracelane.dev`). A browser that signed in before carries BOTH copies, and
 * AuthKit's sign-out clears only the host-only one — the old cookie would keep going to
 * docs, the site and the gateway until it expired.
 *
 * A browser cannot hold two cookies with the same name, domain and path, so a `wos-*`
 * name arriving twice means one of them is the legacy `.tracelane.dev` copy. Only that
 * case produces a header, and the header can only expire the `.tracelane.dev` cookie —
 * the host-only session is a different cookie and is never touched.
 */
const LEGACY_DOMAIN = ".tracelane.dev";

export function legacyCookieCleanup(cookieHeader: string | null): string[] {
	if (!cookieHeader) return [];
	const seen = new Map<string, number>();
	for (const part of cookieHeader.split(";")) {
		const name = part.split("=")[0]?.trim();
		if (name) seen.set(name, (seen.get(name) ?? 0) + 1);
	}
	return [...seen]
		.filter(([name, n]) => n > 1 && name.startsWith("wos-"))
		.map(
			([name]) =>
				`${name}=; Domain=${LEGACY_DOMAIN}; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax`,
		);
}

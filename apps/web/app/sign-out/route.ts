/**
 * Sign-out route handler — ends both the local session and the WorkOS session.
 *
 * Must be a Route Handler, not a page: AuthKit `signOut()` *clears* the session
 * and PKCE cookies, which Next.js 15 forbids in Server Components. It then
 * redirects to the WorkOS logout endpoint (`getLogoutUrl({ sessionId,
 * returnTo })`) so the WorkOS-side session is terminated and the user is not
 * silently re-authenticated on the next visit — landing back on /sign-in.
 *
 * Reached via a plain `<a href="/sign-out">` in the Sidebar (no prefetch, so
 * the GET side effect only fires on a real click).
 */

import { signOut } from "@workos-inc/authkit-nextjs";

export const dynamic = "force-dynamic";

/**
 * Absolute /sign-in URL for the post-logout return. WorkOS requires an
 * absolute `return_to`; derive the origin from the configured redirect URI so
 * it tracks the deployment (prod vs localhost). Falls back to a relative path
 * if the env var is unset (used only by the no-session branch of signOut()).
 */
function signInReturnTo(): string {
	const redirect = process.env.NEXT_PUBLIC_WORKOS_REDIRECT_URI;
	if (!redirect) return "/sign-in";
	try {
		return `${new URL(redirect).origin}/sign-in`;
	} catch {
		return "/sign-in";
	}
}

export async function GET(): Promise<void> {
	// signOut() clears cookies then redirects (throws NEXT_REDIRECT) — it never
	// returns normally. Must not be wrapped in a swallowing try/catch.
	await signOut({ returnTo: signInReturnTo() });
}

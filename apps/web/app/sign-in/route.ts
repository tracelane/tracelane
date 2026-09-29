/**
 * Sign-in route handler — redirects to the WorkOS AuthKit hosted login UI.
 *
 * Must be a Route Handler, not a page: AuthKit v4 enables PKCE, so
 * getSignInUrl() writes the `wos-auth-verifier` cookie. Next.js 15 forbids
 * cookie writes in Server Components (pages); Route Handlers permit them, and
 * the Set-Cookie rides along on the 307 redirect to WorkOS.
 */

import { safeReturnTo } from "@/lib/return-to";
import { getSignInUrl } from "@workos-inc/authkit-nextjs";
import { redirect } from "next/navigation";
import type { NextRequest } from "next/server";

// Reads request cookies + writes the PKCE cookie — never statically rendered.
export const dynamic = "force-dynamic";

/**
 * `?returnTo=/path` (2026-09-27): an expired session sends the browser here with the
 * page it was on, and AuthKit carries it through its PKCE state to the callback, so
 * signing in again resumes that page instead of the dashboard. Only a validated
 * same-origin app path is honoured (`safeReturnTo`) — never an open redirect.
 */
export async function GET(request: NextRequest) {
	const returnTo = safeReturnTo(request.nextUrl.searchParams.get("returnTo"));
	const signInUrl = await getSignInUrl(returnTo ? { returnTo } : undefined);
	redirect(signInUrl);
}

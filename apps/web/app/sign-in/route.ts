/**
 * Sign-in route handler — redirects to the WorkOS AuthKit hosted login UI.
 *
 * Must be a Route Handler, not a page: AuthKit v4 enables PKCE, so
 * getSignInUrl() writes the `wos-auth-verifier` cookie. Next.js 15 forbids
 * cookie writes in Server Components (pages); Route Handlers permit them, and
 * the Set-Cookie rides along on the 307 redirect to WorkOS.
 */

import { getSignInUrl } from "@workos-inc/authkit-nextjs";
import { redirect } from "next/navigation";

// Reads request cookies + writes the PKCE cookie — never statically rendered.
export const dynamic = "force-dynamic";

export async function GET() {
	const signInUrl = await getSignInUrl();
	redirect(signInUrl);
}

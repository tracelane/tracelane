/**
 * Next.js middleware — protects all dashboard routes via WorkOS AuthKit.
 *
 * Public paths (/, /api/auth/**) bypass auth.
 * All other paths require a valid WorkOS session.
 * tenant_id is the WorkOS organizationId from the session.
 *
 * Dev-only E2E bypass: when `e2eAuthEnabled` is true (non-prod build
 * with the opt-in flag set — see lib/e2e-auth.ts for the predicate), let the
 * request reach the page instead of redirecting to /sign-in — `lib/auth.ts`
 * then resolves the disposable test session. `e2eAuthEnabled()` THROWS in a
 * production build that carries the flag (fail-closed + loud), and importing
 * this module boot-crashes the same way, so a prod misconfig can never silently
 * bypass the auth middleware.
 */

import { refuseCrossOriginMutation } from "@/lib/csrf";
import { e2eAuthEnabled } from "@/lib/e2e-auth";
import { legacyCookieCleanup } from "@/lib/legacy-cookie-cleanup";
import { authkitMiddleware } from "@workos-inc/authkit-nextjs";
import {
	type NextFetchEvent,
	type NextRequest,
	NextResponse,
} from "next/server";

const authkit = authkitMiddleware();

export default async function middleware(
	request: NextRequest,
	event: NextFetchEvent,
) {
	// Before auth and before the E2E bypass: a cross-origin state change is refused whoever
	// is signed in (lib/csrf.ts — the session cookie rides same-site requests).
	if (refuseCrossOriginMutation(request)) {
		return NextResponse.json(
			{ error: "cross_origin_refused" },
			{ status: 403 },
		);
	}
	if (e2eAuthEnabled()) return NextResponse.next();
	const response = await authkit(request, event);
	// Expire a legacy `Domain=.tracelane.dev` session cookie left from before the
	// cookie became host-only (lib/legacy-cookie-cleanup.ts). No-op unless a wos-*
	// cookie arrives twice.
	const stale = legacyCookieCleanup(request.headers.get("cookie"));
	if (response && stale.length > 0) {
		for (const header of stale) response.headers.append("set-cookie", header);
	}
	return response;
}

export const config = {
	// Run middleware on every path except static assets and Next.js internals
	matcher: [
		"/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|ico)$).*)",
	],
};

/**
 * Next.js middleware — protects all dashboard routes via WorkOS AuthKit.
 *
 * Public paths (/, /api/auth/**) bypass auth.
 * All other paths require a valid WorkOS session.
 * tenant_id is the WorkOS organizationId from the session.
 *
 * with the opt-in flag set — see lib/e2e-auth.ts for the predicate), let the
 * request reach the page instead of redirecting to /sign-in — `lib/auth.ts`
 * then resolves the disposable test session. `e2eAuthEnabled()` THROWS in a
 * production build that carries the flag (fail-closed + loud), and importing
 * this module boot-crashes the same way, so a prod misconfig can never silently
 * bypass the auth middleware.
 */

import { e2eAuthEnabled } from "@/lib/e2e-auth";
import { authkitMiddleware } from "@workos-inc/authkit-nextjs";
import {
	type NextFetchEvent,
	type NextRequest,
	NextResponse,
} from "next/server";

const authkit = authkitMiddleware();

export default function middleware(
	request: NextRequest,
	event: NextFetchEvent,
) {
	if (e2eAuthEnabled()) return NextResponse.next();
	return authkit(request, event);
}

export const config = {
	// Run middleware on every path except static assets and Next.js internals
	matcher: [
		"/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|ico)$).*)",
	],
};

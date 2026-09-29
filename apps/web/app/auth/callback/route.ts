/**
 * WorkOS OAuth callback handler.
 *
 * WorkOS redirects here after authentication. The stock `handleAuth()` requires
 * the PKCE `state` + cookie that our app sets when IT initiates a login
 * (`/sign-in`). WorkOS-INITIATED flows — invitation accept, magic links — reach
 * this callback with a `code` but NO PKCE state/cookie, so the stock handler
 * throws "Missing required auth parameter" and renders a dead JSON error
 * ("Couldn't sign in… contact your organization admin"). That's why invited
 * users couldn't complete signup.
 *
 * Recovery: on that specific signature, bounce through `/sign-in` (which sets
 * PKCE and redirects to WorkOS). The user is already authenticated at WorkOS
 * from the invite signup, so WorkOS round-trips straight back here WITH a valid
 * state → the exchange succeeds → dashboard. Any OTHER error is a genuine
 * failure → a clean message, no redirect loop.
 */

import { handleAuth } from "@workos-inc/authkit-nextjs";
import { NextResponse } from "next/server";

export const GET = handleAuth({
	onError: async ({ error, request }) => {
		const msg = error instanceof Error ? error.message : String(error);
		console.error("[auth/callback]", msg);
		// Only the missing-PKCE-state signature is recoverable by re-initiating.
		if (
			/required auth parameter|Auth cookie missing|state mismatch/i.test(msg)
		) {
			return NextResponse.redirect(new URL("/sign-in", request.url));
		}
		// A person reads this, often on a phone — send them to a page with a way
		// forward, not a JSON body (B-561, 2026-09-27). Detail stays in the log above.
		return NextResponse.redirect(new URL("/auth/error", request.url));
	},
});

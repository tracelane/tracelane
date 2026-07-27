/**
 * Admin/owner gate for privileged settings mutations — workspace rename, team
 * invites, API-key revoke, CMK register/revoke/rotate (owner-only key
 * operations). ONE fail-closed response mapping shared by every caller:
 * WorkOS unconfigured → 501, role lookup failed → 502 (never assume),
 * non-admin → 403. Returns `null` when the caller may proceed.
 *
 * The 2026-07-22 audit found the CMK + API-key mutation routes enforcing only
 * membership (any viewer could revoke org keys or register a rogue CMK into
 * the encryption trust set) — gate every new privileged mutation through this
 * helper instead of re-deriving the mapping per route.
 */

import { callerIsOrgAdmin } from "@/lib/workos-org";
import { NextResponse } from "next/server";

/**
 * Verify the session user holds an admin/owner role in the session org.
 *
 * @returns `null` when the caller is admin/owner (proceed); otherwise the
 *   error `NextResponse` the route must return (501/502/403, fail-closed).
 */
export async function requireOrgAdmin(session: {
	tenantId: string;
	userId: string;
}): Promise<NextResponse | null> {
	const key = process.env.WORKOS_API_KEY;
	if (!key) {
		return NextResponse.json(
			{ error: "WorkOS API not configured" },
			{ status: 501 },
		);
	}
	const admin = await callerIsOrgAdmin(key, session.tenantId, session.userId);
	if (admin === null) {
		return NextResponse.json(
			{ error: "could not verify permissions" },
			{ status: 502 },
		);
	}
	if (!admin) {
		return NextResponse.json(
			{ error: "admin or owner role required" },
			{ status: 403 },
		);
	}
	return null;
}

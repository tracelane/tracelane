/**
 * DELETE /api/settings/team/invitations/[id] — revoke a pending invitation
 * (IDENTITY_TEAM_SPEC §2/§3). Owner-only, tenant-isolated.
 *
 * A revoked invitation's accept URL stops working (WorkOS-owned) — this is the
 * "a revoked invite cannot be accepted" DoD. The id is verified to belong to
 * the caller's org before any mutation (cross-org id 404s, no existence leak).
 */

import { requireSession } from "@/lib/auth";
import { callerIsOrgAdmin, getInvitationInOrg } from "@/lib/workos-org";
import { type NextRequest, NextResponse } from "next/server";

const WORKOS = "https://api.workos.com";

export async function DELETE(
	_req: NextRequest,
	{ params }: { params: Promise<{ id: string }> },
): Promise<NextResponse> {
	const key = process.env.WORKOS_API_KEY;
	if (!key) {
		return NextResponse.json(
			{ error: "WorkOS API not configured" },
			{ status: 501 },
		);
	}
	const session = await requireSession();
	const { id } = await params;

	// Owner-only. Privilege check FIRST so a non-owner can't probe invitation ids.
	const isAdmin = await callerIsOrgAdmin(key, session.tenantId, session.userId);
	if (isAdmin === null) {
		return NextResponse.json(
			{ error: "could not verify caller role" },
			{ status: 502 },
		);
	}
	if (!isAdmin) {
		return NextResponse.json(
			{ error: "role_forbidden", required_role: "owner" },
			{ status: 403 },
		);
	}

	const inv = await getInvitationInOrg(key, session.tenantId, id);
	if (!inv) {
		return NextResponse.json(
			{ error: "invitation not found" },
			{ status: 404 },
		);
	}

	const res = await fetch(
		`${WORKOS}/user_management/invitations/${encodeURIComponent(id)}/revoke`,
		{ method: "POST", headers: { Authorization: `Bearer ${key}` } },
	);
	if (!res.ok) {
		return NextResponse.json(
			{ error: "workos_revoke_failed" },
			{ status: 502 },
		);
	}
	return NextResponse.json({ revoked: id }, { status: 200 });
}

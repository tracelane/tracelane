/**
 * POST /api/settings/team/invitations/[id]/resend — resend a pending invitation
 * (IDENTITY_TEAM_SPEC §2). Owner-only, tenant-isolated.
 *
 * WorkOS has no native resend, so this is revoke + recreate with the same email
 * and role: the invitee gets a fresh email + fresh accept token, and the old
 * token stops working. Net-zero on the seat count (revoke frees, create takes).
 */

import { requireSession } from "@/lib/auth";
import { callerIsOrgAdmin, getInvitationInOrg } from "@/lib/workos-org";
import { type NextRequest, NextResponse } from "next/server";

const WORKOS = "https://api.workos.com";

export async function POST(
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

	// Revoke the old, then recreate. Order matters: revoke first so we never hold
	// two pending invites for the same email (WorkOS would reject the second).
	const revoke = await fetch(
		`${WORKOS}/user_management/invitations/${encodeURIComponent(id)}/revoke`,
		{ method: "POST", headers: { Authorization: `Bearer ${key}` } },
	);
	if (!revoke.ok) {
		return NextResponse.json(
			{ error: "workos_revoke_failed" },
			{ status: 502 },
		);
	}

	const created = await fetch(`${WORKOS}/user_management/invitations`, {
		method: "POST",
		headers: {
			Authorization: `Bearer ${key}`,
			"Content-Type": "application/json",
		},
		body: JSON.stringify({
			email: inv.email,
			organization_id: session.tenantId,
			role_slug: inv.role_slug ?? "member",
		}),
	});
	if (!created.ok) {
		console.error(
			`[team/invitations/resend] recreate failed: ${created.status}`,
		);
		return NextResponse.json(
			{ error: "workos_resend_failed" },
			{ status: 502 },
		);
	}
	const data = (await created.json()) as {
		id: string;
		email: string;
		state: string;
	};
	return NextResponse.json(
		{ invitationId: data.id, email: data.email, state: data.state },
		{ status: 201 },
	);
}

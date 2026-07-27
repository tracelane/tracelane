/**
 * GET /api/settings/team/invitations — list PENDING org invitations for the
 * pending-list UI (IDENTITY_TEAM_SPEC §2). Row: email, role, invited-date.
 *
 * Owner-gating is enforced on the mutation routes (resend/revoke) and on the
 * gateway; listing is scoped to the caller's own org (tenant isolation) and
 * carries no secrets, so it needs only a valid session.
 */

import { requireSession } from "@/lib/auth";
import { listInvitations } from "@/lib/workos-org";
import { type NextRequest, NextResponse } from "next/server";

interface PendingRow {
	id: string;
	email: string;
	role: string;
	invitedAt: string;
}

export async function GET(_req: NextRequest): Promise<NextResponse> {
	const key = process.env.WORKOS_API_KEY;
	if (!key) {
		return NextResponse.json(
			{ error: "WorkOS API not configured" },
			{ status: 501 },
		);
	}
	const session = await requireSession();

	const invites = await listInvitations(key, session.tenantId);
	if (invites === null) {
		return NextResponse.json(
			{ error: "could not load invitations" },
			{ status: 502 },
		);
	}

	const pending: PendingRow[] = invites
		.filter((i) => i.state === "pending")
		.map((i) => ({
			id: i.id,
			email: i.email,
			role: i.role_slug ?? "member",
			invitedAt: i.created_at,
		}));

	return NextResponse.json(pending);
}

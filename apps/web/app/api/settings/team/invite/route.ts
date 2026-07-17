/**
 * POST /api/settings/team/invite — send a WorkOS org invitation (IDENTITY_TEAM_SPEC §2).
 *
 * Chain: invite → pending → (hosted) accept → membership-with-role → seat count.
 *
 * Guards (all server-side; the gateway/WorkOS are the real barriers, UI only hides):
 *   - Owner-only: a member/viewer cannot invite (callerIsOrgAdmin, fail-closed).
 *   - Role picker: member | viewer only. Owner-grant is a separate explicit action.
 *   - Seat cap (ADR-020): active_memberships + pending_invitations >= seat_cap_max
 *     → typed 403 seat_limit_reached. seat_cap_max == 0 = Enterprise unlimited.
 *     Pending invites count so a Free org cannot stage unlimited invites.
 *   - Rate-limit (per-tenant + per-IP) to suppress bursts.
 *
 * Enumeration-safe by construction: invite is owner-only and an owner already
 * sees the full member list (GET /api/settings/team), so this endpoint reveals
 * nothing new. WorkOS bodies are never echoed (billing.md leak rule).
 */

import { db } from "@/db";
import { tenants } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { type Plan, resolveEntitlements } from "@/lib/entitlements";
import { clientIp, rateLimit } from "@/lib/rate-limit";
import {
	callerIsOrgAdmin,
	listInvitations,
	listMemberships,
} from "@/lib/workos-org";
import { eq } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";

interface InviteBody {
	email: string;
	/** member | viewer. Absent → member (WorkOS default). owner is not grantable here. */
	role?: string;
}

const INVITABLE_ROLES = new Set(["member", "viewer"]);

export async function POST(request: NextRequest): Promise<NextResponse> {
	const workosKey = process.env.WORKOS_API_KEY;
	if (!workosKey) {
		return NextResponse.json(
			{ error: "WorkOS API not configured" },
			{ status: 501 },
		);
	}

	const session = await requireSession();

	// Rate-limit: 20 invites / 5 min per tenant, 10 / 5 min per IP. Cheap burst
	// suppression; the seat cap is the hard bound (see lib/rate-limit.ts).
	const ip = clientIp(request.headers);
	if (
		!rateLimit(`invite:t:${session.tenantId}`, 20, 5 * 60_000) ||
		!rateLimit(`invite:ip:${ip}`, 10, 5 * 60_000)
	) {
		return NextResponse.json({ error: "rate_limited" }, { status: 429 });
	}

	let body: InviteBody;
	try {
		body = (await request.json()) as InviteBody;
	} catch {
		return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
	}

	if (!body.email?.includes("@")) {
		return NextResponse.json(
			{ error: "valid email required" },
			{ status: 422 },
		);
	}
	const role = body.role ?? "member";
	if (!INVITABLE_ROLES.has(role)) {
		return NextResponse.json(
			{ error: "role must be member or viewer" },
			{ status: 422 },
		);
	}

	// Owner-only. Fail closed if WorkOS can't confirm the caller's role.
	const isAdmin = await callerIsOrgAdmin(
		workosKey,
		session.tenantId,
		session.userId,
	);
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

	// Resolve the tenant + its seat cap. tenant_id derives from the session
	// org id, never from the request body.
	const tenantRow = await db
		.select({ id: tenants.id, plan: tenants.plan })
		.from(tenants)
		.where(eq(tenants.workosOrgId, session.tenantId))
		.limit(1);

	const plan: Plan = (tenantRow[0]?.plan as Plan) ?? "builder";
	const entitlements = await resolveEntitlements(tenantRow[0]?.id, plan);

	// seat_cap_max == 0 → unlimited (Enterprise). Otherwise: seats consumed =
	// accepted memberships + PENDING invitations (both reserve a seat). WorkOS
	// lookup failure fails the gate CLOSED. Both lists are cursor-paginated.
	// ponytail: no cross-request lock — two invites at cap-1 can both pass (org
	// lands at cap+1). A one-seat overshoot is acceptable for MVP; add a Postgres
	// advisory lock on (tenant,"seat_invite") if it must be exact.
	if (entitlements.seat_cap_max > 0) {
		const [members, invites] = await Promise.all([
			listMemberships(workosKey, session.tenantId),
			listInvitations(workosKey, session.tenantId),
		]);
		if (members === null || invites === null) {
			return NextResponse.json(
				{ error: "could not verify seat usage" },
				{ status: 502 },
			);
		}
		const used =
			members.length + invites.filter((i) => i.state === "pending").length;
		if (used >= entitlements.seat_cap_max) {
			return NextResponse.json(
				{
					error: "seat_limit_reached",
					seat_cap_max: entitlements.seat_cap_max,
					used,
					upgrade_url: "/settings/billing",
				},
				{ status: 403 },
			);
		}
	}

	const res = await fetch(
		"https://api.workos.com/user_management/invitations",
		{
			method: "POST",
			headers: {
				Authorization: `Bearer ${workosKey}`,
				"Content-Type": "application/json",
			},
			body: JSON.stringify({
				email: body.email.trim().toLowerCase(),
				organization_id: session.tenantId,
				role_slug: role,
			}),
		},
	);

	if (!res.ok) {
		// Never echo the provider body — WorkOS bodies can reflect our ids and are
		// leak-prone (billing.md). Log the status server-side; return an opaque code.
		console.error(`[team/invite] WorkOS invitation failed: ${res.status}`);
		return NextResponse.json(
			{ error: "workos_invitation_failed" },
			{ status: 502 },
		);
	}

	const data = (await res.json()) as {
		id: string;
		email: string;
		state: string;
	};
	return NextResponse.json(
		{ invitationId: data.id, email: data.email, state: data.state, role },
		{ status: 201 },
	);
}

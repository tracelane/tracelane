/**
 * Member management for a single org membership (IDENTITY_TEAM_SPEC §1/§3).
 *
 *   DELETE — remove the member (owner-only). WorkOS revokes their sessions; we
 *            additionally revoke their `tlane_` API keys so their next gateway
 *            request 401s. Mirror row is left for audit-trail integrity.
 *   PATCH  — change the member's role (owner-only): { role: owner|member|viewer }.
 *
 * Guards (all server-side — the UI hides the controls but these are the real
 * gates): owner-only caller, target must belong to the caller's org (tenant
 * isolation; a cross-org id 404s with no existence leak), no self-removal, and
 * last-owner protection (a removal or demotion that would leave zero owners →
 * typed 409 last_owner_protected). "Owner" spans the `owner` slug and WorkOS's
 * legacy `admin` so an admin-only org (pre role-config) is still protected.
 */

import { db } from "@/db";
import { apiKeys, tenants } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { isPrivilegedRole, listMemberships } from "@/lib/workos-org";
import { and, eq, isNull } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";

const WORKOS = "https://api.workos.com";
const ASSIGNABLE_ROLES = new Set(["owner", "member", "viewer"]);

export async function DELETE(
	_req: NextRequest,
	{ params }: { params: Promise<{ membershipId: string }> },
): Promise<NextResponse> {
	const key = process.env.WORKOS_API_KEY;
	if (!key) {
		return NextResponse.json(
			{ error: "WorkOS API not configured" },
			{ status: 501 },
		);
	}

	const session = await requireSession();
	const { membershipId } = await params;

	const members = await listMemberships(key, session.tenantId);
	if (members === null) {
		return NextResponse.json(
			{ error: "could not verify membership" },
			{ status: 502 },
		);
	}

	// Owner check FIRST — a non-owner gets an identical 403 whether or not the id
	// exists in this org, so a plain member can't probe which ids are in-tenant.
	const caller = members.find((m) => m.user_id === session.userId);
	if (!caller || !isPrivilegedRole(caller.role.slug)) {
		return NextResponse.json(
			{ error: "role_forbidden", required_role: "owner" },
			{ status: 403 },
		);
	}

	const target = members.find((m) => m.id === membershipId);
	if (!target) {
		return NextResponse.json({ error: "member not found" }, { status: 404 });
	}
	if (target.user_id === session.userId) {
		return NextResponse.json(
			{ error: "cannot remove yourself" },
			{ status: 400 },
		);
	}

	// Last-owner protection (§1). ponytail: bound = the 2-owner concurrent race
	// (both remove the OTHER of the last two, each sees 2, both pass → 0).
	// Owner-initiated + low-frequency; add a Postgres advisory lock on
	// (tenant,"owners") if it must be exact.
	const privilegedCount = members.filter((m) =>
		isPrivilegedRole(m.role.slug),
	).length;
	if (isPrivilegedRole(target.role.slug) && privilegedCount <= 1) {
		return NextResponse.json(
			{ error: "last_owner_protected" },
			{ status: 409 },
		);
	}

	const del = await fetch(
		`${WORKOS}/user_management/organization_memberships/${encodeURIComponent(membershipId)}`,
		{ method: "DELETE", headers: { Authorization: `Bearer ${key}` } },
	);
	if (!del.ok) {
		return NextResponse.json(
			{ error: "WorkOS removal failed" },
			{ status: 502 },
		);
	}

	// Revoke the removed member's `tlane_` keys (§3) so their next gateway
	// request 401s. Best-effort: the membership + its sessions are already gone
	// via WorkOS, so a revoke failure must not fail the removal (log + move on).
	// Only keys minted by THIS user (minted_by = their WorkOS user id) are
	// touched; pre-0011 keys with a NULL minter are unattributable and untouched.
	try {
		const [t] = await db
			.select({ id: tenants.id })
			.from(tenants)
			.where(eq(tenants.workosOrgId, session.tenantId))
			.limit(1);
		if (t) {
			await db
				.update(apiKeys)
				.set({ revokedAt: new Date() })
				.where(
					and(
						eq(apiKeys.tenantId, t.id),
						eq(apiKeys.mintedBy, target.user_id),
						isNull(apiKeys.revokedAt),
					),
				);
		}
	} catch {
		console.error("[team/remove] api-key revoke failed for removed member");
	}

	return NextResponse.json({ removed: membershipId }, { status: 200 });
}

interface RoleChangeBody {
	role: string;
}

export async function PATCH(
	request: NextRequest,
	{ params }: { params: Promise<{ membershipId: string }> },
): Promise<NextResponse> {
	const key = process.env.WORKOS_API_KEY;
	if (!key) {
		return NextResponse.json(
			{ error: "WorkOS API not configured" },
			{ status: 501 },
		);
	}

	const session = await requireSession();
	const { membershipId } = await params;

	let body: RoleChangeBody;
	try {
		body = (await request.json()) as RoleChangeBody;
	} catch {
		return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
	}
	if (!ASSIGNABLE_ROLES.has(body.role)) {
		return NextResponse.json(
			{ error: "role must be owner, member, or viewer" },
			{ status: 422 },
		);
	}

	const members = await listMemberships(key, session.tenantId);
	if (members === null) {
		return NextResponse.json(
			{ error: "could not verify membership" },
			{ status: 502 },
		);
	}

	const caller = members.find((m) => m.user_id === session.userId);
	if (!caller || !isPrivilegedRole(caller.role.slug)) {
		return NextResponse.json(
			{ error: "role_forbidden", required_role: "owner" },
			{ status: 403 },
		);
	}

	const target = members.find((m) => m.id === membershipId);
	if (!target) {
		return NextResponse.json({ error: "member not found" }, { status: 404 });
	}

	// Last-owner protection (§1): demoting the last owner to a non-owner role is
	// refused. Granting owner (member/viewer → owner) is always allowed.
	const demotesOwner =
		isPrivilegedRole(target.role.slug) && body.role !== "owner";
	const privilegedCount = members.filter((m) =>
		isPrivilegedRole(m.role.slug),
	).length;
	if (demotesOwner && privilegedCount <= 1) {
		return NextResponse.json(
			{ error: "last_owner_protected" },
			{ status: 409 },
		);
	}

	const res = await fetch(
		`${WORKOS}/user_management/organization_memberships/${encodeURIComponent(membershipId)}`,
		{
			method: "PUT",
			headers: {
				Authorization: `Bearer ${key}`,
				"Content-Type": "application/json",
			},
			body: JSON.stringify({ role_slug: body.role }),
		},
	);
	if (!res.ok) {
		console.error(`[team/role] WorkOS role change failed: ${res.status}`);
		return NextResponse.json(
			{ error: "workos_role_change_failed" },
			{ status: 502 },
		);
	}

	// The new role takes effect in the member's NEXT session JWT (WorkOS reissues
	// on refresh) — surfaced in the UI copy per §3.
	return NextResponse.json({ membershipId, role: body.role }, { status: 200 });
}

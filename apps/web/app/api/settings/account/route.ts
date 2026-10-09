/**
 * Account self-service (IDENTITY_TEAM_SPEC §5).
 *
 *   PATCH  — update the caller's display name (WorkOS user + `users` mirror).
 *            Email is read-only at launch.
 *   DELETE — delete the caller's own account. Three cases (checked server-side):
 *            1. sole user of the org  → this IS org deletion: soft-delete the
 *               tenant (archived_at), revoke all keys, delete the WorkOS user,
 *               tombstone the mirror row.
 *            2. last owner WITH other members → 409 (transfer ownership first).
 *            3. otherwise → remove own membership, delete the WorkOS user,
 *               tombstone the mirror row (kept for ledger FK integrity).
 *            In every deleting case the sign-up list row (`signups`, SET-60) is
 *            hard-deleted too.
 *
 * Requires a type-your-email confirmation on DELETE (compensating control for
 * no re-auth at launch, §6). WorkOS is the identity system of record.
 */

import { db } from "@/db";
import { apiKeys, tenants, users } from "@/db/schema";
import { invalidateOrgArchivedCache, requireSession } from "@/lib/auth";
import {
	isPrivilegedRole,
	listMemberships,
	listUserMemberships,
} from "@/lib/workos-org";
import { withAuth } from "@workos-inc/authkit-nextjs";
import { and, eq, gt, isNull, or, sql } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";

import { withOwnerMutation } from "../team/owner-lock";

const WORKOS = "https://api.workos.com";

interface ProfileBody {
	name: string;
}

export async function PATCH(request: NextRequest): Promise<NextResponse> {
	const key = process.env.WORKOS_API_KEY;
	if (!key) {
		return NextResponse.json(
			{ error: "WorkOS API not configured" },
			{ status: 501 },
		);
	}
	const session = await requireSession();

	let body: ProfileBody;
	try {
		body = (await request.json()) as ProfileBody;
	} catch {
		return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
	}
	const name = typeof body.name === "string" ? body.name.trim() : "";
	if (!name || name.length > 255) {
		return NextResponse.json(
			{ error: "name must be 1–255 characters" },
			{ status: 422 },
		);
	}
	// WorkOS stores first/last, not a single display name. Map the whole string to
	// first_name and clear last_name — the UI treats it as one field.
	const res = await fetch(
		`${WORKOS}/user_management/users/${encodeURIComponent(session.userId)}`,
		{
			method: "PUT",
			headers: {
				Authorization: `Bearer ${key}`,
				"Content-Type": "application/json",
			},
			body: JSON.stringify({ first_name: name, last_name: "" }),
		},
	);
	if (!res.ok) {
		return NextResponse.json(
			{ error: "workos_update_failed" },
			{ status: 502 },
		);
	}
	// Mirror into Postgres (non-fatal on failure; WorkOS is authoritative).
	try {
		await db
			.update(users)
			.set({ name })
			.where(eq(users.workosUserId, session.userId));
	} catch {
		// non-fatal — the mirror reconciles on the next user.updated webhook.
	}
	return NextResponse.json({ name }, { status: 200 });
}

interface DeleteBody {
	confirmEmail: string;
}

/** Fail closed before deleting WorkOS or archiving the org, so a failure is retryable. */
async function eraseLocalIdentity(
	userId: string,
): Promise<NextResponse | null> {
	try {
		await db.execute(sql`SELECT erase_account_pii(${userId})`);
		return null;
	} catch {
		console.error("[account/delete] local erasure failed");
		return NextResponse.json(
			{ error: "local_erasure_failed" },
			{ status: 503 },
		);
	}
}

async function deleteWorkosIdentity(
	key: string,
	userId: string,
	orgDeleted: boolean,
): Promise<NextResponse> {
	const del = await fetch(
		`${WORKOS}/user_management/users/${encodeURIComponent(userId)}`,
		{
			method: "DELETE",
			headers: { Authorization: `Bearer ${key}` },
		},
	);
	if (!del.ok)
		return NextResponse.json(
			{ error: "workos_user_delete_failed" },
			{ status: 502 },
		);
	return NextResponse.json({ deleted: true, orgDeleted }, { status: 200 });
}

export async function DELETE(request: NextRequest): Promise<NextResponse> {
	const key = process.env.WORKOS_API_KEY;
	if (!key) {
		return NextResponse.json(
			{ error: "WorkOS API not configured" },
			{ status: 501 },
		);
	}
	const auth = await withAuth().catch(() => null);
	if (!auth?.user) {
		return NextResponse.json({ error: "unauthenticated" }, { status: 401 });
	}
	const session = {
		userId: auth.user.id,
		email: auth.user.email,
		tenantId: auth.organizationId,
	};

	let body: DeleteBody;
	try {
		body = (await request.json()) as DeleteBody;
	} catch {
		return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
	}
	// Type-email confirmation (compensating control for no re-auth, §6).
	if (body.confirmEmail?.trim().toLowerCase() !== session.email.toLowerCase()) {
		return NextResponse.json(
			{ error: "email confirmation does not match" },
			{ status: 422 },
		);
	}

	// A missing selected org can also be a stale session after provisioning.
	// Verify actual memberships before deciding that no workspace safeguards apply.
	let orgId = session.tenantId;
	if (!orgId) {
		const memberships = await listUserMemberships(key, session.userId);
		if (
			memberships === null ||
			memberships.some(
				(m) => !m.organization_id || m.user_id !== session.userId,
			)
		) {
			return NextResponse.json(
				{ error: "could not verify membership" },
				{ status: 502 },
			);
		}
		const orgs = [...new Set(memberships.map((m) => m.organization_id))];
		if (orgs.length > 1) {
			return NextResponse.json(
				{ error: "organization_selection_required" },
				{ status: 409 },
			);
		}
		orgId = orgs[0];
	}
	if (!orgId) {
		const erasureError = await eraseLocalIdentity(session.userId);
		if (erasureError) return erasureError;
		return deleteWorkosIdentity(key, session.userId, false);
	}

	const verifiedOrgId = orgId;
	return withOwnerMutation(verifiedOrgId, async () => {
		const members = await listMemberships(key, verifiedOrgId);
		if (members === null) {
			return NextResponse.json(
				{ error: "could not verify membership" },
				{ status: 502 },
			);
		}
		const owners = members.filter((m) => isPrivilegedRole(m.role.slug));
		const soleUser = members.length <= 1;
		const isOwner = members.some(
			(m) => m.user_id === session.userId && isPrivilegedRole(m.role.slug),
		);

		// Case 2: last owner with other members → block (must transfer first).
		if (!soleUser && isOwner && owners.length <= 1) {
			return NextResponse.json(
				{
					error: "last_owner_protected",
					detail: "transfer ownership before deleting your account",
				},
				{ status: 409 },
			);
		}

		// Resolve the internal tenant id once (for key-revoke + archive).
		const [t] = await db
			.select({ id: tenants.id })
			.from(tenants)
			.where(eq(tenants.workosOrgId, verifiedOrgId))
			.limit(1);

		const erasureError = await eraseLocalIdentity(session.userId);
		if (erasureError) return erasureError;

		if (soleUser) {
			// Case 1: sole user → this IS org deletion. Soft-delete + revoke all keys.
			if (t) {
				try {
					await db
						.update(tenants)
						.set({ archivedAt: new Date() })
						.where(eq(tenants.id, t.id));
					// B-361: same-isolate immediacy for the acting user; see the
					// function doc on `invalidateOrgArchivedCache` for the
					// cross-isolate staleness this deliberately accepts.
					invalidateOrgArchivedCache(verifiedOrgId);
					await db
						.update(apiKeys)
						.set({ revokedAt: new Date() })
						.where(
							and(
								eq(apiKeys.tenantId, t.id),
								or(
									isNull(apiKeys.revokedAt),
									gt(apiKeys.revokedAt, sql`now()`),
								),
							),
						);
				} catch {
					console.error("[account/delete] org soft-delete side effects failed");
				}
			}
		}

		return deleteWorkosIdentity(key, session.userId, soleUser);
	});
}

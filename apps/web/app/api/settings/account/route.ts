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
 *
 * Requires a type-your-email confirmation on DELETE (compensating control for
 * no re-auth at launch, §6). WorkOS is the identity system of record.
 */

import { db } from "@/db";
import { apiKeys, tenants, users } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { isPrivilegedRole, listMemberships } from "@/lib/workos-org";
import { and, eq, isNull } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";

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

/** Tombstone a mirror row without dropping it (ledger FK integrity, §5/GDPR). */
async function tombstoneMirror(workosUserId: string): Promise<void> {
	await db
		.update(users)
		.set({ email: `deleted-${workosUserId}@tombstone.invalid`, name: null })
		.where(eq(users.workosUserId, workosUserId));
}

export async function DELETE(request: NextRequest): Promise<NextResponse> {
	const key = process.env.WORKOS_API_KEY;
	if (!key) {
		return NextResponse.json(
			{ error: "WorkOS API not configured" },
			{ status: 501 },
		);
	}
	const session = await requireSession();

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

	const members = await listMemberships(key, session.tenantId);
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
		.where(eq(tenants.workosOrgId, session.tenantId))
		.limit(1);

	if (soleUser) {
		// Case 1: sole user → this IS org deletion. Soft-delete + revoke all keys.
		if (t) {
			try {
				await db
					.update(tenants)
					.set({ archivedAt: new Date() })
					.where(eq(tenants.id, t.id));
				await db
					.update(apiKeys)
					.set({ revokedAt: new Date() })
					.where(and(eq(apiKeys.tenantId, t.id), isNull(apiKeys.revokedAt)));
			} catch {
				console.error("[account/delete] org soft-delete side effects failed");
			}
		}
	}

	// Delete the WorkOS user (cascades their memberships + revokes their sessions).
	const del = await fetch(
		`${WORKOS}/user_management/users/${encodeURIComponent(session.userId)}`,
		{ method: "DELETE", headers: { Authorization: `Bearer ${key}` } },
	);
	if (!del.ok) {
		return NextResponse.json(
			{ error: "workos_user_delete_failed" },
			{ status: 502 },
		);
	}

	// Tombstone the mirror row (keep for ledger FK integrity; email anonymized).
	try {
		await tombstoneMirror(session.userId);
	} catch {
		console.error("[account/delete] mirror tombstone failed");
	}

	return NextResponse.json(
		{ deleted: true, orgDeleted: soleUser },
		{ status: 200 },
	);
}

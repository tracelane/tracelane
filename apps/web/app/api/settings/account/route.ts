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
import { prepareKeyRevocation } from "@/lib/gateway";
import {
	type OrgMembership,
	countsAsOwner,
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

/** Global deletion needs a complete identity-wide scope, even with a selected org. */
async function membershipScope(
	key: string,
	userId: string,
): Promise<string[] | null> {
	try {
		const memberships = await listUserMemberships(key, userId);
		if (
			memberships === null ||
			memberships.some(
				(m) =>
					!m ||
					typeof m.organization_id !== "string" ||
					!m.organization_id ||
					m.user_id !== userId,
			)
		)
			return null;
		return [...new Set(memberships.map((m) => m.organization_id))].sort();
	} catch {
		return null;
	}
}

function membershipUnavailable(): NextResponse {
	return NextResponse.json(
		{ error: "could not verify membership" },
		{ status: 502 },
	);
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

	const orgs = await membershipScope(key, session.userId);
	if (orgs === null) return membershipUnavailable();
	const orgId = session.tenantId;
	if (!orgId && orgs.length > 0) {
		return NextResponse.json(
			{ error: "organization_selection_required" },
			{ status: 409 },
		);
	}
	if (orgId && !orgs.includes(orgId)) {
		return NextResponse.json({ error: "not_a_member" }, { status: 403 });
	}
	if (!orgId) {
		// No current membership does not prove that live API keys are gone.
		// An unscoped session cannot obtain the tenant-bound gateway acknowledgement.
		const [ownedKey] = await db
			.select({ id: apiKeys.id })
			.from(apiKeys)
			.where(
				and(
					eq(apiKeys.mintedBy, session.userId),
					or(isNull(apiKeys.revokedAt), gt(apiKeys.revokedAt, sql`now()`)),
				),
			)
			.limit(1);
		if (ownedKey)
			return NextResponse.json(
				{ error: "organization_selection_required" },
				{ status: 409 },
			);
		const erasureError = await eraseLocalIdentity(session.userId);
		if (erasureError) return erasureError;
		const [lateKey] = await db
			.select({ id: apiKeys.id })
			.from(apiKeys)
			.where(
				and(
					eq(apiKeys.mintedBy, session.userId),
					or(isNull(apiKeys.revokedAt), gt(apiKeys.revokedAt, sql`now()`)),
				),
			)
			.limit(1);
		if (lateKey)
			return NextResponse.json(
				{ error: "key_revocation_unconfirmed" },
				{ status: 503 },
			);
		return deleteWorkosIdentity(key, session.userId, false);
	}

	const verifiedOrgId = orgId;
	return withOwnerMutation(orgs, async () => {
		// Recheck after acquiring every workspace lock: the identity's scope may
		// have changed while waiting. Never expand locks in a different order.
		const current = await membershipScope(key, session.userId);
		if (current === null) return membershipUnavailable();
		if (
			current.length !== orgs.length ||
			current.some((org, i) => org !== orgs[i])
		) {
			return NextResponse.json(
				{
					error: "membership_changed",
					detail: "Workspace memberships changed. Refresh and retry.",
				},
				{ status: 409 },
			);
		}
		const allMembers = new Map<string, OrgMembership[]>();
		let otherSoleWorkspace = false;
		for (const org of orgs) {
			let members: OrgMembership[] | null;
			try {
				members = await listMemberships(key, org);
			} catch {
				return membershipUnavailable();
			}
			if (
				members === null ||
				new Set(members.map((m) => m?.user_id)).size !== members.length ||
				members.some(
					(m) =>
						!m ||
						m.organization_id !== org ||
						typeof m.user_id !== "string" ||
						!m.user_id ||
						typeof m.role?.slug !== "string",
				)
			)
				return membershipUnavailable();
			const self = members.find((m) => m.user_id === session.userId);
			if (!self) return membershipUnavailable();
			// Workspace deletion retains its WorkOS membership until purge. An
			// archived workspace is cleaned up only if no live keys remain. The
			// shared owner lock also excludes gateway mint/rotation during this check.
			if (org !== verifiedOrgId) {
				const [tenant] = await db
					.select({ id: tenants.id, archivedAt: tenants.archivedAt })
					.from(tenants)
					.where(eq(tenants.workosOrgId, org))
					.limit(1);
				if (tenant?.archivedAt) {
					const [liveKey] = await db
						.select({ tenantId: apiKeys.tenantId })
						.from(apiKeys)
						.where(
							and(
								eq(apiKeys.tenantId, tenant.id),
								or(
									isNull(apiKeys.revokedAt),
									gt(apiKeys.revokedAt, sql`now()`),
								),
							),
						)
						.limit(1);
					if (liveKey)
						return NextResponse.json(
							{ error: "key_revocation_unconfirmed" },
							{ status: 503 },
						);
					allMembers.set(org, members);
					continue;
				}
			}
			const owners = members.filter(countsAsOwner);
			if (
				members.length > 1 &&
				isPrivilegedRole(self.role.slug) &&
				owners.length <= 1
			) {
				return NextResponse.json(
					{
						error: "last_owner_protected",
						detail:
							"Transfer ownership in every workspace before deleting your account.",
					},
					{ status: 409 },
				);
			}
			if (members.length === 1 && org !== verifiedOrgId)
				otherSoleWorkspace = true;
			allMembers.set(org, members);
		}
		// The selected session cannot authorize another tenant's complete key
		// invalidation. Require explicit cleanup instead of orphaning that tenant.
		if (otherSoleWorkspace)
			return NextResponse.json(
				{
					error: "workspace_cleanup_required",
					detail:
						"Delete your other sole-member workspaces before deleting your account.",
				},
				{ status: 409 },
			);
		const soleUser = allMembers.get(verifiedOrgId)?.length === 1;

		// Resolve the internal tenant id once (for key-revoke + archive).
		const [t] = await db
			.select({ id: tenants.id })
			.from(tenants)
			.where(eq(tenants.workosOrgId, verifiedOrgId))
			.limit(1);

		// Account deletion is global: revoke this user's keys in EVERY workspace.
		// A sole-user workspace also loses keys minted by other/unknown actors.
		let revokeAndConfirm: () => Promise<void>;
		try {
			const confirmOwn = await prepareKeyRevocation(verifiedOrgId, true);
			const confirmTenant = soleUser
				? await prepareKeyRevocation(verifiedOrgId)
				: null;
			revokeAndConfirm = async () => {
				await db
					.update(apiKeys)
					.set({ revokedAt: sql`now()` })
					.where(
						and(
							or(
								eq(apiKeys.mintedBy, session.userId),
								soleUser && t ? eq(apiKeys.tenantId, t.id) : undefined,
							),
							or(isNull(apiKeys.revokedAt), gt(apiKeys.revokedAt, sql`now()`)),
						),
					);
				await confirmOwn();
				await confirmTenant?.();
			};
			await revokeAndConfirm();
		} catch {
			return NextResponse.json(
				{ error: "key_revocation_unconfirmed" },
				{ status: 503 },
			);
		}

		const erasureError = await eraseLocalIdentity(session.userId);
		if (erasureError) return erasureError;
		// The durable deletion marker now refuses later mints under the identity
		// lock. Drain any mint which committed before the eraser acquired it.
		try {
			await revokeAndConfirm();
		} catch {
			return NextResponse.json(
				{ error: "key_revocation_unconfirmed" },
				{ status: 503 },
			);
		}

		if (soleUser && t) {
			try {
				await db
					.update(tenants)
					.set({ archivedAt: new Date() })
					.where(eq(tenants.id, t.id));
				// B-361: same-isolate immediacy for the acting user; see the
				// function doc on `invalidateOrgArchivedCache` for the
				// cross-isolate staleness this deliberately accepts.
				invalidateOrgArchivedCache(verifiedOrgId);
			} catch {
				return NextResponse.json(
					{ error: "could not archive organization" },
					{ status: 503 },
				);
			}
		}

		return deleteWorkosIdentity(key, session.userId, soleUser);
	});
}

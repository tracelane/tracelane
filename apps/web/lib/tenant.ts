/**
 * Tenant-row helpers shared across API routes.
 *
 * Maps a WorkOS organization id to the internal tenant UUID, inserting the row
 * on first sight. Postgres holds only cold tenant metadata; the WorkOS org id
 * is the tenant scoping key (CLAUDE.md tenant invariant).
 */

import { db } from "@/db";
import { tenants, users } from "@/db/schema";
import { eq } from "drizzle-orm";

/**
 * Best-effort upsert of the `users` mirror row (B-101). WorkOS is the system of
 * record (spec principle #1); this table is a convenience cache (the account
 * page's name seed, ledger-FK integrity). The gateway webhook CAN'T populate it
 * — WorkOS `user.created` carries no org, and membership events aren't
 * subscribed / the gateway has no Management key — so the web populates it where
 * it already knows email + tenant + WorkOS id (onboarding, team-list backfill).
 *
 * Idempotent (conflict on the unique `workos_user_id`). Swallows all errors: a
 * cache write must NEVER break onboarding or a page render.
 */
export async function upsertUserMirror(opts: {
	tenantDbId: string;
	workosUserId: string;
	email: string;
	name: string | null;
}): Promise<void> {
	try {
		await db
			.insert(users)
			.values({
				userId: crypto.randomUUID(),
				tenantId: opts.tenantDbId,
				email: opts.email,
				workosUserId: opts.workosUserId,
				name: opts.name,
			})
			.onConflictDoUpdate({
				target: users.workosUserId,
				set: {
					tenantId: opts.tenantDbId,
					email: opts.email,
					name: opts.name,
				},
			});
	} catch {
		// Best-effort cache; WorkOS remains the source of truth.
	}
}

/**
 * Resolve the internal tenant UUID for a WorkOS org id, creating the row if
 * absent. Idempotent: concurrent first-calls collapse on the unique
 * `workos_org_id` index (the loser re-selects the winner's row).
 *
 * @throws if the row can neither be found nor inserted (should never happen).
 */
export async function upsertTenantId(workosOrgId: string): Promise<string> {
	const existing = await db
		.select({ id: tenants.id })
		.from(tenants)
		.where(eq(tenants.workosOrgId, workosOrgId))
		.limit(1);
	if (existing[0]) return existing[0].id;

	const inserted = await db
		.insert(tenants)
		.values({ workosOrgId })
		.onConflictDoNothing({ target: tenants.workosOrgId })
		.returning({ id: tenants.id });
	if (inserted[0]) return inserted[0].id;

	// Lost an insert race — the row now exists; re-select it.
	const after = await db
		.select({ id: tenants.id })
		.from(tenants)
		.where(eq(tenants.workosOrgId, workosOrgId))
		.limit(1);
	if (!after[0]) throw new Error("tenants upsert failed to resolve id");
	return after[0].id;
}

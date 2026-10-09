/**
 * SET-60 — record a completed sign-in in `signups` (the operator's list: name, email,
 * first/last seen, count, method). Called from the auth callback's `onSuccess`
 * (`app/auth/callback/route.ts`); spec `specs/SET-60-signup-capture.md`.
 *
 * NOT tenant data: no `tenant_id`, nothing authorizes on this table, no API reads it.
 * `organization_id` is the WorkOS org id as text, informational only.
 *
 * Fail-OPEN (CLAUDE.md §10): a fault-tolerance path. A failure here must never turn a
 * successful sign-in into the "/auth/error" page, so every write is wrapped.
 */

import { db } from "@/db";
import { signups, users } from "@/db/schema";
import { eq, sql } from "drizzle-orm";

/** RFC 5321 maximum for a forward-path; an input-hardening bound, not a tunable. */
export const MAX_EMAIL = 320;
/** Contact-list display name; WorkOS holds the full value. */
export const MAX_NAME = 200;

/**
 * The slice of `HandleAuthSuccessData` (`@workos-inc/authkit-nextjs@4.0.1`,
 * `dist/esm/types/interfaces.d.ts:13-18`) this reads. Structural, so the SDK's type is
 * assignable and the test needs no SDK import.
 */
export interface SignInData {
	user: {
		id: string;
		email: string;
		firstName?: string | null;
		lastName?: string | null;
	};
	organizationId?: string;
	authenticationMethod?: string;
	impersonator?: unknown;
}

/** Trim, drop NUL (Postgres `text` rejects it), cut by code point (never mid-surrogate). */
function bound(value: string | null | undefined, max: number): string | null {
	if (!value) return null;
	const clean = value.split("\u0000").join("").trim();
	if (!clean) return null;
	return Array.from(clean).slice(0, max).join("");
}

function logFailure(what: string, err: unknown): void {
	// One line, error CLASS only: the message can echo the row (email, name).
	console.error(
		`[signups] ${what} failed: ${err instanceof Error ? err.name : "unknown"}`,
	);
}

/**
 * Upsert the `signups` row for a completed sign-in and stamp `users.last_login_at`.
 * Both statements run the migration-0064 deleted-identity trigger: it serializes
 * against account erasure and checks the tombstone inside the write statement.
 * A delayed callback for an erased identity therefore writes neither row.
 *
 * Skips an impersonated session (a WorkOS admin is not that person signing in) and a
 * sign-in with no user id or email (nothing to key or contact on).
 *
 * # Errors
 *
 * Never returns an error and never throws: each write is independently caught and logged
 * as one PII-free line, so neither a missing table nor a down database can break sign-in,
 * and the `users` stamp failing does not stop the `signups` row (nor the reverse).
 */
export async function recordSignIn(data: SignInData): Promise<void> {
	try {
		if (data.impersonator) return;
		const workosUserId = bound(data.user?.id, 255);
		const email = bound(data.user?.email, MAX_EMAIL);
		if (!workosUserId || !email) return;
		const name = bound(
			[data.user.firstName, data.user.lastName].filter(Boolean).join(" "),
			MAX_NAME,
		);
		const organizationId = bound(data.organizationId, 255);
		const authMethod = bound(data.authenticationMethod, 64);

		try {
			await db
				.insert(signups)
				.values({
					workosUserId,
					email,
					name,
					lastLoginAt: sql`now()`,
					organizationId,
					authMethod,
				})
				.onConflictDoUpdate({
					target: signups.workosUserId,
					set: {
						email,
						// A sign-in that carries no name keeps the one we already have.
						name: sql`coalesce(${name}::text, ${signups.name})`,
						lastLoginAt: sql`now()`,
						loginCount: sql`${signups.loginCount} + 1`,
						organizationId,
						authMethod,
					},
				});
		} catch (err) {
			logFailure("upsert", err);
		}

		try {
			await db
				.update(users)
				.set({ lastLoginAt: sql`now()` })
				.where(eq(users.workosUserId, workosUserId));
		} catch (err) {
			logFailure("users.last_login_at", err);
		}
	} catch (err) {
		logFailure("record", err);
	}
}

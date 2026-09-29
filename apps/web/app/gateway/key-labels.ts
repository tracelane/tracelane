/**
 * SET-38 B5: the `/gateway` spend table's key labels — `name · prefix…` with a lifecycle
 * suffix — read from Postgres for THIS tenant (the session's WorkOS org bridged to the
 * tenant uuid by `upsertTenantId`, never a raw org id against a data table). A failed
 * read returns `undefined` and the table falls back to the short id: a display path, so
 * fail-OPEN (CLAUDE.md §10).
 */
import { db } from "@/db";
import { apiKeys } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { upsertTenantId } from "@/lib/tenant";
import { eq } from "drizzle-orm";
import type { KeyLabel } from "./SpendAttribution";

type KeyRow = {
	id: string;
	name: string;
	keyPrefix: string;
	revokedAt: Date | null;
	expiresAt: Date | null;
};

/** Pure: a FUTURE `revoked_at` is a rotation grace window ("retiring"), not revoked. */
export function toKeyLabels(
	rows: KeyRow[],
	now: number,
): Record<string, KeyLabel> {
	const out: Record<string, KeyLabel> = {};
	for (const r of rows) {
		const revoked = r.revokedAt ? r.revokedAt.getTime() : null;
		const state =
			revoked !== null && revoked <= now
				? "revoked"
				: revoked !== null
					? "retiring"
					: r.expiresAt && r.expiresAt.getTime() <= now
						? "expired"
						: null;
		out[r.id] = { name: r.name, prefix: r.keyPrefix, state };
	}
	return out;
}

export async function readKeyLabels(): Promise<
	Record<string, KeyLabel> | undefined
> {
	try {
		const session = await requireSession();
		const tenantDbId = await upsertTenantId(session.tenantId);
		const rows = await db
			.select({
				id: apiKeys.id,
				name: apiKeys.name,
				keyPrefix: apiKeys.keyPrefix,
				revokedAt: apiKeys.revokedAt,
				expiresAt: apiKeys.expiresAt,
			})
			.from(apiKeys)
			.where(eq(apiKeys.tenantId, tenantDbId));
		return toKeyLabels(rows, Date.now());
	} catch (e) {
		// requireSession redirects by THROWING — never swallow that.
		if (e instanceof Error && e.message === "NEXT_REDIRECT") throw e;
		return undefined;
	}
}

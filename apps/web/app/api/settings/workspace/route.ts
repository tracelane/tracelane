/**
 * PATCH /api/settings/workspace — rename the workspace (WorkOS organization).
 *
 * Renames the WorkOS org AND mirrors the new name into `tenants.name` so the
 * sidebar org badge (which reads Postgres) can't go stale. ADMIN-GATED (a plain
 * member can't relabel the workspace for everyone). tenant_id derives from the
 * session org id, never the request body. Server-only (WORKOS_API_KEY).
 */

import { db } from "@/db";
import { apiKeys, tenants } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { callerIsOrgAdmin } from "@/lib/workos-org";
import { and, eq, isNull } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";

interface RenameBody {
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

	let body: RenameBody;
	try {
		body = (await request.json()) as RenameBody;
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

	// Org rename is an admin action — a plain member must not be able to relabel
	// the workspace for everyone. Fail closed (502) if the role can't be verified.
	const admin = await callerIsOrgAdmin(key, session.tenantId, session.userId);
	if (admin === null) {
		return NextResponse.json(
			{ error: "could not verify permissions" },
			{ status: 502 },
		);
	}
	if (!admin) {
		return NextResponse.json(
			{ error: "admin or owner role required" },
			{ status: 403 },
		);
	}

	// Rename the WorkOS org (the source of truth for identity).
	const res = await fetch(
		`https://api.workos.com/organizations/${encodeURIComponent(session.tenantId)}`,
		{
			method: "PUT",
			headers: {
				Authorization: `Bearer ${key}`,
				"Content-Type": "application/json",
			},
			body: JSON.stringify({ name }),
		},
	);
	if (!res.ok) {
		return NextResponse.json(
			{ error: "WorkOS rename failed" },
			{ status: 502 },
		);
	}

	// Mirror into Postgres so the org badge stays in sync. Scoped to the session
	// org; a failure here doesn't undo the WorkOS rename but shouldn't 500 the
	// request — the badge falls back to the generic label until the next read.
	try {
		await db
			.update(tenants)
			.set({ name })
			.where(eq(tenants.workosOrgId, session.tenantId));
	} catch {
		// non-fatal — WorkOS is authoritative; the badge reconciles on next write.
	}

	return NextResponse.json({ name }, { status: 200 });
}

interface DeleteBody {
	confirmName: string;
}

/**
 * DELETE /api/settings/workspace — 30-day soft-delete of the org/tenant
 * (IDENTITY_TEAM_SPEC §5). Owner-only, type-org-name confirmation.
 *
 * Soft-delete = `tenants.archived_at = now()` + revoke ALL of the tenant's
 * `tlane_` keys (so gateway traffic 401s immediately — the key lookup filters
 * `revoked_at IS NULL`). Dashboard access is blocked by the archived-org guard
 * in requireSession. Hard purge (WorkOS org delete, ClickHouse/R2/Neon rows,
 * "purged within 30 days"; soft-delete is reversible in-window (archived_at =
 * NULL) until then.
 */
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

	const admin = await callerIsOrgAdmin(key, session.tenantId, session.userId);
	if (admin === null) {
		return NextResponse.json(
			{ error: "could not verify permissions" },
			{ status: 502 },
		);
	}
	if (!admin) {
		return NextResponse.json(
			{ error: "role_forbidden", required_role: "owner" },
			{ status: 403 },
		);
	}

	const [t] = await db
		.select({ id: tenants.id, name: tenants.name })
		.from(tenants)
		.where(eq(tenants.workosOrgId, session.tenantId))
		.limit(1);
	if (!t) {
		return NextResponse.json({ error: "tenant not found" }, { status: 404 });
	}
	// Type-org-name confirmation (compensating control for no re-auth, §6).
	if ((body.confirmName ?? "").trim() !== (t.name ?? "").trim()) {
		return NextResponse.json(
			{ error: "name confirmation does not match" },
			{ status: 422 },
		);
	}

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
		console.error("[workspace/delete] soft-delete side effects failed");
		return NextResponse.json({ error: "soft_delete_failed" }, { status: 502 });
	}

	return NextResponse.json(
		{ archived: true, purge: "within 30 days" },
		{ status: 200 },
	);
}

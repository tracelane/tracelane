/**
 * DELETE /api/settings/cmk-keys/[keyId] — revoke a CMK key.
 *
 * Sets status = 'revoked'. Gateway stops accepting encryptions
 * from revoked keys on next key-cache refresh (30s TTL).
 * tenant_id from WorkOS session — keyId must belong to caller's tenant.
 * ADMIN-GATED (owner-only key op): a member/viewer must not be able to
 * degrade the tenant's encryption posture.
 */

import { db } from "@/db";
import { cmkKeys, tenants } from "@/db/schema";
import { ipFromRequest, recordAdminAction } from "@/lib/admin-audit";
import { requireOrgAdmin } from "@/lib/admin-gate";
import { requireSession } from "@/lib/auth";
import { and, eq } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";

export async function DELETE(
	req: NextRequest,
	{ params }: { params: Promise<{ keyId: string }> },
): Promise<NextResponse> {
	const session = await requireSession();
	const denied = await requireOrgAdmin(session);
	if (denied) return denied;
	const { keyId } = await params;

	const tenant = await db
		.select({ id: tenants.id })
		.from(tenants)
		.where(eq(tenants.workosOrgId, session.tenantId))
		.limit(1);

	if (!tenant[0]) {
		return NextResponse.json({ error: "tenant not found" }, { status: 404 });
	}

	const updated = await db
		.update(cmkKeys)
		.set({ status: "revoked" })
		.where(and(eq(cmkKeys.id, keyId), eq(cmkKeys.tenantId, tenant[0].id)))
		.returning({
			id: cmkKeys.id,
			alias: cmkKeys.alias,
			fingerprint: cmkKeys.fingerprint,
		});

	if (updated.length === 0) {
		return NextResponse.json({ error: "key not found" }, { status: 404 });
	}

	// ADR-031: key-material changes leave an audit trail.
	await recordAdminAction({
		actorUserId: session.userId,
		actorWorkspaceId: tenant[0].id,
		action: "cmk_key.revoke",
		targetType: "cmk_key",
		targetId: keyId,
		beforeJson: {
			alias: updated[0]?.alias,
			fingerprint: updated[0]?.fingerprint,
		},
		ipAddr: ipFromRequest(req),
		userAgent: req.headers.get("user-agent"),
	});

	return new NextResponse(null, { status: 204 });
}

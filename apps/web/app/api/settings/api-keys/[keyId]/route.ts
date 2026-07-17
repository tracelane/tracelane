/**
 * DELETE /api/settings/api-keys/[keyId] — revoke a key (soft-delete via revokedAt).
 *
 * Only keys belonging to the authenticated tenant can be revoked.
 * tenant_id comes from WorkOS session, never from URL or body.
 */

import { db } from "@/db";
import { apiKeys, tenants } from "@/db/schema";
import { ipFromRequest, recordAdminAction } from "@/lib/admin-audit";
import { requireSession } from "@/lib/auth";
import { and, eq, isNull } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";

export async function DELETE(
	req: NextRequest,
	{ params }: { params: Promise<{ keyId: string }> },
): Promise<NextResponse> {
	const session = await requireSession();
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
		.update(apiKeys)
		.set({ revokedAt: new Date() })
		.where(
			and(
				eq(apiKeys.id, keyId),
				eq(apiKeys.tenantId, tenant[0].id),
				isNull(apiKeys.revokedAt),
			),
		)
		.returning({
			id: apiKeys.id,
			name: apiKeys.name,
			keyPrefix: apiKeys.keyPrefix,
		});

	if (updated.length === 0) {
		return NextResponse.json(
			{ error: "key not found or already revoked" },
			{ status: 404 },
		);
	}

	// ADR-031: record the revoke action.
	await recordAdminAction({
		actorUserId: session.userId,
		actorWorkspaceId: tenant[0].id,
		action: "api_key.revoke",
		targetType: "api_key",
		targetId: keyId,
		beforeJson: {
			name: updated[0]?.name,
			keyPrefix: updated[0]?.keyPrefix,
		},
		// after_json is null on revoke — the row still exists (soft
		// delete), but we don't write the post-state.
		ipAddr: ipFromRequest(req),
		userAgent: req.headers.get("user-agent"),
	});

	return new NextResponse(null, { status: 204 });
}

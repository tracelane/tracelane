/**
 * DELETE /api/settings/cmk-keys/[keyId] — revoke a CMK key.
 *
 * Sets status = 'revoked'. Gateway stops accepting encryptions
 * from revoked keys on next key-cache refresh (30s TTL).
 * tenant_id from WorkOS session — keyId must belong to caller's tenant.
 */

import { db } from "@/db";
import { cmkKeys, tenants } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { and, eq } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";

export async function DELETE(
	_req: NextRequest,
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
		.update(cmkKeys)
		.set({ status: "revoked" })
		.where(and(eq(cmkKeys.id, keyId), eq(cmkKeys.tenantId, tenant[0].id)))
		.returning({ id: cmkKeys.id });

	if (updated.length === 0) {
		return NextResponse.json({ error: "key not found" }, { status: 404 });
	}

	return new NextResponse(null, { status: 204 });
}

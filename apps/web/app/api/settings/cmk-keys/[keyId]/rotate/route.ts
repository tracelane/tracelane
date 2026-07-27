/**
 * POST /api/settings/cmk-keys/[keyId]/rotate
 *
 * Registers the new public key as a replacement for the existing key.
 * Old key's status becomes "rotating". A background job (V2) will
 * re-encrypt all envelope keys with the new CMK, then revoke the old key.
 *
 * tenant_id from WorkOS session — keyId must belong to caller's tenant.
 * ADMIN-GATED (owner-only key op). The replacement PEM is validated and its
 * REAL algorithm stored (never inherited from the old key), and the
 * fingerprint uses the shared SPKI-DER hash so it reproduces with openssl.
 */

import { db } from "@/db";
import { cmkKeys, tenants } from "@/db/schema";
import { ipFromRequest, recordAdminAction } from "@/lib/admin-audit";
import { requireOrgAdmin } from "@/lib/admin-gate";
import { requireSession } from "@/lib/auth";
import { sha256Fingerprint } from "@/lib/cmk-fingerprint";
import { and, eq } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";
import { resolveCmkAlgorithm } from "../../algorithm";

export async function POST(
	request: NextRequest,
	{ params }: { params: Promise<{ keyId: string }> },
): Promise<NextResponse> {
	const session = await requireSession();
	const denied = await requireOrgAdmin(session);
	if (denied) return denied;
	const { keyId } = await params;

	let body: { publicKeyPem: string };
	try {
		body = (await request.json()) as { publicKeyPem: string };
	} catch {
		return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
	}

	if (!body.publicKeyPem?.trim()) {
		return NextResponse.json(
			{ error: "publicKeyPem is required" },
			{ status: 422 },
		);
	}

	const tenant = await db
		.select({ id: tenants.id })
		.from(tenants)
		.where(eq(tenants.workosOrgId, session.tenantId))
		.limit(1);

	if (!tenant[0]) {
		return NextResponse.json({ error: "tenant not found" }, { status: 404 });
	}

	// Find the active key to rotate
	const oldKeys = await db
		.select()
		.from(cmkKeys)
		.where(
			and(
				eq(cmkKeys.id, keyId),
				eq(cmkKeys.tenantId, tenant[0].id),
				eq(cmkKeys.status, "active"),
			),
		)
		.limit(1);

	const oldKey = oldKeys[0];
	if (!oldKey) {
		return NextResponse.json(
			{ error: "active key not found" },
			{ status: 404 },
		);
	}

	// Validate the REPLACEMENT key and store its real algorithm — inheriting
	// the old key's label would misrepresent a different key type.
	const resolved = resolveCmkAlgorithm(body.publicKeyPem);
	if ("error" in resolved) {
		return NextResponse.json({ error: resolved.error }, { status: 422 });
	}

	const fingerprint = await sha256Fingerprint(body.publicKeyPem);

	// INSERT the replacement BEFORE flipping the old key: if the insert fails
	// (duplicate fingerprint under the unique index, dropped connection) the
	// old key stays ACTIVE — never "rotating" with no successor. neon-http has
	// no transactions, so write ordering is the atomicity lever here.
	const newKey = await db
		.insert(cmkKeys)
		.values({
			tenantId: tenant[0].id,
			alias: `${oldKey.alias} (rotated)`,
			fingerprint,
			algorithm: resolved.algorithm,
			purpose: oldKey.purpose,
			rotatedAt: new Date(),
		})
		.returning();

	await db
		.update(cmkKeys)
		.set({ status: "rotating", rotatedAt: new Date() })
		.where(eq(cmkKeys.id, keyId));

	// ADR-031: key-material changes leave an audit trail.
	await recordAdminAction({
		actorUserId: session.userId,
		actorWorkspaceId: tenant[0].id,
		action: "cmk_key.rotate",
		targetType: "cmk_key",
		targetId: keyId,
		afterJson: {
			newKeyId: newKey[0]?.id,
			fingerprint,
			algorithm: resolved.algorithm,
		},
		ipAddr: ipFromRequest(request),
		userAgent: request.headers.get("user-agent"),
	});

	return NextResponse.json(newKey[0], { status: 201 });
}

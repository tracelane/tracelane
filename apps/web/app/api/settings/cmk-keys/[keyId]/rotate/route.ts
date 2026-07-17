/**
 * POST /api/settings/cmk-keys/[keyId]/rotate
 *
 * Registers the new public key as a replacement for the existing key.
 * Old key's status becomes "rotating". A background job (V2) will
 * re-encrypt all envelope keys with the new CMK, then revoke the old key.
 *
 * tenant_id from WorkOS session — keyId must belong to caller's tenant.
 */

import { db } from "@/db";
import { cmkKeys, tenants } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { and, eq } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";

async function sha256Fingerprint(pem: string): Promise<string> {
	const encoded = new TextEncoder().encode(pem);
	const hashBuf = await crypto.subtle.digest("SHA-256", encoded);
	return Array.from(new Uint8Array(hashBuf))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

export async function POST(
	request: NextRequest,
	{ params }: { params: Promise<{ keyId: string }> },
): Promise<NextResponse> {
	const session = await requireSession();
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

	const fingerprint = await sha256Fingerprint(body.publicKeyPem);

	// Mark old key as rotating, insert new key
	await db
		.update(cmkKeys)
		.set({ status: "rotating", rotatedAt: new Date() })
		.where(eq(cmkKeys.id, keyId));

	const newKey = await db
		.insert(cmkKeys)
		.values({
			tenantId: tenant[0].id,
			alias: `${oldKey.alias} (rotated)`,
			fingerprint,
			algorithm: oldKey.algorithm,
			purpose: oldKey.purpose,
			rotatedAt: new Date(),
		})
		.returning();

	return NextResponse.json(newKey[0], { status: 201 });
}

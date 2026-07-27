/**
 * GET  /api/settings/cmk-keys  — list CMK keys for the authenticated tenant
 * POST /api/settings/cmk-keys  — register a new CMK public key
 *
 * Keys are stored in Neon Postgres via Drizzle ORM.
 * Only the SHA-256 fingerprint of the public key is persisted —
 * the raw PEM is processed and then discarded.
 *
 * tenant_id comes from WorkOS session (organizationId), never from the body.
 * Registering a key is ADMIN-GATED (owner-only key op — a member/viewer must
 * not extend the tenant's encryption trust set); listing stays member-readable
 * (fingerprints only, no key material). Backed by ByokKeyManager.tsx.
 */

import { db } from "@/db";
import { cmkKeys } from "@/db/schema";
import { ipFromRequest, recordAdminAction } from "@/lib/admin-audit";
import { requireOrgAdmin } from "@/lib/admin-gate";
import { requireSession } from "@/lib/auth";
import { sha256Fingerprint } from "@/lib/cmk-fingerprint";
import { upsertTenantId } from "@/lib/tenant";
import { eq } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";
import { resolveCmkAlgorithm } from "./algorithm";

export async function GET(_req: NextRequest): Promise<NextResponse> {
	const session = await requireSession();
	const tenantDbId = await upsertTenantId(session.tenantId);

	const keys = await db
		.select()
		.from(cmkKeys)
		.where(eq(cmkKeys.tenantId, tenantDbId))
		.orderBy(cmkKeys.createdAt);

	return NextResponse.json(keys);
}

interface AddKeyBody {
	alias: string;
	publicKeyPem: string;
	purpose: "provider-keys" | "trace-payload" | "all";
}

export async function POST(request: NextRequest): Promise<NextResponse> {
	const session = await requireSession();
	const denied = await requireOrgAdmin(session);
	if (denied) return denied;
	const tenantDbId = await upsertTenantId(session.tenantId);

	let body: AddKeyBody;
	try {
		body = (await request.json()) as AddKeyBody;
	} catch {
		return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
	}

	if (!body.alias?.trim() || !body.publicKeyPem?.trim()) {
		return NextResponse.json(
			{ error: "alias and publicKeyPem are required" },
			{ status: 422 },
		);
	}

	const resolved = resolveCmkAlgorithm(body.publicKeyPem);
	if ("error" in resolved) {
		return NextResponse.json({ error: resolved.error }, { status: 422 });
	}
	const { algorithm } = resolved;

	const fingerprint = await sha256Fingerprint(body.publicKeyPem);

	const inserted = await db
		.insert(cmkKeys)
		.values({
			tenantId: tenantDbId,
			alias: body.alias.trim(),
			fingerprint,
			algorithm,
			purpose: body.purpose ?? "all",
		})
		.returning();

	// ADR-031: key-material changes leave an audit trail.
	await recordAdminAction({
		actorUserId: session.userId,
		actorWorkspaceId: tenantDbId,
		action: "cmk_key.register",
		targetType: "cmk_key",
		targetId: inserted[0]?.id ?? "unknown",
		afterJson: {
			alias: body.alias.trim(),
			fingerprint,
			algorithm,
			purpose: body.purpose ?? "all",
		},
		ipAddr: ipFromRequest(request),
		userAgent: request.headers.get("user-agent"),
	});

	return NextResponse.json(inserted[0], { status: 201 });
}

/**
 * GET  /api/settings/api-keys  — list active API keys for the authenticated tenant
 * POST /api/settings/api-keys  — create a new tlane_* key; raw key returned once
 *
 *
 * Key creation is proxied to the Rust gateway (`POST /v1/keys`) rather than
 * hashed here. The dashboard runs on the Cloudflare Workers runtime, where the
 * web minter's WASM Argon2 (`hash-wasm`) failed at runtime — every create 500'd.
 * The gateway mints with RustCrypto Argon2 natively, reusing the exact same
 * peppered-HMAC + Argon2id derivation (`crates/gateway/src/db/api_keys.rs`), so
 * keys stay verify-compatible. The gateway resolves the tenant from the per-user
 * WorkOS JWT (never the request body); the raw key is returned exactly once.
 *
 * GET still reads directly from Postgres (no hashing involved); tenant_id comes
 * from the WorkOS session, never the request body.
 */

import { db } from "@/db";
import { apiKeys } from "@/db/schema";
import { ipFromRequest, recordAdminAction } from "@/lib/admin-audit";
import { requireSession } from "@/lib/auth";
import { GatewayError, gatewayPost } from "@/lib/gateway";
import { upsertTenantId } from "@/lib/tenant";
import { and, eq, isNull } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";

export async function GET(_req: NextRequest): Promise<NextResponse> {
	const session = await requireSession();
	const tenantDbId = await upsertTenantId(session.tenantId);

	const rows = await db
		.select({
			id: apiKeys.id,
			name: apiKeys.name,
			keyPrefix: apiKeys.keyPrefix,
			createdAt: apiKeys.createdAt,
			lastUsedAt: apiKeys.lastUsedAt,
			mintedBy: apiKeys.mintedBy,
		})
		.from(apiKeys)
		.where(and(eq(apiKeys.tenantId, tenantDbId), isNull(apiKeys.revokedAt)))
		.orderBy(apiKeys.createdAt);

	return NextResponse.json(rows);
}

interface CreateKeyBody {
	name: string;
}

/** The gateway `/v1/keys` response — the raw key is present exactly once. */
interface CreateKeyResult {
	id: string;
	name: string;
	keyPrefix: string;
	createdAt: string;
	lastUsedAt: string | null;
	rawKey: string;
}

export async function POST(request: NextRequest): Promise<NextResponse> {
	const session = await requireSession();
	// Ensures the tenant row exists and gives its internal UUID for the audit
	// row. The gateway independently resolves the same tenant from the JWT.
	const tenantDbId = await upsertTenantId(session.tenantId);

	let body: CreateKeyBody;
	try {
		body = (await request.json()) as CreateKeyBody;
	} catch {
		return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
	}

	const name = body.name?.trim();
	if (!name) {
		return NextResponse.json({ error: "name is required" }, { status: 422 });
	}

	// Mint on the gateway (RustCrypto Argon2). It resolves the tenant from the
	// per-user JWT and returns the raw key once.
	let created: CreateKeyResult;
	try {
		created = await gatewayPost<CreateKeyResult>("/v1/keys", { name });
	} catch (err) {
		if (err instanceof GatewayError) {
			// Surface auth failures as 401; anything else is an upstream fault.
			const status = err.status === 401 ? 401 : 502;
			return NextResponse.json(
				{ error: "failed to create API key" },
				{ status },
			);
		}
		// A `NEXT_REDIRECT` from requireGatewayToken (unauthenticated) must
		// propagate so Next performs the sign-in redirect.
		throw err;
	}

	// ADR-031: record the admin action (best-effort; failure logged not thrown).
	await recordAdminAction({
		actorUserId: session.userId,
		actorWorkspaceId: tenantDbId,
		action: "api_key.create",
		targetType: "api_key",
		targetId: created.id,
		// Key material (raw key / hashes) intentionally never written to the
		// audit row — store only the non-sensitive shape.
		afterJson: {
			name: created.name,
			keyPrefix: created.keyPrefix,
		},
		ipAddr: ipFromRequest(request),
		userAgent: request.headers.get("user-agent"),
	});

	// raw key returned once — never retrievable again
	return NextResponse.json(created, { status: 201 });
}

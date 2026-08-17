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
			// A13 — `scope: null` renders as "Full access (legacy)"; a non-null
			// array renders the capabilities the key actually carries.
			scope: apiKeys.scope,
			expiresAt: apiKeys.expiresAt,
		})
		.from(apiKeys)
		.where(and(eq(apiKeys.tenantId, tenantDbId), isNull(apiKeys.revokedAt)))
		.orderBy(apiKeys.createdAt);

	return NextResponse.json(rows);
}

interface CreateKeyBody {
	name: string;
	/** A13. Omitted ⇒ the gateway records the explicit full set. */
	scope?: string[];
	/** A13. RFC3339, must be in the future. */
	expiresAt?: string;
	budgetUsdMonthly?: number;
}

/** The gateway `/v1/keys` response — the raw key is present exactly once. */
interface CreateKeyResult {
	id: string;
	name: string;
	keyPrefix: string;
	createdAt: string;
	lastUsedAt: string | null;
	rawKey: string;
	/** A13. `null` only for a key minted before A13. */
	scope: string[] | null;
	expiresAt: string | null;
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
		created = await gatewayPost<CreateKeyResult>("/v1/keys", {
			name,
			// The gateway validates these and 400s on an unknown scope / past
			// expiry; this proxy deliberately does NOT re-validate. One validator,
			// at the enforcement point — a second copy here would drift from it.
			...(body.scope ? { scope: body.scope } : {}),
			...(body.expiresAt ? { expires_at: body.expiresAt } : {}),
			...(body.budgetUsdMonthly != null
				? { budget_usd_monthly: body.budgetUsdMonthly }
				: {}),
		});
	} catch (err) {
		if (err instanceof GatewayError) {
			// A CLIENT error is the caller's to fix and must keep its status AND
			// its message — A13 validation returns 400 naming the bad scope or a
			// past expiry, and collapsing that into a generic 502 would tell the
			// user "failed to create API key" while the gateway had already
			// explained exactly what was wrong. Same defect class as the role-403
			// that once surfaced as an opaque failure.
			//
			// 5xx stays opaque: an upstream fault's message can carry internal
			// state and is not actionable by the caller.
			if (err.status >= 400 && err.status < 500) {
				return NextResponse.json(
					{ error: err.message || "invalid request" },
					{ status: err.status },
				);
			}
			return NextResponse.json(
				{ error: "failed to create API key" },
				{ status: 502 },
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
			scope: created.scope,
			expiresAt: created.expiresAt,
		},
		ipAddr: ipFromRequest(request),
		userAgent: request.headers.get("user-agent"),
	});

	// raw key returned once — never retrievable again
	return NextResponse.json(created, { status: 201 });
}

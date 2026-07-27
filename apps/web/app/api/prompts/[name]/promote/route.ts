/**
 * POST /api/prompts/[name]/promote — proxy to gateway promote endpoint.
 *
 * Mints the per-user WorkOS JWT via `requireGatewayToken()` and forwards
 * the request to the Rust gateway. The gateway resolves the tenant from
 * the JWT (never the body) and enforces entitlements:
 *
 *   - Team+ (prompt_promotion_write): 200/201 → promoted / blocked decision
 *   - Builder ($59): 403 with `{ error, feature, message, upgrade_url }`
 *   - Eval gate blocked: 409
 *
 * All responses (including the entitlement 403 and eval-gate 409) are
 * forwarded verbatim so the client can surface the `upgrade_url`.
 *
 * Defense-in-depth: `requireSession()` is called first so this route is
 * unreachable anonymously even if the gateway JWT check is misconfigured.
 * The gateway's own JWT validation is the authoritative enforcement.
 */

import { ipFromRequest, recordAdminAction } from "@/lib/admin-audit";
import { requireGatewayToken, requireSession } from "@/lib/auth";
import { gatewayBaseUrl } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

interface Params {
	params: Promise<{ name: string }>;
}

export async function POST(req: NextRequest, { params }: Params) {
	// requireSession for userId (used in the audit record below).
	const session = await requireSession();
	// requireGatewayToken mints the per-user WorkOS access token — the gateway
	// uses this to resolve org_id → internal tenant UUID (ADR-042).
	const { token } = await requireGatewayToken();

	const { name } = await params;
	const base = gatewayBaseUrl();
	const url = `${base}/v1/prompts/${encodeURIComponent(name)}/promote`;

	const body = await req.text();

	let upstream: Response;
	try {
		upstream = await fetch(url, {
			method: "POST",
			headers: {
				"content-type": "application/json",
				authorization: `Bearer ${token}`,
			},
			body,
			cache: "no-store",
		});
	} catch (_err) {
		// Gateway transport failure — 503 so the client distinguishes
		// "unreachable" from an entitlement or policy rejection.
		return new NextResponse(JSON.stringify({ error: "gateway_unreachable" }), {
			status: 503,
			headers: { "content-type": "application/json" },
		});
	}

	const data = await upstream.text();

	// ADR-031: record the promotion attempt for any non-5xx upstream response.
	// The gateway writes the tamper-evident chain row (ADR-018); this Postgres
	// row is the application-level mirror. We record 403/409 too so auditors
	// can see that a promotion was attempted even when it was rejected.
	if (upstream.status < 500) {
		await recordAdminAction({
			actorUserId: session.userId,
			// session.tenantId is the WorkOS orgId; actorWorkspaceId stays null
			// until upsertTenantId() lands in the auth layer (V1.1).
			actorWorkspaceId: null,
			action: "prompt.promote",
			targetType: "prompt",
			targetId: name,
			afterJson: { upstreamStatus: upstream.status },
			ipAddr: ipFromRequest(req),
			userAgent: req.headers.get("user-agent"),
		});
	}

	return new NextResponse(data, {
		status: upstream.status,
		headers: { "content-type": "application/json" },
	});
}

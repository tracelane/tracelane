/**
 * /api/settings/api-keys/[keyId]
 *
 * PATCH  — SET-38: edit a key's limits in place (name, scope, expiry, budget,
 *          rate limit, budget cadence, velocity breaker). Proxied to the gateway's
 *          `PATCH /v1/keys/{id}` with the user's JWT.
 * DELETE — revoke. B-586: proxied to the gateway's `DELETE /v1/keys/{id}` so the
 *          revocation reaches the gateway's in-process auth cache in the same
 *          step. It used to be a Drizzle UPDATE here, which never reached the
 *          gateway — a key warm in its cache kept working for up to 60 s.
 *
 * Tenant: the gateway resolves it from the per-user WorkOS JWT, never from the
 * URL or the body. The key id in the path is only ever matched INSIDE that tenant.
 *
 * Authorization lives at the gateway, which is authoritative:
 *   - PATCH has NO web-side role gate (spec SET-38 §2): an owner may edit any key,
 *     a member only keys they minted, a viewer nothing — and only the gateway can
 *     check `minted_by` under the row lock. Its 403 body (`role_forbidden`) is
 *     passed through so the UI can say which role is needed.
 *   - DELETE keeps `requireOrgAdmin` as well: revoke has always been owner-only
 *     (a member must not be able to kill the org's gateway ingress by revoking
 *     keys minted by owners), and the gateway enforces the same rule again.
 *
 * Audit: the gateway writes `api_key.update` / `api_key.revoke` to
 * `admin_audit_log` INSIDE its transaction (fail-closed), so this proxy does not
 * write a second row.
 */

import { requireOrgAdmin } from "@/lib/admin-gate";
import { requireSession } from "@/lib/auth";
import {
	GatewayError,
	gatewayDelete,
	gatewayGet,
	gatewayPatch,
} from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

/**
 * The editable fields, dashboard spelling → gateway spelling. ONE table, so the
 * set this proxy forwards and the set it refuses cannot drift apart.
 */
const PATCH_FIELDS = {
	name: "name",
	scope: "scope",
	expiresAt: "expires_at",
	budgetUsdMonthly: "budget_usd_monthly",
	rateLimitRpm: "rate_limit_rpm",
	budgetReset: "budget_reset",
	velocityBreaker: "velocity_breaker",
	// OG-60: the OG-20 policy document and the OG-23 project / environment. The gateway
	// validates all three (`PatchKeyBody`); this proxy forwards them untouched.
	projectId: "project_id",
	environment: "environment",
	policy: "policy",
} as const;

type PatchField = keyof typeof PATCH_FIELDS;

function isPatchField(k: string): k is PatchField {
	return Object.hasOwn(PATCH_FIELDS, k);
}

/**
 * Map a gateway refusal onto this route's response. A 4xx is the caller's to fix
 * and keeps its status AND the gateway's JSON body (`error` code, `message`,
 * `field`) so the UI can put the text beside the field and render a role 403 as a
 * role message, not a generic failure. A 5xx stays opaque.
 */
function refusal(err: GatewayError, fallback: string): NextResponse {
	if (err.status >= 400 && err.status < 500) {
		return NextResponse.json(err.body ?? { error: err.message }, {
			status: err.status,
		});
	}
	return NextResponse.json({ error: fallback }, { status: 502 });
}

export async function PATCH(
	request: NextRequest,
	{ params }: { params: Promise<{ keyId: string }> },
): Promise<NextResponse> {
	await requireSession();
	const { keyId } = await params;

	let body: unknown;
	try {
		body = await request.json();
	} catch {
		return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
	}
	if (!body || typeof body !== "object" || Array.isArray(body)) {
		return NextResponse.json(
			{ error: "expected a JSON object of the fields to change" },
			{ status: 400 },
		);
	}
	const entries = Object.entries(body as Record<string, unknown>);
	const unknown = entries.map(([k]) => k).filter((k) => !isPatchField(k));
	if (unknown.length > 0) {
		// A smuggled `tenantId` (or anything else) is refused, never dropped: a
		// proxy that silently discards what it does not recognise tells the caller
		// their change was saved.
		return NextResponse.json(
			{
				error: `unknown field(s): ${unknown.join(", ")}`,
				field: unknown[0],
			},
			{ status: 400 },
		);
	}
	// JSON Merge Patch: `null` is forwarded as `null` (clear), and an absent field
	// stays absent (unchanged). The gateway validates every value with the same
	// validators key creation uses; this proxy deliberately does not re-validate.
	const forwarded: Record<string, unknown> = {};
	for (const [k, v] of entries) {
		if (isPatchField(k)) forwarded[PATCH_FIELDS[k]] = v;
	}

	try {
		const updated = await gatewayPatch<unknown>(
			`/v1/keys/${encodeURIComponent(keyId)}`,
			forwarded,
		);
		return NextResponse.json(updated, {
			headers: { "Cache-Control": "no-store" },
		});
	} catch (err) {
		if (err instanceof GatewayError) {
			return refusal(err, "Couldn't save — nothing was changed");
		}
		// A NEXT_REDIRECT (no gateway token) must propagate.
		throw err;
	}
}

export async function DELETE(
	_req: NextRequest,
	{ params }: { params: Promise<{ keyId: string }> },
): Promise<NextResponse> {
	const session = await requireSession();
	const denied = await requireOrgAdmin(session);
	if (denied) return denied;
	const { keyId } = await params;

	try {
		await gatewayDelete(`/v1/keys/${encodeURIComponent(keyId)}`);
	} catch (err) {
		if (err instanceof GatewayError) {
			if (err.status === 404) {
				return NextResponse.json(
					{ error: "key not found or already revoked" },
					{ status: 404 },
				);
			}
			if (err.status === 403) {
				return NextResponse.json(
					{ error: "Only a workspace owner can revoke API keys" },
					{ status: 403 },
				);
			}
			return refusal(err, "Couldn't revoke the key — it is unchanged");
		}
		throw err;
	}
	return new NextResponse(null, { status: 204 });
}

/** Read this tenant's current key and budget-window spend through the gateway. */
export async function GET(
	_request: NextRequest,
	{ params }: { params: Promise<{ keyId: string }> },
): Promise<NextResponse> {
	await requireSession();
	const { keyId } = await params;
	try {
		return NextResponse.json(
			await gatewayGet(`/v1/keys/${encodeURIComponent(keyId)}`),
			{ headers: { "Cache-Control": "no-store" } },
		);
	} catch (err) {
		if (err instanceof GatewayError)
			return refusal(err, "Could not load this key");
		throw err;
	}
}

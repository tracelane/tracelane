/**
 * POST /api/settings/workspace/portal — generate a WorkOS Admin Portal link.
 *
 * The customer-facing, WorkOS-hosted self-service portal for SSO, directory
 * sync (SCIM), and domain verification — the correct target for org admins (the
 * bare `dashboard.workos.com` link went to OUR project console, which customers
 * can't access). Links are single-use + short-lived, so we mint one per click.
 *
 * ADMIN-GATED (WorkOS trusts whoever holds the link — a plain member must not be
 * able to mint one). The org derives from the session, never the body. Server-only.
 */

import { db } from "@/db";
import { tenants } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { type Plan, resolveEntitlements } from "@/lib/entitlements";
import { callerIsOrgAdmin } from "@/lib/workos-org";
import { eq } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";

/** WorkOS Admin Portal intents we expose to org admins. */
const ALLOWED_INTENTS = new Set([
	"sso",
	"dsync",
	"domain_verification",
	"audit_logs",
]);

/**
 * Intents that are the PAID `saml_sso` capability (SET-24 / 5D-3).
 *
 * `sso` is SAML configuration and `dsync` is SCIM directory sync — both are sold
 * on Enterprise only (`PLAN_ENTITLEMENTS.enterprise.saml_sso`, the sole `true`).
 * Until 2026-08-10 this route gated on `callerIsOrgAdmin` ALONE, so any org admin
 * on ANY plan — including Free — could open the portal and configure SAML. Role is
 * not a plan: being an admin says who you are, not what you bought.
 *
 * `domain_verification` and `audit_logs` are deliberately NOT here: domain
 * verification is a prerequisite step with no paid capability behind it, and
 * WorkOS audit_logs is a separate surface we do not sell as `saml_sso`.
 */
const SAML_SSO_INTENTS = new Set(["sso", "dsync"]);

interface PortalBody {
	intent: string;
}

export async function POST(request: NextRequest): Promise<NextResponse> {
	const key = process.env.WORKOS_API_KEY;
	if (!key) {
		return NextResponse.json(
			{ error: "WorkOS API not configured" },
			{ status: 501 },
		);
	}

	const session = await requireSession();

	let body: PortalBody;
	try {
		body = (await request.json()) as PortalBody;
	} catch {
		return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
	}

	if (!ALLOWED_INTENTS.has(body.intent)) {
		return NextResponse.json({ error: "invalid intent" }, { status: 422 });
	}

	// The Admin Portal is a HIGH-privilege surface (SSO swap, SCIM, domain
	// verification) — WorkOS trusts whoever holds the generated link. Gate to
	// admins/owners; fail closed (502) if the role can't be verified.
	const admin = await callerIsOrgAdmin(key, session.tenantId, session.userId);
	if (admin === null) {
		return NextResponse.json(
			{ error: "could not verify permissions" },
			{ status: 502 },
		);
	}
	if (!admin) {
		return NextResponse.json(
			{ error: "admin or owner role required" },
			{ status: 403 },
		);
	}

	// SET-24 / 5D-3: ROLE IS NOT A PLAN. The admin check above answers "who is
	// this?"; this answers "did they buy it?". Both are required for a paid
	// capability, and only the first existed.
	if (SAML_SSO_INTENTS.has(body.intent)) {
		const [tenantRow] = await db
			.select({ id: tenants.id, plan: tenants.plan })
			.from(tenants)
			.where(eq(tenants.workosOrgId, session.tenantId))
			.limit(1);

		// Fail CLOSED to `free`. An unknown/missing plan must never inherit a paid
		// capability — `.claude/rules/tenancy.md`: absent entitlement data resolves
		// to the UNPRIVILEGED state, never the privileged one.
		const plan: Plan = (tenantRow?.plan as Plan) ?? "free";
		const entitlements = await resolveEntitlements(tenantRow?.id, plan);
		if (!entitlements.saml_sso) {
			return NextResponse.json(
				{ error: "saml_sso_required", upgrade_url: "/settings/billing" },
				{ status: 403 },
			);
		}
	}

	const res = await fetch("https://api.workos.com/portal/generate_link", {
		method: "POST",
		headers: {
			Authorization: `Bearer ${key}`,
			"Content-Type": "application/json",
		},
		body: JSON.stringify({
			organization: session.tenantId,
			intent: body.intent,
		}),
	});
	if (!res.ok) {
		return NextResponse.json(
			{ error: "could not generate portal link" },
			{ status: 502 },
		);
	}

	const data = (await res.json()) as { link?: string };
	if (!data.link) {
		return NextResponse.json(
			{ error: "portal link missing from WorkOS response" },
			{ status: 502 },
		);
	}
	return NextResponse.json({ link: data.link }, { status: 200 });
}

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

import { requireSession } from "@/lib/auth";
import { callerIsOrgAdmin } from "@/lib/workos-org";
import { type NextRequest, NextResponse } from "next/server";

/** WorkOS Admin Portal intents we expose to org admins. */
const ALLOWED_INTENTS = new Set([
	"sso",
	"dsync",
	"domain_verification",
	"audit_logs",
]);

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

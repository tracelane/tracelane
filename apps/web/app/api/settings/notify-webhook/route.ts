/**
 * PUT / DELETE /api/settings/notify-webhook — the tenant's quota-alert webhook.
 *
 * SET-04. The column (`tenants.slack_webhook_url`), the gateway-side reader
 * (`server.rs::resolve_tenant_quota_webhook`) and the notifier
 * (`notify_quota_exceeded_async`) all shipped long ago; this route is the
 * missing WRITER. Until it existed the column was NULL for every tenant, so the
 * quota-exceeded alert the pricing page promises could never fire for anyone.
 *
 * ADMIN-GATED, same as the org rename: the destination is workspace-wide, so a
 * plain member must not be able to repoint (or silence) everyone's alerts.
 * `tenant_id` derives from the session org id, never the request body.
 *
 * Validation here is a UX guard, not the security boundary — the gateway runs
 * `ssrf_guard::validate_url` against the stored value before every POST, so a
 * row written by any other path is still checked at send time.
 *
 * The column name says "slack" for historical reasons; nothing in this route or
 * in the gateway's send path requires a `hooks.slack.com` host. Any HTTPS
 * receiver works, which is what keeps the notifier channel-agnostic.
 */

import { db } from "@/db";
import { tenants } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { callerIsOrgAdmin } from "@/lib/workos-org";
import { eq } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";

/** Max stored length — the column is TEXT; this bounds abuse, not correctness. */
const MAX_URL_LEN = 2048;

interface PutBody {
	url: string;
}

/**
 * Reject anything that is not a parseable absolute HTTPS URL.
 *
 * Plain `http:` is refused because the payload names the tenant and their usage
 * numbers; sending that in cleartext is a downgrade the customer did not ask
 * for. Returns the normalised href on success so what we store is what we sent.
 */
function normaliseWebhookUrl(raw: unknown): string | null {
	if (typeof raw !== "string") return null;
	const trimmed = raw.trim();
	if (!trimmed || trimmed.length > MAX_URL_LEN) return null;
	let parsed: URL;
	try {
		parsed = new URL(trimmed);
	} catch {
		return null;
	}
	if (parsed.protocol !== "https:") return null;
	return parsed.href;
}

/** Shared admin gate — fails CLOSED (502) when the role cannot be verified. */
async function requireAdmin(
	tenantId: string,
	userId: string,
): Promise<NextResponse | null> {
	const key = process.env.WORKOS_API_KEY;
	if (!key) {
		return NextResponse.json(
			{ error: "WorkOS API not configured" },
			{ status: 501 },
		);
	}
	const admin = await callerIsOrgAdmin(key, tenantId, userId);
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
	return null;
}

export async function PUT(request: NextRequest): Promise<NextResponse> {
	const session = await requireSession();

	let body: PutBody;
	try {
		body = (await request.json()) as PutBody;
	} catch {
		return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
	}

	const url = normaliseWebhookUrl(body?.url);
	if (!url) {
		return NextResponse.json(
			{ error: "url must be an absolute https:// URL under 2048 characters" },
			{ status: 422 },
		);
	}

	const denied = await requireAdmin(session.tenantId, session.userId);
	if (denied) return denied;

	await db
		.update(tenants)
		.set({ slackWebhookUrl: url })
		.where(eq(tenants.workosOrgId, session.tenantId));

	return NextResponse.json({ url }, { status: 200 });
}

export async function DELETE(): Promise<NextResponse> {
	const session = await requireSession();

	const denied = await requireAdmin(session.tenantId, session.userId);
	if (denied) return denied;

	await db
		.update(tenants)
		.set({ slackWebhookUrl: null })
		.where(eq(tenants.workosOrgId, session.tenantId));

	return NextResponse.json({ url: null }, { status: 200 });
}

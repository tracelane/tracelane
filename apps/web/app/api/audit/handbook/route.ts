/**
 * GET /api/audit/handbook — download the Compliance & Evidence Handbook (PDF).
 *
 * The Audit-SKU (paid) companion to the free public User Guide. Gated on the
 * `audit_ledger` entitlement (= f_audit_addon, deny-overrides-grant per ADR-009)
 * — the SAME source that gates the evidence-pack export. A non-entitled tenant
 * gets 403; the free User Guide (public static file) is unaffected.
 *
 * The PDF is a build-time asset (base64) served from the worker bundle so the
 * gate can't be bypassed by guessing a public URL. tenant_id comes from the
 * WorkOS session, never the request.
 */

import { db } from "@/db";
import { tenants } from "@/db/schema";
import { AUDIT_HANDBOOK_PDF_B64 } from "@/lib/audit-handbook-asset";
import { requireSession } from "@/lib/auth";
import { type Plan, resolveEntitlements } from "@/lib/entitlements";
import { eq } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";

export async function GET(_req: NextRequest): Promise<NextResponse> {
	const session = await requireSession();

	const [tenantRow] = await db
		.select({ id: tenants.id, plan: tenants.plan })
		.from(tenants)
		.where(eq(tenants.workosOrgId, session.tenantId))
		.limit(1);

	const plan: Plan = (tenantRow?.plan as Plan) ?? "builder";
	const entitlements = await resolveEntitlements(tenantRow?.id, plan);
	if (!entitlements.audit_ledger) {
		return NextResponse.json(
			{ error: "audit_addon_required", upgrade_url: "/settings/billing" },
			{ status: 403 },
		);
	}

	// Decode the bundled base64 PDF (browser-safe atob path — the worker has no
	// Node Buffer). Convert to bytes once; the file is ~100 KB.
	const bin = atob(AUDIT_HANDBOOK_PDF_B64);
	const bytes = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);

	return new NextResponse(bytes, {
		status: 200,
		headers: {
			"content-type": "application/pdf",
			"content-disposition":
				'attachment; filename="tracelane-audit-compliance-handbook.pdf"',
			"cache-control": "private, no-store",
		},
	});
}

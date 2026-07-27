/**
 * GET /api/entitlements — feature flags + quota + seat caps + retention for
 * the authenticated tenant.
 *
 * Resolution order (deny-overrides-grant per ADR-009 §7.4.9) lives in
 * `@/lib/entitlements` so the seat-cap enforcement on team invite and this
 * handler share one authoritative resolver.
 *
 * tenant_id comes from the WorkOS session, never from the request.
 */

import { db } from "@/db";
import { tenants } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { type Plan, resolveEntitlements } from "@/lib/entitlements";
import { eq } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";

export async function GET(_req: NextRequest): Promise<NextResponse> {
	const session = await requireSession();

	const tenantRow = await db
		.select({
			id: tenants.id,
			plan: tenants.plan,
		})
		.from(tenants)
		.where(eq(tenants.workosOrgId, session.tenantId))
		.limit(1);

	const plan: Plan = (tenantRow[0]?.plan as Plan) ?? "builder";
	const entitlements = await resolveEntitlements(tenantRow[0]?.id, plan);

	return NextResponse.json(entitlements);
}

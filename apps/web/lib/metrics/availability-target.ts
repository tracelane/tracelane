/**
 * The PLAN's availability target for a workspace, 0–1 — the value `/dashboard` measures
 * against (`apps/web/app/dashboard/page.tsx`, `availabilityTarget`). Custom dashboards
 * pass it into `fetchTileData` so an `availability` or `burn_rate` tile uses the same
 * floor and the same target as the built-in headline (spec §7.1 parity; verifier
 * 2026-09-05 found the first build hardcoded 99.9% and the default floor).
 *
 * Falls back to the documented default when there is no tenant row or the read fails:
 * an SLA lookup must never break the surface, and an unseeded tenant is not measured
 * against a target we cannot substantiate.
 */
import {
	SLO_TARGET_AVAILABILITY,
	availabilityTargetForPlanKey,
} from "@/app/slo/budget";
import { db } from "@/db";
import { tenants } from "@/db/schema";
import { PLAN_TO_LOOKUP_KEY, type Plan } from "@/lib/entitlements";
import { eq } from "drizzle-orm";

export async function availabilityTargetFor(
	workosOrgId: string,
): Promise<number> {
	try {
		const [row] = await db
			.select({ plan: tenants.plan })
			.from(tenants)
			.where(eq(tenants.workosOrgId, workosOrgId))
			.limit(1);
		const plan = (row?.plan as Plan) ?? "free";
		return availabilityTargetForPlanKey(PLAN_TO_LOOKUP_KEY[plan]);
	} catch {
		return SLO_TARGET_AVAILABILITY;
	}
}

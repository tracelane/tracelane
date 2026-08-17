/**
 * /plans — the in-app plan ladder (SET-15).
 *
 * Before this page, the only "see all plans" path out of the product was a link
 * to the marketing site (`tracelane.dev/#pricing`), so comparing tiers meant
 * leaving the dashboard and reading copy that no code check binds. This page is
 * built from `PLAN_ENTITLEMENTS` — the same map the entitlement resolver falls
 * back to — so the ladder cannot drift from the quota the gateway enforces.
 *
 * The viewer's CURRENT plan column shows their RESOLVED entitlements (workspace
 * overrides applied, deny-overrides-grant), not the stock plan defaults; other
 * columns show stock defaults, because an override on this workspace says
 * nothing about what another tier would grant.
 *
 * Server component. Reads the session cookie + Postgres at request time.
 */

import { PlanLadder } from "@/components/settings/PlanLadder";
import {
	buildLadder,
	hasCustomLimits,
} from "@/components/settings/plan-catalog";
import { db } from "@/db";
import { tenants } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { type Plan, resolveEntitlements } from "@/lib/entitlements";
import { eq } from "drizzle-orm";
import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

export const metadata: Metadata = { title: "Plans" };

// Session cookie + Postgres at request time — never prerender.
export const dynamic = "force-dynamic";

/**
 * Resolve the tenant row for the session's WorkOS org.
 *
 * Binding `session.tenantId` (the WorkOS org id) into a Postgres
 * `eq(tenants.workosOrgId, …)` filter is the sanctioned bridge; the raw org id
 * is never bound into a gateway/ClickHouse query.
 */
async function getTenant(workosOrgId: string) {
	const rows = await db
		.select({ id: tenants.id, plan: tenants.plan })
		.from(tenants)
		.where(eq(tenants.workosOrgId, workosOrgId))
		.limit(1);
	return rows[0] ?? null;
}

export default async function PlansPage() {
	const session = await requireSession();
	const tenant = await getTenant(session.tenantId);

	if (!tenant) redirect("/onboarding");

	const plan = tenant.plan as Plan;
	const resolved = await resolveEntitlements(tenant.id, plan);
	const cards = buildLadder(plan, resolved);

	return (
		<div className="px-2 py-3 sm:px-4 sm:py-4">
			<div className="mb-4 space-y-1">
				<h1 className="t-h1">Plans</h1>
				<p className="text-xs text-ink-2">
					Every figure below is read from the entitlement the gateway enforces —
					your current plan shows your workspace's own limits. Manage your
					subscription, payment method and invoices in{" "}
					<Link
						href="/settings/billing"
						className="underline underline-offset-2 hover:text-ink"
					>
						Settings → Billing
					</Link>
					.
				</p>
			</div>

			<PlanLadder
				cards={cards}
				currentPlan={plan}
				customLimitsNote={hasCustomLimits(plan, resolved)}
			/>
		</div>
	);
}

/**
 * /plans — the in-app plan ladder (SET-15 / ADR-076).
 *
 * Five tiers, straight from `apps/web/db/plans.v3.json` via `plan-catalog.ts`
 * — never re-typed. Before this page, the only "see all plans" path out of
 * the product was a link to the marketing site, so comparing tiers meant
 * leaving the dashboard and reading copy that no code check binds.
 *
 * The current plan is highlighted from the tenant row (`tenants.plan`); every
 * other column shows the same stock plan figures a signed-out visitor would
 * see on the marketing `/pricing` page — the numbers are identical because
 * both read the same JSON.
 *
 * Server component. Reads the session cookie + Postgres at request time.
 */

import { PlanLadder } from "@/components/settings/PlanLadder";
import { buildLadder } from "@/components/settings/plan-catalog";
import { db } from "@/db";
import { tenants } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import type { Plan } from "@/lib/entitlements";
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
	const cards = buildLadder();

	return (
		<div className="px-2 py-3 sm:px-4 sm:py-4">
			<div className="mb-4 space-y-1">
				<h1 className="t-h1">Plans</h1>
				<p className="text-xs text-ink-2">
					Six meters, priced the same way on every paid tier. Manage your
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

			<PlanLadder cards={cards} currentPlan={plan} />
		</div>
	);
}

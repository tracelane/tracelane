/**
 * /settings/billing — the usage board (spec `BILL-01-metering-and-tiers.md`
 * §8 `#usage` + `#plan-change`). Server component: reads the tenant row once
 * and hands the client `<UsageBoard>` just enough to make its ONE gateway
 * call (spec §2.5b) — everything else (percentages, badges, the breakdown,
 * the ceiling write) happens client-side or on-demand.
 */

import { PlanCard, PlanHeader } from "@/components/billing/PlanCard";
import { UsageBoard } from "@/components/billing/UsageBoard";
import { db } from "@/db";
import { tenants } from "@/db/schema";
import { canAdmin, requireSession } from "@/lib/auth";
import type { Plan } from "@/lib/entitlements";
import { eq } from "drizzle-orm";
import type { Metadata } from "next";
import { redirect } from "next/navigation";

export const metadata: Metadata = { title: "Billing — Settings" };

// Reads the session cookie + Postgres at request time — never prerender.
export const dynamic = "force-dynamic";

async function getTenantBilling(workosOrgId: string) {
	const rows = await db
		.select({
			id: tenants.id,
			plan: tenants.plan,
			polarCustomerId: tenants.polarCustomerId,
			billingInterval: tenants.billingInterval,
			annualPair: tenants.annualPair,
			spendCeilingUsd: tenants.spendCeilingUsd,
			overflowMode: tenants.overflowMode,
		})
		.from(tenants)
		.where(eq(tenants.workosOrgId, workosOrgId))
		.limit(1);
	return rows[0] ?? null;
}

export default async function BillingPage() {
	const session = await requireSession();
	const billing = await getTenantBilling(session.tenantId);

	if (!billing) redirect("/onboarding");

	const plan = billing.plan as Plan;
	const ceilingUsd = billing.spendCeilingUsd
		? Number(billing.spendCeilingUsd)
		: null;
	const overflowMode =
		(billing.overflowMode as "auto_age" | "auto_overage" | null) ?? "auto_age";

	// BILL-02: a refused annual pair sits on Free WITH `billing_interval = year`
	// and an alert — the header must show the banner even though the plan reads
	// free, so the interval is read whenever a pair exists, not only when paid.
	const pair = billing.annualPair ?? null;
	const hasPair = !!(pair?.base || pair?.usage);
	const billingInterval =
		plan === "free" && !hasPair
			? null
			: ((billing.billingInterval as "month" | "year" | null) ?? "month");
	const annual = hasPair
		? {
				basePeriodEnd: pair?.base?.period_end ?? null,
				alert: pair?.alert ?? null,
			}
		: null;

	return (
		<div className="space-y-6">
			{/* The current tier FIRST — the one fact every visitor to this page
			    wants before any meter (founder, 2026-09-14). */}
			<PlanHeader
				plan={plan}
				billingInterval={billingInterval}
				annual={annual}
			/>
			<UsageBoard
				plan={plan}
				canManage={canAdmin(session.role)}
				initialCeilingUsd={ceilingUsd}
				initialOverflowMode={overflowMode}
			/>
			<PlanCard
				plan={plan}
				hasBillingAccount={billing.polarCustomerId !== null}
			/>
		</div>
	);
}

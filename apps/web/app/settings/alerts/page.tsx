/**
 * /settings/alerts — Alert destinations + rules management page.
 *
 * Gated on the `f_alerts` entitlement (ADR-059 / migrations 0012 + 0013). Free
 * tenants see an honest "available on Builder+" upsell — no fabricated data, no
 * 500. Entitled tenants (Builder+ or a workspace grant) get the AlertsManager.
 *
 * tenant_id comes exclusively from the WorkOS session; never from the request.
 */

import { AlertsManager } from "@/components/settings/AlertsManager";
import { db } from "@/db";
import { tenants } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { type Plan, resolveEntitlements } from "@/lib/entitlements";
import { eq } from "drizzle-orm";
import type { Metadata } from "next";

export const metadata: Metadata = { title: "Alerts — Settings" };
export const dynamic = "force-dynamic";

async function isAlertsEntitled(): Promise<boolean> {
	const session = await requireSession();
	const [row] = await db
		.select({ id: tenants.id, plan: tenants.plan })
		.from(tenants)
		.where(eq(tenants.workosOrgId, session.tenantId))
		.limit(1);
	const plan: Plan = (row?.plan as Plan) ?? "free";
	const entitlements = await resolveEntitlements(row?.id, plan);
	return entitlements.f_alerts;
}

// Free tenants see an honest upsell (not an error): alerting is a Builder+
// feature, so surface the value + the upgrade path rather than a dead gate.
function AlertsUpsell() {
	return (
		<div className="rounded-lg border border-dashed border-line p-10 text-center space-y-3">
			<h3 className="text-sm font-semibold text-ink">
				Alerts is available on Builder and above
			</h3>
			<p className="text-xs text-ink-2 max-w-sm mx-auto">
				Set threshold rules on your error rate, latency, cost, and quota, and
				get notified in Slack or Discord the moment one fires. Upgrade to
				Builder to turn on alerting for this workspace.
			</p>
			<a
				href="/settings/billing"
				className="inline-block text-xs font-medium text-accent-ink hover:underline"
			>
				View plans →
			</a>
		</div>
	);
}

export default async function AlertsPage() {
	const entitled = await isAlertsEntitled();

	return (
		<div className="space-y-1">
			<h2 className="text-sm font-semibold text-ink">Alerts</h2>
			<p className="text-xs text-ink-2 mb-6">
				Configure webhook destinations and metric threshold rules. When a rule
				fires, Tracelane sends a notification to the configured destination.
			</p>
			{entitled ? <AlertsManager /> : <AlertsUpsell />}
		</div>
	);
}

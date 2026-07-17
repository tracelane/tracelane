/**
 * /settings/billing — plan and billing management page.
 *
 * Shows current plan, audit status, in-app upgrade actions (POST /api/checkout
 * → Polar-hosted checkout), and opens the Polar-hosted billing portal for
 * payment method / invoice / plan changes. Server component.
 */

import { BillingPortalButton } from "@/components/settings/BillingPortalButton";
import { db } from "@/db";
import { tenants } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { Badge } from "@tracelanedev/ui";
import { eq } from "drizzle-orm";
import type { Metadata } from "next";
import { redirect } from "next/navigation";

export const metadata: Metadata = { title: "Billing — Settings" };

const PLAN_LABEL: Record<string, string> = {
	builder: "Builder — $59/mo",
	team: "Team — $249/mo",
	business: "Business — $899/mo",
	enterprise: "Enterprise",
};

const PLAN_FEATURES: Record<string, string[]> = {
	builder: [
		"30+-provider gateway",
		"Full-fidelity traces (90-day hot)",
		"Predictive guardrails (warn mode)",
		"Prompt promotion (read-only)",
		"1 team member",
	],
	team: [
		"Everything in Builder",
		"Prompt promotion + eval gates",
		"Auto-rollback workflow",
		"Up to 10 team members",
		"Priority support",
	],
	business: [
		"Everything in Team",
		"Tamper-evident audit ledger",
		"BYOK envelope encryption",
		"SLO dashboards",
		"25 team members included (+$19/seat to 50)",
	],
	enterprise: [
		"Everything in Business",
		"SAML SSO",
		"Custom data residency",
		"Dedicated support SLA",
		"Audit add-on ($999/mo)",
	],
};

/**
 * Self-serve upgrade targets per current plan (Enterprise is sales-led — no
 * self-serve checkout). Each target renders a form that POSTs to `/api/checkout`,
 * which 302-redirects to the Polar-hosted checkout. That route fails loud (501)
 * until the deployment sets `POLAR_PRODUCT_ID_<TIER>` for the tier — so the
 * funnel is wired-but-dark pre-launch, never a silently-broken checkout.
 */
const UPGRADE_TARGETS: Record<string, string[]> = {
	free: ["builder", "team", "business"],
	builder: ["team", "business"],
	team: ["business"],
	business: [],
	enterprise: [],
};

const TIER_NAME: Record<string, string> = {
	builder: "Builder",
	team: "Team",
	business: "Business",
};

async function getTenantBilling(workosOrgId: string) {
	const rows = await db
		.select({
			plan: tenants.plan,
			auditEnabled: tenants.auditEnabled,
			polarCustomerId: tenants.polarCustomerId,
		})
		.from(tenants)
		.where(eq(tenants.workosOrgId, workosOrgId))
		.limit(1);

	return rows[0] ?? null;
}

// Reads the session cookie + Postgres at request time — never prerender.
export const dynamic = "force-dynamic";

export default async function BillingPage() {
	const session = await requireSession();
	const billing = await getTenantBilling(session.tenantId);

	if (!billing) redirect("/onboarding");

	const plan = billing.plan;
	const features = PLAN_FEATURES[plan] ?? [];
	const hasBillingAccount = !!billing.polarCustomerId;
	const upgradeTargets = UPGRADE_TARGETS[plan] ?? [];

	return (
		<div className="space-y-6">
			<div>
				<h2 className="text-sm font-semibold text-ink">Current plan</h2>
				<p className="text-xs text-ink-2 mt-0.5">
					Plan changes take effect immediately via Polar webhook.
				</p>
			</div>

			<div className="rounded-lg border border-line p-5 space-y-4">
				<div className="flex items-center justify-between">
					<div>
						<p className="text-base font-semibold text-ink">
							{PLAN_LABEL[plan] ?? plan}
						</p>
						{billing.auditEnabled && (
							<Badge tone="seal" className="mt-1">
								Audit add-on active
							</Badge>
						)}
					</div>
					{hasBillingAccount ? (
						<BillingPortalButton />
					) : (
						<span className="text-xs text-ink-3">
							No billing account yet — upgrade to add payment method.
						</span>
					)}
				</div>

				<ul className="space-y-1.5">
					{features.map((f) => (
						<li key={f} className="flex items-center gap-2 text-xs text-ink-2">
							<svg
								viewBox="0 0 16 16"
								fill="none"
								stroke="currentColor"
								strokeWidth={2}
								className="h-3.5 w-3.5 shrink-0 text-ink-2"
								aria-hidden="true"
							>
								<polyline points="3 8 6 11 13 4" />
							</svg>
							{f}
						</li>
					))}
				</ul>
			</div>

			<div className="rounded-lg border border-line p-5 space-y-3">
				<h3 className="text-sm font-medium text-ink">Upgrade your plan</h3>
				<p className="text-xs text-ink-2">
					Builder → Team unlocks Prompt Promotion, Eval Gates, and
					Auto-Rollback. Team → Business adds the tamper-evident audit ledger
					and BYOK. Business → Enterprise adds 25M+ traces, unlimited seats,
					365-day retention, SSO, and a dedicated support SLA.
				</p>
				{upgradeTargets.length > 0 && (
					<div className="flex flex-wrap gap-2 pt-1">
						{upgradeTargets.map((tier) => (
							// Native form POST → /api/checkout returns a 302 to the
							// Polar-hosted checkout, which the browser follows. No client JS.
							<form
								key={tier}
								action={`/api/checkout?tier=${tier}`}
								method="post"
							>
								<button
									type="submit"
									className="px-3 py-1.5 rounded text-xs bg-accent text-accent-on hover:bg-accent/90 transition-colors"
								>
									Upgrade to {TIER_NAME[tier] ?? tier}
								</button>
							</form>
						))}
						{/* Enterprise is sales-led — a contact CTA, never a checkout
						    button (that route 501s without a Polar Enterprise product). */}
						{plan !== "enterprise" && (
							<a
								href="mailto:sales@tracelane.dev?subject=Tracelane%20Enterprise"
								className="rounded border border-line px-3 py-1.5 text-xs font-medium text-ink-2 transition-colors hover:border-line-2 hover:text-ink"
							>
								Contact us — Enterprise
							</a>
						)}
					</div>
				)}
				{/* When there are no self-serve upgrades left (Business), still offer
				    the Enterprise contact path. */}
				{upgradeTargets.length === 0 && plan !== "enterprise" && (
					<a
						href="mailto:sales@tracelane.dev?subject=Tracelane%20Enterprise"
						className="inline-block rounded border border-line px-3 py-1.5 text-xs font-medium text-ink-2 transition-colors hover:border-line-2 hover:text-ink"
					>
						Contact us — Enterprise
					</a>
				)}
				{/* Marketing pricing is a homepage section (id="pricing"), not a
				    standalone /pricing route — the latter 500s (CF Worker 1101).
				    Link the working anchor. */}
				<a
					href="https://tracelane.dev/#pricing"
					target="_blank"
					rel="noopener noreferrer"
					className="inline-block mt-1 text-xs text-ink-2 underline underline-offset-2 hover:text-ink transition-colors"
				>
					View all plans →
				</a>
			</div>
		</div>
	);
}

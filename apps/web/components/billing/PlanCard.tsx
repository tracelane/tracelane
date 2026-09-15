/**
 * PlanHeader (current plan, top of the page) + PlanCard (audit-ledger +
 * invoices, bottom) for `/settings/billing` (spec §8 `#plan-change`). Server component: every
 * price/window figure comes straight from `plans.v3.json` via
 * `plan-catalog.ts`, never re-typed.
 *
 * Upgrade/downgrade are native `<form method="post">`s to `/api/checkout`,
 * which redirects to Polar checkout (free → paid) or the customer portal
 * (an existing subscriber changing plans, B-140) — this card never has to
 * know which. A live proration PREVIEW ("Prorated today: $X") would need a
 * gateway endpoint this build slice does not define (spec §2.6 lists no
 * `/v1/billing/checkout/preview`); the inline copy below states the POLICY
 * (upgrade prorates immediately, downgrade takes effect at period end —
 * spec §0.5) rather than a computed dollar figure it cannot honestly show.
 */

import { BillingPortalButton } from "@/components/settings/BillingPortalButton";
import { LADDER, buildCard } from "@/components/settings/plan-catalog";
import type { Plan } from "@/lib/entitlements";
import { Badge } from "@tracelanedev/ui";

/**
 * PlanHeader — the CURRENT PLAN, first thing on `/settings/billing` (founder,
 * 2026-09-14: "we should display the current tier as well for the user").
 * Name, price for the interval actually billed, the interval badge, and the
 * plan-change actions. Server component; every figure is `plans.v3.json`.
 */
export function PlanHeader({
	plan,
	billingInterval,
}: {
	plan: Plan;
	/** null on Free (no billing account yet). */
	billingInterval: "month" | "year" | null;
}) {
	const card = buildCard(plan);
	const idx = LADDER.indexOf(plan);
	const price =
		billingInterval === "year" && card.priceYear
			? card.priceYear
			: card.priceMonth;

	return (
		<div className="space-y-4">
			<div
				className="surface-card rounded-[var(--radius-card)] border border-line p-5"
				data-testid="current-plan"
			>
				<div className="flex flex-wrap items-center justify-between gap-3">
					<div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
						{/* A real heading: `e2e/billing.spec.ts` finds this card by
						    role=heading /current plan/, and a screen reader lands on it. */}
						<h2 className="t-card-title">Current plan</h2>
						<p className="text-lg font-semibold text-ink">
							{card.name}
							<span className="ml-2 text-base font-normal text-ink-2">
								{price.fromLabel ? "from " : ""}
								{price.amount}
								{price.suffix}
							</span>
						</p>
						{billingInterval ? (
							<Badge tone="neutral">billed {billingInterval}ly</Badge>
						) : (
							<Badge tone="neutral">no billing account yet</Badge>
						)}
					</div>
					<div className="flex flex-wrap gap-2">
						{plan !== "free" &&
							plan !== "enterprise" &&
							billingInterval !== "year" &&
							card.priceYear && (
								<form
									action={`/api/checkout?tier=${plan}&interval=year`}
									method="post"
								>
									<button
										type="submit"
										className="rounded border border-line bg-surface px-3 py-1.5 text-xs font-medium text-ink-2 transition-colors hover:border-line-2 hover:text-ink"
									>
										Switch to annual {card.priceYear?.amount}
										{card.priceYear?.suffix}
									</button>
								</form>
							)}
						{idx >= 0 && idx < LADDER.length - 2 && LADDER[idx + 1] && (
							<form
								action={`/api/checkout?tier=${LADDER[idx + 1]}&interval=${billingInterval ?? "month"}`}
								method="post"
							>
								<button
									type="submit"
									className="rounded bg-action px-3 py-1.5 text-xs font-medium text-action-on transition-colors hover:bg-action/90"
								>
									Upgrade to {buildCard(LADDER[idx + 1] as Plan).name}
								</button>
							</form>
						)}
						{idx > 0 &&
							plan !== "free" &&
							plan !== "enterprise" &&
							LADDER[idx - 1] && (
								<form
									action={`/api/checkout?tier=${LADDER[idx - 1]}&interval=${billingInterval ?? "month"}`}
									method="post"
								>
									<button
										type="submit"
										className="rounded border border-line bg-surface px-3 py-1.5 text-xs font-medium text-ink-2 transition-colors hover:border-line-2 hover:text-ink"
									>
										Downgrade to {buildCard(LADDER[idx - 1] as Plan).name}
									</button>
								</form>
							)}
						{plan === "business" && (
							<a
								href="mailto:sales@tracelane.dev?subject=Tracelane%20Enterprise"
								className="rounded border border-line bg-surface px-3 py-1.5 text-xs font-medium text-ink-2 transition-colors hover:border-line-2 hover:text-ink"
							>
								Upgrade to Enterprise
							</a>
						)}
					</div>
				</div>
				{plan !== "free" && plan !== "enterprise" && (
					<p className="mt-2 text-2xs text-ink-3">
						Upgrade prorates immediately. Downgrade takes effect at your next
						renewal — your hot window shrinks accordingly, with a 14-day grace
						before auto-age.
					</p>
				)}
			</div>
		</div>
	);
}

/**
 * PlanCard — the audit-ledger + invoices block at the bottom of the page.
 * `hasBillingAccount` is `tenants.polar_customer_id IS NOT NULL`: without a
 * Polar customer there is no portal to open, so the button is not offered and
 * the card says why (a Free workspace that never checked out used to get a
 * button that could only answer 409 — founder, 2026-09-14).
 */
export function PlanCard({
	plan,
	hasBillingAccount,
}: {
	plan: Plan;
	hasBillingAccount: boolean;
}) {
	const card = buildCard(plan);

	return (
		<div className="space-y-4">
			<div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
				<div className="surface-card rounded-[var(--radius-card)] border border-line p-5">
					<p className="t-card-title">Audit ledger</p>
					<p className="mt-1 mb-2 text-xs text-ink-2">
						{card.rows.find((r) => r.label === "Ledger retention")?.value}{" "}
						retention · <Badge tone="seal">self-verify included</Badge>
					</p>
					<p className="text-xs text-ink-2">
						The hash chain, Rekor anchoring and self-verification are on every
						tier. The 7-year evidence-pack export is not yet on the price list —
						nothing here is for sale until it is.
					</p>
				</div>
				<div className="surface-card rounded-[var(--radius-card)] border border-line p-5">
					<p className="t-card-title">Invoices</p>
					{hasBillingAccount ? (
						<>
							<p className="mt-1 mb-3 text-xs text-ink-2">
								Payment method, invoices and plan cancellation live in the
								Polar-hosted billing portal.
							</p>
							<BillingPortalButton />
						</>
					) : (
						<p
							className="mt-1 text-xs text-ink-2"
							data-testid="no-billing-account"
						>
							{plan === "free"
								? "No invoices yet — a billing account is created with your first paid plan (choose one above). Payment method and invoices then live in the Polar-hosted billing portal."
								: plan === "enterprise"
									? "Enterprise is invoiced directly. Email sales@tracelane.dev for an invoice or to change how you pay."
									: // A paid plan with no Polar customer: the plan was applied
										// without a checkout (a seeded or hand-set workspace), so
										// there is no portal to open. Saying "first paid plan" here
										// would contradict the Team/Business header above it.
										"This plan was applied without a checkout, so there is no billing portal for this workspace yet. Email support@tracelane.dev for invoices."}
						</p>
					)}
				</div>
			</div>
		</div>
	);
}

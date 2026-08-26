/**
 * PlanLadder — the in-app plan comparison (SET-15).
 *
 * A server component with no hooks and no client JS: every action is either a
 * link or a native `<form method="post">` to `/api/checkout?tier=…`, which 302s
 * to the Polar-hosted checkout. That is the same mechanism the billing page
 * uses, and the CSP already allows the cross-origin hop
 * (`next.config.ts` `form-action … https://polar.sh`) — a fetch-based button
 * would need new CSP surface for no gain.
 *
 * Limits rendered here come from `plan-catalog.ts`, which derives them from the
 * entitlement map rather than restating them, so the page cannot claim a quota
 * the gateway does not enforce.
 */

import { Badge, Card } from "@tracelanedev/ui";
import { AUDIT_ADDON, type PlanCard } from "./plan-catalog";

function Check() {
	return (
		<svg
			viewBox="0 0 16 16"
			fill="none"
			stroke="currentColor"
			strokeWidth={2}
			className="mt-0.5 h-3.5 w-3.5 shrink-0 text-ink-3"
			aria-hidden="true"
		>
			<polyline points="3 8 6 11 13 4" />
		</svg>
	);
}

function PlanColumn({
	card,
	isCurrent,
}: {
	card: PlanCard;
	isCurrent: boolean;
}) {
	return (
		<Card
			className={
				isCurrent
					? "flex flex-col gap-4 rounded-lg border-action-line p-5"
					: "flex flex-col gap-4 rounded-lg p-5"
			}
			data-plan={card.plan}
			data-current={isCurrent ? "true" : "false"}
		>
			<div className="space-y-1">
				<div className="flex flex-wrap items-center gap-2">
					<h3 className="text-sm font-semibold text-ink">{card.name}</h3>
					{isCurrent && <Badge tone="action">Current plan</Badge>}
				</div>
				<p className="text-base font-semibold text-ink">{card.price}</p>
				{card.plan !== "free" && (
					<p className="text-2xs text-ink-3">list price</p>
				)}
				<p className="text-xs text-ink-2">{card.tagline}</p>
			</div>

			<dl className="space-y-1.5 border-t border-line pt-3 text-xs">
				<div className="flex justify-between gap-3">
					<dt className="text-ink-3">Traces</dt>
					<dd className="text-right font-medium text-ink">{card.traces}</dd>
				</div>
				<div className="flex justify-between gap-3">
					<dt className="text-ink-3">Seats</dt>
					<dd className="text-right font-medium text-ink">{card.seats}</dd>
				</div>
				<div className="flex justify-between gap-3">
					<dt className="text-ink-3">Retention</dt>
					<dd className="text-right font-medium text-ink">{card.retention}</dd>
				</div>
				<div className="flex justify-between gap-3">
					<dt className="shrink-0 text-ink-3">Overage</dt>
					<dd className="text-right text-ink-2">{card.overage}</dd>
				</div>
			</dl>

			<ul className="space-y-1.5 border-t border-line pt-3">
				{card.features.map((f) => (
					<li key={f} className="flex items-start gap-2 text-xs text-ink-2">
						<Check />
						<span>{f}</span>
					</li>
				))}
			</ul>

			<div className="mt-auto pt-2">
				{isCurrent ? (
					<span className="inline-block text-xs text-ink-3">
						You are on this plan
					</span>
				) : card.selfServe ? (
					// Native form POST → /api/checkout 302s to the Polar-hosted
					// checkout, which the browser follows. No client JS.
					<form action={`/api/checkout?tier=${card.plan}`} method="post">
						<button
							type="submit"
							className="w-full rounded bg-action px-3 py-1.5 text-xs font-medium text-action-on transition-colors hover:bg-action/90"
						>
							Choose {card.name}
						</button>
					</form>
				) : card.plan === "enterprise" ? (
					<a
						href="mailto:sales@tracelane.dev?subject=Tracelane%20Enterprise"
						className="inline-block w-full rounded border border-line px-3 py-1.5 text-center text-xs font-medium text-ink-2 transition-colors hover:border-line-2 hover:text-ink"
					>
						Contact us
					</a>
				) : (
					<span className="inline-block text-xs text-ink-3">
						Included by default
					</span>
				)}
			</div>
		</Card>
	);
}

export interface PlanLadderProps {
	cards: PlanCard[];
	/** `null` when the viewer has no resolvable plan (never in practice). */
	currentPlan: string | null;
	/** Set when the workspace carries entitlement overrides on its current plan. */
	customLimitsNote?: boolean;
}

export function PlanLadder({
	cards,
	currentPlan,
	customLimitsNote,
}: PlanLadderProps) {
	return (
		<div className="space-y-6">
			{customLimitsNote && (
				<p className="rounded-lg border border-line bg-surface-2 px-4 py-3 text-xs text-ink-2">
					Your workspace has custom limits on its current plan. The figures on
					your current plan below are <strong>yours</strong>, not the stock plan
					defaults.
				</p>
			)}

			{/* Wide content scrolls inside its own container — the page never
			    scrolls horizontally. */}
			<div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-5">
				{cards.map((c) => (
					<PlanColumn
						key={c.plan}
						card={c}
						isCurrent={c.plan === currentPlan}
					/>
				))}
			</div>

			<Card provenance className="space-y-2 rounded-lg p-5">
				<div className="flex flex-wrap items-center gap-2">
					<h3 className="text-sm font-semibold text-ink">{AUDIT_ADDON.name}</h3>
					<Badge tone="seal">{AUDIT_ADDON.price}</Badge>
					<span className="text-2xs text-ink-3">
						add-on at every tier — never bundled into a plan
					</span>
				</div>
				<p className="text-xs text-ink-2">{AUDIT_ADDON.summary}</p>
				<p className="text-xs text-ink-2">{AUDIT_ADDON.scope}</p>
				<p className="text-xs text-ink-2">{AUDIT_ADDON.verify}</p>
				<a
					href="mailto:sales@tracelane.dev?subject=Tracelane%20Audit%20add-on"
					className="inline-block rounded border border-line px-3 py-1.5 text-xs font-medium text-ink-2 transition-colors hover:border-line-2 hover:text-ink"
				>
					Talk to us about the audit add-on
				</a>
			</Card>

			<div className="space-y-2 text-xs text-ink-3">
				<p>
					<strong className="text-ink-2">One meter.</strong> Quotas are counted
					once per gateway request against a single monthly trace counter —
					there is no second gateway-call budget to track.
				</p>
				<p>
					<strong className="text-ink-2">
						Agent-safety rails are free on every plan
					</strong>
					, hosted free tier and Apache-2.0 self-host alike: MCP rug-pull
					detection, lethal-trifecta detection, prompt-injection patterns,
					tool-schema validation and a cost ceiling. They run inline at the
					gateway and are observe-first by default — a false-positive halt is
					worse than the failure it flags.
				</p>
				<p>
					<strong className="text-ink-2">Verify your own chain, free.</strong>{" "}
					Self-verify of your recent audit chain is on by default at every tier,
					including free. The $999/mo add-on is the paid evidence-pack export.
				</p>
				<p>
					Retention is not customer-configurable — it follows your plan, up to a
					365-day maximum. Prices are list prices; the charge that reaches your
					card is the one Polar bills. Tracelane does not offer a contractual
					uptime SLA or service credits.
				</p>
			</div>
		</div>
	);
}

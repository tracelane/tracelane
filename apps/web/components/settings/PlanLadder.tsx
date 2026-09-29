"use client";
import { Button } from "@tracelanedev/ui";

/**
 * PlanLadder — the in-app plan comparison (SET-15 / ADR-076 §8 `#plans`).
 *
 * Every action is a native `<form method="post">` to
 * `/api/checkout?tier=…&interval=…`, which either 302s to a Polar-hosted
 * checkout (free → paid) or 302s to the customer portal (an existing
 * subscriber changing plans, B-140) — the CTA never has to know which. The
 * CSP already allows the cross-origin hop to Polar
 * (`next.config.ts` `form-action … https://polar.sh`).
 *
 * The ONE client-side bit is the Monthly/Annual toggle — a `SegmentedControl`
 * swapping which price string renders per card. Two REAL prices, never a
 * "save X%" framing (`.claude/rules/billing.md`).
 */

import { Badge, SegmentedControl } from "@tracelanedev/ui";
import { useState } from "react";
import {
	LADDER,
	LADDER_FOOTNOTES,
	NEVER_METERED_TITLE,
	type PlanCard,
	neverMeteredCopy,
} from "./plan-catalog";

type Interval = "month" | "year";

function PlanColumn({
	card,
	isCurrent,
	interval,
	currentIndex,
	cardIndex,
}: {
	card: PlanCard;
	isCurrent: boolean;
	interval: Interval;
	currentIndex: number;
	cardIndex: number;
}) {
	const price =
		interval === "year" && card.priceYear ? card.priceYear : card.priceMonth;
	const ctaLabel =
		cardIndex > currentIndex
			? `Upgrade to ${card.name}`
			: `Downgrade to ${card.name}`;

	return (
		<div
			className={`surface-card rounded-card p-5 flex flex-col gap-3${
				isCurrent ? " border-action-line border-2" : ""
			}`}
			data-plan={card.plan}
			data-current={isCurrent ? "true" : "false"}
		>
			<div>
				<div className="flex flex-wrap items-center gap-2">
					<p className="text-sm font-semibold text-ink">{card.name}</p>
					{isCurrent && <Badge tone="action">Current plan</Badge>}
				</div>
				<p className="flex items-baseline gap-1 flex-wrap mt-1">
					{price.fromLabel && (
						<span className="text-xs text-ink-3 basis-full">from</span>
					)}
					<span className="text-2xl font-semibold tracking-tight text-ink tabular-nums">
						{price.amount}
					</span>
					{price.suffix && (
						<span className="text-xs text-ink-3">{price.suffix}</span>
					)}
				</p>
				<p className="text-2xs text-ink-3 mt-0.5">{card.note}</p>
			</div>

			<dl className="border-t border-line pt-2">
				{card.rows.map((r) => (
					<div
						key={r.label}
						className="flex justify-between gap-2 py-1.5 border-b border-line text-xs last:border-b-0"
					>
						<dt className="text-ink-3">{r.label}</dt>
						<dd className="text-right font-medium text-ink tabular-nums">
							{r.value}
						</dd>
					</div>
				))}
			</dl>

			<div className="mt-auto pt-1">
				{isCurrent ? (
					<span className="inline-block text-xs text-ink-3">
						You are on this plan
					</span>
				) : card.selfServe ? (
					<form
						action={`/api/checkout?tier=${card.plan}&interval=${interval}`}
						method="post"
					>
						<Button
							variant="bare"
							type="submit"
							className="w-full rounded bg-action px-3 py-1.5 text-xs font-medium text-action-on transition-colors hover:bg-action/90"
						>
							{ctaLabel}
						</Button>
					</form>
				) : card.plan === "enterprise" ? (
					<a
						href="mailto:sales@tracelane.dev?subject=Tracelane%20Enterprise"
						className="inline-block w-full rounded border border-line px-3 py-1.5 text-center text-xs font-medium text-ink-2 transition-colors hover:border-line-2 hover:text-ink"
					>
						Contact sales
					</a>
				) : (
					<span className="inline-block text-xs text-ink-3">
						No billing account — nothing to change here.
					</span>
				)}
			</div>
		</div>
	);
}

export interface PlanLadderProps {
	cards: PlanCard[];
	/** `null` when the viewer has no resolvable plan (never in practice). */
	currentPlan: string | null;
}

export function PlanLadder({ cards, currentPlan }: PlanLadderProps) {
	const [interval, setInterval] = useState<Interval>("month");
	const currentIndex = LADDER.findIndex((p) => p === currentPlan);
	// `card.priceYear` is `null` for every card while `plans.v3.json`'s
	// `annual_available` is false (`plan-catalog.ts`) — the same switch that
	// gates the checkout route's `interval=year`. A toggle that changes
	// nothing (no card has a second price to show) is worse than none: it
	// invites a click that produces no visible change.
	const annualOffered = cards.some((c) => c.priceYear !== null);

	return (
		<div className="space-y-6">
			{annualOffered && (
				<div className="flex justify-start">
					<SegmentedControl
						label="Billing interval"
						value={interval}
						onChange={setInterval}
						options={[
							{ value: "month", label: "Monthly" },
							{ value: "year", label: "Annual" },
						]}
					/>
				</div>
			)}

			{/* Wide content scrolls inside its own container — the page never
			    scrolls horizontally. */}
			<div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-5">
				{cards.map((c, i) => (
					<PlanColumn
						key={c.plan}
						card={c}
						isCurrent={c.plan === currentPlan}
						interval={interval}
						currentIndex={currentIndex}
						cardIndex={i}
					/>
				))}
			</div>

			<div className="surface-card surface-card--quiet rounded-card p-5">
				<p className="t-card-title mb-2">{NEVER_METERED_TITLE}</p>
				<p className="text-xs text-ink-2 leading-relaxed">
					{neverMeteredCopy()}
				</p>
			</div>

			<ul className="flex flex-wrap gap-x-5 gap-y-1 text-2xs text-ink-3">
				{LADDER_FOOTNOTES.map((f) => (
					<li key={f}>{f}</li>
				))}
			</ul>
		</div>
	);
}

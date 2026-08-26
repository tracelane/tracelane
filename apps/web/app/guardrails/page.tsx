/**
 * Guardrails — the pre-flight guardrail engine's verdicts for the authenticated
 * tenant, live from `GET /v1/guardrails/stats` over `guardrail_verdicts`.
 *
 * This is the one surface for Tracelane's core differentiator: predictive,
 * pre-flight prevention. Every number is captured on every request — decision
 * mix (allow/block/redact/warn), the fail-open rate (a rail that errored and
 * proceeded — the trust headline), inline overhead percentiles, and per-rail
 * health. Nothing here is derived or fabricated (§ honesty lock). tenant_id comes
 * from the WorkOS session; the gateway owns the tenant-scoped read.
 *
 * ── READING ORDER (P1, 2026-08-22) ──────────────────────────────────────────
 * The page is now four labelled sections at `space-y-8` instead of one
 * `space-y-3` stack, because every gap on the old surface was ~11px: the
 * distance between two metric tiles equalled the distance between the metric
 * strip and the rail table, so the grouping the headings announced was
 * contradicted by the layout under them (the same P0.15 correction the
 * dashboard took).
 *
 * The order is deliberate and it is the reader's question order:
 *   1. VOLUME    — how many evaluations happened at all.
 *   2. OUTCOME   — what enforcement did (block rate, fail-open honesty), then
 *                  the full four-way decision mix.
 *   3. OVERHEAD  — what it cost inline.
 *   4. SURFACE   — which rails exist, and which tool definitions are pinned.
 * No metric was added, removed, recomputed or relabelled to get there.
 */

import { RangeControl } from "@/components/RangeControl";
import { WarmingBanner } from "@/components/empty-states/WarmingBanner";
import { fetchGuardrailStats } from "@/lib/guardrails";
import { rangeLabel, rangeToHours } from "@/lib/range";
import {
	Badge,
	type BadgeProps,
	Card,
	EmptyState,
	Skeleton,
	StatCard,
	StatGrid,
} from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";
import { type ReactNode, Suspense } from "react";
import { RailRoster } from "./RailRoster";
import { ToolPins } from "./ToolPins";
import { WorkedExample } from "./WorkedExample";

/** Honest explanation of the request/response split (some rails run on both). */
const SIDE_HINT =
	"Request-side = rails checked on your input before the model call; response-side = rails checked on the model's reply. Some rails run on both. Response-side evaluation is still rolling out, so it may read 0.";

export const metadata: Metadata = { title: "Guardrails — Tracelane" };
export const dynamic = "force-dynamic";

const pct = (v: number): string => `${v.toFixed(1)}%`;
const ms = (v: number): string => `${v.toLocaleString()} ms`;

/** Verdict-list href for a decision, preserving the active range. */
function verdictHref(decision: string, range?: string): string {
	const q = new URLSearchParams();
	if (decision) q.set("decision", decision);
	if (range) q.set("range", range);
	const s = q.toString();
	return s ? `/guardrails/verdicts?${s}` : "/guardrails/verdicts";
}

/**
 * Section label in the app's ONE section grammar — `.t-eyebrow` plus a hairline
 * that runs to the section's right-hand affordance. It is the same object the
 * dashboard's `SectionLabel` draws; this is a local copy because that one is
 * private to `dashboard/page.tsx`, and promoting it to `packages/ui` is a shared
 * -primitive change that belongs in one commit of its own, not in three
 * concurrent page rewrites. Flagged rather than done.
 *
 * These were `text-sm font-semibold text-ink` h2s — 13px sentence case, i.e. the
 * same size and weight as a CARD title, so a section heading and the title of a
 * card inside it were indistinguishable.
 *
 * THE RULE IS NO LONGER HIDDEN BELOW `sm` (verifier, 2026-08-22). It was
 * `hidden h-px flex-1 bg-line sm:block`, which made THIS the only surface in the
 * app whose section divider vanished on a phone — measured at 390px: /dashboard
 * painted rules of 297/218/165/149/232px, /gateway 223/236/35/246px and /slo
 * 139px, while /guardrails painted **zero** for Decision mix, Guardrail rails
 * and Tool pinning. `min-w-8` is what makes hiding unnecessary: when a long
 * label and a control squeeze the row, the rule keeps a visible 32px stub
 * instead of collapsing to 0 and reading as a rendering fault — the same
 * mechanism `app/gateway/SectionLabel.tsx` already uses.
 */
function SectionLabel({
	children,
	action,
}: { children: ReactNode; action?: ReactNode }) {
	return (
		<div className="flex flex-wrap items-center gap-3">
			<h2 className="t-eyebrow">{children}</h2>
			<span className="h-px min-w-8 flex-1 bg-line" />
			{action}
		</div>
	);
}

async function GuardrailData({ range }: { range?: string }) {
	const label = rangeLabel(range);
	const stats = await fetchGuardrailStats({ hours: rangeToHours(range) });

	// Gateway unreachable ≠ zero evaluations — degrade to the warming state.
	if (stats === null) {
		return (
			<>
				<WarmingBanner />
				<EmptyState
					title="Waiting on the gateway"
					description="Guardrail verdicts appear here once the gateway is reachable and requests have flowed."
				/>
			</>
		);
	}

	const failOpenTone =
		stats.fail_open_rate_pct > 0 ? "danger" : ("ok" as const);
	const zero = stats.total_evaluations === 0;

	/*
	 * The four stored outcome counts, in the order they were already rendered.
	 * VALUES, LABELS AND LINKS ARE VERBATIM — this is a layout change, not an
	 * arithmetic one: `stats.allows` / `.blocks` / `.redacts` / `.warns` are the
	 * gateway's own figures and they sum to `total_evaluations`.
	 *
	 * TONE IS SET ON THE EXCEPTIONS. `redact` is NEUTRAL: a redaction is recorded,
	 * not a failure, and the badge grammar this app uses reserves warn/danger for
	 * the outcomes a reader has to act on. A ZERO count is neutral whatever its
	 * category — colouring "0 blocked" red says a thing happened when nothing did.
	 *
	 * `allowed` keeps `ok` because a BADGE is an 11px chip, not a fill: the
	 * dashboard's verdict donut deliberately gives `allowed` no tone at all,
	 * because there the mark is a ~95% arc and a saturated green ring would make
	 * the loudest object on the card the news that nothing happened. The same
	 * reasoning is why the count below the chip stays in plain ink and there is no
	 * proportional bar here — the share is not the datum on this row, the counts are.
	 */
	const decisionMix: ReadonlyArray<{
		decision: string;
		label: string;
		value: number;
		tone: BadgeProps["tone"];
	}> = [
		{
			decision: "allow",
			label: "allowed",
			value: stats.allows,
			tone: stats.allows > 0 ? "ok" : "neutral",
		},
		{
			decision: "block",
			label: "blocked",
			value: stats.blocks,
			tone: stats.blocks > 0 ? "danger" : "neutral",
		},
		{
			decision: "redact",
			label: "redacted",
			value: stats.redacts,
			tone: "neutral",
		},
		{
			decision: "warn",
			label: "warned",
			value: stats.warns,
			tone: stats.warns > 0 ? "warn" : "neutral",
		},
	];

	return (
		<div className="space-y-8">
			{zero && (
				/* A full-width NOTICE STRIP, so it takes the control radius, not the
				   card radius (verifier, 2026-08-22). This was
				   `rounded-[var(--radius-card)]` — 16.4px measured at 1440 on a
				   ~44px-tall bar — and `components/empty-states/WarmingBanner.tsx`,
				   the app's only other notice strip, already states the rule at its
				   own site: "a 18px card radius on a 44px-tall bar reads as a pill".
				   The two strips sit on THIS page together when the gateway is
				   warming, at `px-4 py-3 text-sm` each, and differed only in radius.
				   The tone stays neutral rather than `--warn-soft`: zero traffic on a
				   new workspace is the normal first state, not a warning. */
				<div className="rounded-lg border border-line bg-surface-2 px-4 py-3 text-sm text-ink-2">
					No guardrail verdicts in the last {label} yet — every request through
					the gateway is evaluated pre-flight. Below is the full rail surface
					and what a block looks like; your real verdicts appear here once
					traffic flows.{" "}
					<Link
						href="/traces"
						className="font-medium text-action-ink hover:underline"
					>
						View traces →
					</Link>
				</div>
			)}

			{/* 1 + 3 — VOLUME, then the two enforcement OUTCOME readings, then what
			    it cost inline. Same four metrics, same arithmetic, same order. */}
			<StatGrid title="Evaluation &amp; enforcement" cols={4}>
				<StatCard
					icon="traffic"
					label={`Evaluations (${label})`}
					value={stats.total_evaluations.toLocaleString()}
					sub={`${stats.request_side.toLocaleString()} request · ${stats.response_side.toLocaleString()} response · response-side rolling out`}
					hint={SIDE_HINT}
				/>
				<StatCard
					icon="failure-signatures"
					label="Block rate"
					value={pct(stats.block_rate_pct)}
					sub={`${stats.blocks.toLocaleString()} blocked pre-flight`}
					variant="action"
				/>
				<StatCard
					icon="error-budget"
					label="Fail-open rate"
					value={pct(stats.fail_open_rate_pct)}
					sub={
						stats.fail_open_verdicts > 0
							? `${stats.fail_open_verdicts.toLocaleString()} verdict${stats.fail_open_verdicts === 1 ? "" : "s"} proceeded after a rail errored`
							: "no rail failed open"
					}
					tone={failOpenTone}
				/>
				<StatCard
					icon="latency"
					label="Inline overhead (p95)"
					value={ms(stats.p95_ms)}
					sub={`p50 ${ms(stats.p50_ms)} · p99 ${ms(stats.p99_ms)}`}
				/>
			</StatGrid>

			{/* 2 — DECISION MIX. Four parts of one whole, and they used to render as
			    four loose chips floating on the page ground with no object saying they
			    belonged together. One quiet card now holds them; each cell is still
			    the same range-preserving click-through to the filtered verdict list.
			    `gap-px` over `bg-line` draws the dividers, because `divide-x` on a
			    grid puts a stray left border on the first cell of the second row when
			    it wraps to two columns on a phone. */}
			<section className="space-y-3">
				<SectionLabel
					action={
						<Link
							href={verdictHref("", range)}
							className="text-sm font-medium text-action-ink hover:underline"
						>
							All verdicts →
						</Link>
					}
				>
					Decision mix
				</SectionLabel>
				<Card quiet className="overflow-hidden p-0">
					<div className="grid grid-cols-2 gap-px bg-line sm:grid-cols-4">
						{decisionMix.map((d) => (
							<Link
								key={d.decision}
								href={verdictHref(d.decision, range)}
								className="flex flex-col items-start gap-2 bg-surface px-5 py-4 transition-colors hover:bg-surface-hover"
							>
								<Badge tone={d.tone}>{d.label}</Badge>
								<span className="t-metric-sm font-mono text-ink">
									{d.value.toLocaleString()}
								</span>
							</Link>
						))}
					</div>
				</Card>
			</section>

			{/* 4 — THE SURFACE. The full rail roster: plain names, the exact action
			    each takes, live counts where a rail fired, gated rails as honest
			    "Advanced" rows. */}
			<section className="space-y-3">
				<SectionLabel
					action={
						<p
							className="text-xs text-ink-3"
							title='All nine inline rails. Free rails run for every workspace; "Advanced" rails are enabled per workspace on Team+.'
						>
							Expand a row for what each rail does · "Advanced" = per-workspace
						</p>
					}
				>
					Guardrail rails
				</SectionLabel>
				<RailRoster live={stats.rails} range={range} />
			</section>

			<section className="space-y-3">
				<SectionLabel>Tool pinning</SectionLabel>
				<p className="max-w-3xl text-sm text-ink-2">
					Approve the tool definitions your agents actually send. Once a
					definition is approved, the guardrail engine flags any later change to
					that tool&apos;s name, schema or description as definition drift — the
					MCP rug-pull case. Tracelane records the definition hash, never the
					tool text.
				</p>
				<ToolPins />
			</section>

			{/* The "show me" moment — a real worked example of a pre-flight block. */}
			<WorkedExample />
		</div>
	);
}

export default async function GuardrailsPage({
	searchParams,
}: {
	searchParams: Promise<{ range?: string }>;
}) {
	const { range } = await searchParams;
	return (
		/* The dashboard's padding ramp, to the utility (verifier, 2026-08-22). This
		   was `px-2 py-3 sm:px-4 sm:py-4` — a DIFFERENT gutter from the four other
		   pages that claim the same grammar, and the difference is measurable: at
		   1440 the h1 started at x=269 here against x=266 on /dashboard, /gateway,
		   /slo and /signatures, so the content column stepped inward when you moved
		   between two pages of the same app. `space-y-8` also replaces the header's
		   own margin — see below. */
		<div className="space-y-8 px-1 py-2 sm:px-2 sm:py-4 lg:px-3">
			{/* Page header in the dashboard's grammar: `.t-h1`, one line of
			    explanation under it, the range CONTROL alone on the right and
			    baseline-aligned with the copy rather than top-aligned against the
			    32px title. Copy is unchanged.
			    NO `mb-*` any more: the gap under the header is the frame's
			    `space-y-8` — the same 29.1px the dashboard leaves. It was `mb-6`
			    (21.9px) while /guardrails/verdicts was `mb-5` (18.2px) and the other
			    four pages were 29.1px: three values for one structural gap, which is
			    what stopped these pages reading as one header system. */}
			<header className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
				<div>
					<h1 className="t-h1">Guardrails</h1>
					<p className="mt-2 max-w-2xl text-sm text-ink-2">
						Pre-flight verdicts across your traffic — blocked, redacted or
						allowed, plus inline overhead. Last {rangeLabel(range)}.
					</p>
				</div>
				<RangeControl />
			</header>
			<Suspense
				fallback={
					<div className="space-y-8">
						<StatGrid cols={4}>
							{[0, 1, 2, 3].map((i) => (
								<Skeleton key={i} className="h-24" />
							))}
						</StatGrid>
						<Skeleton className="h-48" />
					</div>
				}
			>
				<GuardrailData range={range} />
			</Suspense>
		</div>
	);
}

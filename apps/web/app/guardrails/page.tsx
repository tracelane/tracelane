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
 */

import { RangeControl } from "@/components/RangeControl";
import { WarmingBanner } from "@/components/empty-states/WarmingBanner";
import { fetchGuardrailStats } from "@/lib/guardrails";
import { rangeLabel, rangeToHours } from "@/lib/range";
import { Badge, EmptyState, Skeleton, StatCard } from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";
import { Suspense } from "react";
import { RailRoster } from "./RailRoster";
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

	return (
		<div className="space-y-6">
			{zero && (
				<div className="rounded-lg border border-line bg-surface-2/40 px-4 py-3 text-sm text-ink-2">
					No guardrail verdicts in the last {label} yet — every request through
					the gateway is evaluated pre-flight. Below is the full rail surface
					and what a block looks like; your real verdicts appear here once
					traffic flows.{" "}
					<Link
						href="/traces"
						className="font-medium text-accent-ink hover:underline"
					>
						View traces →
					</Link>
				</div>
			)}
			{/* Headline — block rate + the fail-open honesty signal + overhead. */}
			<div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
				<StatCard
					label={`Evaluations (${label})`}
					value={stats.total_evaluations.toLocaleString()}
					sub={`${stats.request_side.toLocaleString()} request · ${stats.response_side.toLocaleString()} response`}
					hint={SIDE_HINT}
				/>
				<StatCard
					label="Block rate"
					value={pct(stats.block_rate_pct)}
					sub={`${stats.blocks.toLocaleString()} blocked pre-flight`}
					tone={stats.blocks > 0 ? "warn" : "ok"}
				/>
				<StatCard
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
					label="Inline overhead (p95)"
					value={ms(stats.p95_ms)}
					sub={`p50 ${ms(stats.p50_ms)} · p99 ${ms(stats.p99_ms)}`}
				/>
			</div>

			{/* Decision mix — the full breakdown, captured per verdict. Each badge is
			    a click-through to the verdict-detail list, filtered + range-preserved. */}
			<div className="flex flex-wrap items-center gap-2">
				<Link href={verdictHref("allow", range)}>
					<Badge tone="ok">{stats.allows.toLocaleString()} allowed</Badge>
				</Link>
				<Link href={verdictHref("block", range)}>
					<Badge tone={stats.blocks > 0 ? "danger" : "neutral"}>
						{stats.blocks.toLocaleString()} blocked
					</Badge>
				</Link>
				<Link href={verdictHref("redact", range)}>
					<Badge tone={stats.redacts > 0 ? "info" : "neutral"}>
						{stats.redacts.toLocaleString()} redacted
					</Badge>
				</Link>
				<Link href={verdictHref("warn", range)}>
					<Badge tone={stats.warns > 0 ? "warn" : "neutral"}>
						{stats.warns.toLocaleString()} warned
					</Badge>
				</Link>
				<Link
					href={verdictHref("", range)}
					className="text-[13px] font-medium text-accent-ink hover:underline"
				>
					All verdicts →
				</Link>
			</div>

			{/* The full rail surface — plain names, the exact action each takes, live
			    counts where a rail fired, and gated rails as honest "Advanced" rows. */}
			<div>
				<div className="mb-2 flex flex-wrap items-baseline justify-between gap-2">
					<h2 className="text-sm font-semibold text-ink">Guardrail rails</h2>
					<p className="text-xs text-ink-3">
						All nine inline rails — expand a row for what it does. Free rails
						run for everyone; "Advanced" rails are enabled per workspace.
					</p>
				</div>
				<RailRoster live={stats.rails} range={range} />
			</div>

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
		<main className="mx-auto max-w-7xl p-6">
			<div className="mb-6 flex flex-wrap items-start justify-between gap-3">
				<div>
					<h1 className="text-2xl font-semibold text-ink">Guardrails</h1>
					<p className="mt-1 max-w-3xl text-sm text-ink-2">
						Pre-flight guardrail verdicts across your traffic — what was
						blocked, redacted, or allowed, how often a rail failed open, and
						inline overhead, over the last {rangeLabel(range)}.
					</p>
				</div>
				<RangeControl />
			</div>
			<Suspense
				key={range ?? "24h"}
				fallback={
					<div className="space-y-4">
						<div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
							{[0, 1, 2, 3].map((i) => (
								<Skeleton key={i} className="h-24" />
							))}
						</div>
						<Skeleton className="h-48" />
					</div>
				}
			>
				<GuardrailData range={range} />
			</Suspense>
		</main>
	);
}

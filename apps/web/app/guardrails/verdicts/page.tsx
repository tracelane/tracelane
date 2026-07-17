/**
 * Guardrail verdict-detail list — the click-through behind the decision-mix
 * counts on /guardrails ("N blocked" → here, filtered to `decision=block`).
 *
 * Why a verdict list and not a filtered trace list: an inline BLOCK 403s the
 * request BEFORE any span is emitted (server.rs), so a blocked verdict has no
 * trace to link to. The honest detail IS the verdict — which rails fired, their
 * reason codes, the side, and when. Every field is captured per verdict in
 * `guardrail_verdicts`; nothing here is derived. tenant_id comes from the
 * session; the gateway owns the tenant-scoped read.
 */

import { RangeControl } from "@/components/RangeControl";
import { WarmingBanner } from "@/components/empty-states/WarmingBanner";
import {
	type GuardrailVerdict,
	fetchGuardrailVerdicts,
} from "@/lib/guardrails";
import { rangeLabel, rangeToHours } from "@/lib/range";
import { Badge, Card, EmptyState, Skeleton } from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";
import { Suspense } from "react";

export const metadata: Metadata = { title: "Guardrail verdicts — Tracelane" };
export const dynamic = "force-dynamic";

type SP = Record<string, string | undefined>;

const DECISIONS = [
	{ v: "", l: "All" },
	{ v: "block", l: "Blocked" },
	{ v: "redact", l: "Redacted" },
	{ v: "warn", l: "Warned" },
	{ v: "allow", l: "Allowed" },
] as const;

/** One per-rail verdict inside the `rails` JSON column. */
type RailEntry = {
	rail?: string;
	outcome?: string;
	reason_code?: string | null;
};

const DECISION_TONE: Record<string, "danger" | "info" | "warn" | "ok"> = {
	block: "danger",
	redact: "info",
	warn: "warn",
	allow: "ok",
};

function parseDate(s: string): Date {
	return new Date(s.includes("T") ? s : `${s.replace(" ", "T")}Z`);
}

function fmtLatency(us: number): string {
	if (us <= 0) return "—";
	if (us < 1000) return `${us}µs`;
	return `${(us / 1000).toFixed(1)}ms`;
}

/** Parse the rails JSON → only the rails that actually fired (non-allow). */
function firedRails(railsJson: string): RailEntry[] {
	try {
		const arr = JSON.parse(railsJson) as RailEntry[];
		if (!Array.isArray(arr)) return [];
		return arr.filter((r) => r.outcome && r.outcome !== "allow");
	} catch {
		return [];
	}
}

/** Decision filter — server-driven links (preserve the active range). */
function decisionHref(sp: SP, v: string): string {
	const q = new URLSearchParams();
	if (v) q.set("decision", v);
	if (sp.range) q.set("range", sp.range);
	const s = q.toString();
	return s ? `/guardrails/verdicts?${s}` : "/guardrails/verdicts";
}

function VerdictRow({ v }: { v: GuardrailVerdict }) {
	const fired = firedRails(v.rails);
	const failedOpen = v.fail_open_rails.length > 0;
	return (
		<tr className="border-b border-line align-top transition-colors last:border-0 hover:bg-surface-2/30">
			<td className="px-4 py-3 text-xs text-ink-2">
				{parseDate(v.event_time).toLocaleString()}
			</td>
			<td className="px-4 py-3 text-[11px] uppercase tracking-wide text-ink-3">
				{v.side}
			</td>
			<td className="px-4 py-3">
				<Badge tone={DECISION_TONE[v.decision] ?? "neutral"}>
					{v.decision}
				</Badge>
			</td>
			<td className="px-4 py-3">
				{fired.length > 0 ? (
					<div className="flex flex-wrap gap-1.5">
						{fired.map((r, i) => (
							<span
								key={`${r.rail}-${i}`}
								className="inline-flex items-center gap-1 rounded-md border border-line bg-surface-2/50 px-1.5 py-0.5 font-mono text-[11px] text-ink-2"
								title={r.reason_code ?? undefined}
							>
								<span className="text-ink">{r.rail}</span>
								{r.reason_code && (
									<span className="text-ink-3">· {r.reason_code}</span>
								)}
							</span>
						))}
					</div>
				) : (
					<span className="text-xs text-ink-3">—</span>
				)}
				{failedOpen && (
					<p className="mt-1 text-[11px] text-warn">
						failed open: {v.fail_open_rails.join(", ")}
					</p>
				)}
			</td>
			<td className="px-4 py-3 text-right font-mono text-xs tabular-nums text-ink-2">
				{fmtLatency(v.total_latency_micros)}
			</td>
			<td className="px-4 py-3 font-mono text-[11px] text-ink-3">
				{v.correlation_id.slice(0, 12)}…
			</td>
		</tr>
	);
}

async function VerdictsData({ sp }: { sp: SP }) {
	const verdicts = await fetchGuardrailVerdicts({
		hours: rangeToHours(sp.range),
		decision: sp.decision,
		limit: 100,
	});

	if (verdicts === null) {
		return (
			<>
				<WarmingBanner />
				<EmptyState
					title="Waiting on the gateway"
					description="Verdicts appear here once the gateway is reachable and requests have flowed."
				/>
			</>
		);
	}

	if (verdicts.length === 0) {
		const filtered = Boolean(sp.decision);
		return (
			<EmptyState
				title={
					filtered
						? `No ${sp.decision} verdicts in the last ${rangeLabel(sp.range)}`
						: `No verdicts in the last ${rangeLabel(sp.range)}`
				}
				description="Every request through the gateway is evaluated pre-flight; verdicts land here as traffic flows. Try widening the range or clearing the decision filter."
				action={
					filtered ? (
						<Link
							href={decisionHref({ ...sp, decision: undefined }, "")}
							className="text-[13px] font-medium text-ink-2 underline underline-offset-2 hover:text-ink"
						>
							Clear filter
						</Link>
					) : undefined
				}
			/>
		);
	}

	return (
		<Card className="overflow-hidden p-0">
			<div className="overflow-x-auto">
				<table className="w-full text-sm">
					<thead className="bg-surface-2/50">
						<tr>
							<th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								Time
							</th>
							<th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								Side
							</th>
							<th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								Decision
							</th>
							<th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								Rails fired
							</th>
							<th className="px-4 py-3 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								Overhead
							</th>
							<th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								Correlation
							</th>
						</tr>
					</thead>
					<tbody>
						{verdicts.map((v, i) => (
							<VerdictRow key={`${v.correlation_id}-${v.side}-${i}`} v={v} />
						))}
					</tbody>
				</table>
			</div>
		</Card>
	);
}

export default async function GuardrailVerdictsPage({
	searchParams,
}: {
	searchParams: Promise<SP>;
}) {
	const sp = await searchParams;
	const active = sp.decision ?? "";
	return (
		<main className="mx-auto max-w-7xl p-6">
			<div className="mb-4 flex items-center gap-3">
				<Link
					href="/guardrails"
					className="shrink-0 text-sm text-ink-2 transition-colors hover:text-ink"
				>
					← Guardrails
				</Link>
				<h1 className="text-2xl font-semibold text-ink">Guardrail verdicts</h1>
			</div>
			<p className="mb-5 max-w-3xl text-sm text-ink-2">
				The verdict behind each decision. A blocked request is stopped
				pre-flight (before a trace is recorded), so this is where a block is
				visible — which rails fired, their reason codes, and when.
			</p>

			<div className="mb-5 flex flex-wrap items-center justify-between gap-3">
				<div className="inline-flex rounded-lg border border-line bg-surface p-0.5">
					{DECISIONS.map((d) => (
						<Link
							key={d.v || "all"}
							href={decisionHref(sp, d.v)}
							className={
								active === d.v
									? "rounded-md bg-accent-soft px-2.5 py-1 text-[12.5px] text-ink"
									: "rounded-md px-2.5 py-1 text-[12.5px] text-ink-2 hover:text-ink"
							}
						>
							{d.l}
						</Link>
					))}
				</div>
				<RangeControl />
			</div>

			<Suspense
				key={`${sp.decision ?? ""}|${sp.range ?? ""}`}
				fallback={
					<div className="space-y-2">
						{[0, 1, 2, 3, 4].map((i) => (
							<Skeleton key={i} className="h-12 w-full" />
						))}
					</div>
				}
			>
				<VerdictsData sp={sp} />
			</Suspense>
		</main>
	);
}

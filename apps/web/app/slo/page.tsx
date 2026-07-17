/**
 * SLO dashboard page — per-hour latency percentiles, error rate, and
 * token usage by provider and model.
 *
 * Reads SLO rollups via the gateway proxy (GET /v1/slo) — the gateway owns
 * the ClickHouse query and resolves the tenant from the forwarded token.
 * RSC: fetched at request time with Suspense streaming.
 */

import type { SloRow } from "@/app/slo/types";
import { RangeControl } from "@/components/RangeControl";
import { WarmingBanner } from "@/components/empty-states/WarmingBanner";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import { rangeBucketMs, rangeLabel, rangeToHours } from "@/lib/range";
import {
	Card,
	EmptyState,
	LatencyTimeline,
	Skeleton,
	StatCard,
	type StatTone,
} from "@tracelanedev/ui";
import type { Metadata } from "next";
import { Suspense } from "react";
import { computeSloBudget } from "./budget";
import { buildLatencyPoints } from "./latency";

export const metadata: Metadata = { title: "SLOs — Tracelane" };

function formatDuration(ms: number): string {
	if (ms < 1000) return `${ms.toFixed(0)}ms`;
	return `${(ms / 1000).toFixed(2)}s`;
}

function formatTokens(n: number): string {
	if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
	if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
	return String(n);
}

function formatBurnRate(x: number): string {
	return Number.isFinite(x) ? `${x.toFixed(2)}×` : "∞×";
}

function formatBudgetRemaining(pct: number): string {
	if (!Number.isFinite(pct)) return "over budget";
	if (pct < 0) return `${Math.abs(pct).toFixed(0)}% over`;
	return `${pct.toFixed(0)}%`;
}

function SloTable({ rows }: { rows: SloRow[] }) {
	if (rows.length === 0) {
		return (
			<EmptyState
				title="No SLO data yet"
				description="Spans will appear here once traffic is flowing through the gateway."
			/>
		);
	}

	// Aggregate summary per provider+model across all hours. Percentiles are
	// averaged across the hourly buckets (mean-of-hourly-pXX) — an approximation,
	// but the same one already applied to p95; p50/p99 use the identical method
	// so the three columns are mutually consistent. The gateway emits all three
	// per hour (SloRow.p50_ms/p95_ms/p99_ms); only p95 was being surfaced.
	const summary = new Map<
		string,
		{
			requests: number;
			errors: number;
			p50_ms_sum: number;
			p95_ms_sum: number;
			p99_ms_sum: number;
			count: number;
			input: number;
			output: number;
		}
	>();
	for (const row of rows) {
		const key = `${row.provider}::${row.model}`;
		const cur = summary.get(key) ?? {
			requests: 0,
			errors: 0,
			p50_ms_sum: 0,
			p95_ms_sum: 0,
			p99_ms_sum: 0,
			count: 0,
			input: 0,
			output: 0,
		};
		summary.set(key, {
			requests: cur.requests + row.requests,
			errors: cur.errors + row.errors,
			p50_ms_sum: cur.p50_ms_sum + row.p50_ms,
			p95_ms_sum: cur.p95_ms_sum + row.p95_ms,
			p99_ms_sum: cur.p99_ms_sum + row.p99_ms,
			count: cur.count + 1,
			input: cur.input + row.total_input_tokens,
			output: cur.output + row.total_output_tokens,
		});
	}

	return (
		<div className="overflow-x-auto rounded-xl border border-line">
			<table className="w-full text-sm">
				<thead className="bg-surface-2/50">
					<tr>
						<th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
							Provider / Model
						</th>
						<th className="px-4 py-3 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
							Requests
						</th>
						<th className="px-4 py-3 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
							Error rate
						</th>
						<th className="px-4 py-3 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
							p50
						</th>
						<th className="px-4 py-3 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
							p95
						</th>
						<th className="px-4 py-3 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
							p99
						</th>
						<th className="px-4 py-3 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
							Input tokens
						</th>
						<th className="px-4 py-3 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
							Output tokens
						</th>
					</tr>
				</thead>
				<tbody className="divide-y divide-line">
					{[...summary.entries()]
						.sort((a, b) => b[1].requests - a[1].requests)
						.map(([key, s]) => {
							const [provider, model] = key.split("::");
							const errorPct =
								s.requests > 0 ? (s.errors / s.requests) * 100 : 0;
							const avgP50 = s.count > 0 ? s.p50_ms_sum / s.count : 0;
							const avgP95 = s.count > 0 ? s.p95_ms_sum / s.count : 0;
							const avgP99 = s.count > 0 ? s.p99_ms_sum / s.count : 0;
							return (
								<tr
									key={key}
									className="transition-colors hover:bg-surface-2/30"
								>
									<td className="px-4 py-3">
										<div className="font-medium text-xs text-ink">
											{provider ?? "—"}
										</div>
										<div className="text-xs text-ink-2 font-mono">
											{model ?? "—"}
										</div>
									</td>
									<td className="px-4 py-3 text-right font-mono tabular-nums text-xs text-ink">
										{s.requests.toLocaleString()}
									</td>
									<td className="px-4 py-3 text-right">
										<span
											className={`font-mono tabular-nums text-xs ${errorPct > 5 ? "text-danger font-semibold" : errorPct > 1 ? "text-warn" : "text-ok"}`}
										>
											{errorPct.toFixed(2)}%
										</span>
									</td>
									<td className="px-4 py-3 text-right font-mono tabular-nums text-xs text-ink-2">
										{formatDuration(avgP50)}
									</td>
									<td className="px-4 py-3 text-right font-mono tabular-nums text-xs text-ink-2">
										{formatDuration(avgP95)}
									</td>
									<td className="px-4 py-3 text-right font-mono tabular-nums text-xs text-ink-2">
										{formatDuration(avgP99)}
									</td>
									<td className="px-4 py-3 text-right font-mono tabular-nums text-xs text-ink-2">
										{formatTokens(s.input)}
									</td>
									<td className="px-4 py-3 text-right font-mono tabular-nums text-xs text-ink-2">
										{formatTokens(s.output)}
									</td>
								</tr>
							);
						})}
				</tbody>
			</table>
		</div>
	);
}

async function SloData({ range }: { range?: string }) {
	const hours = rangeToHours(range);
	const label = rangeLabel(range);
	let rows: SloRow[];
	try {
		// v_slo_stats query and resolves the tenant from the forwarded token.
		rows = await gatewayGet<SloRow[]>(`/v1/slo?hours=${hours}`);
	} catch (err) {
		// Gateway unreachable → warming banner + empty table, not the error card.
		// Re-throw anything else (incl. NEXT_REDIRECT from the auth helper).
		if (err instanceof GatewayError) {
			return (
				<>
					<WarmingBanner />
					<SloTable rows={[]} />
				</>
			);
		}
		throw err;
	}

	// Compute top-level totals
	const totalRequests = rows.reduce((s, r) => s + r.requests, 0);
	const totalErrors = rows.reduce((s, r) => s + r.errors, 0);
	const totalInputTokens = rows.reduce((s, r) => s + r.total_input_tokens, 0);
	const totalOutputTokens = rows.reduce((s, r) => s + r.total_output_tokens, 0);
	const overallErrorPct =
		totalRequests > 0 ? (totalErrors / totalRequests) * 100 : 0;
	// Bucket to the selected range (1h/6h/1d) so the chart spans the whole window
	// instead of truncating at the 48-hourly-bucket cap — mirrors the dashboard.
	const latencyPoints = buildLatencyPoints(rows, rangeBucketMs(range));
	const budget = computeSloBudget(totalRequests, totalErrors);

	return (
		<div className="space-y-6">
			{/* Plain-language "what's measured" — elevates SLO target / availability
			    / error budget to the same clarity the burn-rate line already has. */}
			<details className="rounded-lg border border-line bg-surface-2/30 px-4 py-3 text-sm">
				<summary className="cursor-pointer font-medium text-ink outline-none focus-visible:ring-2 focus-visible:ring-seal">
					What's measured here
				</summary>
				<div className="mt-2 space-y-1.5 text-[13px] text-ink-2">
					<p>
						<span className="font-medium text-ink">SLO target</span> — the
						availability you're aiming for. The ceiling for how often a request
						may fail.
					</p>
					<p>
						<span className="font-medium text-ink">Availability</span> — your
						actual success rate this window, from the captured error rate (1 −
						errors ÷ requests).
					</p>
					<p>
						<span className="font-medium text-ink">Error budget</span> — how
						much failure the target still allows. At the target it's spent; past
						it, you're over.
					</p>
					<p>
						<span className="font-medium text-ink">Burn rate</span> — how fast
						you're spending that budget. 1.0× = on pace to use exactly the
						window's allowance; above exhausts it early, below leaves headroom.
					</p>
					<p className="text-ink-3">
						All computed from captured spans — no new instrumentation, no
						fabricated numbers.
					</p>
				</div>
			</details>

			{/* Error budget — the SLO framing: pure arithmetic over the captured
			    error rate vs the availability target (zero new capture, the #3 edge). */}
			<section className="space-y-3">
				<div>
					<h2 className="text-sm font-semibold text-ink">
						Error budget — last {label} vs a {budget.targetPct.toFixed(1)}%
						availability target
					</h2>
					<p className="mt-0.5 text-[12px] text-ink-3">
						Burn rate is the multiple of the sustainable error rate you're
						spending (1.0× = exactly on pace). Below 1.0× the budget lasts the
						window; above, it's exhausted early.
					</p>
				</div>
				<div className="grid grid-cols-4 gap-4">
					<StatCard
						label="SLO target"
						value={`${budget.targetPct.toFixed(1)}%`}
					/>
					<StatCard
						label={`Availability (${label})`}
						value={`${budget.availabilityPct.toFixed(3)}%`}
						tone={toneOf(budget.tone)}
					/>
					<StatCard
						label="Error budget remaining"
						value={formatBudgetRemaining(budget.budgetRemainingPct)}
						tone={toneOf(budget.tone)}
					/>
					<StatCard
						label="Burn rate"
						value={formatBurnRate(budget.burnRate)}
						tone={toneOf(budget.tone)}
						sub="1.0× = on pace"
					/>
				</div>
			</section>
			<div className="grid grid-cols-4 gap-4">
				<StatCard
					label={`Requests (${label})`}
					value={totalRequests.toLocaleString()}
				/>
				<StatCard
					label="Error rate"
					value={`${overallErrorPct.toFixed(2)}%`}
					tone={
						overallErrorPct > 5 ? "danger" : overallErrorPct > 1 ? "warn" : "ok"
					}
				/>
				<StatCard label="Input tokens" value={formatTokens(totalInputTokens)} />
				<StatCard
					label="Output tokens"
					value={formatTokens(totalOutputTokens)}
				/>
			</div>
			<Card className="p-4">
				<h2 className="mb-3 text-sm font-semibold text-ink">
					Latency over time — last {label}
				</h2>
				<LatencyTimeline points={latencyPoints} />
			</Card>
			<SloTable rows={rows} />
		</div>
	);
}

/** SLO budget tone ("error") → shared StatCard tone ("danger"). */
function toneOf(t: "ok" | "warn" | "error"): StatTone {
	return t === "error" ? "danger" : t;
}

// Queries ClickHouse at request time — never prerender.
export const dynamic = "force-dynamic";

export default async function SloPage({
	searchParams,
}: {
	searchParams: Promise<{ range?: string }>;
}) {
	const { range } = await searchParams;
	return (
		<main className="p-6 max-w-7xl mx-auto">
			<div className="mb-6 flex flex-wrap items-start justify-between gap-3">
				<div>
					<h1 className="text-2xl font-semibold text-ink">SLOs</h1>
					<p className="mt-1 text-sm text-ink-2">
						Error budget, latency percentiles, and error rates by provider/model
						— last {rangeLabel(range)}
					</p>
				</div>
				<RangeControl />
			</div>
			<Suspense
				key={range ?? "24h"}
				fallback={
					<div className="space-y-4">
						<div className="grid grid-cols-4 gap-4">
							{[0, 1, 2, 3].map((i) => (
								<Skeleton key={i} className="h-24" />
							))}
						</div>
						<Skeleton className="h-64" />
					</div>
				}
			>
				<SloData range={range} />
			</Suspense>
		</main>
	);
}

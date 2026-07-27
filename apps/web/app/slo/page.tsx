/**
 * SLO dashboard page — per-hour latency percentiles, error rate, and
 * token usage by provider and model.
 *
 * Reads SLO rollups via the gateway proxy (GET /v1/slo) — the gateway owns
 * the ClickHouse query and resolves the tenant from the forwarded token.
 * RSC: fetched at request time with Suspense streaming.
 */

import type { SloModelRow, SloTimePoint } from "@/app/slo/types";
import { RangeControl } from "@/components/RangeControl";
import { WarmingBanner } from "@/components/empty-states/WarmingBanner";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import { fetchLatencyBreakdown, overheadByModelKey } from "@/lib/latency";
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
import { latencyPointsFromTimeseries } from "./latency";

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

function SloTable({
	modelRows,
	overheadByModel,
}: {
	/** Per-(provider, model) rows with TRUE merged p50/p95/p99 over the window
	 * (GET /v1/slo/models) — exact quantiles, NOT a mean of per-hour percentiles
	 * (provenance audit P2 #8). Already aggregated + ordered by the gateway. */
	modelRows: SloModelRow[];
	/** `"provider::model" → gateway-overhead p95 ms` (§ latency framing). Empty
	 * when the gateway is warming or no span carries a measured overhead. */
	overheadByModel: Map<string, number>;
}) {
	if (modelRows.length === 0) {
		return (
			<EmptyState
				title="No SLO data yet"
				description="Spans will appear here once traffic is flowing through the gateway."
			/>
		);
	}

	return (
		<div className="overflow-x-auto rounded-xl border border-line bg-surface">
			<table className="w-full text-sm">
				<thead className="border-b border-line">
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
						<th
							className="px-4 py-3 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3"
							title="True window percentiles — merged from the stored per-hour quantile states (not an average of hourly percentiles)."
						>
							p50
						</th>
						<th className="px-4 py-3 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
							p95
						</th>
						<th className="px-4 py-3 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
							p99
						</th>
						<th
							className="px-4 py-3 text-right text-[10px] font-semibold uppercase tracking-wide text-accent-ink"
							title="Gateway overhead p95 — the time Tracelane adds, EXCLUDING upstream generation. Compare with the p95 to the left: our slice is tiny."
						>
							Gateway ovh
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
					{modelRows.map((s) => {
						const key = `${s.provider}::${s.model}`;
						const errorPct = s.error_rate_pct;
						return (
							<tr key={key} className="transition-colors hover:bg-surface-2/30">
								<td className="px-4 py-3">
									<div className="font-medium text-xs text-ink">
										{s.provider || "—"}
									</div>
									<div className="text-xs text-ink-2 font-mono">
										{s.model || "—"}
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
									{formatDuration(s.p50_ms)}
								</td>
								<td className="px-4 py-3 text-right font-mono tabular-nums text-xs text-ink-2">
									{formatDuration(s.p95_ms)}
								</td>
								<td className="px-4 py-3 text-right font-mono tabular-nums text-xs text-ink-2">
									{formatDuration(s.p99_ms)}
								</td>
								<td
									className="px-4 py-3 text-right font-mono tabular-nums text-xs text-accent-ink"
									title="Gateway overhead p95 — Tracelane's own slice, excluding upstream generation"
								>
									{(() => {
										const ovh = overheadByModel.get(key);
										return ovh && ovh > 0 ? formatDuration(ovh) : "—";
									})()}
								</td>
								<td className="px-4 py-3 text-right font-mono tabular-nums text-xs text-ink-2">
									{formatTokens(s.total_input_tokens)}
								</td>
								<td className="px-4 py-3 text-right font-mono tabular-nums text-xs text-ink-2">
									{formatTokens(s.total_output_tokens)}
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
	const bucketMs = rangeBucketMs(range);
	const bucketHours = Math.max(1, Math.round(bucketMs / 3_600_000));
	let modelRows: SloModelRow[];
	let timePoints: SloTimePoint[];
	try {
		// slo_hourly_stats queries and resolves the tenant from the forwarded token.
		// Table = per-(provider,model) TRUE merged quantiles; chart = per-bucket
		// TRUE merged quantiles — NOT client-side means of per-hour percentiles
		// (provenance audit P2 #8).
		[modelRows, timePoints] = await Promise.all([
			gatewayGet<SloModelRow[]>(`/v1/slo/models?hours=${hours}`),
			gatewayGet<SloTimePoint[]>(
				`/v1/slo/timeseries?hours=${hours}&bucket=${bucketHours}`,
			),
		]);
	} catch (err) {
		// Gateway unreachable → warming banner + empty table, not the error card.
		// Re-throw anything else (incl. NEXT_REDIRECT from the auth helper).
		if (err instanceof GatewayError) {
			return (
				<>
					<WarmingBanner />
					<SloTable modelRows={[]} overheadByModel={new Map()} />
				</>
			);
		}
		throw err;
	}

	// Per-(provider, model) gateway overhead for the table's "our slice" column
	// (§ latency framing). Best-effort: an unreachable gateway → empty map → "—".
	const overheadByModel = overheadByModelKey(
		await fetchLatencyBreakdown({ hours }),
	);

	// Headline totals over LLM-request rows only (provider!==""), MATCHING the
	// dashboard (dashboard/page.tsx:176). The empty-provider bucket is tool/child
	// spans; including it double-counted requests and diluted the error rate, so
	// the SLO "LLM calls"/"Error rate" tiles reconcile with the identically-named
	// dashboard KPIs (same slo_hourly_stats source). The per-provider table below
	// still renders all rows. (Provenance audit P1 — cross-page parity.)
	const llmRows = modelRows.filter((r) => r.provider !== "");
	const totalRequests = llmRows.reduce((s, r) => s + r.requests, 0);
	const totalErrors = llmRows.reduce((s, r) => s + r.errors, 0);
	const totalInputTokens = llmRows.reduce(
		(s, r) => s + r.total_input_tokens,
		0,
	);
	const totalOutputTokens = llmRows.reduce(
		(s, r) => s + r.total_output_tokens,
		0,
	);
	const overallErrorPct =
		totalRequests > 0 ? (totalErrors / totalRequests) * 100 : 0;
	// Chart points are the gateway's TRUE per-bucket quantiles — just format the
	// UTC label + rename fields (no client re-aggregation).
	const latencyPoints = latencyPointsFromTimeseries(timePoints, bucketMs);
	const budget = computeSloBudget(totalRequests, totalErrors);

	return (
		<div className="space-y-5">
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
			    error rate vs the availability target (product default) (zero new capture, the #3 edge). */}
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
				<div className="grid grid-cols-4 gap-4 items-stretch">
					<StatCard
						icon="error-budget"
						label="SLO target (default)"
						value={`${budget.targetPct.toFixed(1)}%`}
						className="h-full flex flex-col"
					/>
					<StatCard
						icon="time"
						label={`Availability (${label})`}
						value={`${budget.availabilityPct.toFixed(3)}%`}
						tone={toneOf(budget.tone)}
						className="h-full flex flex-col"
					/>
					<StatCard
						icon="error-budget"
						label="Error budget remaining"
						value={formatBudgetRemaining(budget.budgetRemainingPct)}
						variant="accent"
						className="h-full flex flex-col"
					/>
					<StatCard
						icon="latency"
						label="Burn rate"
						value={formatBurnRate(budget.burnRate)}
						variant="inverse"
						sub="1.0× = on pace"
						className="h-full flex flex-col"
					/>
				</div>
			</section>
			<div className="grid grid-cols-4 gap-4 items-stretch">
				<StatCard
					icon="llm-calls"
					label={`LLM calls (${label})`}
					value={totalRequests.toLocaleString()}
					hint="Model requests — one agent run can make several. Not the trace/conversation count (see Traces)."
					className="h-full flex flex-col"
				/>
				<StatCard
					icon="failure-signatures"
					label="Error rate"
					value={`${overallErrorPct.toFixed(2)}%`}
					tone={
						overallErrorPct > 5 ? "danger" : overallErrorPct > 1 ? "warn" : "ok"
					}
					className="h-full flex flex-col"
				/>
				<StatCard
					icon="tokens"
					label="Input tokens"
					value={formatTokens(totalInputTokens)}
					className="h-full flex flex-col"
				/>
				<StatCard
					icon="tokens"
					label="Output tokens"
					value={formatTokens(totalOutputTokens)}
					className="h-full flex flex-col"
				/>
			</div>
			<Card className="p-4">
				<h2 className="mb-3 text-sm font-semibold text-ink">
					Latency over time — last {label}
				</h2>
				<LatencyTimeline points={latencyPoints} />
			</Card>
			<SloTable modelRows={modelRows} overheadByModel={overheadByModel} />
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
		<div className="px-2 py-3 sm:px-4 sm:py-4">
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
		</div>
	);
}

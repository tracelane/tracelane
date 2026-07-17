/**
 * Gateway operations (§6) — per-provider router health for the authenticated
 * tenant, live from the gateway `/v1/gateway/stats` aggregate over `spans`.
 *
 * Honesty (the §6 lock): every number here is a real, captured signal. Request
 * volume, error rate, latency p50/p95/p99, prompt-cache hit rate, and failover
 * activations are span-derived over the selected time window. Rate-limit and
 * quota-reject counts are process-lifetime counters ("since gateway start") —
 * a 429 emits no span, so they come from the gateway's live counters, labeled as
 * such and never a fabricated 0. tenant_id comes from the WorkOS session; the
 * gateway owns the tenant-scoped read.
 */

import { RangeControl } from "@/components/RangeControl";
import { WarmingBanner } from "@/components/empty-states/WarmingBanner";
import { fetchGatewayStats } from "@/lib/gateway-ops";
import { rangeLabel, rangeShort, rangeToHours } from "@/lib/range";
import { Badge, EmptyState, Skeleton, StatCard } from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";
import { Suspense } from "react";
import { TryItCurl } from "./TryItCurl";
import { circuitLabel, circuitTone, circuitUnhealthy } from "./circuit";

export const metadata: Metadata = { title: "Gateway — Tracelane" };
export const dynamic = "force-dynamic";

const pct = (v: number): string => `${v.toFixed(1)}%`;
const ms = (v: number): string => `${v.toLocaleString()} ms`;

async function GatewayData({ range }: { range?: string }) {
	const hours = rangeToHours(range);
	const stats = await fetchGatewayStats({ hours });

	// Gateway unreachable ≠ zero requests — degrade to the warming state.
	if (stats === null) {
		return (
			<>
				<WarmingBanner />
				<EmptyState
					title="Waiting on the gateway"
					description="Router health appears here once the gateway is reachable and requests have flowed."
				/>
			</>
		);
	}

	// Reachable, but no provider requests in the window (teach the first request).
	if (stats.provider_count === 0) {
		return (
			<div className="space-y-6">
				<EmptyState
					title={`No gateway requests in the last ${rangeLabel(range)}`}
					description="Point your agents at the gateway — per-provider request volume, latency, error rate, and cache-hit rate will surface here. Send one request to see it appear:"
					action={
						<Link
							href="/settings/providers"
							className="text-[13px] font-medium text-accent-ink hover:underline"
						>
							Manage providers →
						</Link>
					}
				/>
				<TryItCurl />
			</div>
		);
	}

	return (
		<div className="space-y-6">
			{/* Summary — REAL captured metrics only. */}
			<div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
				<Link
					href={`/traces?range=${rangeShort(range)}`}
					className="block rounded-xl outline-none focus-visible:ring-2 focus-visible:ring-seal"
				>
					<StatCard
						label={`Requests (${rangeShort(range)})`}
						value={stats.total_requests.toLocaleString()}
						sub={`across ${stats.provider_count} provider${stats.provider_count === 1 ? "" : "s"} · view traces`}
						interactive
					/>
				</Link>

				{stats.total_errors > 0 ? (
					<Link
						href={`/traces?status=error&range=${rangeShort(range)}`}
						className="block rounded-xl outline-none focus-visible:ring-2 focus-visible:ring-seal"
					>
						<StatCard
							label="Error rate"
							value={pct(stats.error_rate_pct)}
							sub={`${stats.total_errors.toLocaleString()} error${stats.total_errors === 1 ? "" : "s"} · view them`}
							interactive
						/>
					</Link>
				) : (
					<StatCard
						label="Error rate"
						value={pct(stats.error_rate_pct)}
						sub="no errors in window"
					/>
				)}

				<StatCard
					label="Prompt-cache hit rate"
					value={pct(stats.cache_hit_rate_pct)}
					sub={
						stats.cache_hit_rate_pct > 0 ? (
							"requests that read a provider cache"
						) : (
							<>
								No cached reads yet — enable provider prompt caching (Anthropic{" "}
								<span className="font-mono">cache_control</span>; OpenAI is
								automatic ≥1024 tokens) to cut cost and latency.
							</>
						)
					}
				/>

				<StatCard
					label="Providers active"
					value={String(stats.provider_count)}
					sub={`in the last ${rangeShort(range)}`}
				/>
			</div>

			{/* Per-provider health. */}
			<div className="overflow-x-auto rounded-lg border border-line">
				<table className="w-full text-sm">
					<thead className="bg-surface-2/50">
						<tr>
							<th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								Provider
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
								Cache hit
							</th>
							<th className="px-4 py-3 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								Failover
							</th>
							<th className="px-4 py-3 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								Circuit
							</th>
						</tr>
					</thead>
					<tbody className="divide-y divide-line">
						{stats.providers.map((p) => (
							<tr
								key={p.provider}
								className="transition-colors hover:bg-surface-2/30"
							>
								<td className="px-4 py-3 font-medium text-ink">{p.provider}</td>
								<td className="px-4 py-3 text-right font-mono tabular-nums text-ink">
									{p.requests.toLocaleString()}
								</td>
								<td className="px-4 py-3 text-right">
									{p.errors > 0 ? (
										<Badge tone="danger">{pct(p.error_rate_pct)}</Badge>
									) : (
										<span className="font-mono tabular-nums text-ok">0%</span>
									)}
								</td>
								<td className="px-4 py-3 text-right font-mono tabular-nums text-ink-2">
									{ms(p.p50_ms)}
								</td>
								<td className="px-4 py-3 text-right font-mono tabular-nums text-ink-2">
									{ms(p.p95_ms)}
								</td>
								<td className="px-4 py-3 text-right font-mono tabular-nums text-ink-2">
									{ms(p.p99_ms)}
								</td>
								<td className="px-4 py-3 text-right font-mono tabular-nums text-ink-2">
									{pct(p.cache_hit_rate_pct)}
								</td>
								<td className="px-4 py-3 text-right font-mono tabular-nums text-ink-2">
									{p.failovers > 0 ? (
										<Badge tone="warn">{p.failovers.toLocaleString()}</Badge>
									) : (
										<span className="text-ink-3">—</span>
									)}
								</td>
								<td className="px-4 py-3 text-right">
									{circuitUnhealthy(p.circuit_state) ? (
										<Badge tone={circuitTone(p.circuit_state)}>
											{circuitLabel(p.circuit_state)}
										</Badge>
									) : (
										<span className="font-mono tabular-nums text-ink-3">
											Closed
										</span>
									)}
								</td>
							</tr>
						))}
					</tbody>
				</table>
			</div>

			{/* Router events — resilience + shed-load signals. Failover is window-derived;
			    rate-limit/quota are process-lifetime counters. */}
			<section className="space-y-3">
				<div>
					<h2 className="text-sm font-semibold text-ink">Router events</h2>
					<p className="mt-0.5 text-[12px] text-ink-3">
						Failover activations are counted over the last {rangeShort(range)}.
						Rate-limit and quota rejects are live counters since the gateway
						last started (they carry no trace, so they reset on redeploy).
					</p>
				</div>
				<div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
					{stats.total_failovers > 0 ? (
						<Link
							href={`/traces?failover=true&range=${rangeShort(range)}`}
							className="block rounded-xl outline-none focus-visible:ring-2 focus-visible:ring-seal"
						>
							<StatCard
								label={`Failovers (${rangeShort(range)})`}
								value={stats.total_failovers.toLocaleString()}
								sub="served by a backup provider · view traces"
								interactive
							/>
						</Link>
					) : (
						<StatCard
							label={`Failovers (${rangeShort(range)})`}
							value={stats.total_failovers.toLocaleString()}
							sub={
								<>
									No failovers needed — add a second provider in{" "}
									<Link
										href="/settings/providers"
										className="font-medium text-accent-ink hover:underline"
									>
										LLM Providers
									</Link>{" "}
									to enable automatic failover.
								</>
							}
						/>
					)}

					<StatCard
						label="Rate-limited"
						value={stats.rate_limited_since_start.toLocaleString()}
						sub="429s since gateway start"
					/>
					<StatCard
						label="Quota-exceeded"
						value={stats.quota_exceeded_since_start.toLocaleString()}
						sub="hard-cap 429s since gateway start"
					/>
					<StatCard
						label="Circuit breakers"
						value={
							stats.open_breakers === 0
								? "All closed"
								: `${stats.open_breakers} open`
						}
						sub={
							stats.open_breakers === 0
								? "all upstreams passing"
								: "upstream(s) tripped — failing fast"
						}
					/>
				</div>
			</section>

			{/* The "try it" moment — run a request through the gateway, watch it land. */}
			<TryItCurl />
		</div>
	);
}

export default async function GatewayPage({
	searchParams,
}: {
	searchParams: Promise<{ range?: string }>;
}) {
	const { range } = await searchParams;
	return (
		<main className="mx-auto max-w-7xl p-6">
			<div className="mb-6 flex flex-wrap items-start justify-between gap-3">
				<div>
					<h1 className="text-2xl font-semibold text-ink">Gateway</h1>
					<p className="mt-1 text-sm text-ink-2">
						Provider-by-provider routing health — request distribution, error
						rate, failover activations, and circuit-breaker state per upstream.
						Latency-percentile SLOs and error-budget burn are on the{" "}
						<Link
							href="/slo"
							className="font-medium text-accent-ink hover:underline"
						>
							SLOs page
						</Link>{" "}
						— last {rangeLabel(range)}.
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
						<Skeleton className="h-64" />
					</div>
				}
			>
				<GatewayData range={range} />
			</Suspense>
		</main>
	);
}

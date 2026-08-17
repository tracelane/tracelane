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
import {
	Badge,
	Card,
	EmptyState,
	Gauge,
	MetricIcon,
	Skeleton,
	StatCard,
	StatGrid,
} from "@tracelanedev/ui";
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
			<div className="space-y-3">
				<EmptyState
					title={`No gateway requests in the last ${rangeLabel(range)}`}
					description="Point your agents at the gateway — per-provider request volume, latency, error rate, and cache-hit rate will surface here. Send one request to see it appear:"
					action={
						<Link
							href="/settings/providers"
							className="text-[13px] font-medium text-action-ink hover:underline"
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
		<div className="space-y-3">
			{/* Summary — REAL captured metrics only. */}
			<StatGrid title="Traffic &amp; routing" cols={4}>
				<Link
					href={`/traces?range=${rangeShort(range)}`}
					className="block h-full rounded-lg outline-none focus-visible:ring-2 focus-visible:ring-seal"
				>
					<StatCard
						icon="llm-calls"
						label={`LLM calls (${rangeShort(range)})`}
						hint="Model requests — one agent run can make several. Not the trace/conversation count (see Traces)."
						value={stats.total_requests.toLocaleString()}
						sub={`across ${stats.provider_count} provider${stats.provider_count === 1 ? "" : "s"} · view traces`}
						interactive
					/>
				</Link>

				{stats.total_errors > 0 ? (
					<Link
						href={`/traces?status=error&range=${rangeShort(range)}`}
						className="block h-full rounded-lg outline-none focus-visible:ring-2 focus-visible:ring-seal"
					>
						<StatCard
							icon="failure-signatures"
							label="Error rate"
							value={pct(stats.error_rate_pct)}
							sub={`${stats.total_errors.toLocaleString()} error${stats.total_errors === 1 ? "" : "s"} · view them`}
							interactive
							className="h-full flex flex-col"
						/>
					</Link>
				) : (
					<StatCard
						icon="failure-signatures"
						label="Error rate"
						value={pct(stats.error_rate_pct)}
						sub="no errors in window"
					/>
				)}

				<Card
					className="flex flex-col p-4 h-full"
					title={
						stats.cache_hit_rate_pct > 0
							? "Requests that read a provider prompt cache."
							: "No cached reads yet — enable provider prompt caching (Anthropic cache_control; OpenAI is automatic ≥1024 tokens) to cut cost and latency."
					}
				>
					<div className="flex items-center gap-2">
						<MetricIcon name="time" size={26} />
						<p className="t-card-title text-ink-3">Prompt-cache hit</p>
					</div>
					<div className="flex flex-1 items-center justify-center">
						<Gauge
							value={stats.cache_hit_rate_pct}
							display={pct(stats.cache_hit_rate_pct)}
							label={
								stats.cache_hit_rate_pct > 0
									? "provider-cache reads"
									: "enable caching to cut cost"
							}
						/>
					</div>
				</Card>

				<StatCard
					icon="model-breakdown"
					label="Providers active"
					value={String(stats.provider_count)}
					sub={`in the last ${rangeShort(range)}`}
				/>
			</StatGrid>

			{/* Per-provider health. */}
			<div className="overflow-x-auto rounded-lg border border-line bg-surface">
				<table className="w-full text-sm">
					<thead className="border-b border-line">
						<tr>
							<th className="px-3 py-1.5 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								Provider
							</th>
							<th className="px-3 py-1.5 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								LLM calls
							</th>
							<th className="px-3 py-1.5 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								Error rate
							</th>
							<th className="px-3 py-1.5 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								p50
							</th>
							<th className="px-3 py-1.5 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								p95
							</th>
							<th className="px-3 py-1.5 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								p99
							</th>
							<th
								className="px-3 py-1.5 text-right text-[10px] font-semibold uppercase tracking-wide text-action-ink"
								title="Gateway overhead p95 — the time Tracelane adds per request, EXCLUDING the upstream provider round-trip. Compare with the end-to-end p95 to the left: our slice is tiny."
							>
								Gateway ovh
							</th>
							<th className="px-3 py-1.5 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								Cache hit
							</th>
							<th className="px-3 py-1.5 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								Failover
							</th>
							<th
								className="px-3 py-1.5 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3"
								title="Upstream breaker state — process-wide shared-infra health, not tenant-specific."
							>
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
								<td className="px-3 py-2 font-medium text-ink">{p.provider}</td>
								<td className="px-3 py-2 text-right font-mono tabular-nums text-ink">
									{p.requests.toLocaleString()}
								</td>
								<td className="px-3 py-2 text-right">
									{p.errors > 0 ? (
										<Badge tone="danger">{pct(p.error_rate_pct)}</Badge>
									) : (
										<span className="font-mono tabular-nums text-ok-ink">
											0%
										</span>
									)}
								</td>
								<td className="px-3 py-2 text-right font-mono tabular-nums text-ink-2">
									{ms(p.p50_ms)}
								</td>
								<td className="px-3 py-2 text-right font-mono tabular-nums text-ink-2">
									{ms(p.p95_ms)}
								</td>
								<td className="px-3 py-2 text-right font-mono tabular-nums text-ink-2">
									{ms(p.p99_ms)}
								</td>
								<td
									className="px-3 py-2 text-right font-mono tabular-nums text-action-ink"
									title="Gateway overhead p95 — Tracelane's own slice, excluding upstream generation"
								>
									{p.overhead_p95_ms > 0 ? ms(p.overhead_p95_ms) : "—"}
								</td>
								<td className="px-3 py-2 text-right font-mono tabular-nums text-ink-2">
									{pct(p.cache_hit_rate_pct)}
								</td>
								<td className="px-3 py-2 text-right font-mono tabular-nums text-ink-2">
									{p.failovers > 0 ? (
										<Badge tone="warn">{p.failovers.toLocaleString()}</Badge>
									) : (
										<span className="text-ink-3">—</span>
									)}
								</td>
								<td className="px-3 py-2 text-right">
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
				<StatGrid cols={4}>
					{stats.total_failovers > 0 ? (
						<Link
							href={`/traces?failover=true&range=${rangeShort(range)}`}
							className="block h-full rounded-lg outline-none focus-visible:ring-2 focus-visible:ring-seal"
						>
							<StatCard
								icon="request-flow"
								label={`Failovers (${rangeShort(range)})`}
								value={stats.total_failovers.toLocaleString()}
								sub="served by a backup provider · view traces"
								interactive
								className="h-full flex flex-col"
							/>
						</Link>
					) : (
						<StatCard
							icon="request-flow"
							label={`Failovers (${rangeShort(range)})`}
							value={stats.total_failovers.toLocaleString()}
							sub={
								<>
									No failovers needed — add a second provider in{" "}
									<Link
										href="/settings/providers"
										className="font-medium text-action-ink hover:underline"
									>
										LLM Providers
									</Link>{" "}
									to enable automatic failover.
								</>
							}
							className="h-full flex flex-col"
						/>
					)}

					<StatCard
						icon="traffic"
						label="Rate-limited (since start)"
						value={stats.rate_limited_since_start.toLocaleString()}
						sub="429s since gateway start"
					/>
					<StatCard
						icon="spend"
						label="Quota-exceeded (since start)"
						value={stats.quota_exceeded_since_start.toLocaleString()}
						sub="hard-cap 429s since gateway start"
					/>
					<StatCard
						icon="error-budget"
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
				</StatGrid>
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
		<div className="px-2 py-3 sm:px-4 sm:py-4">
			<div className="mb-4 flex flex-wrap items-start justify-between gap-3">
				<div className="max-w-2xl">
					<h1 className="t-h1">Gateway</h1>
					<p className="mt-1 text-sm text-ink-2">
						Per-provider routing health — volume, errors, failover and breaker
						state. Latency SLOs live on the{" "}
						<Link
							href="/slo"
							className="font-medium text-action-ink hover:underline"
						>
							SLOs page
						</Link>{" "}
						— last {rangeLabel(range)}.
					</p>
				</div>
				<RangeControl />
			</div>
			<Suspense
				fallback={
					<div className="space-y-4">
						<StatGrid cols={4}>
							{[0, 1, 2, 3].map((i) => (
								<Skeleton key={i} className="h-24" />
							))}
						</StatGrid>
						<Skeleton className="h-64" />
					</div>
				}
			>
				<GatewayData range={range} />
			</Suspense>
		</div>
	);
}

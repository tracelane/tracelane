/**
 * returning users land here (not in raw trace rows); it answers "is my agent
 * fleet healthy right now?" in one screen before anyone drills into a trace.
 *
 * Every card is a REAL gateway read — there are no fabricated numbers. When the
 * gateway is unreachable the whole surface degrades to the warming state; when
 * it is reachable but empty each card shows an honest zero. Cards click through
 * relevant view").
 *
 * Reuses the /slo arithmetic verbatim (`computeSloBudget`, `buildLatencyPoints`)
 * so the burn snapshot and latency chart can never drift from the SLO page.
 *
 * Data sources (all gateway-proxied, tenant resolved from the forwarded token):
 *   - GET /v1/slo?hours=24         → requests / error rate / latency / burn
 *   - GET /v1/query/signatures     → top failure signatures
 *   - GET /v1/gateway/stats        → open circuit breakers
 */

import { computeSloBudget } from "@/app/slo/budget";
import { buildLatencyPoints, buildTrafficPoints } from "@/app/slo/latency";
import type { SloRow } from "@/app/slo/types";
import { RangeControl } from "@/components/RangeControl";
import { TrafficTimeline } from "@/components/dashboard/TrafficTimeline";
import { WarmingBanner } from "@/components/empty-states/WarmingBanner";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import { fetchGatewayStats } from "@/lib/gateway-ops";
import {
	rangeBucketMs,
	rangeLabel,
	rangeShort,
	rangeToHours,
} from "@/lib/range";
import {
	Badge,
	Card,
	EmptyState,
	LatencyTimeline,
	StatCard,
} from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";
import { Suspense } from "react";

export const metadata: Metadata = { title: "Overview — Tracelane" };

// Reads the session + gateway at request time — never prerender.
export const dynamic = "force-dynamic";

/** A failure-signature hit — mirrors the /signatures read shape. */
type SignatureHit = {
	signature_id: string;
	your_hits: number;
	action: "blocking" | "flag-only";
};

/** One tool row from the /v1/query/tool-analytics response. */
type ToolRow = {
	tool: string;
	calls: number;
	errors: number;
	p95_ms: number;
};

/** Full response from GET /v1/query/tool-analytics?hours=N. */
type ToolAnalyticsResponse = {
	window_hours: number;
	total_calls: number;
	tools: ToolRow[];
};

/** ms → human latency. Non-positive (no data) renders an em-dash, never "0ms". */
function fmtMs(ms: number): string {
	if (ms <= 0) return "—";
	if (ms < 1000) return `${ms.toFixed(0)}ms`;
	return `${(ms / 1000).toFixed(2)}s`;
}

function fmtBurn(x: number): string {
	return Number.isFinite(x) ? `${x.toFixed(2)}×` : "∞×";
}

function fmtBudget(pct: number): string {
	if (!Number.isFinite(pct)) return "over budget";
	if (pct < 0) return `${Math.abs(pct).toFixed(0)}% over`;
	return `${pct.toFixed(0)}%`;
}

function fmtTokens(n: number): string {
	if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
	if (n >= 1000) return `${(n / 1000).toFixed(1)}K`;
	return String(n);
}

function fmtCost(usd: number): string {
	if (usd < 0.01) return `$${usd.toFixed(4)}`;
	if (usd < 1) return `$${usd.toFixed(3)}`;
	if (usd < 1000) return `$${usd.toFixed(2)}`;
	return `$${(usd / 1000).toFixed(1)}K`;
}

/** Focus ring shared by every click-through stat tile wrapper. */
const TILE_LINK_CLS =
	"block rounded-xl focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal";

async function DashboardData({ range }: { range: string | undefined }) {
	// The global range control drives EVERY read and every card href on this
	// surface, so the numbers and the drill-throughs stay on the same window.
	const hours = rangeToHours(range);
	const bucketMs = rangeBucketMs(range);
	const rShort = rangeShort(range); // "24h" | "7d" | "30d" — for labels + hrefs
	const rLabel = rangeLabel(range); // "24 hours" | "7 days" | "30 days"
	const sinceIso = new Date(Date.now() - hours * 3_600_000).toISOString();

	// Four independent reads — one degrading (e.g. gateway warming) must not
	// blank the others. Each rejection handler re-throws anything that is NOT a
	// GatewayError so NEXT_REDIRECT from the auth helper is never swallowed.
	const [slo, signatures, gw, toolAnalytics] = await Promise.all([
		gatewayGet<SloRow[]>(`/v1/slo?hours=${hours}`).then(
			(rows) => ({ rows, warming: false }),
			(err) => {
				if (err instanceof GatewayError)
					return { rows: [] as SloRow[], warming: true };
				throw err;
			},
		),
		gatewayGet<{ signatures: SignatureHit[] }>(
			`/v1/query/signatures?since=${encodeURIComponent(sinceIso)}`,
		).then(
			(d) => d.signatures,
			(err) => {
				if (err instanceof GatewayError) return [] as SignatureHit[];
				throw err;
			},
		),
		fetchGatewayStats({ hours }), // null on unreachable
		gatewayGet<ToolAnalyticsResponse>(
			`/v1/query/tool-analytics?hours=${hours}`,
		).then(
			(d) => d,
			(err) => {
				if (err instanceof GatewayError) return null; // gateway unreachable
				throw err;
			},
		),
	]);

	const dash = slo.warming; // gateway unreachable → em-dash the SLO-derived cards
	const rows = slo.rows;
	const totalRequests = rows.reduce((s, r) => s + r.requests, 0);
	const totalErrors = rows.reduce((s, r) => s + r.errors, 0);
	const errorPct = totalRequests > 0 ? (totalErrors / totalRequests) * 100 : 0;
	// Request-WEIGHTED mean of the hourly percentiles — Σ(pXX·requests)/Σrequests,
	// the same weighting `buildLatencyPoints` applies to the chart below, so a
	// low-volume outlier bucket can't skew the headline away from the chart.
	// (Percentile-of-percentiles is inherently approximate; a true 24h merged
	// quantile is a server-side follow-up.)
	const wmean = (pick: (r: SloRow) => number): number =>
		totalRequests > 0
			? rows.reduce((s, r) => s + pick(r) * r.requests, 0) / totalRequests
			: 0;
	const meanP50 = wmean((r) => r.p50_ms);
	const meanP95 = wmean((r) => r.p95_ms);
	const meanP99 = wmean((r) => r.p99_ms);
	const budget = computeSloBudget(totalRequests, totalErrors);
	const points = buildLatencyPoints(rows, bucketMs);
	const traffic = buildTrafficPoints(rows, bucketMs);
	// A chart bar → that bucket's traces (gateway list honors since/until).
	const barHref = (p: { t: number }) =>
		`/traces?since=${encodeURIComponent(new Date(p.t).toISOString())}&until=${encodeURIComponent(
			new Date(p.t + bucketMs).toISOString(),
		)}`;

	const totalInputTokens = rows.reduce((s, r) => s + r.total_input_tokens, 0);
	const totalOutputTokens = rows.reduce((s, r) => s + r.total_output_tokens, 0);

	// Router signals — real, from the live gateway aggregate (null when unreachable).
	const cacheHitPct = gw ? gw.cache_hit_rate_pct : null;
	const failovers = gw ? gw.total_failovers : null;
	// Real spend = summed stored per-span cost. 0 (or null) → "—", never a fake $0.
	const spend = gw ? gw.total_cost_usd : null;
	const openBreakers = gw
		? gw.providers.filter((p) => p.circuit_state === "open").length
		: null;
	const halfOpen = gw
		? gw.providers.filter((p) => p.circuit_state === "half_open").length
		: 0;

	// Traffic by provider/model (top 5 by request volume) — real SLO aggregates.
	const byModel = new Map<
		string,
		{ model: string; provider: string; requests: number; tokens: number }
	>();
	for (const r of rows) {
		const key = `${r.provider}::${r.model}`;
		const cur = byModel.get(key) ?? {
			model: r.model || "—",
			provider: r.provider || "—",
			requests: 0,
			tokens: 0,
		};
		cur.requests += r.requests;
		cur.tokens += r.total_input_tokens + r.total_output_tokens;
		byModel.set(key, cur);
	}
	const topModels = [...byModel.values()]
		.sort((a, b) => b.requests - a.requests)
		.slice(0, 5);
	const maxModelReq = topModels[0]?.requests ?? 0;

	const topSigs = [...signatures]
		.sort((a, b) => b.your_hits - a.your_hits)
		.slice(0, 5);

	// Tool analytics — top 5 tools by call volume. null when gateway is unreachable.
	const toolAnalyticsWarming = toolAnalytics === null;
	const totalToolCalls = toolAnalytics?.total_calls ?? 0;
	const topTools = (toolAnalytics?.tools ?? [])
		.sort((a, b) => b.calls - a.calls)
		.slice(0, 5);
	const maxToolCalls = topTools[0]?.calls ?? 0;

	// budget.tone uses the old "error" value from the SLO module — map to "danger"
	// for the shared StatCard token vocabulary.
	const budgetTone =
		budget.tone === "error" ? "danger" : (budget.tone as "ok" | "warn");

	return (
		<div className="space-y-6">
			{dash && <WarmingBanner />}

			{/* Row 1 — the health headline. All four click through to detail. */}
			<div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
				<Link href={`/traces?range=${rShort}`} className={TILE_LINK_CLS}>
					{/* Same range as the card so the drilled-into list count matches. */}
					<StatCard
						label={`Requests (${rShort})`}
						value={dash ? "—" : totalRequests.toLocaleString()}
						interactive
					/>
				</Link>
				<Link
					href={`/traces?status=error&range=${rShort}`}
					className={TILE_LINK_CLS}
				>
					<StatCard
						label={`Error rate (${rShort})`}
						value={dash ? "—" : `${errorPct.toFixed(2)}%`}
						tone={errorPct > 5 ? "danger" : errorPct > 1 ? "warn" : "ok"}
						interactive
					/>
				</Link>
				<Link href="/slo" className={TILE_LINK_CLS}>
					<StatCard
						label={`p95 latency (${rShort})`}
						value={dash ? "—" : fmtMs(meanP95)}
						sub={
							dash ? undefined : `p50 ${fmtMs(meanP50)} · p99 ${fmtMs(meanP99)}`
						}
						interactive
					/>
				</Link>
				<Link href="/gateway" className={TILE_LINK_CLS}>
					{/* Real summed per-span cost. "—" when unreachable OR no priced
					    traffic — we never imply $0 spend from an absence of pricing. */}
					<StatCard
						label={`Spend (${rShort})`}
						value={spend === null || spend === 0 ? "—" : fmtCost(spend)}
						sub={spend && spend > 0 ? "priced traffic only" : undefined}
						interactive
					/>
				</Link>
			</div>

			{/* Row 2 — gateway/traffic signals (real; router values null when the
			    gateway is unreachable). */}
			<div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
				<Link href="/gateway" className={TILE_LINK_CLS}>
					{/* Provider health is UNKNOWN when the gateway is unreachable — never
					    assert green "all providers healthy" during an outage. */}
					<StatCard
						label="Open breakers"
						value={openBreakers === null ? "—" : String(openBreakers)}
						tone={
							openBreakers === null
								? "default"
								: openBreakers > 0
									? "danger"
									: "ok"
						}
						sub={
							openBreakers === null
								? undefined
								: halfOpen > 0
									? `${halfOpen} half-open`
									: "all providers healthy"
						}
						interactive
					/>
				</Link>
				<Link href="/gateway" className={TILE_LINK_CLS}>
					<StatCard
						label={`Cache hit rate (${rShort})`}
						value={cacheHitPct === null ? "—" : `${cacheHitPct.toFixed(1)}%`}
						interactive
					/>
				</Link>
				<Link href="/gateway" className={TILE_LINK_CLS}>
					<StatCard
						label={`Failovers (${rShort})`}
						value={failovers === null ? "—" : failovers.toLocaleString()}
						sub={
							failovers && failovers > 0
								? "cross-provider recoveries"
								: undefined
						}
						interactive
					/>
				</Link>
				<Link href="/slo" className={TILE_LINK_CLS}>
					<StatCard
						label={`Tokens (${rShort})`}
						value={dash ? "—" : fmtTokens(totalInputTokens + totalOutputTokens)}
						sub={
							dash
								? undefined
								: `in ${fmtTokens(totalInputTokens)} · out ${fmtTokens(totalOutputTokens)}`
						}
						interactive
					/>
				</Link>
			</div>

			{/* Error budget (SLO burn snapshot) — reachable only; arithmetic over the
			    captured error rate, no new capture. */}
			{!dash && (
				<section className="space-y-2">
					<h2 className="text-sm font-medium text-ink">
						Error budget — {rShort} vs a {budget.targetPct.toFixed(1)}% target
					</h2>
					<div className="grid gap-4 sm:grid-cols-3">
						<StatCard
							label={`Availability (${rShort})`}
							value={`${budget.availabilityPct.toFixed(3)}%`}
							tone={budgetTone}
						/>
						<StatCard
							label="Budget remaining"
							value={fmtBudget(budget.budgetRemainingPct)}
							tone={budgetTone}
						/>
						<StatCard
							label="Burn rate"
							value={fmtBurn(budget.burnRate)}
							tone={budgetTone}
							sub="1.0× = on pace"
						/>
					</div>
				</section>
			)}

			{/* Time-series row — traffic + latency, side by side on wide screens. */}
			<div className="grid gap-4 lg:grid-cols-2">
				<section className="space-y-2">
					<h2 className="text-sm font-medium text-ink">
						Traffic over time — last {rLabel}
					</h2>
					<Card className="p-4">
						<TrafficTimeline
							points={traffic}
							ariaLabel={`requests per bucket over the last ${rLabel}`}
							hrefFor={barHref}
						/>
					</Card>
				</section>
				<section className="space-y-2">
					<h2 className="text-sm font-medium text-ink">
						Latency over time — last {rLabel}
					</h2>
					<Card className="p-4">
						{points.length > 0 ? (
							<LatencyTimeline points={points} />
						) : (
							<EmptyState
								title="No latency data yet"
								description="Hourly percentiles appear here as requests flow through the gateway."
								className="py-8"
							/>
						)}
					</Card>
				</section>
			</div>

			{/* Tool usage — top tools by call volume with error rate + p95. */}
			<section className="space-y-2">
				<div className="flex items-center justify-between">
					<h2 className="text-sm font-medium text-ink">
						Tool usage ({rShort})
					</h2>
					<Link
						href="/traces"
						className="rounded text-[13px] font-medium text-accent-ink hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
					>
						View traces →
					</Link>
				</div>
				{toolAnalyticsWarming ? (
					<EmptyState
						title="Warming up"
						description="Tool usage data is unavailable while the gateway is warming."
					/>
				) : totalToolCalls === 0 ? (
					<EmptyState
						title="No tool calls yet"
						description="Per-tool call counts, error rates, and p95 latency appear here once your agents invoke tools through the gateway."
						action={
							<Link
								href="/traces"
								className="rounded text-[13px] font-medium text-accent-ink hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
							>
								View traces →
							</Link>
						}
					/>
				) : (
					<Card className="overflow-hidden">
						<table className="w-full text-sm">
							<thead className="bg-surface-2/40">
								<tr>
									<th className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-2">
										Tool
									</th>
									<th className="px-4 py-2.5 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-2">
										Calls
									</th>
									<th className="px-4 py-2.5 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-2">
										Errors
									</th>
									<th className="px-4 py-2.5 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-2">
										p95
									</th>
								</tr>
							</thead>
							<tbody className="divide-y divide-line">
								{topTools.map((t) => {
									const errPct =
										t.calls > 0
											? ((t.errors / t.calls) * 100).toFixed(1)
											: "0.0";
									return (
										<tr
											key={t.tool}
											className="transition-colors hover:bg-surface-2/30"
										>
											<td className="px-4 py-2.5">
												<span
													className="block truncate font-mono text-xs text-ink"
													title={t.tool}
												>
													{t.tool}
												</span>
												<div className="mt-1 h-1 overflow-hidden rounded-full bg-surface-2">
													<div
														className="h-full rounded-full bg-info"
														style={{
															width: `${maxToolCalls > 0 ? (t.calls / maxToolCalls) * 100 : 0}%`,
														}}
													/>
												</div>
											</td>
											<td className="px-4 py-2.5 text-right font-mono text-xs tabular-nums text-ink">
												{t.calls.toLocaleString()}
											</td>
											<td
												className={`px-4 py-2.5 text-right font-mono text-xs tabular-nums ${
													t.errors > 0 ? "text-danger" : "text-ink-3"
												}`}
											>
												{t.errors > 0 ? `${errPct}%` : "—"}
											</td>
											<td className="px-4 py-2.5 text-right font-mono text-xs tabular-nums text-ink-2">
												{fmtMs(t.p95_ms)}
											</td>
										</tr>
									);
								})}
							</tbody>
						</table>
					</Card>
				)}
			</section>

			{/* Breakdown row — traffic by model + top failure signatures. */}
			<div className="grid gap-4 lg:grid-cols-2">
				{/* Traffic by model — top 5 provider/model series by request volume.
			    Real SLO aggregates; the bar is each model's share of the top model. */}
				<section className="space-y-2">
					<div className="flex items-center justify-between">
						<h2 className="text-sm font-medium text-ink">Traffic by model</h2>
						<Link
							href="/slo"
							className="rounded text-[13px] font-medium text-accent-ink hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
						>
							View all →
						</Link>
					</div>
					{topModels.length > 0 ? (
						<Card className="overflow-hidden">
							<table className="w-full text-sm">
								<thead className="bg-surface-2/40">
									<tr>
										<th className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-2">
											Model
										</th>
										<th className="px-4 py-2.5 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-2">
											Requests
										</th>
										<th className="px-4 py-2.5 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-2">
											Tokens
										</th>
									</tr>
								</thead>
								<tbody className="divide-y divide-line">
									{topModels.map((m) => (
										<tr
											key={`${m.provider}::${m.model}`}
											className="transition-colors hover:bg-surface-2/30"
										>
											<td className="px-4 py-2.5">
												{m.model && m.model !== "—" ? (
													<Link
														href={`/traces?model=${encodeURIComponent(m.model)}&range=${rShort}`}
														className="block truncate font-mono text-xs text-ink hover:text-accent-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
														title={`View ${m.model} traces`}
													>
														{m.model}
													</Link>
												) : (
													<span
														className="block truncate font-mono text-xs text-ink"
														title={m.model}
													>
														{m.model}
													</span>
												)}
												<div className="mt-1 h-1 overflow-hidden rounded-full bg-surface-2">
													<div
														className="h-full rounded-full bg-line-2"
														style={{
															width: `${maxModelReq > 0 ? (m.requests / maxModelReq) * 100 : 0}%`,
														}}
													/>
												</div>
											</td>
											<td className="px-4 py-2.5 text-right font-mono text-xs tabular-nums text-ink">
												{m.requests.toLocaleString()}
											</td>
											<td className="px-4 py-2.5 text-right font-mono text-xs tabular-nums text-ink-2">
												{fmtTokens(m.tokens)}
											</td>
										</tr>
									))}
								</tbody>
							</table>
						</Card>
					) : (
						<EmptyState
							title="No traffic yet"
							description="Per-model request volume appears here once your agents call the gateway."
							action={
								<Link
									href="/settings/providers"
									className="rounded text-[13px] font-medium text-accent-ink hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
								>
									Connect a provider →
								</Link>
							}
						/>
					)}
				</section>

				{/* Top failure signatures — the differentiator surface (teal top-border).
			    Rows click through to the full Signatures view. */}
				<section className="space-y-2">
					<div className="flex items-center justify-between">
						<h2 className="text-sm font-medium text-ink">
							Top failure signatures
						</h2>
						<Link
							href="/signatures"
							className="rounded text-[13px] font-medium text-accent-ink hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
						>
							View all →
						</Link>
					</div>
					{topSigs.length > 0 ? (
						<Card className="overflow-hidden">
							<table className="w-full text-sm">
								<thead className="bg-surface-2/40">
									<tr>
										<th className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-2">
											Signature
										</th>
										<th className="px-4 py-2.5 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-2">
											Hits ({rShort})
										</th>
										<th className="px-4 py-2.5 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-2">
											Action
										</th>
									</tr>
								</thead>
								<tbody className="divide-y divide-line">
									{topSigs.map((s) => (
										<tr
											key={s.signature_id}
											className="transition-colors hover:bg-surface-2/30"
										>
											<td className="px-4 py-2.5">
												<Link
													href={`/traces?signature_id=${encodeURIComponent(s.signature_id)}&range=${rShort}`}
													className="rounded font-mono text-xs text-ink hover:text-accent-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
													title={`View ${s.signature_id} traces`}
												>
													{s.signature_id}
												</Link>
											</td>
											<td className="px-4 py-2.5 text-right font-mono text-xs tabular-nums text-ink">
												{s.your_hits.toLocaleString()}
											</td>
											<td className="px-4 py-2.5 text-right">
												<Badge
													tone={s.action === "blocking" ? "danger" : "warn"}
												>
													{s.action === "blocking" ? "blocking" : "flag-only"}
												</Badge>
											</td>
										</tr>
									))}
								</tbody>
							</table>
						</Card>
					) : (
						<EmptyState
							title="No failure signatures matched yet"
							description="When a known agent-failure pattern (tool-schema violation, definition drift) is seen in your traces, it surfaces here."
							action={
								<Link
									href="/signatures"
									className="rounded text-[13px] font-medium text-accent-ink hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
								>
									About failure signatures →
								</Link>
							}
						/>
					)}
				</section>
			</div>
		</div>
	);
}

export default async function DashboardPage({
	searchParams,
}: {
	searchParams: Promise<{ range?: string }>;
}) {
	const { range } = await searchParams;
	return (
		<div className="mx-auto max-w-6xl px-6 py-8">
			<div className="mb-6 flex items-center justify-between gap-4">
				<h1 className="text-xl font-semibold text-ink">Overview</h1>
				<RangeControl />
			</div>
			<Suspense
				key={range ?? "24h"}
				fallback={<p className="text-sm text-ink-3">Loading overview…</p>}
			>
				<DashboardData range={range} />
			</Suspense>
		</div>
	);
}

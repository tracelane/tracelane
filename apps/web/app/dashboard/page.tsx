/**
 * returning users land here (not in raw trace rows); it answers "is my agent
 * fleet healthy right now?" in one screen before anyone drills into a trace.
 *
 * Every card is a REAL gateway read — there are no fabricated numbers. When the
 * gateway is unreachable the whole surface degrades to the warming state; when
 * it is reachable but empty each card shows an honest zero. Cards click through
 * relevant view").
 *
 * Reuses the /slo arithmetic verbatim (`computeSloBudget`,
 * `latencyPointsFromTimeseries`) so the burn snapshot and latency chart can never
 * drift from the SLO page — both now read the gateway's TRUE per-bucket quantiles.
 *
 * Data sources (all gateway-proxied, tenant resolved from the forwarded token):
 *   - GET /v1/slo?hours=24         → requests / error rate / latency / burn
 *   - GET /v1/query/signatures     → top failure signatures
 *   - GET /v1/gateway/stats        → open circuit breakers
 */

import { computeSloBudget } from "@/app/slo/budget";
import {
	buildTrafficPoints,
	latencyPointsFromTimeseries,
} from "@/app/slo/latency";
import type { SloRow, SloSummary, SloTimePoint } from "@/app/slo/types";
import { RangeControl } from "@/components/RangeControl";
import { WarmingBanner } from "@/components/empty-states/WarmingBanner";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import { fetchGatewayStats } from "@/lib/gateway-ops";
import { fetchGuardrailStats } from "@/lib/guardrails";
import { fetchLatencyBreakdown } from "@/lib/latency";
import {
	rangeBucketMs,
	rangeLabel,
	rangeShort,
	rangeToHours,
} from "@/lib/range";
import {
	Badge,
	Card,
	ConcentricRings,
	EmptyState,
	LatencyTimeline,
	Lollipop,
	MetricIcon,
	type MetricIconName,
	RequestFlow,
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

/** Section divider label — reused for every bento group. The eyebrow type
 *  (10px/700/.12em) plus the trailing hairline rule, per visual-pass-01. */
function SectionLabel({ children }: { children: string }) {
	return (
		<div className="mt-1 flex items-center gap-3">
			<span className="t-eyebrow">{children}</span>
			<span className="h-px flex-1 bg-line" />
		</div>
	);
}

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
	const [
		slo,
		sloSummary,
		signatures,
		gw,
		toolAnalytics,
		latency,
		guardrails,
		timePoints,
	] = await Promise.all([
		gatewayGet<SloRow[]>(`/v1/slo?hours=${hours}`).then(
			(rows) => ({ rows, warming: false }),
			(err) => {
				if (err instanceof GatewayError)
					return { rows: [] as SloRow[], warming: true };
				throw err;
			},
		),
		// over the stored per-hour states), for the headline tiles. Null on an
		// unreachable gateway → the tiles fall back to the weighted-mean below.
		gatewayGet<SloSummary>(`/v1/slo/summary?hours=${hours}`).then(
			(s) => s,
			(err) => {
				if (err instanceof GatewayError) return null;
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
		// Honest latency split (§ latency framing): gateway overhead (what WE add)
		// vs upstream provider vs TTFT. null on unreachable → the tiles show "—".
		fetchLatencyBreakdown({ hours }),
		// Pre-flight block rate for the strip — real /v1/guardrails/stats. null on
		// unreachable → the strip pill shows "—".
		fetchGuardrailStats({ hours }),
		// Latency-over-time chart points — the gateway's TRUE per-bucket
		// quantileMerge (provenance audit P2 #8), NOT a client mean of per-hour
		// percentiles. [] on unreachable → the chart is empty, tiles unaffected.
		gatewayGet<SloTimePoint[]>(
			`/v1/slo/timeseries?hours=${hours}&bucket=${Math.max(1, Math.round(bucketMs / 3_600_000))}`,
		).then(
			(p) => p,
			(err) => {
				if (err instanceof GatewayError) return [] as SloTimePoint[];
				throw err;
			},
		),
	]);

	const dash = slo.warming; // gateway unreachable → em-dash the SLO-derived cards
	// empty-provider bucket. Including them made "Requests" a raw SPAN count that
	// double-counted tool spans (also shown as "Tool usage") and over-counted
	// multi-span SDK/agent traces, and diluted the error rate. Every SLO-derived
	// metric below is now over LLM-request spans, so "Requests" reconciles with the
	// /traces list it links to (1 LLM span per request in the common case; a true
	// distinct-trace count via uniqExact(trace_id) is the exact-match follow-up).
	const rows = slo.rows.filter((r) => r.provider !== "");
	const totalRequests = rows.reduce((s, r) => s + r.requests, 0);
	const totalErrors = rows.reduce((s, r) => s + r.errors, 0);
	const errorPct = totalRequests > 0 ? (totalErrors / totalRequests) * 100 : 0;
	// (quantileMerge over the stored per-hour states), NOT a request-weighted mean
	// of the per-hour bucket percentiles. A weighted mean of percentiles is a
	// percentile-of-percentiles and diverges from the real quantile. The wmean is
	// kept only as the fallback when the summary endpoint is unavailable (gateway
	// warming), so the tiles degrade to an approximation rather than to blank.
	const wmean = (pick: (r: SloRow) => number): number =>
		totalRequests > 0
			? rows.reduce((s, r) => s + pick(r) * r.requests, 0) / totalRequests
			: 0;
	const meanP95 = sloSummary ? sloSummary.p95_ms : wmean((r) => r.p95_ms);
	// Provenance audit #9: when the summary endpoint is unavailable the ring falls
	// back to the weighted-mean-of-hourly-p95 (a percentile-of-percentiles). Flag
	// it `~` so an approximation is never shown as a true window quantile.
	const usingFallback = !sloSummary;
	const budget = computeSloBudget(totalRequests, totalErrors);
	const points = latencyPointsFromTimeseries(timePoints, bucketMs);
	const traffic = buildTrafficPoints(rows, bucketMs);
	// A chart bar → that bucket's traces (gateway list honors since/until).
	const barHref = (p: { t: number }) =>
		`/traces?since=${encodeURIComponent(new Date(p.t).toISOString())}&until=${encodeURIComponent(
			new Date(p.t + bucketMs).toISOString(),
		)}`;
	// Traffic as lollipop points — real per-hour request counts (honest zero bars).
	const trafficLolli = traffic.map((p) => ({
		label: p.label,
		value: p.requests,
	}));
	const trafficHref = (i: number) => {
		const p = traffic[i];
		return p ? barHref(p) : `/traces?range=${rShort}`;
	};
	// Real gateway share of the end-to-end trip (both p95; flagged ≈). Null when
	// there is no measured overhead or no window p95 — never a fabricated split.
	const gwTripPct =
		latency && latency.overhead_samples > 0 && meanP95 > 0
			? Math.round((latency.overhead_p95_ms / meanP95) * 100)
			: null;

	const totalInputTokens = rows.reduce((s, r) => s + r.total_input_tokens, 0);
	const totalOutputTokens = rows.reduce((s, r) => s + r.total_output_tokens, 0);

	// Router signals — real, from the live gateway aggregate (null when unreachable).
	const cacheHitPct = gw ? gw.cache_hit_rate_pct : null;
	// Real spend = summed stored per-span cost. 0 (or null) → "—", never a fake $0.
	const spend = gw ? gw.total_cost_usd : null;
	// Pre-flight block rate — real guardrail metric (null when unreachable).
	// (Circuit-breaker + failover resilience signals live on the Gateway page,
	// where the full per-provider router health is shown — not duplicated here.)
	const blockRatePct = guardrails ? guardrails.block_rate_pct : null;

	// Traffic by provider/model (top 5 by request volume) — real SLO aggregates.
	// `errors` is summed too so the request-flow Sankey can split each model into
	// its honest OK / Error outcome (no new read — same rows).
	const byModel = new Map<
		string,
		{
			model: string;
			provider: string;
			requests: number;
			errors: number;
			tokens: number;
		}
	>();
	for (const r of rows) {
		const key = `${r.provider}::${r.model}`;
		const cur = byModel.get(key) ?? {
			model: r.model || "—",
			provider: r.provider || "—",
			requests: 0,
			errors: 0,
			tokens: 0,
		};
		cur.requests += r.requests;
		cur.errors += r.errors;
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

	// The three headline KPIs as the mockup's icon tiles. Values + hrefs are the
	// SAME reads as before (requests / tokens / spend) — presentation only.
	const kpis: {
		icon: MetricIconName;
		label: string;
		value: string;
		href: string;
		hint?: string;
	}[] = [
		{
			icon: "llm-calls",
			label: "LLM calls",
			value: dash ? "—" : totalRequests.toLocaleString(),
			href: `/traces?range=${rShort}`,
			hint: "Model requests — one agent run can make several. Not the trace/conversation count (see Traces).",
		},
		{
			icon: "tokens",
			label: "Tokens",
			value: dash ? "—" : fmtTokens(totalInputTokens + totalOutputTokens),
			href: "/slo",
		},
		{
			icon: "spend",
			label: "Spend (est.)",
			value: spend === null || spend === 0 ? "—" : fmtCost(spend),
			href: "/gateway",
		},
	];

	// Viz data for the request-flow row — derived from the SAME real reads above
	// (SLO rows, byModel); no extra fetch, no fabricated numbers.
	const modelHref = (m: string) =>
		m && m !== "—"
			? `/traces?model=${encodeURIComponent(m)}&range=${rShort}`
			: undefined;
	const flowModels = topModels.slice(0, 4).map((m) => ({
		id: `${m.provider}::${m.model}`,
		label: m.model,
		requests: m.requests,
		errors: m.errors,
		href: modelHref(m.model),
	}));

	// Provider health — top 4 by request volume (presentational, no new fetch).
	const topProviders = (gw?.providers ?? [])
		.slice()
		.sort((a, b) => b.requests - a.requests)
		.slice(0, 4);
	const maxProvReq = topProviders[0]?.requests ?? 0;

	return (
		<div className="space-y-5">
			{dash && <WarmingBanner />}

			{/* Header — greeting (left) + the KPI strip (top-right, per the mockup):
			    error/block pills, availability + cache-hit bars, and the single
			    page-level range control. Every value real; "—" when unreachable. */}
			<div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
				<div>
					<h1 className="t-h1">Welcome back</h1>
					<p className="mt-1.5 text-sm text-ink-3">
						Your agent fleet, at a glance.
					</p>
				</div>
				<div className="flex flex-wrap items-end gap-x-6 gap-y-4 lg:justify-end">
					<div>
						<div className="mb-1.5 text-[11.5px] text-ink-3">Error rate</div>
						<Link
							href={`/traces?status=error&range=${rShort}`}
							className="inline-flex rounded-full bg-surface-inverse px-3.5 py-1.5 text-[13.5px] font-medium tabular-nums text-ink-inverse"
						>
							{dash ? "—" : `${errorPct.toFixed(2)}%`}
						</Link>
					</div>
					<div>
						<div
							className="mb-1.5 text-[11.5px] text-ink-3"
							title="Share of pre-flight guardrail VERDICTS that blocked (denominator = verdicts, not requests)."
						>
							Block rate
						</div>
						<Link
							href="/guardrails"
							className="inline-flex rounded-full bg-accent-soft px-3.5 py-1.5 text-[13.5px] font-medium tabular-nums text-accent-ink"
						>
							{blockRatePct === null ? "—" : `${blockRatePct.toFixed(1)}%`}
						</Link>
					</div>
					<div className="w-[150px] sm:w-[190px]">
						<div className="mb-1.5 text-[11.5px] text-ink-3">
							Availability — vs {budget.targetPct.toFixed(1)}% target
						</div>
						<div className="relative h-9 overflow-hidden rounded-lg border border-line bg-surface-2">
							<div
								className="absolute inset-y-0 left-0 rounded-lg border border-line bg-surface"
								style={{ width: `${Math.min(100, budget.availabilityPct)}%` }}
							/>
							<span className="absolute inset-y-0 left-3 flex items-center text-[13.5px] font-medium tabular-nums text-ink">
								{dash ? "—" : `${budget.availabilityPct.toFixed(3)}%`}
							</span>
						</div>
					</div>
					<div className="w-[128px]">
						<div className="mb-1.5 text-[11.5px] text-ink-3">Cache hit</div>
						<div className="relative h-9 overflow-hidden rounded-lg border border-line bg-surface-2">
							<div
								className="absolute inset-y-0 left-0 rounded-lg border border-line bg-surface"
								style={{ width: `${Math.min(100, cacheHitPct ?? 0)}%` }}
							/>
							<span className="absolute inset-y-0 left-3 flex items-center text-[13.5px] font-medium tabular-nums text-ink">
								{cacheHitPct === null ? "—" : `${cacheHitPct.toFixed(1)}%`}
							</span>
						</div>
					</div>
					<RangeControl />
				</div>
			</div>

			{/* KPI cards — the three headline reals (requests / tokens / spend) as the
			    mockup's monochrome icon tiles. Same reads as before; "—" when
			    unreachable. Each tile clicks through to its detail view. */}
			<div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
				{kpis.map((k) => (
					<Link key={k.label} href={k.href} className={TILE_LINK_CLS}>
						<div className="stat-tile stat-tile--interactive flex h-full items-center gap-3.5 p-4">
							<MetricIcon name={k.icon} />
							<div className="min-w-0">
								<div className="text-[11.5px] text-ink-3" title={k.hint}>
									{k.label}
								</div>
								<div className="mt-1 t-metric text-ink">{k.value}</div>
							</div>
						</div>
					</Link>
				))}
			</div>

			{/* Section 1 — Health at a glance: Where the time goes · Traffic over time
			    (wide) · Error budget dark card. Three real signals in one equal-height
			    row — the trip split, the request volume trend, and the SLO burn. */}
			<SectionLabel>Health at a glance</SectionLabel>
			<div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-12 lg:items-stretch">
				{/* Where the time goes — the honest trip split (real p95 per component;
				    drill-through to the gateway detail). */}
				<Link href="/gateway" className={`${TILE_LINK_CLS} lg:col-span-3`}>
					<Card className="flex h-full flex-col p-4">
						<div className="mb-1 flex items-center justify-between gap-2">
							<div className="flex items-center gap-2">
								<MetricIcon name="time" size={28} />
								<h2 className="t-card-title">Where the time goes</h2>
							</div>
							<span className="text-[10px] text-ink-3">
								gateway vs upstream
							</span>
						</div>
						{latency && latency.overhead_samples > 0 ? (
							<div
								className="flex flex-1 flex-col items-center justify-center"
								title={
									gwTripPct !== null
										? "gateway ≈ N% of the trip is a ratio of two p95s measured over different span populations; percentiles are not additive, so read it as approximate."
										: undefined
								}
							>
								<ConcentricRings
									rings={[
										{
											value: usingFallback
												? `~${fmtMs(meanP95)}`
												: fmtMs(meanP95),
											label: "end-to-end",
										},
										{
											value: fmtMs(latency.provider_p95_ms),
											label: "provider",
										},
										{ value: fmtMs(latency.overhead_p95_ms), label: "gateway" },
									]}
									caption={
										gwTripPct !== null
											? `p95 · gateway ≈ ${gwTripPct}% of the trip${usingFallback ? " (approx)" : ""}`
											: "p95 · end-to-end · provider · gateway"
									}
								/>
							</div>
						) : (
							<EmptyState
								compact
								title="No latency split yet"
								description="Gateway vs provider latency appears here as requests flow."
							/>
						)}
					</Card>
				</Link>

				{/* Traffic over time — real per-hour request counts (wide). */}
				<Card className="flex h-full flex-col p-4 sm:col-span-2 lg:col-span-6">
					<div className="mb-1 flex items-center gap-2">
						<MetricIcon name="traffic" size={28} />
						<h2 className="t-card-title">
							Traffic over time — last {rLabel} · UTC
						</h2>
					</div>
					{trafficLolli.length > 0 ? (
						<div className="flex flex-1 items-center">
							<Lollipop
								points={trafficLolli}
								hrefFor={trafficHref}
								ariaLabel={`requests per bucket over the last ${rLabel}`}
							/>
						</div>
					) : (
						<EmptyState
							compact
							title="No traffic yet"
							description="Requests per bucket appear here as your agents call the gateway."
						/>
					)}
				</Card>

				{/* Error budget — the SLO burn snapshot as the mockup's dark card. Real
				    arithmetic over the captured error rate; "—" when unreachable. */}
				<div className="card-lava-top flex h-full flex-col rounded-xl bg-surface-inverse p-5 lg:col-span-3">
					<div className="flex items-center justify-between gap-3">
						<div className="flex items-center gap-2">
							<MetricIcon name="error-budget" size={28} onInverse />
							<p className="t-card-title text-ink-inverse opacity-60">
								Error budget ({rShort})
							</p>
						</div>
						<p className="text-[11px] text-ink-inverse opacity-60">
							1.0× = on pace
						</p>
					</div>
					<div className="mt-2 font-mono text-[34px] font-semibold leading-none text-accent tabular-nums">
						{dash ? "—" : fmtBurn(budget.burnRate)}
					</div>
					<p className="mt-1.5 text-[11.5px] text-ink-inverse opacity-60">
						burn rate
					</p>
					<dl className="mt-auto space-y-2 border-t border-white/10 pt-3 text-[12.5px]">
						<div className="flex items-center justify-between">
							<dt className="text-ink-inverse opacity-60">Availability</dt>
							<dd className="font-mono tabular-nums text-ink-inverse">
								{dash ? "—" : `${budget.availabilityPct.toFixed(3)}%`}
							</dd>
						</div>
						<div className="flex items-center justify-between">
							<dt className="text-ink-inverse opacity-60">Target (default)</dt>
							<dd className="font-mono tabular-nums text-ink-inverse">
								{budget.targetPct.toFixed(1)}%
							</dd>
						</div>
						<div className="flex items-center justify-between">
							<dt className="text-ink-inverse opacity-60">Budget remaining</dt>
							<dd className="font-mono tabular-nums text-ink-inverse">
								{dash ? "—" : fmtBudget(budget.budgetRemainingPct)}
							</dd>
						</div>
					</dl>
				</div>
			</div>

			{/* Section 2 — Latency, routing & safety: Latency over time (with the full
			    gateway-overhead / provider / TTFT percentile split) · Request flow
			    (Sankey) · Guardrail activity (block/fail-open real verdicts). */}
			<SectionLabel>Latency, routing &amp; safety</SectionLabel>
			<div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-12 lg:items-stretch">
				{/* Latency over time + the full gateway-overhead / provider / TTFT
				    percentile split — all real. */}
				<Card className="flex h-full flex-col p-4 sm:col-span-2 lg:col-span-4">
					<div className="mb-1 flex items-center gap-2">
						<MetricIcon name="latency" size={28} />
						<h2 className="t-card-title">
							Latency over time — last {rLabel} · UTC
						</h2>
					</div>
					{points.length > 0 ? (
						<LatencyTimeline points={points} />
					) : (
						<div className="flex flex-1 items-center">
							<EmptyState
								compact
								title="No latency data yet"
								description="Hourly percentiles appear here as requests flow through the gateway."
								className="w-full"
							/>
						</div>
					)}
					{latency && latency.overhead_samples > 0 && (
						<dl className="mt-3 grid grid-cols-[auto_1fr] items-baseline gap-x-4 gap-y-1.5 border-t border-line pt-3 text-[11px]">
							<dt className="text-ink-3">Gateway</dt>
							<dd className="text-right font-mono tabular-nums text-ink-2">
								p50 {fmtMs(latency.overhead_p50_ms)} · p95{" "}
								{fmtMs(latency.overhead_p95_ms)} · p99{" "}
								{fmtMs(latency.overhead_p99_ms)}
							</dd>
							<dt className="text-ink-3">Provider</dt>
							<dd className="text-right font-mono tabular-nums text-ink-2">
								p50 {fmtMs(latency.provider_p50_ms)} · p95{" "}
								{fmtMs(latency.provider_p95_ms)} · p99{" "}
								{fmtMs(latency.provider_p99_ms)}
							</dd>
							<dt className="text-ink-3">TTFT</dt>
							<dd className="text-right font-mono tabular-nums text-ink-2">
								{latency.ttft_samples > 0
									? `p50 ${fmtMs(latency.ttft_p50_ms)} · p95 ${fmtMs(latency.ttft_p95_ms)} · p99 ${fmtMs(latency.ttft_p99_ms)}`
									: "—"}
							</dd>
						</dl>
					)}
				</Card>

				{/* Request flow — gateway → model → honest OK/Error outcome split. */}
				<Card className="flex h-full flex-col p-4 sm:col-span-2 lg:col-span-4">
					<div className="mb-2 flex items-center justify-between gap-2">
						<div className="flex items-center gap-2">
							<MetricIcon name="request-flow" size={28} />
							<h2 className="t-card-title">Request flow</h2>
						</div>
						<span className="text-[10px] text-ink-3">
							gateway → model → outcome
						</span>
					</div>
					{flowModels.length > 0 ? (
						<div className="flex flex-1 items-center">
							<RequestFlow models={flowModels} />
						</div>
					) : (
						<EmptyState
							compact
							title="No traffic yet"
							description="The request path — gateway → model → OK/Error — appears here as your agents call the gateway."
							className="w-full"
						/>
					)}
				</Card>

				{/* Guardrail activity — real block/fail-open verdicts from the inline
				    guardrail engine (fetchGuardrailStats, already in the Promise.all). */}
				<Card className="flex h-full flex-col p-4 lg:col-span-4">
					<div className="mb-2 flex items-center justify-between gap-2">
						<div className="flex items-center gap-2">
							<MetricIcon name="guardrail" size={28} />
							<h2 className="t-card-title">Guardrail activity</h2>
						</div>
						<span className="text-[10px] text-ink-3">{rShort}</span>
					</div>
					{guardrails === null || guardrails.total_evaluations === 0 ? (
						<div className="flex flex-1 items-center">
							<EmptyState
								compact
								title="No guardrail activity yet"
								description="Block/allow verdicts appear here as requests pass the inline guardrails."
								className="w-full"
							/>
						</div>
					) : (
						<div className="flex flex-1 flex-col justify-center">
							<div className="font-mono t-metric text-accent-ink">
								{guardrails.block_rate_pct.toFixed(1)}%
							</div>
							<p className="text-[11.5px] text-ink-3">block rate</p>
							<div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-3 border-t border-line pt-3">
								<div className="flex flex-col gap-0.5">
									<span className="font-mono text-sm font-semibold tabular-nums text-ink">
										{guardrails.total_evaluations.toLocaleString()}
									</span>
									<span className="text-[10px] text-ink-3">evaluations</span>
								</div>
								<div className="flex flex-col gap-0.5">
									<span className="font-mono text-sm font-semibold tabular-nums text-ink">
										{guardrails.fail_open_rate_pct.toFixed(1)}%
									</span>
									<span className="text-[10px] text-ink-3">fail-open</span>
								</div>
								<div className="flex flex-col gap-0.5">
									<span className="font-mono text-sm font-semibold tabular-nums text-ink">
										{guardrails.blocks.toLocaleString()}
									</span>
									<span className="text-[10px] text-ink-3">blocked</span>
								</div>
								<div className="flex flex-col gap-0.5">
									<span className="font-mono text-sm font-semibold tabular-nums text-ink">
										{guardrails.fail_open_verdicts.toLocaleString()}
									</span>
									<span className="text-[10px] text-ink-3">fail-opens</span>
								</div>
							</div>
						</div>
					)}
				</Card>
			</div>

			{/* Section 3 — Models, providers & failures: Traffic by model table ·
			    Provider health (per-provider request mix + error rate) · Top failure
			    signatures table. All three read already-fetched data — no new fetch. */}
			<SectionLabel>Models, providers &amp; failures</SectionLabel>
			<div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-12 lg:items-stretch">
				{/* Traffic by model — top 5 provider/model series by request volume. */}
				<Card className="flex h-full flex-col overflow-hidden lg:col-span-4">
					<div className="flex items-center justify-between px-4 pt-3.5 pb-2">
						<div className="flex items-center gap-2">
							<MetricIcon name="model-breakdown" size={28} />
							<h2 className="t-card-title">Traffic by model</h2>
						</div>
						<Link
							href="/slo"
							className="rounded text-[12px] font-medium text-accent-ink hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
						>
							View all →
						</Link>
					</div>
					{topModels.length > 0 ? (
						<table className="w-full text-sm">
							<thead className="border-b border-line">
								<tr>
									<th className="px-4 py-2 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
										Model
									</th>
									<th className="px-4 py-2 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
										Requests
									</th>
									<th className="px-4 py-2 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
										Tokens
									</th>
								</tr>
							</thead>
							<tbody className="divide-y divide-line">
								{topModels.map((m) => (
									<tr
										key={`${m.provider}::${m.model}`}
										className="transition-colors hover:bg-surface-2/40"
									>
										<td className="px-4 py-2">
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
													className="h-full rounded-full bar-lava"
													style={{
														width: `${maxModelReq > 0 ? (m.requests / maxModelReq) * 100 : 0}%`,
													}}
												/>
											</div>
										</td>
										<td className="px-4 py-2 text-right font-mono text-xs tabular-nums text-ink">
											{m.requests.toLocaleString()}
										</td>
										<td className="px-4 py-2 text-right font-mono text-xs tabular-nums text-ink-2">
											{fmtTokens(m.tokens)}
										</td>
									</tr>
								))}
							</tbody>
						</table>
					) : (
						<div className="flex flex-1 items-center">
							<EmptyState
								compact
								title="No traffic yet"
								description="Per-model request volume appears here once your agents call the gateway."
								className="w-full"
								action={
									<Link
										href="/settings/providers"
										className="rounded text-[13px] font-medium text-accent-ink hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
									>
										Connect a provider →
									</Link>
								}
							/>
						</div>
					)}
				</Card>

				{/* Provider health — top 4 providers by request volume with error rate
				    and a share bar. Derived inline from fetchGatewayStats (already
				    fetched); no extra read, no fabricated numbers. */}
				<Card className="flex h-full flex-col p-4 lg:col-span-4">
					<div className="mb-2 flex items-center justify-between gap-2">
						<div className="flex items-center gap-2">
							<MetricIcon name="provider" size={28} />
							<h2 className="t-card-title">Provider health</h2>
						</div>
						<span className="text-[10px] text-ink-3">req · err</span>
					</div>
					{topProviders.length === 0 ? (
						<div className="flex flex-1 items-center">
							<EmptyState
								compact
								title="No provider traffic yet"
								description="Per-provider request volume and error rate appear here."
								className="w-full"
							/>
						</div>
					) : (
						<div className="flex flex-1 flex-col justify-center space-y-2">
							{topProviders.map((p) => (
								<div key={p.provider}>
									<div className="flex items-baseline gap-2">
										<span className="min-w-0 flex-1 truncate font-mono text-xs text-ink">
											{p.provider}
										</span>
										<span className="font-mono text-xs tabular-nums text-ink">
											{fmtTokens(p.requests)}
										</span>
										<span className="font-mono text-xs tabular-nums text-ink-3">
											{p.error_rate_pct.toFixed(1)}%
										</span>
									</div>
									<div className="mt-1 h-1 overflow-hidden rounded-full bg-surface-2">
										<div
											className="h-full rounded-full bar-lava"
											style={{
												width: `${maxProvReq > 0 ? (p.requests / maxProvReq) * 100 : 0}%`,
											}}
										/>
									</div>
								</div>
							))}
						</div>
					)}
				</Card>

				{/* Top failure signatures — the differentiator surface. Rows click
				    through to the full Signatures view. */}
				<Card className="flex h-full flex-col overflow-hidden lg:col-span-4">
					<div className="flex items-center justify-between px-4 pt-3.5 pb-2">
						<div className="flex items-center gap-2">
							<MetricIcon name="failure-signatures" size={28} />
							<h2 className="t-card-title">Top failure signatures</h2>
						</div>
						<Link
							href="/signatures"
							className="rounded text-[12px] font-medium text-accent-ink hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
						>
							View all →
						</Link>
					</div>
					{topSigs.length > 0 ? (
						<table className="w-full text-sm">
							<thead className="border-b border-line">
								<tr>
									<th className="px-4 py-2 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
										Signature
									</th>
									<th className="px-4 py-2 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
										Hits ({rShort})
									</th>
									<th className="px-4 py-2 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
										Action
									</th>
								</tr>
							</thead>
							<tbody className="divide-y divide-line">
								{topSigs.map((s) => (
									<tr
										key={s.signature_id}
										className="transition-colors hover:bg-surface-2/40"
									>
										<td className="px-4 py-2">
											<Link
												href={`/traces?signature_id=${encodeURIComponent(s.signature_id)}&range=${rShort}`}
												className="rounded font-mono text-xs text-ink hover:text-accent-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
												title={`View ${s.signature_id} traces`}
											>
												{s.signature_id}
											</Link>
										</td>
										<td className="px-4 py-2 text-right font-mono text-xs tabular-nums text-ink">
											{s.your_hits.toLocaleString()}
										</td>
										<td className="px-4 py-2 text-right">
											<Badge tone={s.action === "blocking" ? "danger" : "warn"}>
												{s.action === "blocking" ? "blocking" : "flag-only"}
											</Badge>
										</td>
									</tr>
								))}
							</tbody>
						</table>
					) : (
						<div className="flex flex-1 items-center">
							<EmptyState
								compact
								title="No failure signatures matched yet"
								description="A known agent-failure pattern (tool-schema violation, definition drift) seen in your traces surfaces here."
								className="w-full"
								action={
									<Link
										href="/signatures"
										className="rounded text-[13px] font-medium text-accent-ink hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
									>
										About failure signatures →
									</Link>
								}
							/>
						</div>
					)}
				</Card>
			</div>

			{/* Tool usage — top tools by call volume with error rate + p95 (full
			    width; the one dashboard surface for agent tool health). */}
			<section className="space-y-2">
				<div className="flex items-center justify-between">
					<div className="flex items-center gap-2">
						<MetricIcon name="tool-usage" size={28} />
						<h2 className="t-card-title">Tool usage ({rShort})</h2>
					</div>
					<Link
						href="/traces"
						className="rounded text-[13px] font-medium text-accent-ink hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
					>
						View traces →
					</Link>
				</div>
				{toolAnalyticsWarming ? (
					<EmptyState
						compact
						title="Warming up"
						description="Tool usage data is unavailable while the gateway is warming."
					/>
				) : totalToolCalls === 0 ? (
					<EmptyState
						compact
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
							<thead className="border-b border-line">
								<tr>
									<th className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
										Tool
									</th>
									<th className="px-4 py-2.5 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
										Calls
									</th>
									<th className="px-4 py-2.5 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
										Error rate
									</th>
									<th className="px-4 py-2.5 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
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
											className="transition-colors hover:bg-surface-2/40"
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
													t.errors > 0 ? "text-danger-ink" : "text-ink-3"
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
		<div className="px-2 py-3 sm:px-4 sm:py-4">
			{/* No `key={range}` — keying on range REMOUNTS the boundary on every
			    range change and flashes the fallback (the "feels slow" reload).
			    Without it, the RangeControl's useTransition keeps the current view
			    on screen and swaps in the new window's data when it arrives. The
			    fallback now shows only on the true first load. */}
			<Suspense
				fallback={<p className="py-8 text-sm text-ink-3">Loading dashboard…</p>}
			>
				<DashboardData range={range} />
			</Suspense>
		</div>
	);
}

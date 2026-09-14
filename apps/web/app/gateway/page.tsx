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
 *
 * ── P1 DESIGN PASS (2026-08-22) — PRESENTATION ONLY ─────────────────────────
 * Every metric, value, unit, window and API call on this page is byte-identical
 * to what it was before the pass; what changed is weight and grammar.
 *
 *  · SECTION RHYTHM. The page was one flat `space-y-3` list of eight unlabelled
 *    blocks, so a metric strip, a table and a code panel all sat the same
 *    distance apart and nothing said which belonged with which. It is now four
 *    named sections at `space-y-8` (the P0.15 section gap) with `SectionLabel`
 *    eyebrows, matching `app/dashboard/page.tsx`.
 *  · WEIGHT. The four traffic/health metrics lead as LIFTED tiles; the four
 *    router-event counters are one FLAT hairline lattice. They were eight
 *    identical floating tiles, which said "these eight facts are equally
 *    important" about a volume reading and a since-restart 429 counter.
 *  · THE TABLE is the shared `Table` primitive rather than the ninth hand-rolled
 *    `<thead>` treatment in the app.
 *
 * The Circuit column now renders the SAME `circuit_state` field through the same
 * `circuit.ts` mapping for every state instead of a badge for two states and bare
 * mono text for the third — no health state is computed here, and none is
 * inferred from any other field.
 */

import { RangeControl } from "@/components/RangeControl";
import { WarmingBanner } from "@/components/empty-states/WarmingBanner";
import { WindowNotice } from "@/components/metrics/WindowNotice";
import type { CostBreakdown } from "@/lib/gateway-ops";
import {
	fetchCostBreakdownFor,
	fetchGatewayStatsFor,
} from "@/lib/metrics/fetch";
import { fmtCount, fmtDurationMs, fmtPercent } from "@/lib/metrics/format";
import { hintOf } from "@/lib/metrics/hint";
import { METRICS } from "@/lib/metrics/registry";
import {
	type TimeRange,
	parseTimeRange,
	withWindow,
} from "@/lib/metrics/time-range";
import {
	Badge,
	Card,
	EmptyState,
	Gauge,
	MetricIcon,
	type MetricIconName,
	Skeleton,
	StatCard,
	StatGrid,
	TBody,
	TD,
	TH,
	THead,
	TR,
	Table,
	cn,
} from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";
import { type ReactNode, Suspense } from "react";
import { SectionLabel } from "./SectionLabel";
import { SpendAttribution } from "./SpendAttribution";
import { TryItCurl } from "./TryItCurl";
import { circuitLabel, circuitTone } from "./circuit";

export const metadata: Metadata = { title: "Gateway — Tracelane" };
export const dynamic = "force-dynamic";

// ONE formatter per kind — the registry's. The tile printed `0.0%` where the
// table beside it printed `0%`, and `1,234 ms` where every other surface prints
// `1.23s` (DSH-11 §3.1). Percentages carry their sample so precision follows n.
const ms = fmtDurationMs;
const pct = (v: number, n?: number): string =>
	fmtPercent(v, { n, floor: 100 }).text;

/**
 * Breaker state → a QUIET status mark: a 6px dot plus the word.
 *
 * One rendering for all three states, where there used to be two. `open` and
 * `half_open` got a `<Badge>` and `closed` got bare `font-mono` text — so the
 * column changed shape depending on its value, and the healthy case was styled as
 * a technical value (mono is for latencies, ids and percentages; "Closed" is a
 * word). A status that looks like a different kind of thing when it is fine is
 * harder to scan, not easier.
 *
 * The tone comes from `circuitTone` on the EXISTING `circuit_state` field and
 * nothing else — no health state is computed from error rate, failovers or
 * latency. Colour is never alone: the label is always rendered beside the dot.
 */
const CIRCUIT_DOT: Record<ReturnType<typeof circuitTone>, string> = {
	ok: "bg-ok",
	warn: "bg-warn",
	danger: "bg-danger",
};
/** Healthy is INK, not green text: the dot carries the state and a whole column
 *  of green words would spend the system's most rationed colour on "normal". */
const CIRCUIT_TEXT: Record<ReturnType<typeof circuitTone>, string> = {
	ok: "text-ink-2",
	warn: "text-warn-ink",
	danger: "text-danger-ink",
};

function CircuitStatus({ state }: { state: string }) {
	const tone = circuitTone(state);
	return (
		<span className="inline-flex items-center gap-1.5 whitespace-nowrap text-xs">
			<span
				aria-hidden="true"
				className={cn("h-1.5 w-1.5 shrink-0 rounded-full", CIRCUIT_DOT[tone])}
			/>
			<span className={CIRCUIT_TEXT[tone]}>{circuitLabel(state)}</span>
		</span>
	);
}

async function GatewayData({
	range,
	by,
}: {
	range: TimeRange;
	by: CostBreakdown["by"];
}) {
	// Both reads in flight together, for ONE window, through lib/metrics — the
	// spend panel must not serialize behind router health.
	const [stats, costs] = await Promise.all([
		fetchGatewayStatsFor(range),
		fetchCostBreakdownFor(range, by),
	]);
	const href = (path: string, extra?: Record<string, string | undefined>) =>
		withWindow(path, range, extra);

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
	//
	// `refusing` is part of the condition because a tenant whose requests are all being
	// REFUSED also has provider_count 0 — and for them the first-request tutorial is
	// actively misleading. It told them to "Send one request to see it appear" while the
	// gateway was answering every request with a budget 429, and the two counters that
	// explain why (`Rate-limited` / `Budget-exceeded (since start)`) live in the Router
	// events section BELOW this early return, so they never rendered. The user was shown
	// a "you have not started yet" screen during an outage of their own quota.
	//
	// These counters are process-lifetime, not windowed, so they are only a signal that
	// refusal is happening — which is exactly when the tutorial must not be the answer.
	const refusing =
		stats.budget_exceeded_since_start > 0 || stats.rate_limited_since_start > 0;
	if (stats.provider_count === 0 && !refusing) {
		return (
			<div className="space-y-8">
				<EmptyState
					title={`No gateway requests — ${range.label}`}
					description="Point your agents at the gateway — per-provider request volume, latency, error rate, and cache-hit rate will surface here. Send one request to see it appear:"
					action={
						<Link
							href="/settings/providers"
							className="text-sm font-medium text-action-ink hover:underline"
						>
							Manage providers →
						</Link>
					}
				/>
				<TryItCurl />
			</div>
		);
	}

	/*
	 * ROUTER EVENTS — the SECONDARY group (P0.4).
	 *
	 * Same four counters, same values, same copy. They are a table of cells rather
	 * than four `<StatCard>`s because a `StatCard` is a lifted tile, and eight
	 * lifted tiles above the fold made a since-restart 429 counter carry the same
	 * visual weight as the window's request volume. One flat surface with hairline
	 * separators reads as "a group of related counters", which is what they are.
	 *
	 * `mono` is per-row on purpose: a count is a technical value, "All closed" is
	 * a word, and the type rule is that monospace is for values only.
	 */
	const routerEvents: {
		icon: MetricIconName;
		label: string;
		hint?: string;
		value: string;
		/** Counts are mono; the breaker aggregate's word-value is not. */
		mono: boolean;
		sub: ReactNode;
		href?: string;
	}[] = [
		{
			icon: "request-flow",
			label: `${METRICS.failovers.label} (${range.short})`,
			hint: hintOf(METRICS.failovers),
			value: fmtCount(stats.total_failovers),
			mono: true,
			sub:
				stats.total_failovers > 0 ? (
					<span className="text-ink-3">
						served by a backup provider · view traces
					</span>
				) : (
					<span className="text-ink-3">
						No failovers needed — add a second provider in{" "}
						<Link
							href="/settings/providers"
							className="font-medium text-action-ink hover:underline"
						>
							LLM Providers
						</Link>{" "}
						to enable automatic failover.
					</span>
				),
			// Only linked when there is something to drill into — and NOT linked in
			// the zero case, whose sub-line already contains its own link (a link
			// inside a link is invalid markup and unreachable by keyboard).
			href:
				stats.total_failovers > 0
					? href("/traces", { failover: "true" })
					: undefined,
		},
		{
			icon: "traffic",
			label: METRICS.rate_limited_since_start.label,
			hint: hintOf(METRICS.rate_limited_since_start),
			value: fmtCount(stats.rate_limited_since_start),
			mono: true,
			sub: <span className="text-ink-3">429s since gateway start</span>,
		},
		{
			icon: "spend",
			label: METRICS.budget_exceeded_since_start.label,
			hint: hintOf(METRICS.budget_exceeded_since_start),
			value: fmtCount(stats.budget_exceeded_since_start),
			mono: true,
			sub: <span className="text-ink-3">budget 429s since gateway start</span>,
		},
		{
			icon: "error-budget",
			label: METRICS.open_breakers.label,
			hint: hintOf(METRICS.open_breakers),
			value:
				stats.open_breakers === 0
					? "All closed"
					: `${stats.open_breakers} open`,
			mono: false,
			// The aggregate reads as a STATE now, which is the whole of "make it
			// clearer": the tone sits on the sub-line (P0.6 keeps the headline
			// graphite) and the words carry it, so it is never colour alone. The
			// value string and both sub strings are unchanged — only their tone is
			// new, and `open_breakers` is the same field it always read.
			sub:
				stats.open_breakers === 0 ? (
					<span className="text-ok-ink">all upstreams passing</span>
				) : (
					<span className="text-danger-ink">
						upstream(s) tripped — failing fast
					</span>
				),
		},
	];

	return (
		<div className="space-y-8">
			{/* ── 1 · TRAFFIC & ROUTING — the lead group ──────────────────────────
			    Traffic → errors → cache → provider count, in that order, because
			    that is the order the questions arrive in. PRIMARY weight: four
			    lifted tiles. Every value is unchanged. */}
			<section aria-label="Traffic and routing" className="space-y-3">
				<SectionLabel>Traffic &amp; routing</SectionLabel>
				<StatGrid cols={4}>
					{/* "Requests routed" / "Failed" — NOT "LLM calls" / "Error rate". Those two
					    labels belong to the hourly SLO view on /dashboard and /slo, which
					    counts a redelivered span twice; this tile counts deduplicated spans.
					    Two definitions, two labels — the registry rule (DSH-11 §3c). */}
					<Link
						href={href("/traces")}
						className="block h-full rounded-[var(--radius-card)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
					>
						<StatCard
							icon="llm-calls"
							label={METRICS.requests_routed.label}
							hint={hintOf(METRICS.requests_routed)}
							value={fmtCount(stats.total_requests)}
							sub={`across ${stats.provider_count} provider${stats.provider_count === 1 ? "" : "s"} · ${range.short} · view traces`}
							interactive
						/>
					</Link>

					{stats.total_errors > 0 ? (
						<Link
							href={href("/traces", { status: "error" })}
							className="block h-full rounded-[var(--radius-card)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
						>
							<StatCard
								icon="failure-signatures"
								label={METRICS.failed_routed.label}
								hint={hintOf(METRICS.failed_routed)}
								value={pct(stats.error_rate_pct, stats.total_requests)}
								sub={`${fmtCount(stats.total_errors)} of ${fmtCount(stats.total_requests)} · view them`}
								sample={{ n: stats.total_requests, floor: 100 }}
								interactive
							/>
						</Link>
					) : (
						<StatCard
							icon="failure-signatures"
							label={METRICS.failed_routed.label}
							hint={hintOf(METRICS.failed_routed)}
							value={
								stats.total_requests > 0 ? pct(0, stats.total_requests) : "—"
							}
							sub={
								stats.total_requests > 0
									? "no errors in window"
									: METRICS.failed_routed.zeroCopy
							}
							sample={
								stats.total_requests > 0
									? { n: stats.total_requests, floor: 100 }
									: undefined
							}
						/>
					)}

					{/* The prompt-cache tile is a hand-built `Card` rather than a
					    `StatCard` because its value is a Gauge, not a line of type —
					    so it has to reproduce the tile's grammar exactly or it reads
					    as a foreign object in the row. Verified against `StatCard`
					    after the P1 pass, property by property: `p-5` (was `p-4`),
					    `MetricIcon size={18}` (was 26), `mb-2 … gap-2` label row, and
					    `.t-metric-label` for the label. The label role is the one that
					    matters most and it is unchanged — a `.t-card-title` here would
					    make one of four tiles in the same row say "Prompt-cache hit"
					    in sentence case while its neighbours say "LLM CALLS", "ERROR
					    RATE" and "PROVIDERS ACTIVE". Same shape, same row, two
					    grammars. */}
					<Card
						className="flex h-full flex-col p-5"
						title={
							stats.cache_hit_rate_pct > 0
								? "Requests that read a provider prompt cache."
								: "No cached reads yet — enable provider prompt caching (Anthropic cache_control; OpenAI is automatic ≥1024 tokens) to cut cost and latency."
						}
					>
						<div className="mb-2 flex items-center gap-2">
							<MetricIcon name="time" size={18} />
							<p className="t-metric-label">Prompt-cache hit</p>
						</div>
						<div className="flex flex-1 items-center justify-center">
							<Gauge
								value={stats.cache_hit_rate_pct}
								display={pct(stats.cache_hit_rate_pct, stats.total_requests)}
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
						label={METRICS.providers_active.label}
						hint={hintOf(METRICS.providers_active)}
						value={String(stats.provider_count)}
						sub={range.label}
					/>
				</StatGrid>
			</section>

			{/* ── 2 · PROVIDER HEALTH ─────────────────────────────────────────────
			    The same ten columns and the same ten values, on the shared table
			    system. A quiet (flat) card: a table is a structured surface, not a
			    floating panel, and it sits directly under the lifted metric row it
			    explains. */}
			<section aria-label="Provider health" className="space-y-3">
				<SectionLabel>Provider health</SectionLabel>
				<Card quiet className="overflow-hidden">
					{/* `-mt-px` slides the header band's own top hairline UNDER the
					    card's border, where `overflow-hidden` clips it. Without it the
					    card edge and `THead`'s `border-y` stack into a 2px rule along
					    the top while every other edge stays 1px. Same mechanism the
					    dashboard's KPI lattice uses for its outermost rules. */}
					<div className="-mt-px">
						<Table>
							<THead>
								<TR>
									<TH>Provider</TH>
									<TH numeric>Requests</TH>
									<TH numeric>Error rate</TH>
									<TH
										numeric
										title="End-to-end p50 INCLUDING the provider's own generation time. It is dominated by how many tokens the model decoded, so it is not a like-for-like speed ranking between providers — see Out tok/req on the SLOs page. The column that is ours is Gateway ovh."
									>
										p50
									</TH>
									<TH numeric>p95</TH>
									<TH numeric>p99</TH>
									<TH
										numeric
										// Primary ink against the neighbours' `--ink-2`: this is
										// the differentiator column, and the emphasis is the
										// point of putting it beside the end-to-end percentiles.
										// It read `text-action-ink` before, which named an
										// AFFORDANCE colour for a column that is not clickable;
										// the two tokens resolve to the same ink, so this is a
										// naming fix, not a visual change.
										className="text-ink"
										title="Gateway overhead p95 — the time Tracelane adds per request, EXCLUDING the upstream provider round-trip. Compare with the end-to-end p95 to the left: our slice is tiny."
									>
										Gateway ovh
									</TH>
									<TH numeric>Cache hit</TH>
									<TH numeric>Failover</TH>
									<TH
										className="text-right"
										title="Upstream breaker state — process-wide shared-infra health, not tenant-specific."
									>
										Circuit
									</TH>
								</TR>
							</THead>
							<TBody>
								{stats.providers.map((p) => (
									<TR key={p.provider}>
										{/* A provider id is a technical identifier in a left
										    column — mono, not right-aligned. */}
										<TD mono>{p.provider}</TD>
										<TD numeric>{fmtCount(p.requests)}</TD>
										<TD numeric>
											{p.errors > 0 ? (
												<Badge tone="danger">
													{pct(p.error_rate_pct, p.requests)}
												</Badge>
											) : (
												<span className="text-ok-ink">
													{pct(0, p.requests)}
												</span>
											)}
										</TD>
										<TD numeric muted>
											{ms(p.p50_ms)}
										</TD>
										<TD numeric muted>
											{ms(p.p95_ms)}
										</TD>
										<TD numeric muted>
											{ms(p.p99_ms)}
										</TD>
										<TD
											numeric
											title="Gateway overhead p95 — Tracelane's own slice, excluding upstream generation"
										>
											{p.overhead_p95_ms > 0 ? ms(p.overhead_p95_ms) : "—"}
										</TD>
										<TD numeric muted>
											{pct(p.cache_hit_rate_pct, p.requests)}
										</TD>
										<TD numeric muted>
											{p.failovers > 0 ? (
												<Badge tone="warn">{fmtCount(p.failovers)}</Badge>
											) : (
												<span className="text-ink-3">—</span>
											)}
										</TD>
										<TD className="text-right">
											<CircuitStatus state={p.circuit_state} />
										</TD>
									</TR>
								))}
							</TBody>
						</Table>
					</div>
				</Card>
			</section>

			{/* ── 3 · SPEND ATTRIBUTION ───────────────────────────────────────────
			    GWY-43: where the money went. Sits above Router events because "what
			    did this cost" is the question a platform team opens this page with,
			    and cost was previously only a single tenant-wide total. */}
			<SpendAttribution
				data={costs}
				hrefFor={(v) => href("/gateway", { by: v })}
				by={by}
			/>

			{/* ── 4 · ROUTER EVENTS — the secondary group ─────────────────────────
			    Resilience + shed-load signals. Failover is window-derived;
			    rate-limit/quota are process-lifetime counters, which is why the
			    explanation below the label stays. */}
			<section aria-label="Router events" className="space-y-3">
				<SectionLabel>Router events</SectionLabel>
				<p className="max-w-3xl text-xs text-ink-3">
					Failover activations are counted over {range.label}. Rate-limit and
					quota rejects are live counters since the gateway last started (they
					carry no trace, so they reset on redeploy).
				</p>
				{/*
				 * THE SEPARATOR MECHANISM: every cell draws its own top and left
				 * hairline and the grid is pulled up and left by 1px, so the outermost
				 * rules slide under the card's border and `overflow-hidden` clips them.
				 * That is what keeps the lattice correct at 1-up, 2-up and 4-up with no
				 * orphan rule — which neither `divide-x` (which strands a left border
				 * at the start of rows 2+) nor a `gap-px` background trick (which
				 * paints the empty tail of the last row) manages.
				 */}
				<div className="surface-card surface-card--quiet overflow-hidden border border-line">
					<div className="-ml-px -mt-px grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
						{routerEvents.map((e) => {
							const body = (
								<>
									<span className="flex items-center gap-2">
										<MetricIcon name={e.icon} size={18} />
										<span className="t-metric-label flex items-center gap-1.5">
											{e.label}
											{e.hint && (
												<span
													aria-label={e.hint}
													title={e.hint}
													className="grid h-3.5 w-3.5 shrink-0 cursor-help place-items-center rounded-full border border-line-2 text-2xs leading-none text-ink-3"
												>
													?
												</span>
											)}
										</span>
									</span>
									{/* Graphite headline (P0.6) — the semantic tone lives in
									    the sub-line, never in the figure. */}
									<span
										className={cn("t-metric text-ink", e.mono && "font-mono")}
									>
										{e.value}
									</span>
									<span className="text-2xs">{e.sub}</span>
								</>
							);
							const cell =
								"flex flex-col gap-2 border-l border-t border-line px-5 py-4";
							return e.href ? (
								<Link
									key={e.label}
									href={e.href}
									className={cn(
										cell,
										"transition-colors hover:bg-surface-hover focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-focus-ring",
									)}
								>
									{body}
								</Link>
							) : (
								<div key={e.label} className={cell}>
									{body}
								</div>
							);
						})}
					</div>
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
	searchParams: Promise<{
		range?: string;
		since?: string;
		until?: string;
		by?: string;
	}>;
}) {
	const sp = await searchParams;
	const byRaw = sp.by;
	const range = parseTimeRange(sp, { defaultPreset: "24h", nowMs: Date.now() });
	// Fail CLOSED on an unknown dimension rather than passing it through: the
	// gateway rejects it with a 400, and a page that renders an error banner for
	// a mistyped query string is worse than one that shows the default view.
	const by: CostBreakdown["by"] =
		byRaw === "model" || byRaw === "provider" ? byRaw : "key";
	return (
		// The dashboard's responsive page frame, to the utility. The gutter ramps
		// with the viewport instead of pinning one value, and `space-y-8` is the
		// P0.15 section gap — the header used to sit `mb-4` from a `space-y-3`
		// stack, so the page title was closer to the first metric row than two
		// unrelated sections were to each other.
		<div className="space-y-8 px-1 py-2 sm:px-2 sm:py-4 lg:px-3">
			{/* OUTSIDE the Suspense boundary on purpose: nothing here reads the
			    gateway, so the page identifies itself and the range control becomes
			    clickable while the data is still in flight. */}
			<header className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
				<div className="max-w-2xl">
					<h1 className="t-h1">Gateway</h1>
					<p className="mt-2 text-sm text-ink-2">
						Per-provider routing health — volume, errors, failover and breaker
						state. Latency SLOs live on the{" "}
						<Link
							href="/slo"
							className="font-medium text-action-ink hover:underline"
						>
							SLOs page
						</Link>{" "}
						— {range.label}.
					</p>
				</div>
				<RangeControl />
			</header>
			<WindowNotice range={range} />
			<Suspense
				fallback={
					<div className="space-y-8">
						{/* `h-28` ≈ the real tile: `p-5` twice, an 11px label row, the
						    28px metric and its sub-line. It was `h-24`, a whole ramp step
						    short, so the metric row grew when the data landed. */}
						<StatGrid cols={4}>
							{[0, 1, 2, 3].map((i) => (
								<Skeleton key={i} className="h-28" />
							))}
						</StatGrid>
						<Skeleton className="h-64" />
					</div>
				}
			>
				<GatewayData range={range} by={by} />
			</Suspense>
		</div>
	);
}

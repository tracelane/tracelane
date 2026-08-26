/**
 * Dashboard — the overview-first landing surface (§1). New users and
 * returning users land here (not in raw trace rows); it answers "is my agent
 * fleet healthy right now?" in one screen before anyone drills into a trace.
 *
 * Every card is a REAL gateway read — there are no fabricated numbers. When the
 * gateway is unreachable the whole surface degrades to the warming state; when
 * it is reachable but empty each card shows an honest zero. Cards click through
 * to the filtered detail view (§1: "click a card → filters the
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

import {
	SLO_TARGET_AVAILABILITY,
	availabilityTargetForPlanKey,
	computeSloBudget,
} from "@/app/slo/budget";
import {
	buildTrafficPoints,
	chartWindow,
	latencyPointsFromTimeseries,
} from "@/app/slo/latency";
import type { SloRow, SloSummary, SloTimePoint } from "@/app/slo/types";
import { RangeControl } from "@/components/RangeControl";
import { WarmingBanner } from "@/components/empty-states/WarmingBanner";
import { db } from "@/db";
import { tenants } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { PLAN_TO_LOOKUP_KEY, type Plan } from "@/lib/entitlements";
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
	Gauge,
	LatencyTimeline,
	Lollipop,
	MetricIcon,
	type MetricIconName,
	ModelDonut,
	RequestFlow,
	SparkBars,
	TimeRuler,
} from "@tracelanedev/ui";
import { eq } from "drizzle-orm";
import type { Metadata } from "next";
import Link from "next/link";
import { type ReactNode, Suspense } from "react";

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

/** Focus ring shared by every click-through card wrapper.
 *
 * The radius is NOT a taste call — it must equal `--radius-card`, or the focus
 * ring traces a different curve from the thing it is outlining. It used to say
 * `rounded-lg`, which was correct only while cards were 8px; P0.5 moved them to
 * the 16–20px band, so this reads the token directly and can no longer drift. */
const TILE_LINK_CLS =
	"block rounded-[var(--radius-card)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring";

/** Section divider label (P0.8) — the eyebrow type plus a trailing hairline rule.
 *  The type itself lives in `.t-eyebrow` (12px / 600 / 0.10em / --ink-2), so the
 *  section grammar is tuned in tokens.css rather than at nine call sites. */
function SectionLabel({ children }: { children: ReactNode }) {
	return (
		<div className="flex items-center gap-3">
			<span className="t-eyebrow">{children}</span>
			<span className="h-px flex-1 bg-line" />
		</div>
	);
}

/**
 * The shared card header. Icon chip · title · optional right-hand meta or link.
 *
 * WHY IT IS A COMPONENT NOW. This header was hand-rolled nine times in this file
 * with four different paddings, two different icon sizes and two different
 * heading sizes, which is most of why the nine cards read as nine unrelated
 * panels (P0.4). One component, one grammar.
 *
 * The icon chip is 20px, down from 28px: `.t-card-title` is 13px sentence case
 * now, and a 28px disc beside 13px type makes the CHIP the header and the title
 * an afterthought.
 */
function CardHead({
	icon,
	title,
	meta,
	action,
}: {
	icon: MetricIconName;
	title: string;
	/** Quiet right-hand qualifier ("gateway vs upstream", "24h"). */
	meta?: string;
	/** Right-hand drill-through. Rendered instead of `meta` when both are given. */
	action?: { href: string; label: string };
}) {
	return (
		<div className="mb-4 flex items-center justify-between gap-3">
			<div className="flex min-w-0 items-center gap-2.5">
				<MetricIcon name={icon} size={20} />
				{/* NOT `truncate`. It was, and "Where the time goes" rendered as
				    "Where the ti…" on a 3-column card while the optional `meta` beside
				    it kept its full width — the title, which is the one thing that
				    names the card, lost to its own qualifier. The title now wraps if it
				    must, and `meta` is what gives way first (below `xl`). */}
				<h2 className="t-card-title">{title}</h2>
			</div>
			{action ? (
				<Link
					href={action.href}
					className="shrink-0 rounded text-xs font-medium text-ink-2 transition-colors hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
				>
					{action.label} <span aria-hidden="true">→</span>
				</Link>
			) : meta ? (
				<span className="hidden shrink-0 text-2xs text-ink-3 xl:inline">
					{meta}
				</span>
			) : null}
		</div>
	);
}

/**
 * A GHOST placeholder for a chart that has no data yet (P0.9: "where
 * appropriate, include a very subtle ghost/placeholder visualization").
 *
 * THE BARS ARE ALL THE SAME HEIGHT, AND THAT IS THE WHOLE DESIGN. A varying
 * silhouette would be a shape a reader can interpret — a trend, a spike, a
 * quiet night — drawn from numbers that do not exist, which is the "do not
 * fabricate data" line in a product whose entire claim is full-fidelity
 * capture. A uniform comb is structurally incapable of implying a trend: it
 * says "a chart goes here" and nothing else.
 *
 * `aria-hidden` because it carries no information; the empty state's own words
 * are the accessible content. The OPACITY is not set here — `EmptyState`'s ghost
 * slot wraps it at `opacity-10` and positions it absolutely so it adds no height.
 * Setting it in both places would multiply to ~0.007 and render nothing at all.
 */
/** The ghost's 24 fixed slot positions. A module constant, not
 *  `Array.from({length:24},(_,i)=>…)` inline: the array index IS the identity of a
 *  fixed-geometry placeholder rect (nothing reorders, nothing is inserted), but an
 *  index-as-key is indistinguishable from the bug that rule exists to catch, so the
 *  slot number is made a real value instead of suppressing the lint. */
const GHOST_SLOTS = Array.from({ length: 24 }, (_, i) => i);

/**
 * The ghost, anchored to the FLOOR of the card.
 *
 * `EmptyState` renders its ghost slot into an `absolute inset-0` box that CENTRES
 * its child, and centring put the comb directly behind the two lines of
 * explanatory copy — on the render the description read as text printed over a
 * barcode. A chart's placeholder belongs where a chart's baseline would be, so
 * this pushes it to the bottom: the copy sits in clear space and the shape still
 * says "a chart goes here".
 */
function GhostFloor() {
	return (
		<span className="flex h-full w-full items-end">
			<GhostBars />
		</span>
	);
}

function GhostBars() {
	return (
		<svg
			viewBox="0 0 120 28"
			preserveAspectRatio="none"
			aria-hidden="true"
			className="h-14 w-full text-chart-primary"
		>
			<title>Placeholder</title>
			{GHOST_SLOTS.map((slot) => (
				<rect
					key={slot}
					x={slot * 5}
					y={6}
					width={3}
					height={22}
					rx={1}
					fill="currentColor"
				/>
			))}
		</svg>
	);
}

/**
 * The in-card empty state (P0.9), in the shape the brief specifies: a calm
 * title, one sentence explaining what will make the data appear, and a REAL
 * link to somewhere that exists.
 *
 * IT IS A THIN WRAPPER OVER THE SHARED `EmptyState`, not a second empty state.
 * All it adds is the `{href,label}` action shape — nine call sites on this page
 * want the same styled drill-through link, and hand-building it nine times is
 * how nine slightly different links happen. The borderless treatment, the ghost
 * slot and the copy grammar all stay in the primitive.
 *
 * `flex-1` is what stops an empty card from collapsing to a different height
 * than its populated neighbour in the same `items-stretch` row.
 */
function CardEmpty({
	title,
	description,
	action,
	ghost,
}: {
	title: string;
	description: string;
	action?: { href: string; label: string };
	ghost?: ReactNode;
}) {
	return (
		<EmptyState
			compact
			className="flex-1"
			ghost={ghost}
			title={title}
			description={description}
			action={
				action ? (
					<Link
						href={action.href}
						className="rounded text-xs font-medium text-ink transition-colors hover:text-ink-2 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
					>
						{action.label} <span aria-hidden="true">→</span>
					</Link>
				) : undefined
			}
		/>
	);
}

/**
 * The tenant's contracted availability target, read from `tenants.plan`.
 *
 * Both this page and /slo previously measured EVERY tenant against the 99.9% default
 * while the alert engine used the plan's real target — so the two surfaces disagreed
 * about breach for Team (99%) and Enterprise (99.95%) tenants. One indexed lookup by
 * `workosOrgId`, the same read /prompts and /plans already do.
 *
 * Falls back to the 99.9% default when there is no tenant row: an unseeded tenant must
 * not be measured against a target we cannot substantiate.
 */
async function availabilityTarget(): Promise<number> {
	try {
		const session = await requireSession();
		const [row] = await db
			.select({ plan: tenants.plan })
			.from(tenants)
			.where(eq(tenants.workosOrgId, session.tenantId))
			.limit(1);
		const plan = (row?.plan as Plan) ?? "free";
		return availabilityTargetForPlanKey(PLAN_TO_LOOKUP_KEY[plan]);
	} catch {
		// Never let an SLA lookup break the surface — the default is the documented
		// fallback, and it is the same value the gateway's `_ =>` arm uses.
		return SLO_TARGET_AVAILABILITY;
	}
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
		// `bucket` matches the display bucket this page already renders at, so the
		// gateway groups server-side instead of shipping every HOUR to the edge.
		// At range=30d that is 906 rows / 213KB -> ~30-60 rows: the Worker has a
		// per-request CPU ceiling, and 30d was the first surface to exceed it under
		// load (Error 1102). Every consumer below is unaffected — the sums are exact
		// under re-aggregation, `wmean` re-weights identically, and byModel/byProvider
		// keep their dimensions. The bucketed percentiles are a TRUE quantileMerge,
		// which is strictly better than the mean-of-hourly-percentiles computed here.
		gatewayGet<SloRow[]>(
			`/v1/slo?hours=${hours}&bucket=${Math.max(1, Math.round(bucketMs / 3_600_000))}`,
		).then(
			(rows) => ({ rows, warming: false }),
			(err) => {
				if (err instanceof GatewayError)
					return { rows: [] as SloRow[], warming: true };
				throw err;
			},
		),
		//  #9: the TRUE window-wide p50/p95/p99 (server-side quantileMerge
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
	//  #4: exclude non-LLM (provider="") rows — tool/child spans land in the
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
	//  #9: headline p50/p95/p99 are the TRUE window quantiles from the server
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
	const budget = computeSloBudget(
		totalRequests,
		totalErrors,
		await availabilityTarget(),
	);
	// R59: both charts are drawn over the REQUESTED window, not over first-observed …
	// last-observed. Without this the domain is a property of the data while the heading
	// above describes the query — and steady traffic all day renders identically to a
	// single 4am burst, which is the one thing these charts exist to tell apart.
	// `Date.now()` is safe here: this is a server component, so there is no client
	// re-render to disagree with.
	const win = chartWindow(Date.now(), hours, bucketMs);
	const points = latencyPointsFromTimeseries(timePoints, bucketMs, win);
	const traffic = buildTrafficPoints(rows, bucketMs, win);
	// A chart bar → that bucket's traces (gateway list honors since/until).
	const barHref = (p: { t: number }) =>
		`/traces?since=${encodeURIComponent(new Date(p.t).toISOString())}&until=${encodeURIComponent(
			new Date(p.t + bucketMs).toISOString(),
		)}`;
	/*
	 * DSH-08 — the three per-bucket series behind the new sparks. All three come
	 * from the SAME `traffic` grid the Traffic-over-time chart is drawn on, so a
	 * spark and the chart above it can never disagree about what a bucket is.
	 * `buildTrafficPoints` short-circuits to [] on zero rows, so "no traffic" gives
	 * an empty array here and StatCard renders no spark at all — never a flat line,
	 * which would claim measured zeros we did not measure.
	 */
	const callsSpark = traffic.map((p) => p.requests);
	const tokensSpark = traffic.map((p) => p.tokens);
	// `errRateSpark` — an error-RATE-per-bucket series — was computed here and is
	// DELETED (2026-08-22) with its only consumer, the spark in the KPI row (see
	// the `kpis` block for why that spark could not be read at the width it had).
	// A live computation whose result nothing renders is worse than none: it reads
	// as a series the surface offers, and the next person wires it somewhere by
	// assuming it was already wanted. Its one real insight is worth keeping in
	// writing for whoever revives it — it was the error RATE, never the error
	// COUNT, because a raw count tracks traffic volume, so a busy healthy hour
	// out-spikes a quiet broken one and the shape says the opposite of the number
	// beside it.
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

	/*
	 * DSH-08 — Spend's chart is a COMPOSITION, not a trend, and that is a data
	 * fact rather than a design preference: `GatewayStats` carries
	 * `total_cost_usd` and a per-provider `cost_usd`, and NOTHING in the whole
	 * dashboard response carries cost over time. A sparkline here would have to be
	 * invented, so the tile shows the split it can actually substantiate.
	 */
	const costSplit = (gw?.providers ?? [])
		.filter((p) => p.cost_usd > 0)
		.sort((a, b) => b.cost_usd - a.cost_usd)
		.slice(0, 4);
	const costSplitTotal = costSplit.reduce((sum, p) => sum + p.cost_usd, 0);

	/*
	 * ── P0.6 THE OPERATIONAL KPI ROW ─────────────────────────────────────────
	 * Five metrics, ONE surface, the number dominant and quiet context under it.
	 * Values and hrefs are the SAME reads as before — presentation only.
	 *
	 * WHAT REPLACED WHAT. These five used to be a row of mixed controls: two
	 * filled pills (a black one for error rate, a soft one for block rate) and two
	 * hand-built horizontal bar-gauges with the figure printed inside the fill.
	 * Four shapes for four numbers of the same kind, and the black pill was the
	 * single loudest object above the fold while carrying a value that is usually
	 * 0.00%. P0.6 names both: "Do NOT use coloured pills as the main KPI treatment"
	 * and "Avoid oversized black pills."
	 *
	 * NO PERIOD-OVER-PERIOD DELTA, AND THAT IS A DATA FACT RATHER THAN AN
	 * OMISSION. The brief's KPI sketch shows "↓ 0.48% vs 24h". Nothing on this
	 * page reads a PREVIOUS window: every fetch above is `?hours=${hours}` for the
	 * current one, so a "vs 24h" figure could only be invented, and P0.20 forbids
	 * both fabricating data and changing data fetching. What IS available is a
	 * comparison against the plan's contracted target, and the availability KPI
	 * carries exactly that — a real delta, against a real threshold. The rest
	 * The rest carry only their window label.
	 *
	 * AND NO SPARK EITHER — REMOVED AFTER LOOKING AT THE RENDER, not after reading
	 * the JSX. The first cut put the real per-bucket error-rate series in this row
	 * as a `SparkBars`. Rendered at the width a fifth of a card actually leaves
	 * (~72px beside the sub-line), a 24-bucket series where 23 buckets sit near 2%
	 * and one spikes normalises to 23 sub-pixel bars and one tick: on screen it is
	 * a dotted line, not a shape. An illegible chart is worse than no chart —
	 * it spends the reader's attention and returns nothing — and P0.6's KPI
	 * treatment is label / number / delta, with no series in it. The shape still
	 * exists where it is legible: the Volume surface below, and the full
	 * Traffic-over-time chart.
	 */
	const availAhead = budget.availabilityPct >= budget.targetPct;
	const kpis: {
		label: string;
		value: string;
		href: string;
		hint?: string;
		/** Quiet context under the number. Carries the semantic tone when there is one. */
		sub: ReactNode;
	}[] = [
		{
			label: "Error rate",
			value: dash ? "—" : `${errorPct.toFixed(2)}%`,
			href: `/traces?status=error&range=${rShort}`,
			hint: "Share of LLM requests that failed, over the selected window.",
			sub: <span className="text-ink-3">last {rLabel}</span>,
		},
		{
			label: "Block rate",
			value: blockRatePct === null ? "—" : `${blockRatePct.toFixed(1)}%`,
			href: "/guardrails",
			hint: "Share of pre-flight guardrail VERDICTS that blocked (denominator = verdicts, not requests).",
			sub: <span className="text-ink-3">of guardrail verdicts</span>,
		},
		{
			label: "Availability",
			value: dash ? "—" : `${budget.availabilityPct.toFixed(3)}%`,
			href: "/slo",
			// The one REAL delta on the page: measured availability against the
			// plan's contracted target. Arrow + words + colour, never colour alone
			// (P0.19).
			sub: dash ? (
				<span className="text-ink-3">
					vs {budget.targetPct.toFixed(1)}% target
				</span>
			) : (
				<span className={availAhead ? "text-ok-ink" : "text-danger-ink"}>
					<span aria-hidden="true">{availAhead ? "▲" : "▼"}</span>{" "}
					{availAhead ? "above" : "below"} {budget.targetPct.toFixed(1)}% target
				</span>
			),
		},
		{
			label: "Cache hit",
			value: cacheHitPct === null ? "—" : `${cacheHitPct.toFixed(1)}%`,
			href: "/gateway",
			hint: "Share of gateway requests served from the response cache.",
			sub: <span className="text-ink-3">gateway cache</span>,
		},
		{
			label: "p95 latency",
			// `usingFallback` flags a weighted-mean-of-hourly-p95 (a
			// percentile-of-percentiles) so an approximation is never shown as a
			// true window quantile.
			// `meanP95 > 0` GUARDS THE MARKER, and the render is what caught it. On a
			// zero-traffic tenant the summary endpoint returns nothing, so
			// `usingFallback` is true and `fmtMs(0)` is an em-dash — and the tile
			// printed "~—", an approximation marker on the ABSENCE of a value. The
			// tilde has to mean "this number is approximate"; on no number it is noise
			// that reads like a rendering fault.
			value:
				dash || meanP95 <= 0
					? "—"
					: usingFallback
						? `~${fmtMs(meanP95)}`
						: fmtMs(meanP95),
			href: "/slo",
			hint: "End-to-end p95 over the window — the true server-side quantile, not a mean of hourly percentiles.",
			sub: <span className="text-ink-3">end to end</span>,
		},
	];

	/*
	 * ── P0.7 THE ACTIVITY SURFACE ────────────────────────────────────────────
	 * LLM calls · Tokens · Spend read as ONE coherent activity surface with three
	 * metric groups and hairline separators, not as three unrelated floating
	 * cards. Same three reads as before.
	 */
	const activity: {
		icon: MetricIconName;
		label: string;
		value: string;
		href: string;
		hint?: string;
		spark?: readonly number[];
		sub?: ReactNode;
	}[] = [
		{
			icon: "llm-calls",
			label: "LLM calls",
			value: dash ? "—" : totalRequests.toLocaleString(),
			href: `/traces?range=${rShort}`,
			hint: "Model requests — one agent run can make several. Not the trace/conversation count (see Traces).",
			spark: dash ? undefined : callsSpark,
			sub: dash ? undefined : `per bucket · last ${rLabel}`,
		},
		{
			icon: "tokens",
			label: "Tokens",
			value: dash ? "—" : fmtTokens(totalInputTokens + totalOutputTokens),
			href: "/slo",
			spark: dash ? undefined : tokensSpark,
			sub: dash ? undefined : "in + out · per bucket",
		},
		{
			icon: "spend",
			label: "Spend (est.)",
			value: spend === null || spend === 0 ? "—" : fmtCost(spend),
			href: "/gateway",
			// NO SPARK, AND THAT IS THE HONEST ANSWER, not a gap. Nothing in this
			// page's reads carries cost over time; `GatewayStats` has a window total
			// and a per-provider split, so the tile shows the split. A sparkline here
			// would be the first fabricated series on the surface.
			sub:
				costSplit.length > 0 && costSplitTotal > 0 ? (
					<span className="flex items-center gap-2">
						<span className="flex h-1 flex-1 overflow-hidden rounded-full bg-surface-2">
							{costSplit.map((prov, i) => (
								<span
									key={prov.provider}
									className="h-full bg-chart-primary"
									style={{
										width: `${(prov.cost_usd / costSplitTotal) * 100}%`,
										opacity: Math.max(0.3, 0.9 - i * 0.2),
									}}
									title={`${prov.provider}: ${fmtCost(prov.cost_usd)}`}
								/>
							))}
						</span>
						<span className="shrink-0">
							{costSplit.length === 1
								? costSplit[0]?.provider
								: `${costSplit.length} providers`}
						</span>
					</span>
				) : undefined,
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

	/*
	 * DSH-08 — guardrail verdicts as a composition. The four arcs are the four
	 * real outcome counts and they sum to `total_evaluations`. Tone is set only on
	 * the EXCEPTIONS — see the `allowed` segment for why the healthy 95% is
	 * deliberately neutral.
	 */
	const guardrailSegments = guardrails
		? (
				[
					{
						id: "blocked",
						label: "blocked",
						value: guardrails.blocks,
						tone: "danger",
					},
					{
						id: "redacted",
						label: "redacted",
						value: guardrails.redacts,
						tone: "warn",
					},
					{
						id: "warned",
						label: "warned",
						value: guardrails.warns,
						tone: "warn",
					},
					{
						id: "allowed",
						label: "allowed",
						value: guardrails.allows,
						// NO TONE, AND THAT IS THE POINT. This was `tone: "ok"`, which is
						// defensible on paper — allowed IS the healthy outcome — and wrong
						// on screen: `allowed` is ~95% of every real window, so the card
						// rendered as a saturated green ring with three slivers on it. The
						// loudest object on the surface was the news that nothing happened.
						// Under "colour is data", the DATUM here is the exception: blocked,
						// redacted, warned. Allowed takes the neutral chart ramp, so the 5%
						// that needs attention is the only thing carrying colour.
					},
				] as const
			).filter((seg) => seg.value > 0)
		: [];

	return (
		/*
		 * P0.15 — SECTION SPACING. `space-y-8` (≈29px at the 1440 root, 32px at
		 * 1920) against the `space-y-3` this page carried. Every section gap on the
		 * old surface was ~11px, which is a CARD gap, not a SECTION gap: with the
		 * distance between two cards inside a group equal to the distance between
		 * two groups, the grouping the section labels announce was contradicted by
		 * the layout underneath them.
		 */
		<div className="space-y-8">
			{/* The page header used to sit here. It moved OUT of this component and
			    above the Suspense boundary in `DashboardPage` — it depends on no
			    gateway read, so rendering it here made the page title wait for the
			    slowest of eight round trips. Measured on a production build: LCP was
			    the "Loading dashboard…" fallback, and the real `<h1>` did not paint
			    until the fan-out resolved. The warming banner stays, because it is the
			    one piece of this header region that IS data-derived (`dash`). */}
			{dash && <WarmingBanner />}

			{/*
			 * P0.6 — the operational KPI row.
			 *
			 * THE SEPARATOR MECHANISM, because it is the one non-obvious thing here:
			 * every cell draws its own top and left hairline and the grid is pulled
			 * up and left by 1px, so the outermost rules slide underneath the card's
			 * own border and `overflow-hidden` clips them. That is what makes the
			 * rules correct at EVERY breakpoint — 2-up, 3-up and 5-up all wrap into
			 * a clean lattice with no orphan rule, which neither `divide-x` (which
			 * strands a left border at the start of rows 2+) nor a `gap-px` +
			 * background trick (which paints the empty tail of the last row) does.
			 */}
			<section
				aria-label="Operational health"
				className="surface-card overflow-hidden border border-line"
			>
				<div className="-ml-px -mt-px grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5">
					{kpis.map((k) => (
						<Link
							key={k.label}
							href={k.href}
							className="group flex flex-col gap-1.5 border-l border-t border-line px-5 py-4 transition-colors hover:bg-surface-hover focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-focus-ring"
						>
							<span className="t-metric-label flex items-center gap-1.5">
								{k.label}
								{k.hint && (
									<span
										aria-label={k.hint}
										title={k.hint}
										className="grid h-3.5 w-3.5 cursor-help place-items-center rounded-full border border-line-2 text-2xs leading-none text-ink-3"
									>
										?
									</span>
								)}
							</span>
							{/* The number is GRAPHITE (P0.6) — the semantic tone lives in the
							    sub-line below it, never in the headline figure. */}
							<span className="t-metric font-mono text-ink">{k.value}</span>
							<span className="flex min-h-4 items-center text-2xs">
								{k.sub}
							</span>
						</Link>
					))}
				</div>
			</section>

			{/*
			 * P0.7 — ACTIVITY. One surface, three metric groups, hairline
			 * separators, stacking to a single column on a phone. It was three
			 * separate cards in a `StatGrid`, which said "three unrelated facts"
			 * about three views of the same traffic.
			 */}
			<section aria-label="Volume" className="space-y-3">
				<SectionLabel>Volume</SectionLabel>
				<div className="surface-card overflow-hidden border border-line">
					<div className="-ml-px -mt-px grid grid-cols-1 sm:grid-cols-3">
						{activity.map((a) => (
							<Link
								key={a.label}
								href={a.href}
								className="flex flex-col gap-2 border-l border-t border-line px-6 py-5 transition-colors hover:bg-surface-hover focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-focus-ring"
							>
								<span className="flex items-center gap-2">
									<MetricIcon name={a.icon} size={20} />
									<span className="t-metric-label flex items-center gap-1.5">
										{a.label}
										{a.hint && (
											<span
												aria-label={a.hint}
												title={a.hint}
												className="grid h-3.5 w-3.5 cursor-help place-items-center rounded-full border border-line-2 text-2xs leading-none text-ink-3"
											>
												?
											</span>
										)}
									</span>
								</span>
								<span className="t-metric font-mono text-ink">{a.value}</span>
								{a.spark && (
									/* `max-w-[13rem]` and a taller bar, both set from the render.
									   `SparkBars` uses `preserveAspectRatio="none"`, so an
									   unconstrained spark in a third-of-a-card cell stretched 24
									   two-unit bars across ~380px — each bar ~10px wide with a 5px
									   gap, which reads as a dashed rule rather than as a series.
									   Capping the width keeps the bars narrow and the 18px height
									   gives the shape somewhere to happen. */
									<SparkBars
										values={a.spark}
										height={18}
										ariaLabel={`${a.label} per bucket over the last ${rLabel}`}
										className="max-w-[13rem]"
									/>
								)}
								<span className="min-h-4 text-2xs text-ink-3">{a.sub}</span>
							</Link>
						))}
					</div>
				</div>
			</section>

			{/* ── Section 1 — HEALTH AT A GLANCE ─────────────────────────────────
			    Traffic over time (PRIMARY, wide) · Error budget (PRIMARY, the one
			    deliberate dark card) · Where the time goes (secondary).
			    P0.4: the three do NOT carry the same visual weight any more. */}
			<section aria-label="Health at a glance" className="space-y-3">
				<SectionLabel>Health at a glance</SectionLabel>
				<div className="grid grid-cols-1 gap-4 lg:grid-cols-12 lg:items-stretch">
					{/* Traffic over time — real per-bucket request counts. PRIMARY. */}
					<Card className="flex h-full flex-col p-6 lg:col-span-6">
						<CardHead
							icon="traffic"
							title={`Traffic over time — last ${rLabel} · UTC`}
						/>
						{trafficLolli.length > 0 ? (
							/*
							 * `flex-col`, and this was a real defect (found by LOOKING at the
							 * render rather than reading the JSX). The wrapper was
							 * `flex flex-1 items-center` with the chart and the TimeRuler as
							 * SIBLINGS — a flex ROW — so the axis was laid out to the RIGHT of
							 * the bars in a ~60px column, printing "30/08" and "13/08" on top
							 * of each other inside the plot area. No test could see it: every
							 * tick was present in the DOM and correct.
							 */
							<div className="flex flex-1 flex-col justify-center">
								<Lollipop
									points={trafficLolli}
									hrefFor={trafficHref}
									ariaLabel={`requests per bucket over the last ${rLabel}`}
								/>
								{/* ONE time axis, replacing the strided labels this chart used
								    to draw itself. `win.endMs` is the LAST BUCKET START, so the
								    axis runs to that bucket's END. Inset to the svg's PAD_L/PAD_R
								    (34/8 of a 640 viewBox) so ticks land on the slot centres the
								    bars use. */}
								<div
									className="mt-2"
									style={{ marginLeft: "5.31%", marginRight: "1.25%" }}
								>
									<TimeRuler
										startMs={win.startMs}
										endMs={win.endMs + bucketMs}
										ticks={4}
										mode="absolute"
									/>
								</div>
							</div>
						) : (
							<CardEmpty
								ghost={<GhostFloor />}
								title="No traffic yet"
								description="Requests will appear here as your agents send traffic through the gateway."
								action={{
									href: "/settings/providers",
									label: "Connect a provider",
								}}
							/>
						)}
					</Card>

					{/*
					 * P0.10 — ERROR BUDGET. The one deliberately dark card, in BOTH
					 * themes, because a burn signal should read as an instrument panel
					 * rather than as the ninth white tile.
					 *
					 * THE BORDER IS LOAD-BEARING AND IT CANNOT BE `border-line`. In dark,
					 * `--surface-inverse` IS the canvas colour, so with no border the card
					 * has no edge whatsoever — a void beside cards that all carry a crisp
					 * hairline. But `--line` is a LIGHT-SURFACE hairline (#e7e7e5), and on
					 * a near-black card in light theme that paints a bright ring.
					 * `border-ink-inverse/15` resolves to ~#2f3032 over the card in BOTH
					 * themes — one expression, correct twice — and lands within a couple
					 * of points of the #292B2F the brief specifies for this card.
					 *
					 * The `.card-lava-top` ink strip that used to sit on this card is
					 * GONE with the class: `--action` and `--surface-inverse` are both
					 * ink, so in light theme it painted a 2px #171717 line on a #151619
					 * card — invisible by construction, and decorative even where it was
					 * visible, which P0 does not allow.
					 */}
					<div className="flex h-full flex-col rounded-[var(--radius-card)] border border-ink-inverse/15 bg-surface-inverse p-6 lg:col-span-3">
						<div className="flex items-center justify-between gap-3">
							<div className="flex items-center gap-2">
								<MetricIcon name="error-budget" size={20} onInverse />
								<h2 className="t-card-title text-ink-inverse">
									Error budget ({rShort})
								</h2>
							</div>
						</div>
						{/*
						 * The burn rate is a VALUE AGAINST A THRESHOLD, which is the
						 * textbook case for a gauge. SCALE: 0–2× across the arc, so the
						 * 1.0× pace line lands at dead centre and "left of the tick" /
						 * "right of the tick" is legible without reading a number. Above
						 * 2× the arc pins full and the NUMERAL keeps counting — the arc
						 * saturates, the datum does not. The centre display is the real
						 * `fmtBurn` value in every case, so a pinned arc can never be
						 * mistaken for a 2× reading.
						 */}
						{dash ? (
							<div className="mt-4 font-mono text-ramp-28 font-semibold leading-none tabular-nums text-ink-inverse">
								—
							</div>
						) : (
							<Gauge
								onInverse
								className="mt-2"
								value={
									Number.isFinite(budget.burnRate)
										? Math.min(100, (budget.burnRate / 2) * 100)
										: 100
								}
								marker={50}
								display={fmtBurn(budget.burnRate)}
								label="burn rate"
							/>
						)}
						<p className="mt-1 text-center text-2xs text-ink-inverse opacity-60">
							1.0× = on pace
						</p>
						<dl className="mt-auto space-y-2.5 border-t border-ink-inverse/10 pt-4 text-xs">
							<div className="flex items-center justify-between gap-3">
								<dt className="text-ink-inverse opacity-60">Availability</dt>
								<dd className="font-mono tabular-nums text-ink-inverse">
									{dash ? "—" : `${budget.availabilityPct.toFixed(3)}%`}
								</dd>
							</div>
							<div className="flex items-center justify-between gap-3">
								<dt className="text-ink-inverse opacity-60">
									Target (your plan)
								</dt>
								<dd className="font-mono tabular-nums text-ink-inverse">
									{budget.targetPct.toFixed(1)}%
								</dd>
							</div>
							<div className="flex items-center justify-between gap-3">
								<dt className="text-ink-inverse opacity-60">
									Budget remaining
								</dt>
								<dd className="font-mono tabular-nums text-ink-inverse">
									{dash ? "—" : fmtBudget(budget.budgetRemainingPct)}
								</dd>
							</div>
						</dl>
					</div>

					{/* Where the time goes — the honest trip split (real p95 per
					    component). SECONDARY weight (P0.4): it is a breakdown of the
					    latency the KPI row already states. */}
					<Link href="/gateway" className={`${TILE_LINK_CLS} lg:col-span-3`}>
						<Card quiet className="flex h-full flex-col p-6">
							<CardHead
								icon="time"
								title="Where the time goes"
								meta="gateway vs upstream"
							/>
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
											{
												value: fmtMs(latency.overhead_p95_ms),
												label: "gateway",
											},
										]}
										caption={
											gwTripPct !== null
												? `p95 · gateway ≈ ${gwTripPct}% of the trip${usingFallback ? " (approx)" : ""}`
												: "p95 · end-to-end · provider · gateway"
										}
									/>
								</div>
							) : (
								<CardEmpty
									title="No latency split yet"
									description="Gateway versus provider latency appears here as requests flow."
								/>
							)}
						</Card>
					</Link>
				</div>
			</section>

			{/* ── Section 2 — LATENCY, ROUTING & SAFETY ───────────────────────── */}
			<section aria-label="Latency, routing and safety" className="space-y-3">
				<SectionLabel>Latency, routing &amp; safety</SectionLabel>
				<div className="grid grid-cols-1 gap-4 lg:grid-cols-12 lg:items-stretch">
					{/* Latency over time + the full gateway-overhead / provider / TTFT
					    percentile split — all real. PRIMARY. */}
					<Card className="flex h-full flex-col p-6 lg:col-span-5">
						<CardHead
							icon="latency"
							title={`Latency over time — last ${rLabel} · UTC`}
						/>
						{points.length > 0 ? (
							<>
								<LatencyTimeline points={points} />
								{/* preserveAspectRatio="none" means the chart svg stretches
								    edge to edge, so the ruler needs no inset. */}
								<TimeRuler
									startMs={win.startMs}
									endMs={win.endMs + bucketMs}
									ticks={4}
									mode="absolute"
								/>
							</>
						) : (
							<CardEmpty
								ghost={<GhostFloor />}
								title="No latency data yet"
								description="Per-bucket percentiles appear here as requests flow through the gateway."
								action={{ href: "/gateway", label: "Gateway setup" }}
							/>
						)}
						{latency && latency.overhead_samples > 0 && (
							<dl className="mt-4 grid grid-cols-[auto_1fr] items-baseline gap-x-4 gap-y-2 border-t border-line pt-4 text-2xs">
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

					{/* Request flow — gateway → model → honest OK/Error split. PRIMARY. */}
					<Card className="flex h-full flex-col p-6 lg:col-span-4">
						<CardHead
							icon="request-flow"
							title="Request flow"
							meta="gateway → model → outcome"
						/>
						{flowModels.length > 0 ? (
							<div className="flex flex-1 items-center">
								<RequestFlow models={flowModels} />
							</div>
						) : (
							<CardEmpty
								title="No traffic yet"
								description="The request path — gateway → model → OK or Error — appears here as your agents call the gateway."
								action={{
									href: "/settings/providers",
									label: "Connect a provider",
								}}
							/>
						)}
					</Card>

					{/* Guardrail activity — real block/fail-open verdicts. SECONDARY. */}
					<Card quiet className="flex h-full flex-col p-6 lg:col-span-3">
						<CardHead
							icon="guardrail"
							title="Guardrail activity"
							meta={rShort}
						/>
						{guardrails === null || guardrails.total_evaluations === 0 ? (
							<CardEmpty
								title="No guardrail activity yet"
								description="Block and allow verdicts appear here as requests pass the inline guardrails."
								action={{ href: "/guardrails", label: "Configure guardrails" }}
							/>
						) : (
							<div className="flex flex-1 flex-col justify-center">
								<div className="t-metric-sm font-mono text-ink">
									{guardrails.block_rate_pct.toFixed(1)}%
								</div>
								<p className="mt-0.5 text-2xs text-ink-3">block rate</p>
								{/*
								 * Four counts that are FOUR PARTS OF ONE WHOLE were rendered as
								 * four unrelated numerals, so nothing on screen said they sum to
								 * `total_evaluations`. A donut is the composition form, and here
								 * the slices ARE the datum — the one legitimate use of colour
								 * under "colour is data": blocked=danger, redacted/warned=warn,
								 * allowed=ok. Zero-valued outcomes are filtered out rather than
								 * drawn as invisible arcs with a legend row claiming 0%.
								 */}
								{guardrailSegments.length > 0 && (
									<ModelDonut
										className="mt-3"
										segments={[...guardrailSegments]}
										total={guardrails.total_evaluations}
										centerLabel="verdicts"
										ariaLabel="guardrail verdict outcomes"
									/>
								)}
								<div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-3 border-t border-line pt-4">
									{[
										{
											v: guardrails.total_evaluations.toLocaleString(),
											l: "evaluations",
										},
										{
											v: `${guardrails.fail_open_rate_pct.toFixed(1)}%`,
											l: "fail-open",
										},
										{ v: guardrails.blocks.toLocaleString(), l: "blocked" },
										{
											v: guardrails.fail_open_verdicts.toLocaleString(),
											l: "fail-opens",
										},
									].map((s) => (
										<div key={s.l} className="flex flex-col gap-0.5">
											<span className="font-mono text-sm font-semibold tabular-nums text-ink">
												{s.v}
											</span>
											<span className="text-2xs text-ink-3">{s.l}</span>
										</div>
									))}
								</div>
							</div>
						)}
					</Card>
				</div>
			</section>

			{/* ── Section 3 — MODELS, PROVIDERS & FAILURES ────────────────────────
			    All three read already-fetched data — no new fetch. All three are
			    SECONDARY (P0.4): they are the breakdown behind the primary signals
			    above, so they sit flat on the ground rather than lifting off it. */}
			<section
				aria-label="Models, providers and failures"
				className="space-y-3"
			>
				<SectionLabel>Models, providers &amp; failures</SectionLabel>
				<div className="grid grid-cols-1 gap-4 lg:grid-cols-12 lg:items-stretch">
					{/* Traffic by model — top 5 provider/model series by request volume. */}
					<Card
						quiet
						className="flex h-full flex-col overflow-hidden lg:col-span-4"
					>
						<div className="px-6 pb-3 pt-5">
							<CardHead
								icon="model-breakdown"
								title="Traffic by model"
								action={{ href: "/slo", label: "View all" }}
							/>
						</div>
						{topModels.length > 0 ? (
							<>
								{/*
								 * The table answers "how many", the donut answers "what share",
								 * and only the second one shows a single model quietly taking
								 * 80% of the fleet. `total` is the TRUE window request count,
								 * not the sum of the top 5, so ModelDonut draws its honest
								 * "Other" arc for the tail rather than implying these five are
								 * all the traffic there was.
								 */}
								<ModelDonut
									className="px-6 pb-4"
									segments={topModels.map((m) => ({
										id: `${m.provider}::${m.model}`,
										label: m.model,
										sub: m.provider,
										value: m.requests,
										href: modelHref(m.model),
									}))}
									total={totalRequests}
									centerLabel="calls"
									ariaLabel="request share by model"
								/>
								<div className="overflow-x-auto">
									<table className="w-full text-sm">
										<thead className="border-y border-line bg-canvas-sunken">
											<tr>
												<th className="t-metric-label px-4 py-2 text-left">
													Model
												</th>
												<th className="t-metric-label px-4 py-2 text-right">
													Requests
												</th>
												<th className="t-metric-label px-4 py-2 text-right">
													Tokens
												</th>
											</tr>
										</thead>
										<tbody className="divide-y divide-line">
											{topModels.map((m) => (
												<tr
													key={`${m.provider}::${m.model}`}
													className="transition-colors hover:bg-surface-hover"
												>
													<td className="px-4 py-3">
														{m.model && m.model !== "—" ? (
															<Link
																href={`/traces?model=${encodeURIComponent(m.model)}&range=${rShort}`}
																className="block truncate font-mono text-xs text-ink hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
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
														<div className="mt-1.5 h-1 overflow-hidden rounded-full bg-surface-2">
															<div
																className="h-full rounded-full bar-data"
																style={{
																	width: `${maxModelReq > 0 ? (m.requests / maxModelReq) * 100 : 0}%`,
																}}
															/>
														</div>
													</td>
													<td className="px-4 py-3 text-right font-mono text-xs tabular-nums text-ink">
														{m.requests.toLocaleString()}
													</td>
													<td className="px-4 py-3 text-right font-mono text-xs tabular-nums text-ink-2">
														{fmtTokens(m.tokens)}
													</td>
												</tr>
											))}
										</tbody>
									</table>
								</div>
							</>
						) : (
							<div className="px-6 pb-6">
								<CardEmpty
									title="No traffic yet"
									description="Per-model request volume appears here once your agents call the gateway."
									action={{
										href: "/settings/providers",
										label: "Connect a provider",
									}}
								/>
							</div>
						)}
					</Card>

					{/* Provider health — top 4 providers by request volume with error rate
					    and a share bar. Derived inline from fetchGatewayStats (already
					    fetched); no extra read, no fabricated numbers. */}
					<Card quiet className="flex h-full flex-col p-6 lg:col-span-4">
						<CardHead
							icon="provider"
							title="Provider health"
							meta="req · err"
						/>
						{topProviders.length === 0 ? (
							<CardEmpty
								title="No provider traffic yet"
								description="Per-provider request volume and error rate appear here."
								action={{
									href: "/settings/providers",
									label: "Connect a provider",
								}}
							/>
						) : (
							/* `justify-start`, not `justify-center`. This card is the
							   shortest in an `items-stretch` row, so centring floated three
							   provider rows in the middle of a tall card with a band of empty
							   space above and below them — which reads as a rendering fault
							   rather than as spacing. Content starts at the top; the card is
							   simply taller than its content, which is what stretch means. */
							<div className="flex flex-1 flex-col justify-start gap-3">
								{topProviders.map((p) => (
									<div key={p.provider}>
										<div className="flex items-baseline gap-2">
											<span className="min-w-0 flex-1 truncate font-mono text-xs text-ink">
												{p.provider}
											</span>
											<span className="font-mono text-xs tabular-nums text-ink">
												{fmtTokens(p.requests)}
											</span>
											<span
												className={`font-mono text-xs tabular-nums ${
													p.error_rate_pct > 0
														? "text-danger-ink"
														: "text-ink-3"
												}`}
											>
												{p.error_rate_pct.toFixed(1)}%
											</span>
										</div>
										<div className="mt-1.5 h-1 overflow-hidden rounded-full bg-surface-2">
											<div
												className="h-full rounded-full bar-data"
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
					<Card
						quiet
						className="flex h-full flex-col overflow-hidden lg:col-span-4"
					>
						<div className="px-6 pb-3 pt-5">
							<CardHead
								icon="failure-signatures"
								title="Top failure signatures"
								action={{ href: "/signatures", label: "View all" }}
							/>
						</div>
						{topSigs.length > 0 ? (
							<div className="overflow-x-auto">
								<table className="w-full text-sm">
									<thead className="border-y border-line bg-canvas-sunken">
										<tr>
											<th className="t-metric-label px-4 py-2 text-left">
												Signature
											</th>
											<th className="t-metric-label px-4 py-2 text-right">
												Hits ({rShort})
											</th>
											<th className="t-metric-label px-4 py-2 text-right">
												Action
											</th>
										</tr>
									</thead>
									<tbody className="divide-y divide-line">
										{topSigs.map((s) => (
											<tr
												key={s.signature_id}
												className="transition-colors hover:bg-surface-hover"
											>
												<td className="px-4 py-3">
													<Link
														href={`/traces?signature_id=${encodeURIComponent(s.signature_id)}&range=${rShort}`}
														className="rounded font-mono text-xs text-ink hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
														title={`View ${s.signature_id} traces`}
													>
														{s.signature_id}
													</Link>
												</td>
												<td className="px-4 py-3 text-right font-mono text-xs tabular-nums text-ink">
													{s.your_hits.toLocaleString()}
												</td>
												<td className="px-4 py-3 text-right">
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
							</div>
						) : (
							<div className="px-6 pb-6">
								<CardEmpty
									title="No failure signatures matched yet"
									description="A known agent-failure pattern — a tool-schema violation, definition drift — surfaces here when it is seen in your traces."
									action={{
										href: "/signatures",
										label: "About failure signatures",
									}}
								/>
							</div>
						)}
					</Card>
				</div>
			</section>

			{/* ── Tool usage — the one dashboard surface for agent tool health.
			    SECONDARY, full width. */}
			<section aria-label="Tool usage" className="space-y-3">
				<SectionLabel>Tool usage ({rShort})</SectionLabel>
				<Card quiet className="overflow-hidden">
					<div className="px-6 pb-3 pt-5">
						<CardHead
							icon="tool-usage"
							title="Tools called through the gateway"
							action={{ href: "/traces", label: "View traces" }}
						/>
					</div>
					{toolAnalyticsWarming ? (
						<div className="px-6 pb-6">
							<CardEmpty
								title="Warming up"
								description="Tool usage data is unavailable while the gateway is warming."
							/>
						</div>
					) : totalToolCalls === 0 ? (
						<div className="px-6 pb-6">
							<CardEmpty
								title="No tool calls yet"
								description="Per-tool call counts, error rates and p95 latency appear here once your agents invoke tools through the gateway."
								action={{ href: "/traces", label: "View traces" }}
							/>
						</div>
					) : (
						<div className="overflow-x-auto">
							<table className="w-full text-sm">
								<thead className="border-y border-line bg-canvas-sunken">
									<tr>
										<th className="t-metric-label px-4 py-2 text-left">Tool</th>
										<th className="t-metric-label px-4 py-2 text-right">
											Calls
										</th>
										<th className="t-metric-label px-4 py-2 text-right">
											Error rate
										</th>
										<th className="t-metric-label px-4 py-2 text-right">p95</th>
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
												className="transition-colors hover:bg-surface-hover"
											>
												<td className="px-4 py-3">
													<span
														className="block truncate font-mono text-xs text-ink"
														title={t.tool}
													>
														{t.tool}
													</span>
													<div className="mt-1.5 h-1 overflow-hidden rounded-full bg-surface-2">
														<div
															className="h-full rounded-full bar-data"
															style={{
																width: `${maxToolCalls > 0 ? (t.calls / maxToolCalls) * 100 : 0}%`,
															}}
														/>
													</div>
												</td>
												<td className="px-4 py-3 text-right font-mono text-xs tabular-nums text-ink">
													{t.calls.toLocaleString()}
												</td>
												<td
													className={`px-4 py-3 text-right font-mono text-xs tabular-nums ${
														t.errors > 0 ? "text-danger-ink" : "text-ink-3"
													}`}
												>
													{t.errors > 0 ? `${errPct}%` : "—"}
												</td>
												<td className="px-4 py-3 text-right font-mono text-xs tabular-nums text-ink-2">
													{fmtMs(t.p95_ms)}
												</td>
											</tr>
										);
									})}
								</tbody>
							</table>
						</div>
					)}
				</Card>
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
		/*
		 * P0.15/P0.16/P0.17 — RESPONSIVE PAGE PADDING. `px-2 py-3` put the whole
		 * dashboard ~7px from the edge of the content column at the 1440 root,
		 * which is why the surface read cramped no matter what the cards did
		 * internally. This ramps with the viewport instead of pinning one gutter.
		 * The horizontal value stays modest on a phone (P0.17: touch targets and
		 * chart width matter more there than margin) and opens up on a desktop.
		 */
		<div className="space-y-8 px-1 py-2 sm:px-2 sm:py-4 lg:px-3">
			{/* Page header — OUTSIDE the Suspense boundary on purpose. The range
			    control sits alone on the right: it is a CONTROL, and it used to be
			    the fifth item in a row of four metrics, which is what made that row
			    read as a toolbar rather than as a readout.
			    Nothing here reads the gateway, so it streams with the shell instead
			    of behind `DashboardData`'s eight-read fan-out. That is the whole
			    point: the page identifies itself and becomes interactive (the range
			    control is clickable) while the data is still in flight. */}
			<header className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
				<div>
					<h1 className="t-h1">Welcome back</h1>
					<p className="mt-2 text-sm text-ink-2">
						Your agent fleet, at a glance.
					</p>
				</div>
				<RangeControl />
			</header>
			{/* No `key={range}` — keying on range REMOUNTS the boundary on every
			    range change and flashes the fallback (the "feels slow" reload).
			    Without it, the RangeControl's useTransition keeps the current view
			    on screen and swaps in the new window's data when it arrives. The
			    fallback now shows only on the true first load. */}
			<Suspense
				fallback={
					<p className="py-10 text-sm text-ink-3">Loading dashboard…</p>
				}
			>
				<DashboardData range={range} />
			</Suspense>
		</div>
	);
}

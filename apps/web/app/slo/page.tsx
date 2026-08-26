/**
 * SLO dashboard page — per-hour latency percentiles, error rate, and
 * token usage by provider and model.
 *
 * Reads SLO rollups via the gateway proxy (GET /v1/slo) — the gateway owns
 * the ClickHouse query and resolves the tenant from the forwarded token.
 * RSC: fetched at request time with Suspense streaming.
 *
 * ── P1 DESIGN PASS (2026-08-22) ─────────────────────────────────────────────
 * PRESENTATION ONLY. Every number, formatter, threshold, window and query on
 * this page is byte-identical to what it was before; `budget.ts` and
 * `latency.ts` are untouched (the dashboard imports both, so a change there
 * would silently move the dashboard's numbers too).
 *
 * WHAT CHANGED, and why, because the reported defect was "visually clean but
 * excessive unused space":
 *
 *  · THE EIGHT `.stat-tile`s BECAME TWO HAIRLINE STRIPS. Eight tiles at `p-5`
 *    with a `gap-4` between them spent most of their height on padding and most
 *    of their width on nothing, and — being eight identical surfaces — said all
 *    eight facts rank the same. The strips are the P0 dashboard's own KPI
 *    grammar (`app/dashboard/page.tsx`, "Operational health"): ONE card, cells
 *    separated by rules, primary for the budget group and `quiet` for volume.
 *  · THE NUMBER IS GRAPHITE (P0.6). Semantic colour moved off the headline
 *    figure and onto a WORDED sub-line, so state never travels on colour alone.
 *    The bands are the ones this page already shipped — `budget.tone`
 *    (`budget.ts`: "<1 ok, [1,2) warn, ≥2 error") and the >5% / >1% error-rate
 *    split that lived inline here. Nothing new was invented.
 *  · THE BURN RATE KEEPS THE DELIBERATE DARK SURFACE and gains the `Gauge` the
 *    dashboard already draws for the SAME number from the SAME arithmetic — a
 *    0–2× arc with the 1.0× pace line at dead centre. It is a shape sized from
 *    a value the card is displaying anyway, not a new measurement.
 *  · THE NO-DATA STATE. With an empty window the latency card used to render
 *    one grey sentence and an orphaned time axis inside a full-height card, and
 *    the table rendered a centred line with nowhere to go. Both are real
 *    `EmptyState`s now, with a real link. The ghost is a UNIFORM comb: a
 *    varying silhouette would be a trend drawn from numbers that do not exist.
 *  · THE TABLE IS ON THE SHARED `Table` PRIMITIVE. It was one of the 21
 *    hand-rolled tables that primitive exists to replace.
 */

import type { SloModelRow, SloTimePoint } from "@/app/slo/types";
import { RangeControl } from "@/components/RangeControl";
import { WarmingBanner } from "@/components/empty-states/WarmingBanner";
import { db } from "@/db";
import { tenants } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { PLAN_TO_LOOKUP_KEY, type Plan } from "@/lib/entitlements";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import { fetchLatencyBreakdown, overheadByModelKey } from "@/lib/latency";
import { rangeBucketMs, rangeLabel, rangeToHours } from "@/lib/range";
import {
	Badge,
	type BadgeProps,
	Card,
	EmptyState,
	Gauge,
	LatencyTimeline,
	MetricIcon,
	type MetricIconName,
	Skeleton,
	TBody,
	TD,
	TH,
	THead,
	TR,
	Table,
	TimeRuler,
	cn,
} from "@tracelanedev/ui";
import { eq } from "drizzle-orm";
import type { Metadata } from "next";
import Link from "next/link";
import { type ReactNode, Suspense } from "react";
import {
	SLO_TARGET_AVAILABILITY,
	type SloBudget,
	availabilityTargetForPlanKey,
	computeSloBudget,
} from "./budget";
import { chartWindow, latencyPointsFromTimeseries } from "./latency";

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

/* ── Layout vocabulary, shared with the P0 dashboard ───────────────────────── */

/**
 * Section divider (P0.8) — the eyebrow type plus a trailing hairline rule.
 *
 * MARKUP ALIGNED WITH `app/gateway/SectionLabel.tsx` AND /guardrails' copy
 * (verifier, 2026-08-22). Three private copies of one object had drifted three
 * ways: this one used a `<span>` where the other two use an `<h2>` (so an
 * identical-looking section label was in the heading outline on two pages and
 * absent from it here), it lacked `flex-wrap` (so a label + action row could
 * overflow instead of wrapping), and its rule lacked `min-w-8` (so a squeezed
 * row collapsed the divider to 0px rather than leaving a visible stub).
 * `.t-eyebrow` sets its own size and weight, so `<h2>` renders identically.
 *
 * Promoting the three copies into `@tracelanedev/ui` is still the right end
 * state and is still deliberately NOT done here — that is a shared-primitive
 * change and belongs in its own commit. Making the copies byte-identical is the
 * part that can be done safely now.
 */
function SectionLabel({
	children,
	action,
}: {
	children: ReactNode;
	/** Right-hand qualifier: a status badge, never a control. */
	action?: ReactNode;
}) {
	return (
		<div className="flex flex-wrap items-center gap-3">
			<h2 className="t-eyebrow">{children}</h2>
			<span className="h-px min-w-8 flex-1 bg-line" />
			{action}
		</div>
	);
}

/** Card header — icon chip · title · optional quiet right-hand qualifier. */
function CardHead({
	icon,
	title,
	meta,
}: {
	icon: MetricIconName;
	title: string;
	meta?: string;
}) {
	return (
		<div className="mb-4 flex items-center justify-between gap-3">
			<div className="flex min-w-0 items-center gap-2.5">
				<MetricIcon name={icon} size={20} />
				<h2 className="t-card-title">{title}</h2>
			</div>
			{meta ? (
				<span className="hidden shrink-0 text-2xs text-ink-3 xl:inline">
					{meta}
				</span>
			) : null}
		</div>
	);
}

/** One reading in a metric strip. `value` is a pre-formatted string — this
 *  component formats nothing and computes nothing. */
type Kpi = {
	icon: MetricIconName;
	label: string;
	value: string;
	/** Plain-language expansion of the label, on a `?` affordance. */
	hint?: string;
	/** Sub-line under the value: the state word, a proportion bar, or nothing. */
	sub?: ReactNode;
};

/**
 * A row of readings sharing ONE card, separated by hairlines rather than by gaps.
 *
 * THE SEPARATOR MECHANISM (copied deliberately from the dashboard, which
 * measured it): every cell draws its own top and left hairline and the grid is
 * pulled up and left by 1px, so the outermost rules slide under the card's own
 * border and `overflow-hidden` clips them. That is what makes the lattice
 * correct at EVERY breakpoint — neither `divide-x` (which strands a left border
 * at the start of rows 2+) nor a `gap-px` background trick does.
 */
function MetricStrip({
	items,
	cols,
	quiet,
	className,
}: {
	items: Kpi[];
	/** Breakpoint column classes for the cell grid. */
	cols: string;
	/** Secondary weight (P0.4) — flat instead of lifted. */
	quiet?: boolean;
	className?: string;
}) {
	return (
		<Card quiet={quiet} className={cn("overflow-hidden", className)}>
			{/* `h-full` + `mt-auto` below is the SAME mechanism `StatCard` uses, and it
			    is what stops a stretched strip from becoming the very defect this pass
			    was opened for. Rendered at 1440: the budget strip sits beside a taller
			    gauge card under `items-stretch`, the Card grew to match, the cells did
			    not, and ~70px of blank sheet hung under the numbers. The label pins to
			    the top, the reading to the bottom, and the extra height becomes the gap
			    between them. */}
			<div className={cn("-ml-px -mt-px grid h-full", cols)}>
				{items.map((k) => (
					<div
						key={k.label}
						className="flex h-full min-w-0 flex-col gap-1.5 border-l border-t border-line px-5 py-4"
					>
						<span className="flex items-center gap-2">
							<MetricIcon name={k.icon} size={18} />
							{/* NOT `truncate`. It was, and on the 4-up volume strip at 1440
							    "LLM calls (24 hours)" rendered as "LLM CALLS (24 H…" — the
							    label that names the metric lost to its own window qualifier.
							    It wraps instead; `mt-auto` on the value block below absorbs
							    the second line without moving the number. */}
							<span className="t-metric-label flex min-w-0 items-start gap-1.5">
								<span>{k.label}</span>
								{k.hint && (
									<span
										aria-label={k.hint}
										title={k.hint}
										className="grid h-3.5 w-3.5 shrink-0 cursor-help place-items-center rounded-full border border-line-2 text-2xs leading-none text-ink-3"
									>
										?
									</span>
								)}
							</span>
						</span>
						<span className="mt-auto flex flex-col gap-1.5 pt-2">
							{/* GRAPHITE, always (P0.6). The tone lives in the sub-line. */}
							<span className="t-metric font-mono text-ink">{k.value}</span>
							<span className="flex min-h-4 items-center text-2xs">
								{k.sub}
							</span>
						</span>
					</div>
				))}
			</div>
		</Card>
	);
}

/**
 * The ghost for a chart with no data (P0.9). THE BARS ARE ALL THE SAME HEIGHT
 * and that is the whole design: a varying silhouette would be a trend, a spike
 * or a quiet night read out of numbers that do not exist. A uniform comb is
 * structurally incapable of implying one — it says "a chart goes here".
 *
 * Anchored to the FLOOR because `EmptyState` centres its ghost slot, and a comb
 * centred behind two lines of copy prints the explanation over a barcode.
 */
const GHOST_SLOTS = Array.from({ length: 24 }, (_, i) => i);

function GhostFloor() {
	return (
		<span className="flex h-full w-full items-end">
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
		</span>
	);
}

/** The shared empty state plus the one styled drill-through link this page uses. */
function SloEmpty({
	title,
	description,
	action,
	ghost,
	className,
}: {
	title: string;
	description: string;
	action?: { href: string; label: string };
	ghost?: ReactNode;
	/**
	 * Extra layout for the block. A caller passing a `ghost` MUST reserve height
	 * with it: `EmptyState` positions the ghost slot `absolute inset-0`, so in a
	 * short box the floor-anchored comb lands ON the action link. Rendered at
	 * 1440 with an empty window, "Gateway setup →" printed straight through the
	 * placeholder bars.
	 */
	className?: string;
}) {
	return (
		<EmptyState
			compact
			className={cn("flex-1", className)}
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

/* ── State vocabulary — words for bands the arithmetic ALREADY computes ────── */

/**
 * Burn-rate health as a word plus a tone.
 *
 * THE BANDS ARE `budget.ts`'s OWN. `SloBudget.tone` is documented there as
 * "<1 ok, [1,2) warn, ≥2 error" and this page already coloured the availability
 * tile from it. All that is added here is the LABEL, so the state has a text
 * channel as well as a colour one. No threshold is invented, and the exact band
 * rides along in the `title` so the claim is checkable.
 */
const BURN_HEALTH: Record<
	SloBudget["tone"],
	{ label: string; tone: BadgeProps["tone"]; title: string }
> = {
	ok: {
		label: "Healthy",
		tone: "ok",
		title: "Burn rate below 1.0× — the error budget lasts the window.",
	},
	warn: {
		label: "Warning",
		tone: "warn",
		title:
			"Burn rate 1.0×–2.0× — the error budget runs out before the window ends.",
	},
	error: {
		label: "Critical",
		tone: "danger",
		title:
			"Burn rate 2.0× or more — the error budget is spent at more than twice the sustainable pace.",
	},
};

/**
 * Availability against the target, in words.
 *
 * THE EQUIVALENCE, so this is a restatement and not a second threshold:
 * `burnRate = errorRate / (1 - target)`, so `burnRate < 1` is exactly
 * `1 - availability < 1 - target` — availability strictly ABOVE the target. The
 * `warn` band opens at burn = 1.0 exactly, where availability EQUALS the target,
 * which is why its wording is "at or below" rather than "below".
 */
const AVAILABILITY_BAND: Record<SloBudget["tone"], string> = {
	ok: "above target",
	warn: "at or below target",
	error: "below target",
};

/** Tone → sub-line colour. Separate from the Badge tones because a sub-line is
 *  text on a card, not a chip: it takes the `-ink` tone directly. */
const BAND_INK: Record<SloBudget["tone"], string> = {
	ok: "text-ok-ink",
	warn: "text-warn-ink",
	error: "text-danger-ink",
};

/**
 * The page's EXISTING error-rate bands — `>5%` danger, `>1%` warn — unchanged in
 * value and only moved off the headline figure onto a worded sub-line. The
 * wording states the band itself so the tone is never the only channel.
 */
function errorRateBand(pct: number): { ink: string; text: string } {
	if (pct > 5) return { ink: "text-danger-ink", text: "over 5%" };
	if (pct > 1) return { ink: "text-warn-ink", text: "over 1%" };
	return { ink: "text-ok-ink", text: "at or under 1%" };
}

/* ── The per-(provider, model) table ───────────────────────────────────────── */

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
	// The widest request count in the set, for the share bar under each row's
	// identity cell. It is sized from `requests`, which the row DISPLAYS two
	// columns over — a shape for a number already on screen, never a new one.
	// Rows arrive ordered by the gateway and that order is left alone.
	const maxRequests = modelRows.reduce((m, r) => Math.max(m, r.requests), 0);

	// NO CARD HEADER. The section eyebrow above already reads "By provider &
	// model", and on the render the card repeated it word for word one row lower
	// — two headings for one table, costing a row and saying nothing twice. A
	// table is a flat structured surface, so `quiet`: the `<THead>` band carries
	// its own top rule and lands flush on the card's edge.
	return (
		<Card quiet className="overflow-hidden">
			{modelRows.length === 0 ? (
				<div className="px-6 py-2">
					<SloEmpty
						title="No SLO data yet"
						description="Spans will appear here once traffic is flowing through the gateway."
						action={{
							href: "/settings/providers",
							label: "Connect a provider",
						}}
					/>
				</div>
			) : (
				<Table>
					<THead>
						<TR>
							<TH>Provider / Model</TH>
							<TH numeric>Requests</TH>
							<TH numeric>Error rate</TH>
							<TH
								numeric
								title="True window percentiles — merged from the stored per-hour quantile states (not an average of hourly percentiles)."
							>
								p50
							</TH>
							<TH numeric>p95</TH>
							<TH numeric>p99</TH>
							<TH
								numeric
								className="text-action-ink"
								title="Gateway overhead p95 — the time Tracelane adds, EXCLUDING upstream generation. Compare with the p95 to the left: our slice is tiny."
							>
								Gateway ovh
							</TH>
							<TH numeric>Input tokens</TH>
							<TH numeric>Output tokens</TH>
						</TR>
					</THead>
					<TBody>
						{modelRows.map((s) => {
							const key = `${s.provider}::${s.model}`;
							const errorPct = s.error_rate_pct;
							const ovh = overheadByModel.get(key);
							const sharePct =
								maxRequests > 0 ? (s.requests / maxRequests) * 100 : 0;
							return (
								<TR key={key}>
									<TD className="min-w-[11rem]">
										<div className="font-medium text-xs text-ink">
											{s.provider || "—"}
										</div>
										<div className="font-mono text-xs text-ink-2">
											{s.model || "—"}
										</div>
										{/* Share of the busiest row's request count. `aria-hidden`
										    — the number itself is in the Requests column, and a bar
										    read aloud is noise. */}
										<div
											aria-hidden="true"
											className="mt-1.5 h-1 w-full max-w-[9rem] overflow-hidden rounded-full bg-surface-2"
										>
											<div
												className="h-full rounded-full bar-data"
												style={{ width: `${sharePct}%` }}
											/>
										</div>
									</TD>
									<TD numeric>{s.requests.toLocaleString()}</TD>
									<TD numeric className={errorRateBand(errorPct).ink}>
										{errorPct.toFixed(2)}%
									</TD>
									<TD numeric muted>
										{formatDuration(s.p50_ms)}
									</TD>
									<TD numeric muted>
										{formatDuration(s.p95_ms)}
									</TD>
									<TD numeric muted>
										{formatDuration(s.p99_ms)}
									</TD>
									<TD
										numeric
										className="text-action-ink"
										title="Gateway overhead p95 — Tracelane's own slice, excluding upstream generation"
									>
										{ovh && ovh > 0 ? formatDuration(ovh) : "—"}
									</TD>
									<TD numeric muted>
										{formatTokens(s.total_input_tokens)}
									</TD>
									<TD numeric muted>
										{formatTokens(s.total_output_tokens)}
									</TD>
								</TR>
							);
						})}
					</TBody>
				</Table>
			)}
		</Card>
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

async function SloData({ range }: { range?: string }) {
	const hours = rangeToHours(range);
	const label = rangeLabel(range);
	const bucketMs = rangeBucketMs(range);
	const bucketHours = Math.max(1, Math.round(bucketMs / 3_600_000));
	let modelRows: SloModelRow[];
	let timePoints: SloTimePoint[];
	try {
		// Gateway-proxied reads (Option 1) — the gateway owns the
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
				<div className="space-y-3">
					<WarmingBanner />
					<SectionLabel>By provider &amp; model</SectionLabel>
					<SloTable modelRows={[]} overheadByModel={new Map()} />
				</div>
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
	// R59: the REQUESTED window, so "— last {range}" above is true. See
	// app/slo/latency.ts ChartWindow for why a data-derived domain was the defect.
	const win = chartWindow(Date.now(), hours, bucketMs);
	const latencyPoints = latencyPointsFromTimeseries(timePoints, bucketMs, win);
	const budget = computeSloBudget(
		totalRequests,
		totalErrors,
		await availabilityTarget(),
	);

	// MIRRORS `LatencyTimeline`'s OWN GUARD (`points.length < 2 || drawable < 2`).
	// The chart refuses to draw below two measured buckets and says so in one grey
	// line — which used to leave that sentence and a full absolute TimeRuler for a
	// chart that is not there, sitting in a card sized for one. When it cannot
	// draw, the card shows an empty state instead; the primitive keeps its own
	// guard as defence in depth.
	const drawableBuckets = latencyPoints.filter((p) => p.p95 != null).length;
	const canChart = latencyPoints.length >= 2 && drawableBuckets >= 2;

	// An empty window is not a healthy one. `computeSloBudget` returns a full,
	// untouched budget at zero traffic (100% available, 0× burn) — correct
	// arithmetic, but "Healthy · above target" printed in green over a window with
	// no requests in it reads as a measurement. The numbers are untouched; only
	// the state WORDS step aside for the honest one.
	const noTraffic = totalRequests === 0;
	const health = BURN_HEALTH[budget.tone];
	const errBand = errorRateBand(overallErrorPct);
	// Bar for the budget-remaining cell, sized from the percentage the cell is
	// already printing. Over-budget (negative, or -Infinity at a 100% target)
	// clamps to an empty track — an honest floor, not a wrapped bar.
	const budgetBarPct = Number.isFinite(budget.budgetRemainingPct)
		? Math.max(0, Math.min(100, budget.budgetRemainingPct))
		: 0;

	const budgetKpis: Kpi[] = [
		{
			icon: "error-budget",
			label: "SLO target (your plan)",
			value: `${budget.targetPct.toFixed(1)}%`,
			sub: <span className="text-ink-3">contracted availability</span>,
		},
		{
			icon: "time",
			label: `Availability (${label})`,
			value: `${budget.availabilityPct.toFixed(3)}%`,
			sub: noTraffic ? (
				<span className="text-ink-3">no traffic in window</span>
			) : (
				<span className={BAND_INK[budget.tone]}>
					{AVAILABILITY_BAND[budget.tone]}
				</span>
			),
		},
		{
			icon: "error-budget",
			label: "Error budget remaining",
			value: formatBudgetRemaining(budget.budgetRemainingPct),
			sub: (
				<span
					aria-hidden="true"
					className="h-1 w-full max-w-[9rem] overflow-hidden rounded-full bg-surface-2"
				>
					<span
						className="block h-full rounded-full bar-data"
						style={{ width: `${budgetBarPct}%` }}
					/>
				</span>
			),
		},
	];

	const volumeKpis: Kpi[] = [
		{
			icon: "llm-calls",
			label: `LLM calls (${label})`,
			value: totalRequests.toLocaleString(),
			hint: "Model requests — one agent run can make several. Not the trace/conversation count (see Traces).",
		},
		{
			icon: "failure-signatures",
			label: "Error rate",
			value: `${overallErrorPct.toFixed(2)}%`,
			sub: noTraffic ? (
				<span className="text-ink-3">no traffic in window</span>
			) : (
				<span className={errBand.ink}>{errBand.text}</span>
			),
		},
		{
			icon: "tokens",
			label: "Input tokens",
			value: formatTokens(totalInputTokens),
		},
		{
			icon: "tokens",
			label: "Output tokens",
			value: formatTokens(totalOutputTokens),
		},
	];

	return (
		<div className="space-y-8">
			{/* Error budget — the SLO framing: pure arithmetic over the captured
			    error rate vs the availability target (product default) (zero new capture, the #3 edge). */}
			<section
				aria-label="Error budget, volume and errors"
				className="space-y-3"
			>
				{/* NO EYEBROW ABOVE THIS H2. On the render an "ERROR BUDGET" section
				    label sat directly on top of a heading that opens with the same two
				    words — the section grammar and the heading were saying one thing
				    twice, in two type styles, one row apart. The heading wins because it
				    carries the window and the target as well as the name; the state
				    badge takes the right-hand slot the eyebrow's rule was occupying. */}
				<div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-1">
					<div className="min-w-0">
						<h2 className="text-sm font-semibold text-ink">
							Error budget — last {label} vs a {budget.targetPct.toFixed(1)}%
							availability target
						</h2>
						<p className="mt-0.5 text-xs text-ink-3">
							Burn rate is the multiple of the sustainable error rate you're
							spending (1.0× = exactly on pace). Below 1.0× the budget lasts the
							window; above, it's exhausted early.
						</p>
					</div>
					{noTraffic ? (
						<Badge tone="neutral">No traffic</Badge>
					) : (
						<Badge tone={health.tone} title={health.title}>
							{health.label}
						</Badge>
					)}
				</div>
				<div className="grid grid-cols-1 gap-4 lg:grid-cols-12 lg:items-stretch">
					{/*
					 * BOTH METRIC STRIPS STACK IN THIS COLUMN, and that is a layout
					 * decision the RENDER forced. One 3-cell strip beside the gauge card
					 * left ~120px of blank sheet between the labels and the numbers,
					 * because a semicircular gauge plus its title and caption is roughly
					 * twice a strip's natural height. Two strips fill it almost exactly
					 * (`flex-1` splits any remainder), the volume group loses nothing —
					 * every cell is self-labelled and the strips separate on weight
					 * (primary lifted vs `quiet` flat) — and the page loses one whole
					 * `space-y-8` section gap.
					 */}
					<div className="flex flex-col gap-4 lg:col-span-8">
						{/* `lg:grow`, NOT `flex-1`, AND THE PHONE RENDER IS WHY. `flex-1` is
						    `flex: 1 1 0%` — basis ZERO — so on a 390px viewport, where the
						    column has no stretch to distribute, the two strips were forced to
						    equal halves and the taller one (three cells stacked at one
						    column) had its last reading sliced off by the Card's
						    `overflow-hidden`: "ERROR BUDGET REMAINING" printed a label and
						    half a numeral. `grow` keeps `basis: auto`, so a strip can take
						    spare height and can never be squeezed below its content. Scoped
						    to `lg` because that is the only breakpoint where the gauge card
						    beside it creates spare height at all. */}
						<MetricStrip
							className="lg:grow"
							cols="grid-cols-1 sm:grid-cols-3"
							items={budgetKpis}
						/>
						<MetricStrip
							quiet
							className="lg:grow"
							cols="grid-cols-2 lg:grid-cols-4"
							items={volumeKpis}
						/>
					</div>
					{/*
					 * THE ONE DELIBERATELY DARK CARD, in BOTH themes, because a burn
					 * signal should read as an instrument panel rather than as another
					 * white tile.
					 *
					 * THE BORDER IS LOAD-BEARING AND CANNOT BE `border-line`. In dark,
					 * `--surface-inverse` IS the canvas colour, so with no border the
					 * card has no edge at all beside cards that all carry a hairline.
					 * But `--line` is a LIGHT-SURFACE hairline, and on a near-black card
					 * in light theme it paints a bright ring. `border-ink-inverse/15`
					 * resolves to the same near-black step in BOTH themes — one
					 * expression, correct twice. Same treatment as the dashboard's
					 * error-budget card, deliberately.
					 */}
					<div className="flex h-full flex-col rounded-[var(--radius-card)] border border-ink-inverse/15 bg-surface-inverse p-6 lg:col-span-4">
						<div className="flex items-center gap-2.5">
							<MetricIcon name="error-budget" size={20} onInverse />
							<h2 className="t-card-title text-ink-inverse">Burn rate</h2>
						</div>
						{/*
						 * The burn rate is a VALUE AGAINST A THRESHOLD, which is the
						 * textbook case for a gauge — and it is the same arc the dashboard
						 * already draws for this exact number. SCALE: 0–2× across the arc,
						 * so the 1.0× pace line lands at dead centre and "left of the tick"
						 * / "right of the tick" is legible without reading a number. Above
						 * 2× the arc pins full and the NUMERAL keeps counting; the centre
						 * display is the real `formatBurnRate` value in every case, so a
						 * pinned arc can never be mistaken for a 2× reading.
						 */}
						<div className="flex flex-1 flex-col items-center justify-center pt-4">
							<Gauge
								onInverse
								value={
									Number.isFinite(budget.burnRate)
										? Math.min(100, (budget.burnRate / 2) * 100)
										: 100
								}
								marker={50}
								display={formatBurnRate(budget.burnRate)}
								label="burn rate"
							/>
							<p className="mt-1 text-center text-2xs text-ink-inverse opacity-60">
								1.0× = on pace
							</p>
						</div>
					</div>
				</div>
				{/* Plain-language "what's measured" — elevates SLO target / availability
				    / error budget to the same clarity the burn-rate line already has.
				    It sits WITH the metrics it explains now, and collapsed it costs one
				    row instead of a full-width block above the readings. */}
				{/* A STRIP, NOT A CARD, so `rounded-lg` (the control band) rather than
				    `--radius-card`, and the inert `--surface-2` well rather than the card
				    fill — collapsed it is a 40px disclosure bar, and at card radius on
				    card colour it read as a card that had failed to load its contents.
				    Same reasoning `WarmingBanner` records for its own radius. */}
				<details className="rounded-lg border border-line bg-surface-2 px-4 py-3 text-sm">
					<summary className="cursor-pointer text-xs font-medium text-ink">
						What's measured here
					</summary>
					<div className="mt-2 space-y-1.5 text-xs text-ink-2">
						<p>
							<span className="font-medium text-ink">SLO target</span> — the
							availability you're aiming for. The ceiling for how often a
							request may fail.
						</p>
						<p>
							<span className="font-medium text-ink">Availability</span> — your
							actual success rate this window, from the captured error rate (1 −
							errors ÷ requests).
						</p>
						<p>
							<span className="font-medium text-ink">Error budget</span> — how
							much failure the target still allows. At the target it's spent;
							past it, you're over.
						</p>
						<p>
							<span className="font-medium text-ink">Burn rate</span> — how fast
							you're spending that budget. 1.0× = on pace to use exactly the
							window's allowance; above exhausts it early, below leaves
							headroom.
						</p>
						<p className="text-ink-3">
							All computed from captured spans — no new instrumentation, no
							fabricated numbers.
						</p>
					</div>
				</details>
			</section>

			{/* No eyebrow: the card's own title names the section AND carries the
			    window and the timezone, so an "LATENCY" label above it would be the
			    same duplication the error-budget block just lost. */}
			<section aria-label="Latency" className="space-y-3">
				<Card className="flex flex-col p-6">
					<CardHead
						icon="latency"
						title={`Latency over time — last ${label} · UTC`}
						meta="true quantiles per bucket"
					/>
					{canChart ? (
						<>
							<LatencyTimeline points={latencyPoints} />
							{/* ADR-074 §7 — the one time axis. `preserveAspectRatio="none"`
							    means the chart svg stretches edge to edge, so the ruler
							    needs no inset. */}
							<TimeRuler
								startMs={win.startMs}
								endMs={win.endMs + bucketMs}
								ticks={4}
								mode="absolute"
							/>
						</>
					) : (
						<SloEmpty
							// The chart it replaces is `h-44` plus a ruler — ~200px — so the
							// card is very nearly the same height with and without data, and
							// the comb has a floor to sit on that is clear of the copy.
							className="min-h-56 justify-center"
							ghost={<GhostFloor />}
							title="No latency data yet"
							description="Per-bucket p50, p95 and p99 appear here once at least two buckets in the window carry traffic."
							action={{ href: "/gateway", label: "Gateway setup" }}
						/>
					)}
				</Card>
			</section>

			<section aria-label="By provider and model" className="space-y-3">
				<SectionLabel
					action={<span className="text-2xs text-ink-3">last {label}</span>}
				>
					By provider &amp; model
				</SectionLabel>
				<SloTable modelRows={modelRows} overheadByModel={overheadByModel} />
			</section>
		</div>
	);
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
		/* Page padding ramps with the viewport, matching the dashboard: a pinned
		   `px-2` gutter put the whole surface ~7px from the edge of the content
		   column at the 1440 root, which reads cramped no matter what the cards do
		   internally. */
		<div className="space-y-8 px-1 py-2 sm:px-2 sm:py-4 lg:px-3">
			{/* The header depends on no gateway read, so it stays OUTSIDE the Suspense
			    boundary: the page identifies itself and the range control becomes
			    clickable while the three reads are still in flight. */}
			<header className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
				<div>
					<h1 className="t-h1">SLOs</h1>
					<p className="mt-2 text-sm text-ink-2">
						Error budget, latency percentiles, and error rates by provider/model
						— last {rangeLabel(range)}
					</p>
				</div>
				<RangeControl />
			</header>
			<Suspense
				fallback={
					<div className="space-y-8">
						<div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
							<Skeleton className="h-32 rounded-[var(--radius-card)] lg:col-span-8" />
							<Skeleton className="h-32 rounded-[var(--radius-card)] lg:col-span-4" />
						</div>
						<Skeleton className="h-28 w-full rounded-[var(--radius-card)]" />
						<Skeleton className="h-64 w-full rounded-[var(--radius-card)]" />
					</div>
				}
			>
				<SloData range={range} />
			</Suspense>
		</div>
	);
}

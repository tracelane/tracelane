import { fmtCount } from "@/lib/metrics/format";
import { PageHeader } from "@tracelanedev/ui";
/**
 * Traces list page — recent traces for the authenticated tenant, with the
 * filter bar (#1 surface gap). Server Component: the gateway owns the
 * tenant-scoped ClickHouse query and resolves the tenant from the forwarded
 * token. Filters (status / model / time) are URL-encoded and passed straight
 * through to the gateway `/v1/traces` params — each reaches the WHERE clause.
 */

import { classifyTraceFetchError, noMatchCopy } from "@/app/traces/empty-state";
import {
	TRACE_EXPORT_PARAMS,
	TRACE_PAGE_PARAMS,
	type TraceParam,
	copyGatewayTraceFilters,
} from "@/app/traces/filter-registry";
import { EmptyTraces } from "@/components/empty-states/EmptyTraces";
import { WarmingBanner } from "@/components/empty-states/WarmingBanner";
import { WindowNotice } from "@/components/metrics/WindowNotice";
import { FilterBar } from "@/components/trace-viewer/FilterBar";
import { LiveTraces } from "@/components/trace-viewer/LiveTraces";
import { TraceExportControls } from "@/components/trace-viewer/TraceExportControls";
import {
	type TraceGroup,
	TraceGroupTable,
} from "@/components/trace-viewer/TraceGroupTable";
import {
	TraceList,
	type TraceSummary,
} from "@/components/trace-viewer/TraceList";
import { requireSession } from "@/lib/auth";
import {
	GatewayError,
	gatewayBaseUrl,
	gatewayGet,
	gatewayGetOrNull,
} from "@/lib/gateway";
import { getBulkSettings } from "@/lib/list-page-settings";
import { fetchTraceCountFor } from "@/lib/metrics/fetch";
import {
	type TimeRange,
	parseOptionalTimeRange,
	windowParams,
} from "@/lib/metrics/time-range";
import {
	EmptyState,
	ErrorState,
	LedgerSeqChip,
	SegmentedControl,
	Skeleton,
} from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";
import { Suspense } from "react";

export const metadata: Metadata = { title: "Traces — Tracelane" };

type SP = Record<string, string | undefined>;

/**
 * ADR-074 §7's ledger chip — ONE chip, at WORKSPACE scope, never per row.
 *
 * The scope is a correctness constraint, not a layout choice. The audit chain is
 * per-tenant, so a per-TRACE "verified" claim is one the data does not support (§9;
 * B-241/B-249 are what that costs). A RANGE says "this workspace's ledger runs
 * 15700–15799", which is true, checkable, and the one thing no competitor's dashboard
 * can show.
 *
 * Renders NOTHING when the range is absent — an empty ledger, an unentitled workspace,
 * or an unreachable gateway. `/v1/audit/ledger-range` omits `from`/`to` for an empty
 * ledger rather than sending 0–0, and 503s rather than reporting empty when it cannot
 * read; both arrive here as "no chip", which is the honest render for all three.
 */
async function LedgerChip() {
	const r = await gatewayGetOrNull<{
		from?: number;
		to?: number;
		total: number;
	}>("/v1/audit/ledger-range");
	if (!r || r.from === undefined || r.to === undefined) return null;
	return <LedgerSeqChip from={r.from} to={r.to} />;
}

/** Allowed page sizes (gateway clamps limit to 1..200). Default = 25. */
const VALID_SIZES = [25, 50, 100, 200] as const;
type PageSize = (typeof VALID_SIZES)[number];

/**
 * The same four sizes as `SegmentedControl` options. Derived, not re-typed, so a
 * size added to `VALID_SIZES` cannot go missing from the control. String values
 * because `?size=` is a URL param and the primitive is keyed on the param value.
 */
const SIZE_OPTIONS = VALID_SIZES.map((s) => ({
	value: String(s),
	label: String(s),
}));

/**
 * Parse the ?size= URL param; falls back to 25 for any invalid/missing value.
 * Anything outside the allowed set is clamped to the default, never errored.
 */
function parseSize(sp: SP): PageSize {
	const raw = sp.size;
	if (!raw) return 25;
	const v = Number(raw);
	return (VALID_SIZES as readonly number[]).includes(v) ? (v as PageSize) : 25;
}

const VALID_GROUPS = [
	"model",
	"operation",
	"status",
	"environment",
	"release",
	"service",
	"user",
	"tag",
] as const;

/**
 * Build a `/traces` URL that preserves the active filters and applies the
 * given overrides (e.g. advance/clear the keyset cursor). Undefined override
 * values drop the param — used to reset back to the newest page.
 */
function pageHref(
	sp: SP,
	overrides: Partial<Record<TraceParam, string | undefined>>,
): string {
	const merged: SP = { ...sp, ...overrides };
	const q = new URLSearchParams();
	for (const k of TRACE_PAGE_PARAMS) {
		const v = merged[k];
		if (v) q.set(k, v);
	}
	const s = q.toString();
	return s ? `/traces?${s}` : "/traces";
}

// The list's window comes from the shared grammar — `parseOptionalTimeRange`
// (`range=all` is the one explicit "no bound" opt-out; a since/until pair wins over
// a preset). Resolved ONCE per request in `TracesPage` so the list, the count, the
// group table and the live stream all ask for the same instant. It lives in
// lib/metrics because a Next page module may export only route fields.

/**
 * B-379 (2026-09-12): the gateway's list, count and groups queries ALWAYS carry a
 * window — a request with no `since` gets the gateway's 7-day default. "All
 * time" on this page must therefore be SENT, not implied: 365 days back, the
 * schema's retention backstop (`spans` TTL), so "all" means everything retained
 * rather than a silent week. One place, so the list, the count, the groups and
 * the live feed keep asking for the same instant.
 */
const ALL_TIME_LOOKBACK_MS = 365 * 24 * 60 * 60 * 1000;
function setWindow(q: URLSearchParams, w: TimeRange | null): void {
	if (w) {
		for (const [k, v] of windowParams(w)) q.set(k, v);
		return;
	}
	q.set("since", new Date(Date.now() - ALL_TIME_LOOKBACK_MS).toISOString());
}

/** Build the gateway `/v1/traces` query from the URL filters + the window. */
function buildQuery(sp: SP, w: TimeRange | null): string {
	const q = new URLSearchParams();
	q.set("limit", String(parseSize(sp)));
	copyGatewayTraceFilters(q, sp, "list");
	setWindow(q, w);
	return q.toString();
}

/**
 * A /traces href that sets the sort column and toggles direction (clicking the
 * active column flips desc↔asc; a new column starts desc). Resets the cursor.
 */
function sortHref(
	sp: SP,
	col: "start_time" | "duration" | "spans" | "cost" | "errors",
): string {
	const curSort = sp.sort ?? "start_time";
	const curOrder = sp.order ?? "desc";
	const order = curSort === col && curOrder === "desc" ? "asc" : "desc";
	return pageHref(sp, { sort: col, order, cursor: undefined });
}

/**
 * The active page filters as a query string, forwarded verbatim to
 * `/api/traces/export` (which translates them to gateway params + adds `format`).
 * Same params as the URL, minus cursor/limit — export is the whole filtered set.
 */
function buildExportBase(sp: SP): string {
	const q = new URLSearchParams();
	for (const { param } of TRACE_EXPORT_PARAMS) {
		if (param === "cursor") continue; // first download starts at the first row
		const value = sp[param];
		if (value) q.set(param, value);
	}
	return q.toString();
}

/** Gateway `/v1/traces/groups` query — the grouping dimension + the same filters. */
function buildGroupQuery(sp: SP, w: TimeRange | null): string {
	const q = new URLSearchParams();
	if (sp.group) q.set("by", sp.group);
	copyGatewayTraceFilters(q, sp, "group");
	setWindow(q, w);
	return q.toString();
}

/**
 * Gateway-form filter params for the live SSE feed — same status/model/range
 * translation as `buildQuery`, but no `limit` (the stream fixes it at 100) and
 * no `cursor` (live always shows the newest). Keeps the live feed in lock-step
 * with the filtered list.
 */
function buildStreamParams(sp: SP, w: TimeRange | null): string {
	const q = new URLSearchParams();
	copyGatewayTraceFilters(q, sp, "stream");
	setWindow(q, w);
	// A live tail reads UP TO NOW. The page's resolved `until` is frozen at render, so
	// sending it made every reconnect re-read the same window and no new trace could
	// ever appear (2026-09-27). A custom absolute window keeps its end — it is a
	// deliberate slice of the past, not a tail.
	if (!w || w.kind === "preset") q.delete("until");
	q.set("include_issues", "false");
	return q.toString();
}

/**
 * Pagination footer. The gateway returns an opaque keyset `next_cursor`
 * (present only when a full page came back, i.e. more rows may exist) — we
 * surface it as a real "Next" link instead of silently capping. Keyset paging
 * is forward-only, so we offer "Newest" (clear cursor) rather than a fake
 * "Previous" the backend can't honor.
 *
 * A compact size selector (25 / 50 / 100 / 200) lets power users expand the
 * window without leaving the page; selecting a size resets the cursor.
 */
function PaginationBar({
	sp,
	nextCursor,
	count,
	total,
}: {
	sp: SP;
	nextCursor: string | null;
	count: number;
	/** Tenant total matching the filters (the "N of TOTAL"); null if unavailable. */
	total: number | null;
}) {
	const paged = Boolean(sp.cursor);
	const pageSize = parseSize(sp);
	return (
		<div className="mt-4 flex flex-wrap items-center justify-between gap-y-2 text-sm text-ink-2">
			<span>
				{total !== null ? (
					<>
						{count} of {fmtCount(total)} trace{total === 1 ? "" : "s"}
						{" · "}
						{pageSize} per page
					</>
				) : (
					<>
						{count} trace{count === 1 ? "" : "s"} · {pageSize} per page
						{nextCursor ? " · more available" : ""}
					</>
				)}
			</span>
			<div className="flex items-center gap-3">
				{/* Page-size selector — the shared <SegmentedControl> in LINK mode,
				    with `linkAs={Link}` so it keeps SOFT client-side navigation. The
				    group gets an `aria-label` because its only visible label is the
				    "N per page" sentence at the other end of the row.

				    THIS COMMENT PREVIOUSLY SAID "plain hrefs with no client JS, exactly
				    as before", AND IT WAS BACKWARDS. Before the conversion this was a
				    `next/link` <Link> — client JS, soft navigation. The first cut of the
				    conversion rendered a bare <a>, which silently turned every page-size
				    click into a FULL DOCUMENT RELOAD; the URLs were byte-identical, so
				    nothing in the diff or the tests could see it. Caught by planting a
				    `window` marker across a click and observing it survive on <Link> and
				    vanish on <a>. `linkAs` restores the original mechanism.*/}
				<SegmentedControl
					linkAs={Link}
					label="Traces per page"
					value={String(pageSize)}
					options={SIZE_OPTIONS}
					hrefFor={(v) =>
						pageHref(sp, {
							size: v === "25" ? undefined : v,
							cursor: undefined,
						})
					}
				/>
				{paged && (
					<Link
						href={pageHref(sp, { cursor: undefined })}
						className="font-medium text-ink-2 underline underline-offset-2 hover:text-ink"
					>
						← Newest
					</Link>
				)}
				{nextCursor && (
					<Link
						href={pageHref(sp, { cursor: nextCursor })}
						className="font-medium text-ink-2 underline underline-offset-2 hover:text-ink"
					>
						Next {pageSize} →
					</Link>
				)}
			</div>
		</div>
	);
}

async function TracesData({
	query,
	sp,
	w,
}: { query: string; sp: SP; w: TimeRange | null }) {
	const gatewayUrl = gatewayBaseUrl();

	let traces: TraceSummary[];
	let nextCursor: string | null = null;
	try {
		const data = await gatewayGet<{
			traces: TraceSummary[];
			next_cursor: string | null;
		}>(`/v1/traces?${query}&include_issues=false`);
		traces = data.traces;
		nextCursor = data.next_cursor ?? null;
	} catch (err) {
		if (err instanceof GatewayError) {
			if (err.status === 400 && err.body?.error === "sort_window_too_wide") {
				const maxHours = Number(err.body.max_hours);
				return (
					<ErrorState
						title="Cost sort needs a shorter window"
						description={`Sort by cost needs a window of ≤ ${maxHours / 24} days. Select a shorter range to enable it.`}
						action={
							<div className="flex items-center gap-3">
								<button
									type="button"
									disabled
									title={`Cost sort needs a window of ≤ ${maxHours / 24} days`}
									className="cursor-not-allowed text-sm text-ink-3"
								>
									Cost sort unavailable
								</button>
								<Link
									href={pageHref(sp, {
										range: "24h",
										since: undefined,
										until: undefined,
										cursor: undefined,
									})}
									className="text-sm font-medium text-ink-2 underline underline-offset-2 hover:text-ink"
								>
									Use a 24-hour window
								</Link>
							</div>
						}
					/>
				);
			}
			// OBS-01. Classification is a pure, unit-tested function
			// (`empty-state.ts`) — a 4xx is a REJECTED request, not an
			// unreachable gateway, most commonly `?q=` forced below the 4-char
			// minimum (`trace_reads.rs::validate_search_term`). "error ≠ empty"
			// (CLAUDE.md §1): rendering the warming banner for a validation
			// failure would tell the user their gateway is down when it
			// answered them perfectly correctly.
			const failure = classifyTraceFetchError(err);
			if (failure.kind === "forbidden")
				return (
					<ErrorState
						title="You don't have access to trace data"
						description="Ask a workspace administrator for access."
					/>
				);
			if (failure.kind === "rejected") {
				return (
					<ErrorState
						title={sp.issue ? "Issue filter error" : "Search error"}
						description={failure.message}
						action={
							<Link
								href={pageHref(sp, {
									q: undefined,
									issue: undefined,
									cursor: undefined,
								})}
								className="text-sm font-medium text-ink-2 underline underline-offset-2 hover:text-ink"
							>
								{sp.issue ? "Clear filter" : "Clear search"}
							</Link>
						}
					/>
				);
			}
			// Gateway unreachable / 5xx ≠ zero rows: degrade to the warming empty-state.
			return (
				<>
					<WarmingBanner />
					<EmptyTraces gatewayUrl={gatewayUrl} />
				</>
			);
		}
		// Re-throw anything else (incl. NEXT_REDIRECT from the auth helper).
		throw err;
	}

	if (traces.length === 0) {
		// Paged past the last row (keyset cursor set) — offer a way back to the
		// newest page rather than the misleading "no data yet" state.
		if (sp.cursor) {
			return (
				<EmptyState
					title="No more traces"
					description="You've reached the end of the list for these filters."
					action={
						<Link
							href={pageHref(sp, { cursor: undefined })}
							className="text-sm font-medium text-ink-2 underline underline-offset-2 hover:text-ink"
						>
							← Newest
						</Link>
					}
				/>
			);
		}
		// Empty states, honest about the implicit 1h default window:
		//  · explicit filters (incl. a specific range pill) → "no match", widen/clear
		//  · no range param (the 1h default) → ambiguous (new tenant vs traffic
		//    older than 1h); serve both, with an all-time escape
		//  · explicit all-time, no filters → genuinely no data → full onboarding
		const contentFilter = Boolean(
			sp.issue ||
				sp.status ||
				sp.model ||
				sp.since ||
				sp.until ||
				sp.min_latency_ms ||
				sp.signature_id ||
				sp.q ||
				sp.end_user ||
				sp.agent ||
				sp.model_family,
		);
		const allTime = sp.range === "all" || sp.range === "";
		const windowPill = Boolean(sp.range) && !allTime;
		if (contentFilter || windowPill) {
			// OBS-01. Copy selection is a pure, unit-tested function
			// (`empty-state.ts`) — a SEARCH returning zero rows names the term
			// as the thing to change, distinct from "no data matches these
			// filters" (spec §2, proof #3).
			const copy = noMatchCopy(sp.q, sp.issue);
			return (
				<EmptyState
					title={copy.title}
					description={copy.description}
					action={
						<Link
							href={
								sp.issue
									? pageHref(sp, { issue: undefined, cursor: undefined })
									: sp.q
										? pageHref(sp, { q: undefined, cursor: undefined })
										: "/traces"
							}
							className="text-sm font-medium text-ink-2 underline underline-offset-2 hover:text-ink"
						>
							{sp.issue
								? "Clear filter"
								: sp.q
									? "Clear search"
									: "Clear filters"}
						</Link>
					}
				/>
			);
		}
		if (sp.range === undefined) {
			return (
				<EmptyState
					title="No traces in the last hour"
					description="Showing the last hour by default. New to Tracelane? Point your agent at the gateway and your first trace appears here. Already sending? Your traffic may be older than this window."
					action={
						<Link
							href="/traces?range=all"
							className="text-sm font-medium text-action-ink underline underline-offset-2 hover:text-ink"
						>
							View all time →
						</Link>
					}
				/>
			);
		}
		return <EmptyTraces gatewayUrl={gatewayUrl} />;
	}

	// Best-effort tenant total matching the filters, for the "N of M" footer —
	// the SAME window as the list (lib/metrics), never a second computation. An
	// unreachable count omits the total; it never fails the list render.
	const total = await fetchTraceCountFor(w, new URLSearchParams(query));
	const [bulk, session] = await Promise.all([
		getBulkSettings(),
		requireSession(),
	]);

	return (
		<>
			<TraceList
				withGenerationIssues
				key={query}
				selectable
				selectionMax={bulk.max}
				viewerRole={session.role}
				traces={traces}
				sort={sp.sort ?? "start_time"}
				order={sp.order ?? "desc"}
				durationHref={sortHref(sp, "duration")}
				startedHref={sortHref(sp, "start_time")}
				spansHref={sortHref(sp, "spans")}
				costHref={sortHref(sp, "cost")}
				errorsHref={sortHref(sp, "errors")}
			/>

			<PaginationBar
				sp={sp}
				nextCursor={nextCursor}
				count={traces.length}
				total={total}
			/>
		</>
	);
}

async function GroupData({
	by,
	query,
	sp,
}: { by: string; query: string; sp: SP }) {
	let groups: TraceGroup[];
	try {
		groups = await gatewayGet<TraceGroup[]>(`/v1/traces/groups?${query}`);
	} catch (err) {
		if (err instanceof GatewayError) {
			const failure = classifyTraceFetchError(err);
			if (failure.kind === "forbidden")
				return (
					<ErrorState
						title="You don't have access to trace data"
						description="Ask a workspace administrator for access."
					/>
				);
			if (failure.kind === "rejected")
				return (
					<ErrorState title="Filter error" description={failure.message} />
				);
			return (
				<>
					<WarmingBanner />
					<TraceGroupTable groups={[]} by={by} />
				</>
			);
		}
		throw err;
	}
	if (!groups.length && sp.issue)
		return (
			<EmptyState
				{...noMatchCopy(sp.q, sp.issue)}
				action={
					<Link
						href={pageHref(sp, { issue: undefined, cursor: undefined })}
						className="text-sm text-ink-2 underline"
					>
						Clear filter
					</Link>
				}
			/>
		);
	return <TraceGroupTable groups={groups} by={by} />;
}

// Queries ClickHouse at request time — never prerender.
export const dynamic = "force-dynamic";

export default async function TracesPage({
	searchParams,
}: {
	searchParams: Promise<SP>;
}) {
	const sp = await searchParams;
	const w = parseOptionalTimeRange(sp, {
		defaultPreset: "1h",
		nowMs: Date.now(),
	});
	const query = buildQuery(sp, w);
	const exportBase = buildExportBase(sp);
	const exportWindow = new URLSearchParams();
	setWindow(exportWindow, w);
	if (!exportWindow.has("until"))
		exportWindow.set("until", new Date().toISOString());
	const groupBy =
		sp.group && VALID_GROUPS.includes(sp.group as (typeof VALID_GROUPS)[number])
			? sp.group
			: null;
	const groupQuery = buildGroupQuery(sp, w);

	return (
		<div className="px-2 py-3 sm:px-4 sm:py-4">
			<div className="mb-4 flex flex-wrap items-center justify-between gap-3">
				<div className="flex items-baseline gap-3">
					<PageHeader title={<>Traces</>} />
					<Suspense fallback={null}>
						<LedgerChip />
					</Suspense>
				</div>
				<div className="flex items-center gap-4">
					<TraceExportControls
						baseQuery={exportBase}
						windowQuery={exportWindow.toString()}
					/>
				</div>
			</div>

			<FilterBar />

			{sp.failover === "true" && (
				<div className="mt-2 flex items-center gap-2 rounded-control border border-line bg-surface-2 px-3 py-1.5 text-xs text-ink-2">
					<span className="font-medium text-ink">Failover only</span>
					<span>— traces where a cross-provider failover fired.</span>
					<Link
						href={pageHref(sp, { failover: undefined })}
						className="ml-auto font-medium text-action-ink hover:underline"
					>
						Clear ✕
					</Link>
				</div>
			)}

			{(sp.since || sp.until) && (
				<div className="mt-2 flex items-center gap-2 rounded-control border border-line bg-surface-2 px-3 py-1.5 text-xs text-ink-2">
					<span className="font-medium text-ink">Custom time window</span>
					<span>— traces within the period you drilled into.</span>
					<Link
						href={pageHref(sp, { since: undefined, until: undefined })}
						className="ml-auto font-medium text-action-ink hover:underline"
					>
						Clear ✕
					</Link>
				</div>
			)}

			{w && <WindowNotice range={w} />}
			{sp.issue && (
				<p className="mb-2 text-xs text-ink-2">
					Window: {w?.label ?? "All time"}
				</p>
			)}
			{groupBy ? (
				<Suspense
					key={groupQuery}
					fallback={
						<div className="space-y-2">
							{[0, 1, 2].map((i) => (
								<Skeleton key={i} className="h-12 w-full" />
							))}
						</div>
					}
				>
					<GroupData by={groupBy} query={groupQuery} sp={sp} />
				</Suspense>
			) : (
				<LiveTraces streamParams={buildStreamParams(sp, w)}>
					<Suspense
						key={query}
						fallback={
							<div className="space-y-2">
								{[0, 1, 2, 3, 4].map((i) => (
									<Skeleton key={i} className="h-12 w-full" />
								))}
							</div>
						}
					>
						<TracesData query={query} sp={sp} w={w} />
					</Suspense>
				</LiveTraces>
			)}
		</div>
	);
}

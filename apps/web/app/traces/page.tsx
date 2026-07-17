/**
 * Traces list page — recent traces for the authenticated tenant, with the
 * filter bar (#1 surface gap). Server Component: the gateway owns the
 * tenant-scoped ClickHouse query and resolves the tenant from the forwarded
 * token. Filters (status / model / time) are URL-encoded and passed straight
 * through to the gateway `/v1/traces` params — each reaches the WHERE clause.
 */

import { EmptyTraces } from "@/components/empty-states/EmptyTraces";
import { WarmingBanner } from "@/components/empty-states/WarmingBanner";
import { FilterBar } from "@/components/trace-viewer/FilterBar";
import { LiveTraces } from "@/components/trace-viewer/LiveTraces";
import {
	type TraceGroup,
	TraceGroupTable,
} from "@/components/trace-viewer/TraceGroupTable";
import {
	TraceList,
	type TraceSummary,
} from "@/components/trace-viewer/TraceList";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import { EmptyState, Skeleton } from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";
import { Suspense } from "react";

export const metadata: Metadata = { title: "Traces — Tracelane" };

type SP = Record<string, string | undefined>;

/** Keyset page size — kept in sync with the gateway's per-page cap. */
const PAGE_SIZE = 50;

/** The page-facing filter params (not the gateway-derived ones). */
const PAGE_PARAMS = [
	"status",
	"model",
	"range",
	"since",
	"until",
	"min_latency_ms",
	"signature_id",
	"failover",
	"sort",
	"order",
	"group",
	"cursor",
] as const;

const VALID_GROUPS = ["model", "operation", "status"] as const;

/**
 * Build a `/traces` URL that preserves the active filters and applies the
 * given overrides (e.g. advance/clear the keyset cursor). Undefined override
 * values drop the param — used to reset back to the newest page.
 */
function pageHref(
	sp: SP,
	overrides: Partial<Record<(typeof PAGE_PARAMS)[number], string | undefined>>,
): string {
	const merged: SP = { ...sp, ...overrides };
	const q = new URLSearchParams();
	for (const k of PAGE_PARAMS) {
		const v = merged[k];
		if (v) q.set(k, v);
	}
	const s = q.toString();
	return s ? `/traces?${s}` : "/traces";
}

/**
 * RFC3339 lower-bound for a range preset, or null for "all time".
 *
 * No range param defaults to the last 24h so the list loads fast (the founder
 * ask — "All time" over the whole tenant is slow). The explicit "All time"
 * option passes `range=all` (or legacy `""`) to opt out and scan everything.
 */
function rangeSince(range: string | undefined): string | null {
	const r = range ?? "24h";
	const now = Date.now();
	const ms =
		r === "1h"
			? 3_600_000
			: r === "24h"
				? 86_400_000
				: r === "7d"
					? 604_800_000
					: r === "30d"
						? 2_592_000_000
						: 0; // "all" / "" / unknown → no lower bound (all time)
	return ms ? new Date(now - ms).toISOString() : null;
}

/** Build the gateway `/v1/traces` query from the URL filters. */
function buildQuery(sp: SP): string {
	const q = new URLSearchParams();
	q.set("limit", String(PAGE_SIZE));
	if (sp.model) q.set("model", sp.model);
	if (sp.min_latency_ms) q.set("min_latency_ms", sp.min_latency_ms);
	if (sp.signature_id) q.set("signature_id", sp.signature_id);
	if (sp.failover === "true") q.set("failover", "true");
	if (sp.status === "error") q.set("has_error", "true");
	else if (sp.status === "ok") q.set("has_error", "false");
	// A raw since/until window (e.g. a dashboard chart-click) wins over the range
	// preset; the gateway validates both as RFC3339 and rejects malformed input.
	const since = sp.since ?? rangeSince(sp.range);
	if (since) q.set("since", since);
	if (sp.until) q.set("until", sp.until);
	if (sp.sort) q.set("sort", sp.sort);
	if (sp.order) q.set("order", sp.order);
	if (sp.cursor) q.set("cursor", sp.cursor);
	return q.toString();
}

/**
 * A /traces href that sets the sort column and toggles direction (clicking the
 * active column flips desc↔asc; a new column starts desc). Resets the cursor.
 */
function sortHref(sp: SP, col: "start_time" | "duration" | "spans"): string {
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
	if (sp.status) q.set("status", sp.status);
	if (sp.model) q.set("model", sp.model);
	if (sp.range) q.set("range", sp.range);
	if (sp.min_latency_ms) q.set("min_latency_ms", sp.min_latency_ms);
	if (sp.signature_id) q.set("signature_id", sp.signature_id);
	if (sp.failover === "true") q.set("failover", "true");
	if (sp.sort) q.set("sort", sp.sort);
	if (sp.order) q.set("order", sp.order);
	return q.toString();
}

/** Gateway `/v1/traces/groups` query — the grouping dimension + the same filters. */
function buildGroupQuery(sp: SP): string {
	const q = new URLSearchParams();
	if (sp.group) q.set("by", sp.group);
	if (sp.model) q.set("model", sp.model);
	if (sp.min_latency_ms) q.set("min_latency_ms", sp.min_latency_ms);
	if (sp.signature_id) q.set("signature_id", sp.signature_id);
	if (sp.failover === "true") q.set("failover", "true");
	if (sp.status === "error") q.set("has_error", "true");
	else if (sp.status === "ok") q.set("has_error", "false");
	const since = sp.since ?? rangeSince(sp.range);
	if (since) q.set("since", since);
	if (sp.until) q.set("until", sp.until);
	return q.toString();
}

/**
 * Gateway-form filter params for the live SSE feed — same status/model/range
 * translation as `buildQuery`, but no `limit` (the stream fixes it at 100) and
 * no `cursor` (live always shows the newest). Keeps the live feed in lock-step
 * with the filtered list.
 */
function buildStreamParams(sp: SP): string {
	const q = new URLSearchParams();
	if (sp.model) q.set("model", sp.model);
	if (sp.min_latency_ms) q.set("min_latency_ms", sp.min_latency_ms);
	if (sp.signature_id) q.set("signature_id", sp.signature_id);
	if (sp.failover === "true") q.set("failover", "true");
	if (sp.status === "error") q.set("has_error", "true");
	else if (sp.status === "ok") q.set("has_error", "false");
	const since = sp.since ?? rangeSince(sp.range);
	if (since) q.set("since", since);
	if (sp.until) q.set("until", sp.until);
	return q.toString();
}

/**
 * Pagination footer. The gateway returns an opaque keyset `next_cursor`
 * (present only when a full page came back, i.e. more rows may exist) — we
 * surface it as a real "Next" link instead of silently capping at 50. Keyset
 * paging is forward-only, so we offer "Newest" (clear cursor) rather than a
 * fake "Previous" the backend can't honor.
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
	return (
		<div className="mt-4 flex items-center justify-between text-sm text-ink-2">
			<span>
				{total !== null ? (
					<>
						{count} of {total.toLocaleString()} trace{total === 1 ? "" : "s"}
						{" · "}
						{PAGE_SIZE} per page
					</>
				) : (
					<>
						{count} trace{count === 1 ? "" : "s"} · {PAGE_SIZE} per page
						{nextCursor ? " · more available" : ""}
					</>
				)}
			</span>
			<div className="flex items-center gap-4">
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
						Next {PAGE_SIZE} →
					</Link>
				)}
			</div>
		</div>
	);
}

async function TracesData({ query, sp }: { query: string; sp: SP }) {
	const gatewayUrl =
		process.env.NEXT_PUBLIC_GATEWAY_URL ?? "http://localhost:8080";

	let traces: TraceSummary[];
	let nextCursor: string | null = null;
	try {
		const data = await gatewayGet<{
			traces: TraceSummary[];
			next_cursor: string | null;
		}>(`/v1/traces?${query}`);
		traces = data.traces;
		nextCursor = data.next_cursor ?? null;
	} catch (err) {
		// Gateway unreachable ≠ zero rows: degrade to the warming empty-state.
		// Re-throw anything else (incl. NEXT_REDIRECT from the auth helper).
		if (err instanceof GatewayError) {
			return (
				<>
					<WarmingBanner />
					<EmptyTraces gatewayUrl={gatewayUrl} />
				</>
			);
		}
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
							className="text-[13px] font-medium text-ink-2 underline underline-offset-2 hover:text-ink"
						>
							← Newest
						</Link>
					}
				/>
			);
		}
		// Empty states, honest about the implicit 24h default window:
		//  · explicit filters (incl. a specific range pill) → "no match", widen/clear
		//  · no range param (the 24h default) → ambiguous (new tenant vs traffic
		//    older than 24h); serve both, with an all-time escape
		//  · explicit all-time, no filters → genuinely no data → full onboarding
		const contentFilter = Boolean(
			sp.status ||
				sp.model ||
				sp.since ||
				sp.until ||
				sp.min_latency_ms ||
				sp.signature_id,
		);
		const allTime = sp.range === "all" || sp.range === "";
		const windowPill = Boolean(sp.range) && !allTime;
		if (contentFilter || windowPill) {
			return (
				<EmptyState
					title="No traces match these filters"
					description="Try widening the time range or clearing the model filter."
					action={
						<Link
							href="/traces"
							className="text-[13px] font-medium text-ink-2 underline underline-offset-2 hover:text-ink"
						>
							Clear filters
						</Link>
					}
				/>
			);
		}
		if (sp.range === undefined) {
			return (
				<EmptyState
					title="No traces in the last 24 hours"
					description="Showing the last 24 hours. New to Tracelane? Point your agent at the gateway and your first trace appears here. Already sending? Your traffic may be older than this window."
					action={
						<Link
							href="/traces?range=all"
							className="text-[13px] font-medium text-accent-ink underline underline-offset-2 hover:text-ink"
						>
							View all time →
						</Link>
					}
				/>
			);
		}
		return <EmptyTraces gatewayUrl={gatewayUrl} />;
	}

	// Best-effort tenant total matching the filters, for the "50 of N" footer.
	// A failure just omits the total (never fails the list render).
	let total: number | null = null;
	try {
		const c = await gatewayGet<{ total: number }>(`/v1/traces/count?${query}`);
		total = typeof c.total === "number" ? c.total : null;
	} catch {
		total = null;
	}

	return (
		<>
			<TraceList
				traces={traces}
				sort={sp.sort ?? "start_time"}
				order={sp.order ?? "desc"}
				durationHref={sortHref(sp, "duration")}
				startedHref={sortHref(sp, "start_time")}
				spansHref={sortHref(sp, "spans")}
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

async function GroupData({ by, query }: { by: string; query: string }) {
	let groups: TraceGroup[];
	try {
		groups = await gatewayGet<TraceGroup[]>(`/v1/traces/groups?${query}`);
	} catch (err) {
		if (err instanceof GatewayError) {
			return (
				<>
					<WarmingBanner />
					<TraceGroupTable groups={[]} by={by} />
				</>
			);
		}
		throw err;
	}
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
	const query = buildQuery(sp);
	const exportBase = buildExportBase(sp);
	const exportPrefix = exportBase ? `${exportBase}&` : "";
	const groupBy =
		sp.group && VALID_GROUPS.includes(sp.group as (typeof VALID_GROUPS)[number])
			? sp.group
			: null;
	const groupQuery = buildGroupQuery(sp);

	return (
		<main className="mx-auto max-w-7xl p-6">
			<div className="mb-6 flex items-center justify-between">
				<h1 className="text-2xl font-semibold text-ink">Traces</h1>
				<div className="flex items-center gap-4">
					<div className="flex items-center gap-2 text-xs">
						<a
							href={`/api/traces/export?${exportPrefix}format=csv`}
							download
							className="rounded-md border border-line px-2.5 py-1.5 font-medium text-ink-2 transition-colors hover:border-line-2 hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
						>
							Export CSV
						</a>
						<a
							href={`/api/traces/export?${exportPrefix}format=json`}
							download
							className="rounded-md border border-line px-2.5 py-1.5 font-medium text-ink-3 transition-colors hover:text-ink-2 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
						>
							JSON
						</a>
					</div>
				</div>
			</div>

			<FilterBar />

			{sp.failover === "true" && (
				<div className="mt-2 flex items-center gap-2 rounded-md border border-line bg-surface-2/40 px-3 py-1.5 text-xs text-ink-2">
					<span className="font-medium text-ink">Failover only</span>
					<span>— traces where a cross-provider failover fired.</span>
					<Link
						href={pageHref(sp, { failover: undefined })}
						className="ml-auto font-medium text-accent-ink hover:underline"
					>
						Clear ✕
					</Link>
				</div>
			)}

			{(sp.since || sp.until) && (
				<div className="mt-2 flex items-center gap-2 rounded-md border border-line bg-surface-2/40 px-3 py-1.5 text-xs text-ink-2">
					<span className="font-medium text-ink">Custom time window</span>
					<span>— traces within the period you drilled into.</span>
					<Link
						href={pageHref(sp, { since: undefined, until: undefined })}
						className="ml-auto font-medium text-accent-ink hover:underline"
					>
						Clear ✕
					</Link>
				</div>
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
					<GroupData by={groupBy} query={groupQuery} />
				</Suspense>
			) : (
				<LiveTraces streamParams={buildStreamParams(sp)}>
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
						<TracesData query={query} sp={sp} />
					</Suspense>
				</LiveTraces>
			)}
		</main>
	);
}

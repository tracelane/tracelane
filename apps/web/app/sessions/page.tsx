/**
 * Sessions list page — multi-turn agent conversation view (PRD §5.2.3).
 *
 * Lists sessions for the authenticated tenant: groups of related traces
 * threaded by `gen_ai.conversation.id`. Reads via the per-user JWT through
 * the gateway `/v1/sessions` endpoint — no direct ClickHouse reads from the
 * dashboard (ADR-042).
 *
 * Sort (turns / cost / tokens / duration / last-activity) and filters
 * (status / model / date-range) are URL params forwarded straight to the
 * gateway — the ORDER BY / HAVING / WHERE are all server-side (never a
 * client-only re-sort of one page). Each row opens the session's ordered
 * turns at `/sessions/[id]` (each turn → its full trace).
 */

import { RangeControl } from "@/components/RangeControl";
import { WarmingBanner } from "@/components/empty-states/WarmingBanner";
import { WindowNotice } from "@/components/metrics/WindowNotice";
import { SessionFilters } from "@/components/sessions/SessionFilters";
import { SessionRow, parseDate } from "@/components/sessions/SessionRow";
import { fetchSessionsFor } from "@/lib/metrics/fetch";
import {
	MAX_SESSION_WINDOW_MS,
	type TimeRange,
	parseTimeRange,
} from "@/lib/metrics/time-range";
import type { SessionSummary } from "@/lib/sessions";
import { Card, EmptyState, Skeleton, TimeRuler } from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";
import { Suspense } from "react";

export const metadata: Metadata = { title: "Sessions — Tracelane" };

// Queries ClickHouse (via gateway) at request time — never prerender.
export const dynamic = "force-dynamic";

type SP = Record<string, string | undefined>;

/** Sortable columns → the gateway `sort` param (allowlisted both ends). */
type SortCol = "turns" | "cost" | "tokens" | "duration" | "last_activity";
const SORT_PARAMS = ["status", "model", "range", "sort", "order"] as const;

/**
 * A /sessions URL that sets the sort column and toggles direction (clicking the
 * active column flips desc↔asc; a new column starts desc). Preserves the active
 * status / model / range filters.
 */
function sortHref(sp: SP, col: SortCol): string {
	const curSort = sp.sort ?? "last_activity";
	const curOrder = sp.order ?? "desc";
	const order = curSort === col && curOrder === "desc" ? "asc" : "desc";
	const q = new URLSearchParams();
	for (const k of SORT_PARAMS) {
		const v = k === "sort" ? col : k === "order" ? order : sp[k];
		if (v) q.set(k, v);
	}
	return `/sessions?${q.toString()}`;
}

/** A sortable column header — a link that flips the sort + shows the arrow. */
/**
 * ADR-074 §7 on /sessions — the same Timeline column the traces list carries, for the
 * same reason: this table's x-axis is COLUMNS and its time axis is row order, so a
 * header ruler would align to nothing. The rows get a real time dimension and the ruler
 * lives in that column's own <th>.
 *
 * A session's START is derived: `last_activity - duration_us`. The gateway sends no
 * first_activity, and deriving it is exact rather than approximate — duration_us IS the
 * first-to-last span the "First → last" column already displays.
 */
function sessionWindow(
	rows: SessionSummary[],
): { startMs: number; endMs: number } | null {
	let startMs = Number.POSITIVE_INFINITY;
	let endMs = Number.NEGATIVE_INFINITY;
	for (const s of rows) {
		const end = parseDate(s.last_activity).getTime();
		if (!Number.isFinite(end)) continue;
		const start = end - Math.max(0, s.duration_us) / 1_000;
		if (start < startMs) startMs = start;
		if (end > endMs) endMs = end;
	}
	if (!Number.isFinite(startMs) || !(endMs > startMs)) return null;
	return { startMs, endMs };
}

function SortHeader({
	sp,
	col,
	label,
}: {
	sp: SP;
	col: SortCol;
	label: string;
}) {
	const active = (sp.sort ?? "last_activity") === col;
	const order = sp.order ?? "desc";
	return (
		<th className="px-3 py-1.5 text-right t-metric-label">
			<Link
				href={sortHref(sp, col)}
				className="inline-flex items-center gap-1 hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
			>
				{label}
				<span className="text-ink-3">
					{active ? (order === "desc" ? "▼" : "▲") : "↕"}
				</span>
			</Link>
		</th>
	);
}

async function SessionsData({ sp, range }: { sp: SP; range: TimeRange }) {
	const sessions = await fetchSessionsFor(range, {
		sort: sp.sort,
		order: sp.order,
		status: sp.status,
		model: sp.model,
	});

	// Unreachable ≠ empty (B-334): an outage used to render as "No sessions in
	// this window", which is a confident zero over a read that never happened.
	if (sessions === null) {
		return (
			<>
				<WarmingBanner />
				<EmptyState
					title="Waiting on the gateway"
					description="Sessions appear here once the gateway is reachable."
				/>
			</>
		);
	}

	if (sessions.length === 0) {
		const filtered = Boolean(sp.status || sp.model);
		return filtered ? (
			<EmptyState
				title="No sessions match these filters"
				description="Try widening the time range or clearing the status / model filter."
				action={
					<Link
						href="/sessions"
						className="text-sm font-medium text-ink-2 underline underline-offset-2 hover:text-ink"
					>
						Clear filters
					</Link>
				}
			/>
		) : (
			<EmptyState
				title="No sessions in this window"
				description="Sessions thread an agent's related traces by conversation id. Widen the range, or once your agents emit `gen_ai.conversation.id`, multi-turn runs show up here. Recording Claude Code? Run `tlane init claude-code`."
			/>
		);
	}

	// The list is capped at the gateway's default (50) with no cursor; when exactly
	// full, say so honestly rather than implying it's the complete set (audit #12).
	const atCap = sessions.length >= 50;
	// ADR-074 §7 — window from the ROWS, never a URL range (same rule as TraceList).
	const win = sessionWindow(sessions);

	return (
		<div className="space-y-2">
			<Card className="overflow-x-auto">
				<table className="w-full text-sm">
					<thead>
						<tr className="border-b border-line">
							<th className="px-3 py-1.5 text-left t-metric-label">Session</th>
							{/* OBS-20. Not sortable: sorting is an allowlisted ORDER BY on
							    the aggregate (`SessionSort`), and an identity column is a
							    thing you filter to, not a thing you rank by. */}
							<th
								className="px-3 py-1.5 text-left t-metric-label"
								title="Who initiated the session — the end-user id your application sent via the x-tracelane-user-id header. Empty when none was sent."
							>
								User
							</th>
							<SortHeader sp={sp} col="turns" label="Turns" />
							<th
								className="px-3 py-1.5 text-left t-metric-label"
								title="The latest model in the session. A session that switched models shows only the most recent — open the session to see every turn."
							>
								Model
							</th>
							{win && (
								<th
									className="w-[24%] min-w-[9rem] px-3 pt-1.5 pb-0.5 align-bottom"
									title="Each bar is one session, positioned by its real first→last span. UTC."
								>
									<span className="sr-only">Timeline</span>
									<TimeRuler
										startMs={win.startMs}
										endMs={win.endMs}
										ticks={4}
										mode="absolute"
									/>
								</th>
							)}
							<SortHeader sp={sp} col="tokens" label="Tokens" />
							<SortHeader sp={sp} col="duration" label="First → last" />
							<SortHeader sp={sp} col="cost" label="Cost" />
							<th className="px-3 py-1.5 text-left t-metric-label">Status</th>
							<SortHeader sp={sp} col="last_activity" label="Last activity" />
						</tr>
					</thead>
					<tbody>
						{sessions.map((s) => (
							<SessionRow key={s.session_id} s={s} win={win} />
						))}
					</tbody>
				</table>
			</Card>
			{atCap && (
				<p className="px-1 text-xs text-ink-3">
					Showing the first 50 sessions — narrow the date range or add filters
					to see more.
				</p>
			)}
			{/* OBS-20. Shown when there ARE sessions but not one carries a user id —
			    the expected state for a correctly deployed tenant that has simply
			    not instrumented it yet. Without this the User column is a row of
			    dashes that reads as broken, which is exactly how the existing
			    `x-human-authorizer` header came to be built and never once used:
			    nothing customer-readable ever mentioned it. */}
			{sessions.length > 0 && sessions.every((s) => !s.end_user) && (
				<p className="px-1 text-xs text-ink-3">
					No user ids yet — send an{" "}
					<code className="font-mono text-2xs">x-tracelane-user-id</code> header
					(or OpenAI&rsquo;s <code className="font-mono text-2xs">user</code>{" "}
					field) to attribute traces to your end users.{" "}
					<a
						className="text-action-ink hover:underline"
						href="https://docs.tracelane.dev/concepts"
					>
						Docs
					</a>
				</p>
			)}
			<p className="px-1 text-2xs text-ink-3">
				Tokens and cost are summed per session across all turns — they may
				double-count when usage is recorded on both a wrapper span and its inner
				span. “—” means unpriced or no usage, not necessarily zero.
			</p>
		</div>
	);
}

export default async function SessionsPage({
	searchParams,
}: {
	searchParams: Promise<SP>;
}) {
	const sp = await searchParams;
	// Sessions are sparse multi-turn aggregates, so a 24h default reads as "empty"
	// on low traffic — 30d, and the sessions family's own 90 d cap.
	const range = parseTimeRange(sp, {
		defaultPreset: "30d",
		nowMs: Date.now(),
		maxWidthMs: MAX_SESSION_WINDOW_MS,
	});
	return (
		<div className="px-2 py-3 sm:px-4 sm:py-4">
			<div className="mb-4 flex flex-wrap items-center justify-between gap-3">
				<div>
					<h1 className="t-h1">Sessions</h1>
					<p className="mt-1 text-sm text-ink-2">
						Multi-turn conversations grouped from related traces — {range.label}
						.
					</p>
				</div>
				<div className="flex flex-wrap items-center gap-2">
					<SessionFilters />
					<RangeControl defaultPreset="30d" />
				</div>
			</div>
			<WindowNotice range={range} />
			<Suspense
				// `range` intentionally OMITTED from the key: the RangeControl's
				// useTransition swaps the range data in place with no remount/flash
				// (consistent with dashboard/slo/gateway). The other filters still
				// key the boundary (their controls remount as before).
				key={`${sp.status ?? ""}|${sp.model ?? ""}|${sp.sort ?? ""}|${sp.order ?? ""}`}
				fallback={
					<div className="space-y-2">
						{[0, 1, 2, 3, 4].map((i) => (
							<Skeleton key={i} className="h-12 w-full" />
						))}
					</div>
				}
			>
				<SessionsData sp={sp} range={range} />
			</Suspense>
		</div>
	);
}

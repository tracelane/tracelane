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
import { SessionFilters } from "@/components/sessions/SessionFilters";
import { formatDateTimeUtc } from "@/lib/format-date";
import { rangeToHours } from "@/lib/range";
import { type SessionSummary, fetchSessions } from "@/lib/sessions";
import { Badge, Card, EmptyState, Skeleton } from "@tracelanedev/ui";
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

/** Format a ClickHouse toString datetime or ISO 8601 string for display. */
function parseDate(s: string): Date {
	// A "…T08:45:53" with a T but NO zone parses as LOCAL — anchor to UTC unless
	// the string already carries a zone (the naive-timestamp class; see parseUtcMs).
	const hasZone = /([zZ]|[+-]\d{2}:?\d{2})$/.test(s);
	return new Date(hasZone ? s : `${s.replace(" ", "T")}Z`);
}

function formatCost(usd: number): string {
	if (usd === 0) return "—";
	return `$${usd.toFixed(4)}`;
}

function formatTokens(n: number): string {
	if (n <= 0) return "—";
	if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
	if (n >= 1000) return `${(n / 1000).toFixed(1)}K`;
	return String(n);
}

function formatDuration(us: number): string {
	if (us <= 0) return "—";
	if (us < 1_000) return `${us}µs`;
	if (us < 1_000_000) return `${(us / 1_000).toFixed(1)}ms`;
	return `${(us / 1_000_000).toFixed(2)}s`;
}

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
		<th className="px-4 py-3 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
			<Link
				href={sortHref(sp, col)}
				className="inline-flex items-center gap-1 hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
			>
				{label}
				<span className="text-ink-3">
					{active ? (order === "desc" ? "▼" : "▲") : "↕"}
				</span>
			</Link>
		</th>
	);
}

function SessionRow({ s }: { s: SessionSummary }) {
	const isError = s.status === "error";
	return (
		<tr className="border-b border-line transition-colors last:border-0 hover:bg-surface-2/40">
			<td className="px-4 py-3">
				<Link
					href={`/sessions/${encodeURIComponent(s.session_id)}`}
					className="font-mono text-xs text-accent-ink hover:underline"
				>
					{s.session_id.length > 24
						? `${s.session_id.slice(0, 12)}…${s.session_id.slice(-8)}`
						: s.session_id}
				</Link>
			</td>
			<td className="px-4 py-3 tabular-nums text-right text-sm text-ink-2">
				{s.turns}
			</td>
			<td className="px-4 py-3 font-mono text-xs text-ink-2">
				{s.model || "—"}
			</td>
			<td className="px-4 py-3 tabular-nums text-right text-sm text-ink-2">
				{formatTokens(s.total_tokens)}
			</td>
			<td className="px-4 py-3 tabular-nums text-right text-sm text-ink-2">
				{formatDuration(s.duration_us)}
			</td>
			<td className="px-4 py-3 tabular-nums text-right text-sm text-ink-2">
				{formatCost(s.cost_usd)}
			</td>
			<td className="px-4 py-3">
				{isError ? (
					<Badge tone="danger">error</Badge>
				) : (
					<Badge tone="ok">ok</Badge>
				)}
			</td>
			<td className="px-4 py-3 text-right text-xs text-ink-2">
				{formatDateTimeUtc(parseDate(s.last_activity).toISOString())}
			</td>
		</tr>
	);
}

async function SessionsData({ sp }: { sp: SP }) {
	// Sessions are sparse multi-turn aggregates, so a 24h default reads as "empty"
	// on low traffic — default to 30d so recent conversations actually show.
	const since = new Date(
		Date.now() - rangeToHours(sp.range ?? "30d") * 3_600_000,
	).toISOString();
	const sessions = await fetchSessions({
		since,
		sort: sp.sort,
		order: sp.order,
		status: sp.status,
		model: sp.model,
	});

	if (sessions.length === 0) {
		const filtered = Boolean(sp.status || sp.model);
		return filtered ? (
			<EmptyState
				title="No sessions match these filters"
				description="Try widening the time range or clearing the status / model filter."
				action={
					<Link
						href="/sessions"
						className="text-[13px] font-medium text-ink-2 underline underline-offset-2 hover:text-ink"
					>
						Clear filters
					</Link>
				}
			/>
		) : (
			<EmptyState
				title="No sessions in this window."
				description="Sessions thread an agent's related traces by conversation id. Widen the range, or once your agents emit `gen_ai.conversation.id`, multi-turn runs show up here."
			/>
		);
	}

	// The list is capped at the gateway's default (50) with no cursor; when exactly
	// full, say so honestly rather than implying it's the complete set (audit #12).
	const atCap = sessions.length >= 50;

	return (
		<div className="space-y-2">
			<Card className="overflow-x-auto">
				<table className="w-full text-sm">
					<thead>
						<tr className="border-b border-line">
							<th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								Session
							</th>
							<SortHeader sp={sp} col="turns" label="Turns" />
							<th
								className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3"
								title="The latest model in the session. A session that switched models shows only the most recent — open the session to see every turn."
							>
								Model
							</th>
							<SortHeader sp={sp} col="tokens" label="Tokens" />
							<SortHeader sp={sp} col="duration" label="First → last" />
							<SortHeader sp={sp} col="cost" label="Cost" />
							<th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								Status
							</th>
							<SortHeader sp={sp} col="last_activity" label="Last activity" />
						</tr>
					</thead>
					<tbody>
						{sessions.map((s) => (
							<SessionRow key={s.session_id} s={s} />
						))}
					</tbody>
				</table>
			</Card>
			{atCap && (
				<p className="px-1 text-[12px] text-ink-3">
					Showing the first 50 sessions — narrow the date range or add filters
					to see more.
				</p>
			)}
			<p className="px-1 text-[11px] text-ink-3">
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
	return (
		<div className="px-2 py-3 sm:px-4 sm:py-4">
			<div className="mb-6 flex flex-wrap items-center justify-between gap-3">
				<div>
					<h1 className="t-h1">Sessions</h1>
					<p className="mt-1 text-sm text-ink-2">
						Multi-turn conversations grouped from related traces.
					</p>
				</div>
				<div className="flex flex-wrap items-center gap-2">
					<SessionFilters />
					<RangeControl defaultRange="30d" />
				</div>
			</div>
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
				<SessionsData sp={sp} />
			</Suspense>
		</div>
	);
}

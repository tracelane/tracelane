/**
 * Session detail page — ordered turn-by-turn trace thread for a single
 * multi-turn session.
 *
 * Fetches `/v1/sessions/:id/traces` via the per-user JWT (no static bearer —
 * links to its full trace detail at `/traces/[traceId]`. A null gateway
 * result (404 or any GatewayError) calls `notFound()` — the gateway returns
 * the SAME 404 for "session missing" and "not this tenant's", so existence
 * never leaks across tenants.
 */

import { type SessionTraceRow, fetchSessionTraces } from "@/lib/sessions";
import { Badge, EmptyState, Skeleton } from "@tracelanedev/ui";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Suspense } from "react";

interface Props {
	params: Promise<{ sessionId: string }>;
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
	const { sessionId } = await params;
	const label =
		sessionId.length > 16 ? `${sessionId.slice(0, 16)}…` : sessionId;
	return { title: `Session ${label} — Tracelane` };
}

// Queries ClickHouse (via gateway) at request time — never prerender.
export const dynamic = "force-dynamic";

function formatDuration(us: number): string {
	if (us < 1_000) return `${us}µs`;
	if (us < 1_000_000) return `${(us / 1_000).toFixed(1)}ms`;
	return `${(us / 1_000_000).toFixed(2)}s`;
}

/** Format a ClickHouse toString datetime or ISO 8601 string for display. */
function parseDate(s: string): Date {
	return new Date(s.includes("T") ? s : `${s.replace(" ", "T")}Z`);
}

function TurnRow({ turn, index }: { turn: SessionTraceRow; index: number }) {
	const isError = turn.error_count > 0;
	return (
		<tr className="border-b border-line transition-colors last:border-0 hover:bg-surface-2/40">
			<td className="px-4 py-3 tabular-nums text-sm text-ink-2">{index}</td>
			<td className="px-4 py-3">
				<Link
					href={`/traces/${encodeURIComponent(turn.trace_id)}`}
					className="font-mono text-xs text-info hover:underline"
				>
					{turn.root_name || turn.trace_id.slice(0, 16)}
				</Link>
				<span className="ml-2 font-mono text-[11px] text-ink-3">
					{turn.trace_id.slice(0, 8)}
				</span>
			</td>
			<td className="px-4 py-3 text-xs text-ink-2">
				{parseDate(turn.start_time).toLocaleString()}
			</td>
			<td className="px-4 py-3 tabular-nums text-right text-xs text-ink-2">
				{formatDuration(turn.duration_us)}
			</td>
			<td className="px-4 py-3 tabular-nums text-right text-xs text-ink-2">
				{turn.span_count}
			</td>
			<td className="px-4 py-3">
				{isError ? (
					<Badge tone="danger">
						{turn.error_count} error{turn.error_count > 1 ? "s" : ""}
					</Badge>
				) : (
					<Badge tone="ok">ok</Badge>
				)}
			</td>
			<td className="px-4 py-3 font-mono text-xs text-ink-2">
				{turn.model || "—"}
			</td>
		</tr>
	);
}

async function SessionDetail({ sessionId }: { sessionId: string }) {
	const result = await fetchSessionTraces(sessionId);
	if (result === null) {
		// Gateway 404 — same response for "session missing" and "not this
		// tenant's". notFound() is consistent with that (no cross-tenant leak).
		notFound();
	}

	const { traces } = result;

	if (traces.length === 0) {
		return (
			<EmptyState
				title="No traces in this session yet."
				description="The session exists but has no recorded traces. They'll appear as the agent runs."
			/>
		);
	}

	// Summarise the model across turns. If all traces share one model, show it;
	// if mixed, label as "multiple". Avoids fabricating a summary that doesn't
	// reflect the data.
	const uniqueModels = [
		...new Set(traces.map((t) => t.model).filter((m) => m.length > 0)),
	];
	const modelLabel =
		uniqueModels.length === 1
			? (uniqueModels[0] ?? "—")
			: uniqueModels.length > 1
				? "multiple"
				: "—";

	return (
		<>
			<div className="mb-4 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-ink-2">
				<span>
					<span className="font-medium text-ink">{traces.length}</span>{" "}
					{traces.length === 1 ? "turn" : "turns"}
				</span>
				<span className="font-mono">{modelLabel}</span>
			</div>
			<div className="overflow-x-auto rounded-xl border border-line">
				<table className="w-full text-sm">
					<thead>
						<tr className="border-b border-line bg-surface-2/60">
							<th className="px-4 py-3 text-left text-xs font-medium text-ink-2">
								#
							</th>
							<th className="px-4 py-3 text-left text-xs font-medium text-ink-2">
								Operation
							</th>
							<th className="px-4 py-3 text-left text-xs font-medium text-ink-2">
								Started
							</th>
							<th className="px-4 py-3 text-right text-xs font-medium text-ink-2">
								Duration
							</th>
							<th className="px-4 py-3 text-right text-xs font-medium text-ink-2">
								Spans
							</th>
							<th className="px-4 py-3 text-left text-xs font-medium text-ink-2">
								Status
							</th>
							<th className="px-4 py-3 text-left text-xs font-medium text-ink-2">
								Model
							</th>
						</tr>
					</thead>
					<tbody>
						{traces.map((turn, i) => (
							<TurnRow key={turn.trace_id} turn={turn} index={i + 1} />
						))}
					</tbody>
				</table>
			</div>
		</>
	);
}

export default async function SessionDetailPage({ params }: Props) {
	const { sessionId } = await params;

	return (
		<main className="mx-auto max-w-7xl p-6">
			<div className="mb-6 flex items-center gap-3">
				<Link
					href="/sessions"
					className="shrink-0 text-sm text-ink-2 transition-colors hover:text-ink"
				>
					← Back to sessions
				</Link>
				<h1 className="min-w-0 flex-1 truncate font-mono text-xl font-semibold text-ink">
					{sessionId}
				</h1>
			</div>
			<Suspense
				fallback={
					<div className="space-y-1.5">
						<Skeleton className="h-9 w-[92%]" />
						<Skeleton className="h-9 w-[83%]" />
						<Skeleton className="h-9 w-[74%]" />
					</div>
				}
			>
				<SessionDetail sessionId={sessionId} />
			</Suspense>
		</main>
	);
}

"use client";

/**
 * TraceList — client component that renders a table of trace summaries.
 *
 * Whole-row click navigates to the trace detail page. The inner Link in the
 * operation cell preserves keyboard accessibility. Status column uses the
 * shared Badge primitive: ok / danger / warn — never Lava text on links.
 *
 * Columns: root operation, model, duration, spans, tokens, cost, status, started.
 */

import { Badge, EmptyState } from "@tracelanedev/ui";
import Link from "next/link";
import { useRouter } from "next/navigation";

export type TraceSummary = {
	trace_id: string;
	root_name: string;
	start_time: string;
	duration_us: number;
	span_count: number;
	error_count: number;
	intervention: number;
	model: string;
	/** Summed real cost (USD) over the trace's spans; 0 when unpriced. */
	cost_usd: number;
	/** Summed input + output tokens over the trace's spans; 0 when no usage. */
	total_tokens: number;
};

function formatDuration(us: number): string {
	if (us < 1_000) return `${us}µs`;
	if (us < 1_000_000) return `${(us / 1_000).toFixed(1)}ms`;
	return `${(us / 1_000_000).toFixed(2)}s`;
}

/** Cost as USD; `—` for zero/absent so the column reads honestly, not "$0.00". */
function formatCost(usd: number): string {
	if (!usd) return "—";
	return usd < 0.01 ? `$${usd.toFixed(4)}` : `$${usd.toFixed(2)}`;
}

/** Compact token count (1.2K / 1.4M); `—` for zero/absent. */
function formatTokens(n: number): string {
	if (!n) return "—";
	if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
	if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
	return `${n}`;
}

/**
 * Relative time label from an ISO timestamp ("2h ago", "just now").
 * The full ISO string is exposed via the <time> title attribute.
 * suppressHydrationWarning is required: SSR and client render at different
 * wall-clock offsets; the client value is correct.
 */
function relativeTime(iso: string): string {
	const diff = Date.now() - new Date(iso).getTime();
	if (diff < 60_000) return "just now";
	if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
	if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
	const days = Math.floor(diff / 86_400_000);
	if (days < 30) return `${days}d ago`;
	return new Date(iso).toISOString().slice(0, 10);
}

/**
 * Intervention / policy badge. Severity is deliberately distinct from runtime
 * errors so a policy-block (warn amber) is never confused with a crash (danger
 * red). Both levels share the warn amber to indicate "guardrail acted"; the
 * text label ("blocked" vs "warned") distinguishes the outcome.
 *
 * blocked (2) = warn — pre-flight policy enforcement stopped the action
 * warned  (1) = warn — advisory raised, action continued
 */
function InterventionBadge({ level }: { level: number }) {
	if (level === 0) return null;
	return <Badge tone="warn">{level === 2 ? "blocked" : "warned"}</Badge>;
}

/** Sortable column header — uppercase-muted grammar + seal focus ring. */
function SortHeader({
	label,
	href,
	active,
	order,
	align = "text-left",
}: {
	label: string;
	href: string;
	active: boolean;
	order: string;
	align?: string;
}) {
	return (
		<th
			className={`px-4 py-2 text-[10px] font-semibold uppercase tracking-wide text-ink-3 ${align}`}
		>
			<a
				href={href}
				className="inline-flex items-center gap-1 transition-colors hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
			>
				{label}
				<span className="text-[10px]">
					{active ? (order === "asc" ? "↑" : "↓") : "↕"}
				</span>
			</a>
		</th>
	);
}

export function TraceList({
	traces,
	sort = "start_time",
	order = "desc",
	durationHref,
	startedHref,
	spansHref,
}: {
	traces: TraceSummary[];
	sort?: string;
	order?: string;
	durationHref?: string;
	startedHref?: string;
	spansHref?: string;
}) {
	const router = useRouter();

	if (traces.length === 0) {
		return (
			<EmptyState
				title="No traces yet"
				description="Point your agents at the gateway to start capturing traces."
			/>
		);
	}

	return (
		<div className="overflow-x-auto rounded-lg border border-line">
			<table className="w-full text-sm">
				<thead className="bg-surface-2">
					<tr>
						<th className="px-4 py-2 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
							Operation
						</th>
						<th className="px-4 py-2 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
							Model
						</th>
						{durationHref ? (
							<SortHeader
								label="Duration"
								href={durationHref}
								active={sort === "duration"}
								order={order}
								align="text-right"
							/>
						) : (
							<th className="px-4 py-2 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								Duration
							</th>
						)}
						{spansHref ? (
							<SortHeader
								label="Spans"
								href={spansHref}
								active={sort === "spans"}
								order={order}
								align="text-right"
							/>
						) : (
							<th className="px-4 py-2 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								Spans
							</th>
						)}
						<th className="px-4 py-2 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
							Tokens
						</th>
						<th className="px-4 py-2 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
							Cost
						</th>
						<th className="px-4 py-2 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
							Status
						</th>
						{startedHref ? (
							<SortHeader
								label="Started"
								href={startedHref}
								active={sort === "start_time"}
								order={order}
							/>
						) : (
							<th className="px-4 py-2 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								Started
							</th>
						)}
					</tr>
				</thead>
				<tbody className="divide-y">
					{traces.map((t) => (
						// biome-ignore lint/a11y/useKeyWithClickEvents: keyboard users navigate via the focusable name Link below (same href); the row onClick is a mouse-only convenience, not the sole path.
						<tr
							key={t.trace_id}
							className="cursor-pointer transition-colors hover:bg-surface-2 active:bg-accent-soft focus-within:bg-surface-2"
							onClick={() => router.push(`/traces/${t.trace_id}`)}
						>
							<td className="px-4 py-2.5">
								<Link
									href={`/traces/${t.trace_id}`}
									onClick={(e) => e.stopPropagation()}
									className="font-medium text-ink hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
								>
									{t.root_name || t.trace_id.slice(0, 16)}
								</Link>
								<span className="ml-2 font-mono text-xs text-ink-3">
									{t.trace_id.slice(0, 8)}
								</span>
							</td>
							<td className="px-4 py-2.5 font-mono text-xs text-ink-2">
								{t.model || "—"}
							</td>
							<td className="px-4 py-2.5 text-right font-mono text-xs tabular-nums">
								{formatDuration(t.duration_us)}
							</td>
							<td className="px-4 py-2.5 text-right font-mono text-xs tabular-nums">
								{t.span_count}
							</td>
							<td className="px-4 py-2.5 text-right font-mono text-xs tabular-nums">
								{formatTokens(t.total_tokens)}
							</td>
							<td className="px-4 py-2.5 text-right font-mono text-xs tabular-nums">
								{formatCost(t.cost_usd)}
							</td>
							<td className="px-4 py-2.5">
								<div className="flex items-center gap-1.5">
									{t.error_count > 0 && (
										<Badge tone="danger">
											{t.error_count} error{t.error_count > 1 ? "s" : ""}
										</Badge>
									)}
									<InterventionBadge level={t.intervention} />
									{t.error_count === 0 && t.intervention === 0 && (
										<Badge tone="ok">OK</Badge>
									)}
								</div>
							</td>
							<td className="px-4 py-2.5 tabular-nums text-xs text-ink-3">
								<time
									dateTime={t.start_time}
									title={t.start_time}
									suppressHydrationWarning
								>
									{relativeTime(t.start_time)}
								</time>
							</td>
						</tr>
					))}
				</tbody>
			</table>
		</div>
	);
}

/**
 * TraceGroupTable — server component: traces grouped by a dimension (model /
 * operation / status) with per-group count, error rate, and avg/p95 duration.
 * Data from GET /v1/traces/groups. The group key links back to the filtered
 * trace list where a matching list filter exists (model, status).
 */

import { EmptyState } from "@tracelanedev/ui";
import Link from "next/link";

export type TraceGroup = {
	group_key: string;
	trace_count: number;
	error_traces: number;
	avg_duration_us: number;
	p95_duration_us: number;
};

function fmtDuration(us: number): string {
	if (us < 1_000) return `${Math.round(us)}µs`;
	if (us < 1_000_000) return `${(us / 1_000).toFixed(1)}ms`;
	return `${(us / 1_000_000).toFixed(2)}s`;
}

/** Link to the filtered trace list when the group dimension is a list filter. */
function groupFilterHref(by: string, key: string): string | null {
	if (by === "model") return `/traces?model=${encodeURIComponent(key)}`;
	if (by === "status")
		return `/traces?status=${key === "error" ? "error" : "ok"}`;
	return null; // operation (root_name) isn't a list filter
}

export function TraceGroupTable({
	groups,
	by,
}: {
	groups: TraceGroup[];
	by: string;
}) {
	if (groups.length === 0) {
		return (
			<EmptyState
				title="No traces to group"
				description="No traces match the current filters for this grouping."
			/>
		);
	}
	const label =
		by === "model" ? "Model" : by === "operation" ? "Operation" : "Status";
	return (
		<div className="overflow-x-auto rounded-lg border border-line">
			<table className="w-full text-sm">
				<thead className="bg-surface-2">
					<tr>
						<th className="px-4 py-2 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
							{label}
						</th>
						<th className="px-4 py-2 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
							Traces
						</th>
						<th className="px-4 py-2 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
							Error rate
						</th>
						<th className="px-4 py-2 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
							Avg
						</th>
						<th className="px-4 py-2 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
							p95
						</th>
					</tr>
				</thead>
				<tbody className="divide-y">
					{groups.map((g) => {
						const href = groupFilterHref(by, g.group_key);
						const errPct =
							g.trace_count > 0 ? (g.error_traces / g.trace_count) * 100 : 0;
						return (
							<tr
								key={g.group_key}
								className="transition-colors hover:bg-surface-2"
							>
								<td className="px-4 py-2.5 font-mono text-xs">
									{href ? (
										<Link
											href={href}
											className="text-ink-2 underline-offset-2 hover:text-ink hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
										>
											{g.group_key || "—"}
										</Link>
									) : (
										g.group_key || "—"
									)}
								</td>
								<td className="px-4 py-2.5 text-right font-mono text-xs tabular-nums">
									{g.trace_count.toLocaleString()}
								</td>
								<td className="px-4 py-2.5 text-right">
									<span
										className={`font-mono text-xs tabular-nums ${errPct > 5 ? "text-danger" : errPct > 1 ? "text-warn" : "text-ok"}`}
									>
										{errPct.toFixed(1)}%
									</span>
								</td>
								<td className="px-4 py-2.5 text-right font-mono text-xs tabular-nums">
									{fmtDuration(g.avg_duration_us)}
								</td>
								<td className="px-4 py-2.5 text-right font-mono text-xs tabular-nums">
									{fmtDuration(g.p95_duration_us)}
								</td>
							</tr>
						);
					})}
				</tbody>
			</table>
		</div>
	);
}

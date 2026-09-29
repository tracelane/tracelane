import { fmtCount } from "@/lib/metrics/format";
import { fmtDur } from "@tracelanedev/ui";
import { TBody, TD, TH, THead, TR, Table } from "@tracelanedev/ui";
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

const fmtDuration = fmtDur;

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
				description="Grouping summarises the traces the filters return, and right now they return none. Widen the time range or clear a filter."
			/>
		);
	}
	const label =
		by === "model" ? "Model" : by === "operation" ? "Operation" : "Status";
	return (
		<div className="overflow-x-auto rounded-card border border-line">
			<Table className="w-full text-sm">
				<THead className="bg-surface-2">
					<TR>
						<TH className="px-3 py-1.5 text-left t-metric-label">{label}</TH>
						<TH className="px-3 py-1.5 text-right t-metric-label">Traces</TH>
						<TH className="px-3 py-1.5 text-right t-metric-label">
							Error rate
						</TH>
						<TH className="px-3 py-1.5 text-right t-metric-label">Avg</TH>
						<TH className="px-3 py-1.5 text-right t-metric-label">p95</TH>
					</TR>
				</THead>
				<TBody className="divide-y">
					{groups.map((g) => {
						const href = groupFilterHref(by, g.group_key);
						const errPct =
							g.trace_count > 0 ? (g.error_traces / g.trace_count) * 100 : 0;
						return (
							<TR
								key={g.group_key}
								className="transition-colors hover:bg-surface-hover"
							>
								<TD className="px-3 py-2 font-mono text-xs">
									{href ? (
										<Link
											href={href}
											className="text-ink-2 underline-offset-2 hover:text-ink hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
										>
											{g.group_key || "—"}
										</Link>
									) : (
										g.group_key || "—"
									)}
								</TD>
								<TD className="px-3 py-2 text-right font-mono text-xs tabular-nums">
									{fmtCount(g.trace_count)}
								</TD>
								<TD className="px-3 py-2 text-right">
									<span
										className={`font-mono text-xs tabular-nums ${errPct > 5 ? "text-danger-ink" : errPct > 1 ? "text-warn-ink" : "text-ok-ink"}`}
									>
										{errPct.toFixed(1)}%
									</span>
								</TD>
								<TD className="px-3 py-2 text-right font-mono text-xs tabular-nums">
									{fmtDuration(g.avg_duration_us)}
								</TD>
								<TD className="px-3 py-2 text-right font-mono text-xs tabular-nums">
									{fmtDuration(g.p95_duration_us)}
								</TD>
							</TR>
						);
					})}
				</TBody>
			</Table>
		</div>
	);
}

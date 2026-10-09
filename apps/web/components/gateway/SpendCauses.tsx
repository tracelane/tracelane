"use client";
import { ApiError, apiFetch } from "@/lib/api-fetch";
import { fmtUsd } from "@/lib/metrics/format";
import { Button } from "@tracelanedev/ui";
import { useEffect, useState } from "react";
export type SpendCausesData = {
	by: string;
	bucket: {
		start: string;
		end: string;
		cost_usd_series: number;
		cost_usd_spans: number;
	};
	available_dimensions: string[];
	rows: {
		dimension: string;
		cost_usd: number;
		share_pct: number | null;
		requests: number;
		unpriced_requests: number;
		baseline_usd?: number;
		excess_usd?: number;
		traces_href: string | null;
	}[];
	unattributed: { unpriced_requests: number; unlabelled_cost_usd: number };
	overlapping_dimensions: boolean;
};
const DIMENSIONS = [
	"model",
	"key",
	"provider",
	"environment",
	"service",
	"user",
	"tag",
];
function missingLabel(d: string): string {
	const header =
		d === "environment"
			? "x-tracelane-environment"
			: d === "service"
				? "x-tracelane-service"
				: d === "tag"
					? "x-tracelane-tags"
					: null;
	return header
		? `No LLM requests in this window carry this label — set ${header} (see docs)`
		: `No LLM requests in this window carry ${d}.`;
}
export function SpendCausesView({
	data,
	onDimension,
}: { data: SpendCausesData; onDimension: (d: string) => void }) {
	const baselines = data.rows.some((r) => r.baseline_usd !== undefined);
	const raw = data.bucket.cost_usd_spans;
	const series = data.bucket.cost_usd_series;
	const discrepancy = raw !== 0 ? Math.abs((series / raw - 1) * 100) : null;
	const unit =
		Date.parse(data.bucket.end) - Date.parse(data.bucket.start) === 3600000
			? "hour"
			: "day";
	return (
		<div className="space-y-3">
			<h3 className="text-sm font-semibold">Largest contributors</h3>
			<fieldset className="flex flex-wrap gap-2" aria-label="Spend dimension">
				{DIMENSIONS.map((d) => (
					<span
						key={d}
						title={
							data.available_dimensions.includes(d)
								? undefined
								: missingLabel(d)
						}
					>
						<Button
							variant="secondary"
							size="sm"
							aria-pressed={data.by === d}
							disabled={!data.available_dimensions.includes(d)}
							onClick={() => onDimension(d)}
						>
							{d}
						</Button>
					</span>
				))}
			</fieldset>
			{DIMENSIONS.filter(
				(d) =>
					!data.available_dimensions.includes(d) &&
					["environment", "service", "tag"].includes(d),
			).map((d) => (
				<p key={d} className="text-xs text-ink-3">
					{missingLabel(d)}
				</p>
			))}
			<p className="text-xs text-ink-3">
				Series total: {fmtUsd(series)} · Raw spans total: {fmtUsd(raw)}
			</p>
			{/* Ignore differences below half a cent. */}
			{Math.abs(series - raw) >= 0.005 && (
				<p className="rounded-control bg-warn-soft p-2 text-xs text-warn-ink">
					{discrepancy === null
						? `The series records ${fmtUsd(series)}; raw spans total ${fmtUsd(raw)}.`
						: `Series differs from the raw spans by ${discrepancy.toFixed(1)}%.`}
				</p>
			)}
			{data.unattributed.unpriced_requests > 0 && (
				<p className="text-sm text-warn-ink">
					{data.unattributed.unpriced_requests.toLocaleString()} LLM requests in
					this {unit} had no recorded cost and cannot be attributed
				</p>
			)}
			{data.overlapping_dimensions && (
				<p className="text-xs text-ink-3">
					Tags can overlap; shares may sum to more than 100%.
				</p>
			)}
			{data.rows.length === 0 ? (
				<p className="text-sm text-ink-3">No raw LLM spans in this bucket.</p>
			) : (
				<div className="overflow-x-auto">
					<table className="w-full text-left text-xs">
						<thead>
							<tr className="border-b border-line text-ink-3">
								<th className="p-2">{data.by}</th>
								<th className="p-2 text-right">Cost</th>
								<th className="p-2 text-right">Share</th>
								<th className="p-2 text-right">LLM requests</th>
								<th className="p-2 text-right">Unpriced LLM requests</th>
								{baselines && (
									<>
										<th className="p-2 text-right">Baseline</th>
										<th className="p-2 text-right">Excess</th>
									</>
								)}
								<th className="p-2">Traces</th>
							</tr>
						</thead>
						<tbody>
							{data.rows.map((r) => (
								<tr key={r.dimension} className="border-b border-line">
									<td className="max-w-64 break-words p-2 font-mono">
										{r.dimension}
									</td>
									<td className="p-2 text-right tabular-nums">
										{fmtUsd(r.cost_usd)}
									</td>
									<td className="p-2 text-right tabular-nums">
										{r.share_pct === null ? "—" : `${r.share_pct.toFixed(1)}%`}
									</td>
									<td className="p-2 text-right tabular-nums">
										{r.requests.toLocaleString()}
									</td>
									<td className="p-2 text-right tabular-nums">
										{r.unpriced_requests.toLocaleString()}
									</td>
									{baselines && (
										<>
											<td className="p-2 text-right tabular-nums">
												{fmtUsd(r.baseline_usd)}
											</td>
											<td className="p-2 text-right tabular-nums">
												{fmtUsd(r.excess_usd)}
											</td>
										</>
									)}
									<td className="p-2">
										{r.traces_href?.startsWith("/traces?") ? (
											<a className="underline" href={r.traces_href}>
												View traces
											</a>
										) : (
											<span className="text-ink-3">
												trace filter not available yet
											</span>
										)}
									</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			)}
			<p className="text-xs text-ink-3">
				Unlabelled spend: {fmtUsd(data.unattributed.unlabelled_cost_usd)}. These
				are the largest contributors, not a proven cause.
			</p>
		</div>
	);
}
export function SpendCauses({
	bucketStart,
	granularity,
}: { bucketStart: string; granularity: "hour" | "day" }) {
	const [by, setBy] = useState("model");
	const [data, setData] = useState<SpendCausesData | null>(null);
	const [error, setError] = useState<unknown>(null);
	const [attempt, setAttempt] = useState(0);
	useEffect(() => {
		void attempt;
		const abort = new AbortController();
		setData(null);
		setError(null);
		const q = new URLSearchParams({
			by,
			bucket_start: bucketStart,
			granularity,
		});
		apiFetch<SpendCausesData>(`/api/spend/spike-causes?${q}`, {
			signal: abort.signal,
		})
			.then((d) => {
				if (!abort.signal.aborted) setData(d);
			})
			.catch((e) => {
				if (!abort.signal.aborted) setError(e);
			});
		return () => abort.abort();
	}, [bucketStart, granularity, by, attempt]);
	if (error)
		return (
			<p role="alert">
				{error instanceof ApiError && error.status === 403
					? "You don't have access to traces in this workspace"
					: "Spend series unavailable"}{" "}
				<Button
					variant="secondary"
					size="sm"
					onClick={() => setAttempt((n) => n + 1)}
				>
					Retry
				</Button>
			</p>
		);
	if (!data)
		return (
			<div
				className="h-36 animate-pulse rounded-control bg-surface-2"
				aria-label="Loading spend contributors"
			/>
		);
	return <SpendCausesView data={data} onDimension={setBy} />;
}

"use client";
import { ApiError, apiFetch } from "@/lib/api-fetch";
import { fmtUsd } from "@/lib/metrics/format";
import { Button, SegmentedControl } from "@tracelanedev/ui";
import { useEffect, useState } from "react";
import { SpendCauses } from "./SpendCauses";
export type SpendSeries = {
	granularity: "hour" | "day";
	min_history_buckets: number;
	baseline_buckets: number;
	history: "ok" | "insufficient";
	window: { since: string; until: string; clamped: boolean };
	buckets: {
		bucket_start: string;
		cost_usd: number;
		priced_requests: number;
		unpriced_requests: number;
		requests: number;
	}[];
	spikes: {
		bucket_start: string;
		cost_usd: number;
		baseline_usd: number;
		ratio: number | null;
	}[];
};
export function SpendSeriesView({
	data,
	onSelect,
	selected,
}: {
	data: SpendSeries;
	onSelect: (s: string) => void;
	selected: string | null;
}) {
	const unpriced = data.buckets.reduce((s, b) => s + b.unpriced_requests, 0);
	const priced = data.buckets.reduce((s, b) => s + b.priced_requests, 0);
	const min = Math.min(0, ...data.buckets.map((b) => b.cost_usd));
	const max = Math.max(0, ...data.buckets.map((b) => b.cost_usd));
	const x = (i: number) =>
		20 + (i / Math.max(1, data.buckets.length - 1)) * 760;
	const y = (cost: number) => 180 - ((cost - min) / (max - min || 1)) * 160;
	const points = data.buckets
		.map((b, i) => `${x(i)},${y(b.cost_usd)}`)
		.join(" ");
	return (
		<div className="space-y-3">
			{priced === 0 ? (
				<p className="text-sm">
					No priced spend yet.{" "}
					<a href="/providers" className="underline">
						Connect a provider
					</a>
				</p>
			) : (
				<>
					<svg
						viewBox="0 0 800 200"
						className="w-full text-action-ink"
						role="img"
						aria-label="Spend by time bucket in US dollars"
					>
						<title>Spend by time bucket in US dollars</title>
						<line
							x1="20"
							y1={y(0)}
							x2="780"
							y2={y(0)}
							stroke="currentColor"
							className="text-line"
						/>
						<polyline
							points={points}
							fill="none"
							stroke="currentColor"
							strokeWidth="2"
						/>
						{data.spikes.map((spike) => {
							const i = data.buckets.findIndex(
								(b) => b.bucket_start === spike.bucket_start,
							);
							return i < 0 ? null : (
								<circle
									key={spike.bucket_start}
									cx={x(i)}
									cy={y(spike.cost_usd)}
									r={selected === spike.bucket_start ? 7 : 5}
									fill="currentColor"
									className="text-warn-ink"
								>
									<title>{`${spike.bucket_start}: ${fmtUsd(spike.cost_usd)}`}</title>
								</circle>
							);
						})}
					</svg>
					<div className="flex justify-between gap-3 text-xs text-ink-3">
						<span>
							{new Date(data.window.since).toLocaleString(undefined, {
								timeZone: "UTC",
							})}{" "}
							UTC
						</span>
						<span>
							{new Date(data.window.until).toLocaleString(undefined, {
								timeZone: "UTC",
							})}{" "}
							UTC
						</span>
					</div>
					{data.history === "insufficient" ? (
						<p className="text-sm text-ink-3">
							Not enough history to detect spikes (needs ≥
							{data.min_history_buckets}{" "}
							{data.granularity === "hour" ? "hours" : "days"}).
						</p>
					) : data.spikes.length === 0 ? (
						<p className="text-sm text-ink-3">No spike in this window.</p>
					) : (
						<ul className="flex flex-wrap gap-2" aria-label="Spend spikes">
							{data.spikes.map((s) => (
								<li key={s.bucket_start} className="max-w-full">
									<Button
										variant="secondary"
										size="sm"
										className="h-auto max-w-full whitespace-normal text-left"
										aria-pressed={selected === s.bucket_start}
										onClick={() => onSelect(s.bucket_start)}
									>
										{new Date(s.bucket_start).toLocaleString(undefined, {
											timeZone: "UTC",
										})}{" "}
										UTC · {fmtUsd(s.cost_usd)} · baseline{" "}
										{fmtUsd(s.baseline_usd)}
										{s.ratio !== null && ` · ${s.ratio.toFixed(1)}×`}
									</Button>
								</li>
							))}
						</ul>
					)}
				</>
			)}
			{unpriced > 0 && (
				<p className="text-xs text-ink-3">
					{unpriced.toLocaleString()} LLM requests had no recorded cost and are
					not included in spend.
				</p>
			)}
			{data.window.clamped && (
				<p className="text-xs text-ink-3">
					Showing the served window above, aligned to whole{" "}
					{data.granularity === "hour" ? "hours" : "days"}.
				</p>
			)}
		</div>
	);
}
export function SpendOverTime({ query }: { query: string }) {
	const [granularity, setGranularity] = useState<"hour" | "day">("hour");
	const [data, setData] = useState<SpendSeries | null>(null);
	const [error, setError] = useState<unknown>(null);
	const [attempt, setAttempt] = useState(0);
	const [selected, setSelected] = useState<string | null>(null);
	useEffect(() => {
		void attempt;
		const abort = new AbortController();
		setData(null);
		setError(null);
		setSelected(null);
		const qs = new URLSearchParams(query);
		qs.set("granularity", granularity);
		apiFetch<SpendSeries>(`/api/spend/series?${qs}`, { signal: abort.signal })
			.then((d) => {
				if (!abort.signal.aborted) setData(d);
			})
			.catch((e) => {
				if (!abort.signal.aborted) setError(e);
			});
		return () => abort.abort();
	}, [query, granularity, attempt]);
	return (
		<section
			aria-label="Spend over time"
			className="space-y-3 rounded-card border border-line bg-surface p-5"
		>
			<div className="flex flex-wrap items-center justify-between gap-3">
				<h2 className="text-base font-semibold">Spend over time</h2>
				<SegmentedControl
					label="Spend granularity"
					value={granularity}
					onChange={setGranularity}
					options={[
						{ value: "hour", label: "Hourly" },
						{ value: "day", label: "Daily" },
					]}
				/>
			</div>
			{error ? (
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
			) : !data ? (
				<div
					className="h-48 animate-pulse rounded-card bg-surface-2"
					aria-label="Loading spend series"
				/>
			) : (
				<SpendSeriesView
					data={data}
					selected={selected}
					onSelect={setSelected}
				/>
			)}
			{selected && (
				<div id="spike-details" className="border-t border-line pt-4">
					<SpendCauses bucketStart={selected} granularity={granularity} />
				</div>
			)}
		</section>
	);
}

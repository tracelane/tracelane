"use client";

/**
 * WindowBreakdown — "What's using your window" (spec §8), grouped by
 * API key / service / capture state / trace shape. A SEPARATE on-demand
 * fetch to `/api/billing/window-breakdown` (spec §2.5b) — it does not run on
 * the usage board's initial load, only when this panel is open.
 */

import { apiFetchRaw } from "@/lib/api-fetch";
import type { GatewayWindowBreakdownResponse } from "@/lib/billing-usage";
import { SegmentedControl } from "@tracelanedev/ui";
import { useEffect, useState } from "react";

type By = GatewayWindowBreakdownResponse["by"];

const OPTIONS: { value: By; label: string }[] = [
	{ value: "key", label: "API key" },
	{ value: "service", label: "service" },
	{ value: "capture", label: "capture state" },
	{ value: "shape", label: "trace shape" },
];

export function WindowBreakdown() {
	const [by, setBy] = useState<By>("capture");
	const [data, setData] = useState<GatewayWindowBreakdownResponse | null>(null);
	const [error, setError] = useState(false);
	const [loading, setLoading] = useState(true);

	useEffect(() => {
		let cancelled = false;
		setLoading(true);
		setError(false);
		apiFetchRaw(`/api/billing/window-breakdown?by=${by}`)
			.then((res) => {
				if (!res.ok) throw new Error(String(res.status));
				return res.json() as Promise<GatewayWindowBreakdownResponse>;
			})
			.then((body) => {
				if (!cancelled) setData(body);
			})
			.catch(() => {
				if (!cancelled) setError(true);
			})
			.finally(() => {
				if (!cancelled) setLoading(false);
			});
		return () => {
			cancelled = true;
		};
	}, [by]);

	return (
		<div className="surface-card rounded-[var(--radius-card)] border border-line p-5">
			<div className="mb-3 flex flex-wrap items-center justify-between gap-3">
				<p className="t-card-title">What&apos;s using your window</p>
				<SegmentedControl
					label="Group breakdown by"
					value={by}
					onChange={setBy}
					options={OPTIONS}
				/>
			</div>

			{loading && (
				<div className="space-y-2">
					{[0, 1, 2].map((i) => (
						<div key={i} className="h-6 animate-pulse rounded bg-surface-2" />
					))}
				</div>
			)}

			{!loading && error && (
				<p className="text-xs text-danger-ink">
					Could not load the breakdown — your traces are still being recorded.
				</p>
			)}

			{!loading && !error && data && data.rows.length === 0 && (
				<p className="text-xs text-ink-2">
					Nothing in your indexed window matches this filter.
				</p>
			)}

			{!loading && !error && data && data.rows.length > 0 && (
				<>
					<div>
						{data.rows.map((row) => {
							const pct =
								data.total_bytes > 0
									? Math.round((row.bytes / data.total_bytes) * 100)
									: 0;
							return (
								<div
									key={row.key}
									className="grid grid-cols-[minmax(110px,160px)_1fr_auto] items-center gap-3 border-b border-line py-2 text-xs last:border-b-0"
								>
									<span className="text-ink-2">
										{row.key ||
											(by === "key"
												? "Dashboard session (no key)"
												: "(not set)")}
									</span>
									<div className="h-1.5 overflow-hidden rounded-full bg-surface-2">
										<div
											className="h-full rounded-full bar-data"
											style={{ width: `${pct}%` }}
										/>
									</div>
									<span className="whitespace-nowrap tabular-nums text-ink">
										{(row.bytes / 1e9).toFixed(1)} GB · {pct}%
									</span>
								</div>
							);
						})}
					</div>
					<p className="mt-2 text-2xs text-ink-3">
						Showing {data.rows.length} groups
						{data.truncated
							? " — row limit reached; percentages cover the groups shown."
							: ""}
					</p>
				</>
			)}
		</div>
	);
}

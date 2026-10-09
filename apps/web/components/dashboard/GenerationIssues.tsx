"use client";

import { ApiError, apiFetch } from "@/lib/api-fetch";
import { formatDateTimeUtc } from "@/lib/format-date";
import {
	ISSUE_LABELS,
	type IssueSummary,
	issueLabel,
} from "@/lib/generation-issues";
import Link from "next/link";
import { useEffect, useState } from "react";

export function GenerationIssues() {
	const [request, setRequest] = useState<RequestInit>({});
	const [data, setData] = useState<IssueSummary>();
	const [error, setError] = useState<number>();
	useEffect(() => {
		const controller = new AbortController();
		setData(undefined);
		setError(undefined);
		apiFetch<IssueSummary>("/api/traces/issues/summary", {
			...request,
			signal: controller.signal,
		})
			.then((value) => {
				if (!controller.signal.aborted) setData(value);
			})
			.catch((cause) => {
				if (!controller.signal.aborted)
					setError(cause instanceof ApiError ? cause.status : 502);
			});
		return () => controller.abort();
	}, [request]);
	return (
		<section
			aria-label="Generation issues"
			className="space-y-3 rounded-xl border border-line bg-surface p-4"
		>
			<div className="flex flex-wrap items-baseline justify-between gap-2">
				<h2 className="font-semibold text-ink">
					Generation issues{data ? ` · last ${data.window_days} days` : ""}
				</h2>
				{data && (
					<p className="text-xs text-ink-3">
						as of {formatDateTimeUtc(data.as_of)}
					</p>
				)}
			</div>
			{error ? (
				error === 403 ? (
					<p className="text-sm text-ink-2">
						You don't have access to trace data
					</p>
				) : (
					<button
						type="button"
						className="text-sm text-action-ink underline"
						onClick={() => setRequest({ cache: "reload" })}
					>
						Couldn't load — retry
					</button>
				)
			) : !data ? (
				<output
					aria-label="Loading generation issues"
					className="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-9"
				>
					{Object.keys(ISSUE_LABELS).map((kind) => (
						<div
							key={kind}
							className="h-24 animate-pulse rounded-lg bg-surface-2"
						/>
					))}
				</output>
			) : data.total_traces === 0 ? (
				<p className="text-sm text-ink-2">
					No traces in the last {data.window_days} days yet — chips appear as
					calls are recorded.
				</p>
			) : (
				<>
					<p className="text-xs text-ink-3">
						of {data.total_traces.toLocaleString()} traces
					</p>
					<div className="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-9">
						{data.counts.map(({ kind, trace_count }) => (
							<Link
								key={kind}
								href={`/traces?${new URLSearchParams({ issue: kind, since: data.since, until: data.until })}`}
								aria-label={`${issueLabel(kind)}: ${trace_count} traces`}
								className="flex min-h-24 flex-col justify-between gap-2 rounded-lg border border-line p-3 hover:bg-surface-hover focus-visible:outline-action"
							>
								<span className="text-xs text-ink-2">{issueLabel(kind)}</span>
								<span className="text-xl font-semibold tabular-nums text-ink">
									{trace_count.toLocaleString()}
								</span>
							</Link>
						))}
					</div>
					<div className="flex flex-wrap gap-x-5 gap-y-1 text-xs text-ink-3">
						<p>
							{data.no_served_model_calls.toLocaleString()} calls recorded no
							served model
						</p>
						<p>
							{data.no_finish_reason_calls.toLocaleString()} calls recorded no
							finish reason
						</p>
						<p>
							Cancelled, estimated and capture trimmed: gateway traffic only
						</p>
						{data.gateway_signal_calls === 0 && (
							<p>No gateway signals recorded</p>
						)}
						{!data.content_capture && <p>Content capture is currently off</p>}
					</div>
				</>
			)}
		</section>
	);
}

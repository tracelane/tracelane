"use client";

import { ApiError, apiFetch } from "@/lib/api-fetch";
import {
	type IssueRollup,
	type IssueChip as RecordedIssue,
	issueLabel,
} from "@/lib/generation-issues";
import { Badge, Tooltip } from "@tracelanedev/ui";
import { useEffect, useState } from "react";

export function IssueChip({ issue }: { issue: RecordedIssue }) {
	return (
		<Tooltip
			content={`${issue.detail} · ${issue.affected_spans} affected span${issue.affected_spans === 1 ? "" : "s"}`}
		>
			<Badge tone={issue.severity} tabIndex={0}>
				{issueLabel(issue.kind)}
			</Badge>
		</Tooltip>
	);
}

export function IssueChips({
	issues,
	inlineLimit,
}: { issues: RecordedIssue[]; inlineLimit: number }) {
	if (!issues.length) return null;
	return (
		<div className="flex flex-wrap items-center gap-1 motion-safe:animate-in motion-safe:fade-in">
			{issues.slice(0, inlineLimit).map((issue) => (
				<IssueChip key={issue.kind} issue={issue} />
			))}
			{issues.length > inlineLimit && (
				<details
					className="text-xs text-ink-2"
					onClick={(event) => event.stopPropagation()}
					onKeyDown={(event) => event.stopPropagation()}
				>
					<summary
						className="cursor-pointer rounded-control px-1 focus-visible:outline-2 focus-visible:outline-focus-ring"
						aria-label="Show all generation issues"
					>
						+{issues.length - inlineLimit}
					</summary>
					<div className="mt-1 flex flex-col items-start gap-1 rounded-control border border-line bg-surface p-2">
						{issues.map((issue) => (
							<IssueChip key={issue.kind} issue={issue} />
						))}
					</div>
				</details>
			)}
		</div>
	);
}

/** A single page-bounded read; stale pages are cancelled, never attached to new rows. */
export function useIssueRollup(traceIds: string, enabled: boolean) {
	const [state, setState] = useState<{
		key: string;
		data?: IssueRollup;
		error?: string;
	}>({ key: "" });
	useEffect(() => {
		if (!enabled || !traceIds) return;
		const controller = new AbortController();
		setState({ key: traceIds });
		apiFetch<IssueRollup>(
			`/api/traces/issues/rollup?${new URLSearchParams({ trace_ids: traceIds })}`,
			{ signal: controller.signal },
		)
			.then((data) => {
				if (!controller.signal.aborted) setState({ key: traceIds, data });
			})
			.catch((error) => {
				if (!controller.signal.aborted)
					setState({
						key: traceIds,
						error:
							error instanceof ApiError && error.status === 403
								? "You don't have access to trace data"
								: "Generation-issue badges are unavailable right now; the list is complete.",
					});
			});
		return () => controller.abort();
	}, [traceIds, enabled]);
	const current = enabled && state.key === traceIds ? state : undefined;
	return {
		data: current?.data?.issues_available ? current.data : undefined,
		error:
			current?.error ??
			(current?.data && !current.data.issues_available
				? "Generation-issue badges are unavailable right now; the list is complete."
				: undefined),
	};
}

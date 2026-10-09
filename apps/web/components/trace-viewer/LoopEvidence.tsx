"use client";
import { ApiError, apiFetch } from "@/lib/api-fetch";
import { fmtUsd } from "@/lib/metrics/format";
import { extractToolCalls } from "@/lib/tool-calls";
import { Button, StatusBadge } from "@tracelanedev/ui";
import { useEffect, useState } from "react";
import type { Span } from "./types";

export type LoopInstance = {
	group_kind: "session" | "trace";
	group_id: string;
	tool: string;
	instance_id: string;
	first_call_index: number;
	calls: number;
	first_at: string;
	last_at: string;
	trace_ids: string[];
	span_ids: string[];
	repeat_cost_usd: number | null;
	repeat_unpriced: number;
	repeat_output_tokens: number;
};
export type LoopResponse = {
	min_repeats: number;
	window_secs: number;
	instances: LoopInstance[];
	total_instances: number;
	truncated: boolean;
	tool_calls: number;
	unfingerprinted_tool_calls: number;
};
function attrs(span: Span | undefined): Record<string, unknown> {
	try {
		const a: unknown = JSON.parse(span?.attributes ?? "{}");
		return a && typeof a === "object" && !Array.isArray(a)
			? (a as Record<string, unknown>)
			: {};
	} catch {
		return {};
	}
}
function capturedArguments(span: Span, instance: LoopInstance): unknown {
	const a = attrs(span);
	if (!instance.span_ids.includes(span.span_id)) return undefined;
	if (instance.first_call_index === 0)
		return a["gen_ai.tool.name"] === instance.tool
			? a.gen_ai_tool_call_arguments
			: undefined;
	const call = extractToolCalls(span.attributes).rows[
		instance.first_call_index - 1
	];
	return call?.name === instance.tool ? call.arguments : undefined;
}
function RepeatedCalls({
	instance,
	spans,
	traceId,
	onSelectSpan,
}: {
	instance: LoopInstance;
	spans: Span[];
	traceId: string;
	onSelectSpan: (id: string) => void;
}) {
	const [remote, setRemote] = useState<Span[] | null>(null);
	const [failure, setFailure] = useState(false);
	const [loading, setLoading] = useState(false);
	const local = spans.find((s) => s.span_id === instance.span_ids[0]);
	const evidence =
		remote?.filter((s) => s.span_id === instance.span_ids[0]) ??
		(local ? [local] : []);
	const args = evidence
		.map((s) => capturedArguments(s, instance))
		.find((a) => a !== undefined);
	async function loadFirst() {
		setLoading(true);
		setFailure(false);
		try {
			const first = instance.trace_ids[0];
			if (first)
				setRemote(
					await apiFetch<Span[]>(
						`/api/traces/${encodeURIComponent(first)}/spans`,
					),
				);
		} catch {
			setFailure(true);
		} finally {
			setLoading(false);
		}
	}
	return (
		<details className="rounded-card border border-line p-3">
			<summary className="cursor-pointer text-sm">
				<StatusBadge
					status="loop"
					tone="warn"
					label={`Repeated tool call · ${instance.tool} ×${instance.calls}`}
				/>{" "}
				<span className="text-ink-3">
					within{" "}
					{Math.max(
						0,
						(Date.parse(instance.last_at) - Date.parse(instance.first_at)) /
							1000,
					)}{" "}
					s
				</span>
			</summary>
			<div className="mt-3 space-y-3 text-sm">
				{args !== undefined ? (
					<pre className="overflow-auto rounded-control bg-surface-2 p-3 text-xs">
						{typeof args === "string" ? args : JSON.stringify(args, null, 2)}
					</pre>
				) : evidence.length ? (
					<p>
						Same arguments each time (fingerprint match). The arguments aren't
						recorded in this workspace.
					</p>
				) : (
					<Button
						size="sm"
						variant="secondary"
						onClick={loadFirst}
						disabled={loading}
					>
						{loading ? "Loading arguments…" : "Load first call arguments"}
					</Button>
				)}
				{failure && (
					<p role="alert">
						Couldn't load — your traces are unaffected.{" "}
						<Button size="sm" onClick={loadFirst}>
							Retry
						</Button>
					</p>
				)}
				<p title="Distinct spans carrying the second and later calls, excluding the first call. A span requesting several tools counts whole.">
					Spend on the repeats:{" "}
					{instance.repeat_cost_usd === null
						? "—"
						: fmtUsd(instance.repeat_cost_usd)}
					{instance.repeat_unpriced > 0 &&
						` · ${instance.repeat_unpriced} unpriced`}{" "}
					· {instance.repeat_output_tokens.toLocaleString()} output tokens
				</p>
				<ul className="flex flex-wrap gap-3" aria-label="Repeated spans">
					{instance.span_ids
						.filter((id) => spans.some((s) => s.span_id === id))
						.map((id) => (
							<li key={id}>
								<button
									type="button"
									className="text-action-ink underline"
									onClick={() => onSelectSpan(id)}
								>
									Span {id}
								</button>
							</li>
						))}
				</ul>
				<ul
					className="flex flex-wrap gap-3"
					aria-label="Traces containing repeated calls"
				>
					{instance.trace_ids
						.filter((id) => id !== traceId)
						.map((id) => (
							<li key={id}>
								<a
									className="text-action-ink underline"
									href={`/traces/${encodeURIComponent(id)}`}
								>
									Trace {id}
								</a>
							</li>
						))}
				</ul>
				{instance.calls > instance.span_ids.length && (
					<p className="text-ink-3">
						+{instance.calls - instance.span_ids.length} more calls
					</p>
				)}
			</div>
		</details>
	);
}
export function LoopEvidenceView({
	data,
	spans,
	traceId,
	onSelectSpan,
}: {
	data: LoopResponse;
	spans: Span[];
	traceId: string;
	onSelectSpan: (id: string) => void;
}) {
	const hasTools = data.tool_calls > 0;
	return (
		<section aria-label="Repeated tool calls" className="space-y-2">
			<p
				className="text-xs text-ink-3"
				title="Gateway responses retain at most 32 tool calls. Calls beyond that cap have no stored name or fingerprint and are not counted."
			>
				{data.min_repeats}+ identical calls within {data.window_secs / 60} min
			</p>
			{data.instances.length ? (
				data.instances.map((i) => (
					<RepeatedCalls
						key={i.instance_id}
						instance={i}
						spans={spans}
						traceId={traceId}
						onSelectSpan={onSelectSpan}
					/>
				))
			) : (
				<p className="text-sm text-ink-3">
					{hasTools ? "0 loops detected" : "No tool calls in this range."}
				</p>
			)}
			{hasTools &&
				spans.length === 1 &&
				!attrs(spans[0]).gen_ai_conversation_id &&
				data.instances.length === 0 && (
					<p className="text-xs text-ink-3">
						Loops are found within a session or trace. Send{" "}
						<code>x-conversation-id</code> (or use <code>use_session()</code> in
						the SDK) so repeated calls across requests can be compared.
					</p>
				)}
			{data.truncated && (
				<p>
					Showing the {data.instances.length} largest of {data.total_instances}
				</p>
			)}
			{data.unfingerprinted_tool_calls > 0 && (
				<p className="text-xs text-ink-3">
					{data.unfingerprinted_tool_calls} tool calls couldn't be compared —
					sent before this feature, or through a path without a fingerprint key.
				</p>
			)}
		</section>
	);
}
export function LoopEvidence({
	traceId,
	spans,
	onSelectSpan,
}: { traceId: string; spans: Span[]; onSelectSpan: (id: string) => void }) {
	const [data, setData] = useState<LoopResponse | null>(null);
	const [error, setError] = useState<unknown>(null);
	const [retry, setRetry] = useState(0);
	const session = spans
		.map((s) => attrs(s).gen_ai_conversation_id)
		.find((v) => typeof v === "string" && v) as string | undefined;
	useEffect(() => {
		void retry; // Explicit reload requested by the Retry control.
		const abort = new AbortController();
		setData(null);
		setError(null);
		const win = new URLSearchParams(window.location.search);
		const qs = new URLSearchParams({ trace_id: traceId });
		for (const k of ["since", "until"]) {
			const v = win.get(k);
			if (v) qs.set(k, v);
		}
		async function load() {
			const trace = await apiFetch<LoopResponse>(`/api/agent-loops?${qs}`, {
				signal: abort.signal,
			});
			if (session) {
				qs.delete("trace_id");
				qs.set("session_id", session);
				const grouped = await apiFetch<LoopResponse>(`/api/agent-loops?${qs}`, {
					signal: abort.signal,
				});
				return grouped;
			}
			return trace;
		}
		load()
			.then((v) => {
				if (!abort.signal.aborted) setData(v);
			})
			.catch((e) => {
				if (!abort.signal.aborted) setError(e);
			});
		return () => abort.abort();
	}, [traceId, session, retry]);
	if (error)
		return (
			<div role="alert" className="text-sm">
				{error instanceof ApiError && error.status === 403 ? (
					"You don't have access to traces in this workspace"
				) : (
					<>
						Couldn't load — your traces are unaffected.{" "}
						<Button
							size="sm"
							variant="secondary"
							onClick={() => setRetry((n) => n + 1)}
						>
							Retry
						</Button>
					</>
				)}
			</div>
		);
	if (!data)
		return (
			<div
				aria-label="Loading repeated tool calls"
				className="h-10 animate-pulse rounded-control bg-surface-2"
			/>
		);
	return (
		<LoopEvidenceView
			data={data}
			spans={spans}
			traceId={traceId}
			onSelectSpan={onSelectSpan}
		/>
	);
}

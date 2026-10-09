"use client";
import { apiFetch } from "@/lib/api-fetch";
import { isTraceId } from "@/lib/trace-id";
import { useEffect, useState } from "react";

const string = (value: unknown): string | undefined =>
	typeof value === "string" && value.length > 0 ? value : undefined;
const records = (value: unknown): Record<string, unknown>[] =>
	Array.isArray(value)
		? value.filter(
				(item): item is Record<string, unknown> =>
					item !== null && typeof item === "object" && !Array.isArray(item),
			)
		: [];

function CaptureLink() {
	const [canEdit, setCanEdit] = useState(false);
	useEffect(() => {
		let active = true;
		apiFetch<{ can_edit: boolean }>("/api/settings/content-capture")
			.then((capture) => {
				if (active) setCanEdit(capture.can_edit);
			})
			.catch(() => {});
		return () => {
			active = false;
		};
	}, []);
	return canEdit ? (
		<a className="text-action-ink underline" href="/settings/workspace">
			Change in Settings → Workspace
		</a>
	) : null;
}

function Card({
	title,
	children,
}: { title: string; children: React.ReactNode }) {
	return (
		<section className="space-y-2 rounded-card border border-line bg-surface-2 p-3">
			<h3 className="t-metric-label">{title}</h3>
			{children}
		</section>
	);
}

export function OtlpDetails({ attrs }: { attrs: Record<string, unknown> }) {
	const withheld = Array.isArray(attrs.tracelane_content_withheld)
		? attrs.tracelane_content_withheld
		: [];
	const input = string(attrs.input_value);
	const output = string(attrs.output_value);
	const service = [
		string(attrs.service_name),
		string(attrs.service_version),
		string(attrs.deployment_environment),
	]
		.filter(Boolean)
		.join(" · ");
	const exceptionType = string(attrs.exception_type);
	const exceptionMessage = string(attrs.exception_message);
	const documents = records(attrs.tracelane_retrieval_documents);
	const events = records(attrs.tracelane_events);
	const stack = events
		.map((event) => event.attributes)
		.filter(
			(item): item is Record<string, unknown> =>
				item !== null && typeof item === "object" && !Array.isArray(item),
		)
		.map((item) => string(item["exception.stacktrace"]))
		.find(Boolean);
	const links = records(attrs.tracelane_links);
	const dropped =
		attrs.tracelane_attrs_dropped &&
		typeof attrs.tracelane_attrs_dropped === "object"
			? (attrs.tracelane_attrs_dropped as {
					count?: unknown;
					reasons?: Record<string, number>;
				})
			: null;
	const droppedCount = typeof dropped?.count === "number" ? dropped.count : 0;
	return (
		<>
			{service && <p className="text-xs text-ink-2">{service}</p>}
			{(["input", "output"] as const).map((part) => {
				const value = part === "input" ? input : output;
				const hidden = withheld.includes(part);
				if (!value && !hidden) return null;
				return (
					<Card key={part} title={part === "input" ? "Input" : "Output"}>
						{hidden ? (
							<p className="text-xs text-ink-2">
								{part === "input" ? "Prompt" : "Response"} text not recorded —
								this workspace records metadata only. <CaptureLink />
							</p>
						) : (
							<>
								<pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words text-xs text-ink">
									{value}
								</pre>
								{value?.endsWith("…[truncated]") && (
									<p className="text-xs text-ink-3">
										Text cut at the capture limit.
									</p>
								)}
							</>
						)}
					</Card>
				);
			})}
			{(exceptionType || exceptionMessage || stack) && (
				<Card title="Exception">
					<p className="text-xs text-danger-ink">
						{exceptionType ? `Exception: ${exceptionType}` : "Exception"}
					</p>
					{exceptionMessage && (
						<p className="text-xs text-ink">{exceptionMessage}</p>
					)}
					{stack && (
						<details>
							<summary className="text-xs text-ink-3">Stacktrace</summary>
							<pre className="overflow-auto whitespace-pre-wrap font-mono text-xs">
								{stack}
							</pre>
						</details>
					)}
				</Card>
			)}
			{(documents.length > 0 || string(attrs.tracelane_retrieval_query)) && (
				<Card title="Retrieval">
					{string(attrs.tracelane_retrieval_query) && (
						<p className="text-xs text-ink">
							{string(attrs.tracelane_retrieval_query)}
						</p>
					)}
					{documents.map((doc, index) => (
						<p className="text-xs text-ink" key={JSON.stringify(doc)}>
							{[
								string(doc.id) ?? `Document ${index + 1}`,
								typeof doc.score === "number" ? String(doc.score) : null,
							]
								.filter(Boolean)
								.join(" · ")}
							{string(doc.content) ? (
								<span className="block whitespace-pre-wrap text-ink-2">
									{string(doc.content)}
								</span>
							) : (
								<span className="text-ink-3"> · text not recorded</span>
							)}
						</p>
					))}
				</Card>
			)}
			{events.length > 0 && (
				<Card title={`Events (${events.length})`}>
					{events.map((event) => (
						<div className="text-xs text-ink" key={JSON.stringify(event)}>
							{typeof event.time_unix_us === "number" ? (
								<time className="mr-2 font-mono">
									{new Date(event.time_unix_us / 1000).toISOString()}
								</time>
							) : null}
							{string(event.name) ?? "event"}
							{event.attributes != null ? (
								<pre className="overflow-auto whitespace-pre-wrap font-mono text-2xs">
									{JSON.stringify(event.attributes, null, 2)}
								</pre>
							) : null}
						</div>
					))}
				</Card>
			)}
			{links.length > 0 && (
				<Card title={`Links (${links.length})`}>
					{links.map((link) => (
						<p
							className="break-all font-mono text-xs"
							key={JSON.stringify(link)}
						>
							{isTraceId(link.trace_id) ? (
								<a
									className="text-action-ink underline"
									href={`/traces/${encodeURIComponent(String(link.trace_id))}`}
								>
									{String(link.trace_id)}
								</a>
							) : (
								"unknown trace"
							)}{" "}
							· {string(link.span_id) ?? "unknown span"}
						</p>
					))}
				</Card>
			)}
			{droppedCount > 0 && (
				<p
					className="text-xs text-ink-3"
					title={JSON.stringify(dropped?.reasons ?? {})}
				>
					{droppedCount} attributes not kept
				</p>
			)}
		</>
	);
}

import { ObjectPageCommands } from "@/components/command-palette/object-commands";
import { IssueChip } from "@/components/trace-viewer/IssueChip";
import { formatDateTimeUtc } from "@/lib/format-date";
import { fmtUsd } from "@/lib/metrics/format";
import type { SessionTranscriptResponse } from "@/lib/sessions";
import { extractToolCalls, formatBytes } from "@/lib/tool-calls";
import { Badge, StatusBadge, fmtDur } from "@tracelanedev/ui";
import { TurnActions } from "./TurnActions";
function Message({ value }: { value: unknown }) {
	if (typeof value === "string")
		return <p className="whitespace-pre-wrap break-words">{value}</p>;
	if (!value || typeof value !== "object") return null;
	const message = value as Record<string, unknown>;
	const content = message.content ?? message.parts;
	const text =
		typeof content === "string"
			? content
			: Array.isArray(content)
				? content
						.map((part) =>
							typeof part === "object" && part !== null && "text" in part
								? String(part.text)
								: "[Non-text content — open trace]",
						)
						.join("\n")
				: "[Non-text content — open trace]";
	return (
		<div className="space-y-1">
			<p className="text-xs font-semibold uppercase text-ink-2">
				{typeof message.role === "string" ? message.role : "Message"}
			</p>
			<p className="whitespace-pre-wrap break-words">{text}</p>
			{text.includes("…[truncated]") && (
				<StatusBadge status="truncated when recorded" tone="warn" />
			)}
		</div>
	);
}
function Messages({ value }: { value: unknown }) {
	const values = Array.isArray(value) ? value : [value];
	return (
		<div className="space-y-4">
			{values.map((message, index) => (
				<Message key={`${index}:${JSON.stringify(message)}`} value={message} />
			))}
		</div>
	);
}
const cost = (value: number | null) => fmtUsd(value);
export function SessionTranscript({
	data,
	sessionId,
	viewerRole,
	userId,
}: {
	data: SessionTranscriptResponse;
	sessionId: string;
	viewerRole: string | null;
	userId: string;
}) {
	const { totals, turns, capture } = data;
	const captureOff =
		capture.workspace_policy === "off" &&
		!turns.some((t) => t.exchange?.content === "captured");
	return (
		<div className="space-y-5">
			<ObjectPageCommands
				commands={data.turns.flatMap((turn) => [
					{
						id: `turn-${turn.ordinal}-trace`,
						label: `Open turn ${turn.ordinal} trace`,
						href: `/traces/${encodeURIComponent(turn.trace_id)}`,
						group: "action" as const,
					},
					...(turn.exchange?.span_id
						? [
								{
									id: `turn-${turn.ordinal}-playground`,
									label: `Open turn ${turn.ordinal} in playground`,
									href: `/playground?trace=${encodeURIComponent(turn.trace_id)}&span=${encodeURIComponent(turn.exchange.span_id)}`,
									group: "action" as const,
								},
							]
						: []),
				])}
			/>
			<section
				aria-label="Whole session totals"
				className="rounded-card border border-line bg-surface p-4"
			>
				<p className="mb-3 text-xs text-ink-2">
					Whole recorded session · not limited to this page or the sessions
					list's time window
				</p>
				{
					<>
						<div className="flex flex-wrap gap-x-6 gap-y-2 text-sm">
							<span>
								Turns <strong>{totals.turns}</strong>
							</span>
							<span title="Summed over all spans; wrapper and inner usage can double-count. Zero may mean usage was not reported.">
								Tokens in / out{" "}
								<strong>
									{totals.input_tokens || "—"} / {totals.output_tokens || "—"}
								</strong>
							</span>
							<span
								title={`${totals.priced_spans} of ${totals.spans} spans priced`}
							>
								Cost <strong>{cost(totals.cost_usd)}</strong>
							</span>
							<span>
								First → last <strong>{fmtDur(totals.duration_us)}</strong>{" "}
								(includes idle time)
							</span>
							<span>
								Errors{" "}
								<strong className={totals.error_spans ? "text-danger-ink" : ""}>
									{totals.error_spans}
								</strong>
							</span>
						</div>
						<p className="mt-3 text-xs text-ink-2">
							Models {totals.models.join(" · ") || "—"}
							{totals.end_user && ` · User ${totals.end_user}`}
							{totals.agent_name && ` · Agent ${totals.agent_name}`}
						</p>
					</>
				}
			</section>
			{captureOff && (
				<aside className="rounded-control border border-line bg-surface-2 p-4 text-sm">
					Content capture is off. Timing, tokens, cost, tool names and errors
					are still recorded.{" "}
					<a className="underline" href="/settings/workspace">
						Content capture settings
					</a>
				</aside>
			)}
			{turns.map((turn) => {
				const exchange = turn.exchange;
				const tools = extractToolCalls(exchange?.tool_attrs ?? "{}");
				const content = exchange?.content ?? "absent";
				const missing =
					content === "unloaded"
						? "Text is stored but could not be loaded — retry"
						: content === "unreadable"
							? "The recorded text could not be parsed"
							: capture.workspace_policy === "off"
								? "Prompt and response text are not recorded for this workspace."
								: turn.intervention === 2
									? "Response blocked — nothing was returned, so nothing was recorded"
									: "No text recorded for this turn — recorded before capture was on, or by a route that does not capture output yet";
				return (
					<article
						id={`turn-${turn.ordinal}`}
						key={turn.trace_id}
						className="rounded-card border border-line bg-surface"
					>
						<header className="flex flex-wrap items-center justify-between gap-3 border-b border-line p-4">
							<div className="flex flex-wrap items-center gap-3">
								<h2 className="font-semibold">Turn {turn.ordinal}</h2>
								<time className="text-xs text-ink-2">
									{formatDateTimeUtc(turn.start_time)}
								</time>
								<span className="font-mono text-xs">{turn.model || "—"}</span>
								<StatusBadge status={turn.error_spans ? "error" : "ok"} />
								{exchange?.issues?.map((issue) => (
									<IssueChip key={issue.kind} issue={issue} />
								))}
								{turn.intervention > 0 && (
									<StatusBadge
										status={
											turn.intervention === 2 ? "blocked" : "intervention"
										}
										tone={turn.intervention === 2 ? "danger" : "warn"}
									/>
								)}
							</div>
							<TurnActions
								traceId={turn.trace_id}
								spanId={exchange?.span_id}
								viewerRole={viewerRole}
								userId={userId}
								canCopyContent={
									capture.workspace_policy === "on" && content === "captured"
								}
							/>
						</header>
						<div className="space-y-4 p-4">
							<p className="text-xs text-ink-2">
								{fmtDur(turn.duration_us)} · Tokens in / out{" "}
								{turn.input_tokens || "—"} / {turn.output_tokens || "—"} · Cost{" "}
								{cost(turn.cost_usd)} · {turn.error_spans} errors
							</p>
							{content === "captured" ? (
								<>
									<Messages value={exchange?.input_tail} />
									<Messages value={exchange?.output} />
									{turn.intervention === 2 && (
										<p>
											Response blocked — nothing was returned, so nothing was
											recorded
										</p>
									)}
								</>
							) : (
								<p className="text-sm text-ink-2">
									{missing}
									{content === "unloaded" && (
										<>
											{" "}
											·{" "}
											<a
												className="underline"
												href={`/sessions/${encodeURIComponent(sessionId)}`}
											>
												Retry
											</a>
										</>
									)}
									{content === "unreadable" && (
										<>
											{" "}
											·{" "}
											<a
												className="underline"
												href={`/traces/${turn.trace_id}`}
											>
												Raw attributes
											</a>
										</>
									)}
								</p>
							)}
							{turn.status_message && (
								<p className="text-sm text-danger-ink">{turn.status_message}</p>
							)}
							{tools.rows.length > 0 && (
								<ul className="space-y-2">
									{tools.rows.map((tool, index) => (
										<li
											key={`${index}:${tool.name}`}
											className="rounded-control bg-surface-2 p-3 text-sm"
										>
											Tool call · <code>{tool.name}</code>
											{tool.argumentBytes !== undefined &&
												` · ${formatBytes(tool.argumentBytes)}`}
										</li>
									))}
								</ul>
							)}
							{exchange?.finish_reasons.length ? (
								<p className="text-xs text-ink-2">
									Finish: {exchange.finish_reasons.join(", ")}
								</p>
							) : null}
							<div className="flex flex-wrap gap-4 text-xs">
								<a className="underline" href={`/traces/${turn.trace_id}`}>
									Full prompt ({exchange?.input_message_count ?? 0} messages) —
									open trace
								</a>
								{turn.span_count > 1 && (
									<a className="underline" href={`/traces/${turn.trace_id}`}>
										{turn.span_count - 1} more steps — open trace
									</a>
								)}
							</div>
						</div>
					</article>
				);
			})}
			{turns.length > 0 ? (
				<p className="text-sm text-ink-2">
					Showing turns {turns[0]?.ordinal}–{turns[turns.length - 1]?.ordinal}{" "}
					of {totals.turns}
				</p>
			) : (
				<p>
					No turns on this page.{" "}
					<a
						className="underline"
						href={`/sessions/${encodeURIComponent(sessionId)}`}
					>
						First page
					</a>
				</p>
			)}
		</div>
	);
}

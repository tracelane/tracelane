"use client";
import { Button } from "@tracelanedev/ui";

import { PageHeader } from "@tracelanedev/ui";

import { formatDateTimeUtc } from "@/lib/format-date";
import {
	type IdentityKind,
	identityForKey,
	identityHref,
	providerIdentity,
} from "@/lib/kya/identity";
import type {
	Activity,
	ActivityLoad,
	ActivityResponse,
	KyaWindow,
} from "@/lib/kya/types";
import { fmtByKind, fmtCount, fmtPercent } from "@/lib/metrics/format";
import { type MetricId, metric } from "@/lib/metrics/registry";
import { ObjectSurface } from "@tracelanedev/ui";
import Link from "next/link";
import { IdentityAvatar } from "./IdentityAvatar";

export type ActivityViewProps = {
	kind: IdentityKind;
	window: KyaWindow;
	profileKey?: string;
	result: ActivityLoad;
	onRetry: () => void;
};
const actionClass =
	"inline-flex items-center justify-center rounded-card border border-line bg-surface px-3 py-2 text-sm font-medium text-ink hover:bg-surface-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring";
const sources: Record<string, string> = {
	sdk: "agent name from your SDK",
	header: "agent name from header",
	client: "recognised from client",
	direct: "none (direct API calls)",
};
function Stamp({ us }: { us: number }) {
	const date = new Date(us / 1000);
	if (!Number.isFinite(date.getTime()) || us <= 0) return <span>Unknown</span>;
	const iso = date.toISOString();
	return <time dateTime={iso}>{formatDateTimeUtc(iso)}</time>;
}
function MetricCell({
	id,
	value,
	large = false,
}: { id: MetricId; value: number | null; large?: boolean }) {
	const def = metric(id);
	const formatted =
		def.kind === "percent"
			? fmtPercent(value, { floor: 1 }).text
			: fmtByKind(def.kind, value);
	return (
		<div className="min-w-0" data-metric={id}>
			<dt className="text-xs text-ink-3" title={def.numerator}>
				{def.label}
			</dt>
			<dd
				className={`${large ? "text-3xl" : "text-xl"} mt-1 break-words font-semibold tabular-nums tracking-tight text-ink`}
				title={value === null ? "Not recorded" : String(value)}
			>
				{formatted}
			</dd>
		</div>
	);
}
function IdentitySource({ row }: { row: Activity }) {
	return (
		<p className="text-xs leading-relaxed text-ink-2">
			<span className="text-ink-3">Identity source · </span>
			{row.sources
				.map((source) => sources[source.key] ?? "Unknown source")
				.join(" · ") || "Unknown source"}
		</p>
	);
}
function PriceCoverage({ row }: { row: Activity }) {
	return row.unpriced_calls > 0 ? (
		<p className="mt-1 text-xs text-ink-3">
			{fmtCount(row.unpriced_calls)}{" "}
			{row.unpriced_calls === 1 ? "call" : "calls"} unpriced
		</p>
	) : null;
}
function MakersAndProviders({
	row,
	kind,
}: { row: Activity; kind: IdentityKind }) {
	const identity = identityForKey(kind, row.key);
	return (
		<div className="space-y-1 text-sm text-ink-2">
			<p>
				{identity.makerLabel
					? `${kind === "model" ? "Made by " : ""}${identity.makerLabel}`
					: (identity.description ??
						(kind === "model"
							? "Maker not identified"
							: "Agent name supplied with your calls"))}
				{identity.makerLabel && identity.description
					? ` · ${identity.description}`
					: ""}
			</p>
			{kind === "model" && (
				<p className="text-xs text-ink-3">
					Served by{" "}
					{row.providers
						.map((provider) => providerIdentity(provider).label)
						.join(", ") || "unknown provider"}
				</p>
			)}
			{!identity.known && (
				<p className="text-xs text-ink-3">Not in our catalog yet</p>
			)}
		</div>
	);
}
export function NamingHelp({ open = false }: { open?: boolean }) {
	return (
		<details
			id="name-your-agent"
			open={open}
			className="rounded-card border border-line bg-surface p-5"
		>
			<summary className="cursor-pointer text-sm font-medium text-ink">
				Name your agent
			</summary>
			<p className="mt-3 text-sm text-ink-2">
				Give calls a name you recognise. Use either signal; a supplied agent
				name takes priority over client recognition.
			</p>
			<div className="mt-4 grid gap-4 lg:grid-cols-2">
				<div>
					<h3 className="mb-2 text-xs font-medium text-ink-2">
						From your SDK · on a chat span
					</h3>
					<pre className="overflow-x-auto rounded-card bg-canvas-sunken p-3 text-xs text-ink">
						<code>
							{
								'span.setAttribute("gen_ai.agent.name", "my-agent");\nspan.setAttribute("gen_ai.operation.name", "chat");'
							}
						</code>
					</pre>
				</div>
				<div>
					<h3 className="mb-2 text-xs font-medium text-ink-2">
						Through the gateway · request header
					</h3>
					<pre className="overflow-x-auto rounded-card bg-canvas-sunken p-3 text-xs text-ink">
						<code>x-tracelane-agent-name: my-agent</code>
					</pre>
				</div>
			</div>
			<p className="mt-3 text-xs text-ink-3">
				Use a project or agent name, not personal information. Names are
				supplied by callers and do not grant access.
			</p>
		</details>
	);
}
function Related({
	row,
	kind,
	retry,
	compact = false,
	window,
}: {
	row: Activity;
	kind: IdentityKind;
	retry: () => void;
	compact?: boolean;
	window: KyaWindow;
}) {
	const other = kind === "agent" ? "model" : "agent";
	return (
		<section
			className={
				compact ? "" : "rounded-card border border-line bg-surface p-5"
			}
		>
			<h3
				className={`${compact ? "text-xs text-ink-3" : "text-base font-semibold text-ink"} mb-3`}
			>
				{kind === "agent" ? "Models used" : "Agents using it"}
			</h3>
			{row.cross_list === null ? (
				<ListFailure retry={retry} />
			) : (
				<>
					<div className={compact ? "flex flex-wrap gap-2" : "space-y-3"}>
						{row.cross_list.map((entry) => (
							<div
								key={entry.key}
								className={
									compact
										? "rounded-card bg-canvas-sunken px-2 py-1 text-xs"
										: "flex items-center justify-between gap-3 text-sm"
								}
							>
								<IdentityAvatar
									identity={identityForKey(other, entry.key)}
									window={window}
									showLabel
								/>
								{!compact && (
									<span className="shrink-0 tabular-nums text-ink-2">
										{fmtCount(entry.calls)}{" "}
										{entry.calls === 1 ? "call" : "calls"}
									</span>
								)}
							</div>
						))}
					</div>
					{row.cross_count > row.cross_list.length && (
						<p className="mt-3 text-xs text-ink-3">
							+{fmtCount(row.cross_count - row.cross_list.length)} more
						</p>
					)}
				</>
			)}
		</section>
	);
}
function ListFailure({ retry }: { retry: () => void }) {
	return (
		<div className="flex items-center justify-between gap-3 rounded-card bg-canvas-sunken p-3 text-sm text-ink-2">
			<span>Couldn't load</span>
			<Button
				variant="bare"
				type="button"
				onClick={retry}
				className={actionClass}
			>
				Retry
			</Button>
		</div>
	);
}
function IdentityCard({
	row,
	kind,
	window,
	retry,
}: {
	row: Activity;
	kind: IdentityKind;
	window: KyaWindow;
	retry: () => void;
}) {
	const identity = identityForKey(kind, row.key);
	return (
		<ObjectSurface
			as="article"
			objectId={row.key}
			title={identity.label}
			href={`${identityHref(identity)}?window=${window}`}
			fields={[
				{ label: "Calls", value: fmtCount(row.calls) },
				{ label: "Errors", value: fmtCount(row.errors) },
				{ label: "Providers", value: row.providers.join(", ") || "Unknown" },
				{ label: "Source", value: <IdentitySource row={row} /> },
			]}
			className="flex min-w-0 flex-col rounded-card border border-line bg-surface p-5 shadow-sm"
		>
			<div className="flex items-start gap-3">
				<IdentityAvatar identity={identity} size={40} window={window} />
				<div className="min-w-0 flex-1">
					<h2 className="break-words text-lg font-semibold tracking-tight text-ink">
						<Link
							href={`${identityHref(identity)}?window=${window}`}
							className="hover:underline"
						>
							{identity.label}
						</Link>
					</h2>
					<MakersAndProviders row={row} kind={kind} />
				</div>
				<span aria-hidden="true" className="text-ink-3">
					↗
				</span>
			</div>
			<dl className="my-6 grid grid-cols-2 gap-x-4 gap-y-5">
				<MetricCell id="kya_calls" value={row.calls} large />
				<div>
					<MetricCell id="kya_cost" value={row.cost_usd} large />
					<PriceCoverage row={row} />
				</div>
				<MetricCell
					id="kya_error_rate"
					value={row.error_rate === null ? null : row.error_rate * 100}
				/>
				<MetricCell
					id="kya_p50"
					value={row.p50_us === null ? null : row.p50_us / 1000}
				/>
			</dl>
			<Related row={row} kind={kind} window={window} compact retry={retry} />
			<div className="mt-auto pt-5">
				<div className="border-t border-line pt-3">
					<IdentitySource row={row} />
				</div>
			</div>
		</ObjectSurface>
	);
}
function Profile({
	row,
	data,
	kind,
	window,
	retry,
}: {
	row: Activity;
	data: ActivityResponse;
	kind: IdentityKind;
	window: KyaWindow;
	retry: () => void;
}) {
	const identity = identityForKey(kind, row.key);
	const traceQuery = new URLSearchParams({
		[kind === "agent" ? "agent" : "model_family"]: row.key,
		since: new Date(data.since_us / 1000).toISOString(),
		until: new Date(data.until_us / 1000).toISOString(),
	});
	return (
		<div className="space-y-5">
			<PageHeader title={identity.label} />
			<section className="rounded-card border border-line bg-surface p-5 sm:p-7">
				<div className="flex flex-wrap items-center gap-5">
					<IdentityAvatar identity={identity} size={96} link={false} />
					<div className="min-w-0 flex-1">
						<div className="mt-2">
							<MakersAndProviders row={row} kind={kind} />
						</div>
						<div className="mt-3">
							<IdentitySource row={row} />
						</div>
					</div>
				</div>
				<div className="mt-6 grid gap-2 border-t border-line pt-4 text-xs text-ink-3 sm:grid-cols-2">
					<p>
						First seen in this window · <Stamp us={row.first_seen_us} />
					</p>
					<p>
						Last seen in this window · <Stamp us={row.last_seen_us} />
					</p>
				</div>
			</section>
			<section
				className="rounded-card border border-line bg-surface p-5 sm:p-7"
				aria-label="Activity in this window"
			>
				<dl className="grid grid-cols-2 gap-6 lg:grid-cols-4">
					<MetricCell id="kya_calls" value={row.calls} large />
					<MetricCell id="kya_traces" value={row.traces} large />
					<div>
						<MetricCell id="kya_cost" value={row.cost_usd} large />
						<PriceCoverage row={row} />
					</div>
					<MetricCell
						id="kya_error_rate"
						value={row.error_rate === null ? null : row.error_rate * 100}
						large
					/>
					<div>
						<MetricCell id="kya_tokens_in" value={row.tokens_in} />
						{row.input_usage_missing > 0 && (
							<p className="mt-1 text-xs text-ink-3">
								{fmtCount(row.input_usage_missing)}{" "}
								{row.input_usage_missing === 1 ? "call" : "calls"} without input
								usage
							</p>
						)}
					</div>
					<div>
						<MetricCell id="kya_tokens_out" value={row.tokens_out} />
						{row.output_usage_missing > 0 && (
							<p className="mt-1 text-xs text-ink-3">
								{fmtCount(row.output_usage_missing)}{" "}
								{row.output_usage_missing === 1 ? "call" : "calls"} without
								output usage
							</p>
						)}
					</div>
					<MetricCell
						id="kya_p50"
						value={row.p50_us === null ? null : row.p50_us / 1000}
					/>
					<MetricCell
						id="kya_p95"
						value={row.p95_us === null ? null : row.p95_us / 1000}
					/>
				</dl>
				<div className="mt-6 border-t border-line pt-4 text-sm text-ink-2">
					<span className="font-medium text-ink">
						{
							fmtPercent(
								row.share_of_workspace === null
									? null
									: row.share_of_workspace * 100,
								{ floor: 1 },
							).text
						}
					</span>{" "}
					· of workspace calls
				</div>
			</section>
			<div className="grid gap-5 lg:grid-cols-2">
				<Related row={row} kind={kind} window={window} retry={retry} />
				<section className="rounded-card border border-line bg-surface p-5">
					<h2 className="text-base font-semibold text-ink">Tools called</h2>
					<p className="mt-1 mb-4 text-xs text-ink-3">
						Names captured on tool spans and model responses.
					</p>
					{row.tools === null ? (
						<ListFailure retry={retry} />
					) : row.tools.length === 0 ? (
						<p className="text-sm text-ink-2">No tool calls recorded</p>
					) : (
						<>
							<div className="space-y-3">
								{row.tools.map((tool) => (
									<div
										key={tool.key}
										className="flex items-center justify-between gap-3 text-sm"
									>
										<span className="min-w-0 break-words font-mono text-ink">
											{tool.key}
										</span>
										<span
											className="shrink-0 tabular-nums text-ink-2"
											title={metric("kya_tool_calls").numerator}
										>
											{fmtCount(tool.calls)}{" "}
											{tool.calls === 1 ? "call" : "calls"}
										</span>
									</div>
								))}
							</div>
							{row.tool_count > row.tools.length && (
								<p className="mt-3 text-xs text-ink-3">
									+{fmtCount(row.tool_count - row.tools.length)} more
								</p>
							)}
						</>
					)}
				</section>
			</div>
			<section className="rounded-card border border-line bg-surface p-5">
				<div className="mb-4 flex flex-wrap items-center justify-between gap-3">
					<h2 className="text-base font-semibold text-ink">Recent traces</h2>
					<Link
						href={`/traces?${traceQuery}`}
						className="text-sm text-action-ink hover:underline"
					>
						View all in Traces →
					</Link>
				</div>
				{row.recent_traces === null ? (
					<ListFailure retry={retry} />
				) : (
					<div className="divide-y divide-line">
						{row.recent_traces.map((trace) => (
							<div
								key={trace.trace_id}
								className="flex flex-wrap items-center justify-between gap-2 py-3 text-xs"
							>
								<Link
									href={`/traces/${encodeURIComponent(trace.trace_id)}`}
									className="min-w-0 break-all font-mono text-action-ink hover:underline"
								>
									{trace.trace_id}
								</Link>
								<span className="text-ink-3">
									<Stamp us={trace.last_seen_us} />
								</span>
							</div>
						))}
					</div>
				)}
			</section>
		</div>
	);
}
function Loading() {
	return (
		<output className="block">
			<p className="mb-4 text-sm text-ink-2">Loading activity…</p>
			<div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
				{["claude-code", "codex", "gemini-cli"].map((key) => (
					<div
						key={key}
						className="rounded-card border border-line bg-surface p-5"
						aria-hidden="true"
					>
						<IdentityAvatar
							identity={identityForKey("agent", key)}
							size={40}
							link={false}
						/>
						<div className="mt-5 h-5 w-3/4 animate-pulse rounded bg-canvas-sunken" />
						<div className="mt-4 h-14 animate-pulse rounded bg-canvas-sunken" />
						<div className="mt-5 h-4 w-1/2 animate-pulse rounded bg-canvas-sunken" />
					</div>
				))}
			</div>
		</output>
	);
}
export function ActivityView({
	kind,
	window,
	profileKey,
	result,
	onRetry,
}: ActivityViewProps) {
	const data = result.status === "ready" ? result.data : null;
	const noun = kind === "agent" ? "agents" : "models";
	const path = profileKey
		? `/agents/${kind}/${encodeURIComponent(profileKey)}`
		: "/agents";
	return (
		<div className="space-y-5 px-2 py-3 sm:px-4 sm:py-4">
			<header className="flex flex-wrap items-center justify-between gap-3">
				<div>
					{profileKey ? (
						<Link
							href={`/agents?kind=${kind}&window=${window}`}
							className="text-sm text-ink-2 hover:underline"
						>
							← All {noun}
						</Link>
					) : (
						<>
							<PageHeader title={<>Agents</>} />
							<p className="mt-1 text-sm text-ink-2">
								Who made your model calls, what they used, and what happened.
								Open an identity to follow its activity into traces.
							</p>
						</>
					)}
				</div>
				<div className="flex flex-wrap items-center gap-3">
					{!profileKey && (
						<nav
							aria-label="Identity kind"
							className="flex rounded-card border border-line bg-surface p-1"
						>
							{(["agent", "model"] as const).map((tab) => (
								<Link
									key={tab}
									href={`/agents?kind=${tab}&window=${window}`}
									aria-current={kind === tab ? "page" : undefined}
									className={`rounded-control px-3 py-1.5 text-sm ${kind === tab ? "bg-selected font-medium text-selected-on" : "text-ink-2 hover:bg-surface-hover"}`}
								>
									{tab === "agent" ? "Agents" : "Models"}
								</Link>
							))}
						</nav>
					)}
					<nav aria-label="Activity window" className="flex gap-1">
						{(["7d", "30d"] as const).map((days) => (
							<Link
								key={days}
								href={`${path}?kind=${kind}&window=${days}`}
								aria-current={window === days ? "page" : undefined}
								className={`${actionClass} ${window === days ? "font-semibold" : "text-ink-3"}`}
							>
								{days}
							</Link>
						))}
					</nav>
				</div>
			</header>
			{data?.sample_data && (
				<p className="rounded-card border border-line bg-canvas-sunken px-4 py-2 text-xs text-ink-2">
					Sample data · local preview
				</p>
			)}
			{data && (
				<p className="text-xs text-ink-3">
					Last {data.window_days} days
					{data.window_days < data.requested_days
						? ` (your plan keeps ${data.retention_days})`
						: ""}{" "}
					· LLM calls only; tool, agent and internal spans are excluded from
					Calls.
				</p>
			)}
			{result.status === "loading" ? (
				<Loading />
			) : result.status === "error" ? (
				<section className="rounded-card border border-line bg-surface p-6">
					<h2 className="text-lg font-semibold text-ink">
						{result.code === 403
							? "You don't have access to traces in this workspace"
							: result.code === 404
								? "No activity for this identity in this window"
								: "Couldn't load agent activity. Your traces are unaffected."}
					</h2>
					<p className="mt-2 text-sm text-ink-2">
						{result.code === 403
							? "Ask your workspace owner for access."
							: result.code === 404
								? "Choose another window or return to the identity directory."
								: "Try the activity read again."}
					</p>
					{result.code !== 403 && (
						<Button
							variant="bare"
							type="button"
							onClick={onRetry}
							className={`${actionClass} mt-5`}
						>
							Retry
						</Button>
					)}
				</section>
			) : data && data.identities.length === 0 ? (
				<div className="space-y-5">
					<section className="rounded-card border border-line bg-surface p-7">
						<h2 className="text-xl font-semibold text-ink">
							{data.has_retained_activity
								? `No ${noun} in the last ${data.window_days} days`
								: "No agent activity yet."}
						</h2>
						<p className="mt-2 text-sm text-ink-2">
							{data.has_retained_activity
								? "Activity exists outside this selected window."
								: "Send a model call through the gateway, or record LLM spans with your SDK."}
						</p>
						{data.has_retained_activity && window === "7d" && (
							<Link
								href={`/agents?kind=${kind}&window=30d`}
								className={`${actionClass} mt-5`}
							>
								Switch to 30 days →
							</Link>
						)}
					</section>
					{!data.has_retained_activity && <NamingHelp open />}
				</div>
			) : data && profileKey && data.identities[0] ? (
				<Profile
					window={window}
					row={data.identities[0]}
					data={data}
					kind={kind}
					retry={onRetry}
				/>
			) : data ? (
				<>
					{kind === "agent" &&
						data.identities.every((row) => row.key === "~direct") && (
							<div className="rounded-card border border-line bg-canvas-sunken p-4 text-sm leading-relaxed text-ink-2">
								Your calls don't say which agent made them. Name your agent to
								get its own card.
							</div>
						)}
					<div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
						{data.identities.map((row) => (
							<IdentityCard
								key={row.key}
								row={row}
								kind={kind}
								window={window}
								retry={onRetry}
							/>
						))}
					</div>
					<p className="text-xs text-ink-3">
						{data.truncated
							? `Showing top ${fmtCount(data.identities.length)} of ${fmtCount(data.total_identities)} ${noun} by Calls`
							: `${fmtCount(data.total_identities)} ${data.total_identities === 1 ? kind : noun} with recorded calls in this window`}
					</p>
					{kind === "agent" && <NamingHelp />}
				</>
			) : null}
		</div>
	);
}

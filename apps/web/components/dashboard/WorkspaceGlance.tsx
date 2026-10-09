import type { WorkspaceGlanceResponse } from "@/lib/metrics/fetch";
import { fmtBytes, fmtCount, fmtUsd } from "@/lib/metrics/format";
import { METRICS } from "@/lib/metrics/registry";
import Link from "next/link";
import { StorageCard } from "./StorageCard";

type SectionState = WorkspaceGlanceResponse["volume"]["state"];
function Metric({
	label,
	value,
	state,
	detail,
	href,
}: {
	label: string;
	value: string;
	state: SectionState;
	detail?: string;
	href?: string;
}) {
	const body = (
		<>
			<p className="t-metric-label">{label}</p>
			<p className="mt-2 font-mono text-xl tabular-nums text-ink">
				{state === "ok" ? value : "—"}
			</p>
			<p className="mt-1 text-xs text-ink-2">
				{state === "over_cap"
					? "This window is too large to count on demand."
					: state === "denied"
						? "Read access denied."
						: state === "unavailable"
							? (detail ?? "Couldn’t compute this figure.")
							: detail}
			</p>
		</>
	);
	return href && state === "ok" ? (
		<Link
			href={href}
			className="rounded-card border border-line bg-surface p-3 hover:bg-surface-hover"
		>
			{body}
		</Link>
	) : (
		<div className="rounded-card border border-line bg-surface p-3">{body}</div>
	);
}

export function WorkspaceGlance({ data }: { data: WorkspaceGlanceResponse }) {
	const empty =
		data.volume.state === "ok" &&
		data.volume.traces === 0 &&
		data.ingest.state === "ok" &&
		data.ingest.total_bytes === 0;
	return (
		<section aria-label="Workspace at a glance" className="space-y-3">
			<div className="flex flex-wrap items-baseline justify-between gap-2">
				<h2 className="t-h2">Workspace at a glance</h2>
				<p className="text-xs text-ink-2">
					Not affected by the time range · as of{" "}
					{new Date(data.as_of).toLocaleString("en-US", {
						timeZone: "UTC",
						dateStyle: "medium",
						timeStyle: "short",
					})}{" "}
					UTC
				</p>
			</div>
			{empty ? (
				<div className="rounded-card border border-line bg-surface p-5">
					<p>
						Nothing recorded yet. Send a request through the gateway or point an
						OTLP exporter at us.
					</p>
					<Link
						href="/settings/api-keys"
						className="mt-2 inline-block text-action-ink underline"
					>
						Get started
					</Link>
				</div>
			) : (
				<div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
					<Metric
						label={`${METRICS.glance_traces.label} ${data.volume.window_days} days`}
						state={data.volume.state}
						value={fmtCount(data.volume.traces ?? 0)}
						detail={
							data.volume.state === "ok" && data.volume.traces
								? `${((data.volume.spans ?? 0) / data.volume.traces).toFixed(1)} spans per trace`
								: undefined
						}
						href="/traces"
					/>
					<Metric
						label={`${METRICS.glance_spans.label} · last ${data.volume.window_days} days`}
						state={data.volume.state}
						value={fmtCount(data.volume.spans ?? 0)}
						href="/traces"
					/>
					{data.ingest.source === "meter" && (
						<>
							<Metric
								label={METRICS.glance_ingested_total.label}
								state={data.ingest.state}
								value={fmtBytes(data.ingest.total_bytes)}
								detail={
									data.ingest.since
										? `Since metering began ${data.ingest.since}`
										: "No meter reading yet"
								}
							/>
							<Metric
								label={METRICS.glance_ingested_period.label}
								state={data.ingest.state}
								value={fmtBytes(data.ingest.period_bytes)}
								detail={
									data.ingest.period_kind === "billing_cycle"
										? "Your billing cycle"
										: "Calendar month"
								}
								href="/settings/billing"
							/>
						</>
					)}
					<Metric
						label={METRICS.glance_stored.label}
						state={data.stored.state}
						value={fmtBytes(data.stored.bytes)}
						detail={
							data.stored.state === "unavailable"
								? "not computed yet"
								: "Logical bytes within retention"
						}
					/>
					<Metric
						label={`${METRICS.glance_agents.label} · last ${data.agents.window_days} days`}
						state={data.agents.state}
						value={fmtCount(data.agents.active ?? 0)}
						detail={
							data.agents.state === "ok"
								? `${fmtCount(data.agents.direct_calls ?? 0)} direct API calls, excluded`
								: undefined
						}
						href="/agents"
					/>
					<Metric
						label={METRICS.glance_spend_period.label}
						state={data.spend.state}
						value={data.spend.usd === null ? "—" : fmtUsd(data.spend.usd)}
						detail={
							data.spend.unpriced_requests
								? `${fmtCount(data.spend.unpriced_requests)} calls unpriced`
								: "Priced calls only"
						}
						href="/gateway"
					/>
					<Metric
						label={`${METRICS.glance_providers.label} · last ${data.providers.window_days} days`}
						state={data.providers.state}
						value={fmtCount(data.providers.count ?? 0)}
						detail={data.providers.top.join(" · ") || "No provider recorded"}
						href="/settings/providers"
					/>
				</div>
			)}
			{data.storage ? (
				<StorageCard storage={data.storage} />
			) : (
				<p className="text-xs text-ink-3">
					On-disk size isn&apos;t shown on Tracelane Cloud — storage is shared
					and we don&apos;t measure it per workspace. Ingested and Stored are
					the figures your plan is measured on.
				</p>
			)}
		</section>
	);
}

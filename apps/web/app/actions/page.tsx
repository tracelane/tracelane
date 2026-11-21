import {
	CoveragePanel,
	loadCoverage,
} from "@/components/actions/CoveragePanel";
import { ReadFailure } from "@/components/empty-states/ReadFailure";
import { type ActionList, evidenceSummary, stateInfo } from "@/lib/actions";
import { formatDateTimeUtc } from "@/lib/format-date";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import { Badge, PageHeader } from "@tracelanedev/ui";
import Link from "next/link";

const COVERAGE =
	"Shows calls to protected tools that went through Tracelane. Calls that do not go through Tracelane are not seen.";

export default async function ActionsPage({
	searchParams,
}: { searchParams?: Promise<{ before?: string }> }) {
	const raw = (await searchParams)?.before;
	const before = raw && /^\d{1,18}$/.test(raw) ? raw : null;
	const header = (
		<>
			<PageHeader title="Actions" note={COVERAGE} />
		</>
	);
	// Start coverage alongside the actions read, so it never adds a serial round trip.
	const coveragePromise = loadCoverage();
	let data: ActionList;
	try {
		data = await gatewayGet<ActionList>(
			`/v1/actions${before ? `?before=${before}` : ""}`,
		);
	} catch (err) {
		const status = err instanceof GatewayError ? err.status : 503;
		return (
			<div className="space-y-4 p-6">
				{header}
				{status === 409 ? (
					<p role="alert" className="text-sm">
						Action control is off for this workspace.
					</p>
				) : (
					<ReadFailure
						status={status}
						resource="actions"
						retryHref="/actions"
					/>
				)}
			</div>
		);
	}
	const coverage = await coveragePromise;
	return (
		<div className="space-y-4 p-6">
			{header}
			<CoveragePanel coverage={coverage} />
			{(data.skipped_malformed ?? 0) > 0 && (
				<p className="text-sm text-ink-2">
					{data.skipped_malformed} action record(s) on this page could not be
					read and are not shown. Download evidence to inspect them.
				</p>
			)}
			{data.actions.length === 0 ? (
				<p className="rounded-card border border-line p-6 text-sm">
					No protected actions yet. Protected tools are configured with the
					policy API.
				</p>
			) : (
				<ul className="divide-y divide-line rounded-card border border-line">
					{data.actions.map((a) => {
						const s = stateInfo(a.state);
						return (
							<li key={a.action_id}>
								<Link
									href={`/actions/${encodeURIComponent(a.action_id)}`}
									className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-3 text-sm"
								>
									<span className="font-mono text-xs text-ink-2">
										{formatDateTimeUtc(a.occurred_at)}
									</span>
									<span className="font-mono">{a.tool_name ?? "—"}</span>
									<span className="flex-1 text-ink-2">
										{evidenceSummary(a.evidence)}
									</span>
									{a.malformed && (
										<span className="text-xs text-ink-2">Unreadable event</span>
									)}
									<Badge tone={s.tone}>{s.label}</Badge>
								</Link>
							</li>
						);
					})}
				</ul>
			)}
			<div className="flex gap-4 text-sm">
				{before && (
					<Link className="underline" href="/actions">
						Newest
					</Link>
				)}
				{data.next_before != null && (
					<Link
						className="underline"
						href={`/actions?before=${data.next_before}`}
					>
						Older →
					</Link>
				)}
			</div>
		</div>
	);
}

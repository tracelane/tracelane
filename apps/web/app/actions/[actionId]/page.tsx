import { ReadFailure } from "@/components/empty-states/ReadFailure";
import { RoleScope } from "@/components/gateway/RoleScope";
import {
	type ActionDetail,
	type ActionEventRow,
	EVIDENCE_MODE_LABEL,
	approvalStatusLabel,
	eventLabel,
	evidenceValue,
} from "@/lib/actions";
import { formatDateTimeUtc } from "@/lib/format-date";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import { Badge, PageHeader } from "@tracelanedev/ui";
import Link from "next/link";
import { DecisionPanel } from "./DecisionPanel";

function bodyNote(e: ActionEventRow): string | null {
	const b = e.body ?? {};
	const s = (k: string) =>
		typeof b[k] === "string" || typeof b[k] === "number" ? String(b[k]) : null;
	// Field names are the signed payload's own (packages/verifier-rust/src/action/mod.rs
	// ActionPayload). A renamed field renders nothing rather than a guess.
	const parts =
		e.event_type === "decision_made"
			? [
					s("decision") &&
						`Decision ${String(s("decision")).replaceAll("_", " ")}`,
					s("rule_id") && `rule ${s("rule_id")}`,
					s("policy_version") && `policy v${s("policy_version")}`,
				]
			: e.event_type.startsWith("execution_")
				? [
						s("receipt_digest") &&
							`receipt ${String(s("receipt_digest")).slice(0, 12)}`,
					]
				: e.event_type === "denied_runtime"
					? [
							s("reason") &&
								`Reason ${String(s("reason")).replaceAll("_", " ")}`,
						]
					: [];
	const out = parts.filter(Boolean).join(" · ");
	return out || null;
}

export default async function ActionPage({
	params,
}: { params: Promise<{ actionId: string }> }) {
	const { actionId } = await params;
	let d: ActionDetail;
	try {
		d = await gatewayGet<ActionDetail>(
			`/v1/actions/${encodeURIComponent(actionId)}`,
		);
	} catch (err) {
		const status = err instanceof GatewayError ? err.status : 503;
		return (
			<div className="space-y-4 p-6">
				<Link href="/actions" className="underline">
					Actions
				</Link>
				{status === 404 ? (
					<p role="alert">This action doesn't exist in this workspace.</p>
				) : status === 409 ? (
					<p role="alert">Action control is off for this workspace.</p>
				) : (
					<ReadFailure
						status={status}
						resource="this action"
						retryHref={`/actions/${encodeURIComponent(actionId)}`}
					/>
				)}
			</div>
		);
	}
	const events = [...d.events].sort((a, b) => a.seq - b.seq);
	const proposed = events.find((e) => e.event_type === "action_proposed");
	const ap = d.approval;
	const isPending = ap?.status === "pending";
	const pending = isPending && !!d.descriptor_digest;
	return (
		<div className="space-y-4 p-6">
			<Link href="/actions" className="underline">
				Actions
			</Link>
			<PageHeader
				title={
					ap?.tool_name ?? (proposed ? "Protected action" : "Refused action")
				}
				actions={
					ap && (
						<Badge tone={isPending ? "warn" : "neutral"}>
							{approvalStatusLabel(ap.status)}
						</Badge>
					)
				}
			/>
			<ol className="space-y-2 border-l border-line pl-4">
				{events.map((e) => (
					<li key={e.seq} className="text-sm">
						<span className="font-mono text-xs text-ink-2">
							#{e.seq} {formatDateTimeUtc(e.occurred_at)}
						</span>{" "}
						{eventLabel(e.event_type)}
						{e.event_type === "approval_requested" && ap?.expires_at && (
							<span className="text-ink-2">
								{" "}
								— expires {formatDateTimeUtc(ap.expires_at)}
							</span>
						)}
						{bodyNote(e) && (
							<span className="text-ink-2"> — {bodyNote(e)}</span>
						)}
					</li>
				))}
			</ol>
			{d.events_truncated && (
				<p className="text-sm text-ink-2">
					Older events not shown — download evidence for the full record.
				</p>
			)}
			{d.approval_expired && (
				<p className="text-sm text-ink-2">
					The bound request details are past retention. The events above remain.
				</p>
			)}
			{ap && isPending && !pending && (
				<output className="block text-sm text-ink-2">
					This request can't be decided from this view.
				</output>
			)}
			{ap && pending && (
				<section className="space-y-3 rounded-card border border-line p-4">
					<h2 className="text-sm font-medium">Bound request</h2>
					<dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1 text-sm">
						<dt className="text-ink-2">Tool</dt>
						<dd className="font-mono">
							{ap.tool_name}
							{ap.server_id ? ` @ ${ap.server_id}` : ""}
						</dd>
						<dt className="text-ink-2">Policy</dt>
						<dd className="font-mono">
							{ap.policy_id} v{ap.policy_version}{" "}
							<span title={ap.policy_hash}>
								hash {ap.policy_hash.slice(0, 12)}
							</span>
						</dd>
						{ap.proposer_key_id && (
							<>
								<dt className="text-ink-2">Proposer key</dt>
								<dd className="font-mono">{ap.proposer_key_id}</dd>
							</>
						)}
						{Object.entries(ap.evidence_fields).map(([name, f]) => (
							<div key={name} className="contents">
								<dt className="font-mono text-ink-2">{name}</dt>
								<dd>
									{evidenceValue(f, ap.evidence_fields)}{" "}
									<span className="text-xs text-ink-3">
										{EVIDENCE_MODE_LABEL[f.mode] ?? f.mode}
									</span>
								</dd>
							</div>
						))}
					</dl>
					<RoleScope>
						<DecisionPanel
							approvalId={ap.approval_id}
							digest={d.descriptor_digest ?? ""}
						/>
					</RoleScope>
				</section>
			)}
			<p className="text-sm text-ink-2">
				<a className="underline" href="/api/audit/export">
					Download evidence
				</a>{" "}
				· Verify offline with <code>tlane verify</code>.
			</p>
		</div>
	);
}

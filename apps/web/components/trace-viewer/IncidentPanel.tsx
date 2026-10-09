"use client";
import { ApiError, apiFetch, apiFetchRaw } from "@/lib/api-fetch";
import { useQuery } from "@tanstack/react-query";
import { Button, Skeleton } from "@tracelanedev/ui";
import { useId, useState } from "react";

type Evidence = { field: string; failing: unknown; good: unknown };
export type IncidentPacket = {
	trigger: {
		kind: string;
		label?: string;
		result?: string;
		span_id?: string;
	}[];
	what_happened: { trace_id: string; span_id: string; note?: string | null };
	what_changed: {
		good_trace_id: string | null;
		fields: (Evidence & { changed: boolean })[];
		note: string | null;
		prompt_version: string;
	};
	linked_spans: { trace_id: string; span_id: string }[];
	explanations: {
		note: string | null;
		items: {
			what: string;
			confidence: "supported" | "uncertain";
			evidence: Evidence[];
		}[];
	};
	limits: {
		incident_last_good_lookback_hours: number;
		export_permission: "allowed" | "forbidden" | "unavailable";
		can_record_outcome: boolean;
		outcome_reason_max_bytes: number;
	};
};
type Outcome = {
	result: "success" | "failure";
	reason: string;
	version: number;
};
const fieldNames: Record<string, string> = {
	gen_ai_request_model: "Requested model",
	gen_ai_response_model: "Served model",
	tracelane_model_substitution: "Substitution verdict",
	tracelane_request_tool_definitions_hash: "Tool definitions hash",
	tracelane_request_tool_count: "Tool count",
	deployment_environment: "Environment",
	service_version: "Release",
};
function display(value: unknown): string {
	return value == null || value === ""
		? "not captured"
		: typeof value === "string"
			? value
			: JSON.stringify(value);
}
function failure(error: unknown): string {
	if (error instanceof ApiError) {
		if (error.status === 403)
			return "Your role or API key does not permit this action.";
		if (error.status === 404) return "This trace is unavailable.";
		if (error.status === 422)
			return "Content not captured. This trace has no readable recorded input to export.";
		if (error.status === 429)
			return "Outcome rate limit reached. Wait before retrying.";
		if (error.body?.code === "reason_too_long")
			return `Reason exceeds the ${error.body.max_bytes} byte limit. Shorten it and retry.`;
	}
	return "Could not load or save incident data. Retry.";
}
export function IncidentPanel({ traceId }: { traceId: string }) {
	const incident = useQuery({
		queryKey: ["incident", traceId],
		queryFn: () =>
			apiFetch<IncidentPacket>(
				`/api/traces/${encodeURIComponent(traceId)}/incident`,
			),
		retry: false,
	});
	const outcome = useQuery({
		queryKey: ["outcome", traceId],
		queryFn: () =>
			apiFetch<{ outcome: Outcome | null }>(
				`/api/outcomes?subject=${encodeURIComponent(traceId)}`,
			),
		retry: false,
	});
	const [reason, setReason] = useState("");
	const [mode, setMode] = useState<"recorded" | "mocked">("recorded");
	const [format, setFormat] = useState<"dataset" | "promptfoo">("dataset");
	const [busy, setBusy] = useState(false);
	const [notice, setNotice] = useState<string | null>(null);
	const [actionError, setActionError] = useState<string | null>(null);
	const id = useId();
	async function record(result: "success" | "failure") {
		setBusy(true);
		setActionError(null);
		setNotice(null);
		try {
			await apiFetch("/api/outcomes", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					subject_kind: "trace",
					subject_id: traceId,
					result,
					reason,
					source: "web",
				}),
			});
			setNotice(`Outcome recorded: ${result}.`);
			await Promise.all([outcome.refetch(), incident.refetch()]);
		} catch (err) {
			setActionError(failure(err));
		} finally {
			setBusy(false);
		}
	}
	async function download() {
		setBusy(true);
		setActionError(null);
		setNotice(null);
		try {
			const response = await apiFetchRaw(
				`/api/traces/${encodeURIComponent(traceId)}/regression?format=${format}&mode=${mode}`,
			);
			if (!response.ok)
				throw new ApiError(
					response.status,
					undefined,
					await response.json().catch(() => null),
				);
			const url = URL.createObjectURL(await response.blob());
			const anchor = document.createElement("a");
			anchor.href = url;
			anchor.download =
				format === "dataset" ? "regression.jsonl" : "regression.promptfoo.json";
			document.body.appendChild(anchor);
			anchor.click();
			anchor.remove();
			URL.revokeObjectURL(url);
			setNotice(
				response.headers.get("x-truncated") === "true"
					? "Exported up to the case limit. The file is marked truncated."
					: "Fixture exported. Expected output is null; choose assertions before running a model.",
			);
		} catch (err) {
			setActionError(failure(err));
		} finally {
			setBusy(false);
		}
	}
	const packet = incident.data;
	return (
		<section
			aria-labelledby={`${id}-title`}
			className="mt-6 space-y-5 rounded-card border border-line bg-surface-1 p-5"
		>
			<div>
				<h2 id={`${id}-title`} className="text-base font-semibold text-ink">
					Incident packet
				</h2>
				<p className="mt-1 text-sm text-ink-2">
					Recorded evidence and changes since the last comparable good run.
				</p>
			</div>
			{incident.isPending ? (
				<div aria-label="Loading incident packet" className="space-y-2">
					<Skeleton className="h-8 w-full" />
					<Skeleton className="h-8 w-full" />
				</div>
			) : incident.error ? (
				<div role="alert" className="text-sm text-ink-2">
					{failure(incident.error)}{" "}
					<Button variant="secondary" onClick={() => void incident.refetch()}>
						Retry incident
					</Button>
				</div>
			) : packet ? (
				<>
					<div className="flex flex-wrap gap-2">
						{packet.trigger.length === 0 ? (
							<p className="text-sm text-ink-2">no failing signal recorded</p>
						) : (
							packet.trigger.map((trigger, index) => (
								<span
									key={`${trigger.kind}-${trigger.span_id ?? trigger.label ?? index}`}
									className="rounded-control bg-surface-2 px-2 py-1 text-xs text-ink"
								>
									{trigger.kind === "error"
										? "Error status"
										: `${trigger.kind}: ${trigger.label ?? trigger.result ?? "recorded"}`}
								</span>
							))
						)}
					</div>
					<div>
						<h3 className="text-sm font-medium text-ink">What changed</h3>
						<p className="mt-1 text-xs text-ink-2">
							Lookback: {packet.limits.incident_last_good_lookback_hours} hours
							· {packet.what_changed.prompt_version}
						</p>
						{packet.what_changed.note ? (
							<p className="mt-3 text-sm text-ink-2">
								{packet.what_changed.note}
							</p>
						) : (
							<div className="mt-3 overflow-x-auto">
								<table className="w-full text-left text-sm">
									<thead className="text-xs text-ink-2">
										<tr>
											<th className="pb-2">Field</th>
											<th className="pb-2">Last good run</th>
											<th className="pb-2">This run</th>
										</tr>
									</thead>
									<tbody>
										{packet.what_changed.fields.map((field) => (
											<tr key={field.field} className="border-t border-line">
												<th className="py-2 pr-3 font-normal">
													{fieldNames[field.field] ?? field.field}
												</th>
												<td className="max-w-xs break-all py-2 pr-3 text-ink-2">
													{display(field.good)}
												</td>
												<td className="max-w-xs break-all py-2 text-ink">
													{display(field.failing)}
													{field.changed ? (
														<span className="ml-2 text-xs text-ink-2">
															changed
														</span>
													) : null}
												</td>
											</tr>
										))}
									</tbody>
								</table>
							</div>
						)}
						{packet.what_changed.good_trace_id ? (
							<a
								className="mt-2 inline-block text-sm underline"
								href={`/traces/${encodeURIComponent(packet.what_changed.good_trace_id)}`}
							>
								Open last good run
							</a>
						) : null}
					</div>
					<div>
						<h3 className="text-sm font-medium text-ink">Explanations</h3>
						{packet.explanations.note ? (
							<p className="mt-2 text-sm text-ink-2">
								{packet.explanations.note}
							</p>
						) : (
							<ul className="mt-2 space-y-3">
								{packet.explanations.items.map((explanation) => (
									<li
										key={`${explanation.what}-${explanation.evidence.map((e) => e.field).join("-")}`}
										className="rounded-control border border-line p-3"
									>
										<div className="flex flex-wrap items-center gap-2">
											<span className="text-sm text-ink">
												{explanation.what}
											</span>
											<span className="rounded-control bg-surface-2 px-2 py-0.5 text-xs text-ink-2">
												{explanation.confidence}
											</span>
										</div>
										<ul className="mt-2 space-y-1 text-xs text-ink-2">
											{explanation.evidence.map((e) => (
												<li key={e.field}>
													{fieldNames[e.field] ?? e.field}: {display(e.good)} →{" "}
													{display(e.failing)}
												</li>
											))}
										</ul>
									</li>
								))}
							</ul>
						)}
					</div>
					<div>
						<h3 className="text-sm font-medium text-ink">Linked spans</h3>
						<div className="mt-2 flex flex-wrap gap-3">
							{packet.linked_spans.map((span) => (
								<a
									key={span.span_id}
									className="font-mono text-xs underline"
									href={`/traces/${encodeURIComponent(span.trace_id)}?span=${encodeURIComponent(span.span_id)}`}
								>
									{span.span_id}
								</a>
							))}
						</div>
					</div>
					{packet.limits.export_permission === "allowed" ? (
						<div className="space-y-2 border-t border-line pt-4">
							<h3 className="text-sm font-medium text-ink">
								Regression fixture
							</h3>
							<p className="text-xs text-ink-2">
								Recorded: inspect captured input. Mocked: replay with recorded
								tool messages as fixed context. No tools execute. Live mode is
								not supported.
							</p>
							<div className="flex flex-wrap items-center gap-2">
								<label className="text-sm" htmlFor={`${id}-mode`}>
									Mode
								</label>
								<select
									id={`${id}-mode`}
									value={mode}
									onChange={(e) => setMode(e.target.value as typeof mode)}
									className="rounded-control border border-line bg-surface-1 p-2 text-sm"
								>
									<option value="recorded">Recorded</option>
									<option value="mocked">Mocked</option>
								</select>
								<label className="text-sm" htmlFor={`${id}-format`}>
									Format
								</label>
								<select
									id={`${id}-format`}
									value={format}
									onChange={(e) => setFormat(e.target.value as typeof format)}
									className="rounded-control border border-line bg-surface-1 p-2 text-sm"
								>
									<option value="dataset">Dataset JSONL</option>
									<option value="promptfoo">Promptfoo</option>
								</select>
								<Button
									variant="secondary"
									disabled={busy}
									onClick={() => void download()}
								>
									Export fixture
								</Button>
							</div>
						</div>
					) : (
						<p className="text-xs text-ink-2">
							{packet.limits.export_permission === "unavailable"
								? "Export permission could not be verified."
								: "Fixture export requires datasets access and a role that can manage datasets."}
						</p>
					)}
				</>
			) : null}
			<div className="space-y-2 border-t border-line pt-4">
				<h3 className="text-sm font-medium text-ink">Task outcome</h3>
				{outcome.isPending ? (
					<Skeleton className="h-8 w-full" />
				) : outcome.error ? (
					<p role="alert" className="text-sm text-ink-2">
						{failure(outcome.error)}{" "}
						<Button variant="secondary" onClick={() => void outcome.refetch()}>
							Retry outcome
						</Button>
					</p>
				) : outcome.data?.outcome ? (
					<p className="text-sm text-ink">
						Recorded: {outcome.data.outcome.result}
						{outcome.data.outcome.reason
							? ` — ${outcome.data.outcome.reason}`
							: ""}
					</p>
				) : (
					<p className="text-sm text-ink-2">
						No outcome recorded. Record outcomes with{" "}
						<code>POST /v1/outcomes</code>.
					</p>
				)}
				{packet?.limits.can_record_outcome ? (
					<>
						<label
							htmlFor={`${id}-reason`}
							className="block text-sm text-ink-2"
						>
							Reason (optional; {packet.limits.outcome_reason_max_bytes} bytes
							maximum)
						</label>
						<textarea
							id={`${id}-reason`}
							value={reason}
							onChange={(e) => setReason(e.target.value)}
							rows={2}
							className="w-full rounded-control border border-line bg-surface-1 p-2 text-sm text-ink"
						/>
						<div className="flex gap-2">
							<Button
								variant="secondary"
								disabled={busy}
								onClick={() => void record("success")}
							>
								Record success
							</Button>
							<Button
								variant="secondary"
								disabled={busy}
								onClick={() => void record("failure")}
							>
								Record failure
							</Button>
						</div>
					</>
				) : packet ? (
					<p className="text-xs text-ink-2">
						Your role or API key cannot record outcomes.
					</p>
				) : null}
			</div>
			{actionError ? (
				<p role="alert" className="text-sm text-ink">
					{actionError}
				</p>
			) : null}
			{notice ? <output className="text-sm text-ink-2">{notice}</output> : null}
		</section>
	);
}

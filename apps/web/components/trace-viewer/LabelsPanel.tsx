import { outputSpeed } from "@/lib/output-speed";

const text = (value: unknown) =>
	typeof value === "string" && value.length > 0 ? value : null;
const record = (value: unknown): Record<string, unknown> =>
	value && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: {};

export function LabelsPanel({
	attrs,
	durationUs,
	minGenerationMs,
}: {
	attrs: Record<string, unknown>;
	durationUs: number;
	minGenerationMs?: number;
}) {
	const environment = text(attrs.deployment_environment);
	const release = text(attrs.service_version);
	const service = text(attrs.service_name);
	const tags = Array.isArray(attrs.tracelane_tags)
		? attrs.tracelane_tags.filter(
				(tag): tag is string => typeof tag === "string",
			)
		: [];
	const metadata = Object.entries(record(attrs.tracelane_metadata)).filter(
		(entry): entry is [string, string] => typeof entry[1] === "string",
	);
	const dropped = Object.entries(record(attrs.tracelane_labels_dropped)).filter(
		(entry): entry is [string, number] =>
			typeof entry[1] === "number" && entry[1] > 0,
	);
	const hasLabels = !!(
		environment ||
		release ||
		service ||
		tags.length ||
		metadata.length ||
		dropped.length
	);
	const speed =
		minGenerationMs === undefined
			? null
			: outputSpeed(attrs, durationUs, minGenerationMs);
	const streamed =
		attrs.gen_ai_request_stream === true || attrs.gen_ai_request_stream === 1;
	const generationMs =
		(durationUs - (Number(attrs.tracelane_gateway_overhead_us) || 0)) / 1000 -
		Number(attrs.gen_ai_response_time_to_first_chunk) * 1000;
	const tooShort =
		streamed &&
		minGenerationMs !== undefined &&
		Number.isFinite(generationMs) &&
		generationMs > 0 &&
		generationMs < minGenerationMs;
	return (
		<div className="space-y-3">
			{hasLabels && (
				<section
					aria-label="Labels"
					className="space-y-2 rounded-card border border-line bg-surface-2 p-3 text-sm"
				>
					<h3 className="t-metric-label">Labels</h3>
					<p>
						{[
							environment && `Environment ${environment}`,
							release && `Release ${release}`,
							service && `Service ${service}`,
						]
							.filter(Boolean)
							.join(" · ") || "Deployment labels not recorded"}
					</p>
					{tags.length > 0 && <p>Tags: {tags.join(" · ")}</p>}
					{metadata.length > 0 && (
						<table className="w-full text-xs">
							<caption className="text-left font-semibold">Metadata</caption>
							<tbody>
								{metadata.map(([key, value]) => (
									<tr key={key}>
										<th className="py-1 pr-2 text-left font-mono font-normal text-ink-2">
											{key}
										</th>
										<td className="break-all py-1">{value}</td>
									</tr>
								))}
							</tbody>
						</table>
					)}
					{dropped.length > 0 && (
						<p className="text-xs text-warn-ink">
							Labels dropped at capture:{" "}
							{dropped.map(([key, count]) => `${key} ${count}`).join(" · ")}
						</p>
					)}
				</section>
			)}
			{(attrs.gen_ai_request_stream !== undefined ||
				attrs.gen_ai_request_model !== undefined) && (
				<section
					aria-label="Output speed"
					className="rounded-card border border-line bg-surface-2 p-3 text-sm"
				>
					<h3 className="t-metric-label">Output speed</h3>
					<p className="font-mono tabular-nums">
						{speed
							? `${speed.estimated ? "≈" : ""}${Math.round(speed.value)} tok/s${speed.estimated ? " (estimated tokens)" : ""}`
							: "—"}
					</p>
					{!speed && (
						<p className="mt-1 text-xs text-ink-2">
							{!streamed
								? "Only measured for streamed responses: a non-streamed reply has no first-token time, so generation can't be separated from waiting."
								: minGenerationMs === undefined
									? "Output speed setting unavailable."
									: tooShort
										? `Too short to measure (< ${minGenerationMs} ms of generation).`
										: "First-token time or output tokens were not recorded."}
						</p>
					)}
				</section>
			)}
		</div>
	);
}

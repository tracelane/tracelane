"use client";

/** The caller's settings on this span. Missing fields are never provider defaults. */
export function RequestConfigPanel({
	attrs,
	previousToolHash,
	toolPreviewLimit,
}: {
	attrs: Record<string, unknown>;
	previousToolHash?: string;
	toolPreviewLimit?: number;
}) {
	const fields = [
		["Temperature", "gen_ai_request_temperature"],
		["Top P", "gen_ai_request_top_p"],
		["Max tokens", "gen_ai_request_max_tokens"],
		["Seed", "gen_ai_request_seed"],
		["Tool choice", "tracelane_request_tool_choice_mode"],
		["Tool choice function", "tracelane_request_tool_choice_function"],
		["Deployment ID", "tracelane_request_deployment_id"],
		["ZDR required", "tracelane_zdr_required"],
	] as const;
	const names = Array.isArray(attrs.tracelane_request_tool_names)
		? attrs.tracelane_request_tool_names.filter(
				(v): v is string => typeof v === "string",
			)
		: [];
	const offered =
		typeof attrs.tracelane_request_tool_count === "number"
			? attrs.tracelane_request_tool_count
			: undefined;
	const hash =
		typeof attrs.tracelane_request_tool_definitions_hash === "string"
			? attrs.tracelane_request_tool_definitions_hash
			: undefined;
	const flags = Array.isArray(attrs.tracelane_misconfig_flags)
		? attrs.tracelane_misconfig_flags.filter(
				(v): v is string => typeof v === "string",
			)
		: undefined;
	const hasConfig =
		fields.some(([, key]) => attrs[key] !== undefined) ||
		offered !== undefined ||
		names.length > 0 ||
		hash !== undefined ||
		flags !== undefined;
	if (!hasConfig) return null;
	const shown = names.slice(0, toolPreviewLimit ?? names.length);
	return (
		<section
			className="rounded-card border border-line bg-surface-2 p-3"
			aria-label="Request config"
		>
			<h3 className="mb-2 t-metric-label">Request config</h3>
			<dl className="space-y-1 text-xs">
				{fields.map(([label, key]) => (
					<div className="flex justify-between gap-3" key={key}>
						<dt className="text-ink-3">{label}</dt>
						<dd className="break-all text-right text-ink">
							{attrs[key] === undefined ? "not recorded" : String(attrs[key])}
						</dd>
					</div>
				))}
				<div className="flex justify-between gap-3">
					<dt className="text-ink-3">Tools offered</dt>
					<dd className="text-right text-ink">
						{offered === undefined ? "not recorded" : offered}
					</dd>
				</div>
			</dl>
			{names.length > 0 && (
				<p className="mt-2 break-words text-xs text-ink-2">
					{shown.join(", ")}{" "}
					<span className="text-ink-3">
						{shown.length < names.length ||
						(offered !== undefined && offered > names.length)
							? `(showing ${shown.length} of ${names.length} recorded · ${offered ?? names.length} offered)`
							: ""}
					</span>
				</p>
			)}
			{hash && (
				<p className="mt-2 break-all text-xs text-ink-3">
					Tool definitions hash: <code className="font-mono">{hash}</code>
				</p>
			)}
			{hash && previousToolHash && (
				<p
					className={
						hash === previousToolHash
							? "mt-1 text-xs text-ink-3"
							: "mt-1 text-xs text-warn-ink"
					}
				>
					{hash === previousToolHash
						? "same tool set as the previous call"
						: "tool set CHANGED since the previous call"}
				</p>
			)}
			<div className="mt-2 text-xs text-ink-2">
				Misconfiguration:{" "}
				{flags === undefined ? (
					"Not evaluated"
				) : flags.length === 0 ? (
					"Checked: no flags"
				) : (
					<span className="text-danger-ink">{flags.join(", ")}</span>
				)}
			</div>
			<p className="mt-2 text-2xs text-ink-3">
				Tracelane does not record: stop sequences, frequency or presence
				penalty, n, response format, reasoning effort, top k, or
				provider-specific options.
			</p>
		</section>
	);
}

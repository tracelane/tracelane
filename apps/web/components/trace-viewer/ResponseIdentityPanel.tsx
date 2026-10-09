"use client";

import { CopyButton } from "./CopyButton";
import type { Span } from "./types";

/** Provider-returned identity and a bounded probability summary, when present. */
export function ResponseIdentityPanel({
	attrs,
	caps,
}: { attrs: Record<string, unknown>; caps?: Span["caps"] }) {
	const responseId =
		typeof attrs.gen_ai_response_id === "string"
			? attrs.gen_ai_response_id
			: undefined;
	const model =
		typeof attrs.gen_ai_response_model === "string"
			? attrs.gen_ai_response_model
			: undefined;
	const fingerprint =
		typeof attrs["openai.response.system_fingerprint"] === "string"
			? attrs["openai.response.system_fingerprint"]
			: undefined;
	const reasons = Array.isArray(attrs.gen_ai_response_finish_reasons)
		? attrs.gen_ai_response_finish_reasons.filter(
				(v): v is string => typeof v === "string",
			)
		: [];
	const mean =
		typeof attrs.tracelane_response_logprob_mean === "number"
			? attrs.tracelane_response_logprob_mean
			: undefined;
	const min =
		typeof attrs.tracelane_response_logprob_min === "number"
			? attrs.tracelane_response_logprob_min
			: undefined;
	const count =
		typeof attrs.tracelane_response_logprob_token_count === "number"
			? attrs.tracelane_response_logprob_token_count
			: undefined;
	if (
		attrs.gen_ai_request_model === undefined &&
		!responseId &&
		!model &&
		!fingerprint &&
		reasons.length === 0 &&
		count === undefined
	)
		return null;
	const measured =
		mean !== undefined &&
		min !== undefined &&
		count !== undefined &&
		count > 0 &&
		Number.isFinite(mean) &&
		Number.isFinite(min) &&
		mean <= 0 &&
		min <= 0;
	const pct = (logprob: number) =>
		`${(Math.exp(logprob) * 100).toFixed(1).replace(/\.0$/, "")}%`;
	return (
		<section
			className="rounded-card border border-line bg-surface-2 p-3"
			aria-label="Response identity"
		>
			<h3 className="mb-2 t-metric-label">Response identity</h3>
			<dl className="space-y-1 text-xs">
				{responseId && (
					<div className="flex items-center justify-between gap-2">
						<dt className="text-ink-3">Provider response ID</dt>
						<dd
							className="flex items-center gap-1 break-all font-mono text-ink"
							title="Quote this to the provider's support"
						>
							{responseId}
							<CopyButton value={responseId} label="Copy response ID" />
						</dd>
					</div>
				)}
				{model && (
					<div className="flex justify-between gap-3">
						<dt className="text-ink-3">Served model</dt>
						<dd className="text-right text-ink">{model}</dd>
					</div>
				)}
				{fingerprint && (
					<div className="flex justify-between gap-3">
						<dt className="text-ink-3">System fingerprint</dt>
						<dd className="break-all font-mono text-ink">{fingerprint}</dd>
					</div>
				)}
				{reasons.length > 0 && (
					<div className="flex justify-between gap-3">
						<dt className="text-ink-3">Finish reason</dt>
						<dd className="text-ink">{reasons.join(", ")}</dd>
					</div>
				)}
			</dl>
			{measured ? (
				<div className="mt-2 border-t border-line pt-2 text-xs text-ink-2">
					<p>
						Average token probability ≈ {pct(mean)} (from mean logprob;
						uncalibrated)
					</p>
					<p>Least-confident token probability ≈ {pct(min)}</p>
					<p>
						Over {count.toLocaleString()} tokens
						{caps && count === caps.logprob_tokens
							? ` · first ${count.toLocaleString()} tokens only`
							: ""}
					</p>
				</div>
			) : (
				<p className="mt-2 text-xs text-ink-3">
					No logprobs recorded — the caller may not have requested them, or the
					provider returned none. Anthropic returns none.
				</p>
			)}
		</section>
	);
}

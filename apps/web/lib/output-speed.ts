/** Mirrors GWY-54 §2.6's ClickHouse expression; no value without a streamed TTFT. */
export function outputSpeed(
	attrs: Record<string, unknown>,
	durationUs: number,
	minGenerationMs: number,
): { value: number; estimated: boolean } | null {
	const stream =
		attrs.gen_ai_request_stream === true || attrs.gen_ai_request_stream === 1;
	const ttft = Number(attrs.gen_ai_response_time_to_first_chunk);
	const tokens = Number(attrs.gen_ai_usage_output_tokens);
	const overhead =
		attrs.tracelane_gateway_overhead_us === undefined
			? 0
			: Number(attrs.tracelane_gateway_overhead_us);
	if (
		!stream ||
		!Number.isFinite(ttft) ||
		ttft <= 0 ||
		!Number.isFinite(tokens) ||
		tokens <= 0 ||
		!Number.isFinite(overhead) ||
		!Number.isFinite(durationUs) ||
		!Number.isFinite(minGenerationMs)
	)
		return null;
	const generationSeconds = (durationUs - overhead) / 1_000_000 - ttft;
	if (generationSeconds <= 0 || generationSeconds * 1000 < minGenerationMs)
		return null;
	return {
		value: tokens / generationSeconds,
		estimated: attrs.tracelane_usage_estimated === true,
	};
}

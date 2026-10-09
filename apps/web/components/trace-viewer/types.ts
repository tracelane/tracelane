import type { GenerationDetails } from "@/lib/generation-issues";
export type UsageBuckets = {
	uncached_input: number;
	cache_read: number;
	cache_write: number;
	reasoning: number;
	output: number;
};
export type SpanUsage = {
	convention: "inclusive" | "exclusive" | "unknown";
	buckets: UsageBuckets | null;
	bucket_cost_usd: UsageBuckets | null;
	billed_tokens: number | null;
	cost_usd: number | null;
	cost_origin: "computed" | "provider_reported" | "unpriced" | "unknown";
	estimated: boolean;
	input_tokens: number | null;
	output_tokens: number | null;
	cache_read_tokens: number | null;
	cache_write_tokens: number | null;
	reasoning_tokens: number | null;
};
/**
 * Shared span shape returned by the gateway `/v1/traces/{id}/spans` read.
 * (Moved out of the retired SpanTree component; rendered by the transcript spine.)
 */
export type Span = GenerationDetails & {
	usage?: SpanUsage;
	caps?: { tool_names: number; logprob_tokens: number };
	span_id: string;
	parent_span_id: string | null;
	name: string;
	start_time: string;
	end_time: string;
	/** Microseconds since epoch (gateway `SpanRow.start_time_us`) — precise
	 * waterfall geometry without lossy `Date.parse`. May be absent on legacy rows. */
	start_time_us?: number;
	duration_us: number;
	/** OTel status: 2 = ERROR. */
	status_code: number;
	status_message: string;
	/** JSON-encoded attribute map (gen_ai.* / llm.* / tracelane.* / tool_* …). */
	attributes: string;
	/** matched failure-signature (AFT) ids → the seen-before signal. */
	aft_ids: string[];
	/** guardrail intervention: 0 none · 1 warned · 2 blocked. */
	intervention: number;
};

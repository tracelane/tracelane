/**
 * Shared span shape returned by the gateway `/v1/traces/{id}/spans` read.
 * (Moved out of the retired SpanTree component; rendered by the transcript spine.)
 */
export type Span = {
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

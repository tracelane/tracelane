export const traceRefusals: Record<string, string> = {
	invalid_trace_id: "This trace ID is invalid.",
	not_found: "This trace or span was not found in this workspace.",
	span_has_no_content: "No prompt text was recorded for this span.",
	ambiguous_span:
		"This trace has several LLM calls. Open the trace and choose one.",
	span_content_unreadable: "The recorded content could not be read.",
	item_too_large: "The recorded content exceeds the dataset item size limit.",
};
export function bulkRefusal(error: unknown, max: unknown): string | null {
	if (error === "bulk_too_large")
		return typeof max === "number"
			? `Too many traces selected — the limit is ${max}. Reduce the selection and retry.`
			: "Too many traces selected. Reduce the selection and retry.";
	if (error === "bulk_limit_unavailable")
		return "The selection limit is unavailable. Nothing was changed. Retry shortly.";
	return null;
}

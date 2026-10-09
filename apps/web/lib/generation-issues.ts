/** Display names only: the gateway supplies classifications and source-field detail. */
export const ISSUE_LABELS = {
	model_swapped: "Model swapped",
	alias: "Alias",
	fallback: "Served by fallback",
	truncated: "Hit token limit",
	filtered: "Filtered",
	empty: "Empty output",
	cancelled: "Stream cancelled",
	estimated: "Usage estimated",
	capture_trimmed: "Capture trimmed",
} as const;
export type IssueKind = keyof typeof ISSUE_LABELS;
export type IssueChip = {
	kind: IssueKind;
	severity: "warn" | "neutral" | "info";
	detail: string;
	affected_spans: number;
};
export type IssueRollup = {
	traces: { trace_id: string; issues: IssueChip[] }[];
	issues_available: boolean;
	inline_limit: number;
};
export function issueLabel(kind: string): string {
	return ISSUE_LABELS[kind as IssueKind] ?? kind;
}

/** Missing evidence is distinct from an empty issue set. Supplied by the gateway. */
export type SignalsRecorded = {
	attributes_readable: boolean;
	chat_operation: boolean;
	present: string[];
	missing: string[];
};
export type GenerationDetails = {
	issues?: IssueChip[];
	signals_recorded?: SignalsRecorded;
};

export type IssueSummary = {
	total_traces: number;
	llm_calls: number;
	no_served_model_calls: number;
	no_finish_reason_calls: number;
	gateway_signal_calls: number;
	counts: { kind: IssueKind; trace_count: number }[];
	window_days: number;
	since: string;
	until: string;
	as_of: string;
	content_capture: boolean;
};

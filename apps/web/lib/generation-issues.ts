/** Display names only: the gateway supplies classifications and source-field detail. */
export const ISSUE_LABELS = {
	model_swapped: "Model swapped",
	alias: "Alias",
	fallback: "Served by fallback",
	truncated: "Truncated",
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

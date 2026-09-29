import type { IdentityKind } from "./identity";

export type KyaWindow = "7d" | "30d";
export type CountedKey = { key: string; calls: number };
export type Activity = {
	key: string;
	raw_key: string;
	calls: number;
	traces: number;
	tokens_in: number | null;
	tokens_out: number | null;
	input_usage_missing: number;
	output_usage_missing: number;
	cost_usd: number | null;
	unpriced_calls: number;
	errors: number;
	error_rate: number | null;
	p50_us: number | null;
	p95_us: number | null;
	first_seen_us: number;
	last_seen_us: number;
	share_of_workspace: number | null;
	sources: CountedKey[];
	providers: string[];
	cross_list: CountedKey[] | null;
	cross_count: number;
	tools: CountedKey[] | null;
	tool_count: number;
	recent_traces: { trace_id: string; last_seen_us: number }[] | null;
};
export type ActivityResponse = {
	kind: IdentityKind;
	requested_days: number;
	window_days: number;
	retention_days: number;
	since_us: number;
	until_us: number;
	workspace_calls: number;
	has_retained_activity: boolean;
	total_identities: number;
	truncated: boolean;
	identities: Activity[];
	/** Fixture servers label seeded observations; production never sets this. */
	sample_data?: boolean;
};
export type ActivityLoad =
	| { status: "loading" }
	| { status: "error"; code: number }
	| { status: "ready"; data: ActivityResponse };

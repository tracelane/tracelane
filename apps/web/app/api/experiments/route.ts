/**
 * `/api/experiments` — EVL-02 experiments, proxied to the gateway.
 *
 * Thin server-side proxy, the same pattern as `/api/traces/compare`: the gateway
 * owns the ClickHouse read and resolves the tenant from the forwarded Bearer
 * token. The dashboard never touches ClickHouse and never binds a tenant id into
 * a query (`apps/web/CLAUDE.md`).
 *
 * **Every 4xx passes through with its own status**, because they are different
 * answers and the UI renders each differently:
 *
 * | Status | Means | The UI shows |
 * |---|---|---|
 * | `403 entitlement_required` | the plan does not include experiments | a LOCKED page, HTTP 200, naming the plan |
 * | `403 role_forbidden` | a `viewer`/`member` tried to start one | the button disabled with the role named |
 * | `402 workspace_budget_exceeded` | the workspace is at its monthly budget | the budget banner with both figures |
 * | `404` | unknown id, or another tenant's — deliberately identical | "not found in this workspace" |
 *
 * Collapsing those into one "something went wrong" is the exact defect this repo
 * already tracks: a role 403 that reads as a generic failure sends the user to
 * debug the wrong thing.
 */

import {
	GatewayError,
	forwardParams,
	gatewayGet,
	gatewayPost,
} from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

/** One row of the experiments list. */
export type ExperimentSummary = {
	experiment_id: string;
	name: string;
	dataset_id: string;
	snapshot_id: string;
	status: "running" | "complete" | "errored";
	/** The FROZEN snapshot's size — the denominator of `41 / 50`. */
	item_count: number;
	arms: number;
	notes: string;
	created_at_ms: number;
	created_by: string;
};

export type ExperimentListResponse = {
	experiments: ExperimentSummary[];
	next_cursor: string | null;
};

/** One arm's header strip. Every nullable field is UNKNOWN, never zero. */
export type ArmAggregate = {
	arm_id: string;
	arm_label: string;
	ordinal: number;
	eval_run_id: string | null;
	prompt_version_id: string;
	model: string;
	status: "pending" | "running" | "passed" | "failed" | "errored";
	/** `null` = no item was scored. Rendered `—`, never `0%`. */
	pass_rate: number | null;
	passed: number;
	failed: number;
	errored: number;
	/** `null` = no scored items. `0` = measured. The two must not render alike. */
	mean_score: number | null;
	/** `null` when nothing completed — never `0ms`. */
	p95_latency_ms: number | null;
	total_cost_usd: number;
	unpriced_items: number;
	items_run: number;
	items_matched: number;
};

export type ExperimentDetail = {
	experiment_id: string;
	name: string;
	dataset_id: string;
	snapshot_id: string;
	status: "running" | "complete" | "errored";
	item_count: number;
	notes: string;
	created_at_ms: number;
	created_by: string;
	arms: ArmAggregate[];
	/** Both arms terminal — the gateway decides this, not the page. */
	comparable: boolean;
};

/** One side of a compared row, or `null` when that arm never reached the item. */
export type ComparedSide = {
	case_name: string;
	status: string;
	/** `null` = UNKNOWN → `—`. `0` = measured → `0.00`. Never collapsed. */
	score: number | null;
	latency_ms: number;
	cost_usd: number | null;
	output: string;
	/** `true` = the output is NOT complete; the cell says so explicitly. */
	output_truncated: boolean;
	error: string | null;
};

/** The six verdicts PARTITION the rows exactly — the counts add up to the rows. */
export type Verdict =
	| "regressed"
	| "unknown"
	| "improved"
	| "unchanged"
	| "only_in_a"
	| "only_in_b";

export type ComparedItem = {
	/** `null` for a row aligned on ordinal. Never the all-zero UUID as an id. */
	dataset_item_id: string | null;
	item_ordinal: number;
	label: string;
	a: ComparedSide | null;
	b: ComparedSide | null;
	/** `null` when EITHER side's score is unknown — an errored item has no delta. */
	delta_score: number | null;
	delta_latency_ms: number | null;
	/** `null` when the A-side latency was 0 — never ∞, never a fake 0%. */
	delta_latency_pct: number | null;
	delta_cost_usd: number | null;
	delta_cost_pct: number | null;
	latency_slower: boolean;
	latency_faster: boolean;
	cost_higher: boolean;
	cost_lower: boolean;
	verdict: Verdict;
};

/** Echoed in the payload so this app never hardcodes a rule it must keep in step. */
export type CompareThresholds = {
	score_delta_min: number;
	latency_delta_min_ms: number;
	latency_delta_min_pct: number;
	cost_delta_min_usd: number;
	cost_delta_min_pct: number;
};

export type ExperimentCompareResponse = {
	experiment_id: string;
	name: string;
	dataset_id: string;
	snapshot_id: string;
	item_count: number;
	a: ArmAggregate;
	b: ArmAggregate;
	rows: ComparedItem[];
	regressed_count: number;
	improved_count: number;
	unchanged_count: number;
	unknown_count: number;
	only_in_a: number;
	only_in_b: number;
	thresholds: CompareThresholds;
	summary: string;
	/** Present only when an arm produced fewer items than the snapshot holds. */
	partial_note?: string;
};

export async function GET(req: NextRequest): Promise<NextResponse> {
	const qs = forwardParams(req.nextUrl.searchParams, ["limit", "cursor"]);
	try {
		const data = await gatewayGet<ExperimentListResponse>(
			`/v1/experiments${qs.toString() ? `?${qs.toString()}` : ""}`,
		);
		return NextResponse.json(data);
	} catch (err) {
		return passThrough(err, "list_failed");
	}
}

export async function POST(req: NextRequest): Promise<NextResponse> {
	let body: unknown;
	try {
		body = await req.json();
	} catch {
		return NextResponse.json({ error: "invalid_json" }, { status: 400 });
	}
	try {
		// The gateway answers 202 — arms run for minutes — and the body carries
		// the experiment id the caller navigates to.
		const data = await gatewayPost<unknown>("/v1/experiments", body);
		return NextResponse.json(data, { status: 202 });
	} catch (err) {
		return passThrough(err, "create_failed");
	}
}

/**
 * Forward the gateway's own status and, where it sent a structured refusal, its
 * own body.
 *
 * The gateway's refusals carry `error`, `message` and the fields the UI renders
 * (`required_role`, `budget_usd`, `max_items`…). Re-wrapping them would strip
 * exactly the parts that let the page say something useful, so a 4xx keeps its
 * status and a 5xx becomes a single honest "the gateway could not be reached".
 */
function passThrough(err: unknown, fallback: string): NextResponse {
	if (err instanceof GatewayError) {
		if (err.status >= 500) {
			// A 5xx is OURS, and its body may name internals. One honest sentence.
			return NextResponse.json(
				{ error: "unavailable", reason: "gateway_unreachable" },
				{ status: 502 },
			);
		}
		// The gateway's 4xx bodies are already customer-safe and typed — they are
		// what the UI renders. `body` is null only when the upstream sent nothing
		// parseable, and then the status is the whole answer.
		return NextResponse.json(
			err.body ?? { error: fallback, status: err.status },
			{
				status: err.status,
			},
		);
	}
	throw err;
}

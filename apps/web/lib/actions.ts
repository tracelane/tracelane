/** Shapes of `GET /v1/actions` and `GET /v1/actions/{id}`, plus the pure formatters the pages share. */

export type ActionState =
	| "blocked"
	| "awaiting_approval"
	| "approved"
	| "executed"
	| "failed"
	| "needs_review"
	| "refused_paused"
	| "expired"
	| "invalidated"
	| "denied";

export type EvidenceMode = "clear" | "tokenize" | "digest_only";

/** The stored, signed `EvidenceField` (serde-tagged); currency is a separate field. */
export type EvidenceField =
	| {
			mode: "clear";
			value:
				| { MinorUnits: number }
				| { Currency: string }
				| { Boolean: boolean };
	  }
	| { mode: "tokenize"; hmac?: string; last4?: string }
	| { mode: "digest_only"; sha256?: string };

export type EvidenceMap = Record<string, EvidenceField>;

export interface ActionSummary {
	action_id: string;
	occurred_at: string;
	tool_name: string | null;
	tool_ref?: string | null;
	state: ActionState;
	evidence?: EvidenceMap;
	/** A state-changing event of this action could not be read; state is forced to needs_review. */
	malformed?: boolean;
}

export interface ActionList {
	actions: ActionSummary[];
	next_before?: number | null;
	/** Action heads on this page that could not be read and were left out. */
	skipped_malformed?: number;
}

export interface ActionEventRow {
	seq: number;
	event_type: string;
	occurred_at: string;
	actor_kind?: "agent_key" | "human" | "system";
	body?: Record<string, unknown>;
}

export interface ApprovalDescriptor {
	approval_id: string;
	status: string;
	expires_at?: string;
	tool_name: string;
	server_id?: string;
	policy_id: string;
	policy_version: number | string;
	policy_hash: string;
	proposer_key_id?: string;
	evidence_fields: EvidenceMap;
}

export interface ActionDetail {
	action_id: string;
	events: ActionEventRow[];
	events_truncated?: boolean;
	approval?: ApprovalDescriptor | null;
	descriptor_digest?: string | null;
	/** Retention cleared the bound request; the events remain. */
	approval_expired?: boolean;
}

export type Tone = "ok" | "warn" | "danger" | "info" | "neutral";

const STATES: Record<ActionState, { label: string; tone: Tone }> = {
	blocked: { label: "Blocked", tone: "danger" },
	awaiting_approval: { label: "Awaiting approval", tone: "warn" },
	approved: { label: "Approved", tone: "info" },
	executed: { label: "Executed", tone: "ok" },
	failed: { label: "Failed", tone: "danger" },
	needs_review: { label: "Needs review", tone: "warn" },
	refused_paused: { label: "Refused — workspace paused", tone: "danger" },
	expired: { label: "Expired", tone: "neutral" },
	invalidated: { label: "Invalidated by policy change", tone: "neutral" },
	denied: { label: "Denied", tone: "danger" },
};

export function stateInfo(state: string): { label: string; tone: Tone } {
	return (
		(STATES as Record<string, { label: string; tone: Tone }>)[state] ?? {
			label: state || "Unknown",
			tone: "neutral",
		}
	);
}

const EVENTS: Record<string, string> = {
	action_proposed: "Proposed by an agent",
	decision_made: "Policy decision",
	approval_requested: "Approval requested",
	approval_granted: "Approved by a workspace approver",
	approval_denied: "Denied by a workspace approver",
	approval_attempt_rejected: "Approval attempt rejected",
	approval_consumed: "Approval used",
	approval_expired: "Approval expired",
	approval_invalidated: "Approval invalidated by policy change",
	legacy_forward_attempted: "Forwarded without protection",
	execution_started: "Execution started",
	execution_succeeded: "Execution succeeded",
	execution_failed: "Execution failed",
	execution_unknown: "Execution outcome unknown",
	denied_runtime: "Refused at runtime",
	policy_activated: "Policy activated",
};

/** Closed table with a safe fallback for an event type a newer gateway may add. */
export function eventLabel(type: string): string {
	return EVENTS[type] ?? `Event: ${type}`;
}

/** Integer minor units + ISO currency → "$15,000.00"; anything unusable → null. */
export function formatMinor(value: unknown, currency?: string): string | null {
	if (typeof value !== "number" || !Number.isSafeInteger(value) || !currency)
		return null;
	try {
		const f = new Intl.NumberFormat("en-US", { style: "currency", currency });
		const digits = f.resolvedOptions().maximumFractionDigits ?? 2;
		// Divide integers, not floating point: even safe minor units can lose a cent.
		const minor = BigInt(value);
		const scale = 10n ** BigInt(digits);
		const whole = minor / scale;
		const fraction = (minor < 0n ? -minor : minor) % scale;
		return f
			.formatToParts(whole === 0n && value < 0 ? -0 : whole)
			.map((part) =>
				part.type === "fraction"
					? fraction.toString().padStart(digits, "0")
					: part.value,
			)
			.join("");
	} catch {
		return null;
	}
}

export const EVIDENCE_MODE_LABEL: Record<EvidenceMode, string> = {
	clear: "shown",
	tokenize: "tokenized — last 4",
	digest_only: "hidden — digest only",
};

/** The one clear Currency field of a map, or null when there are none or several. */
function soleCurrency(map: EvidenceMap): string | null {
	const found = Object.values(map).flatMap((f) =>
		f.mode === "clear" && "Currency" in f.value ? [f.value.Currency] : [],
	);
	return found.length === 1 ? (found[0] ?? null) : null;
}

/** The one value a field may show; hash material (hmac, sha256) is never rendered. */
export function evidenceValue(f: EvidenceField, map: EvidenceMap = {}): string {
	if (f.mode === "tokenize") return f.last4 ? `•••• ${f.last4}` : "••••";
	if (f.mode === "digest_only") return "—";
	const v = f.value;
	if ("MinorUnits" in v) {
		const cur = soleCurrency(map);
		return (
			(cur && formatMinor(v.MinorUnits, cur)) || `${v.MinorUnits} (minor units)`
		);
	}
	if ("Currency" in v) return String(v.Currency);
	if ("Boolean" in v) return v.Boolean ? "yes" : "no";
	return "—";
}

/** "$15,000.00 → •••• T001": first amount, then first tokenized field. */
export function evidenceSummary(e: EvidenceMap | undefined): string {
	const map = e ?? {};
	const fields = Object.values(map);
	const amount = fields.find(
		(f) => f.mode === "clear" && "MinorUnits" in f.value,
	);
	const token = fields.find((f) => f.mode === "tokenize");
	return [
		amount && evidenceValue(amount, map),
		token && evidenceValue(token, map),
	]
		.filter(Boolean)
		.join(" → ");
}

const APPROVAL_STATUS: Record<string, string> = {
	pending: "Pending",
	approved: "Approved",
	denied: "Denied",
	expired: "Expired",
	consumed: "Used",
	invalidated: "Invalidated",
};
export function approvalStatusLabel(s: string): string {
	return APPROVAL_STATUS[s] ?? s;
}

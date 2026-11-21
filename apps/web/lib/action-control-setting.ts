/**
 * Owner switch for action control (preview) — the pure decision and the visible copy.
 * The route performs what this returns and nothing else; the invariants are swept in
 * `action-control-setting.test.ts`. No I/O here.
 */

/** `admin` = the verified owner or admin role; `unverified` = WorkOS could not confirm it. */
export type ChangeRole = "admin" | "other" | "unverified";

export type ChangeInput = {
	role: ChangeRole;
	current: boolean;
	requested: boolean;
	confirmed: boolean;
};

export type RefuseReason =
	| "not_owner"
	| "role_unverified"
	| "confirmation_required";

export type ChangeDecision =
	| { action: "refuse"; reason: RefuseReason; warning: string | null }
	| { action: "noop"; warning: null }
	| { action: "write"; next: boolean; warning: string | null };

/** SRE review 2026-10-29: OFF silently downgrades protected tools, so the UI warns first. */
export const ACTION_CONTROL_OFF_WARNING =
	"Protected tools fall back to the standard per-tool rules, and approvals waiting on protected tools stop applying. The fall-back is not logged call by call; this switch is recorded in the change log.";

/** Gateway entitlement cache: 15 minute TTL, change listener off by default. */
export const PROPAGATION_NOTE =
	"Usually takes effect within 15 minutes. The first agent call after a quiet period may still use the old setting.";

export const ACTION_CONTROL_ON_CONFIRMATION =
	"Calls to protected tools will be checked against your workspace policy, which can allow, deny or hold them for approval. This change is recorded in the change log.";

export const ACTION_CONTROL_SUMMARY =
	"Calls to protected tools are checked against your workspace policy, which can allow them, deny them or hold them for approval of the exact call. Each decision is recorded in the signed action ledger.";

export function decideActionControlChange(i: ChangeInput): ChangeDecision {
	// Authority first: a caller who cannot change the setting learns nothing else.
	if (i.role === "unverified")
		return { action: "refuse", reason: "role_unverified", warning: null };
	if (i.role !== "admin")
		return { action: "refuse", reason: "not_owner", warning: null };
	if (i.current === i.requested) return { action: "noop", warning: null };
	const warning = i.requested ? null : ACTION_CONTROL_OFF_WARNING;
	if (!i.confirmed)
		return { action: "refuse", reason: "confirmation_required", warning };
	return { action: "write", next: i.requested, warning };
}

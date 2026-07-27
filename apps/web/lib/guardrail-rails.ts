/**
 * The guardrail rail roster — plain-language, HONEST metadata for each of the 9
 * inline rails, keyed by the exact ledger id the gateway emits.
 *
 * Every `action` and `blurb` here is traced to the rail's real behaviour in
 * `crates/gateway/src/guardrail/rails/*.rs` — NOT inferred from the id (the ids
 * over-claim: R2/R6 redact, R5 only warns, R8 is a heuristic). Honesty lock: if a
 * rail's code changes what it does, this copy changes with it.
 *
 * `gated` reflects `GuardrailFeature` (rail.rs): free rails run for everyone;
 * gated rails require a workspace entitlement. We do NOT promise a specific tier —
 * no plan seed grants these yet (they're enabled per-workspace), so the honest
 * label is "Advanced", not "available on Team".
 */

export type RailAction = "block" | "redact" | "warn";
export type RailSide = "request" | "response" | "both";

export interface RailMeta {
	/** Exact ledger id emitted by the gateway (the join key to live stats). */
	id: string;
	/** Plain name — lead with this; keep the code as a secondary mono label. */
	name: string;
	/** The PRIMARY action, for the tone/badge. Rails that do more say so in blurb. */
	action: RailAction;
	side: RailSide;
	/** Free (runs for everyone) vs gated (advanced, per-workspace entitlement). */
	gated: boolean;
	/** One honest sentence — exactly what it does, incl. the real limits. */
	blurb: string;
}

/** Ordered R1→R8. `RailRoster` merges this with the tenant's live per-rail stats. */
export const RAIL_ROSTER: RailMeta[] = [
	{
		id: "R1_cost",
		name: "Cost & loop caps",
		action: "block",
		side: "both",
		gated: false,
		blurb:
			"Blocks requests or responses that exceed per-workspace token, call-loop, or spend caps, and warns near budget. Cost is a pre-flight estimate, not billing.",
	},
	{
		id: "R2_secrets_pii",
		name: "Secrets & PII redaction",
		action: "redact",
		side: "both",
		gated: true,
		blurb:
			"Detects and redacts secrets and structured PII (API keys, cards, SSNs, emails) in the request — and, once the streaming seam lands, the response. It redacts; it does not block.",
	},
	{
		id: "R3_schema",
		name: "Tool-schema validation",
		action: "block",
		side: "request",
		gated: false,
		blurb:
			"Blocks tool calls whose arguments break the declared input schema, and tool descriptions carrying poisoning patterns.",
	},
	{
		id: "R3_pinning",
		name: "Tool-definition pinning",
		action: "block",
		side: "request",
		gated: true,
		blurb:
			"Blocks a request when a tool's definition changed from the last-approved version — a silent MCP rug-pull.",
	},
	{
		id: "R4_trifecta",
		name: "Lethal-trifecta prevention",
		action: "block",
		side: "request",
		gated: true,
		blurb:
			"Blocks (or warns, in approve mode) requests where untrusted input, private-data access, and an exfil-capable tool converge — the lethal trifecta. Request-side only in V1.",
	},
	{
		id: "R5_format",
		name: "Response format check",
		action: "warn",
		side: "response",
		gated: true,
		blurb:
			"Flags (warns) when a response that declared a JSON or schema format fails to parse or validate. It records; it does not block or re-ask in V1.",
	},
	{
		id: "R6_sysprompt_leak",
		name: "System-prompt leak redaction",
		action: "redact",
		side: "response",
		gated: true,
		blurb:
			"Detects and redacts verbatim system-prompt text leaking back in the response. It redacts; it does not block.",
	},
	{
		id: "R7_topic_competitor",
		name: "Topic & competitor policy",
		action: "block",
		side: "both",
		gated: true,
		blurb:
			"Blocks configured denied-topic keywords and redacts competitor mentions — active only once a workspace has loaded its term lists.",
	},
	{
		id: "R8_injection",
		name: "Prompt-injection detection",
		action: "block",
		side: "request",
		gated: false,
		blurb:
			"Blocks known prompt-injection phrases (warns on weaker signals) in the request via a curated pattern list. Heuristic, not an ML classifier — novel or obfuscated attacks can still pass.",
	},
];

/**
 * The tier that unlocks each gated rail (ADR-064, amended 2026-07-14). Free rails
 * have no entry. Kept in lockstep with the `plan_entitlements` grants in
 * apps/web/db/seed.mjs — the label is a real purchase path only because the seed
 * grants that tier the rail. Amendment: all six gated rails now unlock at Team+
 * (R2/R4 moved down from Business) to make the full guardrail suite an
 * adoption-tier feature, not a Business-only one.
 */
export const RAIL_TIER: Record<string, "Team" | "Business"> = {
	R3_pinning: "Team",
	R5_format: "Team",
	R6_sysprompt_leak: "Team",
	R7_topic_competitor: "Team",
	R2_secrets_pii: "Team",
	R4_trifecta: "Team",
};

const BY_ID: Record<string, RailMeta> = Object.fromEntries(
	RAIL_ROSTER.map((r) => [r.id, r]),
);

/** Metadata for a live rail id, or a safe fallback for an unknown id. */
export function railMeta(id: string): RailMeta {
	return (
		BY_ID[id] ?? {
			id,
			name: id,
			action: "warn",
			side: "both",
			gated: false,
			blurb: "",
		}
	);
}

/** Human label + tone for the action badge (pairs colour with the word). */
export const ACTION_LABEL: Record<RailAction, string> = {
	block: "Blocks",
	redact: "Redacts",
	warn: "Warns",
};

/**
 * AFT-1 canonical id → human label map.
 *
 * Source: spec/aft-1/aft-1.md (CC0 1.0). Names extracted verbatim from the
 * "Name" field of each taxonomy entry. Do NOT invent labels — every entry here
 * maps 1:1 to an AFT-1 spec entry. Add new entries only when the spec gains a
 * new entry (update spec/aft-1/aft-1.md first).
 *
 * Also includes the legacy short-form ids (AF-0x) that predate the full AFT-1
 * domain/name/seq format; kept for backward compat with spans captured before
 * the canonical ids landed.
 */
export const AFT_LABELS: Record<string, string> = {
	// ── MCP Domain ────────────────────────────────────────────────────────────
	"AFT-MCP-RUGPULL-001": "MCP server rug-pull",
	"AFT-MCP-ARGDRIFT-001": "MCP argument drift",

	// ── Tool Domain ───────────────────────────────────────────────────────────
	"AFT-TOOL-SCHEMA-001": "Hallucinated tool-call schema violation",
	"AFT-TOOL-DRIFT-001": "Tool-definition drift (silent rug-pull)",

	// ── Taint Domain ──────────────────────────────────────────────────────────
	"AFT-TAINT-LETHAL-001": "Lethal-trifecta taint propagation",

	// ── Prompt-Injection Domain ───────────────────────────────────────────────
	"AFT-PI-CASCADE-001": "Prompt-injection cascade",

	// ── A2UI Domain (Agent-to-UI) ─────────────────────────────────────────────
	"AFT-A2UI-CATALOG-001": "A2UI non-catalog component type",
	"AFT-A2UI-STUCKLOOP-001": "A2UI stuck-loop",
	"AFT-A2UI-CAPTCHA-001": "CAPTCHA blocking agent progress",

	// ── A2A Domain (Agent-to-Agent) ───────────────────────────────────────────
	"AFT-A2A-LIFECYCLE-001": "A2A handoff lifecycle violation",

	// ── Context Domain ────────────────────────────────────────────────────────
	"AFT-CONTEXT-OVERFLOW-001": "Context-window overflow",

	// ── Trajectory Domain ─────────────────────────────────────────────────────
	"AFT-TRAJ-RETRYLOOP-001": "Retry storm (tool-call loop)",
	"AFT-TRAJ-ANOMALY-001": "Trajectory-level anomaly",

	// ── Legacy short-form ids (pre-AFT-1 draft; backward compat only) ─────────
	"AF-01": "Prompt injection",
	"AF-02": "Data exfiltration",
	"AF-03": "Tool misuse",
	"AF-04": "Scope escalation",
	"AF-05": "Lethal trifecta",
	"AF-13": "Missing system prompt boundary",
};

/**
 * Return the human-readable label for an AFT id. Falls back to the raw id if
 * the id is not in the map (future spec entries, or non-standard ids).
 *
 * @param id - An AFT-1 id, e.g. "AFT-TOOL-SCHEMA-001" or legacy "AF-01".
 * @returns Human label, e.g. "Hallucinated tool-call schema violation".
 */
export function aftLabel(id: string): string {
	return AFT_LABELS[id] ?? id;
}

/**
 * Canonical AFT-1 id → taxonomy entry. ONE vocabulary end-to-end.
 *
 * The Failure Signatures page IS the AFT-1 taxonomy (spec/aft-1/aft-1.md, CC0)
 * running live: `spans.aft_ids` carries the CANONICAL AFT-1 id (e.g.
 * `AFT-TOOL-SCHEMA-001`) — that is what real detectors in
 * `crates/gateway/src/predictive/*` emit, and what the demo seeder
 * (`scripts/seed/demo_traces.py`) emits too. There is NO slug vocabulary and NO
 * mapping layer: the id stored on the span IS the key here.
 *
 * `detectorStatus` is the honesty axis:
 *   - `live`    — a reference detector emits this id today (it is being detected).
 *   - `roadmap` — a valid AFT-1 taxonomy entry whose reference detector ships in
 *                 V1.1 (the entry exists in the standard; we do not detect it yet).
 * A `live` entry MUST correspond to a real detector and a `roadmap` entry MUST
 * NOT — enforced by `scripts/ci/check-aft-vocabulary.py` (detector ids ⊆ these
 * keys; `live` ⟺ a predictive detector emits it; the seeder may only emit known
 * ids). When a new AFT-1 entry lands, add it here AND update aft-labels.ts.
 */

export interface AftTaxonomyEntry {
	/** Canonical `AFT-<DOMAIN>-<NAME>-<SEQ>` id (== the map key). */
	id: string;
	/** AFT-1 "Name". */
	name: string;
	/** What the pattern is (AFT-1 "Description", condensed to one line). */
	description: string;
	/** How it is detected — one honest sentence (AFT-1 "Detection" field). */
	detection: string;
	/** Whether a reference detector emits this id today. */
	detectorStatus: "live" | "roadmap";
}

const TAXONOMY: Record<string, AftTaxonomyEntry> = {
	"AFT-MCP-RUGPULL-001": {
		id: "AFT-MCP-RUGPULL-001",
		name: "MCP server rug-pull",
		description:
			"An MCP server's tool definitions change after the agent consented to use them — new parameter types, hidden side effects, or escalated permissions.",
		detection:
			"The content hash of the full tool manifest changes between calls within a session.",
		detectorStatus: "live",
	},
	"AFT-MCP-ARGDRIFT-001": {
		id: "AFT-MCP-ARGDRIFT-001",
		name: "MCP argument drift",
		description:
			"Arguments passed to an MCP tool deviate from the schema declared at consent time — a sign of prompt injection or a compromised server.",
		detection:
			"Argument type/shape validation against the consented schema on every call.",
		detectorStatus: "live",
	},
	"AFT-TOOL-SCHEMA-001": {
		id: "AFT-TOOL-SCHEMA-001",
		name: "Hallucinated tool-call schema violation",
		description:
			"A model emits a tool call that does not conform to the declared schema — an undeclared tool, a missing required field, or a wrong primitive type.",
		detection:
			"Stateless JSON-Schema-subset validation of every tool call against the request's declared tool input_schema.",
		detectorStatus: "live",
	},
	"AFT-TOOL-DRIFT-001": {
		id: "AFT-TOOL-DRIFT-001",
		name: "Tool-definition drift (silent rug-pull)",
		description:
			"A declared tool keeps its name but its definition mutates across requests — a sensitive field appears or a constraint loosens — shifting the contract the user consented to.",
		detection:
			"A per-(tenant, tool) fingerprint of the full definition, compared across requests; sensitive-named fields or loosened constraints flag as a rug-pull.",
		detectorStatus: "live",
	},
	"AFT-TAINT-LETHAL-001": {
		id: "AFT-TAINT-LETHAL-001",
		name: "Lethal-trifecta taint propagation",
		description:
			"An agent simultaneously has access to sensitive data, an external channel, and untrusted input — the high-risk exfiltration shape.",
		detection:
			"Taint labels for data access, channel access, and untrusted input, evaluated for co-occurrence within a trace.",
		detectorStatus: "live",
	},
	"AFT-PI-CASCADE-001": {
		id: "AFT-PI-CASCADE-001",
		name: "Prompt-injection cascade",
		description:
			"Untrusted content in one span propagates to a downstream LLM call without sanitisation; the downstream call may execute injected instructions.",
		detection:
			"An untrusted-content sentinel is present in an LLM input that originated from a prior span's output.",
		detectorStatus: "live",
	},
	"AFT-CONTEXT-OVERFLOW-001": {
		id: "AFT-CONTEXT-OVERFLOW-001",
		name: "Context-window overflow",
		description:
			"A model response is cut off because the context or output-token window filled — a truncated, incomplete result downstream steps may consume as complete.",
		detection:
			"The completion terminated on a length signal (finish_reason = length / stop_reason = max_tokens) rather than finishing naturally.",
		detectorStatus: "roadmap",
	},
	"AFT-A2UI-CATALOG-001": {
		id: "AFT-A2UI-CATALOG-001",
		name: "A2UI non-catalog component type",
		description:
			"An agent attempts to render a UI component whose type is not in the standard catalogue — a hallucinated component name or injected markup.",
		detection: "The component type is not in the standard-catalogue allowlist.",
		detectorStatus: "live",
	},
	"AFT-A2UI-STUCKLOOP-001": {
		id: "AFT-A2UI-STUCKLOOP-001",
		name: "A2UI stuck-loop",
		description:
			"The agent repeatedly generates UI actions with no effect — a zero DOM-mutation score across multiple steps.",
		detection: "A zero DOM-mutation score persisting past the first step.",
		detectorStatus: "live",
	},
	"AFT-A2UI-CAPTCHA-001": {
		id: "AFT-A2UI-CAPTCHA-001",
		name: "CAPTCHA blocking agent progress",
		description:
			"A browser agent has reached a page where a CAPTCHA blocks further automation; it cannot proceed without a human.",
		detection:
			"A CAPTCHA-detected signal, or URL/content matching CAPTCHA signatures.",
		detectorStatus: "live",
	},
	"AFT-A2A-LIFECYCLE-001": {
		id: "AFT-A2A-LIFECYCLE-001",
		name: "A2A handoff lifecycle violation",
		description:
			"An agent-to-agent handoff skips or repeats a lifecycle transition (init → running → complete/failed) — a broken orchestration layer.",
		detection:
			"Validation of the A2A span sequence against the lifecycle state machine.",
		detectorStatus: "live",
	},
	"AFT-TRAJ-RETRYLOOP-001": {
		id: "AFT-TRAJ-RETRYLOOP-001",
		name: "Retry storm (tool-call loop)",
		description:
			"An agent repeats the same tool call without making progress — a runaway retry loop spending tokens and latency.",
		detection:
			"Near-identical tool calls (same tool + equivalent arguments) recur within a single trace beyond a threshold — a rule-based loop detector.",
		detectorStatus: "roadmap",
	},
	"AFT-TRAJ-ANOMALY-001": {
		id: "AFT-TRAJ-ANOMALY-001",
		name: "Trajectory-level anomaly",
		description:
			"The sequence of spans in a trace is statistically anomalous versus a learned distribution of normal traces — a catch-all for novel failure modes.",
		detection:
			"A learned sequence model flags a reconstruction error above threshold.",
		detectorStatus: "live",
	},
};

/**
 * Resolve a canonical AFT-1 id to its taxonomy entry, or `null` if the id is not
 * in the taxonomy (never fabricate an entry). With the CI vocabulary guard in
 * place, every id a real detector emits resolves here, so `null` is only reached
 * by genuinely-unknown data — the caller renders the raw id honestly.
 */
export function aftFor(id: string): AftTaxonomyEntry | null {
	return TAXONOMY[id] ?? null;
}

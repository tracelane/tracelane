/**
 * Coverage of protected action control: which tools Tracelane has seen, and whether each is
 * Protected or Observed only. Pure; the sources are `GET /v1/mcp-tools` (tools seen through the
 * gateway, `mcp_routes.rs` "/v1/mcp-tools") and `GET /v1/action-policies` plus each active
 * contract's `protected` flag (`policy.rs` Contract.protected). Never claims protection it
 * could not read: an unreadable contract is "Could not check", not Protected.
 */

export const COVERAGE_NOTE =
	"Calls that do not go through Tracelane are not seen.";
export const MAX_ROWS = 100;

export interface SeenTool {
	server_id: string;
	server_name?: string | null;
	tool_name: string;
}
export interface PolicyRef {
	tool_ref: string;
	server_id: string;
	tool_name: string;
}
/** tool_ref -> the contract's `protected` flag; absent means it could not be read. */
export type ProtectedFlags = Record<string, boolean | undefined>;

export type CoverageState = "protected" | "observed" | "unchecked";
export interface CoverageRow {
	key: string;
	server: string;
	tool: string;
	state: CoverageState;
	seen: boolean;
}
export interface Coverage {
	rows: CoverageRow[];
	truncated: boolean;
	protectedCount: number;
	total: number;
	sentence: string;
}

const keyOf = (server: string, tool: string) => `${server}\u0000${tool}`;

export function buildCoverage(
	seen: readonly SeenTool[],
	policies: readonly PolicyRef[],
	flags: ProtectedFlags,
): Coverage {
	const rows = new Map<string, CoverageRow>();
	for (const t of seen) {
		const k = keyOf(t.server_id, t.tool_name);
		if (!rows.has(k))
			rows.set(k, {
				key: k,
				server: t.server_name || "Unnamed server",
				tool: t.tool_name,
				state: "observed",
				seen: true,
			});
	}
	for (const p of policies) {
		const k = keyOf(p.server_id, p.tool_name);
		const row = rows.get(k) ?? {
			key: k,
			server: "Unnamed server",
			tool: p.tool_name,
			state: "observed" as CoverageState,
			seen: false,
		};
		const flag = flags[p.tool_ref];
		row.state =
			flag === true ? "protected" : flag === false ? "observed" : "unchecked";
		rows.set(k, row);
	}
	const order: Record<CoverageState, number> = {
		protected: 0,
		unchecked: 1,
		observed: 2,
	};
	const all = [...rows.values()].sort(
		(a, b) =>
			order[a.state] - order[b.state] ||
			a.server.localeCompare(b.server) ||
			a.tool.localeCompare(b.tool),
	);
	const protectedCount = all.filter((r) => r.state === "protected").length;
	const unchecked = all.filter((r) => r.state === "unchecked").length;
	const total = all.length;
	let sentence: string;
	if (total === 0) sentence = "No tools have been seen through Tracelane yet.";
	else {
		sentence = `${protectedCount} of ${total} ${total === 1 ? "tool" : "tools"} seen through Tracelane ${protectedCount === 1 ? "is" : "are"} protected; the rest are observed only.`;
		if (unchecked > 0) sentence += ` ${unchecked} could not be checked.`;
	}
	return {
		rows: all.slice(0, MAX_ROWS),
		truncated: all.length > MAX_ROWS,
		protectedCount,
		total,
		sentence,
	};
}

/** `contract_jcs` is the stored contract text; anything but a boolean flag is "could not read". */
export function protectedFlagOf(contractJcs: unknown): boolean | undefined {
	if (typeof contractJcs !== "string") return undefined;
	try {
		const v = (JSON.parse(contractJcs) as { protected?: unknown }).protected;
		return typeof v === "boolean" ? v : undefined;
	} catch {
		return undefined;
	}
}

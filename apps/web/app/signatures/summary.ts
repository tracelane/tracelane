/**
 * Answer-first summary for Failure Signatures (founder 2026-11-19: same principles as the
 * audit page). One headline answers "did my agents hit a known failure pattern?", with
 * the scope in the same card. Pure; numbers only as given.
 *
 * Semantics (registry `signatures_matched` / `traces_affected`): `patterns` is the number
 * of DISTINCT live patterns with at least one hit; `occurrences` is the sum of their hits;
 * `tracesAffected` is the gateway's DISTINCT trace count — never a sum of per-pattern
 * trace counts (a trace hitting several patterns counts once). `null` means the gateway
 * did not report it, which is said, never shown as 0.
 */
const n = (x: number) => x.toLocaleString("en-US");
const count = (x: number, one: string, many: string) =>
	`${n(x)} ${x === 1 ? one : many}`;

export interface SignaturesSummary {
	tone: "ok" | "attention";
	headline: string;
	detail: string;
}

export function summarizeSignatures(
	patterns: number,
	occurrences: number,
	tracesAffected: number | null,
	rangeLabel: string,
): SignaturesSummary {
	const window = rangeLabel.toLowerCase();
	if (patterns <= 0)
		return {
			tone: "ok",
			headline: `No known failure patterns in the ${window}`,
			detail:
				"Every recorded call is checked against known agent failure patterns, such as a tool call that breaks its schema. Matches appear here with how often they happened and which traces they touched.",
		};
	const traces =
		tracesAffected === null
			? "Affected traces were not reported by this gateway"
			: `${count(tracesAffected, "distinct trace", "distinct traces")} affected`;
	return {
		tone: "attention",
		headline: `${count(patterns, "known failure pattern", "known failure patterns")} matched in the ${window}`,
		detail: `${count(occurrences, "occurrence", "occurrences")} in total. ${traces}. Open a pattern to see the evidence and the traces it touched.`,
	};
}

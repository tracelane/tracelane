/**
 * Answer-first summary of an audit check (AUD-40 Part C). Turns the verifier's
 * verdict and the coverage figures into what an auditor asks:
 *   1. Unaltered?  — derived ONLY from the hash-chain result for the rows checked.
 *   2. Vouched for? — signed by a trusted key and publicly anchored.
 *   3. Coverage   — how much of the stored ledger this check covered.
 * Pure and total over every input, so the page can never show a "yes" it cannot back.
 *
 * Rules (spec §5): RED only on a real failure (broken chain, stripped proof, failed
 * signature). GREEN only when all three answers are "yes". No "yes" without a report.
 * Coverage speaks about STORED rows; it never claims every call was recorded (ADR-077:
 * completeness of recording is not provable yet).
 */
import type { AuditVerdict } from "./verdict";

export type AnswerState = "yes" | "partly" | "no" | "unknown";
export interface Answer {
	state: AnswerState;
	text: string;
}
export interface AuditSummary {
	tone: "ok" | "neutral" | "danger";
	headline: string;
	unaltered: Answer;
	vouched: Answer;
	coverage: Answer;
	next: string;
}
export interface AuditFacts {
	verdict: AuditVerdict;
	/** `report.hash_chain_valid`; null when there is no report yet. */
	hashChainValid: boolean | null;
	/** Every batch verified under Tracelane's platform key (shared-key path). */
	platformVerified: boolean;
	/** Newest rows signed but not yet publicly anchored. */
	unanchoredTail: number;
	/** Rows inside the established hash-check range. */
	checkedRows: number;
	/** Stored rows for the workspace; undefined when the inventory read failed. */
	totalRows: number | undefined;
	readError?: "unauthorized" | "forbidden" | "failed";
}

const n = (x: number) => x.toLocaleString("en-US");
const plural = (x: number, one: string, many: string) =>
	`${n(x)} ${x === 1 ? one : many}`;

const UNKNOWN = (text: string): Answer => ({ state: "unknown", text });

const FULL_EXPORT =
	"Export the full ledger and run tlane verify to check every stored row.";

function unaltered(f: AuditFacts): Answer {
	if (f.verdict.state === "unrooted_window")
		return UNKNOWN(
			"The rows link up, but nothing trusted anchors this window, so no change can be ruled out.",
		);
	if (f.hashChainValid === true && f.checkedRows > 0)
		return {
			state: "yes",
			text: `No checked row was changed, inserted or removed (${plural(f.checkedRows, "row", "rows")}).`,
		};
	if (f.hashChainValid === false)
		return {
			state: "no",
			text: "A recorded hash, sequence or link does not match in the checked range.",
		};
	return UNKNOWN("Not established by this check.");
}

function vouched(f: AuditFacts): Answer {
	const v = f.verdict;
	switch (v.state) {
		case "verified":
		case "verified_windowed":
			if (f.unanchoredTail > 0)
				return {
					state: "partly",
					text: `Signed. The newest ${plural(f.unanchoredTail, "row is", "rows are")} still waiting for a public anchor.`,
				};
			return f.platformVerified
				? {
						state: "yes",
						text: "Signed with Tracelane’s platform key and publicly anchored.",
					}
				: {
						state: "yes",
						text: "Signed with your workspace key and publicly anchored.",
					};
		case "chain_only":
			return {
				state: "partly",
				text: "The hashes match, but no public anchor was verified in this check.",
			};
		case "anchor_hole":
			return {
				state: "partly",
				text: `${plural(v.rows, "row sits", "rows sit")} outside every signed batch.`,
			};
		case "stripped":
			return {
				state: "no",
				text: "A batch claims a public proof that is missing from the evidence.",
			};
		case "signature_failed":
			return {
				state: "no",
				text: "A batch signature or public proof did not verify.",
			};
		case "anchors_unverifiable":
			return UNKNOWN(
				"No trusted signing key was available, so signatures were not checked.",
			);
		case "unrooted_window":
			return UNKNOWN("No verified public anchor covers this window.");
		case "chain_broken":
			return UNKNOWN("Not assessed past the first failing row.");
		default:
			return UNKNOWN("Not established by this check.");
	}
}

function coverage(f: AuditFacts): Answer {
	if (f.totalRows === undefined)
		return UNKNOWN(
			`${plural(f.checkedRows, "row", "rows")} checked. The stored total is unavailable.`,
		);
	if (f.totalRows === 0) return UNKNOWN("No rows are stored yet.");
	if (f.checkedRows <= 0)
		return UNKNOWN(
			`None of the ${plural(f.totalRows, "stored row", "stored rows")} were established by this check.`,
		);
	if (f.checkedRows >= f.totalRows)
		return {
			state: "yes",
			text: `All ${plural(f.totalRows, "stored row was", "stored rows were")} checked.`,
		};
	return {
		state: "partly",
		text: `${n(f.checkedRows)} of ${plural(f.totalRows, "stored row", "stored rows")} checked here. The rest need the full export.`,
	};
}

const FAILURE_HEADLINE: Partial<Record<AuditVerdict["state"], string>> = {
	chain_broken: "Integrity check failed",
	stripped: "A public proof is missing",
	signature_failed: "A signature or proof did not verify",
};

export function summarizeAudit(f: AuditFacts): AuditSummary {
	if (f.readError) {
		const next =
			f.readError === "unauthorized"
				? "Sign in again, then reload this page."
				: f.readError === "forbidden"
					? "Ask a workspace admin for access to the audit ledger."
					: "Reload to retry. If it keeps failing, contact support.";
		const why = UNKNOWN(
			"The ledger could not be read, so nothing was checked.",
		);
		return {
			tone: "neutral",
			headline: "We couldn’t check your evidence",
			unaltered: why,
			vouched: why,
			coverage: why,
			next,
		};
	}
	if (f.verdict.state === "ready") {
		const pending = UNKNOWN("Checking…");
		return {
			tone: "neutral",
			headline: "Checking your evidence",
			unaltered: pending,
			vouched: pending,
			coverage: pending,
			next: "The result appears here when the check finishes.",
		};
	}
	if (f.verdict.state === "empty") {
		const none = UNKNOWN("Nothing to check yet.");
		return {
			tone: "neutral",
			headline: "No evidence yet",
			unaltered: none,
			vouched: none,
			coverage:
				f.totalRows && f.totalRows > 0
					? UNKNOWN(
							`${plural(f.totalRows, "stored row is", "stored rows are")} outside this window.`,
						)
					: none,
			next: "Route a call through the gateway to start recording.",
		};
	}
	const a = unaltered(f);
	const v = vouched(f);
	const c = coverage(f);
	const failure = FAILURE_HEADLINE[f.verdict.state];
	if (failure)
		return {
			tone: "danger",
			headline: failure,
			unaltered: a,
			vouched: v,
			coverage: c,
			next: "Save the check report and send it to support. Treat a repeated failure as a potential integrity incident.",
		};
	const allYes = a.state === "yes" && v.state === "yes" && c.state === "yes";
	if (allYes)
		return {
			tone: "ok",
			headline: "Verified: unchanged, signed and anchored",
			unaltered: a,
			vouched: v,
			coverage: c,
			next: "Save the check report for your records.",
		};
	const headline =
		a.state === "yes" && v.state === "yes"
			? "The checked rows passed"
			: a.state === "yes" && v.state === "partly"
				? "Unchanged. Public proof is partly pending"
				: f.verdict.state === "anchors_unverifiable"
					? "Signatures could not be checked"
					: "Integrity not established by this check";
	const next =
		f.verdict.state === "anchors_unverifiable"
			? "Ask a workspace admin to confirm the trusted audit key, then reload."
			: f.unanchoredTail > 0 && v.state === "partly"
				? "Reload in a few minutes to check the pending public anchor."
				: c.state === "partly" || c.state === "unknown"
					? FULL_EXPORT
					: "Reload later to check for public proofs, or contact support if this persists.";
	return {
		tone: "neutral",
		headline,
		unaltered: a,
		vouched: v,
		coverage: c,
		next,
	};
}

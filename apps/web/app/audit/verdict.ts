/**
 * Audit "Verify integrity" verdict — a single pure derivation from the
 * in-browser {@link VerifyReport}, so the headline banner, the red-card styling,
 * and the two-claim breakdown all read the SAME state. Extracted (and unit-
 * tested) because a prior inline version let the big green "Verified" banner
 * show while CLAIM 2 said "Verification FAILED" — the banner was computed
 * WITHOUT `signatures_valid`, so it could be greener than the claims. Here the
 * green states are the ONLY non-alarm states and both require `signatures_valid`.
 *
 * Honesty model (ADR-062): the hash chain is the tamper-evidence; public
 * anchoring is per-batch + best-effort, so "chain intact, no anchor in this
 * view" is a GREEN (qualified) outcome, not a failure. A real anchor/signature
 * problem (merkle mismatch, untrusted key, strip) is RED.
 */

import type { VerifyReport } from "@tracelanedev/audit-verifier";

export type AuditVerdict =
	/** No report yet — the pre-verify "ready" state. */
	| { state: "ready" }
	/** GREEN: chain intact, signed, AND ≥1 public anchor fully verified here. */
	| { state: "verified"; rows: number; anchors: number }
	/** GREEN (ADR-070): WINDOWED verify — genesis was retention-truncated out, so
	 *  the chain is rooted at a public Rekor anchor and verified from `fromSeq` to
	 *  tip. Honest scope: rows before `fromSeq` are present-but-unverified. */
	| {
			state: "verified_windowed";
			rows: number;
			anchors: number;
			fromSeq: number;
	  }
	/** GREEN (qualified): chain intact + signed, but no public anchor fell inside
	 *  the loaded window — tamper-evident, just not publicly anchored in this view.
	 *  Only reachable on a genesis-rooted verify (seq 0 present). */
	| { state: "chain_only"; rows: number }
	/** NEUTRAL: the loaded view has zero rows — nothing to verify (a brand-new
	 *  tenant, or a window with no events). Never GREEN "verified": verifying
	 *  nothing is not a pass. Not an alarm either — an empty ledger is not tampering.
	 *  A TRUNCATED response (0 rows loaded out of a NON-empty ledger) is caught
	 *  server-side and returned RED; the browser cannot see the true total from the
	 *  chain bytes alone, so from here 0 rows always reads as "empty". */
	| { state: "empty" }
	/** RED: a row hash / prev-hash link no longer matches — the chain is broken. */
	| { state: "chain_broken"; rows: number; firstSeq: number | null }
	/** RED (ADR-070): a WINDOWED view with no public Rekor anchor to root it —
	 *  the loaded rows may chain among themselves but nothing publicly trusted
	 *  holds them, so integrity cannot be established. Never green. */
	| { state: "unrooted_window" }
	/** RED: an anchor committed to "anchored" but its public proof is absent. */
	| { state: "stripped" }
	/** RED: a real anchor/signature failure (fingerprint mismatch, untrusted key). */
	| { state: "signature_failed"; reasons: string[] };

/**
 * Derive the single verdict from a report. Order matters: a broken chain or a
 * strip is RED regardless of anchors; only once the chain is intact and NOT
 * stripped do we distinguish "real signature failure" (RED) from "anchored /
 * chain-only" (GREEN).
 */
export function deriveAuditVerdict(report: VerifyReport | null): AuditVerdict {
	if (!report) return { state: "ready" };

	if (!report.hash_chain_valid) {
		const firstBroken = report.errors.find((e) => e.seq != null);
		return {
			state: "chain_broken",
			rows: report.rows_seen,
			firstSeq: firstBroken?.seq ?? null,
		};
	}
	if (report.strip_detected) return { state: "stripped" };

	// Chain is intact from here. A false `signatures_valid` now means a GENUINE
	// anchor/signature failure (the server-side coverage filter removed the
	// `anchor_rows_missing` false-alarm before the verifier ever saw it).
	if (!report.signatures_valid) {
		const reasons = [...new Set(report.errors.map((e) => e.kind))];
		return { state: "signature_failed", reasons };
	}
	// An empty view has nothing to verify — never GREEN (verifying zero rows is not
	// a pass). A truncated response (0 loaded out of a non-empty ledger) is caught
	// and reddened server-side; from the chain bytes alone this reads as "empty".
	if (report.rows_seen === 0) return { state: "empty" };

	// ADR-070: a windowed view (genesis retention-truncated) with no public Rekor
	// anchor to root it is RED — nothing publicly trusted holds the loaded rows.
	if (!report.trust_established) return { state: "unrooted_window" };

	// Chain intact AND rooted from here.
	if (report.verified_from_seq > 0) {
		// WINDOWED verify — rooted at a public Rekor anchor (trust_established
		// guarantees anchors_included > 0). Green, with the honest anchor→tip scope.
		return {
			state: "verified_windowed",
			rows: report.rows_seen,
			anchors: report.anchors_included,
			fromSeq: report.verified_from_seq,
		};
	}
	if (report.anchors_included > 0) {
		return {
			state: "verified",
			rows: report.rows_seen,
			anchors: report.anchors_included,
		};
	}
	return { state: "chain_only", rows: report.rows_seen };
}

/** True for the RED states — the caller paints the alarm card + banner. */
export function isAlarm(v: AuditVerdict): boolean {
	return (
		v.state === "chain_broken" ||
		v.state === "unrooted_window" ||
		v.state === "stripped" ||
		v.state === "signature_failed"
	);
}

/** Machine failure `kind` → plain English an operator can read to an auditor.
 * Unknown kinds degrade to the de-underscored raw kind (never a blank). */
const KIND_HUMAN: Record<string, string> = {
	anchor_rows_missing:
		"an anchored batch referenced rows outside the loaded view (coverage, not tampering)",
	anchor_stripped:
		"a batch claims to be publicly anchored but its proof is missing",
	merkle_root_mismatch: "an anchor's fingerprint no longer matches its rows",
	bad_merkle_root: "an anchor's fingerprint is malformed",
	untrusted_tenant_key:
		"a batch was signed by a key that is not your trusted audit key",
	bad_tenant_pubkey: "a batch's signing key is malformed",
	row_hash_mismatch: "a row's contents no longer match its recorded hash",
	chain_break: "a row's link to the previous row is broken",
	prev_hash_mismatch: "a row's link to the previous row is broken",
	unrooted_window:
		"this view starts after your chain's genesis (older rows are past your retention window) and has no public Rekor anchor inside it to establish trust — configure your tenant audit public key so an anchor in this view can root the chain",
};

export function humanizeVerdictKind(kind: string): string {
	return KIND_HUMAN[kind] ?? kind.replace(/_/g, " ");
}

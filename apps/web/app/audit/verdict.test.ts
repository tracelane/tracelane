/**
 * Tests for the audit verdict derivation. The headline case is the regression
 * guard: a report with anchors present but `signatures_valid=false` must NEVER
 * be "verified" (the old inline banner ignored `signatures_valid` and showed
 * green over a red CLAIM 2 — the exact founder-caught bug). Negative cases first
 * per `.claude/rules/testing.md`.
 */

import type { VerifyReport } from "@tracelanedev/audit-verifier";
import { describe, expect, it } from "vitest";
import {
	type AuditVerdict,
	deriveAuditVerdict,
	humanizeVerdictKind,
	isAlarm,
} from "./verdict";

function report(over: Partial<VerifyReport>): VerifyReport {
	return {
		ledger_path: "self-verify",
		rows_seen: 1000,
		hash_chain_valid: true,
		signatures_valid: true,
		rekor_anchors_seen: 0,
		rekor_anchors_resolved: 0,
		anchors_included: 0,
		anchors_unverified: 0,
		strip_detected: false,
		verified_from_seq: 0,
		trust_established: true,
		errors: [],
		...over,
	};
}

describe("deriveAuditVerdict", () => {
	it("REGRESSION: anchors present but signatures invalid is NEVER green", () => {
		// The exact founder-caught bug: anchors_included>0 + hash chain valid made
		// the old banner green even though the signature/anchor check FAILED.
		const v = deriveAuditVerdict(
			report({
				anchors_included: 3,
				signatures_valid: false,
				errors: [{ seq: null, kind: "merkle_root_mismatch", detail: "x" }],
			}),
		);
		expect(v.state).toBe("signature_failed");
		expect(isAlarm(v)).toBe(true);
	});

	it("REJECT: null report → ready", () => {
		expect(deriveAuditVerdict(null)).toEqual<AuditVerdict>({ state: "ready" });
	});

	it("RED: broken chain → chain_broken with the first failing seq", () => {
		const v = deriveAuditVerdict(
			report({
				hash_chain_valid: false,
				errors: [
					{ seq: 42, kind: "row_hash_mismatch", detail: "x" },
					{ seq: 43, kind: "prev_hash_mismatch", detail: "y" },
				],
			}),
		);
		expect(v).toEqual<AuditVerdict>({
			state: "chain_broken",
			rows: 1000,
			firstSeq: 42,
		});
		expect(isAlarm(v)).toBe(true);
	});

	it("RED: strip wins even when the chain is intact", () => {
		const v = deriveAuditVerdict(
			report({ strip_detected: true, anchors_included: 2 }),
		);
		expect(v.state).toBe("stripped");
		expect(isAlarm(v)).toBe(true);
	});

	it("RED: real signature failure (deduped reasons)", () => {
		const v = deriveAuditVerdict(
			report({
				signatures_valid: false,
				errors: [
					{ seq: null, kind: "untrusted_tenant_key", detail: "a" },
					{ seq: null, kind: "untrusted_tenant_key", detail: "b" },
				],
			}),
		);
		expect(v).toEqual<AuditVerdict>({
			state: "signature_failed",
			reasons: ["untrusted_tenant_key"],
		});
	});

	it("GREEN: chain + signatures + ≥1 anchor → verified", () => {
		const v = deriveAuditVerdict(report({ anchors_included: 5 }));
		expect(v).toEqual<AuditVerdict>({
			state: "verified",
			rows: 1000,
			anchors: 5,
		});
		expect(isAlarm(v)).toBe(false);
	});

	it("GREEN (qualified): chain intact + signed, no anchor in view → chain_only", () => {
		const v = deriveAuditVerdict(report({ anchors_included: 0 }));
		expect(v).toEqual<AuditVerdict>({ state: "chain_only", rows: 1000 });
		expect(isAlarm(v)).toBe(false);
	});

	it("NEUTRAL: zero rows → empty, never green (verifying nothing is not a pass)", () => {
		// A clean-but-empty report would otherwise fall through to chain_only (GREEN).
		// It must read "empty" instead — and NOT be an alarm (empty ≠ tampering).
		const v = deriveAuditVerdict(report({ rows_seen: 0, anchors_included: 0 }));
		expect(v).toEqual<AuditVerdict>({ state: "empty" });
		expect(isAlarm(v)).toBe(false);
	});

	it("GREEN (ADR-070): windowed verify rooted at a Rekor anchor → verified_windowed w/ scope", () => {
		const v = deriveAuditVerdict(
			report({ verified_from_seq: 1300, anchors_included: 4 }),
		);
		expect(v).toEqual<AuditVerdict>({
			state: "verified_windowed",
			rows: 1000,
			anchors: 4,
			fromSeq: 1300,
		});
		expect(isAlarm(v)).toBe(false);
	});

	it("RED (ADR-070): windowed view with no anchor to root it → unrooted_window", () => {
		const v = deriveAuditVerdict(
			report({
				trust_established: false,
				errors: [{ seq: null, kind: "unrooted_window", detail: "x" }],
			}),
		);
		expect(v).toEqual<AuditVerdict>({ state: "unrooted_window" });
		expect(isAlarm(v)).toBe(true);
	});
});

describe("humanizeVerdictKind", () => {
	it("maps known kinds to plain English", () => {
		expect(humanizeVerdictKind("anchor_rows_missing")).toContain(
			"outside the loaded view",
		);
		expect(humanizeVerdictKind("row_hash_mismatch")).toContain(
			"no longer match",
		);
	});
	it("degrades an unknown kind to de-underscored text (never blank)", () => {
		expect(humanizeVerdictKind("some_new_kind")).toBe("some new kind");
	});
});

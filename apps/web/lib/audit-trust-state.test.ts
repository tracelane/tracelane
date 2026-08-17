import { describe, expect, it } from "vitest";
import {
	type AuditTrustState,
	auditTrustState,
	hasUsableTrustRoot,
} from "./audit-trust-state";

const PUBKEY = "6dw9BR3UN+FcO4MHPVFGzMgqPdL6IBQqat26EDKCWQk=";

describe("auditTrustState", () => {
	it("no anchor records → no-batches, whatever the pubkey says", () => {
		expect(auditTrustState({ anchorRecordCount: 0, anchoredCount: 0 })).toBe(
			"no-batches",
		);
		expect(
			auditTrustState({
				anchorRecordCount: 0,
				anchoredCount: 0,
				tenantPubkeyB64: PUBKEY,
			}),
		).toBe("no-batches");
	});

	// THE REGRESSION. Production, 2026-08-15: five tenants had signed rows and one
	// audit_anchor_records row each, and `/v1/audit/pubkey` returned 404. The old
	// predicate `!tenantPubkeyB64 || anchorRecords.length === 0` short-circuited on the
	// missing pubkey and rendered "No signed batches yet" over real, signed data.
	it("signed rows with NO trust root → operator-signed, NEVER no-batches", () => {
		const got = auditTrustState({
			anchorRecordCount: 1,
			anchoredCount: 0,
			tenantPubkeyB64: undefined,
		});
		expect(got).toBe("operator-signed");
		expect(got).not.toBe("no-batches");
	});

	// The 1bb14687 shape: HTTP 200 with an EMPTY pubkey (fingerprint = sha256("")).
	// Success-shaped and carrying nothing. It must resolve exactly like the 404.
	it("an EMPTY pubkey is not a trust root — same state as a 404", () => {
		expect(
			auditTrustState({
				anchorRecordCount: 1,
				anchoredCount: 0,
				tenantPubkeyB64: "",
			}),
		).toBe("operator-signed");
		expect(
			auditTrustState({
				anchorRecordCount: 1,
				anchoredCount: 0,
				tenantPubkeyB64: "   ",
			}),
		).toBe("operator-signed");
		expect(hasUsableTrustRoot("")).toBe(false);
		expect(hasUsableTrustRoot(null)).toBe(false);
		expect(hasUsableTrustRoot(PUBKEY)).toBe(true);
	});

	it("signed with the tenant's own key, not yet anchored → tenant-signed", () => {
		expect(
			auditTrustState({
				anchorRecordCount: 3,
				anchoredCount: 0,
				tenantPubkeyB64: PUBKEY,
			}),
		).toBe("tenant-signed");
	});

	// An anchor RECORD is written for every signed batch, anchored or not. Counting
	// records as anchors would claim public anchoring for batches that reached no log —
	// which is what the header line did before R43.
	it("a record is not an anchor: only anchoredCount promotes to publicly-anchored", () => {
		expect(
			auditTrustState({
				anchorRecordCount: 5,
				anchoredCount: 0,
				tenantPubkeyB64: PUBKEY,
			}),
		).not.toBe("publicly-anchored");
		expect(
			auditTrustState({
				anchorRecordCount: 5,
				anchoredCount: 1,
				tenantPubkeyB64: PUBKEY,
			}),
		).toBe("publicly-anchored");
	});

	// The property the founder asked for, asserted rather than reviewed: every distinct
	// production shape lands on a DISTINCT state, so none can borrow another's copy.
	it("the four production shapes map to four DISTINCT states", () => {
		const shapes: Array<[string, AuditTrustState]> = [
			[
				"fresh tenant, nothing signed",
				auditTrustState({ anchorRecordCount: 0, anchoredCount: 0 }),
			],
			[
				"32ccef57 — signed, 404 pubkey",
				auditTrustState({ anchorRecordCount: 1, anchoredCount: 0 }),
			],
			[
				"signed with own key, not anchored",
				auditTrustState({
					anchorRecordCount: 1,
					anchoredCount: 0,
					tenantPubkeyB64: PUBKEY,
				}),
			],
			[
				"a4037bef — anchored in Rekor",
				auditTrustState({
					anchorRecordCount: 161,
					anchoredCount: 161,
					tenantPubkeyB64: PUBKEY,
				}),
			],
		];
		const states = shapes.map(([, s]) => s);
		expect(new Set(states).size).toBe(4);
		expect(states).toEqual([
			"no-batches",
			"operator-signed",
			"tenant-signed",
			"publicly-anchored",
		]);
	});

	it("negative/garbage counts fail to the safest state rather than throwing", () => {
		expect(auditTrustState({ anchorRecordCount: -1, anchoredCount: -1 })).toBe(
			"no-batches",
		);
	});
});

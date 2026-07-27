/**
 * Conformance tests for the TypeScript audit-ledger verifier.
 *
 * Each test loads a shared vector from `evals/audit-ledger/` and asserts the
 * exact VerifyReport fields mandated by the cross-language conformance contract.
 * All runs use `offline: true` so no network calls are made.
 */

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { describe, expect, it } from "vitest";
import {
	type VerifyReport,
	genesisV2,
	rowHashV2,
	verifyChain,
	verifyLedgerText,
} from "./index.js";
import { verifyLedger } from "./node.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/** Resolve a path relative to the shared evals/audit-ledger directory. */
function vectorPath(name: string): string {
	return path.resolve(__dirname, "../../../evals/audit-ledger", name);
}

describe("verifyLedger conformance vectors", () => {
	it("verifyLedgerText (browser path) — good passes; tampered fails AT the exact row", async () => {
		// The dashboard runs this exact public verifier client-side over the
		// exported NDJSON. good → chain valid; tampered → the failure names WHERE.
		const good = await verifyLedgerText(
			readFileSync(vectorPath("good.ndjson"), "utf-8"),
			{ offline: true },
		);
		expect(good.hash_chain_valid).toBe(true);
		expect(good.rows_seen).toBeGreaterThan(0);

		const tampered = await verifyLedgerText(
			readFileSync(vectorPath("tampered.ndjson"), "utf-8"),
			{ offline: true },
		);
		expect(tampered.hash_chain_valid).toBe(false);
		const breaks = tampered.errors.filter(
			(e) => e.kind === "row_hash_mismatch" || e.kind === "prev_hash_mismatch",
		);
		expect(breaks.length).toBeGreaterThanOrEqual(1);
		// not just "invalid" — it pinpoints the broken event (a concrete seq).
		expect(breaks[0]?.seq).toEqual(expect.any(Number));
		// with no resolvable anchors, signatures are NOT asserted valid (honesty).
		expect(tampered.rekor_anchors_resolved).toBe(0);
	});

	it("good.ndjson — valid 100-row chain passes all checks", async () => {
		const report = await verifyLedger(vectorPath("good.ndjson"), {
			offline: true,
		});

		expect(report.hash_chain_valid).toBe(true);
		expect(report.rows_seen).toBe(100);
		expect(report.errors).toEqual([]);
	});

	it("eval-verdict.ndjson — promotion-record chain (null eval_run_id) verifies", async () => {
		// Wedge item 3. Middle row's eval_run_id is JSON null (manual override) —
		// proves null canonicalizes identically to the Rust + Python verifiers.
		const report = await verifyLedger(vectorPath("eval-verdict.ndjson"), {
			offline: true,
		});

		expect(report.hash_chain_valid).toBe(true);
		expect(report.rows_seen).toBe(3);
		expect(report.errors).toEqual([]);
	});

	it("tampered.ndjson — mutated payload detected as row_hash_mismatch", async () => {
		const report = await verifyLedger(vectorPath("tampered.ndjson"), {
			offline: true,
		});

		expect(report.hash_chain_valid).toBe(false);
		const mismatchErrors = report.errors.filter(
			(e) => e.kind === "row_hash_mismatch",
		);
		expect(mismatchErrors.length).toBeGreaterThanOrEqual(1);
	});

	it("no-anchor.ndjson — valid chain with no Rekor entries", async () => {
		const report = await verifyLedger(vectorPath("no-anchor.ndjson"), {
			offline: true,
		});

		expect(report.hash_chain_valid).toBe(true);
		expect(report.rekor_anchors_seen).toBe(0);
	});
});

// ── ADR-070: windowed verify (genesis retention-truncated) — TS mirror of the
//    Rust `verify_chain` windowed tests. Slices the valid good.ndjson chain to
//    seq >= 10 (genesis absent) and roots via a mock includedStarts, so the
//    two verifiers assert the identical windowed behavior byte-for-byte.
type ChainRows = Parameters<typeof verifyChain>[1];
const WTENANT = "00000000-0000-0000-0000-000000000001";

function emptyReport(): VerifyReport {
	return {
		ledger_path: "t",
		rows_seen: 0,
		hash_chain_valid: true,
		signatures_valid: true,
		rekor_anchors_seen: 0,
		rekor_anchors_resolved: 0,
		anchors_included: 0,
		strip_detected: false,
		verified_from_seq: 0,
		trust_established: true,
		errors: [],
	};
}

function windowedRows(): ChainRows {
	const rows = readFileSync(vectorPath("good.ndjson"), "utf-8")
		.split("\n")
		.filter(Boolean)
		.map((l) => JSON.parse(l) as { seq: number });
	return rows.filter((r) => r.seq >= 10) as unknown as ChainRows;
}

describe("ADR-070 windowed verify (TS)", () => {
	it("roots at the anchor; scope = anchor start, NOT min loaded", () => {
		const rows = windowedRows();
		const report = emptyReport();
		report.rows_seen = (rows as unknown[]).length;
		// Resolved anchor covers seq 12+ (window loaded from seq 10).
		verifyChain(report, rows, "v2", new Map([[WTENANT, 12]]));
		expect(report.hash_chain_valid).toBe(true);
		expect(report.trust_established).toBe(true);
		expect(report.verified_from_seq).toBe(12); // not 10 — no scope inflation
		expect(report.errors).toEqual([]); // pre-anchor rows skipped, not errored
	});

	it("in-window tamper is RED (row_hash_mismatch at the exact seq)", () => {
		const rows = windowedRows() as unknown as Array<{
			seq: number;
			payload: unknown;
		}>;
		const r13 = rows.find((r) => r.seq === 13);
		if (r13)
			r13.payload = {
				...(typeof r13.payload === "object" ? r13.payload : {}),
				tampered: true,
			};
		const report = emptyReport();
		verifyChain(
			report,
			rows as unknown as ChainRows,
			"v2",
			new Map([[WTENANT, 12]]),
		);
		expect(report.hash_chain_valid).toBe(false);
		expect(
			report.errors.some((e) => e.kind === "row_hash_mismatch" && e.seq === 13),
		).toBe(true);
	});

	it("windowed with NO resolved anchor is unrooted RED, never green", () => {
		const rows = windowedRows();
		const report = emptyReport();
		verifyChain(report, rows, "v2", new Map());
		expect(report.trust_established).toBe(false);
		expect(report.errors.some((e) => e.kind === "unrooted_window")).toBe(true);
		expect(report.verified_from_seq).toBe(0);
	});
});

// ── Multitenant aggregate: the report-level `verified_from_seq` must be the
//    LATEST (max) per-tenant start, not the earliest — no scope inflation. TS
//    mirror of the Rust `multitenant_aggregate_is_latest_start_not_earliest`.
const MT_TENANT_A = "00000000-0000-0000-0000-0000000000a1";
const MT_TENANT_B = "00000000-0000-0000-0000-0000000000b1";

function tenantUuidBytes(tenant: string): Uint8Array {
	return hexToBytes(tenant.replace(/-/g, ""));
}

/**
 * Build a valid v2.1 chain (payload = verbatim canonical STRING, row hashes
 * computed) of `count` rows starting at `startSeq`, chained from `prev`. `prev`
 * is the genesis seed for a start-0 chain, or the anchor seed for a windowed one.
 */
function buildV21Chain(
	tenant: string,
	startSeq: number,
	count: number,
	prev: Uint8Array,
): ChainRows {
	const tu = tenantUuidBytes(tenant);
	let chainPrev = prev;
	const rows: Array<Record<string, unknown>> = [];
	for (let i = 0; i < count; i++) {
		const seq = startSeq + i;
		const payload = JSON.stringify({ i: seq });
		const rh = rowHashV2(chainPrev, tu, seq, "evt", "actor", payload);
		rows.push({
			format: "v2.1",
			tenant_id: tenant,
			seq,
			event_time: "2026",
			event_type: "evt",
			actor: "actor",
			payload,
			prev_hash: seq === 0 ? "" : bytesToHex(chainPrev),
			row_hash: bytesToHex(rh),
			rekor_entry_id: null,
		});
		chainPrev = rh;
	}
	return rows as unknown as ChainRows;
}

describe("multitenant aggregate verified_from_seq (TS)", () => {
	it("aggregate = MAX per-tenant start (windowed B=10), never MIN (genesis A=0)", () => {
		// Tenant A is genesis-rooted (start 0); tenant B is windowed, rooted at a
		// resolved anchor (start 10). A `min` aggregate (0) would read
		// "genesis→tip for ALL" and hide B's pre-anchor gap; `max` (10) reads
		// "verified no earlier than seq 10" — true for both tenants.
		const rowsA = buildV21Chain(
			MT_TENANT_A,
			0,
			2,
			genesisV2(tenantUuidBytes(MT_TENANT_A)),
		);
		const seedB = new Uint8Array(32).fill(9);
		const rowsB = buildV21Chain(MT_TENANT_B, 10, 2, seedB);
		const rows = [
			...(rowsA as unknown as unknown[]),
			...(rowsB as unknown as unknown[]),
		] as unknown as ChainRows;

		const report = emptyReport();
		report.rows_seen = 4;
		// Only tenant B needs an injected anchor start; A is genesis-present (0).
		verifyChain(report, rows, "v2.1", new Map([[MT_TENANT_B, 10]]));

		expect(report.hash_chain_valid).toBe(true);
		expect(report.trust_established).toBe(true);
		// aggregate MUST be MAX (windowed B = 10), never MIN (genesis A = 0).
		expect(report.verified_from_seq).toBe(10);
	});
});

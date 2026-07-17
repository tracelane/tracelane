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
import { describe, expect, it } from "vitest";
import { verifyLedgerText } from "./index.js";
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

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
/**
 * Conformance tests against canonical vectors in `evals/audit-ledger/`.
 *
 * Mirrors the Rust + Python verifier conformance suites. All three verifiers
 * MUST agree on each vector.
 */
import { describe, expect, it } from "vitest";
import { verifyLedgerText } from "../src/index.js";
import { verifyLedger } from "../src/node.js";

function b64(s: string): Uint8Array {
	return Uint8Array.from(Buffer.from(s, "base64"));
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectorsDir = join(__dirname, "..", "..", "..", "evals", "audit-ledger");

function vector(name: string): string {
	return join(vectorsDir, name);
}

describe("audit-verifier conformance", () => {
	it("good vector passes chain check", async () => {
		const path = vector("good.ndjson");
		if (!existsSync(path)) {
			console.warn(`skipping: vector not found at ${path}`);
			return;
		}
		const report = await verifyLedger(path, { offline: true });
		expect(report.hash_chain_valid).toBe(true);
		expect(report.rows_seen).toBe(100);
	});

	it("tampered vector fails chain check", async () => {
		const path = vector("tampered.ndjson");
		if (!existsSync(path)) return;
		const report = await verifyLedger(path, { offline: true });
		expect(report.hash_chain_valid).toBe(false);
		expect(report.errors.length).toBeGreaterThan(0);
	});

	it("no-anchor vector chain still valid", async () => {
		const path = vector("no-anchor.ndjson");
		if (!existsSync(path)) return;
		const report = await verifyLedger(path, { offline: true });
		expect(report.hash_chain_valid).toBe(true);
		expect(report.rekor_anchors_seen).toBe(0);
	});

	// 1e2, 0.50) as the verbatim canonical STRING. All three verifiers hash it
	// byte-for-byte, so it passes identically — the parity bug cannot exist.
	it("v2.1 boundary-number vector passes (verbatim string)", async () => {
		const path = vector("boundary-numbers.v2_1.ndjson");
		if (!existsSync(path)) return;
		const report = await verifyLedger(path, { offline: true });
		expect(report.hash_chain_valid).toBe(true);
		expect(report.rows_seen).toBe(2);
	});

	// re-derive path (JSON.parse/stringify) is lossy for these numbers, so the
	// recomputed hash diverges from the writer's. This is precisely why Path 2
	// (verbatim string) was chosen; the vector above passes where this cannot.
	it("legacy-v2 object vector reproduces the lossy JS re-derive", async () => {
		const path = vector("boundary-numbers.v2-legacy.ndjson");
		if (!existsSync(path)) return;
		const report = await verifyLedger(path, { offline: true });
		expect(report.hash_chain_valid).toBe(false);
		expect(report.errors.some((e) => e.kind === "row_hash_mismatch")).toBe(
			true,
		);
	});
});

describe("ADR-062 anchor verification (offline, real Rekor v2)", () => {
	const metaPath = vector("anchor-vectors.meta.json");

	it("anchored.v1 verifies FULLY with the trusted tenant key", async () => {
		if (!existsSync(vector("anchored.v1.ndjson"))) return;
		const meta = JSON.parse(readFileSync(metaPath, "utf8"));
		const trusted = b64(meta.trusted_tenant_ed25519_pubkey_b64);
		const text = readFileSync(vector("anchored.v1.ndjson"), "utf8");
		const r = await verifyLedgerText(text, {
			formatVersion: "v2.1",
			tenantPubkey: trusted,
		});
		expect(r.hash_chain_valid).toBe(true);
		expect(r.errors).toEqual([]);
		expect(r.signatures_valid).toBe(true);
		expect(r.rekor_anchors_resolved).toBe(1);
		expect(r.anchors_included).toBe(1); // Layer 2 inclusion + Layer 3 checkpoint
		expect(r.strip_detected).toBe(false);
	});

	it("forged-anchor is REJECTED at the trusted-key gate (C1/C2)", async () => {
		// A genuinely-log-included Rekor entry, but signed under an ATTACKER key.
		if (!existsSync(vector("forged-anchor.ndjson"))) return;
		const meta = JSON.parse(readFileSync(metaPath, "utf8"));
		const trusted = b64(meta.trusted_tenant_ed25519_pubkey_b64);
		const text = readFileSync(vector("forged-anchor.ndjson"), "utf8");
		const r = await verifyLedgerText(text, {
			formatVersion: "v2.1",
			tenantPubkey: trusted,
		});
		expect(r.hash_chain_valid).toBe(true); // the chain itself is fine
		expect(r.signatures_valid).toBe(false); // but the anchor is rejected
		expect(r.anchors_included).toBe(0);
		expect(r.errors.some((e) => e.kind === "untrusted_tenant_key")).toBe(true);
	});

	it("chain-only mode (no trusted key) asserts NO anchor — never green", async () => {
		if (!existsSync(vector("anchored.v1.ndjson"))) return;
		const text = readFileSync(vector("anchored.v1.ndjson"), "utf8");
		const r = await verifyLedgerText(text, { formatVersion: "v2.1" });
		expect(r.hash_chain_valid).toBe(true);
		expect(r.rekor_anchors_resolved).toBe(0);
		expect(r.anchors_included).toBe(0);
	});
});

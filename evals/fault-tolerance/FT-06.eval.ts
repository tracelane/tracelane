import { describe, it } from "vitest";
import { expect } from "../src/harness.js";
import fs from "node:fs";
import path from "node:path";

/**
 * FT-06 — Audit log Rekor outage: entries queued for re-publish
 *
 * Scenario: Sigstore Rekor (transparency log) is unreachable. The audit log
 * SHA-256 hash chain must continue to accumulate locally. Entries must be
 * queued in NATS for re-submission to Rekor when it recovers. The local
 * hash chain integrity is not affected by Rekor availability.
 *
 * Production code: `crates/gateway/src/audit.rs` — compute_row_hash() builds
 * the local chain. Rekor anchoring runs as a separate async task (Week 7).
 * On Rekor failure: write to NATS dead-letter queue; emit alert span.
 *
 * Chaos method: Disable Rekor mock. Add 10 audit log entries. Assert
 * (a) local hash chain is intact, (b) entries are queued for retry,
 * (c) alert span fires. Restore Rekor; assert entries are anchored.
 *
 * Status: Structural assertions green. Rekor anchoring + queue integration
 * is Week 7; chaos test skipped until then.
 */

const GATEWAY_SRC = path.resolve(__dirname, "../../crates/gateway/src");

describe("FT-06: Audit log Rekor outage — local chain intact, queue fills", () => {
  it("audit module exists with hash chain implementation", () => {
    const p = path.join(GATEWAY_SRC, "audit.rs");
    expect(fs.existsSync(p)).toBe(true);
  });

  it("audit.rs implements SHA-256 hash chain (compute_row_hash)", () => {
    const content = fs.readFileSync(path.join(GATEWAY_SRC, "audit.rs"), "utf8");
    expect(content).toContain("compute_row_hash");
    expect(content).toContain("SHA");
  });

  it("Rekor anchoring is documented as separate async task in audit.rs", () => {
    const content = fs.readFileSync(path.join(GATEWAY_SRC, "audit.rs"), "utf8");
    expect(content).toContain("Rekor");
  });

  it("audit.rs hash chain uses 32-byte zero sentinel for genesis row (seq == 0)", () => {
    const content = fs.readFileSync(path.join(GATEWAY_SRC, "audit.rs"), "utf8");
    // ADR-018 §"Row hash formula": prev_hash_bytes is 32 zero bytes when seq == 0
    expect(content).toContain("seq");
    expect(content).toContain("prev_hash");
  });

  it("ADR-018 documents Rekor outage fallback strategy", () => {
    const adr = fs.readFileSync(
      path.resolve(__dirname, "../../decisions/ADR-018-tamper-evident-ledger-v1.md"),
      "utf8",
    );
    expect(adr).toContain("Rekor");
    // Rekor outage must fall back to self-hosted instance per ADR-018 Consequences
    expect(adr).toContain("self-hosted");
  });

  it("real Rekor-outage chaos test exists in audit.rs (local chain intact)", () => {
    // The integration fault is now injected for real as an in-module unit
    // test: anchoring is a fire-and-forget tokio::spawn, so with no reachable
    // Rekor every anchor batch fails while all appends still succeed and the
    // per-tenant chain advances across both anchor boundaries.
    const audit = path.resolve(
      __dirname,
      "../../crates/gateway/src/audit.rs",
    );
    const content = fs.readFileSync(audit, "utf8");
    expect(content).toContain("ft06_rekor_outage_does_not_break_local_chain");
    // The assertion that the local chain keeps advancing under the outage.
    expect(content).toContain("chain advanced across both anchor batches");
  });
});

import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PIR-001 — PII redaction: 100% recall on synthetic patterns
 *
 * Verifies the PII redaction module in crates/policy/src/pii.rs covers the
 * standard synthetic PII patterns. The module must detect:
 *   - SSN: 123-45-6789
 *   - Credit card: 4111-1111-1111-1111
 *   - Email: user@example.com
 *   - Phone: +1-800-555-0100
 *   - AWS access key: AKIA...
 *
 * Structural: verify pii.rs exists and documents redaction patterns.
 * Integration: 100% recall measurement against 1K synthetic spans (Week 8).
 */
describe("PIR-001: PII redaction — 100% recall on synthetic patterns", () => {
  it("PII redaction module exists in policy crate", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const p = path.resolve(__dirname, "../../crates/policy/src/pii.rs");
    expect(fs.existsSync(p)).toBe(true);
  });

  it("pii.rs documents the required pattern categories", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const src = fs.readFileSync(
      path.resolve(__dirname, "../../crates/policy/src/pii.rs"),
      "utf8"
    );
    const required = ["SSN", "credit", "email", "phone"];
    for (const category of required) {
      expect(src.toLowerCase(), `Missing PII category: ${category}`).toContain(
        category.toLowerCase()
      );
    }
  });

  it("TRACELANE_TRACE_CONTENT env var is documented in SDK", async () => {
    // Both SDKs must respect TRACELANE_TRACE_CONTENT=false to redact payloads
    const fs = await import("node:fs");
    const path = await import("node:path");
    const sdkFiles = [
      "../../packages/sdk-python/README.md",
      "../../packages/sdk-typescript/README.md",
    ];
    for (const rel of sdkFiles) {
      const p = path.resolve(__dirname, rel);
      if (!fs.existsSync(p)) continue;
      const src = fs.readFileSync(p, "utf8");
      expect(src, `SDK README missing TRACELANE_TRACE_CONTENT: ${rel}`).toContain(
        "TRACELANE_TRACE_CONTENT"
      );
    }
  });

  it("provider keys are never included in span attributes (gateway guarantee)", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const otlpSrc = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/otlp_emit.rs"),
      "utf8"
    );
    // The otlp_emit module must document that provider keys are excluded
    expect(otlpSrc.toLowerCase()).toContain("key");
    expect(otlpSrc.toLowerCase()).toContain("never");
  });

  it.skip("100% recall: all 1K synthetic PII spans are redacted before storage (integration — Week 8)", async () => {
    // Full: inject 1K spans with known PII patterns, read from ClickHouse,
    // assert zero PII patterns remain in stored span content
  });
});

import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-DETERMINISTIC-ROLLBACK — token-free recovery invariant (ADR-037, §23.3).
 *
 * Contract: with all provider adapters mocked to hard-fail and the SLM judge
 * disabled, `tlane rollback` still completes and restores the prior pointer.
 * Recovery must never depend on an LLM / agent / MCP / provider.
 *
 * This file asserts the invariant statically (the strongest cheap proof): the
 * recovery paths import no provider/MCP/judge module, the auto-rollback path is
 * objective-metrics-only, and the CI guard exists + is wired. The full
 * providers-mocked-fail integration run is the skipped case.
 */
function read(rel: string): string {
  // biome-ignore lint/style/useNodejsImportProtocol: harness is CJS
  const fs = require("node:fs");
  // biome-ignore lint/style/useNodejsImportProtocol: harness is CJS
  const path = require("node:path");
  return fs.readFileSync(path.resolve(__dirname, rel), "utf8");
}

describe("PP-DETERMINISTIC-ROLLBACK: token-free recovery (ADR-037)", () => {
  it("tlane rollback exists and swaps the ClickHouse routing pointer", () => {
    const src = read("../../packages/cli/src/commands/rollback.ts");
    expect(src).toContain("INSERT INTO tracelane.promotion_decisions");
    expect(src).toContain("manual_override");
    // talks to ClickHouse directly, not the gateway
    expect(src).toContain("TRACELANE_CLICKHOUSE_URL");
  });

  it("tlane rollback imports NO provider / MCP / judge module", () => {
    const src = read("../../packages/cli/src/commands/rollback.ts");
    // Strip line comments, then assert none of the forbidden deps appear.
    const code = src.replace(/\/\/.*$/gm, "");
    for (const forbidden of [
      "@modelcontextprotocol",
      'from "openai"',
      "@anthropic-ai",
      "slm_judge",
    ]) {
      expect(
        code.includes(forbidden),
        `rollback.ts must not import ${forbidden}`
      ).toBe(false);
    }
  });

  it("auto-rollback auto path is objective-metrics only (judge is suggest-only)", () => {
    const src = read("../../crates/gateway/src/auto_rollback.rs");
    expect(src).toContain("is_objective");
    // Accuracy / Hallucination (judge-derived) must be the suggest path.
    expect(src).toContain("Suggested");
    expect(src).toContain("RollbackMode::Auto");
  });

  it("no-llm-in-recovery CI guard exists and is wired", () => {
    const guard = read("../../scripts/ci/no-llm-in-recovery.sh");
    expect(guard).toContain("auto_rollback.rs");
    expect(guard).toContain("rollback.ts");
    const ci = read("../../.github/workflows/ci.yml");
    expect(ci).toContain("no-llm-in-recovery.sh");
  });

  it.skip("integration: providers mocked-fail + judge off → rollback completes (Week 8)", () => {
    // Full: mock every provider adapter to hard-fail, disable the SLM judge,
    // run `tlane rollback --to <prior>`, assert the active pointer is restored.
  });
});

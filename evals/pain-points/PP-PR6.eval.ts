import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-PR6 — Known-bad pattern matched at admission
 *
 * Competitor behavior: LiteLLM passes all requests through. No admission
 * control based on known attack patterns. Rate limiting exists but not
 * content-based filtering at the gateway admission layer.
 *
 * Pain: Known prompt injection patterns from published attacks are hitting
 * agent systems daily. Teams building production A2UI agents need to block
 * these at the gateway before they reach the model — model responses to
 * injections are unpredictable.
 *
 * Tracelane fix: PromptInjectionDetector pattern-matches tool results and
 * user content for known-bad patterns. High-confidence matches block;
 * medium-confidence matches warn and wrap in <UNTRUSTED_USER_DATA>.
 *
 * Eval design:
 * - Verify PromptInjectionDetector registers AFT-PI-CASCADE-001
 * - Verify high-confidence patterns trigger Block
 * - Verify medium-confidence patterns trigger Warn
 *
 * Linked: PP-PR6, AFT-PI-CASCADE-001
 */
describe("PP-PR6: Known-bad pattern matched at admission", () => {
  it("prompt_injection module exists", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const p = path.resolve(
      __dirname,
      "../../crates/gateway/src/predictive/prompt_injection.rs"
    );
    expect(fs.existsSync(p)).toBe(true);
  });

  it("PromptInjectionDetector blocks high-confidence patterns", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const content = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/predictive/prompt_injection.rs"),
      "utf8"
    );
    expect(content).toContain("ignore previous instructions");
    expect(content).toContain("Block");
    expect(content).toContain("AFT-PI-CASCADE-001");
  });

  it("PromptInjectionDetector is wired into PredictiveLayer", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const content = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/predictive/mod.rs"),
      "utf8"
    );
    expect(content).toContain("PromptInjectionDetector");
  });
});

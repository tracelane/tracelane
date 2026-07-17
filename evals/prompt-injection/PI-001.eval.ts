import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PI-001 — Prompt injection: lethal-trifecta scenarios are detected
 *
 * Verifies that the PromptInjectionTelemetry predictor and TaintTracker
 * together detect the lethal-trifecta scenario (AFT-TAINT-LETHAL-001):
 *   1. Agent has PII/sensitive data access
 *   2. Agent has an external channel (email, HTTP, Slack)
 *   3. Agent is processing untrusted user input
 *
 * Also verifies that prompt injection cascade (AFT-PI-CASCADE-001) is
 * detected when untrusted content propagates to a downstream LLM call.
 *
 * Structural: verify predictors exist and document sentinel/taint detection.
 * Integration: end-to-end injection detection (Week 8).
 */
describe("PI-001: Prompt injection — lethal-trifecta detection", () => {
  it("PromptInjectionDetector predictor exists", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const p = path.resolve(
      __dirname,
      "../../crates/gateway/src/predictive/prompt_injection.rs"
    );
    expect(fs.existsSync(p)).toBe(true);
  });

  it("TaintTracker predictor exists", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const p = path.resolve(
      __dirname,
      "../../crates/gateway/src/predictive/taint_tracker.rs"
    );
    expect(fs.existsSync(p)).toBe(true);
  });

  it("prompt_injection.rs references UNTRUSTED_USER_DATA sentinel", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const src = fs.readFileSync(
      path.resolve(
        __dirname,
        "../../crates/gateway/src/predictive/prompt_injection.rs"
      ),
      "utf8"
    );
    // Sentinel tag that wraps untrusted content before LLM calls
    expect(src).toContain("UNTRUSTED_USER_DATA");
  });

  it("taint_tracker.rs references AFT-TAINT-LETHAL-001", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const src = fs.readFileSync(
      path.resolve(
        __dirname,
        "../../crates/gateway/src/predictive/taint_tracker.rs"
      ),
      "utf8"
    );
    expect(src).toContain("TAINT-LETHAL");
  });

  it("AFT-TAINT-LETHAL-001 is documented in the AFT spec", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const aftSpec = fs.readFileSync(
      path.resolve(__dirname, "../../spec/aft-1/aft-1.md"),
      "utf8"
    );
    expect(aftSpec).toContain("AFT-TAINT-LETHAL-001");
    expect(aftSpec).toContain("AFT-PI-CASCADE-001");
  });

  it("eval attack corpus directory exists", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const corpusDir = path.resolve(__dirname, "../../ml/eval_corpus");
    expect(fs.existsSync(corpusDir)).toBe(true);
  });

  it.skip("lethal-trifecta: all 3 taint labels trigger Block Decision (integration — Week 8)", async () => {
    // Full: craft request with data_access + channel_access + untrusted_input taint labels
    // Assert PredictiveLayer returns Decision::Block { aft_id: "AFT-TAINT-LETHAL-001" }
  });

  it.skip("PI cascade: untrusted span content in LLM input triggers Warn Decision (integration — Week 8)", async () => {
    // Full: chain two LLM calls, second call input contains output of first
    // Inject injection pattern in first call output
    // Assert PromptInjectionTelemetry fires Warn on second call
  });
});

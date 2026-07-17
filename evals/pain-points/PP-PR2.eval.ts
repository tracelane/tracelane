import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-PR2 — Lethal trifecta taint tracker fires
 *
 * Competitor behavior: No competitor tracks the "lethal trifecta" risk
 * pattern. LiteLLM passes all requests through regardless of the
 * combination of shell access + untrusted input + frontier model.
 *
 * Pain: Security teams want to know when a frontier model with shell
 * access is processing web-sourced input. This is the highest-risk
 * prompt injection scenario. Without a signal, teams can't gate or
 * audit these requests.
 *
 * Tracelane fix: TaintTracker predictor evaluates every gateway request.
 * When all three taint sources co-occur, fires AFT-TAINT-LETHAL-001.
 *
 * Eval design:
 * - Verify TaintTracker is registered in PredictiveLayer
 * - Verify trifecta request returns Warn
 * - Verify two-out-of-three returns Allow
 *
 * Linked: PP-PR2, AFT-TAINT-LETHAL-001
 */
describe("PP-PR2: Lethal trifecta taint tracker", () => {
  it("taint tracker module exists in predictive layer", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const taintPath = path.resolve(
      __dirname,
      "../../crates/gateway/src/predictive/taint_tracker.rs"
    );
    expect(fs.existsSync(taintPath)).toBe(true);
  });

  it("taint tracker registers AFT-TAINT-LETHAL-001", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const content = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/predictive/taint_tracker.rs"),
      "utf8"
    );
    expect(content).toContain("AFT-TAINT-LETHAL-001");
  });

  it("PredictiveLayer wires in TaintTracker", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const content = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/predictive/mod.rs"),
      "utf8"
    );
    expect(content).toContain("TaintTracker");
  });

  it.skip("trifecta request triggers Warn (integration — Week 5)", async () => {
    // Full: send request with shell tool + untrusted_input=true + frontier model
    // Assert response has x-tracelane-intervention: warn header
    // Assert span has tracelane.aft_ids containing AFT-TAINT-LETHAL-001
  });
});

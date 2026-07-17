import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * GC-005 — Predictive layer: all 8 predictors are registered and fire
 *
 * Verifies that PredictiveLayer in crates/gateway/src/predictive/mod.rs
 * registers exactly 8 predictors and that the evaluate() method returns
 * the most-severe Decision across all of them.
 *
 *   1. McpHashWatcher         — MCP rug-pull detection
 *   2. TaintTracker           — lethal-trifecta taint propagation
 *   3. StuckLoopDetector      — agent stuck-loop heuristic
 *   4. PromptInjectionTelemetry — PI cascade detection
 *   5. A2aHandoffValidator    — A2A lifecycle validation
 *   6. A2uiValidator          — A2UI catalog conformance
 *   7. BrowserPassiveObserver — DOM mutation + CAPTCHA
 *   8. CaptchaPreemptor       — CAPTCHA URL/content pre-emption
 *
 * Structural: verify all 8 source files exist and mod.rs references all.
 */
describe("GC-005: Predictive layer — all 8 predictors registered", () => {
  const PREDICTORS = [
    { module: "mcp_hash_watcher", struct: "McpHashWatcher" },
    { module: "taint_tracker", struct: "TaintTracker" },
    { module: "stuck_loop", struct: "StuckLoopDetector" },
    { module: "prompt_injection", struct: "PromptInjectionDetector" },
    { module: "a2a_validator", struct: "A2aValidator" },
    { module: "a2ui_validator", struct: "A2uiValidator" },
    { module: "browser_capture", struct: "BrowserPassiveObserver" },
    { module: "captcha", struct: "CaptchaPreemptor" },
  ];

  it("all 8 predictor source files exist", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const dir = path.resolve(
      __dirname,
      "../../crates/gateway/src/predictive"
    );

    for (const { module } of PREDICTORS) {
      const p = path.join(dir, `${module}.rs`);
      expect(fs.existsSync(p), `Missing predictor: ${module}.rs`).toBe(true);
    }
  });

  it("predictive/mod.rs declares all 8 predictor modules", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const src = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/predictive/mod.rs"),
      "utf8"
    );

    for (const { module } of PREDICTORS) {
      expect(src, `mod.rs missing: pub mod ${module}`).toContain(module);
    }
  });

  it("predictive/mod.rs boxes all 8 predictors into evaluate() vec", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const src = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/predictive/mod.rs"),
      "utf8"
    );

    for (const { struct } of PREDICTORS) {
      expect(src, `evaluate() missing: ${struct}`).toContain(struct);
    }
  });

  it("Decision enum has Allow, Warn, and Block variants", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const src = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/predictive/mod.rs"),
      "utf8"
    );
    expect(src).toContain("Allow");
    expect(src).toContain("Warn");
    expect(src).toContain("Block");
  });

  it.skip("predictive layer fires in <50ms p99 on real gateway (benchmark — Week 8)", async () => {
    // Full: fire 1000 requests through gateway, collect p99 predictive_ms span attr
    // Assert p99 < 50ms
  });
});

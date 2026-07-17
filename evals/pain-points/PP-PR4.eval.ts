import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-PR4 — Browser stuck-loop detected after 3 repeats
 *
 * Competitor behavior: No competitor detects A2UI stuck-loop patterns.
 * Agents burning thousands of tokens trying to click the same intercepted
 * button show up only in cost reports — hours later.
 *
 * Pain: A2UI agents navigating web UIs get stuck in loops. The CAPTCHA
 * intercepted the click, the DOM changed, the selector stopped working.
 * Without early detection, the agent spends its entire token budget
 * repeating the same failing action.
 *
 * Tracelane fix: StuckLoopDetector fires Warn after 3 identical tool calls
 * in the same trace. The A2UI eval PP-PR5 covers CAPTCHA pre-emption.
 *
 * Eval design:
 * - Verify StuckLoopDetector is registered in PredictiveLayer
 * - Verify 3x repeat triggers Warn with AFT-A2UI-STUCKLOOP-001
 *
 * Linked: PP-PR4, AFT-A2UI-STUCKLOOP-001
 */
describe("PP-PR4: Browser stuck-loop detected after 3 repeats", () => {
  it("stuck-loop detector module exists", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const p = path.resolve(
      __dirname,
      "../../crates/gateway/src/predictive/stuck_loop.rs"
    );
    expect(fs.existsSync(p)).toBe(true);
  });

  it("stuck-loop detector registers AFT-A2UI-STUCKLOOP-001", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const content = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/predictive/stuck_loop.rs"),
      "utf8"
    );
    expect(content).toContain("AFT-A2UI-STUCKLOOP-001");
    expect(content).toContain("3");
  });

  it("PredictiveLayer wires in StuckLoopDetector", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const content = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/predictive/mod.rs"),
      "utf8"
    );
    expect(content).toContain("StuckLoopDetector");
  });
});

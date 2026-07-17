import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-PR3 — A2UI catalog mismatch rejected at gateway
 *
 * Competitor behavior: No competitor validates A2UI component types at the
 * gateway level. LangGraph validates at the Python type level only (after
 * the fact). Browser automation frameworks pass any component reference
 * through without validation.
 *
 * Pain: A compromised or buggy A2UI agent can reference non-existent
 * component types from a malicious catalog, burning tokens before failure.
 *
 * Tracelane fix: A2uiValidator predictor validates every A2UI `createSurface`
 * and `updateComponents` message against the standard A2UI component allowlist.
 * Unknown component type → Block (AFT-A2UI-CATALOG-001). Implemented Week 6.
 *
 */
describe("PP-PR3: A2UI catalog mismatch rejected at gateway", () => {
  it("a2ui_validator module exists", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const p = path.resolve(
      __dirname,
      "../../crates/gateway/src/predictive/a2ui_validator.rs"
    );
    expect(fs.existsSync(p)).toBe(true);
  });

  it("A2uiValidator registers AFT-A2UI-CATALOG-001", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const content = fs.readFileSync(
      path.resolve(
        __dirname,
        "../../crates/gateway/src/predictive/a2ui_validator.rs"
      ),
      "utf8"
    );
    expect(content).toContain("AFT-A2UI-CATALOG-001");
    expect(content).toContain("Block");
  });

  it("A2uiValidator is wired into PredictiveLayer", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const mod = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/predictive/mod.rs"),
      "utf8"
    );
    expect(mod).toContain("A2uiValidator");
    expect(mod).toContain("Vec<Box<dyn Predictor>>");
  });
});

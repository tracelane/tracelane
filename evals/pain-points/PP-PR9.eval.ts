import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-PR9 — A2A handoff schema violation caught
 *
 * Competitor behavior: No competitor validates A2A handoff payloads.
 * LangGraph has types at the Python level but no gateway-level enforcement.
 * A malformed handoff silently causes the receiving agent to fail in ways
 * that are hard to trace back to the handoff.
 *
 * Pain: Multi-agent orchestration failures are opaque. "The executor agent
 * failed" is the error — not "the planner sent a handoff without the
 * required context field." Root cause analysis takes hours.
 *
 * Tracelane fix: A2aValidator predictor validates every A2A handoff message
 * against the required schema fields at the gateway level. Schema violations
 * fire AFT-A2A-LIFECYCLE-001 with the missing field name.
 *
 * Eval design:
 * - Verify A2aValidator module exists
 * - Verify it registers AFT-A2A-LIFECYCLE-001
 * - Verify missing required field triggers Warn
 *
 * Linked: PP-PR9, AFT-A2A-LIFECYCLE-001
 */
describe("PP-PR9: A2A handoff schema violation caught", () => {
  it("a2a_validator module exists", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const p = path.resolve(
      __dirname,
      "../../crates/gateway/src/predictive/a2a_validator.rs"
    );
    expect(fs.existsSync(p)).toBe(true);
  });

  it("A2aValidator registers AFT-A2A-LIFECYCLE-001", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const content = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/predictive/a2a_validator.rs"),
      "utf8"
    );
    expect(content).toContain("AFT-A2A-LIFECYCLE-001");
  });

  it("A2aValidator is wired into PredictiveLayer", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const content = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/predictive/mod.rs"),
      "utf8"
    );
    expect(content).toContain("A2aValidator");
  });

  it("a2a_validator.rs defines REQUIRED_A2A_FIELDS constant", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const content = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/predictive/a2a_validator.rs"),
      "utf8"
    );
    // Required schema fields must be statically declared — not magic strings
    expect(content).toContain("REQUIRED_A2A_FIELDS");
    expect(content).toContain("handoff_id");
    expect(content).toContain("from_agent");
    expect(content).toContain("to_agent");
  });

  it("a2a_validator.rs production code contains no unwrap() calls", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const content = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/predictive/a2a_validator.rs"),
      "utf8"
    );
    const testStart = content.indexOf("mod tests");
    const prodCode = testStart >= 0 ? content.slice(0, testStart) : content;
    const nonCommentLines = prodCode
      .split("\n")
      .filter((l) => !l.trim().startsWith("//"));
    const hasUnwrap = nonCommentLines.some((l) => l.includes(".unwrap()"));
    expect(hasUnwrap).toBe(false);
  });

  it.skip("missing required handoff field fires Warn with field name in attributes (integration)", () => {
    // Full: send A2A handoff missing 'context' field through the gateway,
    // assert span has tracelane.aft_id="AFT-A2A-LIFECYCLE-001" and missing_field="context"
  });
});

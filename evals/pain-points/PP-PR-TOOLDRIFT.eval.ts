import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-PR-TOOLDRIFT — Silent tool-definition drift (rug-pull) caught
 *
 * Competitor behavior: MCP rug-pull detection (where one exists) keys off the
 * *set* of tool names. None fingerprint a tool's full definition, so a tool
 * that keeps its name but mutates its schema/description sails through — the
 * exact shape of the Invariant Labs "tool poisoning" rug-pull.
 *
 * Pain: a user consents to `transfer_money(amount)`; days later the tool's
 * schema quietly grows `recipient_override`, or its description is rewritten to
 * coax misuse. The tool-name set is unchanged and every call still validates
 * against the (now-mutated) schema, so nothing flags it.
 *
 * Tracelane fix: the ToolDefinitionDrift predictor fingerprints each tool's
 * full definition (name + description + key-sorted input_schema) per
 * (tenant, tool) and fires AFT-TOOL-DRIFT-001 when it changes. Drift that
 * introduces a sensitive-named field (`*_override`, `admin`, …) escalates from
 * Warn to Block. Reuses the in-memory DashMap pattern — no new infra.
 *
 * Eval design (structural — full inline behavior is in Rust unit tests):
 * - module exists, registers AFT-TOOL-DRIFT-001, wired into PredictiveLayer
 * - fingerprints the full definition (description + input_schema)
 * - sensitive-field escalation is present
 * - production code holds no unwrap()
 *
 * Linked: PP-PR-TOOLDRIFT, AFT-TOOL-DRIFT-001, ADR-024 §1 item 2
 */
const MODULE = "../../crates/gateway/src/predictive/tool_definition_drift.rs";

async function read(rel: string): Promise<string> {
  const fs = await import("node:fs");
  const path = await import("node:path");
  return fs.readFileSync(path.resolve(__dirname, rel), "utf8");
}

describe("PP-PR-TOOLDRIFT: silent tool-definition drift caught", () => {
  it("tool_definition_drift module exists", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    expect(fs.existsSync(path.resolve(__dirname, MODULE))).toBe(true);
  });

  it("registers AFT-TOOL-DRIFT-001", async () => {
    expect(await read(MODULE)).toContain("AFT-TOOL-DRIFT-001");
  });

  it("is wired into PredictiveLayer", async () => {
    const content = await read("../../crates/gateway/src/predictive/mod.rs");
    expect(content).toContain("ToolDefinitionDrift");
  });

  it("fingerprints the full definition, not just the tool name", async () => {
    const content = await read(MODULE);
    expect(content).toContain("description");
    expect(content).toContain("input_schema");
    expect(content).toContain("definition_hash");
  });

  it("escalates a sensitive new field to Block", async () => {
    const content = await read(MODULE);
    expect(content).toContain("SENSITIVE_NEW_FIELD_PATTERNS");
    expect(content).toContain("override");
    expect(content).toContain("introduces_sensitive_field");
  });

  it("emits the tool.definition_drift telemetry target", async () => {
    expect(await read(MODULE)).toContain("tool.definition_drift");
  });

  it("production code contains no unwrap() calls", async () => {
    const content = await read(MODULE);
    const testStart = content.indexOf("mod tests");
    const prod = testStart >= 0 ? content.slice(0, testStart) : content;
    const hasUnwrap = prod
      .split("\n")
      .filter((l) => !l.trim().startsWith("//"))
      .some((l) => l.includes(".unwrap()"));
    expect(hasUnwrap).toBe(false);
  });

  it.skip("inline: a tool's schema mutating mid-session fires Warn (integration)", () => {
    // Full: declare transfer_money(amount); re-declare with recipient_override
    // through the gateway; assert span tracelane.aft_id="AFT-TOOL-DRIFT-001".
  });
});

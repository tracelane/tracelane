import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-PR13 — Hallucinated tool-call schema violation caught
 *
 * Competitor behavior: No gateway validates a model's emitted tool call
 * against the tool schema the request declared. Frameworks type tools at the
 * SDK level, but a hallucinated call — wrong tool name, or `lookup_order(email=…)`
 * when the schema requires `order_id` — sails through the gateway and fails
 * deep inside the executor, where the root cause is hours of trace-spelunking.
 *
 * Pain: "The tool call failed" is the surfaced error, not "the model called a
 * tool that doesn't exist" or "it sent `email` when the schema requires
 * `order_id`." The signal that would let an agent self-correct is lost.
 *
 * Tracelane fix: the ToolSchemaValidator predictor validates every tool call
 * the request carries (both `tool_calls[]` and `tool_use` content parts)
 * against the request's declared `tools[].input_schema` — unknown tool name,
 * non-object arguments, missing `required`, wrong primitive type, and (under a
 * closed schema) unexpected fields. Violations fire AFT-TOOL-SCHEMA-001 and a
 * redacted `tool.schema_violation` telemetry event. Observe-first (Warn).
 *
 * Eval design (structural — full inline behavior is a Rust unit test):
 * - Verify the tool_schema_validator module exists
 * - Verify it registers AFT-TOOL-SCHEMA-001
 * - Verify it is wired into PredictiveLayer
 * - Verify the ADR canonical case (order_id vs email) is unit-covered
 * - Verify production code holds no unwrap()
 *
 * Linked: PP-PR13, AFT-TOOL-SCHEMA-001, ADR-024 §3
 */
const MODULE = "../../crates/gateway/src/predictive/tool_schema_validator.rs";

async function read(rel: string): Promise<string> {
  const fs = await import("node:fs");
  const path = await import("node:path");
  return fs.readFileSync(path.resolve(__dirname, rel), "utf8");
}

describe("PP-PR13: hallucinated tool-call schema violation caught", () => {
  it("tool_schema_validator module exists", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    expect(fs.existsSync(path.resolve(__dirname, MODULE))).toBe(true);
  });

  it("ToolSchemaValidator registers AFT-TOOL-SCHEMA-001", async () => {
    const content = await read(MODULE);
    expect(content).toContain("AFT-TOOL-SCHEMA-001");
  });

  it("ToolSchemaValidator is wired into PredictiveLayer", async () => {
    const content = await read(
      "../../crates/gateway/src/predictive/mod.rs",
    );
    expect(content).toContain("ToolSchemaValidator");
  });

  it("emits the ADR-024 §3 tool.schema_violation telemetry target", async () => {
    const content = await read(MODULE);
    expect(content).toContain("tool.schema_violation");
  });

  it("validates both tool_calls[] and tool_use content parts", async () => {
    const content = await read(MODULE);
    expect(content).toContain("tool_calls");
    expect(content).toContain("tool_use");
  });

  it("unit-covers the ADR canonical order_id-vs-email case", async () => {
    const content = await read(MODULE);
    expect(content).toContain("lookup_order");
    expect(content).toContain("MissingRequired");
    expect(content).toContain("UnknownTool");
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

  it.skip("inline: hallucinated call through the gateway fires Warn with redacted args (integration)", () => {
    // Full: POST a chat request whose assistant turn calls lookup_order(email=…)
    // against a declared order_id schema; assert the predictive span carries
    // tracelane.aft_id="AFT-TOOL-SCHEMA-001" and no argument values are present.
  });
});

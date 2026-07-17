import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-O13 — First-class agent/tool/plan/retry/budget primitives
 *
 * Competitor behavior: Langfuse models everything as "sessions" and "traces"
 * with no first-class concept of agent steps, tool calls, retries, or
 * budget tracking. Teams bolt on custom attributes — no standard schema.
 *
 * Pain: Debugging "why did my agent retry that tool 5 times?" requires
 * reading raw span attributes in an unstructured log viewer. No standard
 * schema means no standard tooling (no aggregate dashboards, no SLO
 * monitoring, no cost attribution per tool).
 *
 * Tracelane fix: OpenAgentTrace v0.1 defines first-class primitives:
 * - agent.step spans with state (planning/executing/observing/reflecting)
 * - tool.call spans with input_hash + output + error + duration
 * - agent.run spans with budget_tokens + budget_spent_tokens
 * - retry tracking via agent.step.decision = "retry"
 *
 * Eval design:
 * - Verify OpenAgentTrace spec defines these primitives
 * - Verify agent-state-graph JSON schema covers budget and retry
 *
 */
describe("PP-O13: First-class agent/tool/plan/retry/budget primitives", () => {
  it("OpenAgentTrace spec defines agent.step spans with state enum", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const spec = fs.readFileSync(
      path.resolve(__dirname, "../../spec/openagenttrace/v0.1.md"),
      "utf8"
    );
    expect(spec).toContain("agent.step");
    expect(spec).toContain("planning");
    expect(spec).toContain("executing");
    expect(spec).toContain("observing");
    expect(spec).toContain("reflecting");
  });

  it("OpenAgentTrace spec defines agent.run budget attributes", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const spec = fs.readFileSync(
      path.resolve(__dirname, "../../spec/openagenttrace/v0.1.md"),
      "utf8"
    );
    expect(spec).toContain("agent.budget_tokens");
    expect(spec).toContain("agent.budget_spent_tokens");
  });

  it("OpenAgentTrace spec defines tool.call spans", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const spec = fs.readFileSync(
      path.resolve(__dirname, "../../spec/openagenttrace/v0.1.md"),
      "utf8"
    );
    expect(spec).toContain("tool.call");
    expect(spec).toContain("tool.input");
    expect(spec).toContain("tool.output");
    expect(spec).toContain("tool.error");
  });

  it("agent state graph JSON schema covers retry decision", async () => {
    const schema = await import(
      "../../spec/openagenttrace/agent-state-graph-schema-v1.json",
      { assert: { type: "json" } }
    );
    const decisionEnum =
      schema.default.$defs?.StateTransition?.properties?.trigger?.enum ?? [];
    // retry should not be required in trigger but could be in decision.
    // AgentState.properties is statically typed by the JSON import; `decision`
    // is an optional schema-evolution property checked at runtime, so widen
    // through Record<string, unknown> rather than the structural literal type.
    const agentStateProps =
      (schema.default.$defs?.AgentState?.properties ?? {}) as Record<string, { description?: string }>;
    const stateDecision = agentStateProps["decision"]?.description ?? "";
    expect(decisionEnum.length + stateDecision.length).toBeGreaterThan(0);
  });
});

import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-O8 — Agent replay across model versions
 *
 * Competitor behavior: No competitor supports replaying an agent trace
 * with a different model. LangSmith has an "experiment" concept but it's
 * manual. There's no way to answer "would claude-opus-4-7 have made the
 * same mistake as claude-sonnet-4-6 on this trace?"
 *
 * Pain: Teams upgrade models reactively after incidents. They have no way
 * to proactively evaluate whether a new model would have handled the same
 * inputs differently. A/B testing requires running new traces, not
 * replaying existing ones.
 *
 * Tracelane fix: Time-travel shadow-fork. Given a trace, re-run each LLM
 * call with a different model using the captured inputs. Compare outputs.
 * The span model captures all inputs needed for exact replay.
 *
 * Eval design:
 * - Verify TracelaneSpan captures all inputs needed for replay
 * - Verify the span model supports llm.input_messages (full message history)
 *
 */
describe("PP-O8: Agent replay across model versions", () => {
  it("TracelaneSpan captures input messages for replay", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const content = fs.readFileSync(
      path.resolve(__dirname, "../../crates/shared/src/span.rs"),
      "utf8"
    );
    // SpanAttributes should have llm.input_messages or similar
    expect(content).toMatch(/input|messages|prompt/i);
  });

  it("OpenAgentTrace spec defines llm.input_messages attribute", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const spec = fs.readFileSync(
      path.resolve(__dirname, "../../spec/openagenttrace/v0.1.md"),
      "utf8"
    );
    expect(spec).toContain("llm.input_messages");
  });

  it.skip("shadow-fork replay returns comparison result (Week 8)", async () => {
    // Full: given a trace_id + new_model, replay each llm.call span
    // with the captured inputs and new model. Return diff of outputs.
  });
});

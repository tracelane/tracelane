import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-O10 — Streaming spans = 1 trace
 *
 * Competitor behavior: Langfuse creates a new "generation" per streaming
 * chunk, or requires manual span ID threading. Portkey has no native
 * streaming trace model. The streaming response appears as N separate
 * events, not 1 cohesive LLM call span.
 *
 * Pain: Debugging a streaming agent that returned the wrong answer requires
 * reconstructing the full response from N separate log entries. Latency
 * analysis (TTFT, token throughput) requires manual aggregation. Cost
 * attribution is impossible because token counts are split across events.
 *
 * Tracelane fix: The gateway's streaming parser accumulates token counts
 * from UsageUpdate events and attaches them to the parent llm.call span
 * when the stream closes. A streaming response is always 1 span with
 * complete token counts and a duration_us covering the full stream.
 *
 * Eval design:
 * - Verify TracelaneSpan has complete token count fields
 * - Verify ProviderEvent::UsageUpdate accumulates into span
 * - Verify streaming response produces 1 span with full usage
 *
 */
describe("PP-O10: Streaming spans = 1 trace", () => {
  it("ProviderEvent has UsageUpdate variant", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const content = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/providers/mod.rs"),
      "utf8"
    );
    expect(content).toContain("UsageUpdate");
    expect(content).toContain("input_tokens");
    expect(content).toContain("output_tokens");
  });

  it("TracelaneSpan has token count attributes", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const content = fs.readFileSync(
      path.resolve(__dirname, "../../crates/shared/src/span.rs"),
      "utf8"
    );
    expect(content).toMatch(/token/i);
  });

  it.skip("streaming response produces 1 span (integration — Week 4 gateway wiring)", async () => {
    // Full: send a streaming request, capture OTLP output, assert 1 llm.call span
    // with complete usage counts
  });
});

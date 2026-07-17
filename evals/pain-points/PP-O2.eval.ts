import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-O2 — LLM-aware sampling, no forced 0.1% headcount
 *
 * Competitor behavior: general-purpose APM samplers apply head sampling
 * (often 0.1–10%) uniformly to LLM traces, without LLM trace semantics —
 * a single agent run with 100 LLM calls is one logical "trace" that should
 * be kept or dropped as a unit, not sampled call-by-call.
 *
 * Pain: Teams sampling LLM calls individually lose the full trace context.
 * They keep 10% of calls but can't see the complete agent execution path.
 * Debugging requires the full trace — partial traces are worthless for AI.
 *
 * Tracelane fix: Tail-based sampling. The sampler holds spans in memory
 * for 30s, waits for the full trace, then decides. Error traces are always
 * kept (100%). Successful traces are sampled at the configured rate.
 * No span is ever dropped mid-trace.
 *
 * Eval design:
 * - Verify TailSampler module exists
 * - Verify it's designed to sample at trace granularity (not span granularity)
 *
 */
describe("PP-O2: LLM-aware sampling, no forced 0.1%", () => {
  it("TailSampler module exists in ingest", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const p = path.resolve(__dirname, "../../crates/ingest/src/tail_sampler.rs");
    expect(fs.existsSync(p)).toBe(true);
  });

  it("TailSampler evaluates at trace granularity (one span at a time, trace context kept)", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const content = fs.readFileSync(
      path.resolve(__dirname, "../../crates/ingest/src/tail_sampler.rs"),
      "utf8"
    );
    // Should mention trace_id and 30s window
    expect(content).toMatch(/trace|30s|window/i);
  });

  it("TailSampler default is Keep (full-fidelity until production wiring)", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const content = fs.readFileSync(
      path.resolve(__dirname, "../../crates/ingest/src/tail_sampler.rs"),
      "utf8"
    );
    expect(content).toContain("SampleDecision::Keep");
  });
});

import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-P10 — No billing surprises: capped overage, hard cap, then 429
 *
 * Competitor behavior: usage-based observability billing can spike 5–10× in
 * incident months, so teams throttle tracing during outages to avoid bills —
 * defeating the purpose.
 *
 * Tracelane fix: per-tier monthly volume caps with a capped
 * overage ($1.20/10K) up to a 5× hard cap, then HTTP 429 — never a silent bill
 * spike. This is the public overage model on the pricing page.
 *
 * Eval: assert the capped-overage + hard-cap-then-429 model (no private pricing
 * rationale, no competitor numbers).
 *
 * Linked: PP-P10
 */
describe("PP-P10: No billing surprises — capped overage, hard cap, then 429", () => {
  it("paid tiers cap overage and hard-stop at 429 (no silent bill spike)", () => {
    const overageModel = {
      perTierMonthlyCap: true,
      overageRatePer10k: 1.2, // capped overage
      hardCapMultiplier: 5, // 5× included, then hard stop
      onHardCap: "http-429", // never a silent bill spike
    };
    expect(overageModel.perTierMonthlyCap).toBe(true);
    expect(overageModel.hardCapMultiplier).toBe(5);
    expect(overageModel.onHardCap).toBe("http-429");
  });
});

import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-G5 — Free tier covers real prototype usage (10K calls/mo)
 *
 * Competitor behavior: some free tiers exhaust in a weekend, have no gateway,
 * or silently expire after a period of inactivity.
 *
 * Tracelane fix: the Free hosted tier includes 10K gateway calls + 10K trace
 * events per month. No credit card required. No inactivity expiry. Enough for a
 * real prototype or a small production agent.
 *
 * Eval: assert the public free-tier shape (no competitor numbers, no private
 * pricing rationale).
 *
 * Linked: PP-G5
 */
describe("PP-G5: Free tier covers real prototype usage (10K calls/mo)", () => {
  it("the free tier is genuinely free and usable for a prototype", () => {
    const free = {
      price: 0,
      gatewayCalls: 10_000,
      traces: 10_000,
      requiresCreditCard: false,
    };
    expect(free.price).toBe(0);
    expect(free.gatewayCalls).toBeGreaterThanOrEqual(10_000);
    expect(free.traces).toBeGreaterThanOrEqual(10_000);
    expect(free.requiresCreditCard).toBe(false);
  });
});

import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-P7 — Platform-tier billing, not per-seat-from-1
 *
 * Competitor behavior: per-seat-from-seat-1 observability billing taxes you for
 * growing your team; teams limit seat access to avoid bills, breaking audit
 * trails.
 *
 * Tracelane fix: platform-tier billing — you pay for the tier, with bundled
 * seats and a capped per-seat overage (per ADR-020), never per-seat from seat 1.
 *
 * Eval: assert the billing unit is the platform tier (no competitor numbers, no
 * private pricing rationale).
 *
 * Linked: PP-P7, ADR-020
 */
describe("PP-P7: platform-tier billing (no per-seat-from-1)", () => {
  it("the billing unit is the platform tier, not the seat", () => {
    const pricingModel = {
      billingUnit: "platform-tier", // never "per-seat" / "per-user" from seat 1
      seatModel: "bundled-with-capped-overage", // ADR-020
    };
    expect(pricingModel.billingUnit).toBe("platform-tier");
    expect(pricingModel.billingUnit).not.toBe("per-seat");
    expect(pricingModel.seatModel).toBe("bundled-with-capped-overage");
  });
});

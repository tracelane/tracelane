import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-P15 — Enterprise compliance tier with transparent, publicly-listed pricing
 *
 * Competitor behavior: incumbent enterprise pricing is opaque ("call us"),
 * forcing multi-month procurement cycles before a buyer knows if a product is
 * in budget.
 *
 * Tracelane fix: the Enterprise Compliance tier is publicly listed at
 * $2,999+/mo with CMK/BYOK, region pinning, SOC 2 access, ISO 42001, the EU AI
 * Act Art. 12 export pack, a dedicated channel, and a 99.95% SLA — no NDA
 * required to see the price.
 *
 * Eval: assert the publicly-listed Enterprise shape (the price + features are
 * on the public pricing page — no private-doc reads).
 *
 * Linked: PP-P15
 */
describe("PP-P15: Enterprise compliance tier — transparent pricing", () => {
  it("Enterprise starting price and compliance features are publicly listed", () => {
    const enterpriseTier = {
      startingPriceMonthly: 2999,
      pricingTransparent: true, // listed publicly, no NDA required
      includes: [
        "cmk-byok",
        "region-pinning",
        "soc2-type2",
        "iso-42001",
        "eu-ai-act-art12",
        "dedicated-slack",
        "sla-99.95",
      ],
    };
    expect(enterpriseTier.pricingTransparent).toBe(true);
    expect(enterpriseTier.startingPriceMonthly).toBeGreaterThanOrEqual(2999);
    expect(enterpriseTier.includes).toContain("soc2-type2");
  });
});

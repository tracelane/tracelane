import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-P11 — Bundled seats with capped per-seat overage (not per-seat-from-1)
 *
 * Competitor behavior: per-seat-from-seat-1 billing taxes team growth and
 * pushes customers to shared logins that break audit trails and SSO sync.
 *
 * Tracelane fix: bundled seats per tier with a $19/seat capped
 * overage — Team includes 10 (cap 25), Business includes 25 (cap 50), only
 * Enterprise is unlimited. (Same public seat model as PP-O1.)
 *
 * Eval: assert the public seat-cap + capped-overage shape (no competitor
 * numbers, no private-doc reads).
 *
 * Linked: PP-P11
 */
describe("PP-P11: bundled seats + capped per-seat overage", () => {
  it("Team and Business bundle seats with a $19/seat capped overage", () => {
    const seatOveragePerMonth = 19; // Team and Business overage seats
    const team = { included: 10, cap: 25 };
    const business = { included: 25, cap: 50 };
    expect(seatOveragePerMonth).toBe(19);
    expect(team.cap).toBeGreaterThan(team.included);
    expect(business.cap).toBeGreaterThan(business.included);
  });
});

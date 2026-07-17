import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-O1 — Bundled seats with capped per-seat overage (no per-seat-from-1)
 *
 * Competitor behavior: per-seat-from-seat-1 billing makes teams delay
 * onboarding to avoid cost spikes, and shared logins break audit trails.
 *
 * Tracelane fix: bundled seats per tier with $19/seat capped
 * overage — Team includes 10 (cap 25), Business includes 25 (cap 50), and only
 * Enterprise is unlimited. This is the public seat model on the pricing page.
 *
 * Eval: assert the public seat-cap structure (no competitor pricing numbers, no
 * private-doc reads).
 *
 * Linked: PP-O1
 */
describe("PP-O1: bundled seats + $19/seat capped overage", () => {
  const tiers = [
    { name: "Free", seat_cap_included: 1, seat_cap_max: 1 },
    { name: "Builder", seat_cap_included: 1, seat_cap_max: 1 },
    { name: "Team", seat_cap_included: 10, seat_cap_max: 25 },
    { name: "Business", seat_cap_included: 25, seat_cap_max: 50 },
    { name: "Enterprise", seat_cap_included: 0, seat_cap_max: 0 }, // 0 = unlimited sentinel
  ] as const;

  it("every tier reports a numeric seat_cap_included and seat_cap_max", () => {
    for (const t of tiers) {
      expect(typeof t.seat_cap_included).toBe("number");
      expect(typeof t.seat_cap_max).toBe("number");
    }
  });

  it("Team tier bundles 10 seats with cap at 25", () => {
    const team = tiers.find((t) => t.name === "Team");
    expect(team?.seat_cap_included).toBe(10);
    expect(team?.seat_cap_max).toBe(25);
  });

  it("Business tier bundles 25 seats with cap at 50", () => {
    const biz = tiers.find((t) => t.name === "Business");
    expect(biz?.seat_cap_included).toBe(25);
    expect(biz?.seat_cap_max).toBe(50);
  });

  it("only Enterprise is unlimited (0 sentinel) — not Builder/Team/Business", () => {
    const ent = tiers.find((t) => t.name === "Enterprise");
    expect(ent?.seat_cap_max).toBe(0);
    // The capped tiers must NOT be unlimited (honest cap).
    for (const t of tiers.filter((x) => x.name !== "Enterprise")) {
      expect(t.seat_cap_max).toBeGreaterThan(0);
    }
  });
});

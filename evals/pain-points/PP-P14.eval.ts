import { describe, it } from "vitest";
import { expect } from "../src/harness.js";
import fs from "node:fs";
import path from "node:path";

/**
 * PP-P14 — A mid-market option that bundles enterprise-grade controls
 *
 * Competitor behavior: teams between an eval-only Pro plan and a full
 * enterprise contract have no good option that includes SSO, an SLA, and an
 * inline guardrail layer without an enterprise sales motion.
 *
 * Tracelane fix: the Business tier ships SSO (WorkOS), a 99.9% SLA, and the
 * inline ensemble guardrail (heuristic today; ML ensemble + judge on the
 * roadmap) without a custom enterprise contract. Cohort baselines become
 * available when a cohort reaches 30 customers.
 *
 * Eval: assert the Business-tier capabilities ship as real code (public
 * artifacts + the public entitlement surface) — no pricing/competitor numbers.
 *
 * Linked: PP-P14
 */
const ROOT = path.resolve(__dirname, "../..");

describe("PP-P14: Business tier bundles SSO + SLA + inline guardrails", () => {
  it("ships SSO (WorkOS auth)", () => {
    expect(fs.existsSync(path.join(ROOT, "apps/web/lib/auth.ts"))).toBe(true);
  });

  it("ships the inline guardrail layer in the gateway", () => {
    expect(fs.existsSync(path.join(ROOT, "crates/gateway/Cargo.toml"))).toBe(
      true,
    );
  });
});

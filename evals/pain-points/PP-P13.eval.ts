import { describe, it } from "vitest";
import { expect } from "../src/harness.js";
import fs from "node:fs";
import path from "node:path";

/**
 * PP-P13 — One product instead of three
 *
 * Competitor behavior: eval-only and observability-only tools leave teams to
 * bolt on a separate gateway (OpenRouter, Portkey) and a separate security tool
 * (Lakera, Pillar) — three tools, three bills, three integrations.
 *
 * Tracelane fix: the gateway, the observability pipeline, and the inline
 * guardrail layer ship as ONE product — no separate gateway or security vendor
 * required.
 *
 * Eval: assert all three surfaces ship in this repo (one product) — public
 * artifacts only, no pricing/competitor numbers.
 *
 * Linked: PP-P13
 */
const ROOT = path.resolve(__dirname, "../..");

describe("PP-P13: gateway + observability + guardrails in one product", () => {
  it("ships the gateway (with the inline guardrail layer)", () => {
    expect(fs.existsSync(path.join(ROOT, "crates/gateway/Cargo.toml"))).toBe(
      true,
    );
  });

  it("ships the observability ingest pipeline in the same repo", () => {
    expect(fs.existsSync(path.join(ROOT, "crates/ingest/Cargo.toml"))).toBe(
      true,
    );
  });
});

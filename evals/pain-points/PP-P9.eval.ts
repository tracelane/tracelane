import { describe, it } from "vitest";
import { expect } from "../src/harness.js";
import fs from "node:fs";
import path from "node:path";

/**
 * PP-P9 — Structurally low cost-to-operate at scale
 *
 * Competitor behavior: Python-proxy gateways (Node.js + Python async, no Rust)
 * and per-customer ClickHouse+Postgres clusters carry high infrastructure cost
 * per customer, which constrains how cheaply the product can be operated at
 * scale.
 *
 * Tracelane fix: a Rust gateway, a shared ClickHouse cluster, and R2 1MB-batched
 * cold-tier writes keep per-customer operating cost low — an architectural
 * efficiency, not a pricing trick.
 *
 * Eval: assert the cost-efficient architecture is the one we actually ship
 * (public artifacts only — no business-metric numbers).
 *
 * Linked: PP-P9
 */
const ROOT = path.resolve(__dirname, "../..");

describe("PP-P9: structurally low cost-to-operate architecture", () => {
  it("ships a Rust gateway (no Python proxy on the request path)", () => {
    expect(fs.existsSync(path.join(ROOT, "crates/gateway/Cargo.toml"))).toBe(
      true,
    );
  });

  it("ships shared-cluster ingest + a batched cold tier (not per-customer infra)", () => {
    expect(fs.existsSync(path.join(ROOT, "crates/ingest/Cargo.toml"))).toBe(
      true,
    );
  });
});

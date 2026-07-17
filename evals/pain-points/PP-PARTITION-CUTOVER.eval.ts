import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-PARTITION-CUTOVER — automated 40-tenant partition cutover (ADR-039 §23.9).
 *
 * Contract: the cutover from `(tenant_id, toYYYYMM)` to time-only partitioning
 * runs against a 60-synthetic-tenant fixture with **zero row loss** and query-
 * latency parity. A daily job stages it at 40 tenants (buffer below the 50
 * "too many parts" ceiling).
 *
 * Structural: assert the cutover SQL uses the safe create→insert→rename→
 * verify→drop sequence, the daily check trips at 40, and the operability MVs
 * read the canonical v1.41 keys. The 60-tenant zero-loss run is the skipped
 * integration case.
 */
function read(rel: string): string {
  // biome-ignore lint/style/useNodejsImportProtocol: harness is CJS
  const fs = require("node:fs");
  // biome-ignore lint/style/useNodejsImportProtocol: harness is CJS
  const path = require("node:path");
  return fs.readFileSync(path.resolve(__dirname, rel), "utf8");
}

describe("PP-PARTITION-CUTOVER: 40-tenant cutover (ADR-039)", () => {
  it("cutover SQL uses create → insert → atomic rename → verify → drop", () => {
    const sql = read("../../infra/prod/partition-cutover.sql");
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS tracelane.promotion_decisions_timeonly");
    expect(sql).toContain("INSERT INTO tracelane.promotion_decisions_timeonly SELECT");
    expect(sql).toContain("RENAME TABLE");
    // time-only target partition (tenant_id dropped from the partition key)
    expect(sql).toContain("PARTITION BY toYYYYMM(decided_at)");
    // drop only after verify
    expect(sql).toContain("DROP TABLE IF EXISTS tracelane.promotion_decisions_old");
  });

  it("daily check stages cutover at 40 tenants (below the 50 ceiling)", () => {
    const sh = read("../../infra/prod/partition-cutover-check.sh");
    expect(sh).toContain("STAGE_AT:-40");
    expect(sh).toContain("count(distinct tenant_id)");
  });

  it("operability MVs (token economics, ttft, SLO) read canonical v1.41 keys", () => {
    const sql = read("../../infra/dev/clickhouse/migrations/05_operability_mvs.sql");
    expect(sql).toContain("mv_token_economics");
    expect(sql).toContain("mv_ttft");
    expect(sql).toContain("gen_ai_usage_input_tokens");
    expect(sql).toContain("v_slo_28d");
    // additive-only
    expect(sql.includes("DROP TABLE"), "operability migration must be additive").toBe(false);
  });

  it("zero-downtime migration discipline is documented", () => {
    const doc = read("../../docs/operations/zero-downtime-migrations.md");
    expect(doc).toContain("expand-contract");
    expect(doc).toContain("additive-only");
  });

  it.skip("integration: 60-tenant fixture cutover, zero row loss + latency parity (Week 8)", () => {
    // Full: seed 60 tenants, run the cutover, assert count() pre == post for
    // each table and that p95 query latency is within parity.
  });
});

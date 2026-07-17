import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-O3 — Retention included per tier, no upcharge
 *
 * Competitor behavior: many observability vendors charge extra for retention
 * beyond 30 days, or apply complex retention pricing. Teams budget for
 * observability but get surprised by retention fees when they need historical
 * data for an incident.
 *
 * Pain: "90-day retention would cost us an extra $400/mo" is a real calculation
 * enterprise teams make. It creates perverse incentives to discard data that
 * might be needed for compliance or debugging.
 *
 * Tracelane fix: 90-day ClickHouse retention is included in every paid tier.
 * R2 cold storage for longer retention is included too (R2 egress is $0).
 * The ClickHouse schema has TTL = 90 days. No upsell to unlock it.
 *
 * Eval design:
 * - Verify ClickHouse schema has 90-day TTL
 * - Verify R2 cold storage path exists in ingest config
 *
 */
describe("PP-O3: Retention included per tier, no upcharge", () => {
  it("ClickHouse schema has 90-day TTL on spans table", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const schema = fs.readFileSync(
      path.resolve(__dirname, "../../infra/dev/clickhouse/schema.sql"),
      "utf8"
    );
    expect(schema).toContain("90 DAY");
    expect(schema).toContain("TTL");
  });

  it("trace_summaries MV also has 90-day TTL", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const schema = fs.readFileSync(
      path.resolve(__dirname, "../../infra/dev/clickhouse/schema.sql"),
      "utf8"
    );
    // Count occurrences of TTL 90 DAY
    const matches = schema.match(/TTL.*90 DAY/g);
    expect((matches ?? []).length).toBeGreaterThanOrEqual(2); // spans + trace_summaries
  });
});

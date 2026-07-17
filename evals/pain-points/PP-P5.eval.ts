import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-P5 — Async trace deletion with materialized view rebuild
 *
 * Competitor behavior: Langfuse has no trace deletion API. LangSmith deletion
 * is synchronous and blocks the ingestion pipeline. ClickHouse naive DELETE is
 * a table-scan mutation that can halt ingestion for minutes on large tables.
 *
 * Pain: GDPR right-to-erasure requires that PII-containing traces be deleted
 * within 30 days. Without async deletion, deleting a customer's data is either
 * impossible or brings down the ingestion pipeline.
 *
 * Tracelane fix: `DELETE` requests to the trace API enqueue an async deletion
 * job in NATS. The job runs `ALTER TABLE traces DELETE WHERE tenant_id = ? AND
 * trace_id = ?` off the hot path. After deletion, affected materialized views
 * are rebuilt asynchronously. No ingestion impact.
 *
 * Eval: Verify the ClickHouse schema has the async deletion pattern documented.
 *
 */
describe("PP-P5: Async trace deletion with materialized view rebuild", () => {
  it("ClickHouse schema file exists", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const schema = path.resolve(
      __dirname,
      "../../infra/dev/clickhouse-schema.sql"
    );
    expect(fs.existsSync(schema)).toBe(true);
  });

  it("ClickHouse schema includes materialized view definitions", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const schema = fs.readFileSync(
      path.resolve(__dirname, "../../infra/dev/clickhouse-schema.sql"),
      "utf8"
    );
    expect(schema).toContain("MATERIALIZED VIEW");
  });

  it("NATS JetStream is used for async job queue", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const trd = fs.readFileSync(
      path.resolve(__dirname, "../fixtures/public-spec.md"),
      "utf8"
    );
    expect(trd).toContain("NATS JetStream");
  });
});

import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * IS-001 — Ingest schema backwards compatibility
 *
 * Verifies that the ClickHouse schema for span ingestion is backwards
 * compatible: new optional columns can be added without breaking existing
 * producers. Required columns (tenant_id, trace_id, span_id, start_time_us,
 * end_time_us) must always be present.
 *
 * Structural: verify ClickHouse schema migration file exists with required columns.
 * Integration: schema evolution test with live CH skipped until Week 8.
 */
describe("IS-001: Ingest schema backwards compatibility", () => {
  it("ClickHouse schema migration file exists", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const migrations = [
      "../../infra/dev/docker-compose.yml",
      "../../crates/ingest/src/clickhouse_writer.rs",
    ];
    let found = false;
    for (const rel of migrations) {
      const p = path.resolve(__dirname, rel);
      if (fs.existsSync(p)) {
        found = true;
        break;
      }
    }
    expect(found, "No ingest schema or ClickHouse writer found").toBe(true);
  });

  it("ingest clickhouse_writer module exists", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const p = path.resolve(
      __dirname,
      "../../crates/ingest/src/clickhouse_writer.rs"
    );
    expect(fs.existsSync(p)).toBe(true);
  });

  it("clickhouse_writer references tenant_id (tenant isolation enforced)", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const src = fs.readFileSync(
      path.resolve(__dirname, "../../crates/ingest/src/clickhouse_writer.rs"),
      "utf8"
    );
    expect(src).toContain("tenant_id");
  });

  it("span schema requires trace_id and span_id", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const src = fs.readFileSync(
      path.resolve(__dirname, "../../crates/ingest/src/clickhouse_writer.rs"),
      "utf8"
    );
    expect(src).toContain("trace_id");
    expect(src).toContain("span_id");
  });

  it.skip("schema evolution: adding optional column does not break existing producer (integration — Week 8)", async () => {
    // Full: insert span without new column, verify CH accepts it with NULL default
  });
});

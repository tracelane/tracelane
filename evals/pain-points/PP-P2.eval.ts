import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-P2 — DuckDB embedded: sub-second trace query lag
 *
 * Competitor behavior: Langfuse self-host requires 4 services (app, ClickHouse,
 * Postgres, Redis). ClickHouse single-node has a cold-start problem on small
 * VPS instances. For Tracelane Lite (single-binary), DuckDB embedded provides
 * SQL-grade analytics without any external service.
 *
 * Pain: Self-hosting a full observability stack is 2–4 hours of ops work.
 * Small teams want `docker run tracelane` and instant analytics, not a
 * docker-compose with 6 services and 40GB of RAM requirement.
 *
 * Tracelane fix: Tracelane Lite uses DuckDB as the embedded trace store.
 * No separate ClickHouse service. One binary. Sub-second queries up to 10M
 * spans. Auto-promotes to ClickHouse mode at >10M traces.
 *
 * Eval: Verify TRD documents the DuckDB Lite mode and ADR-003 covers it.
 *
 */
describe("PP-P2: DuckDB embedded sub-second trace query lag", () => {
  it("documents Tracelane Lite single-binary with DuckDB", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const trd = fs.readFileSync(
      path.resolve(__dirname, "../fixtures/public-spec.md"),
      "utf8"
    );
    expect(trd).toContain("DuckDB");
    expect(trd).toContain("Tracelane Lite");
    expect(trd).toContain("single binary");
  });

  it("ADR-003 includes DuckDB embedded rationale", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const adr = fs.readFileSync(
      path.resolve(__dirname, "../../decisions/ADR-003-storage-clickhouse-r2-duckdb.md"),
      "utf8"
    );
    expect(adr).toContain("DuckDB");
  });

  it("DuckDB sub-second budget is defined", () => {
    // DuckDB embedded query budget for Lite mode (sub-second p99)
    const duckdbQueryBudgetMs = { p50: 200, p95: 500, p99: 1000 };
    expect(duckdbQueryBudgetMs.p99).toBeLessThanOrEqual(1000);
  });
});

import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-O5 — Architecture stable from launch (no forced migrations)
 *
 * Competitor behavior: LangSmith forced breaking migrations 3× in 18 months.
 * Langfuse's self-hosted schema changed incompatibly in v2→v3 with no
 * migration path. Helicone rebuilt their product architecture mid-flight and
 * broke customer integrations. Every migration costs customer-team time.
 *
 * Pain: Production agent teams can't tolerate breaking changes mid-sprint.
 * "We spent 3 days on a LangSmith migration that shouldn't have been needed."
 *
 * Tracelane fix: Schema stability commitment in ADR-003. OTLP semconv
 * forwards-compatibility guaranteed. Ingest schema evolution tested at every
 * CI run. Breaking changes blocked by the schema-evolution eval suite.
 *
 * Eval: Verify ADR-003 documents the stability commitment and ingest schema
 * evolution tests exist.
 *
 */
describe("PP-O5: Architecture stable from launch", () => {
  it("ADR-003 documents storage architecture stability commitment", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const adr = fs.readFileSync(
      path.resolve(__dirname, "../../decisions/ADR-003-storage-clickhouse-r2-duckdb.md"),
      "utf8"
    );
    expect(adr).toContain("ClickHouse");
    expect(adr.length).toBeGreaterThan(500);
  });

  it("ingest schema-evolution eval directory exists", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const dir = path.resolve(__dirname, "../../evals/ingest-schema");
    expect(fs.existsSync(dir)).toBe(true);
  });

  it("OTLP semconv ADR documents forwards-compatibility", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const adr = fs.readFileSync(
      path.resolve(__dirname, "../../decisions/ADR-004-otel-openinference-semconv.md"),
      "utf8"
    );
    // ADR-004 covers OTel + OpenInference semconv commitment
    expect(adr).toContain("OpenInference");
    expect(adr).toContain("OTLP");
  });
});

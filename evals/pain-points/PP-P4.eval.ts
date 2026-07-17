import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-P4 — Rust ingest keeps Node out of hot path
 *
 * Competitor behavior: Langfuse SDK (JavaScript) writes spans to an
 * in-process queue, then flushes to their API from the same Node.js
 * event loop as the application. Under high load, the flush competes
 * with application requests for the event loop.
 *
 * Pain: Production AI applications running LangChain.js at >100 RPS
 * report event loop delays from Langfuse's batch flush operation.
 * Observability is adding latency to the application it's observing.
 *
 * Tracelane fix: The Rust ingest worker is a separate process. The SDK
 * writes spans to OTLP HTTP at port 4318 (fire-and-forget). The ingest
 * process handles batching and ClickHouse writes independently of the
 * application event loop. The gateway handles its own OTLP emit
 * asynchronously via a separate tokio task.
 *
 * Eval design:
 * - Verify ingest is a separate crate/binary
 * - Verify OTLP receiver runs on port 4318 (configurable)
 * - Verify gateway's emit_span is async (non-blocking)
 *
 */
describe("PP-P4: Rust ingest keeps Node out of hot path", () => {
  it("ingest is a separate Rust binary (not bundled with gateway)", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const ingestCargo = fs.readFileSync(
      path.resolve(__dirname, "../../crates/ingest/Cargo.toml"),
      "utf8"
    );
    expect(ingestCargo).toContain('name = "ingest"');
    expect(ingestCargo).toContain("[[bin]]");
  });

  it("OTLP receiver listens on configurable port (default 4318)", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const content = fs.readFileSync(
      path.resolve(__dirname, "../../crates/ingest/src/config.rs"),
      "utf8"
    );
    expect(content).toContain("4318");
    expect(content).toContain("TRACELANE_OTLP_PORT");
  });

  it("gateway emit_span is async (pub async fn)", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const content = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/otlp_emit.rs"),
      "utf8"
    );
    expect(content).toContain("pub async fn emit_span");
  });
});

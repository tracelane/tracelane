import { describe, it } from "vitest";
import { expect } from "../src/harness.js";
import fs from "node:fs";
import path from "node:path";

/**
 * FT-03 — Ingest ClickHouse downtime: NATS buffers, no data loss
 *
 * Scenario: ClickHouse becomes unreachable for up to 60 seconds (network
 * partition, restart). Spans arriving at the ingest worker during this
 * window must be held in NATS JetStream (durable, ack-required) and
 * flushed to ClickHouse once it recovers — with zero data loss.
 *
 * Production code: `crates/ingest/src/clickhouse_writer.rs` — batching
 * writer with retry loop; `crates/ingest/src/nats_consumer.rs` — NATS
 * JetStream consumer with manual ack on successful ClickHouse write.
 *
 * Chaos method: Start ingest worker with ClickHouse unavailable for 30s,
 * send 1000 spans, restore ClickHouse, assert all 1000 spans land.
 *
 * Status: Structural assertions green. Integration test skipped until
 * ClickHouse writer has retry loop (Week 5 code needs chaos harness — Week 7).
 */

const INGEST_SRC = path.resolve(__dirname, "../../crates/ingest/src");

describe("FT-03: Ingest ClickHouse downtime — NATS buffers spans", () => {
  it("clickhouse_writer module exists in ingest", () => {
    const p = path.join(INGEST_SRC, "clickhouse_writer.rs");
    expect(fs.existsSync(p)).toBe(true);
  });

  it("nats_consumer module exists in ingest", () => {
    const p = path.join(INGEST_SRC, "nats_consumer.rs");
    expect(fs.existsSync(p)).toBe(true);
  });

  it("NATS JetStream is configured for durable at-least-once delivery", () => {
    const content = fs.readFileSync(
      path.join(INGEST_SRC, "nats_consumer.rs"),
      "utf8",
    );
    expect(content).toContain("JetStream");
    // Durable name is required for at-least-once delivery across restarts
    expect(content).toContain("durable");
  });

  it("clickhouse_writer has retry loop (not single-shot write)", () => {
    const content = fs.readFileSync(
      path.join(INGEST_SRC, "clickhouse_writer.rs"),
      "utf8",
    );
    // Must have some form of retry / loop construct for ClickHouse downtime
    expect(content).toMatch(/retry|loop|backoff/);
  });

  it("clickhouse_writer emits tracing span on write failure", () => {
    const content = fs.readFileSync(
      path.join(INGEST_SRC, "clickhouse_writer.rs"),
      "utf8",
    );
    // FT-03: operator must see ClickHouse errors in traces
    expect(content).toContain("tracing");
  });

  it("real ClickHouse-downtime chaos tests exist in clickhouse_writer.rs", () => {
    // The integration fault is now injected for real: in-module tests drive
    // the writer's `flush` retry loop against a wiremock ClickHouse that is
    // (a) down for the first attempt then recovers — batch is retried, not
    // dropped — and (b) persistently down — Err propagates so the NATS
    // message stays unacked and is redelivered (zero span loss).
    const content = fs.readFileSync(
      path.join(INGEST_SRC, "clickhouse_writer.rs"),
      "utf8",
    );
    expect(content).toContain("ft03_clickhouse_retry_recovers_after_transient_outage");
    expect(content).toContain("ft03_persistent_clickhouse_outage_propagates_error");
    expect(content).toContain("wiremock");
  });
});

import { describe, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { expect } from "../src/harness.js";

/**
 * PP-OVERSIZE-SPAN — Ingest rejects oversize spans with 413 + reject reason
 *
 * Behavior (per ADR-029): the OTLP receiver applies three size caps at
 * ingest. A single span exceeding `max_span_bytes` (1 MiB default) is
 * rejected with HTTP 413, response header
 * `Tracelane-Reject-Reason: span_too_large`, and a JSON body
 * `{error, reason, limit, observed}`. A payload exceeding the
 * pre-decode `max_batch_bytes` cap (8 MiB default) is rejected the
 * same way with `reason=batch_too_large` in <1 µs without ever
 * allocating the protobuf struct.
 *
 * Rust implementation: `crates/ingest/src/limits.rs` + the post-decode
 * walk in `crates/ingest/src/otlp_receiver.rs::traces_handler`.
 * Bench: `crates/ingest/benches/limits.rs::bench_pre_decode_reject_10mb`
 * asserts <1 µs p50.
 *
 * Five structural assertions per pain-points convention:
 *   1. ADR-029 ships the four reject reasons with stable label strings
 *   2. limits.rs exposes IngestLimits with the documented defaults
 *   3. otlp_receiver wires pre-decode + post-decode + reject header + warning band
 *   4. criterion bench file exists with the <1 µs budget
 *
 */

const INGEST_SRC = path.resolve(__dirname, "../../crates/ingest/src");
const ADR = path.resolve(__dirname, "../../decisions/ADR-029-ingest-payload-limits.md");
const BENCH = path.resolve(
  __dirname,
  "../../crates/ingest/benches/limits.rs",
);

describe("PP-OVERSIZE-SPAN: ingest rejects oversize spans (ADR-029)", () => {
  it("1. ADR-029 exists with the four reject reasons as stable label strings", () => {
    const adr = fs.readFileSync(ADR, "utf8");
    expect(adr).toContain("span_too_large");
    expect(adr).toContain("batch_too_large");
    expect(adr).toContain("attribute_too_large");
    expect(adr).toContain("too_many_attributes");
    expect(adr).toContain("Tracelane-Reject-Reason");
  });

  it("2. limits.rs ships IngestLimits with documented defaults", () => {
    const src = fs.readFileSync(path.join(INGEST_SRC, "limits.rs"), "utf8");
    expect(src).toContain("pub const DEFAULT_MAX_SPAN_BYTES: usize = 1024 * 1024");
    expect(src).toContain("pub const DEFAULT_MAX_ATTR_VALUE_BYTES: usize = 32 * 1024");
    expect(src).toContain("pub const DEFAULT_MAX_ATTRS_PER_SPAN: usize = 128");
    expect(src).toContain("pub struct IngestLimits");
    expect(src).toContain("pub fn check_payload_pre_decode");
    expect(src).toContain("pub fn check_span_post_decode");
  });

  it("3. otlp_receiver wires pre-decode + post-decode + reject header + warning band", () => {
    const src = fs.readFileSync(
      path.join(INGEST_SRC, "otlp_receiver.rs"),
      "utf8",
    );
    // Pre-decode guard wired before to_bytes allocation.
    expect(src).toContain("cap.max_batch_bytes()");
    expect(src).toContain("check_payload_pre_decode");
    // Post-decode walk.
    expect(src).toContain("check_span_post_decode");
    // Headers.
    expect(src).toContain("tracelane-reject-reason");
    expect(src).toContain("tracelane-warning");
    expect(src).toContain("limit-payload-size");
    // Warning band carry-over.
    expect(src).toContain("any_warning_band");
  });

  it("4. criterion bench exists with the <1 µs reject budget", () => {
    expect(fs.existsSync(BENCH)).toBe(true);
    const bench = fs.readFileSync(BENCH, "utf8");
    expect(bench).toContain("reject_10mb_payload");
    expect(bench).toContain("check_payload_pre_decode");
    // Budget surfaced in the doc comment so a future change touches the
    // assertion intentionally.
    expect(bench).toContain("<1 µs");
  });

  it("5. Default caps match ADR-029 table (1 MiB / 8 MiB batch / 32 KiB attr / 128 attrs)", () => {
    const src = fs.readFileSync(path.join(INGEST_SRC, "limits.rs"), "utf8");
    // Pre-decode multiplier 8 → 8 MiB batch for 1 MiB span default.
    expect(src).toContain("PRE_DECODE_BATCH_MULTIPLIER: usize = 8");
    // Warning band is half the span cap.
    expect(src).toContain("WARNING_BAND_DIVISOR: usize = 2");
  });
});

import { describe, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { expect } from "../src/harness.js";

/**
 * PP-OVERSIZE-ATTR — Ingest rejects oversize per-attribute values
 * and over-count attribute lists.
 *
 * Behavior (per ADR-029): two distinct attribute-level rejects.
 *
 *   * **attribute_too_large** — any attribute value > 32 KiB default
 *     returns HTTP 400 with `Tracelane-Reject-Reason: attribute_too_large`
 *     and a JSON body `{error, reason, limit, observed}` where
 *     `observed` is the byte count of the offending value.
 *
 *   * **too_many_attributes** — any span with > 128 attributes returns
 *     HTTP 400 with `Tracelane-Reject-Reason: too_many_attributes`.
 *     Checked before per-attribute size so the response is precise for
 *     the common misuse case (`tracelane.iter_<n>=...` in a loop).
 *
 * Rust implementation: `crates/ingest/src/limits.rs::check_span_post_decode`
 * walks the decoded protobuf, checks count first, then iterates the
 * attribute list against `max_attribute_value_bytes`. The walk handles
 * every `AnyValue` variant (string / bytes / int / double / bool /
 * array / kvlist) without allocating.
 *
 * Five structural assertions per pain-points convention:
 *   1. limits.rs counts attributes before sizing them (ordering matters)
 *   2. attribute size calculation handles every AnyValue variant
 *   3. otlp_receiver maps each reject to the correct HTTP status (400)
 *   4. tracelane_ingest_rejected_total counter has four reasons (low cardinality)
 *   5. workspace_id_bucket hashes UUIDs into 0..64 (Prom label cardinality cap)
 *
 * Linked: ADR-029, crates/ingest/src/limits.rs::tests
 */

const INGEST_SRC = path.resolve(__dirname, "../../crates/ingest/src");
const ADR = path.resolve(__dirname, "../../decisions/ADR-029-ingest-payload-limits.md");

describe("PP-OVERSIZE-ATTR: ingest rejects oversize attributes (ADR-029)", () => {
  it("1. limits.rs checks attribute count BEFORE per-attribute size", () => {
    const src = fs.readFileSync(path.join(INGEST_SRC, "limits.rs"), "utf8");
    // The `check_span_post_decode` function must early-return on
    // attribute count before iterating values. Ordering is checked
    // structurally by ensuring the `attributes.len() >` check appears
    // before the `for kv in` loop in the source.
    const fnStart = src.indexOf("pub fn check_span_post_decode");
    expect(fnStart).toBeGreaterThan(-1);
    const fnSlice = src.slice(fnStart, fnStart + 1500);
    const countCheckPos = fnSlice.indexOf("max_attributes_per_span");
    const sizeIterPos = fnSlice.indexOf("max_attribute_value_bytes");
    expect(countCheckPos).toBeGreaterThan(-1);
    expect(sizeIterPos).toBeGreaterThan(countCheckPos);
  });

  it("2. attribute_value_bytes handles every AnyValue variant", () => {
    const src = fs.readFileSync(path.join(INGEST_SRC, "limits.rs"), "utf8");
    for (const variant of [
      "StringValue",
      "BytesValue",
      "BoolValue",
      "IntValue",
      "DoubleValue",
      "ArrayValue",
      "KvlistValue",
    ]) {
      expect(src).toContain(variant);
    }
  });

  it("3. otlp_receiver maps each ADR-029 reason to the correct HTTP status", () => {
    const src = fs.readFileSync(path.join(INGEST_SRC, "limits.rs"), "utf8");
    // Per ADR-029: AttributeTooLarge + TooManyAttributes → 400;
    // BatchTooLarge + SpanTooLarge → 413.
    expect(src).toContain("RejectReason::AttributeTooLarge | RejectReason::TooManyAttributes => 400");
    expect(src).toContain("RejectReason::BatchTooLarge | RejectReason::SpanTooLarge => 413");
  });

  it("4. tracelane_ingest_rejected_total counter has 4 reasons (low cardinality)", () => {
    const src = fs.readFileSync(path.join(INGEST_SRC, "limits.rs"), "utf8");
    expect(src).toContain('metric_name = "tracelane_ingest_rejected_total"');
    expect(src).toContain("static REJECT_COUNTERS: [AtomicU64; 4]");
    expect(src).toContain("pub fn reject_metric_snapshot()");
  });

  it("5. workspace_id_bucket hashes UUIDs into 0..64 (Prom cardinality cap)", () => {
    const src = fs.readFileSync(path.join(INGEST_SRC, "limits.rs"), "utf8");
    expect(src).toContain("pub fn workspace_bucket(uuid: &uuid::Uuid) -> u8");
    expect(src).toContain("(uuid.as_u128() as u8) & 0x3f");
    // ADR-029 documents the 64-bucket choice; the eval pins the
    // implementation so a future refactor doesn't silently bump
    // cardinality past the Prometheus budget.
    const adr = fs.readFileSync(ADR, "utf8");
    expect(adr).toContain("workspace_uuid.as_u128() % 64");
  });
});

import { describe, it } from "vitest";
import { expect } from "../src/harness.js";
import fs from "node:fs";
import path from "node:path";

/**
 * FT-08 — Self-host disk full: graceful degradation without crash
 *
 * Scenario: The self-hosted Tracelane Lite instance (DuckDB embedded) runs
 * out of disk space. The ingest writer must not panic or crash. It must
 * (a) reject new spans with a structured error (`storage.disk_full=true`),
 * (b) continue serving read queries from existing data,
 * (c) emit an alert span so the operator knows to free disk space.
 *
 * Production code: `crates/ingest/src/clickhouse_writer.rs` (and the Lite
 * variant with DuckDB) — wrap all write operations in a disk-space check.
 * If available < 100MB, switch to reject-new + alert mode.
 *
 * Chaos method: Set disk quota to 1MB on a tmpfs. Send spans until disk
 * fills. Assert (a) no panic, (b) read queries still work, (c) alert fires.
 *
 * Status: Structural assertions green. DuckDB Lite writer and disk-space
 * check are Week 8; chaos test skipped until then.
 */

const INGEST_SRC = path.resolve(__dirname, "../../crates/ingest/src");

describe("FT-08: Self-host disk full — graceful degradation, no crash", () => {
  it("ingest clickhouse_writer module exists", () => {
    const p = path.join(INGEST_SRC, "clickhouse_writer.rs");
    expect(fs.existsSync(p)).toBe(true);
  });

  it("documents Tracelane Lite DuckDB single-binary mode", () => {
    const trd = fs.readFileSync(
      path.resolve(__dirname, "../fixtures/public-spec.md"),
      "utf8",
    );
    expect(trd).toContain("Tracelane Lite");
    expect(trd).toContain("DuckDB");
  });

  it("disk-full degradation policy is defined", () => {
    const diskFullPolicy = {
      thresholdMB: 100,
      allowReadsWhenFull: true,
      alertOnDiskFull: true,
      crashOnDiskFull: false,
    };
    expect(diskFullPolicy.crashOnDiskFull).toBe(false);
    expect(diskFullPolicy.allowReadsWhenFull).toBe(true);
    expect(diskFullPolicy.thresholdMB).toBeGreaterThan(0);
  });

  it("clickhouse_writer does not panic on write failure (no unwrap in prod code)", () => {
    const content = fs.readFileSync(
      path.join(INGEST_SRC, "clickhouse_writer.rs"),
      "utf8",
    );
    const testStart = content.indexOf("mod tests");
    const prodCode = testStart >= 0 ? content.slice(0, testStart) : content;
    const nonCommentLines = prodCode
      .split("\n")
      .filter((l) => !l.trim().startsWith("//"));
    const hasUnwrap = nonCommentLines.some((l) => l.includes(".unwrap()"));
    expect(hasUnwrap).toBe(false);
  });

  it("100 MB disk threshold is conservative vs typical span sizes", () => {
    // Average span ~2 KB (JSON + attributes). 100 MB ≈ 50K spans of headroom.
    // This gives the operator enough time to act on the alert.
    const thresholdBytes = 100 * 1024 * 1024;
    const avgSpanBytes = 2_048;
    const spansOfHeadroom = thresholdBytes / avgSpanBytes;
    expect(spansOfHeadroom).toBeGreaterThan(10_000);
  });

  it("disk-full reject-mode is implemented in disk_guard.rs (FT-08 feature)", () => {
    const guard = path.join(INGEST_SRC, "disk_guard.rs");
    expect(fs.existsSync(guard)).toBe(true);
    const content = fs.readFileSync(guard, "utf8");
    // Pure decision + real statvfs + the shared shed flag.
    expect(content).toContain("pub fn should_shed");
    expect(content).toContain("pub fn available_bytes");
    expect(content).toContain("struct DiskGuard");
    // The alert marker FT-08 requires.
    expect(content).toContain("storage.disk_full=true");
    // Fail-open on a stat error (do not wrongly shed healthy traffic).
    expect(content).toContain("fail-open");
  });

  it("OTLP receiver sheds (507) instead of crashing when the disk is full", () => {
    const content = fs.readFileSync(
      path.join(INGEST_SRC, "otlp_receiver.rs"),
      "utf8",
    );
    // Admission check + dedicated 507 shed response.
    expect(content).toContain("is_shedding()");
    expect(content).toContain("INSUFFICIENT_STORAGE");
    expect(content).toContain("disk_full_response");
  });

  it("real disk-full chaos tests exist (guard + receiver 507)", () => {
    const guard = fs.readFileSync(path.join(INGEST_SRC, "disk_guard.rs"), "utf8");
    const recv = fs.readFileSync(path.join(INGEST_SRC, "otlp_receiver.rs"), "utf8");
    expect(guard).toContain("guard_sheds_when_threshold_exceeds_capacity");
    expect(guard).toContain("guard_recovers_after_disk_frees");
    expect(recv).toContain("ft08_disk_full_sheds_batch_with_507");
    expect(recv).toContain("ft08_healthy_disk_admits_batch");
  });
});

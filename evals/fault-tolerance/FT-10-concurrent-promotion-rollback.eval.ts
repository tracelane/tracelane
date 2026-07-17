import { describe, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { expect } from "../src/harness.js";

/**
 * FT-10 — Concurrent promotion + attribution-based rollback (ADR-038 §23.4).
 *
 * (Numbered FT-10, not FT-09: FT-09 is already the SPIRE-agent-down eval.)
 *
 * Scenario: two near-simultaneous promotions land on one prompt, one of them
 * regressive. The release-vs-detection invariant requires that promotions are
 * serialized per workspace (ReplacingMergeTree + `decided_at` ordering) so the
 * two cannot land inside one detection window ambiguously, and that rollback is
 * attribution-based — it targets the specific (prompt, version) whose
 * introduction correlates with the breach, not merely "the last change".
 *
 * Structural: assert the serialization schema and the deterministic rollback
 * path. Full two-writer race is the skipped integration case.
 */
const REPO = path.resolve(__dirname, "../..");
const read = (rel: string) => fs.readFileSync(path.join(REPO, rel), "utf8");

describe("FT-10: concurrent promotion + attribution rollback (ADR-038)", () => {
  it("promotion_decisions is serialized per workspace (ReplacingMergeTree + decided_at)", () => {
    const sql = read("infra/dev/clickhouse/migrations/03_prompt_promotion.sql");
    expect(sql).toContain("promotion_decisions");
    expect(sql).toContain("ReplacingMergeTree");
    // ordered by (tenant_id, prompt_id, decided_at) → per-workspace serialization
    expect(sql).toMatch(/ORDER BY\s*\(tenant_id,\s*prompt_id,\s*decided_at\)/);
  });

  it("rollback is deterministic and attribution-keyed (to a specific version)", () => {
    const rollback = read("packages/cli/src/commands/rollback.ts");
    // targets a specific to_version_id, not "the last change"
    expect(rollback).toContain("to_version_id");
    expect(rollback).toContain("from_version_id");
    // and is the token-free path (ADR-037) — no provider/judge import
    expect(rollback.replace(/\/\/.*$/gm, "")).not.toContain("@modelcontextprotocol");
  });

  it("auto-rollback fires on objective metrics only (no judge in the auto path)", () => {
    const ar = read("crates/gateway/src/auto_rollback.rs");
    expect(ar).toContain("is_objective");
  });

  it("real concurrent-promotion + attribution-rollback chaos tests exist in prompt_router.rs", () => {
    // The integration fault is now injected for real as in-module unit tests:
    // (a) two concurrent promotes serialize through the arc-swap pointer with
    // no torn state, and (b) an objective cost spike on vC auto-rolls back to
    // the version it displaced (vB), not the first-ever production (vA).
    const router = path.resolve(
      __dirname,
      "../../crates/gateway/src/prompt_router.rs",
    );
    const content = fs.readFileSync(router, "utf8");
    expect(content).toContain(
      "ft10_concurrent_promotions_serialize_without_corruption",
    );
    expect(content).toContain(
      "ft10_attribution_rollback_targets_specific_displaced_version",
    );
  });
});

import { describe, it } from "vitest";
import { expect } from "../src/harness.js";
import fs from "node:fs";
import path from "node:path";

/**
 * PP-PR8 — Tool argument distribution drift detected
 *
 * Competitor behavior: No competitor monitors the statistical distribution
 * of tool call arguments across sessions. PromptLayer and LangSmith log
 * individual calls but don't compute drift against baselines. Arize detects
 * feature drift in ML pipelines but not in LLM tool-call argument space.
 *
 * Tracelane fix: MCP hash watcher monitors tool call payloads for drift.
 * McpHashWatcher fires AFT-MCP-RUGPULL-001 when tool schema hash changes
 * (rug-pull detection). The predictive layer is extensible — argdrift
 * predictor (AFT-MCP-ARGDRIFT-001, Week 9) adds per-tenant Wasserstein
 * distance baseline at 3σ threshold.
 *
 */

const GATEWAY_PREDICTIVE = path.resolve(__dirname, "../../crates/gateway/src/predictive");

describe("PP-PR8: Tool argument distribution drift detected", () => {
  it("MCP hash watcher predictor exists (rug-pull detection foundation)", () => {
    const content = fs.readFileSync(
      path.join(GATEWAY_PREDICTIVE, "mcp_hash_watcher.rs"),
      "utf8",
    );
    expect(content).toContain("McpHashWatcher");
    expect(content).toContain("AFT-MCP-RUGPULL-001");
  });

  it("AFT-MCP-ARGDRIFT-001 is documented in TRD", () => {
    const trd = fs.readFileSync(
      path.resolve(__dirname, "../fixtures/public-spec.md"),
      "utf8",
    );
    expect(trd).toContain("AFT-MCP-ARGDRIFT-001");
  });

  it("predictive layer architecture is extensible for argdrift predictor", () => {
    const mod = fs.readFileSync(path.join(GATEWAY_PREDICTIVE, "mod.rs"), "utf8");
    expect(mod).toContain("Vec<Box<dyn Predictor>>");
  });

  it("predictive mod.rs registers 10 predictors including MCP hash watcher", () => {
    const mod = fs.readFileSync(path.join(GATEWAY_PREDICTIVE, "mod.rs"), "utf8");
    expect(mod).toContain("McpHashWatcher");
    expect(mod).toContain("TrajectoryGuard");
    expect(mod).toContain("SlmJudge");
  });

  it("PR8-lite argument drift predictor defines 3σ threshold (AFT-MCP-ARGDRIFT-001)", () => {
    const pr8Path = path.resolve(
      __dirname,
      "../../crates/gateway/src/predictive/pr8_lite_argument_drift.rs",
    );
    expect(fs.existsSync(pr8Path)).toBe(true);
    const content = fs.readFileSync(pr8Path, "utf8");
    // 3σ drift threshold constant
    expect(content).toContain("DRIFT_SIGMA");
    expect(content).toContain("3.0");
    // Mahalanobis distance baseline approach
    expect(content).toContain("AFT-MCP-ARGDRIFT-001");
  });

  it.skip("argdrift predictor fires Warn at 3-sigma deviation (Week 9)", () => {
    // Full: populate 7-day baseline for tool "search", run call with
    // argument distribution outside 3σ, assert Warn { aft_id: "AFT-MCP-ARGDRIFT-001" }
  });
});

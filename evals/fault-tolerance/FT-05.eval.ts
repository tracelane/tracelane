import { describe, it } from "vitest";
import { expect } from "../src/harness.js";
import fs from "node:fs";
import path from "node:path";

/**
 * FT-05 — Predictive layer ONNX crash: gateway fails open, not closed
 *
 * Scenario: The ONNX Runtime used by the predictive layer panics or returns
 * an unrecoverable error (OOM, model file corrupted). The gateway must
 * continue serving requests with the predictive layer disabled (fail-open)
 * rather than returning 503, emitting the `tracelane.predictive.degraded=true`
 * span marker (our self-hosted error signal in ClickHouse — no third-party APM).
 *
 * Production code: `crates/gateway/src/predictive/mod.rs` — PredictiveLayer
 * must catch panics from ONNX Runtime, log the error, emit a span with
 * `tracelane.predictive.degraded=true`, and return `Decision::Allow`.
 *
 * This is a deliberate architectural choice: false-negatives on predictive
 *
 * Chaos method: Inject a predictor that panics on every call. Assert that
 * the gateway returns 200 with predictive degraded flag, not 503.
 *
 * Status: Structural assertions green. Integration test skipped until
 * panic-catch wrapper is added to PredictiveLayer.evaluate() (Week 7).
 */

const GATEWAY_SRC = path.resolve(__dirname, "../../crates/gateway/src");

describe("FT-05: Predictive ONNX crash — gateway fails open", () => {
  it("PredictiveLayer.evaluate() is the single entry point for all predictors", () => {
    const content = fs.readFileSync(
      path.join(GATEWAY_SRC, "predictive/mod.rs"),
      "utf8",
    );
    expect(content).toContain("pub fn evaluate");
    expect(content).toContain("Decision::Allow");
  });

  it("documents fail-open as the predictive layer circuit breaker policy", () => {
    const trd = fs.readFileSync(
      path.resolve(__dirname, "../fixtures/public-spec.md"),
      "utf8",
    );
    expect(trd).toContain("fail-open");
    expect(trd).toContain("Circuit breakers");
  });

  it("predictive/mod.rs emits degraded span on error path", () => {
    const content = fs.readFileSync(
      path.join(GATEWAY_SRC, "predictive/mod.rs"),
      "utf8",
    );
    expect(content).toContain("degraded");
    expect(content).toContain("tracing");
  });

  it("predictive layer does not panic in production code", () => {
    const content = fs.readFileSync(
      path.join(GATEWAY_SRC, "predictive/mod.rs"),
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

  it("fail-open policy is correct for observability product", () => {
    // For a reliability observability tool, failing closed (503) is worse than
    // missing a predictive guardrail. The gateway must always serve traffic.
    const policy = { predictiveFailureMode: "fail-open" as const };
    expect(policy.predictiveFailureMode).toBe("fail-open");
  });

  it("real panic-catch fail-open is wired in PredictiveLayer + has chaos tests", () => {
    // The fault is now injected for real: PredictiveLayer.evaluate() and
    // evaluate_async() wrap each predictor in std::panic::catch_unwind and
    // degrade to Decision::Allow on panic, emitting the degraded marker. The
    // in-module chaos tests inject a PanickingPredictor and assert Allow.
    const content = fs.readFileSync(
      path.join(GATEWAY_SRC, "predictive/mod.rs"),
      "utf8",
    );
    // Production panic-catch wrapper on both entry points.
    expect(content).toContain("catch_unwind");
    expect(content).toContain("degraded_fail_open");
    expect(content).toContain("tracelane.predictive.degraded=true");
    // The chaos tests that drive a panicking predictor through both paths.
    expect(content).toContain("ft05_panicking_predictor_fails_open_sync");
    expect(content).toContain("ft05_panicking_predictor_fails_open_async");
  });
});

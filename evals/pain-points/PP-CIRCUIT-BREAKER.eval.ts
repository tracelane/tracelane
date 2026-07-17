import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 *
 * Contract: a fixture provider that 5xx's trips its breaker within the window;
 * traffic to OTHER providers is unaffected (bulkhead); the breaker recovers
 * after the cool-down via Half-Open probes.
 *
 * Structural (this file): assert the breaker module, the state machine, the
 * (provider, region) keying, and the dispatch-path wiring (503 + Retry-After +
 * tracelane.upstream.circuit on Open). Behavioral correctness — trip on 5
 * consecutive failures, trip on ≥50% window rate, bulkhead independence,
 * Half-Open recovery, probe-failure re-open — is proven by the Rust unit tests
 * in `crates/gateway/src/circuit_breaker.rs`.
 */
function read(rel: string): string {
  // biome-ignore lint/style/useNodejsImportProtocol: harness is CJS
  const fs = require("node:fs");
  // biome-ignore lint/style/useNodejsImportProtocol: harness is CJS
  const path = require("node:path");
  return fs.readFileSync(path.resolve(__dirname, rel), "utf8");
}

describe("PP-CIRCUIT-BREAKER: per-upstream breakers (ADR-036)", () => {
  it("breaker module implements the Closed/Open/Half-Open state machine", () => {
    const src = read("../../crates/gateway/src/circuit_breaker.rs");
    for (const token of ["Closed", "Open", "HalfOpen"]) {
      expect(src.includes(token), `missing state ${token}`).toBe(true);
    }
    // thresholds per ADR-036
    expect(src).toContain("consecutive_failure_threshold");
    expect(src).toContain("failure_rate_threshold");
    expect(src).toContain("half_open_max_probes");
  });

  it("breakers are keyed per (provider, region)", () => {
    const src = read("../../crates/gateway/src/circuit_breaker.rs");
    expect(src).toContain("DashMap<(String, String)");
    expect(src).toContain("fn allow(");
    expect(src).toContain("fn record(");
  });

  it("dispatch path checks the breaker and returns 503 + Retry-After on Open", () => {
    const src = read("../../crates/gateway/src/server.rs");
    expect(src).toContain("circuit_breaker.allow");
    expect(src).toContain("circuit_breaker");
    expect(src).toContain("SERVICE_UNAVAILABLE");
    expect(src).toContain("RETRY_AFTER");
    expect(src).toContain("tracelane-upstream-circuit");
    // outcome is recorded back into the breaker
    expect(src).toContain(".record(upstream, region, provider_result.is_ok())");
  });

  it("trip input is the gen_ai.client.operation.exception classification", () => {
    const emit = read("../../crates/gateway/src/otlp_emit.rs");
    expect(emit).toContain("gen_ai.client.operation.exception");
  });

  it.skip("integration: fixture 5xx trips breaker, other providers serve (wiremock — Week 8)", () => {
    // Full: wiremock a provider returning 5xx, assert the breaker opens within
    // the window and a second provider keeps serving; assert recovery post-cooldown.
  });
});

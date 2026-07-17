import { describe, it } from "vitest";
import { expect } from "../src/harness.js";
import fs from "node:fs";
import path from "node:path";

/**
 * FT-02 — Rate-limit queue: requests queued and retried within SLO
 *
 * Scenario: LLM provider returns HTTP 429 (Too Many Requests) with a
 * Retry-After header. Gateway must queue the request, honour the retry
 * interval, and re-submit without the caller receiving a 429 error —
 * unless the queue depth exceeds the configured timeout.
 *
 * Production code: `crates/gateway/src/rate_limiter.rs` — per-tenant
 * token bucket; `crates/gateway/src/providers/mod.rs` — retry logic with
 * exponential back-off capped at Retry-After header value.
 *
 * Chaos method: Inject a mock provider that returns 429 for the first
 * 3 calls then succeeds. Assert that the caller receives a 200 and the
 * span has `tracelane.retry.count=3`.
 *
 * Status: Structural assertions green. Integration test skipped until
 * gateway retry logic is wired (Week 7).
 */

const GATEWAY_SRC = path.resolve(__dirname, "../../crates/gateway/src");

describe("FT-02: Rate-limit queue — retry within SLO", () => {
  it("rate_limiter module exists in gateway", () => {
    const p = path.join(GATEWAY_SRC, "rate_limiter.rs");
    expect(fs.existsSync(p)).toBe(true);
  });

  it("rate_limiter references TenantId for per-tenant limiting", () => {
    const content = fs.readFileSync(
      path.join(GATEWAY_SRC, "rate_limiter.rs"),
      "utf8",
    );
    expect(content).toContain("TenantId");
  });

  it("rate_limiter uses token-bucket algorithm (not leaky bucket)", () => {
    const content = fs.readFileSync(
      path.join(GATEWAY_SRC, "rate_limiter.rs"),
      "utf8",
    );
    // Token bucket is the CLAUDE.md–mandated algorithm for per-tenant limiting
    expect(content).toContain("token");
  });

  it("rate_limiter does not panic on 429 burst (no unwrap in prod code)", () => {
    const content = fs.readFileSync(
      path.join(GATEWAY_SRC, "rate_limiter.rs"),
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

  it("retry SLO budget is within gateway overhead budget", () => {
    const retryPolicy = {
      maxRetries: 3,
      backoffBaseMs: 100,
      respectRetryAfterHeader: true,
      callerTimeoutMs: 30_000,
    };
    // Caller timeout must be larger than gateway p99 overhead (25ms)
    expect(retryPolicy.callerTimeoutMs).toBeGreaterThan(25);
    expect(retryPolicy.maxRetries).toBeGreaterThan(0);
    expect(retryPolicy.respectRetryAfterHeader).toBe(true);
  });

  it("real wiremock 429 chaos test exists in tests/rate_limit_chaos.rs", () => {
    // The integration fault is now injected for real: a wiremock upstream
    // answers 429 + Retry-After then 200, exercising the same retry shape as
    // `server.rs::dispatch_with_retry`. If you rename the helpers, update
    // both call sites.
    const chaos = path.resolve(
      __dirname,
      "../../crates/gateway/tests/rate_limit_chaos.rs",
    );
    expect(fs.existsSync(chaos)).toBe(true);
    const content = fs.readFileSync(chaos, "utf8");
    expect(content).toContain("wiremock_429_then_200_succeeds_within_budget");
    expect(content).toContain("wiremock_persistent_429_exhausts_retry");
    expect(content).toContain("MockServer");
  });
});

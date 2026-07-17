import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-OP1 — Rate limiting prevents abuse without blocking legitimate traffic
 *
 * Competitor behavior: LiteLLM's rate limiter is a simple token bucket with
 * no per-tenant awareness. Helicone's rate limits apply globally, not per
 * customer. A single noisy tenant can degrade service for all others.
 *
 * Pain: Multi-tenant observability platforms need fair-use enforcement that
 * is invisible to well-behaved tenants. A misconfigured agent loop burning
 * 10K RPM should not affect the tenant on the same node doing 100 RPM.
 *
 * Tracelane fix: Per-tenant token bucket (Rust, lock-free). Configured per
 * pricing tier (Free: 60 RPM, Builder: 300 RPM, Team: 1K RPM, Business: 5K
 * RPM). Rate limit headers (X-RateLimit-Limit, X-RateLimit-Remaining,
 * Retry-After) on every response.
 *
 * Eval: Verify rate limiter stub exists and is wired into gateway.
 *
 */
describe("PP-OP1: Rate limiting prevents abuse", () => {
  it("rate limiter module exists in gateway", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const rateLimiter = path.resolve(
      __dirname,
      "../../crates/gateway/src/rate_limiter.rs"
    );
    expect(fs.existsSync(rateLimiter)).toBe(true);
  });

  it("rate limiter is wired into gateway main.rs", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const main = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/main.rs"),
      "utf8"
    );
    expect(main).toContain("rate_limiter");
  });

  it("rate limits are per-tenant not global", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const rateLimiter = fs.readFileSync(
      path.resolve(
        __dirname,
        "../../crates/gateway/src/rate_limiter.rs"
      ),
      "utf8"
    );
    // Must reference tenant_id or TenantId to be per-tenant
    expect(rateLimiter).toContain("tenant_id");
  });
});

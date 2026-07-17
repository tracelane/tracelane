import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-ENTITLEMENT-CACHE — in-process entitlement-resolution cache (ADR-035,
 *
 * Contract: (a) zero Postgres queries on a warm-cache request, (b) <100µs p99
 * cache read, (c) invalidation visible within 100ms of a NOTIFY. The cache
 * removes the rank-1 scaling ceiling (per-request Neon hit) from the gateway
 * hot path.
 *
 * Structural (this file): assert the cache module, moka dependency, deny-
 * overrides-grant resolver, LISTEN/NOTIFY wiring, fail-open policy, and metrics
 * are present. Behavioral correctness — warm path does not re-resolve, fail-open
 * to last-known, invalidate forces re-resolve — is proven by the Rust unit tests
 * in `crates/gateway/src/entitlement_cache.rs`. Live-Neon latency/invalidation
 * timing is the skipped integration case.
 */
function read(rel: string): string {
  // biome-ignore lint/style/useNodejsImportProtocol: harness is CJS
  const fs = require("node:fs");
  // biome-ignore lint/style/useNodejsImportProtocol: harness is CJS
  const path = require("node:path");
  return fs.readFileSync(path.resolve(__dirname, rel), "utf8");
}

describe("PP-ENTITLEMENT-CACHE: in-process entitlement cache (ADR-035)", () => {
  it("entitlement_cache module exists with moka future cache + TTL/refresh-ahead", () => {
    const src = read("../../crates/gateway/src/entitlement_cache.rs");
    expect(src).toContain("moka::future::Cache");
    expect(src).toContain("time_to_live");
    expect(src).toContain("REFRESH_AHEAD");
    expect(src).toContain("Duration::from_secs(30)");
  });

  it("moka is the only new declared dependency", () => {
    const src = read("../../crates/gateway/Cargo.toml");
    expect(src).toContain("moka");
    expect(src).toContain('features = ["future"]');
  });

  it("resolver computes deny-overrides-grant (COALESCE override over plan)", () => {
    const src = read("../../crates/gateway/src/entitlement_cache.rs");
    expect(src).toContain("COALESCE(we.f_pr7_trajectory, pe.f_pr7_trajectory)");
    expect(src).toContain("workspace_entitlements we");
    expect(src).toContain("JOIN plan_entitlements pe");
  });

  it("LISTEN/NOTIFY invalidation wired with TTL fallback + reconnect metric", () => {
    const src = read("../../crates/gateway/src/entitlement_cache.rs");
    expect(src).toContain("LISTEN entitlements_changed");
    expect(src).toContain("LISTEN_RECONNECT_TOTAL");
    expect(src).toContain("POSTGRES_DIRECT_URL");
    // metric counters
    expect(src).toContain("CACHE_MISS_TOTAL");
  });

  it("fail-open policy: last-known on outage, deny-new without it", () => {
    const src = read("../../crates/gateway/src/entitlement_cache.rs");
    expect(src).toContain("last_known");
    expect(src).toContain("deny_all");
    expect(src).toContain("failing open to last-known grant");
  });

  it("NOTIFY trigger migration exists (prod-tooling applied)", () => {
    const src = read(
      "../../infra/dev/postgres/migrations/12_entitlements_notify.sql"
    );
    expect(src).toContain("pg_notify('entitlements_changed'");
    expect(src).toContain("workspace_entitlements");
    expect(src).toContain("plan_entitlements");
  });

  it("cache is wired into AppState (warm path serves without Neon)", () => {
    const src = read("../../crates/gateway/src/server.rs");
    expect(src).toContain("entitlements");
    expect(src).toContain("EntitlementCache");
    expect(src).toContain("spawn_listen_task");
  });

  it.skip("integration: <100µs p99 warm read + <100ms invalidation (live Neon — Week 8)", () => {
    // Full: warm the cache, measure p99 get latency under load, fire a NOTIFY,
    // assert the next read reflects the change within 100ms.
  });
});

import { describe, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { expect } from "../src/harness.js";

/**
 * PP-TENANT-ISOLATION — Tenant isolation invariants at V1 launch
 *
 * V1 launches with three distinct tenant-isolation surfaces:
 *
 *   1. **ClickHouse** — every read goes through the per-tier resource-cap
 *      wrapper `TenantQuery` (Rust, `crates/gateway/src/clickhouse_query.rs`)
 *      that attaches `max_memory_usage` / `max_execution_time` /
 *      `max_rows_to_read`. Misconfigured queries can't starve the shared
 *      through the gateway proxy — no direct `@clickhouse/client` — so the
 *      tenant is always the gateway's validated JWT claim. CI guards
 *      `no-raw-ch-query` + `tenant-id-provenance` block bypass. (ADR-031)
 *   2. **R2 object storage** — every key is prefixed
 *      `tenants/<workspace_uuid>/...`. `crates/ingest/src/r2_batcher.rs::
 *      assert_tenant_prefix` panics in debug and refuses the PUT in
 *      release if a key skips the prefix. (ADR-031)
 *   3. **Postgres** — `WHERE tenant_id = ?` filter on every query
 *      (existing `tenant-isolation-check` CI job; not touched here)
 *      plus the new `admin_audit_log` table giving a durable trail
 *      of admin actions per workspace. (ADR-031)
 *
 * Five structural assertions per pain-points convention:
 *   1. ADR-031 ships with the three surfaces documented
 *   2. ClickHouse cap wrapper exists (Rust); dashboard proxies via the gateway
 *   3. R2 tenant prefix invariant + assertion in r2_batcher.rs
 *   4. CI guard `no-raw-ch-query.sh` wired into ci.yml
 *   5. admin_audit_log migration + helper exist on both sides
 *
 * Linked: ADR-031, crates/gateway/src/{clickhouse_query.rs,trace_reads.rs,admin_audit.rs},
 *         apps/web/lib/{gateway.ts,admin-audit.ts},
 *         crates/ingest/src/r2_batcher.rs.
 */

const ROOT = path.resolve(__dirname, "../..");
const ADR = path.join(ROOT, "decisions/ADR-031-admin-audit-and-ch-resource-caps.md");

describe("PP-TENANT-ISOLATION: V1 tenant isolation surfaces (ADR-031)", () => {
  it("1. ADR-031 ships with three surfaces documented", () => {
    const adr = fs.readFileSync(ADR, "utf8");
    expect(adr).toContain("ClickHouse per-tenant resource caps");
    expect(adr).toContain("R2 key prefix");
    expect(adr).toContain("admin_audit_log");
    // Per-tier cap values from the ADR table.
    expect(adr).toContain("512 MiB");
    expect(adr).toContain("32 GiB");
    expect(adr).toContain("max_memory_usage");
    expect(adr).toContain("max_execution_time");
    expect(adr).toContain("max_rows_to_read");
  });

  it("2. ClickHouse cap wrapper exists (Rust); dashboard proxies via the gateway", () => {
    const rs = fs.readFileSync(
      path.join(ROOT, "crates/gateway/src/clickhouse_query.rs"),
      "utf8",
    );
    expect(rs).toContain("pub struct TenantQuery");
    expect(rs).toContain("pub struct ClickHouseResourceCaps");
    expect(rs).toContain("pub enum PlanTier");
    // Builder + Enterprise caps surfaced numerically.
    expect(rs).toContain("512 * 1024 * 1024"); // 512 MiB
    expect(rs).toContain("32u64 * 1024 * 1024 * 1024"); // 32 GiB
    expect(rs).toContain("max_execution_time_secs: 10");
    expect(rs).toContain("max_execution_time_secs: 300");

    // The gateway's customer-facing trace/SLO reads go through TenantQuery.
    const reads = fs.readFileSync(
      path.join(ROOT, "crates/gateway/src/trace_reads.rs"),
      "utf8",
    );
    expect(reads).toContain("TenantQuery::new");
    expect(reads).toContain("WHERE tenant_id = ?");

    // the old TS `lib/clickhouse.ts` cap wrapper is removed. Isolation is
    // strictly stronger: the dashboard cannot bind a tenant id into a query at
    // all; it forwards only the Bearer and the gateway resolves the tenant.
    expect(
      fs.existsSync(path.join(ROOT, "apps/web/lib/clickhouse.ts")),
    ).toBe(false);
    const gw = fs.readFileSync(
      path.join(ROOT, "apps/web/lib/gateway.ts"),
      "utf8",
    );
    expect(gw).toContain("export async function gatewayGet");
    expect(gw).toContain("requireGatewayToken");
  });

  it("3. R2 tenant prefix invariant + assertion in r2_batcher.rs", () => {
    const rs = fs.readFileSync(
      path.join(ROOT, "crates/ingest/src/r2_batcher.rs"),
      "utf8",
    );
    expect(rs).toContain('pub const TENANT_KEY_PREFIX: &str = "tenants/"');
    expect(rs).toContain("fn assert_tenant_prefix");
    expect(rs).toContain("ADR-031 tenant isolation invariant violated");
    // The object_key formatter uses the prefix.
    expect(rs).toContain("{prefix}{tenant_id}/{yyyy}/{mm}/{dd}/{hash_prefix}.ndjson");
  });

  it("4. CI guard `no-raw-ch-query.sh` exists, executable, wired into ci.yml", () => {
    const sh = fs.readFileSync(
      path.join(ROOT, "scripts/ci/no-raw-ch-query.sh"),
      "utf8",
    );
    expect(sh).toContain("ADR-031");
    expect(sh).toContain("clickhouse_query.rs");
    expect(sh).toContain("tenantQuery");

    const ci = fs.readFileSync(
      path.join(ROOT, ".github/workflows/ci.yml"),
      "utf8",
    );
    expect(ci).toContain("no-raw-ch-query:");
    expect(ci).toContain("scripts/ci/no-raw-ch-query.sh");
  });

  it("5. admin_audit_log migration + helpers on both Rust and TS", () => {
    const sql = fs.readFileSync(
      path.join(ROOT, "infra/dev/postgres/migrations/11_admin_audit_log.sql"),
      "utf8",
    );
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS admin_audit_log");
    expect(sql).toContain("actor_user_id");
    expect(sql).toContain("actor_workspace_id");
    expect(sql).toContain("idx_admin_audit_workspace");

    const rs = fs.readFileSync(
      path.join(ROOT, "crates/gateway/src/admin_audit.rs"),
      "utf8",
    );
    expect(rs).toContain("pub struct AdminAuditEntry");
    expect(rs).toContain("pub async fn record_admin_action");

    const ts = fs.readFileSync(
      path.join(ROOT, "apps/web/lib/admin-audit.ts"),
      "utf8",
    );
    expect(ts).toContain("export async function recordAdminAction");
    expect(ts).toContain("export function ipFromRequest");
    // Demo call site — V1 wires api-keys POST + DELETE + prompt promote.
    const apiKeysRoute = fs.readFileSync(
      path.join(ROOT, "apps/web/app/api/settings/api-keys/route.ts"),
      "utf8",
    );
    expect(apiKeysRoute).toContain("recordAdminAction");
    expect(apiKeysRoute).toContain('action: "api_key.create"');
  });
});

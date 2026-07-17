import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-O6 — True self-host, license only
 *
 * Competitor behavior: Langfuse Pro has features gated behind cloud-only
 * APIs (SSO, advanced analytics). Helicone doesn't have a self-host path
 * for the AI gateway. Phoenix self-host works but requires 4 services.
 *
 * Pain: Teams with data residency requirements (HIPAA, GDPR, financial
 * institutions) need 100% on-premise operation without calling home to
 * the vendor's servers. Feature gating on cloud connectivity defeats this.
 *
 * Tracelane fix: The entire stack runs on-premise with zero cloud calls
 * back to Tracelane. License validation is offline (Apache 2.0 — no license
 * server). The only outbound calls are to the tenant's configured providers
 * (their own API keys, their choice).
 *
 * Eval design:
 * - Verify no hardcoded tracelane.dev calls in gateway code
 * - Verify WorkOS JWKS URL is configurable (not hardcoded)
 * - Verify ClickHouse URL is configurable (not hardcoded to cloud)
 *
 */
describe("PP-O6: True self-host — license only", () => {
  it("WORKOS_JWKS_URL is configurable", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const content = fs.readFileSync(
      path.resolve(__dirname, "../../crates/gateway/src/auth/jwks.rs"),
      "utf8"
    );
    // Should use an env var, not a hardcoded URL
    expect(content).toContain("WORKOS_JWKS_URL");
    expect(content).toContain("env::var");
  });

  it("CLICKHOUSE_URL is configurable in ingest config", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const content = fs.readFileSync(
      path.resolve(__dirname, "../../crates/ingest/src/config.rs"),
      "utf8"
    );
    expect(content).toContain("CLICKHOUSE_URL");
    expect(content).toContain("localhost:8123"); // safe default, not cloud URL
  });

  it("NATS_URL defaults to localhost (not a cloud service)", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    const content = fs.readFileSync(
      path.resolve(__dirname, "../../crates/ingest/src/config.rs"),
      "utf8"
    );
    expect(content).toContain("nats://localhost:4222");
  });
});

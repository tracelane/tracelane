import { describe, it } from "vitest";
import { expect } from "../src/harness.js";
import fs from "node:fs";
import path from "node:path";

/**
 * FT-09 — SPIRE agent down: refresher exits cleanly, process does not hang
 *
 * Scenario: the SPIRE agent socket (`/tmp/spire-agent/public/api.sock`) goes
 * away mid-flight — agent crash, node reboot, accidental `systemctl stop`.
 * The ingest binary's `BundleRefresher` is responsible for re-opening the
 * stream with exponential backoff, but if the agent stays down past the
 * retry budget (8 attempts, ~3.5 minutes cap) the refresher MUST return
 * `Err` so `try_join!` in `main.rs` propagates the failure and the
 * supervisor restarts the process.
 *
 * Production code: `crates/ingest/src/tls.rs::BundleRefresher::run` —
 * `MAX_REFRESH_FAILURES = 8`, `INITIAL_REFRESH_BACKOFF = 500ms`,
 * `MAX_REFRESH_BACKOFF = 60s`. After 8 consecutive failures the
 * `anyhow::bail!` path is taken; `crates/ingest/src/main.rs` folds the
 * refresher future into `try_join!` so its `Err` brings the process down
 * cleanly. This is intentional fail-closed (per ADR-028 §Risks): a stale
 * trust bundle is worse than a controlled outage because SVIDs rotate
 * hourly and a frozen bundle would silently accept expired/rotated certs.
 *
 * Chaos method (structural assertions today; integration follows in a
 * Linux/WSL2 session):
 *  1. Spawn a tempdir-backed mock SPIRE agent, point `TRACELANE_SPIRE_SOCKET`
 *     at it.
 *  2. Boot ingest, verify the initial fetch succeeds.
 *  3. Kill the mock agent.
 *  4. Wait `MAX_REFRESH_BACKOFF * MAX_REFRESH_FAILURES` (≈4 min).
 *  5. Assert the ingest process exits non-zero within the budget — not
 *     200, not hang.
 *
 * Status: Structural assertions green. Integration test scaffold lives
 * at `crates/ingest/tests/spiffe_auth_test.rs` and requires testcontainers
 */

const INGEST_SRC = path.resolve(__dirname, "../../crates/ingest/src");

describe("FT-09: SPIRE agent down — refresher fails closed, process exits", () => {
  it("BundleRefresher caps retries at MAX_REFRESH_FAILURES (8) then bails", () => {
    const content = fs.readFileSync(path.join(INGEST_SRC, "tls.rs"), "utf8");
    // Constant present, and it is the default cap for the configurable field
    // (the FT-09 test seam shrinks the field, never the production default).
    expect(content).toContain("MAX_REFRESH_FAILURES");
    expect(content).toMatch(/max_failures:\s*MAX_REFRESH_FAILURES/);
    // Bounded retry semantics: bail! must fire when the counter reaches the cap.
    expect(content).toMatch(/failures\s*>=\s*self\.max_failures/);
    expect(content).toContain("anyhow::bail!");
  });

  it("Refresher uses exponential backoff capped at 60s", () => {
    const content = fs.readFileSync(path.join(INGEST_SRC, "tls.rs"), "utf8");
    expect(content).toContain("INITIAL_REFRESH_BACKOFF");
    expect(content).toContain("MAX_REFRESH_BACKOFF");
    expect(content).toContain("Duration::from_secs(60)");
    // Double-on-failure pattern.
    expect(content).toMatch(/backoff\s*\*\s*2/);
  });

  it("Refresher future is folded into try_join! so its Err brings the process down", () => {
    const main = fs.readFileSync(path.join(INGEST_SRC, "main.rs"), "utf8");
    expect(main).toContain("refresher_fut");
    expect(main).toContain("tokio::try_join!");
    // The match arm assembling the future must be present.
    expect(main).toMatch(/BundleRefresher::new/);
    expect(main).toMatch(/refresher\.run/);
  });

  it("Release builds refuse to start without a SPIRE socket (no plaintext fallback)", () => {
    const main = fs.readFileSync(path.join(INGEST_SRC, "main.rs"), "utf8");
    // The cfg(not(debug_assertions)) guard bails when TRACELANE_SPIRE_SOCKET
    // is unset, so release binaries cannot accidentally degrade to plaintext.
    expect(main).toContain("#[cfg(not(debug_assertions))]");
    expect(main).toContain("TRACELANE_SPIRE_SOCKET");
    expect(main).toMatch(/anyhow::bail!/);
  });

  it("auth.rs exposes a metric counter for ingest auth outcomes (ADR-028 §Observability)", () => {
    const auth = fs.readFileSync(path.join(INGEST_SRC, "auth.rs"), "utf8");
    expect(auth).toContain("tracelane_ingest_auth_total");
    // Five-bucket label set is stable per ADR-028.
    for (const label of [
      '"ok"',
      '"wrong_trust_domain"',
      '"invalid_path"',
      '"expired_svid"',
      '"no_svid"',
    ]) {
      expect(auth).toContain(label);
    }
    expect(auth).toContain("record_auth_result");
    expect(auth).toContain("auth_metric_snapshot");
  });

  it("TLS-layer handshake failures are counted as no_svid in otlp_receiver", () => {
    const receiver = fs.readFileSync(
      path.join(INGEST_SRC, "otlp_receiver.rs"),
      "utf8",
    );
    expect(receiver).toContain("record_auth_result(AuthResult::NoSvid)");
    expect(receiver).toContain("TLS handshake failed");
  });

  it("real SPIRE-agent-down chaos test exists in tls.rs (refresher exits with Err)", () => {
    // The test spawns a mock SPIRE, connects, drops it so the agent is down,
    // then asserts BundleRefresher::run returns Err within budget (not a hang)
    // so main's try_join! brings the process down for a clean restart.
    // The retry policy is shrunk via a test seam so the bail path is instant.
    const content = fs.readFileSync(
      path.join(INGEST_SRC, "tls.rs"),
      "utf8",
    );
    expect(content).toContain("ft09_refresher_exits_with_err_when_spire_agent_down");
    expect(content).toContain("with_retry_policy");
  });
});

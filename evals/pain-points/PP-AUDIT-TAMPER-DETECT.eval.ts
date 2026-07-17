import { describe, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { expect } from "../src/harness.js";

/**
 * PP-AUDIT-TAMPER-DETECT — `tracelane-audit` CLI detects single-byte
 * tampering of a known-good audit range and exits non-zero with a
 * field-level diff naming the offending event.
 *
 * Implementation (per ADR-034):
 *   * `crates/tracelane-audit-cli/` — new binary `tracelane-audit`
 *     with the `verify` subcommand. Wraps the shipped
 *     argument parsing + HTTP fetch + PASS/FAIL render.
 *   * Exit code contract: 0 PASS, 1 FAIL, 2 I/O.
 *   * `--file` offline mode: skip HTTP, verify a local NDJSON.
 *   * `--pinned-pubkey` defends against malicious Rekor mirror
 *     substituting a different signing key.
 *
 * Companion guards:
 *   * `crates/gateway/src/audit_retention.rs` — hardcodes the 180-day
 *     floor for Audit-add-on workspaces; panics if a contractual
 *     override goes below.
 *   * `.github/workflows/release-audit-cli.yml` — cross-compiles 4
 *     targets, Cosign-signs, CycloneDX SBOM, SLSA L3 provenance,
 *     Trusted-Publishes to crates.io.
 *
 * Five structural assertions per pain-points convention:
 *   1. ADR-034 ships with the CLI surface + exit-code contract
 *   2. CLI crate + Cargo.toml ship and are wired into the workspace
 *   3. Main implements verify subcommand + exit-code contract + offline mode
 *   4. Release workflow ships 4 targets + Cosign + SBOM + SLSA L3 + Trusted Publishing
 *   5. Audit retention floor is hardcoded at 180 days with a fail-loud override guard
 *
 * Linked: ADR-034, crates/tracelane-audit-cli/, packages/verifier-rust/.
 */

const ROOT = path.resolve(__dirname, "../..");
const ADR = path.join(ROOT, "decisions/ADR-034-audit-verifier-cli.md");
const CLI_DIR = path.join(ROOT, "crates/tracelane-audit-cli");

describe("PP-AUDIT-TAMPER-DETECT: tracelane-audit CLI (ADR-034)", () => {
  it("1. ADR-034 ships with the CLI surface + exit-code contract", () => {
    const adr = fs.readFileSync(ADR, "utf8");
    expect(adr).toContain("tracelane-audit verify");
    expect(adr).toContain("--workspace");
    expect(adr).toContain("--from");
    expect(adr).toContain("--to");
    expect(adr).toContain("--file");
    // Exit code contract.
    expect(adr).toMatch(/`0`.*PASS/);
    expect(adr).toMatch(/`1`.*FAIL/);
    expect(adr).toMatch(/`2`.*I\/O/);
    // PDF deferral acknowledged.
    expect(adr).toContain("PDF");
    expect(adr).toContain("V1.1");
  });

  it("2. CLI crate + Cargo.toml ship and are wired into the workspace", () => {
    const cargo = fs.readFileSync(path.join(CLI_DIR, "Cargo.toml"), "utf8");
    expect(cargo).toContain('name = "tracelane-audit"');
    expect(cargo).toContain('name = "tracelane-audit"');
    // Reuses the shipped verifier — no duplication.
    expect(cargo).toContain("tracelane-audit-verifier");
    // Minimal posture for single-binary distribution.
    expect(cargo).toContain("ureq");
    expect(cargo).toContain("clap");
    // Workspace registration.
    const wsCargo = fs.readFileSync(path.join(ROOT, "Cargo.toml"), "utf8");
    expect(wsCargo).toContain('"crates/tracelane-audit-cli"');
  });

  it("3. Main implements verify subcommand + exit-code contract + offline mode", () => {
    const main = fs.readFileSync(
      path.join(CLI_DIR, "src/main.rs"),
      "utf8",
    );
    // Subcommand surface.
    expect(main).toMatch(/enum Command \{[\s\S]*Verify/);
    expect(main).toContain("VerifyArgs");
    // Exit code contract literal mapping.
    expect(main).toContain("ExitCode::from(0)");
    expect(main).toContain("ExitCode::from(1)");
    expect(main).toContain("ExitCode::from(2)");
    // Offline file path.
    expect(main).toContain("fn fetch_audit_range");
    expect(main).toContain("--file");
    // Pinned pubkey size check (R1 H2).
    expect(main).toContain("32 bytes");
    // Tamper-detect test fixture is present in the CLI's own unit suite.
    expect(main).toContain("offline_file_mode_fails_on_tampered_row_hash");
  });

  it("4. Release workflow ships 4 targets + Cosign + SBOM + SLSA L3 + Trusted Publishing", () => {
    const wf = fs.readFileSync(
      path.join(ROOT, ".github/workflows/release-audit-cli.yml"),
      "utf8",
    );
    // Four targets per ADR-034.
    expect(wf).toContain("x86_64-unknown-linux-musl");
    expect(wf).toContain("x86_64-apple-darwin");
    expect(wf).toContain("aarch64-apple-darwin");
    expect(wf).toContain("x86_64-pc-windows-msvc");
    // Cosign keyless signing.
    expect(wf).toContain("sigstore/cosign-installer");
    expect(wf).toContain("cosign sign-blob --yes");
    // SBOM.
    expect(wf).toContain("anchore/sbom-action");
    expect(wf).toContain("cyclonedx-json");
    // SLSA L3 reusable workflow.
    expect(wf).toContain("slsa-framework/slsa-github-generator");
    expect(wf).toContain("generator_generic_slsa3.yml");
    // Trusted Publishing crates.io.
    expect(wf).toContain("environment: crates-io");
    expect(wf).toContain("cargo publish -p tracelane-audit");
    // Every action SHA-pinned (ADR-008).
    expect(wf).toMatch(/sigstore\/cosign-installer@[0-9a-f]{40}/);
    expect(wf).toMatch(/anchore\/sbom-action@[0-9a-f]{40}/);
    expect(wf).toMatch(/slsa-framework\/slsa-github-generator\/.+@[0-9a-f]{40}/);
  });

  it("5. Audit retention floor is hardcoded at 180 days with fail-loud override guard", () => {
    const ret = fs.readFileSync(
      path.join(ROOT, "crates/gateway/src/audit_retention.rs"),
      "utf8",
    );
    expect(ret).toContain("AUDIT_ADDON_MIN_RETENTION_DAYS: i32 = 180");
    expect(ret).toContain("pub fn resolve_audit_retention");
    // Fail-loud assertion when an override would go below the floor.
    expect(ret).toContain("assert!");
    expect(ret).toContain("contractual_override");
    expect(ret).toContain("AUDIT_ADDON_MIN_RETENTION_DAYS");
    // Module is registered in the gateway binary.
    const main = fs.readFileSync(
      path.join(ROOT, "crates/gateway/src/main.rs"),
      "utf8",
    );
    expect(main).toContain("mod audit_retention;");
  });
});

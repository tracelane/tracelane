<!-- tracelane:classification: PUBLIC -->
# Changelog

All notable changes to `@tracelanedev/audit-verifier` are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/); this package
is versioned in lockstep with the Rust and Python reference verifiers.

## [0.3.0] - 2026-09-01

### Security
- **An anchor that could not be checked no longer reads as verified.** When a ledger
  carries anchor records but no trusted `tenantPubkey` is supplied, signature and
  anchor verification does not run. Those anchors were previously skipped in silence
  while the report could still carry `signatures_valid: true`, leaving a caller no way
  to tell an unchecked anchor from a verified one. The report now carries
  `anchors_unverified`; a non-zero value means `signatures_valid` is vacuous and a
  caller must not report a pass. Exercised by the `forged-anchor` conformance vector.

### Added
- `anchors_unverified` on the verification report.

## [0.2.3] - 2026-08-01

### Changed
- Version-only release. No source changes since 0.2.1 — re-cut because the 0.2.2
  tag published this package but produced no signed release artifacts (the
  release job could not resolve one of its pinned actions). 0.2.3 is the same
  code from a release that carries a GitHub Release, Cosign signatures and an SBOM.
  A verified SLSA Level 3 attestation is not claimed - the slsa-github-generator
  final job fails even on successful releases.

## [0.2.2] - 2026-08-01

### Changed
- Version-only release. No source changes since 0.2.1 — re-cut so the published
  artifact comes from the signed-tag release path, which v0.2.1 never reached
  (no GitHub Release, Cosign signature, SBOM, or SLSA provenance was produced).

## [0.2.1] - 2026-07-25

### Fixed
- **Windowed verify.** A retention-windowed ledger — one whose genesis
  (seq 0) has aged out of the loaded window — now verifies **GREEN** when it is
  rooted at a publicly-included Rekor anchor batch inside the window, instead of
  reporting a false **RED** (`seq_out_of_order`, "expected seq 0"). `verifyChain`
  keys on the minimum loaded seq: `0` → full genesis verify (unchanged); `> 0` →
  windowed verify rooted at the earliest resolved anchor, with `verified_from_seq`
  set to that anchor's batch-start (rows before it are present-but-unverified). A
  windowed ledger with **no** resolved in-window anchor stays RED
  (`unrooted_window`) — never falsely green. `VerifyReport` gains
  `verified_from_seq` and `trust_established`.

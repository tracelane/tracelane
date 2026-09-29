<!-- tracelane:classification: PUBLIC -->
# Changelog

All notable changes to `tracelane-audit-verifier` are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/); this package
is versioned in lockstep with the Rust and TypeScript reference verifiers.

## [Unreleased]

### Added
- **Platform-signed batches.** A workspace's batches are signed by
  Tracelane's shared platform key until the workspace has its own audit key. A new
  `platformPubkey` option (Rust `with_platform_pubkey`, Python `platform_pubkey`)
  verifies those batches and reports them apart — `platform_signed_batches` and
  `platform_signed_ranges` — instead of rejecting them as `untrusted_tenant_key`.
  The production platform key is pinned as `TRACELANE_PLATFORM_PUBKEY_B64`.

### Security
- The platform key is accepted only **before** a workspace's first workspace-signed
  batch. A platform-signed batch after it fails with the new error kind
  `platform_key_after_workspace_key`. Shared conformance vectors:
  `evals/audit-ledger/platform-*.ndjson`, `workspace-then-platform.ndjson`.
- A new option, `workspaceKeySinceSeq` (the `workspace_key_since_seq` published by
  `GET /v1/audit/pubkey`), holds the same rule when the verified range contains no
  workspace-signed batch at all; a platform-signed batch never roots a windowed verify;
  a platform-signed copy of a workspace-signed batch (same start) fails.
- The pinned platform keys are a list, `TRACELANE_PLATFORM_PUBKEYS_B64`, so a rotation
  keeps verifying the batches the retired key signed.

## [0.3.0] - 2026-09-01

### Security
- **An anchor that could not be checked no longer reads as verified.** When a ledger
  carries anchor records but no trusted tenant public key is supplied, signature and
  anchor verification does not run. Those anchors were previously skipped in silence
  while the report could still carry `signatures_valid: true`, leaving a caller no way
  to tell an unchecked anchor from a verified one. The report now carries
  `anchors_unverified`; a non-zero value means `signatures_valid` is vacuous and a
  caller must not report a pass. Exercised by the `forged-anchor` conformance vector.

### Added
- `anchors_unverified` on the verification report.

### Changed
- `cryptography` floor raised from 49.0.0 to 50.0.0.

## [0.2.3] - 2026-08-01

### Changed
- Version-only release. No source changes since 0.2.1 — re-cut because the 0.2.2
  tag published this package but produced no signed release artifacts (the
  release job could not resolve one of its pinned actions). 0.2.3 is the same
  code from a release that carries a GitHub Release, Cosign signatures and an SBOM.
  Release artifacts are signed with
  Sigstore cosign.

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
  reporting a false **RED** (`seq_out_of_order`). `_verify_anchors_offline` now
  runs before `_verify_chain` and returns the per-tenant included-anchor starts;
  `_verify_chain` keys on the minimum loaded seq (`0` → full genesis verify,
  unchanged; `> 0` → windowed, rooted at the earliest resolved anchor). A windowed
  ledger with **no** resolved in-window anchor stays RED (`unrooted_window`) —
  never falsely green. `VerifyReport` gains `verified_from_seq` and
  `trust_established`. Restores byte-parity with the Rust and TypeScript verifiers.

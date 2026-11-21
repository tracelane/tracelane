<!-- tracelane:classification: PUBLIC -->
# Changelog

All notable changes to `tracelane-audit-verifier` (Rust reference verifier) are
documented here. Versioned in lockstep with the TypeScript and Python verifiers.

## [Unreleased]

### Added
- **`actions.refused_workspace_paused` in the action report.** Counts `denied_runtime` rows with reason `workspace_paused`: distinct protected tool calls a paused workspace refused. Other refusal reasons are not counted. The field is new in the serialized report; it is 0 for a bundle with no such rows.
- **Action evidence bundles (`action` module).** Offline verification of an action-control
  evidence ZIP against an externally supplied workspace public key: the hashed manifest, the
  chain from genesis, the signed covering head (which must equal the last row), and the
  recorded action sequence. A key embedded in the bundle is never accepted as the trust root.
  An execution with an unknown outcome is reported as UNKNOWN, never as success.
  `action::bundle::Failure` and `FailureKind` are `#[non_exhaustive]`; match `FailureKind`
  with a wildcard arm. Crate version 0.3.0 (the lockstep version with the TypeScript and
  Python verifiers is set at release).
- **Tool-server countersignatures in action bundles (`action::receipt`).** When the ledger
  holds a receipt-key registration for a tool server (`tool_receipt_key_registered`), every
  successful execution on that server that starts after it must carry the tool server's
  Ed25519 signature over the attestation digest, its execution, action, request digest, tenant
  and server, its receipt id and the outcome (domain `tracelane.tool-receipt.v3`). A success row with a missing, replayed or non-verifying countersignature
  fails the bundle; the gateway records such calls as unknown. The report counts `countersigned`
  and `uncountersigned` successes. A countersignature shows that the registered key signed;
  the verifier cannot tell who holds that key.
- **Action bundle COSE statement (`action::cose`).** An optional `checkpoint.cose` member, a
  COSE_Sign1 (RFC 9052) over the exact bytes of `checkpoint.json`, is verified under the same
  external workspace key and reported as `cose_statement`. Header layout aligned to the
  Signed Statement format of draft-ietf-scitt-architecture-22; no Receipt, and no
  conformance claim. No new runtime dependency.
- **Checkpoint chain and gap report.** Action bundles may carry `checkpoints.ndjson`, the signed
  checkpoint chain ending at the covering head, plus `timestamps/<sha256>.tsr` tokens. The
  verifier checks every signature, link, time and sequence order, and reports the checkpoint
  count, the longest interval and, with `verify_with_options` / CLI `--max-gap`, every longer
  interval as a gap. Exports carry the most recent window of the chain (up to 2000
  checkpoints); the report states where it starts (`chain_start`) and whether it reaches
  the first checkpoint (`from_genesis`). `--max-gap` on a bundle without the chain fails.
  Verifiers built before this member existed reject such bundles; use 0.3.0 or later.
- **`tool_definition_changed` refusal reason.** A protected tool call refused because the
  tool's live definition no longer matches its approved pin is recorded as a signed
  `denied_runtime` event with this reason, and the verifier accepts it. Verifiers built before this
  reason existed reject such a bundle (the reason vocabulary is closed), so verify these bundles
  with 0.3.0 or later.
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
  (seq 0) has aged out of the loaded window — now verifies **GREEN** when rooted
  at a publicly-included Rekor anchor batch inside the window, instead of a false
  **RED** (`seq_out_of_order`). `verify_chain` keys on the minimum loaded seq
  (`0` → full genesis verify, unchanged; `> 0` → windowed, rooted at the earliest
  resolved anchor). `verified_from_seq` is the report-level LATEST per-tenant
  anchor batch-start; a windowed ledger with no resolved in-window anchor stays
  RED (`unrooted_window`). `VerifyReport` gains `verified_from_seq` and
  `trust_established`.

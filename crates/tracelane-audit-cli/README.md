<!-- tracelane:classification: PUBLIC -->
# tracelane-audit

Public verifier CLI for Tracelane tamper-evident agent ledgers. It verifies a
ledger you already hold **offline and independently** — a third party can run it
on a fresh Linux box with no Node, no Python, no network access, and no Tracelane
account. The trust root is the workspace's Ed25519 public key you obtain
out-of-band, not anything inside the export.

See the audit-format documentation for the full design rationale.

## Install

### Published verifiers (recommended for auditors)

The offline verifier ships as a package, not as a standalone binary:

```bash
npm  install -g @tracelanedev/audit-verifier     # Node
pip  install    tracelane-audit-verifier         # Python
```

Both are published from the release workflow — npm with `--provenance`, PyPI via
Trusted Publishing (OIDC, no long-lived token). Release **artifacts** are
Cosign-signed keyless and carry a CycloneDX SBOM; build provenance is attested with
GitHub `attest-build-provenance`. A verified **SLSA Level 3** attestation is *not*
claimed — see [SECURITY.md](../../SECURITY.md).

### From source

```bash
cargo build --release -p tracelane-audit
./target/release/tracelane-audit --help
```

This crate is **not** published to crates.io and no `tracelane-audit-<target>` binary is
attached to GitHub Releases today — the release workflow builds the gateway binaries and
publishes the npm/PyPI verifiers. Build from source or use a published verifier above.

## Usage

```bash
# Online — fetch from the Tracelane API
tracelane-audit verify \
  --workspace 00000000-0000-0000-0000-00000000000a \
  --from 2026-05-01T00:00:00Z \
  --to   2026-05-26T00:00:00Z \
  --api-url https://api.tracelane.dev \
  --read-key tlane_audit_read_... \
  --tenant-pubkey I5rZ...workspace-ed25519-pubkey-base64

# Offline — verify a local export. --tenant-pubkey is the trust root.
tracelane-audit verify --file ./my-audit-range.ndjson \
  --tenant-pubkey I5rZ...workspace-ed25519-pubkey-base64

# JSON output for piping
tracelane-audit verify --file ./my-audit-range.ndjson \
  --tenant-pubkey I5rZ... --format json | jq
```

**Without `--tenant-pubkey` the anchor layer does not run at all**, so a forged anchor would not be caught. The verifier therefore exits **non-zero with `INCOMPLETE`** when a ledger carries anchor records and no trusted key was supplied. Obtain the key out-of-band (dashboard Settings → Audit signing key, or `GET /v1/audit/pubkey`) — never from the export you are auditing.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | PASS — every check passed. |
| 1 | FAIL — at least one check failed; output includes field-level diffs. |
| 2 | I/O or network failure before verification could run. |

## What gets verified

Four independent cryptographic checks, all bundled into one
`VerifyReport`:

1. **Hash chain replay** — recompute every `row_hash` from
   `(tenant_id, seq, event_type, actor, payload, prev_hash)` and
   verify each row's `prev_hash` matches the previous row's
   recomputed hash.
2. **Sequence monotonicity** — `seq` starts at zero (or the per-
   tenant resume point) and increments by 1 on every row.
3. **Merkle root recomputation** — for each Rekor anchor, recompute
   the RFC 6962 §2.1 Merkle root over the anchored rows' hashes and
   verify it matches the root signed in the Rekor entry's
   `hashedrekord` body.
4. **Ed25519 signature verification** — verify the signed payload
   from step 3 against either (a) the pubkey embedded in the Rekor
   body or (b) a pinned operator-supplied pubkey
   (`--pinned-pubkey`).

If any check fails, the verifier prints a field-level diff
identifying the offending `seq` + which check failed.

## V1 launch deferrals

- `--format pdf` (a printable rendering of the verification report) is
  queued for V1.1. The `text` and `json` formats carry the
  full report today.

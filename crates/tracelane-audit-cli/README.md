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

## Output formats

`text` and `json` carry the full verification report. A PDF format is not available.

## Control-mapping pack

Source-built Rust CLI only; the npm and PyPI verifiers do not provide this command.

```bash
tracelane-audit evidence-pack --file evidence.zip --pubkey tenant-public-key.txt --out pack/
```

Add `--require-tree` to `verify` or `evidence-pack` when a verified signed tree
checkpoint is required. The option applies to local action ZIPs only. A missing
checkpoint fails with exit code 4 and writes no evidence pack; an invalid note
still fails its signature, tenant, size or root checks. Without the option, older
bundles retain the explicit `tree checkpoint: absent` report. This requirement
does not establish that every action was recorded.

The command runs the same offline action-ZIP verification as `verify`. If verification fails it exits with the same code and writes nothing. If it passes it writes three files into a new or empty directory: `controls.csv`, `oscal-component-definition.json` (OSCAL 1.1.2) and `summary.html`.

The pack maps a fixed, reviewed list of control topics (`evidence/control-map.json`: EU AI Act Articles 12 and 19, OCC Bulletin 2026-54, the FINOS AI Governance Framework and the RBI FREE-AI report) to what one verified bundle carries. Each row is `partial` or `not covered`, names the bundle evidence and the source line of the check, and states its gap.

**It is a mapping, not an assessment.** It carries no per-record inclusion proof and no signed attestation that a time range holds every record. A verified bundle shows that rows 0 to the signed head are contiguous under the key you supplied; it does not show that every event was recorded. Every output file repeats these limits. Requirement text is paraphrased; read the source before relying on a row.

## Action ZIP timestamps

Gateway timestamp acquisition: **In development, not yet available**. The source-built Rust verifier supports the offline checks below; the npm and PyPI verifiers do not provide this action-ZIP timestamp command.

The Rust action-bundle verifier accepts an optional `checkpoint.tsr` RFC 3161 response. The CLI checks it without network access:

```bash
tracelane-audit verify --offline --file evidence.zip --pubkey tenant-public-key.txt \
  --tsa-cert independently-obtained-tsa.der
```

Repeat `--tsa-cert` for multiple trusted TSA leaf certificates (DER or PEM). Obtain these public certificates independently; certificates embedded in the bundle do not establish trust. A missing token reports `timestamped: false` and JSON `gen_time: null`. A valid token reports `timestamped: true` and the TSA's authenticated generation time. A well-formed token without a matching external TSA pin reports `timestamped: false`, `timestamp_reason: "tsa_unpinned"` and `gen_time: null`. A wrong imprint or malformed token fails. A pin matches only when it is the exact certificate the token binds (issuer, serial and SigningCertificateV2 hash); a token whose binding names no supplied pin reports `tsa_unpinned`, the same as a stripped token, because the bundle manifest is unsigned. When a pin matches, signature, purpose and validity failures fail. A `--tsa-cert` that is not a PEM or DER X.509 certificate is a trust-input error (exit 5). The supported signature algorithms are RSA PKCS#1 SHA-256 and ECDSA P-256 SHA-256, with SHA-256 imprint and SigningCertificateV2 binding.

Certificate validity is checked at generation time, including fractional seconds. Historical tokens can remain valid after a certificate later expires. No online revocation status is fetched or claimed. These options require a local action ZIP. Timestamp validation failures use exit code 4; the tenant checkpoint key's missing/wrong trust uses code 5. Older action-bundle verifier versions reject the new optional member; use a version supporting timestamp responses for these exports.

Bundles also carry `checkpoints.ndjson`: every signed checkpoint for the workspace, in order, ending at the covering head, with optional `timestamps/<sha256 of statement>.tsr` tokens. The verifier checks each signature against the same pinned key, each link to the previous checkpoint, that time and sequence never go backwards, and that an equal sequence never carries a different head hash; any break fails. It reports the number of checkpoints and the longest interval between two. Add `--max-gap SECONDS` to list every longer interval as a gap: a period in which the recorder signed nothing. Set it to your heartbeat cadence plus slack. A gap shows missing signed evidence of liveness; it does not by itself prove that records were lost. An export carries the most recent window of the chain (up to 2000 checkpoints); the report gives the signed start of that window and says whether it reaches the workspace's first checkpoint, and gaps are measured only inside it. A bundle without the member reports the chain as absent, and `--max-gap` on such a bundle fails rather than passing unchecked.

## Action ZIP COSE statement

The gateway includes this member in every action evidence bundle it exports. The source-built Rust verifier supports the offline check below; the npm and PyPI verifiers do not read action ZIPs.

The Rust action-bundle verifier accepts an optional `checkpoint.cose` member: a COSE_Sign1 message (RFC 9052) whose payload is the exact bytes of `checkpoint.json`, signed with the same workspace Ed25519 key. Its protected header carries the algorithm (EdDSA), content type `application/json`, a `kid` equal to the checkpoint `key_id`, and CWT Claims with `iss` (`urn:uuid:<workspace id>`) and `sub` (`tracelane.action-head.v1`). The header layout is aligned to the Signed Statement format of draft-ietf-scitt-architecture-22. It is a signed statement only: there is no Receipt and no Transparency Service registration, and no conformance with that draft is claimed.

The check uses the same external `--pubkey` and no network access. A member that verifies reports `COSE statement: true` (JSON `cose_statement: true`). A bundle without the member reports `false`; the bundle manifest is unsigned, so a removed member cannot be told apart from one never produced. A member that is not the expected encoding of `checkpoint.json` fails with exit code 4, and one whose signature does not verify under the supplied key fails with code 5. `checkpoint.sig` is still required and checked first. Older action-bundle verifier versions reject the new optional member.

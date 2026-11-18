<!-- tracelane:classification: PUBLIC -->
# `packages/verifier-rust`

Reference verifier for Tracelane **tamper-evident audit ledgers** (Rust).

Reads an NDJSON ledger (one `AuditRow` per line) and produces a deterministic
`VerifyReport` with four independent checks:

1. **Hash-chain replay** — recompute every `row_hash` from the canonical format and verify each row's `prev_hash` matches the previous row's recomputed hash.
2. **Sequence continuity** — per-tenant `seq` is gap-free and monotonic.
3. **Signature** (when present) — Ed25519 over the chain head.
4. **Anchor** (when present) — Sigstore Rekor inclusion proof.

## Format versions
- **v2.1 (current):** `payload` is the **verbatim stored canonical JSON string** (the exact `row_hash` preimage), SHA-256'd byte-for-byte and never re-derived. The Rust / TypeScript / Python NDJSON verifiers hash the same stored bytes; they do not independently re-derive numeric JSON for v2.1.
- **v2 (legacy re-derive):** length-prefixed, domain-separated framing; kept read-only for pre-v2.1 exports.

## Install

This crate is **not published to crates.io**. Use it as a path dependency from a
checkout of this repository:

```toml
[dependencies]
tracelane-audit-verifier = { path = "packages/verifier-rust" }
```

The published verifiers are
[`@tracelanedev/audit-verifier`](https://www.npmjs.com/package/@tracelanedev/audit-verifier)
(npm) and [`tracelane-audit-verifier`](https://pypi.org/project/tracelane-audit-verifier/)
(PyPI). Their shared NDJSON conformance corpus checks matching verification verdicts.

The shared NDJSON conformance vectors for Rust, `verifier-typescript` and
`verifier-python` live in
`../../evals/audit-ledger/`.

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

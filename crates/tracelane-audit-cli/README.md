# tracelane-audit

Public verifier CLI for Tracelane tamper-evident agent ledgers. Built
to support **EU AI Act Article 12** independent verification by an
auditor running a fresh Linux box — no Node, no Python, no Tracelane
account required to inspect a ledger you already hold.

See [ADR-034](../../decisions/ADR-034-audit-verifier-cli.md) for the
full design rationale and [the compliance docs](../../apps/docs/compliance/eu-ai-act-article-12.mdx)
for Article 12 field mapping.

## Install

### Pre-built binaries (recommended for auditors)

Download from [GitHub Releases](https://github.com/tracelane/tracelane/releases?q=tracelane-audit).
Each release ships:

- `tracelane-audit-x86_64-unknown-linux-musl` (static, no glibc dependency)
- `tracelane-audit-x86_64-apple-darwin`
- `tracelane-audit-aarch64-apple-darwin`
- `tracelane-audit-x86_64-pc-windows-msvc.exe`

Each binary is:

- **Cosign-signed (keyless)** via GitHub Actions OIDC. Verify with
  `cosign verify-blob --bundle <bundle> <binary>`.
- **SLSA Build Level 3 provenance.** Verify with
  `slsa-verifier verify-artifact --provenance-path <provenance.intoto.jsonl> <binary>`.
- **CycloneDX SBOM** attached as a release asset.

### From crates.io

```bash
cargo install tracelane-audit
```

## Usage

```bash
# Online — fetch from the Tracelane API
tracelane-audit verify \
  --workspace 00000000-0000-0000-0000-00000000000a \
  --from 2026-05-01T00:00:00Z \
  --to   2026-05-26T00:00:00Z \
  --api-url https://api.tracelane.dev \
  --read-key tlane_audit_read_...

# Offline — verify a local export
tracelane-audit verify --file ./my-audit-range.ndjson --offline

# JSON output for piping
tracelane-audit verify --file ./my-audit-range.ndjson --format json | jq
```

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

## Article 12 conformance

Tracelane publishes a written conformance statement at
[`/docs/audit/conformance-statement`](../../apps/docs/audit/conformance-statement.mdx)
mapping each Article 12 obligation to a Tracelane mechanism. A
field-level table of how Article 12(2)(a)–(c) and 12(3)(a)–(d) map
to the verifier checks lives at
[`/docs/compliance/eu-ai-act-article-12`](../../apps/docs/compliance/eu-ai-act-article-12.mdx).

## V1 launch deferrals

- `--format pdf` (regulator-ready conformance packet) is queued for
  V1.1 per ADR-034. The `text` and `json` formats cover the
  regulator-runnable contract for V1.

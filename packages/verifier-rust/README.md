# `packages/verifier-rust`

Reference verifier for Tracelane **tamper-evident audit ledgers** (Rust).

Reads an NDJSON ledger (one `AuditRow` per line) and produces a deterministic
`VerifyReport` with four independent checks:

1. **Hash-chain replay** — recompute every `row_hash` from the canonical format and verify each row's `prev_hash` matches the previous row's recomputed hash.
2. **Sequence continuity** — per-tenant `seq` is gap-free and monotonic.
3. **Signature** (when present) — Ed25519 over the chain head.
4. **Anchor** (when present) — Sigstore Rekor inclusion proof.

## Format versions
- **v2.1 (current, ADR-050):** `payload` is the **verbatim stored canonical JSON string** (the exact `row_hash` preimage), SHA-256'd byte-for-byte and never re-derived. This makes the Rust / TypeScript / Python verifiers **identical by construction** — the numeric-canonicalization parity bug class cannot exist.
- **v2 (legacy re-derive):** length-prefixed, domain-separated framing; kept read-only for pre-ADR-050 exports.

This is the canonical implementation; `verifier-typescript` and
`verifier-python` are byte-for-byte equivalents. Conformance vectors live in
`../../evals/audit-ledger/`. ~11 public items.

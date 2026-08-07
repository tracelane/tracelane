<!-- tracelane:classification: PUBLIC -->
# Tracelane Tamper-Evident Audit Log Format

**Version:** 1.0  
**Status:** V1 — production

---

## Overview

Tracelane maintains a tamper-evident, hash-chained audit log of AI agent
interactions. Every event is chained by SHA-256 to the event before it, batch
Merkle roots are signed with a per-tenant Ed25519 key, and anchored batches
carry a Sigstore Rekor v2 inclusion proof on a best-effort basis.

The point of the format is that the evidence stands on its own. The preimage is
fully specified below, so a third party holding the tenant public key can verify
an exported chain offline — with their own implementation if they prefer, or
with one of the three open-source verifiers (Rust, TypeScript, Python) that
recompute exactly these hashes.

Tracelane makes **no claim that this format satisfies any named compliance
framework** — there is no certification and no third-party attestation behind
it. What it produces is a record an outside party can check independently;
whether that record meets a particular obligation is a determination for you and
your auditor.

---

## Hash chain structure

Each audit event computes a SHA-256 row hash that chains to the previous event:

```
row_hash = SHA256(
  "tracelane-audit-row-v2\0"        // domain separator
  || len(tenant_id) || tenant_id     // 16 raw UUID bytes
  || seq                             // u64, big-endian, NOT length-prefixed
  || len(event_type) || event_type
  || len(actor)      || actor
  || len(payload)    || payload      // RFC 8785 (JCS) canonical JSON
  || len(prev_hash)  || prev_hash    // 32 raw bytes
)
```

Every variable-length field is **length-prefixed** (`u64` big-endian length, then the
bytes), and the whole preimage is **domain-separated** by the `tracelane-audit-row-v2\0`
tag. That framing is what makes field-boundary collisions impossible — a crafted `actor`
cannot be made to impersonate part of the payload. `seq` is fixed-width and therefore not
prefixed. For `seq = 0`, `prev_hash` is the genesis seed, which is fully determined by the tenant:

```
genesis_prev_hash = SHA256( "tracelane-audit-v2-genesis\0" || tenant_id )
```

(16 raw UUID bytes, **not** length-prefixed here.) A third-party verifier can therefore
reconstruct row 0 from this document alone.

Reference implementation: `row_hash_v2` in
`crates/gateway/src/audit_format/mod.rs`. The three open-source verifiers
(`packages/verifier-{rust,typescript,python}`) recompute exactly this.

Every 100 events (`TRACELANE_REKOR_ANCHOR_EVERY`, default `100` —
`crates/gateway/src/server.rs:93-96`) the Merkle root over all row hashes in the
batch is computed and signed with Ed25519. **Anchoring that root to a public
transparency log is best-effort, and off unless configured.** The gateway POSTs
only when `TRACELANE_REKOR_URL` is set — unset or empty means sign-and-persist
locally, never an external POST (`crates/gateway/src/audit.rs:1499-1503`) — and
anchoring additionally needs a mintable per-tenant ECDSA anchor key, which is
Audit-add-on gated (`audit.rs:1523-1528`). When either is absent, or the log is
unreachable, the batch stays signed-but-unanchored (`anchor_state = 0x00`) and
the offline verifier reports it as unanchored rather than failing.

The anchoring target is Sigstore Rekor **v2** —
`log2025-1.rekor.sigstore.dev` (`crates/tracelane-audit-cli/src/main.rs:95`,
`packages/verifier-rust/src/lib.rs:534`) — a public, append-only transparency log
operated by the Linux Foundation. The legacy v1 host `rekor.sigstore.dev` is a
**different log with an independent index space**; a v2 entry ID does not resolve
there.

---

## Audit event schema

```json
{
  "tenant_id": "string (UUID)",
  "seq": "uint64 (monotonic per tenant)",
  "event_time": "ISO-8601 timestamp (microsecond precision, UTC)",
  "event_type": "request | intervention | export | key_rotation | policy_change",
  "actor": "string (JWT sub claim — never from request body)",
  "payload": {
    "trace_id": "string (UUID, present for request/intervention events)",
    "span_id": "string (UUID, present for intervention events)",
    "provider": "string (e.g. openai, anthropic)",
    "model": "string (model ID)",
    "input_tokens": "uint32",
    "output_tokens": "uint32",
    "aft_ids": ["string"],
    "intervention": "none | warn | block",
    "latency_ms": "float"
  },
  "prev_hash": "string (SHA-256 hex of previous row; for seq=0 the genesis seed above, never empty)",
  "row_hash": "string (SHA-256 hex of this row)",
  "rekor_entry_id": "string (Rekor v2 entry ID — OPTIONAL: the key is omitted entirely, not null, on any batch that did not anchor)"
}
```

`rekor_entry_id` is `skip_serializing_if = "Option::is_none"`
(`crates/gateway/src/audit_export.rs:98`), so its **absence** is the normal
unanchored case — a verifier must treat a missing key as "not anchored", not as a
malformed row (test: `export_row_skips_rekor_when_none`, `audit_export.rs:1142`).

---

## Verification

### Verify the hash chain locally

```bash
tlane verify ./audit.ndjson --tenant-pubkey <base64>
```

This recomputes all row hashes and verifies the chain is unbroken.

### Verify a batch anchor

An anchored batch exports an ANCHOR record (discriminated by `"type":"anchor"`;
`crates/gateway/src/audit_export.rs:103-104`) carrying the entry signature,
inclusion proof and checkpoint. The same command checks it:

```bash
tlane verify ./audit.ndjson --tenant-pubkey <base64>
```

For an anchored batch this verifies three layers offline: the ECDSA-P256 entry
signature, the RFC 6962 inclusion proof, and the C2SP checkpoint against the
pinned `log2025-1` key (`packages/verifier-rust/src/lib.rs:1119-1227`).

The digest the log stores is **not** the Merkle root — it is
`SHA-256("tracelane-anchor-ecdsa-v1\0" || merkle_root)`
(`crates/gateway/src/audit.rs:241-247`), so a hand-rolled lookup keyed on the bare
root hex will not match. A batch with no anchor record verifies as
signed-but-unanchored, which is a reported state, not a failure.

---

## EU AI Act Article 12 export

Generate a compliance evidence pack:

```bash
tlane export --pack eu-ai-act-art12 --output-dir ./compliance-pack/
```

The pack includes:
1. `art12-01-audit-chain.md` — hash chain summary and Rekor entry UUIDs
2. `art12-02-ai-disclosure.md` — AI system disclosure statement
3. `art12-03-model-registry.json` — registry of all AI models used
4. `art12-04-data-processing.md` — data sources, retention, PII handling
5. `art12-05-guardrail-evidence.md` — predictive guardrail implementation evidence
6. `art12-06-rekor-transparency.md` — Sigstore Rekor entries
7. `manifest.json` — machine-readable pack manifest

---

## Pricing

| Tier | Audit log retention |
|---|---|
| Free hosted ($0) | 7 days |
| Builder ($59) | 30 days |
| Team ($249) | 90 days |
| Business ($899) | 180 days |
| Enterprise (from $2,999) | 365 days |

Source: `apps/web/db/seed.mjs:60-153`. `retention_days` is a plain integer column,
set per plan and overridable per workspace
(`COALESCE(we.retention_days, pe.retention_days)` —
`crates/gateway/src/entitlement_cache.rs:525`). **There is no multi-year retention
tier and no year-scale configuration mechanism** — 365 days is the highest value
configured anywhere in the repo.

**Audit-log export requires the Audit add-on (+$999/mo) on every tier, Enterprise
included.** `GET /v1/audit/export` and `GET /v1/audit/summary` check
`FeatureKey::AuditAddon` before any ClickHouse read
(`crates/gateway/src/audit_export.rs:827,892`), and `f_audit_addon` defaults to
FALSE on every plan (`apps/web/db/schema.ts:163`) and is seeded on none — it is a
per-tenant flag grant, not a plan default (`apps/web/db/seed.mjs:12-16`). Without
it those endpoints return an entitlement-required error, not a reduced export. No
base tier carries self-serve export.

The add-on delivers:
- Per-tenant Ed25519-signed Merkle roots, with best-effort Sigstore Rekor v2 anchoring on the terms in [Hash chain structure](#hash-chain-structure) above
- Offline verification by a third party, with no Tracelane account

Timestamps come from the gateway host's clock, plus the Rekor entry time on batches
that actually anchored. Tracelane makes **no eIDAS or qualified-timestamp claim** —
there is no QTSP integration.

---

## Implementation reference

- `crates/gateway/src/audit_format/mod.rs` — `row_hash_v2()`, `genesis_prev_hash()`, `merkle_root()` — **the v2 format this document specifies**
- `crates/gateway/src/audit.rs` — `AuditChain`, `RekorClient::anchor_batch()` (`:1536`) → `submit_anchor_v2()` (`:1633`).
  Note `compute_row_hash()` / `compute_merkle_root()` in this file are the **v1 format and are
  `#[deprecated]`** (`audit.rs:148,156,173`) — "vulnerable to field-boundary attacks". Do not
  implement against them.
- `packages/cli/src/commands/export.ts` — `tlane export --pack eu-ai-act-art12`
- `infra/dev/clickhouse/schema.sql` — `tracelane.audit_log` table

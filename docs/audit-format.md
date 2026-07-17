# Tracelane Tamper-Evident Audit Log Format

**Version:** 1.0  
**Status:** V1 — production  
**EU AI Act:** Article 12 (transparency and record-keeping for high-risk AI systems)  
**Enforcement date:** August 2, 2026

---

## Overview

Tracelane maintains a tamper-evident, hash-chained audit log of all AI agent
interactions. The audit log is designed to satisfy:

- **EU AI Act Article 12** — logging of high-risk AI system operations
- **India DPDP Phase II** — data processing records for Significant Data Fiduciaries
- **HIPAA 2025 amendments** — tamper-evident audit trails for healthcare AI
- **Treasury FS AI RMF** (230 controls) — audit evidence for financial AI systems

---

## Hash chain structure

Each audit event computes a SHA-256 row hash that chains to the previous event:

```
row_hash = SHA256(
  tenant_id || seq || event_type || actor || payload_json || prev_hash
)
```

Where `||` is byte concatenation with a null byte separator.

Every 100 events, the Merkle root over all row hashes in the batch is computed,
signed with Ed25519, and submitted to [Sigstore Rekor](https://rekor.sigstore.dev) —
a public, append-only transparency log operated by the Linux Foundation.

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
  "prev_hash": "string (SHA-256 hex of previous row, empty for seq=0)",
  "row_hash": "string (SHA-256 hex of this row)",
  "rekor_entry_id": "string | null (Rekor UUID, populated every 100 events)"
}
```

---

## Verification

### Verify the hash chain locally

```bash
tlane verify --tenant <tenant-id> --from <seq-start> --to <seq-end>
```

This recomputes all row hashes and verifies the chain is unbroken.

### Verify a Rekor anchor

```bash
rekor-cli verify \
  --uuid <rekor_entry_id> \
  --artifact-hash <merkle_root_hex>
```

Or via the Tracelane CLI:
```bash
tlane verify --tenant <tenant-id> --rekor-url https://rekor.sigstore.dev
```

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

| Tier | Audit log retention | Compliance export |
|---|---|---|
| Free / Builder ($59) | 30 days | Not included |
| Team ($249) | 90 days | Self-serve export |
| Business ($899) | 1 year | Self-serve export |
| Enterprise ($2,999+) | Configurable (3–7 years) | Full compliance pack |
| **Audit SKU ($999/mo)** | **Configurable** | **eIDAS-grade export, custom retention** |

The $999/mo Audit SKU delivers:
- eIDAS-grade qualified timestamps
- Custom retention periods up to 7 years
- Notarized Rekor anchors with certificate chain
- Per-export regulatory packets (priced by scope)
- Dedicated compliance engineer for first export

---

## Implementation reference

- `crates/gateway/src/audit.rs` — `AuditChain`, `compute_row_hash()`, `compute_merkle_root()`, `RekorClient::submit()`
- `packages/cli/src/commands/export.ts` — `tlane export --pack eu-ai-act-art12`
- `infra/dev/clickhouse/schema.sql` — `tracelane.audit_log` table

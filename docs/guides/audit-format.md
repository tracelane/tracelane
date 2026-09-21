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
`crates/gateway/src/server.rs:163-166`) the Merkle root over all row hashes in the
batch is computed and signed with Ed25519. **Anchoring that root to a public
transparency log is best-effort, and off unless configured.** The gateway POSTs
only when `TRACELANE_REKOR_URL` is set — unset or empty means sign-and-persist
locally, never an external POST (`crates/gateway/src/audit.rs:2598-2603`) — and
anchoring additionally needs a per-tenant ECDSA anchor key
(`audit.rs:2623-2679`, `store.get_or_create_anchor`). Minting that key is gated
on the `f_audit_selfverify` entitlement
(`crates/gateway/src/audit_keys.rs:398-415,486-524`), which defaults to true on
every plan and can be denied per workspace (`apps/web/db/schema.ts:315,412`),
so anchoring runs on every tier. When either the URL or the key is absent, or
the log is unreachable, the batch stays signed-but-unanchored
(`anchor_state = 0x00`) and the offline verifier reports it as unanchored
rather than failing.

The anchoring target is Sigstore Rekor **v2** —
`log2025-1.rekor.sigstore.dev` (`crates/tracelane-audit-cli/src/main.rs:95`,
`packages/verifier-rust/src/lib.rs:534`) — a public, append-only transparency log
operated by the Linux Foundation. The legacy v1 host `rekor.sigstore.dev` is a
**different log with an independent index space**; a v2 entry ID does not resolve
there.

---

## Audit event schema

One exported row, as `GET /v1/audit/export` writes it (`ExportRow`,
`crates/gateway/src/audit_export.rs:89-104`):

```json
{
  "format": "v2.1",
  "tenant_id": "string (UUID)",
  "seq": "uint64 (monotonic per tenant)",
  "event_time": "ISO-8601 timestamp (microsecond precision, UTC)",
  "event_type": "chat.completions.request | embeddings.request | messages.request | guardrail.verdict | eval.verdict",
  "actor": "string (the JWT sub claim, or apikey:<id> for an API key — never from the request body)",
  "payload": "string (the canonical JSON the row hash covers, verbatim — not a nested object)",
  "prev_hash": "string (SHA-256 hex of previous row; for seq=0 the genesis seed above, never empty)",
  "row_hash": "string (SHA-256 hex of this row)",
  "rekor_entry_id": "string (the Rekor v2 log index of the entry that anchored this row's batch — OPTIONAL: the key is omitted entirely, not null, on any batch that did not anchor)"
}
```

`format` is always `v2.1` for new exports (`audit_export.rs:81`): `payload` is
the stored canonical-JSON **string**, the exact `row_hash` preimage, so a
verifier hashes it byte-for-byte and never re-serialises it. `actor` is the
authenticated principal (`crates/gateway/src/admission.rs:757-762`;
`crates/gateway/src/auth/api_key.rs:58,109-112` for the `apikey:` form). What
the payload string contains depends on `event_type`:

| `event_type` | Written by | Payload keys |
|---|---|---|
| `chat.completions.request` | `POST /v1/chat/completions` admission (`admission.rs:825,851-864`) | `model`, `warn_aft_id`, `trace_id` |
| `embeddings.request` | `POST /v1/embeddings` admission (`admission.rs:901,923-933`) | `model`, `input_count`, `trace_id` |
| `messages.request` | `POST /v1/messages` admission (`crates/gateway/src/anthropic_messages.rs:936,979-990`) | `model`, `warn_aft_id`, `stream`, `trace_id` |
| `guardrail.verdict` | the guardrail recorder (`crates/gateway/src/guardrail/recorder.rs:103-109`) | the serialised guardrail verdict |
| `eval.verdict` | a prompt promotion or rollback (`crates/gateway/src/prompt_routes.rs:94-107`) | `prompt`, `promotion_id`, `from_env`, `to_env`, `to_version_id`, `decision`, `eval_run_id` |

The three `*.request` payloads gain a `business_reference` key only when the
request supplied one (`admission.rs:754-756`).

`rekor_entry_id` is `skip_serializing_if = "Option::is_none"`
(`crates/gateway/src/audit_export.rs:102`), so its **absence** is the normal
unanchored case — a verifier must treat a missing key as "not anchored", not as a
malformed row (test: `export_row_skips_rekor_when_none`, `audit_export.rs:1601`).

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

Generate the documentation pack:

```bash
tlane export --pack eu-ai-act-art12 --output-dir ./compliance-pack/
```

The pack is a set of documentation templates the CLI writes locally
(`packages/cli/src/commands/export.ts:48-90`). It reads no ledger and contacts
no server, so it accompanies your exported ledger rather than containing it.
Files:
1. `art12-01-audit-chain.md` — a description of the hash chain and anchoring mechanism (`export.ts:241-291`)
2. `art12-02-ai-disclosure.md` — the AI disclosure statement, copied from `AI_DISCLOSURE.md` when the command runs inside a checkout of this repository and marked `missing` in the manifest otherwise (`export.ts:292-314,512-526`)
3. `art12-03-model-registry.json` — a fixed example model registry, not the models your tenant used (`export.ts:315-369`)
4. `art12-04-data-processing.md` — a data-processing record template: data sources, retention, PII handling (`export.ts:370-407`)
5. `art12-05-guardrail-evidence.md` — a description of the guardrail implementation (`export.ts:408-443`)
6. `art12-06-rekor-transparency.md` — a description of the Rekor anchoring mechanism; it lists no entries (`export.ts:444-497`)
7. `manifest.json` — machine-readable pack manifest

---

## Pricing

> Retention is per plan and has three windows — an indexed window, a
> queryable-history window and a ledger window (`indexed_window_days`,
> `queryable_days`, `ledger_days`; `apps/web/db/schema.ts:330-332`) — sourced
> from `apps/web/db/plans.v3.json`. See [pricing](https://docs.tracelane.dev/pricing).

| Tier | Ledger/audit-log retention (ruled) |
|---|---|
| Free ($0) | 30 days queryable |
| Builder ($29/mo, $24 annual) | 2 years queryable |
| Team ($229/mo, $190 annual) | 2 years queryable |
| Business ($799/mo, $665 annual) | 2 years queryable |
| Enterprise (from $2,499/mo) | 7 years queryable |

Source: `apps/web/db/plans.v3.json` (`ledger_days` per plan) — the single
machine-readable source for these figures, cross-checked by
`scripts/ci/check-pricing-copy-vs-seed.py`. The gateway reads the per-plan
`indexed_window_days` / `queryable_days` / `ledger_days` columns
(`crates/gateway/src/entitlement_cache.rs:778-780`).

**There is no paid audit product.** The `tlane export --pack` templates above
are not plan-gated — the command takes no credential
(`packages/cli/src/commands/export.ts:548-590`); the bulk `GET /v1/audit/export`
route is Enterprise-only. `/v1/audit/export` is not sold as an evidence pack at
any price (it carries no per-record Merkle proof and no completeness
attestation); 7-year ledger retention is part of Enterprise instead.
Self-verification (`tlane verify` against your own export) is included on every
tier. The gate on `GET /v1/audit/export` is the `FeatureKey::AuditAddon` check
before any ledger read (`crates/gateway/src/audit_export.rs:1144,1224`);
`f_audit_addon` is seeded true for Enterprise and false elsewhere and is not a
purchasable flag (`apps/web/db/schema.ts:254`, `apps/web/db/seed.mjs:67,159`).
Without it those endpoints return an entitlement-required error, not a reduced
export. No non-Enterprise tier carries self-serve bulk export.

Included on every tier:
- Per-tenant Ed25519-signed Merkle roots, with best-effort Sigstore Rekor v2 anchoring on the terms in [Hash chain structure](#hash-chain-structure) above
- Offline verification by a third party, with no Tracelane account

Enterprise-only:
- 7-year ledger retention instead of 2
- The bulk `GET /v1/audit/export` regulatory-export route

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
- `apps/web/db/migrations/0047_adr078_ledger_canonical_pg.sql` — `audit_log_rows` / `audit_anchor_records`, the canonical ledger when Postgres is configured (`apps/web/db/schema.ts` is the Drizzle source)
- `infra/dev/clickhouse/schema.sql` — `tracelane.audit_log` table: the ledger's ClickHouse copy, or its only home on a no-Postgres self-host

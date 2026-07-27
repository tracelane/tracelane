# Audit signing (Ed25519) — activation, testing, and runbook


This is the flight recorder's **provable** layer: every audit batch's Merkle root is signed with Ed25519 and the signature is persisted on the batch's `audit_log` rows. Combined with the SHA-256 hash chain, this makes the ledger tamper-**evident** and non-repudiable — with **zero third-party dependency** (per ADR-025; EU AI Act Article 12 is technology-neutral).

---

## 1. What it does

Per tenant, the audit chain hashes each event (`row_hash_v2`, SHA-256, domain-separated). Every `TRACELANE_REKOR_ANCHOR_EVERY` events it forms a batch, computes the RFC-6962 Merkle root (`merkle_root_v2`), signs the **raw 32-byte root** with Ed25519, and backfills the `signature` + `signing_pubkey` onto that batch's rows.

- **Integrity** = the SHA-256 chain (each row hash includes the previous → any edit breaks the chain).
- **Authenticity / non-repudiation** = the Ed25519 signature over the batch root.
- **Zero third-party** = the signature lives on your ClickHouse rows; an external transparency log (Rekor) is **opt-in** (`TRACELANE_REKOR_URL`) and, if unset, nothing is POSTed anywhere.

Signing key resolution: a per-tenant BYOK-encrypted key (`tenant_audit_keys`, auto-generated on first use, pubkey pinned in Postgres) when available, else the global `TRACELANE_REKOR_SIGNING_KEY`.

## 2. The change (code)

`crates/gateway/src/audit.rs`
- `submit_for_tenant` → returns `AnchorOutcome { signature_b64, pubkey_b64, rekor_entry_id }`. It signs, then the external Rekor POST is **opt-in + non-fatal**: with `TRACELANE_REKOR_URL` unset it returns `(no-rekor)` and the signature is kept locally; a POST failure never loses the signature. (Previously the POST was fatal and `rekor_url` defaulted to the **public** `rekor.sigstore.dev` — so prod had zero signatures and any signing would have leaked the root to a third party.)
- `anchor_to_rekor` — the extracted, SSRF-guarded external submit (only reached when a Rekor URL is explicitly set).
- `backfill_signature` — persists `signature`/`signing_pubkey` onto the batch rows via the existing per-batch `ALTER … UPDATE`, whenever signed, independent of Rekor.
- `is_real_rekor_entry` — gates the sentinels (`(no-key)` / `(no-rekor)` / `(unknown-uuid)`) out of metering and the UUID backfill.

`crates/gateway/src/audit_keys.rs`
- `get_or_create` now writes `tenant_audit_keys.public_key_b64` at mint (the H1 pin source), and **re-loads the persisted row after `INSERT … ON CONFLICT DO NOTHING`** so concurrent first-use converges on one key.

`crates/gateway/src/server.rs`
- `Config::rekor_signing_key` is `Option<SecretString>` (zeroize + redacted Debug), exposed only at the `AuditChain` call site.

Schema: `audit_log` gains `signature String DEFAULT ''` + `signing_pubkey String DEFAULT ''` (`infra/dev/clickhouse/schema.sql` + migration `09_audit_signature_columns.sql`). Additive; the migration MUST land before the gateway that writes those fields.

## 3. How it was tested

**Unit (Rust, `cargo test -p gateway`, 58 audit tests / 0 fail):**
- `signature_round_trips_and_detects_tamper` — sign a Merkle root, verify with `ring` against the pubkey (Ok), flip a root byte (Err). The core crypto property.
- `rekor_client_with_global_signs_root` / `_with_no_keys_returns_none` / `global_signing_is_deterministic_per_key` — key resolution + Ed25519 determinism.
- `anchor_outcome_unsigned_is_no_key`, `fire_anchor_hook_meters_real_entry_but_not_no_key` — sentinel + metering discipline.
- `audit_keys::tests::{generate_and_sign, public_key_length, different_keys_per_generate}` — keypair generation.

**Opus security review** (`.claude/rules/security.md`, crypto/audit surface): cleared SSRF, tenant-isolation, private-key handling, and signed-bytes correctness; rated the default change a **net security improvement**. Fixed in-branch: **H2** (SecretString key), **M2** (`(unknown-uuid)` over-metering), **H1** (persist the pubkey pin at mint). Documented gates for the verifier PR: pin the pubkey to Postgres (not the row-inline mirror), and the M1 backfill-race semantics. Full write-up in ADR-057 §"Security review".

**On-node real proof (the one that matters — green on real data, not an empty table):**
1. Provisioned the key + `TRACELANE_REKOR_ANCHOR_EVERY=1`, deployed the gateway (`cca6bfc`).
2. Sent one authenticated `chat.completions.request` with a real tenant key. (It 502'd at provider dispatch — irrelevant: the audit event is appended **before** dispatch.)
3. Queried prod ClickHouse — real `signature` + `signing_pubkey` present on the new rows (seq 9 and 10).
4. Recomputed each batch's Merkle root and verified the Ed25519 signature with `verify_signed_row`:
   - `PROOF ✓ prod signed row verifies (Ed25519 over recomputed Merkle root)`
   - `PROOF ✓ tampered root fails verification`
5. **The proof caught a real bug:** the same tenant had **two different** per-tenant pubkeys. Root cause: `get_or_create` returned its locally-generated keypair after `ON CONFLICT DO NOTHING`, so concurrent first-use diverged. Fixed (re-load after insert → converge). This is exactly why we prove on real data — an empty-table "green" would have hidden it.

To re-verify any prod signed row:
```
ROW_HASH=<hex row_hash> SIG_B64=<signature> PUBKEY_B64=<signing_pubkey> \
  cargo test -p gateway --bin gateway verify_signed_row -- --ignored --nocapture
```

## 4. Config (prod gateway `.env` at `/opt/tracelane/app/infra/prod/.env`)

| Var | Value | Meaning |
|---|---|---|
| `TRACELANE_REKOR_SIGNING_KEY` | base64 PKCS#8 (ring **v2**) | Global fallback signing key. **Generate with ring, not `openssl genpkey`** (v1 is rejected). |
| `TRACELANE_REKOR_ANCHOR_EVERY` | `100` (prod) | Events per signed batch. **Never 1 in prod** — one CH mutation per event. Use `1` only for a single-request proof, then reset. |
| `TRACELANE_REKOR_URL` | *(empty)* | Empty ⇒ zero third-party (sign + persist locally, no POST). Set to a self-hosted Rekor to also anchor externally. Public `rekor.sigstore.dev` is **not** compatible (it wants PEM SPKI; we send raw). |

## 5. Runbook

**Generate a key** (also for rotation):
```
cargo test -p gateway --bin gateway print_signing_key -- --ignored --nocapture
```

**Deploy / activate:**
1. Apply migration 09 to prod CH (idempotent): `ALTER TABLE tracelane.audit_log ADD COLUMN IF NOT EXISTS signature String DEFAULT ''` (+ `signing_pubkey`).
2. Add `TRACELANE_REKOR_SIGNING_KEY=<key>` to the prod `.env` (founder-managed).
3. `scripts/deploy/gateway.sh` (rebuilds from `main`, restarts, re-reads `.env`).
4. Prove per §3.

**Rotate the key:** generate a new one, replace `TRACELANE_REKOR_SIGNING_KEY`, redeploy. Old rows stay verifiable against their stored pubkey; new rows use the new key. (The proof key from 2026-07-09 appeared in a chat log — rotate it before any external audit reliance.)

## 6. Follow-ups (before the "tamper-evident VERIFIED" claim ships)

- **Verifier pins the pubkey to Postgres**, not the row-inline `audit_log.signing_pubkey` (a CH-write attacker could rewrite both). `tenant_audit_keys.public_key_b64` (per-tenant) / the known global pubkey. — ADR-057 H1.
- **M1** — the per-row backfill is eventually-consistent, so `signature=''` means "not-yet-backfilled," not "unsigned." A per-batch `audit_anchor_batches` record (signature stored once per batch) is the clean fix the verifier should consult.
- Self-hosted Rekor v2 + eIDAS QTSP are opt-in / deferred (ADR-057 §Deferred).

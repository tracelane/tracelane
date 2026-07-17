//! Tamper-evident audit log (v2) with Ed25519 hash chain and Sigstore
//! Rekor anchoring.
//!
//! audit-ledger security review.
//!
//! - **C1**: row hash uses length-prefixed, domain-separated framing
//!   (`audit_format::row_hash_v2`).
//! - **C2**: Merkle tree is RFC 6962 with leaf/node domain separators
//!   (`audit_format::merkle_root_v2`).
//! - **C3**: genesis seed is `SHA256(DOMAIN_GENESIS_V2 || tenant_id)`,
//!   not the empty string.
//! - **C4**: per-tenant Ed25519 signing keys via
//!   [`audit_keys::TenantAuditKeyStore`]. Each tenant's Merkle root is
//!   signed by a tenant-scoped key; cross-tenant signing-key compromise
//!   surface is bounded by `TenantAuditKeyStore` access (minting is
//!   Non-entitled tenants and dev fall back to the global
//!   `TRACELANE_REKOR_SIGNING_KEY`.
//! - **C5**: Ed25519 PKCS#8 bytes wrapped in `secrecy::SecretBox` so
//!   they zeroize on drop.
//! - **C6**: signature is over raw bytes, not a hex encoding. **ADR-062
//!   Amendment 1 supersedes the "raw root" form**: the Ed25519 local
//!   attestation now signs the BOUND `local_attest_msg` (domain tag ‖
//!   merkle_root ‖ anchor_commitment) so a stripped / swapped / downgraded
//!   export bundle fails offline verification (permissionless-log C1/H3 fix).
//!   The public anchor is an ECDSA-P256 `hashedrekord` v0.0.2 (pure Ed25519 is
//!   rejected by Rekor v2); see `decisions/ADR-062-*.md`.
//! - **H3**: ClickHouse `ALTER TABLE ... UPDATE` now uses parameter
//!   binding AND filters on `tenant_id` (CLAUDE.md hard rule).
//! - **H4**: `(last_seq, last_row_hash)` persisted per-tenant to
//!   Postgres via monotonic UPSERT (`GREATEST`-guarded); restart
//!   resumes correctly.
//! - **H5**: per-tenant `Mutex` via `DashMap` — cross-tenant appends
//!   no longer serialize.
//!
//! ## Deferred to follow-up PRs
//!
//! - **H1/H2**: customer-side verifier (`packages/verifier-rust/`)
//!   actually validating Ed25519 signatures and Rekor inclusion proofs.
//! - **H6**: persist unanchored batches for Rekor outage recovery.

use std::sync::{Arc, OnceLock};
// future malformed payload that panics inside an audit-append can't
// permanently DoS the tenant's chain (`std::sync::Mutex` would refuse
// every subsequent lock). The audit chain invariants are protected by
// the row hash itself, so panic-then-recover is safer than hard fail.
use parking_lot::Mutex;

use anyhow::{Context as _, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chrono::Utc;
use clickhouse::Client as ClickhouseClient;
use dashmap::DashMap;
use ring::signature::{self, KeyPair as _};
use secrecy::SecretBox;
use secrecy::zeroize::Zeroize as _;
use serde_json::{Value, json};
use tracing::instrument;

use crate::audit_format;
use crate::audit_keys::{TenantAnchorKeypair, TenantAuditKeyStore};
use tracelane_shared::TenantId;

/// An audit event.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub tenant_id: TenantId,
    pub event_type: &'static str,
    pub actor: String,
    pub payload: Value,
}

// ---------------------------------------------------------------------------
// Legacy v1 helpers — kept for verifying existing ClickHouse rows.
// ---------------------------------------------------------------------------

/// **v1 — DEPRECATED.** Use `audit_format::row_hash_v2` for new writes.
///
/// Retained at `pub(crate)` so the gateway's verifier-compat path can
/// still walk v1 ClickHouse rows during the v1→v2 migration window.
/// **Not part of the public API** — external callers (the
/// verifier-rust crate, the Python verifier, etc.) must implement v1
/// reading independently and gate it behind their own feature flag.
/// Opus-rereview HIGH-2 fix.
#[deprecated(note = "v1 hash format is vulnerable to field-boundary attacks. \
            Use `audit_format::row_hash_v2`.")]
#[allow(dead_code)]
pub(crate) fn compute_row_hash(
    prev_hash: &str,
    tenant_id: &TenantId,
    seq: u64,
    event_type: &str,
    actor: &str,
    payload_json: &str,
) -> String {
    use ring::digest;
    let input = format!("{tenant_id}|{seq}|{event_type}|{actor}|{payload_json}|{prev_hash}");
    let d = digest::digest(&digest::SHA256, input.as_bytes());
    hex::encode(d.as_ref())
}

/// **v1 — DEPRECATED.** Use `audit_format::merkle_root_v2`.
///
/// `pub(crate)` only — see `compute_row_hash` for rationale.
/// Opus-rereview HIGH-2 fix.
#[deprecated(note = "v1 Merkle tree is vulnerable to second-preimage attacks. \
            Use `audit_format::merkle_root_v2`.")]
#[allow(dead_code)]
pub(crate) fn compute_merkle_root(hashes: &[String]) -> String {
    use ring::digest;
    if hashes.is_empty() {
        return hex::encode(digest::digest(&digest::SHA256, b"empty").as_ref());
    }
    let mut level: Vec<String> = hashes.to_vec();
    while level.len() > 1 {
        if level.len() % 2 != 0 {
            let last = level.last().cloned().unwrap_or_default();
            level.push(last);
        }
        level = level
            .chunks(2)
            .map(|pair| {
                let combined = format!("{}{}", pair[0], pair[1]);
                let d = digest::digest(&digest::SHA256, combined.as_bytes());
                hex::encode(d.as_ref())
            })
            .collect();
    }
    let leaf = level.into_iter().next().unwrap_or_default();
    let d = digest::digest(&digest::SHA256, leaf.as_bytes());
    hex::encode(d.as_ref())
}

// ---------------------------------------------------------------------------
// AuditLogRow — ClickHouse row matching tracelane.audit_log schema
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Serialize, clickhouse::Row)]
pub struct AuditLogRow {
    pub tenant_id: String,
    pub seq: u64,
    /// Microseconds since Unix epoch (DateTime64(6, 'UTC')).
    pub event_time: i64,
    pub event_type: String,
    pub actor: String,
    pub payload: String,
    pub prev_hash: String,
    pub row_hash: String,
    pub rekor_entry_id: Option<String>,
    /// base64 Ed25519 signature over the batch Merkle root (ADR-057); `""` until
    /// the batch anchors. Empty for unsigned deployments.
    pub signature: String,
    /// base64 Ed25519 public key that produced `signature`; `""` until anchored.
    pub signing_pubkey: String,
}

// ---------------------------------------------------------------------------
// ADR-062 Amendment 1 — anchor crypto. The byte formats below are FROZEN: do NOT
// change the domain tags or `anchor_commitment` layout after the first prod
// anchor — they are baked into every anchored root's signatures (a change is a
// hard fork that invalidates all prior offline verifications).
// ---------------------------------------------------------------------------

/// Domain tag for the ECDSA anchor artifact (what Rekor SHA-256's + the ECDSA
/// anchor key signs). FROZEN.
const DOMAIN_ANCHOR: &[u8] = b"tracelane-anchor-ecdsa-v1\0";
/// Domain tag for the Ed25519 local attestation. FROZEN.
const DOMAIN_ATTEST: &[u8] = b"tracelane-audit-ed25519-v1\0";

/// `ANCHOR_ARTIFACT = DOMAIN_ANCHOR ‖ merkle_root`. Rekor stores its SHA-256 as
/// the hashedrekord `data.digest`; the ECDSA anchor key signs these exact bytes.
fn anchor_artifact(root: &audit_format::Hash) -> Vec<u8> {
    let mut v = Vec::with_capacity(DOMAIN_ANCHOR.len() + root.len());
    v.extend_from_slice(DOMAIN_ANCHOR);
    v.extend_from_slice(root);
    v
}

/// SHA-256 convenience (the anchor-commitment + artifact-digest hash).
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// `anchor_commitment` (ADR-062 Amendment 1) — binds the anchor identity into the
/// Ed25519 local attestation so a stripped / swapped / downgraded bundle fails
/// offline verification. `None` → not anchored (single `0x00`). `Some` →
/// `0x01 ‖ SHA256(ecdsa_spki) ‖ SHA256(log_url) ‖ u64_be(log_index)` (73 bytes).
fn anchor_commitment(anchored: Option<(&[u8], &str, u64)>) -> Vec<u8> {
    match anchored {
        None => vec![0x00],
        Some((ecdsa_spki, log_url, log_index)) => {
            let mut v = Vec::with_capacity(1 + 32 + 32 + 8);
            v.push(0x01);
            v.extend_from_slice(&sha256(ecdsa_spki));
            v.extend_from_slice(&sha256(log_url.as_bytes()));
            v.extend_from_slice(&log_index.to_be_bytes());
            v
        }
    }
}

/// `LOCAL_ATTEST_MSG = DOMAIN_ATTEST ‖ merkle_root ‖ anchor_commitment` — the
/// message the tenant Ed25519 key signs (never the raw root — that was the v0
/// design the security review broke).
fn local_attest_msg(root: &audit_format::Hash, commitment: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(DOMAIN_ATTEST.len() + root.len() + commitment.len());
    v.extend_from_slice(DOMAIN_ATTEST);
    v.extend_from_slice(root);
    v.extend_from_slice(commitment);
    v
}

/// A parsed Rekor v2 `TransparencyLogEntry` — the offline-verifiable bundle we
/// persist (`audit_anchor_records`) + export (ADR-062 Amendment 1). Rekor v2 has
/// no online entry lookup, so the inclusion proof + checkpoint MUST be captured
/// here at anchor time.
#[derive(Debug, Clone)]
pub(crate) struct RekorV2Receipt {
    pub log_url: String,
    /// Numeric log index as the raw string (for the export bundle).
    pub log_index: String,
    /// The same log index parsed to `u64` ONCE at parse time — the commitment
    /// consumer uses this so an unvalidated string can never reach the signed
    /// bytes (security-review MED #1).
    pub log_index_u64: u64,
    /// base64 of the canonicalized hashedrekord entry body (RFC6962 leaf preimage;
    /// carries the ECDSA digest + sig + SPKI).
    pub canonicalized_body_b64: String,
    /// `{log_index, tree_size, hashes:[b64]}` — verbatim, for the inclusion fold.
    pub inclusion_proof: Value,
    /// C2SP signed-note text — the log's signed checkpoint (tree head).
    pub checkpoint_envelope: String,
}

/// Outcome of anchoring one audit batch (ADR-062 Amendment 1). The Ed25519
/// signature is over the BOUND [`local_attest_msg`], never the raw Merkle root.
#[derive(Debug, Clone)]
pub(crate) struct BatchAnchorOutcome {
    /// base64 Ed25519 sig over `LOCAL_ATTEST_MSG`; empty if no signing key.
    pub ed25519_sig_b64: String,
    /// base64 raw 32-byte Ed25519 pubkey; empty if unsigned.
    pub ed25519_pubkey_b64: String,
    /// Whether the batch was anchored to Rekor (receipt present).
    pub anchored: bool,
    /// The Rekor receipt when anchored.
    pub receipt: Option<RekorV2Receipt>,
    /// base64 ECDSA anchor SPKI (present iff anchored).
    pub ecdsa_spki_b64: String,
}

impl BatchAnchorOutcome {
    /// Whether a signature was produced (a signing key was present).
    fn is_signed(&self) -> bool {
        !self.ed25519_sig_b64.is_empty()
    }

    /// The value backfilled onto `audit_log.rekor_entry_id`: the numeric Rekor log
    /// index when anchored, else a sentinel (`(no-rekor)` = signed-not-anchored,
    /// `(no-key)` = unsigned) which [`is_real_rekor_entry`] excludes from metering
    /// + the UUID backfill.
    fn rekor_entry_id(&self) -> String {
        match &self.receipt {
            Some(r) => r.log_index.clone(),
            None if self.is_signed() => "(no-rekor)".to_string(),
            None => "(no-key)".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// AuditChain — per-tenant chain tracker with Rekor anchoring
// ---------------------------------------------------------------------------

struct TenantChainState {
    seq: u64,
    prev_hash: audit_format::Hash,
    pending_hashes: Vec<audit_format::Hash>,
    batch_start_seq: u64,
}

impl TenantChainState {
    fn genesis(tenant_id: &TenantId) -> Self {
        Self {
            seq: 0,
            prev_hash: audit_format::genesis_prev_hash(tenant_id),
            pending_hashes: Vec::new(),
            batch_start_seq: 0,
        }
    }
}

/// Hook invoked once per **successful** Rekor anchor batch, with the anchoring
/// [`AuditChain::set_billing`] so each anchor batch meters one `audit_anchors`
/// usage event (ADR-048); tests inject a channel. Sync — it only *dispatches*
/// fire-and-forget work, never blocking or awaiting on the anchor path.
type AnchorHook = Arc<dyn Fn(TenantId) + Send + Sync>;

pub struct AuditChain {
    /// Per-tenant locks.
    states: DashMap<TenantId, Mutex<TenantChainState>>,
    rekor_client: RekorClient,
    anchor_every: usize,
    clickhouse_client: Option<ClickhouseClient>,
    /// Postgres pool for the persistent chain-state table.
    pg_pool: Option<deadpool_postgres::Pool>,
    /// via [`set_billing`](Self::set_billing); unset = anchoring is not metered.
    anchor_hook: OnceLock<AnchorHook>,
}

impl AuditChain {
    pub fn new(
        anchor_every: usize,
        signing_key_b64: Option<&str>,
        clickhouse_url: Option<&str>,
    ) -> Result<Self> {
        Self::with_pg_pool(anchor_every, signing_key_b64, clickhouse_url, None)
    }

    pub fn with_pg_pool(
        anchor_every: usize,
        signing_key_b64: Option<&str>,
        clickhouse_url: Option<&str>,
        pg_pool: Option<deadpool_postgres::Pool>,
    ) -> Result<Self> {
        Self::with_tenant_keys(anchor_every, signing_key_b64, clickhouse_url, pg_pool, None)
    }

    /// Full constructor with per-tenant signing-key support.
    ///
    /// `tenant_keys`: Optional `TenantAuditKeyStore`. When provided,
    /// each tenant's Merkle root is signed with its own Ed25519 key
    /// from the Postgres `tenant_audit_keys` table. When `None`, the
    /// global `signing_key_b64` is used for every tenant (backwards
    /// compatible with dev / non-Enterprise tiers).
    ///
    /// The two key paths are NOT mutually exclusive: if `tenant_keys`
    /// is set and a particular tenant has no keypair yet,
    /// `TenantAuditKeyStore::get_or_create` generates one on the fly
    /// and persists it (envelope-encrypted via BYOK).
    pub fn with_tenant_keys(
        anchor_every: usize,
        signing_key_b64: Option<&str>,
        clickhouse_url: Option<&str>,
        pg_pool: Option<deadpool_postgres::Pool>,
        tenant_keys: Option<Arc<TenantAuditKeyStore>>,
    ) -> Result<Self> {
        let rekor_client = RekorClient::new(signing_key_b64, tenant_keys)?;
        let clickhouse_client = clickhouse_url.map(crate::clickhouse_query::ch_client);
        Ok(Self {
            states: DashMap::new(),
            rekor_client,
            anchor_every,
            clickhouse_client,
            pg_pool,
            anchor_hook: OnceLock::new(),
        })
    }

    /// already set. Prod uses [`set_billing`](Self::set_billing); tests inject a
    /// counter/channel to assert the anchor→meter wiring without Postgres/Rekor.
    pub fn set_anchor_hook(&self, hook: AnchorHook) {
        let _ = self.anchor_hook.set(hook);
    }

    /// Wire the Polar billing recorder so each successful Rekor anchor batch
    ///
    /// Called once at startup, after the recorder is built (see `server.rs`).
    /// Off the anchor path: the hook only **spawns** the tenant → Polar-customer
    /// lookup + `record()`, mirroring the `TokensProcessed` fire-and-forget
    /// pattern. A tenant with no Polar customer (unbilled) or no Postgres pool is
    /// a silent no-op — the audit ledger is unaffected either way.
    pub fn set_billing(&self, recorder: Arc<crate::billing::Recorder>) {
        self.set_anchor_hook(Arc::new(move |tenant_id: TenantId| {
            spawn_anchor_meter(Arc::clone(&recorder), tenant_id);
        }));
    }

    /// Load persisted chain state at startup, reconciling any durable ClickHouse
    /// rows written ahead of the persisted head. Idempotent.
    ///
    /// **Warm-from-crash reconcile (ADR-065 HOLE C):** Postgres
    /// `(last_seq, last_row_hash)` is the authoritative head. A crash after the
    /// CH row write but before the PG advance/commit (the F1 CH-durable-before-PG
    /// ordering) leaves a durable CH row *ahead* of the persisted head. On
    /// startup we adopt it — advance PG to the longest strictly-contiguous,
    /// correctly-chaining continuation of CH rows — so the row is never orphaned
    /// or reset, and the next append continues from `adopted_seq + 1` (no
    /// duplicate, no gap). A CH row that does not chain from the persisted head
    /// is NOT adopted (never chain from an unverified row).
    #[instrument(skip(self))]
    pub async fn warm_from_postgres(&self) -> Result<()> {
        let Some(ref pool) = self.pg_pool else {
            tracing::info!("no pg pool — skipping audit_chain_state warm");
            return Ok(());
        };
        let rows = crate::db::audit_chain_state::load_all(pool)
            .await
            .context("load_all audit_chain_state")?;
        let count = rows.len();
        let mut reconciled_tenants = 0usize;
        for r in rows {
            let mut head_seq = r.last_seq;
            let mut head_hash = r.last_row_hash;
            if let Some(ref ch) = self.clickhouse_client {
                match self
                    .reconcile_head_from_ch(pool, ch, &r.tenant_id, head_seq, head_hash)
                    .await
                {
                    Ok(Some((adopted_seq, adopted_hash))) => {
                        reconciled_tenants += 1;
                        head_seq = adopted_seq;
                        head_hash = adopted_hash;
                    }
                    Ok(None) => {}
                    Err(err) => tracing::warn!(
                        error = %err, tenant_id = %r.tenant_id,
                        "audit warm-reconcile failed — resuming from persisted head"
                    ),
                }
            }
            self.states.entry(r.tenant_id.clone()).or_insert_with(|| {
                Mutex::new(TenantChainState {
                    seq: head_seq + 1,
                    prev_hash: head_hash,
                    pending_hashes: Vec::with_capacity(self.anchor_every),
                    batch_start_seq: head_seq + 1,
                })
            });
        }
        tracing::info!(
            count,
            reconciled_tenants,
            "audit_chain_state warmed from Postgres"
        );
        Ok(())
    }

    /// Adopt any durable ClickHouse rows written ahead of the persisted head for
    /// one tenant (ADR-065 HOLE C). Walks CH rows with `seq > head_seq` (deduped
    /// via `FINAL`), adopting each strictly-next, correctly-chaining row; stops
    /// at the first gap or chain break (never adopts an unverified row). If any
    /// row is adopted, advances the persisted head (monotonic `upsert`) and
    /// returns the new `(seq, row_hash)`; otherwise `Ok(None)`.
    async fn reconcile_head_from_ch(
        &self,
        pool: &deadpool_postgres::Pool,
        ch: &ClickhouseClient,
        tenant_id: &TenantId,
        head_seq: u64,
        head_hash: audit_format::Hash,
    ) -> Result<Option<(u64, audit_format::Hash)>> {
        const RECONCILE_LIMIT: u32 = 10_000;
        let rows = read_rows_after(ch, tenant_id, head_seq, RECONCILE_LIMIT).await?;
        if rows.is_empty() {
            return Ok(None);
        }
        let mut adopted_seq = head_seq;
        let mut running_prev = head_hash;
        for r in rows {
            if r.seq != adopted_seq + 1 {
                break; // gap or reorder — stop adopting
            }
            let prev = audit_format::hex_decode(&r.prev_hash)
                .map_err(|e| anyhow::anyhow!("reconcile prev_hash at seq {}: {e}", r.seq))?;
            if prev != running_prev {
                break; // chain break — never adopt a row that does not chain
            }
            let rh = audit_format::hex_decode(&r.row_hash)
                .map_err(|e| anyhow::anyhow!("reconcile row_hash at seq {}: {e}", r.seq))?;
            adopted_seq = r.seq;
            running_prev = rh;
        }
        if adopted_seq == head_seq {
            return Ok(None);
        }
        crate::db::audit_chain_state::upsert(pool, tenant_id, adopted_seq, &running_prev)
            .await
            .context("reconcile upsert of adopted head")?;
        tracing::info!(
            tenant_id = %tenant_id,
            from_seq = head_seq,
            to_seq = adopted_seq,
            "audit warm-reconcile adopted durable CH rows ahead of persisted head"
        );
        Ok(Some((adopted_seq, running_prev)))
    }

    /// Append one audit event, advancing the tenant's tamper-evident hash chain.
    ///
    /// **B-108 forward fix (ADR-065 F1):** when a Postgres pool is configured
    /// (always true in prod), seq assignment + chain-head advance are
    /// serialized **across processes** by a per-tenant `SELECT … FOR UPDATE`
    /// row lock ([`append_pg_serialized`](Self::append_pg_serialized)), and the
    /// ClickHouse row is written durably *inside* that transaction. This closes
    /// the cross-process duplicate-seq race that a process-local
    /// `parking_lot::Mutex` could not (blue-green deploy overlap /
    /// restart-with-lagged-persist). Without a pool (dev / OSS self-host without
    /// Postgres — inherently single-process), the legacy in-memory `DashMap`
    /// path is used ([`append_in_memory`](Self::append_in_memory)); the
    /// cross-process race cannot arise there.
    ///
    /// # Errors
    ///
    /// Fail-closed on the PG path (a PG or durable-CH-write failure aborts the
    /// append — the event is not recorded rather than recorded with a forked
    /// seq). The in-memory path only errors on a malformed payload.
    #[instrument(skip(self, event), fields(
        tenant_id = %event.tenant_id,
        event_type = %event.event_type,
    ))]
    pub async fn append(&self, event: AuditEvent) -> Result<()> {
        let redacted = tracelane_policy::pii::redact_json(&event.payload);
        let payload_json = audit_format::canonical_payload(&redacted);

        match self.pg_pool.clone() {
            Some(pool) => self.append_pg_serialized(&pool, event, payload_json).await,
            None => self.append_in_memory(event, payload_json),
        }
    }

    /// **ADR-065 F1** — the cross-process-safe append. One Postgres transaction
    /// per event: `FOR UPDATE`-lock the tenant head, compute `row_hash`, write
    /// the ClickHouse row durably, advance the head, commit. The row lock is the
    /// cross-process serialization the Mutex could not provide.
    ///
    /// Anchor batches are **seq-aligned** (`[k·N … (k+1)·N−1]`), not driven by a
    /// per-process in-memory counter: exactly one process commits each
    /// batch-final seq (seqs are globally serialized by the row lock), so it
    /// alone anchors that batch, and it rebuilds the leaf set by reading the
    /// contiguous rows back from ClickHouse (deduped) — never from a
    /// per-process `pending_hashes` that, under two co-running processes, would
    /// hold a non-contiguous subset and produce a Merkle root the verifier
    /// cannot reconstruct.
    async fn append_pg_serialized(
        &self,
        pool: &deadpool_postgres::Pool,
        event: AuditEvent,
        payload_json: String,
    ) -> Result<()> {
        let tenant_id = event.tenant_id.clone();
        let genesis = audit_format::genesis_prev_hash(&tenant_id);
        let ch_for_write = self.clickhouse_client.clone();
        let event_type = event.event_type;
        let actor = event.actor.clone();

        // The closure is the durable-CH-write step, run INSIDE the PG tx between
        // the FOR UPDATE read and the head advance. It computes row_hash over the
        // seq/prev the lock just claimed, then writes (and awaits) the CH row.
        let outcome = crate::db::audit_chain_state::append_atomic(
            pool,
            &tenant_id,
            genesis,
            |seq, prev_hash| {
                let ch = ch_for_write.clone();
                let tenant_id = tenant_id.clone();
                let actor = actor.clone();
                let payload_json = payload_json.clone();
                async move {
                    let row_hash = audit_format::row_hash_v2(
                        &prev_hash,
                        &tenant_id,
                        seq,
                        event_type,
                        &actor,
                        &payload_json,
                    );
                    if let Some(ch) = ch {
                        let row = AuditLogRow {
                            tenant_id: tenant_id.to_string(),
                            seq,
                            event_time: Utc::now().timestamp_micros(),
                            event_type: event_type.to_string(),
                            actor,
                            payload: payload_json,
                            prev_hash: audit_format::hex_encode(&prev_hash),
                            row_hash: audit_format::hex_encode(&row_hash),
                            rekor_entry_id: None,
                            // Backfilled per anchor batch by `backfill_signature`.
                            signature: String::new(),
                            signing_pubkey: String::new(),
                        };
                        // Awaited — durable before the head advances (F1).
                        write_audit_row(&ch, row)
                            .await
                            .context("durable audit_log row write")?;
                    }
                    Ok(row_hash)
                }
            },
        )
        .await?;

        let seq = outcome.seq;
        tracing::debug!(
            row_hash_hex = %audit_format::hex_encode(&outcome.row_hash),
            seq,
            "audit event hashed (pg-serialized)"
        );

        // Seq-aligned anchor batches. The append that commits a batch-final seq
        // (there is exactly one, seqs being globally serialized) anchors
        // `[batch_start … seq]`, reading the contiguous leaf set back from
        // ClickHouse. Requires a CH client; without one there are no rows to
        // anchor (dev). Off the hot path (spawned).
        let n = self.anchor_every as u64;
        if n > 0 && (seq + 1).is_multiple_of(n) {
            if let Some(ch) = self.clickhouse_client.clone() {
                let batch_start = seq + 1 - n;
                let rekor = self.rekor_client.clone();
                let tid = tenant_id.clone();
                let anchor_hook = self.anchor_hook.get().cloned();
                tokio::spawn(async move {
                    anchor_batch_from_ch(rekor, ch, tid, batch_start, seq, anchor_hook).await;
                });
            }
        }

        Ok(())
    }

    /// Legacy in-memory append (no Postgres pool → single-process dev / OSS
    /// self-host). Advances the per-tenant `DashMap` chain state under a
    /// `parking_lot::Mutex` and fires the CH write + anchor as fire-and-forget
    /// tasks. The cross-process race (B-108) cannot arise without a shared
    /// Postgres, so this path is unchanged. **Not used when `pg_pool` is set.**
    fn append_in_memory(&self, event: AuditEvent, payload_json: String) -> Result<()> {
        let (row_hash, seq, prev_hash_snapshot, should_anchor, pending_snapshot, batch_start) = {
            let state_ref = self
                .states
                .entry(event.tenant_id.clone())
                .or_insert_with(|| Mutex::new(TenantChainState::genesis(&event.tenant_id)));
            // parking_lot::Mutex returns the guard directly — no poison
            // semantics, no Result. See module use-decl for rationale.
            let mut state = state_ref.lock();

            let hash = audit_format::row_hash_v2(
                &state.prev_hash,
                &event.tenant_id,
                state.seq,
                event.event_type,
                &event.actor,
                &payload_json,
            );
            let seq = state.seq;
            let prev_hash_snapshot = state.prev_hash;
            state.prev_hash = hash;
            state.seq += 1;
            state.pending_hashes.push(hash);

            let should_anchor = state.pending_hashes.len() >= self.anchor_every;
            let batch_start = state.batch_start_seq;
            let snapshot = if should_anchor {
                state.batch_start_seq = seq + 1;
                std::mem::replace(
                    &mut state.pending_hashes,
                    Vec::with_capacity(self.anchor_every),
                )
            } else {
                vec![]
            };

            (
                hash,
                seq,
                prev_hash_snapshot,
                should_anchor,
                snapshot,
                batch_start,
            )
        };

        tracing::debug!(
            row_hash_hex = %audit_format::hex_encode(&row_hash),
            seq,
            "audit event hashed (in-memory)"
        );

        // Persist row to ClickHouse — non-blocking.
        if let Some(ref ch) = self.clickhouse_client {
            let row = AuditLogRow {
                tenant_id: event.tenant_id.to_string(),
                seq,
                event_time: Utc::now().timestamp_micros(),
                event_type: event.event_type.to_string(),
                actor: event.actor.clone(),
                payload: payload_json,
                prev_hash: audit_format::hex_encode(&prev_hash_snapshot),
                row_hash: audit_format::hex_encode(&row_hash),
                rekor_entry_id: None,
                // Backfilled per anchor batch by `backfill_signature` (ADR-057).
                signature: String::new(),
                signing_pubkey: String::new(),
            };
            let ch = ch.clone();
            tokio::spawn(async move {
                if let Err(err) = write_audit_row(&ch, row).await {
                    tracing::warn!(error = %err, "ClickHouse audit_log write failed");
                }
            });
        }

        if should_anchor {
            let rekor = self.rekor_client.clone();
            let ch = self.clickhouse_client.clone();
            let tenant_id = event.tenant_id.clone();
            let anchor_hook = self.anchor_hook.get().cloned();
            tokio::spawn(async move {
                anchor_task(
                    rekor,
                    ch,
                    tenant_id,
                    pending_snapshot,
                    batch_start,
                    seq,
                    anchor_hook,
                )
                .await;
            });
        }

        Ok(())
    }
}

// Opus-rereview HIGH-1 fix: NO `Default` impl.
//
// Previously `Default::default()` silently fell back to a
// `RekorClient::no_op()` on key-parse failure — a misconfigured prod
// that happened to construct an AuditChain via `Default` would have
// zero audit guarantees and zero logging that anchoring was off
// (fail-open in a security path, banned by `.claude/rules/rust.md`).
//
// Callers MUST go through `AuditChain::new(...)` or `with_pg_pool(...)`
// and propagate the `Result`. The compiler now enforces this; a
// future `Default::default()` would be a compile error.

async fn write_audit_row(client: &ClickhouseClient, row: AuditLogRow) -> anyhow::Result<()> {
    let mut insert = client
        .insert("audit_log")
        .context("clickhouse audit_log insert init")?;
    insert
        .write(&row)
        .await
        .context("clickhouse audit_log insert write")?;
    insert
        .end()
        .await
        .context("clickhouse audit_log insert end")?;
    Ok(())
}

/// One per-batch anchor bundle (ADR-062 Amendment 1) — the offline-verifiable
/// record the export streams and the three verifiers check. Written once per
/// signed batch, anchored or not.
#[derive(Debug, serde::Serialize, clickhouse::Row)]
pub(crate) struct AuditAnchorRecordRow {
    pub tenant_id: String,
    pub batch_start_seq: u64,
    pub batch_end_seq: u64,
    /// hex of the RFC6962 Merkle root over the batch rows.
    pub merkle_root: String,
    /// `anchored` | `unanchored` — matches the byte the Ed25519 sig committed to.
    pub anchor_state: String,
    /// base64 Ed25519 sig over `LOCAL_ATTEST_MSG`.
    pub ed25519_sig: String,
    /// base64 raw 32-byte Ed25519 pubkey (reference; verifier uses the trusted key).
    pub ed25519_pubkey: String,
    /// base64 ECDSA anchor SPKI (empty when unanchored).
    pub ecdsa_pubkey_spki: String,
    pub rekor_log_url: String,
    pub rekor_log_index: String,
    /// base64 canonicalized hashedrekord body (empty when unanchored).
    pub canonicalized_body: String,
    /// JSON `{log_index, tree_size, hashes[]}` (empty when unanchored).
    pub inclusion_proof: String,
    /// C2SP signed-note checkpoint (empty when unanchored).
    pub checkpoint_envelope: String,
    /// Microseconds since Unix epoch (DateTime64(6, 'UTC')).
    pub anchored_at: i64,
}

/// Build the anchor-record row from a batch outcome. Reads the full receipt so
/// the offline bundle is durable (Rekor v2 cannot be re-queried later).
fn build_anchor_record(
    tenant_id: &TenantId,
    root: &audit_format::Hash,
    start_seq: u64,
    end_seq: u64,
    outcome: &BatchAnchorOutcome,
) -> AuditAnchorRecordRow {
    let (log_url, log_index, canon, incl, checkpoint) = match &outcome.receipt {
        Some(r) => (
            r.log_url.clone(),
            r.log_index.clone(),
            r.canonicalized_body_b64.clone(),
            r.inclusion_proof.to_string(),
            r.checkpoint_envelope.clone(),
        ),
        None => (
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        ),
    };
    AuditAnchorRecordRow {
        tenant_id: tenant_id.to_string(),
        batch_start_seq: start_seq,
        batch_end_seq: end_seq,
        merkle_root: audit_format::hex_encode(root),
        anchor_state: if outcome.anchored {
            "anchored".to_string()
        } else {
            "unanchored".to_string()
        },
        ed25519_sig: outcome.ed25519_sig_b64.clone(),
        ed25519_pubkey: outcome.ed25519_pubkey_b64.clone(),
        ecdsa_pubkey_spki: outcome.ecdsa_spki_b64.clone(),
        rekor_log_url: log_url,
        rekor_log_index: log_index,
        canonicalized_body: canon,
        inclusion_proof: incl,
        checkpoint_envelope: checkpoint,
        anchored_at: Utc::now().timestamp_micros(),
    }
}

async fn write_anchor_record(
    client: &ClickhouseClient,
    row: AuditAnchorRecordRow,
) -> anyhow::Result<()> {
    let mut insert = client
        .insert("audit_anchor_records")
        .context("clickhouse audit_anchor_records insert init")?;
    insert
        .write(&row)
        .await
        .context("clickhouse audit_anchor_records insert write")?;
    insert
        .end()
        .await
        .context("clickhouse audit_anchor_records insert end")?;
    Ok(())
}

/// Backfill `rekor_entry_id` on audit rows after a successful anchor.
///
/// R1 H3 fix: parameter binding instead of raw SQL interpolation, AND
/// the `WHERE` filter includes `tenant_id = ?` per the CLAUDE.md hard
/// rule for every ClickHouse query.
async fn backfill_rekor_entry_id(
    client: &ClickhouseClient,
    tenant_id: &TenantId,
    entry_id: &str,
    start_seq: u64,
    end_seq: u64,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        entry_id.chars().all(|c| c.is_ascii_hexdigit() || c == '-'),
        "invalid Rekor log index — unexpected characters"
    );

    // ADR-031 V1.1 sweep: this audit-internal `ALTER TABLE ... UPDATE`
    // bypasses the TenantQuery wrapper. The query is bounded (single
    // tenant, sub-1000-row update window) so per-tier resource caps
    // would add no value here, but the V1.1 sweep should route through
    // a write-side TenantQuery variant for consistency. Exempted in
    // `scripts/ci/no-raw-ch-query.sh`.
    client
        .query(
            "ALTER TABLE audit_log UPDATE rekor_entry_id = ? \
             WHERE tenant_id = ? AND seq >= ? AND seq <= ?",
        )
        .bind(entry_id)
        .bind(tenant_id.to_string())
        .bind(start_seq)
        .bind(end_seq)
        .execute()
        .await
        .context("ClickHouse rekor_entry_id backfill mutation")?;
    Ok(())
}

/// Backfill the Ed25519 `signature` + `signing_pubkey` onto a batch's audit rows
/// (ADR-057, zero-third-party). Runs whenever the batch was signed, independent
/// of any external Rekor anchor. Same tenant-bounded `ALTER … UPDATE` shape as
/// `backfill_rekor_entry_id`; the values are our own base64 signing output
/// (parameter-bound, not user input).
async fn backfill_signature(
    client: &ClickhouseClient,
    tenant_id: &TenantId,
    signature_b64: &str,
    pubkey_b64: &str,
    start_seq: u64,
    end_seq: u64,
) -> anyhow::Result<()> {
    // ADR-031 V1.1 sweep: audit-internal ALTER, exempted in no-raw-ch-query.sh
    // (bounded single-tenant, sub-1000-row window). tenant_id filter present.
    client
        .query(
            "ALTER TABLE audit_log UPDATE signature = ?, signing_pubkey = ? \
             WHERE tenant_id = ? AND seq >= ? AND seq <= ?",
        )
        .bind(signature_b64)
        .bind(pubkey_b64)
        .bind(tenant_id.to_string())
        .bind(start_seq)
        .bind(end_seq)
        .execute()
        .await
        .context("ClickHouse audit signature backfill mutation")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Rekor HTTP client
// ---------------------------------------------------------------------------

/// Fire the per-anchor billing hook for a batch that produced a REAL Rekor
/// entry. `(no-key)` sentinels — returned by `submit_for_tenant` when no signing
/// key is configured — produced NO Rekor entry, so metering `audit_anchors` for
/// them would over-charge a billed tenant whose signing key was mis-provisioned
/// convention the ClickHouse `rekor_entry_id` backfill already enforces.
/// Extracted (not inlined) so the meter-vs-no-meter decision is unit-testable
/// without a live Rekor round-trip.
/// Whether a `rekor_entry_id` denotes a REAL external Rekor anchor, vs a
/// sentinel: `(no-key)` (unsigned), `(no-rekor)` (signed but not externally
/// anchored, ADR-057), or `(unknown-uuid)` (Rekor response had no parseable
pub(crate) fn is_real_rekor_entry(entry_id: &str) -> bool {
    !matches!(entry_id, "(no-key)" | "(no-rekor)" | "(unknown-uuid)")
}

fn fire_anchor_hook(anchor_hook: &Option<AnchorHook>, entry_uuid: &str, tenant_id: &TenantId) {
    if !is_real_rekor_entry(entry_uuid) {
        return;
    }
    if let Some(hook) = anchor_hook {
        hook(tenant_id.clone());
    }
}

/// Meter one successful Rekor anchor batch against the tenant's Polar customer
/// `polar_customer_id` via Postgres, then records `audit_anchors += 1`. Mirrors
/// `server.rs::spawn_billing_record` (the `TokensProcessed` path). Only real
/// anchors reach here — `(no-key)` batches are gated out by `fire_anchor_hook`.
/// A tenant with no Polar customer (unbilled) or no Postgres pool is a silent
/// no-op, so an unbilled tenant is never charged.
fn spawn_anchor_meter(recorder: Arc<crate::billing::Recorder>, tenant_id: TenantId) {
    tokio::spawn(async move {
        let pool = match crate::db::global_pool() {
            Some(p) => p,
            None => return,
        };
        let customer_id = match crate::db::tenants::get(pool, &tenant_id).await {
            Ok(Some(t)) => match t.polar_customer_id {
                Some(id) => crate::billing::PolarCustomerId(id),
                None => return, // unbilled tenant — never metered
            },
            Ok(None) => return,
            Err(err) => {
                tracing::warn!(error = %err, "audit-anchor billing tenant lookup failed");
                return;
            }
        };
        recorder
            .record(crate::billing::Meter::AuditAnchors, &customer_id, 1)
            .await;
    });
}

async fn anchor_task(
    rekor_client: RekorClient,
    clickhouse_client: Option<ClickhouseClient>,
    tenant_id: TenantId,
    hashes: Vec<audit_format::Hash>,
    start_seq: u64,
    end_seq: u64,
    anchor_hook: Option<AnchorHook>,
) {
    let root = audit_format::merkle_root_v2(&hashes);
    let root_hex = audit_format::hex_encode(&root);
    tracing::info!(
        merkle_root_hex = %root_hex,
        event_count = hashes.len(),
        start_seq,
        end_seq,
        tenant_id = %tenant_id,
        "anchoring audit batch to Sigstore Rekor"
    );

    let outcome = rekor_client.anchor_batch(&tenant_id, &root).await;
    let entry_id = outcome.rekor_entry_id();
    tracing::info!(
        rekor_entry_id = %entry_id,
        anchored = outcome.anchored,
        signed = outcome.is_signed(),
        "audit batch anchor outcome"
    );

    if let Some(ch) = clickhouse_client {
        // Persist the full offline-verifiable bundle (ADR-062) once per SIGNED
        // batch — anchored or not: the bound Ed25519 attestation verifies either
        // way, and the verifier degrades honestly when `anchor_state` is
        // unanchored. Rekor v2 has no online lookup, so the inclusion proof +
        // checkpoint captured at anchor time are the ONLY offline-verification
        // source (ADR-062 Amendment 1).
        if outcome.is_signed() {
            let row = build_anchor_record(&tenant_id, &root, start_seq, end_seq, &outcome);
            let ch = ch.clone();
            let tid = tenant_id.clone();
            tokio::spawn(async move {
                if let Err(err) = write_anchor_record(&ch, row).await {
                    tracing::warn!(
                        tenant_id = %tid,
                        start_seq,
                        end_seq,
                        error = %err,
                        "ClickHouse audit_anchor_records write failed"
                    );
                }
            });
        }
        // Zero-third-party (ADR-057): backfill the Ed25519 signature onto the
        // batch rows whenever the batch was signed, independent of Rekor.
        if outcome.is_signed() {
            let ch = ch.clone();
            let tid = tenant_id.clone();
            let sig = outcome.ed25519_sig_b64.clone();
            let pk = outcome.ed25519_pubkey_b64.clone();
            tokio::spawn(async move {
                if let Err(err) = backfill_signature(&ch, &tid, &sig, &pk, start_seq, end_seq).await
                {
                    tracing::warn!(
                        tenant_id = %tid,
                        start_seq,
                        end_seq,
                        error = %err,
                        "ClickHouse audit signature backfill failed"
                    );
                }
            });
        }
        // Backfill the Rekor log index onto rows only when a REAL anchor landed.
        if is_real_rekor_entry(&entry_id) {
            let ch = ch.clone();
            let tid = tenant_id.clone();
            let id = entry_id.clone();
            tokio::spawn(async move {
                if let Err(err) = backfill_rekor_entry_id(&ch, &tid, &id, start_seq, end_seq).await
                {
                    tracing::warn!(
                        rekor_entry_id = %id,
                        tenant_id = %tid,
                        start_seq,
                        end_seq,
                        error = %err,
                        "ClickHouse rekor_entry_id backfill failed"
                    );
                }
            });
        }
    }

    // `(no-key)` / `(no-rekor)` batches produced no Rekor entry and are gated out
    // by `fire_anchor_hook`. The hook only dispatches fire-and-forget work.
    fire_anchor_hook(&anchor_hook, &entry_id, &tenant_id);
}

/// **ADR-065 F1 anchor path** — anchor a seq-aligned batch `[start_seq …
/// end_seq]` by reading its leaf set back from ClickHouse (deduped) rather than
/// from a per-process in-memory buffer.
///
/// Under the PG-serialized append, exactly one process commits each batch-final
/// seq and calls this. Reading the contiguous rows from the durable store makes
/// the Merkle root correct regardless of which co-running process wrote which
/// row — the load-bearing fix for the cross-process anchor-batching hole. By the
/// time a batch-final seq commits, every seq `< end_seq` has committed too (the
/// `FOR UPDATE` lock serializes seq assignment), so all rows are durable.
///
/// The read uses `FINAL` so a crash-retry duplicate at any seq collapses to its
/// `ReplacingMergeTree` version winner — the same canonical leaf set the export
/// (GATE 1) and the verifier reconstruct, so the anchored root stays valid
/// (GATE 2). A missing / non-contiguous / short batch is logged and skipped
/// (never anchor a malformed batch); best-effort, like a Rekor outage.
async fn anchor_batch_from_ch(
    rekor_client: RekorClient,
    clickhouse_client: ClickhouseClient,
    tenant_id: TenantId,
    start_seq: u64,
    end_seq: u64,
    anchor_hook: Option<AnchorHook>,
) {
    let hashes =
        match read_batch_row_hashes(&clickhouse_client, &tenant_id, start_seq, end_seq).await {
            Ok(h) => h,
            Err(err) => {
                tracing::error!(
                    error = %err, tenant_id = %tenant_id, start_seq, end_seq,
                    "audit anchor: reading batch leaf set from ClickHouse failed — skipping anchor"
                );
                return;
            }
        };
    let expected = (end_seq - start_seq + 1) as usize;
    if hashes.len() != expected {
        // read_batch_row_hashes already enforces contiguity; a length mismatch
        // means rows are still missing (durability lag) — do NOT anchor a batch
        // whose leaves the verifier could not reconstruct.
        tracing::error!(
            got = hashes.len(), expected, tenant_id = %tenant_id, start_seq, end_seq,
            "audit anchor: batch leaf set is incomplete after dedup — skipping anchor"
        );
        return;
    }
    anchor_task(
        rekor_client,
        Some(clickhouse_client),
        tenant_id,
        hashes,
        start_seq,
        end_seq,
        anchor_hook,
    )
    .await;
}

/// Read the contiguous canonical `row_hash` leaf set for `[start … end]` from
/// ClickHouse, deduped via `FINAL` (GATE 1: the `ReplacingMergeTree` version
/// winner per `(tenant_id, seq)`, on an un-merged table). Fails if any seq in
/// the range is missing or the rows are non-contiguous — the caller must not
/// anchor a malformed batch.
async fn read_batch_row_hashes(
    client: &ClickhouseClient,
    tenant_id: &TenantId,
    start_seq: u64,
    end_seq: u64,
) -> anyhow::Result<Vec<audit_format::Hash>> {
    #[derive(Debug, serde::Deserialize, clickhouse::Row)]
    struct HashRow {
        seq: u64,
        row_hash: String,
    }
    // FINAL collapses any (tenant_id, seq) duplicate to its version winner. The
    // tenant_id filter is the CLAUDE.md hard rule; audit.rs is allow-listed in
    // no-raw-ch-query.sh (bounded, single-tenant, seq-windowed).
    let rows = client
        .query(
            "SELECT seq, row_hash FROM audit_log FINAL \
             WHERE tenant_id = ? AND seq >= ? AND seq <= ? \
             ORDER BY seq ASC",
        )
        .bind(tenant_id.to_string())
        .bind(start_seq)
        .bind(end_seq)
        .fetch_all::<HashRow>()
        .await
        .context("read audit_log batch row_hashes")?;

    let mut out = Vec::with_capacity(rows.len());
    for (expected, r) in (start_seq..).zip(rows) {
        anyhow::ensure!(
            r.seq == expected,
            "non-contiguous seq in anchor batch: expected {expected}, got {}",
            r.seq
        );
        let h = audit_format::hex_decode(&r.row_hash)
            .map_err(|e| anyhow::anyhow!("row_hash at seq {}: {e}", r.seq))?;
        out.push(h);
    }
    Ok(out)
}

/// One `(seq, prev_hash, row_hash)` triple read back from ClickHouse during
/// warm-reconcile. `prev_hash` / `row_hash` are hex.
#[derive(Debug, serde::Deserialize, clickhouse::Row)]
struct ReconcileRow {
    seq: u64,
    prev_hash: String,
    row_hash: String,
}

/// Read up to `limit` deduped rows with `seq > after_seq` for `tenant_id`,
/// ordered ascending, for warm-reconcile (HOLE C). `FINAL` picks the version
/// winner so a crash-retry orphan never masks the canonical row.
async fn read_rows_after(
    client: &ClickhouseClient,
    tenant_id: &TenantId,
    after_seq: u64,
    limit: u32,
) -> anyhow::Result<Vec<ReconcileRow>> {
    let rows = client
        .query(
            "SELECT seq, prev_hash, row_hash FROM audit_log FINAL \
             WHERE tenant_id = ? AND seq > ? \
             ORDER BY seq ASC \
             LIMIT ?",
        )
        .bind(tenant_id.to_string())
        .bind(after_seq)
        .bind(limit)
        .fetch_all::<ReconcileRow>()
        .await
        .context("read audit_log rows after head for reconcile")?;
    Ok(rows)
}

/// Submits hashedrekord entries to Sigstore Rekor v2.
///
/// zeroize on drop. `ring::Ed25519KeyPair` itself is not zeroizable
/// upstream — the SecretBox is the canonical zero-on-process-exit
/// source of truth.
///
/// store. When set, `submit_for_tenant` prefers it over the global
/// `signing` material; tenants without a keypair (or when the store
/// returns an error) fall back to the global key.
#[derive(Clone)]
struct RekorClient {
    http: reqwest::Client,
    /// Global / fallback signing material loaded from
    /// `TRACELANE_REKOR_SIGNING_KEY`. Used when no per-tenant store
    /// is configured, when a tenant has no keypair yet AND the
    /// store-lookup path errors, or in dev.
    signing: Option<Arc<SigningMaterial>>,
    /// Per-tenant signing-key store. When `Some`, the
    /// submit path looks up / generates a tenant-scoped key and
    /// uses it in preference to `signing`. When `None`, every
    /// tenant signs with the global key (Phase-3 behaviour).
    tenant_keys: Option<Arc<TenantAuditKeyStore>>,
    /// External transparency log to anchor to, or `None` for zero-third-party
    /// (ADR-057): sign + persist locally, never POST. Set via `TRACELANE_REKOR_URL`.
    rekor_url: Option<String>,
}

struct SigningMaterial {
    key_pair: signature::Ed25519KeyPair,
    /// PKCS#8 DER bytes; zeroes on drop.
    _pkcs8_zeroizing: SecretBox<Vec<u8>>,
}

impl RekorClient {
    fn new(
        signing_key_b64: Option<&str>,
        tenant_keys: Option<Arc<TenantAuditKeyStore>>,
    ) -> Result<Self> {
        let signing = signing_key_b64
            .map(|b64| {
                let mut der = B64.decode(b64).context("base64-decode signing key")?;
                let kp = signature::Ed25519KeyPair::from_pkcs8(&der)
                    .map_err(|e| anyhow::anyhow!("invalid Ed25519 PKCS#8 key: {e:?}"))?;
                let pkcs8 = SecretBox::new(Box::new(der.clone()));
                der.zeroize();
                Ok::<_, anyhow::Error>(Arc::new(SigningMaterial {
                    key_pair: kp,
                    _pkcs8_zeroizing: pkcs8,
                }))
            })
            .transpose()?;

        // Zero-third-party by default (ADR-057): only anchor to an EXPLICITLY
        // configured transparency log. Unset/empty → sign + persist locally, no
        // external POST (never silently default to the public Rekor).
        let rekor_url = std::env::var("TRACELANE_REKOR_URL")
            .ok()
            .filter(|u| !u.trim().is_empty());

        Ok(Self {
            // SSRF-hardened client — the operator-set TRACELANE_REKOR_URL must
            // never be allowed to point at IMDS / RFC1918 / loopback. The
            // per-call `ssrf_guard::validate_url` (in `submit_for_tenant`)
            // performs DNS resolution + blocklist check on every request,
            // matching the provider-adapter pattern from PR #8 (A9).
            http: crate::ssrf_guard::safe_client_builder()
                // Rekor v2 blocks until a checkpoint covers the new entry; the
                // CLIENTS.md guidance is >=20s. 25s with headroom (ADR-062).
                .timeout(std::time::Duration::from_secs(25))
                .build()
                .context("build Rekor HTTP client")?,
            signing,
            tenant_keys,
            rekor_url,
        })
    }

    /// Anchor a batch's Merkle `root` (ADR-062 Amendment 1).
    ///
    /// (1) Best-effort: anchor to Rekor v2 with the tenant's ECDSA anchor key —
    /// requires a configured `TRACELANE_REKOR_URL` AND a mintable per-tenant anchor
    /// key (Audit-SKU gated). (2) Ed25519-sign the BOUND [`local_attest_msg`] —
    /// which commits to the root, the anchor state, and (when anchored) the ECDSA
    /// pubkey / log URL / log index — with the per-tenant key (global fallback on a
    /// transient Postgres blip, matching the prior behaviour).
    ///
    /// Anchoring NEVER blocks: a Rekor failure leaves the batch signed-but-
    /// unanchored (`anchor_state = 0x00`) and the offline verifier degrades
    /// honestly. A strip / swap / downgrade of the exported bundle breaks the
    /// Ed25519 check (the attacker lacks the tenant key) — the C1/H3 fix.
    async fn anchor_batch(
        &self,
        tenant_id: &TenantId,
        root: &audit_format::Hash,
    ) -> BatchAnchorOutcome {
        // (0) Load/mint the Ed25519 signing key FIRST. This creates the
        //     `tenant_audit_keys` ROW that (1)'s conditional anchor-key UPDATE
        //     needs — otherwise a tenant's very FIRST batch would 0-row-UPDATE and
        //     could never mint its anchor key, anchoring as `unanchored`
        //     (security-review MED #2). Global-key fallback keeps the
        //     no-per-tenant-store / unentitled / Postgres-blip paths working.
        let ed_keypair = match self.tenant_keys.as_ref() {
            Some(store) => match store.get_or_create(tenant_id).await {
                Ok(kp) => Some(kp),
                Err(err) => {
                    tracing::warn!(
                        error = %err, tenant_id = %tenant_id,
                        "per-tenant Ed25519 lookup failed; falling back to global signing key"
                    );
                    None
                }
            },
            None => None,
        };

        // (1) Best-effort anchor to Rekor v2 (ECDSA — pure Ed25519 is rejected).
        //     The Ed25519 row now exists, so `get_or_create_anchor` can UPDATE it.
        let anchored: Option<(RekorV2Receipt, Vec<u8>)> = match (
            self.rekor_url.as_deref(),
            self.tenant_keys.as_ref(),
        ) {
            (Some(url), Some(store)) => match store.get_or_create_anchor(tenant_id).await {
                Ok(anchor_key) => match self.submit_anchor_v2(&anchor_key, root, url).await {
                    Ok(receipt) => Some((receipt, anchor_key.public_key_spki_der())),
                    Err(err) => {
                        tracing::warn!(
                            error = %err, tenant_id = %tenant_id,
                            "Rekor v2 anchor failed — batch signed locally, not anchored"
                        );
                        None
                    }
                },
                Err(err) => {
                    tracing::debug!(
                        error = %err, tenant_id = %tenant_id,
                        "no ECDSA anchor key (unentitled/dev) — batch signed locally, not anchored"
                    );
                    None
                }
            },
            _ => None,
        };

        // (2) Build the anchor_commitment + Ed25519-sign the BOUND message with the
        //     already-loaded per-tenant key (global fallback when absent).
        let commitment = match &anchored {
            // `log_index_u64` is parsed + validated once in `parse_v2_receipt`
            // (MED #1: no unvalidated string reaches the commitment).
            Some((r, spki)) => anchor_commitment(Some((spki, &r.log_url, r.log_index_u64))),
            None => anchor_commitment(None),
        };
        let msg = local_attest_msg(root, &commitment);

        let signed: Option<(Vec<u8>, Vec<u8>)> = match &ed_keypair {
            Some(kp) => Some((kp.sign(&msg), kp.public_key_bytes())),
            None => self.sign_with_global(&msg).map(|(s, p, _)| (s, p)),
        };

        let (ed25519_sig_b64, ed25519_pubkey_b64) = match signed {
            Some((sig, pk)) => (B64.encode(sig), B64.encode(pk)),
            None => {
                tracing::debug!(
                    tenant_id = %tenant_id,
                    "audit batch left unsigned (no signing key for this tenant or globally)"
                );
                (String::new(), String::new())
            }
        };
        let (anchored_flag, receipt, ecdsa_spki_b64) = match anchored {
            Some((r, spki)) => (true, Some(r), B64.encode(spki)),
            None => (false, None, String::new()),
        };

        BatchAnchorOutcome {
            ed25519_sig_b64,
            ed25519_pubkey_b64,
            anchored: anchored_flag,
            receipt,
            ecdsa_spki_b64,
        }
    }

    /// Submit `root`'s ECDSA anchor entry to Rekor v2 as a `hashedrekord` v0.0.2
    /// (ADR-062). Signs the [`anchor_artifact`] with the tenant ECDSA anchor key,
    /// POSTs to `{rekor_url}/api/v2/log/entries`, and returns the offline-
    /// verifiable receipt. SSRF-guarded per call; the 25s client timeout covers
    /// Rekor v2 blocking until a checkpoint covers the new entry.
    async fn submit_anchor_v2(
        &self,
        anchor_key: &TenantAnchorKeypair,
        root: &audit_format::Hash,
        rekor_url: &str,
    ) -> Result<RekorV2Receipt> {
        let artifact = anchor_artifact(root);
        let digest = sha256(&artifact);
        let sig_der = anchor_key.sign(&artifact).context("ECDSA anchor sign")?;
        let spki = anchor_key.public_key_spki_der();
        let body = json!({
            "hashedRekordRequestV002": {
                "digest": B64.encode(digest),
                "signature": {
                    "content": B64.encode(&sig_der),
                    "verifier": {
                        "publicKey": { "rawBytes": B64.encode(&spki) },
                        "keyDetails": "PKIX_ECDSA_P256_SHA_256"
                    }
                }
            }
        });
        let url = format!("{}/api/v2/log/entries", rekor_url.trim_end_matches('/'));
        // A9: SSRF guard on the operator-supplied Rekor URL. Blocks IMDS,
        // RFC1918, loopback, etc. — matches the provider-adapter pattern.
        crate::ssrf_guard::validate_url(&url)
            .await
            .context("Rekor v2 URL failed SSRF guard")?;
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("Rekor v2 POST /api/v2/log/entries")?;
        if !resp.status().is_success() {
            let status = resp.status();
            // Body may echo request detail; do NOT log it (provider-error rule).
            anyhow::bail!("Rekor v2 returned {status}");
        }
        let v: Value = resp.json().await.context("parse Rekor v2 response")?;
        parse_v2_receipt(&v, rekor_url)
    }

    /// Sign `msg` with the global `TRACELANE_REKOR_SIGNING_KEY`. `None` when no
    /// global key is configured. The `&'static str` label is a logging aid.
    fn sign_with_global(&self, msg: &[u8]) -> Option<(Vec<u8>, Vec<u8>, &'static str)> {
        let material = self.signing.as_ref()?;
        let sig = material.key_pair.sign(msg);
        let pubkey = material.key_pair.public_key().as_ref().to_vec();
        Some((sig.as_ref().to_vec(), pubkey, "global"))
    }
}

/// Parse a Rekor v2 `TransparencyLogEntry` JSON into the offline bundle
/// (ADR-062). Validates that `logIndex` is numeric; captures the canonicalized
/// body, inclusion proof, and signed checkpoint — the ONLY offline-verification
/// source, since Rekor v2 has no online entry lookup.
fn parse_v2_receipt(v: &Value, log_url: &str) -> Result<RekorV2Receipt> {
    let get_str = |val: &Value, k: &str| val.get(k).and_then(Value::as_str).map(str::to_owned);
    let log_index = get_str(v, "logIndex").context("Rekor v2 response missing logIndex")?;
    let log_index_u64 = log_index
        .parse::<u64>()
        .context("Rekor v2 logIndex is not a u64")?;
    let canonicalized_body_b64 =
        get_str(v, "canonicalizedBody").context("Rekor v2 response missing canonicalizedBody")?;
    let ip = v
        .get("inclusionProof")
        .context("Rekor v2 response missing inclusionProof")?;
    let checkpoint_envelope = ip
        .get("checkpoint")
        .and_then(|c| c.get("envelope"))
        .and_then(Value::as_str)
        .context("Rekor v2 inclusionProof missing checkpoint.envelope")?
        .to_owned();
    let inclusion_proof = json!({
        "log_index": get_str(ip, "logIndex"),
        "tree_size": get_str(ip, "treeSize"),
        "hashes": ip.get("hashes").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
    });
    Ok(RekorV2Receipt {
        log_url: log_url.to_owned(),
        log_index,
        log_index_u64,
        canonicalized_body_b64,
        inclusion_proof,
        checkpoint_envelope,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tracelane_shared::TenantId;
    use uuid::Uuid;

    fn tenant() -> TenantId {
        TenantId::from_jwt_claim(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap())
    }

    fn tenant2() -> TenantId {
        TenantId::from_jwt_claim(Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap())
    }

    //
    // These exercise `RekorClient::sign_with_global` plus the
    // `submit_for_tenant` selection logic *up to* the point of the HTTP
    // POST. We deliberately do NOT mock Rekor here — the wire shape is
    // covered by existing tests; what we want to lock down is which
    // signing key was actually used.
    //
    // Strategy: peel back to the layer below `submit_for_tenant`.
    // `sign_with_global` is `fn`, not `async`, so it's directly callable.

    /// Generate a fresh PKCS#8 Ed25519 keypair and return its
    /// base64 form. Used to seed RekorClient::new in tests.
    fn fresh_signing_key_b64() -> String {
        use ring::rand;
        let rng = rand::SystemRandom::new();
        let doc = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        B64.encode(doc.as_ref())
    }

    #[test]
    fn rekor_client_with_global_signs_root() {
        let key_b64 = fresh_signing_key_b64();
        let rekor = RekorClient::new(Some(&key_b64), None).unwrap();
        let root: audit_format::Hash = [7u8; 32];
        let (sig, pubkey, source) = rekor.sign_with_global(&root).expect("global key present");
        assert_eq!(sig.len(), 64, "Ed25519 signature is always 64 bytes");
        assert_eq!(pubkey.len(), 32, "Ed25519 raw public key is 32 bytes");
        assert_eq!(source, "global");
    }

    #[test]
    fn rekor_client_with_no_keys_returns_none() {
        let rekor = RekorClient::new(None, None).unwrap();
        let root: audit_format::Hash = [7u8; 32];
        assert!(
            rekor.sign_with_global(&root).is_none(),
            "no global key + no tenant store → sign_with_global is None"
        );
    }

    #[test]
    fn global_signing_is_deterministic_per_key() {
        // The same key signing the same root produces the same
        // signature (Ed25519 is deterministic per RFC 8032 §5.1.6).
        // This is the property the verifier relies on.
        let key_b64 = fresh_signing_key_b64();
        let rekor = RekorClient::new(Some(&key_b64), None).unwrap();
        let root: audit_format::Hash = [42u8; 32];
        let s1 = rekor.sign_with_global(&root).unwrap().0;
        let s2 = rekor.sign_with_global(&root).unwrap().0;
        assert_eq!(s1, s2);
    }

    #[test]
    fn signature_round_trips_and_detects_tamper() {
        // The zero-third-party verify property `tlane verify` relies on (ADR-057):
        // a signed Merkle root verifies against the stored pubkey, and a tampered
        // root fails. Uses `ring` verification directly (no external Rekor).
        let key_b64 = fresh_signing_key_b64();
        let rekor = RekorClient::new(Some(&key_b64), None).unwrap();
        let root: audit_format::Hash = [9u8; 32];
        let (sig, pubkey, _src) = rekor.sign_with_global(&root).expect("global key present");

        let pk = signature::UnparsedPublicKey::new(&signature::ED25519, &pubkey);
        assert!(
            pk.verify(root.as_slice(), &sig).is_ok(),
            "valid signature over the Merkle root must verify"
        );

        let mut tampered = root;
        tampered[0] ^= 0xff;
        assert!(
            pk.verify(tampered.as_slice(), &sig).is_err(),
            "a tampered Merkle root must fail verification"
        );
    }

    // ---- ADR-062 Amendment 1 — anchor crypto (FROZEN formats) ----------

    fn empty_outcome(signed: bool, receipt: Option<RekorV2Receipt>) -> BatchAnchorOutcome {
        BatchAnchorOutcome {
            ed25519_sig_b64: if signed { "sig".into() } else { String::new() },
            ed25519_pubkey_b64: if signed { "pk".into() } else { String::new() },
            anchored: receipt.is_some(),
            ecdsa_spki_b64: if receipt.is_some() {
                "spki".into()
            } else {
                String::new()
            },
            receipt,
        }
    }

    #[test]
    fn batch_outcome_rekor_entry_id_sentinels() {
        // unsigned → (no-key); signed-not-anchored → (no-rekor); anchored → index.
        assert_eq!(empty_outcome(false, None).rekor_entry_id(), "(no-key)");
        assert_eq!(empty_outcome(true, None).rekor_entry_id(), "(no-rekor)");
        let r = RekorV2Receipt {
            log_url: "https://log2025-1.rekor.sigstore.dev".into(),
            log_index: "18707688".into(),
            log_index_u64: 18707688,
            canonicalized_body_b64: "x".into(),
            inclusion_proof: json!({}),
            checkpoint_envelope: "cp".into(),
        };
        let out = empty_outcome(true, Some(r));
        assert_eq!(out.rekor_entry_id(), "18707688");
        // A numeric log index is a REAL anchor (metered + backfilled); sentinels aren't.
        assert!(is_real_rekor_entry(&out.rekor_entry_id()));
        assert!(!is_real_rekor_entry("(no-rekor)"));
    }

    #[test]
    fn anchor_commitment_layout_and_binding() {
        // Not-anchored is a single 0x00 byte.
        assert_eq!(anchor_commitment(None), vec![0x00]);
        // Anchored is 0x01 ‖ SHA256(spki) ‖ SHA256(url) ‖ u64_be(index) = 73 bytes.
        let c = anchor_commitment(Some((b"spki-a", "https://log", 42)));
        assert_eq!(c.len(), 1 + 32 + 32 + 8);
        assert_eq!(c[0], 0x01);
        assert_eq!(&c[c.len() - 8..], &42u64.to_be_bytes());
        // Swapping the ECDSA pubkey CHANGES the commitment (the C1 binding).
        let c2 = anchor_commitment(Some((b"spki-B", "https://log", 42)));
        assert_ne!(c, c2, "a swapped anchor pubkey must change the commitment");
        // Swapping the log index changes it (the H3 anchor-state binding).
        let c3 = anchor_commitment(Some((b"spki-a", "https://log", 43)));
        assert_ne!(c, c3);
    }

    #[test]
    fn signed_inputs_are_domain_separated() {
        let root: audit_format::Hash = [7u8; 32];
        let art = anchor_artifact(&root);
        assert!(
            art.starts_with(DOMAIN_ANCHOR),
            "ECDSA artifact carries its tag"
        );
        let msg = local_attest_msg(&root, &anchor_commitment(None));
        assert!(
            msg.starts_with(DOMAIN_ATTEST),
            "Ed25519 message carries its tag"
        );
        // The two domains are distinct → a sig from one context can't replay.
        assert_ne!(DOMAIN_ANCHOR, DOMAIN_ATTEST);
        // Different anchor states → different signed message (strip/downgrade breaks it).
        let anchored = anchor_commitment(Some((b"spki", "https://log", 1)));
        assert_ne!(
            local_attest_msg(&root, &anchor_commitment(None)),
            local_attest_msg(&root, &anchored),
            "anchored vs unanchored must sign different bytes"
        );
    }

    #[test]
    fn parse_v2_receipt_extracts_fields() {
        // A real captured Rekor v2 hashedrekord 201 response (trimmed hashes).
        let captured = r#"{
          "logIndex": "18707688",
          "logId": {"keyId": "zxGZFVvd0FEmjR8WrFwMdcAJ9vtaY/QXf44Y1wUeP6A="},
          "kindVersion": {"kind": "hashedrekord", "version": "0.0.2"},
          "inclusionProof": {
            "logIndex": "18707688",
            "rootHash": "oNe5oDkgcIFl3BqtbXy+0JrJU54Iz6xjljbQlGKkqu8=",
            "treeSize": "18707726",
            "hashes": ["b8zUioSfAF7SLOHOTuHJbm+aYp+qH/a1wzJaS8zSJwk="],
            "checkpoint": {"envelope": "log2025-1.rekor.sigstore.dev\n18707726\noNe5oDkg=\n\n— log2025-1.rekor.sigstore.dev zxGZ=\n"}
          },
          "canonicalizedBody": "eyJhcGlWZXJzaW9uIjoiMC4wLjIifQ=="
        }"#;
        let v: Value = serde_json::from_str(captured).unwrap();
        let r = parse_v2_receipt(&v, "https://log2025-1.rekor.sigstore.dev").unwrap();
        assert_eq!(r.log_index, "18707688");
        assert_eq!(r.log_url, "https://log2025-1.rekor.sigstore.dev");
        assert!(
            r.checkpoint_envelope
                .starts_with("log2025-1.rekor.sigstore.dev\n18707726\n")
        );
        assert_eq!(r.inclusion_proof["tree_size"], "18707726");
        assert_eq!(r.inclusion_proof["hashes"].as_array().unwrap().len(), 1);
        assert!(!r.canonicalized_body_b64.is_empty());
    }

    #[test]
    fn parse_v2_receipt_rejects_nonnumeric_logindex() {
        let v: Value = serde_json::from_str(
            r#"{"logIndex":"not-a-number","canonicalizedBody":"x","inclusionProof":{"checkpoint":{"envelope":"e"}}}"#,
        )
        .unwrap();
        assert!(parse_v2_receipt(&v, "https://log").is_err());
    }

    /// Keygen utility — prints a fresh ring-generated **v2** PKCS#8 Ed25519 key for
    /// provisioning `TRACELANE_REKOR_SIGNING_KEY`. `openssl genpkey` emits v1 PKCS#8
    /// which `RekorClient::new`'s `from_pkcs8` rejects; this is the reliable source.
    /// Run explicitly:
    ///   cargo test -p gateway --bin gateway print_signing_key -- --ignored --nocapture
    #[test]
    #[ignore = "keygen utility; prints key material — run explicitly"]
    fn print_signing_key() {
        println!("TRACELANE_REKOR_SIGNING_KEY={}", fresh_signing_key_b64());
    }

    /// `row_hash` (hex) + `signature` (b64) + `signing_pubkey` (b64) via env,
    /// recompute the 1-row batch Merkle root exactly as the gateway did and verify
    /// the Ed25519 signature — the honest, green-on-real-data proof. With
    /// `SIGNING_KEY_B64` it also asserts the stored pubkey equals the pubkey
    /// DERIVED from the signing key (H1: pin against the key, not the row mirror).
    /// Run:
    ///   ROW_HASH=<hex> SIG_B64=<b64> PUBKEY_B64=<b64> SIGNING_KEY_B64=<b64> \
    ///     cargo test -p gateway --bin gateway verify_signed_row -- --ignored --nocapture
    #[test]
    #[ignore = "on-node proof; requires ROW_HASH/SIG_B64/PUBKEY_B64 env"]
    fn verify_signed_row() {
        let row_hash_hex = std::env::var("ROW_HASH").expect("ROW_HASH");
        let sig = B64
            .decode(std::env::var("SIG_B64").expect("SIG_B64"))
            .expect("SIG_B64 base64");
        let pubkey = B64
            .decode(std::env::var("PUBKEY_B64").expect("PUBKEY_B64"))
            .expect("PUBKEY_B64 base64");

        // Recompute the single-leaf batch Merkle root with the SAME function the
        // gateway signs (anchor_every=1 → one row per batch).
        let mut leaf: audit_format::Hash = [0u8; 32];
        for (i, b) in leaf.iter_mut().enumerate() {
            *b = u8::from_str_radix(&row_hash_hex[i * 2..i * 2 + 2], 16).expect("row_hash hex");
        }
        let root = audit_format::merkle_root_v2(&[leaf]);

        let pk = signature::UnparsedPublicKey::new(&signature::ED25519, &pubkey);
        pk.verify(root.as_slice(), &sig)
            .expect("prod signature must verify against the recomputed Merkle root");
        println!("PROOF ✓ prod signed row verifies (Ed25519 over recomputed Merkle root)");

        if let Ok(key_b64) = std::env::var("SIGNING_KEY_B64") {
            let der = B64.decode(key_b64).expect("SIGNING_KEY_B64 base64");
            let kp = signature::Ed25519KeyPair::from_pkcs8(&der).expect("signing key pkcs8");
            assert_eq!(
                kp.public_key().as_ref(),
                &pubkey[..],
                "stored signing_pubkey must equal the pubkey derived from the signing key (H1 pin)"
            );
            println!(
                "PROOF ✓ stored pubkey == derived-from-signing-key pubkey (H1 — not the row mirror)"
            );
        }

        let mut tampered = root;
        tampered[0] ^= 0xff;
        assert!(
            pk.verify(tampered.as_slice(), &sig).is_err(),
            "a tampered Merkle root must fail verification"
        );
        println!("PROOF ✓ tampered root fails verification");
    }

    #[test]
    fn different_global_keys_produce_different_signatures() {
        let key_a = fresh_signing_key_b64();
        let key_b = fresh_signing_key_b64();
        let rekor_a = RekorClient::new(Some(&key_a), None).unwrap();
        let rekor_b = RekorClient::new(Some(&key_b), None).unwrap();
        let root: audit_format::Hash = [99u8; 32];
        let sig_a = rekor_a.sign_with_global(&root).unwrap().0;
        let sig_b = rekor_b.sign_with_global(&root).unwrap().0;
        assert_ne!(
            sig_a, sig_b,
            "different signing keys must yield different signatures"
        );
    }

    // Note: end-to-end `submit_for_tenant` with a real
    // `TenantAuditKeyStore` requires a live Postgres + ByokMasterKey
    // pair — that's covered in
    // `crates/gateway/tests/postgres_tenant_integration.rs` (separate
    // integration tier; uses TEST_POSTGRES_URL). In-process unit
    // tests can't fake the store without faking BYOK, which is more
    // surface than the C4 invariant warrants. The unit-level locked
    // invariant is "global signing yields a 64-byte Ed25519 sig with
    // a 32-byte public key and the source label 'global'" — done
    // above.

    #[tokio::test]
    async fn audit_chain_append_increments_seq_per_tenant() {
        let chain = AuditChain::new(100, None, None).unwrap();
        let ev_for = |t: &TenantId| AuditEvent {
            tenant_id: t.clone(),
            event_type: "request",
            actor: "user1".into(),
            payload: json!({}),
        };
        chain.append(ev_for(&tenant())).await.unwrap();
        chain.append(ev_for(&tenant())).await.unwrap();
        chain.append(ev_for(&tenant2())).await.unwrap();

        let s1 = chain.states.get(&tenant()).unwrap();
        let s2 = chain.states.get(&tenant2()).unwrap();
        assert_eq!(s1.lock().seq, 2);
        assert_eq!(s2.lock().seq, 1);
    }

    // ---- B-108 forward-fix integration harness (ADR-065 F1) --------------
    //
    // These `#[ignore]`d tests need a live Postgres (audit_chain_state) AND a
    // live ClickHouse (audit_log as ReplacingMergeTree). Run them from the dev
    // stack (`docker compose -f infra/dev/docker-compose.yml up -d`) serially —
    // GATE 1 / GATE 2 recreate the shared `audit_log` table:
    //   POSTGRES_TEST_URL=postgres://… CLICKHOUSE_TEST_URL=http://localhost:8123 \
    //     cargo test -p gateway --bin gateway audit::tests:: -- --ignored --nocapture

    /// Build a deadpool from `POSTGRES_TEST_URL`.
    fn pg_test_pool() -> deadpool_postgres::Pool {
        let url = std::env::var("POSTGRES_TEST_URL")
            .expect("POSTGRES_TEST_URL required (live Postgres with audit_chain_state)");
        let pg_cfg: tokio_postgres::Config = url.parse().unwrap();
        let mut cfg = deadpool_postgres::Config::new();
        cfg.host = pg_cfg.get_hosts().first().and_then(|h| match h {
            tokio_postgres::config::Host::Tcp(s) => Some(s.clone()),
            _ => None,
        });
        cfg.port = pg_cfg.get_ports().first().copied();
        cfg.user = pg_cfg.get_user().map(str::to_owned);
        cfg.password = pg_cfg
            .get_password()
            .map(|p| String::from_utf8_lossy(p).into_owned());
        cfg.dbname = pg_cfg.get_dbname().map(str::to_owned);
        cfg.create_pool(
            Some(deadpool_postgres::Runtime::Tokio1),
            tokio_postgres::NoTls,
        )
        .unwrap()
    }

    /// `CLICKHOUSE_TEST_URL` or `None` (skip the test).
    fn ch_test_url() -> Option<String> {
        std::env::var("CLICKHOUSE_TEST_URL").ok()
    }

    fn ch_test_client(url: &str) -> ClickhouseClient {
        ClickhouseClient::default()
            .with_url(url)
            .with_database("tracelane")
    }

    /// Seed a `tenants` row so the `audit_chain_state.tenant_id` FK is satisfied
    /// (the PG-serialized append INSERTs the chain-state row synchronously now).
    async fn seed_tenant(pool: &deadpool_postgres::Pool, tenant: &TenantId) {
        let client = pool.get().await.unwrap();
        let org = format!("org-test-{}", uuid::Uuid::new_v4());
        client
            .execute(
                "INSERT INTO tenants (id, workos_org_id) VALUES ($1, $2) \
                 ON CONFLICT (id) DO NOTHING",
                &[tenant.as_uuid(), &org],
            )
            .await
            .unwrap();
    }

    /// The persisted head seq for `tenant`, or `None` if no row yet.
    async fn pg_head_seq(pool: &deadpool_postgres::Pool, tenant: &TenantId) -> Option<u64> {
        crate::db::audit_chain_state::load_all(pool)
            .await
            .unwrap()
            .into_iter()
            .find(|r| &r.tenant_id == tenant)
            .map(|r| r.last_seq)
    }

    /// Drop + recreate `audit_log` as ReplacingMergeTree (the post-migration
    /// engine) for a fresh test. Destructive to the shared table — deliberate.
    async fn ch_reset_replacing_audit_log(ch: &ClickhouseClient) {
        ch.query("CREATE DATABASE IF NOT EXISTS tracelane")
            .execute()
            .await
            .unwrap();
        for stmt in [
            "DROP TABLE IF EXISTS tracelane.audit_log_pre_rmt",
            "DROP TABLE IF EXISTS tracelane.audit_log_rmt",
            "DROP TABLE IF EXISTS tracelane.audit_log",
            "CREATE TABLE tracelane.audit_log \
             (tenant_id String, seq UInt64, event_time DateTime64(6,'UTC'), \
              event_type String, actor String, payload String DEFAULT '{}', \
              prev_hash String DEFAULT '', row_hash String, \
              rekor_entry_id Nullable(String), signature String DEFAULT '', \
              signing_pubkey String DEFAULT '') \
             ENGINE = ReplacingMergeTree(event_time) \
             PARTITION BY toYYYYMM(event_time) ORDER BY (tenant_id, seq) \
             SETTINGS index_granularity = 8192",
        ] {
            ch.query(stmt).execute().await.unwrap();
        }
    }

    /// Drop + recreate `audit_log` as the PRE-migration MergeTree, for GATE 2
    /// (which then applies migration 11 to convert it).
    async fn ch_reset_mergetree_audit_log(ch: &ClickhouseClient) {
        ch.query("CREATE DATABASE IF NOT EXISTS tracelane")
            .execute()
            .await
            .unwrap();
        for stmt in [
            "DROP TABLE IF EXISTS tracelane.audit_log_pre_rmt",
            "DROP TABLE IF EXISTS tracelane.audit_log_rmt",
            "DROP TABLE IF EXISTS tracelane.audit_log",
            "CREATE TABLE tracelane.audit_log \
             (tenant_id String, seq UInt64, event_time DateTime64(6,'UTC'), \
              event_type String, actor String, payload String DEFAULT '{}', \
              prev_hash String DEFAULT '', row_hash String, \
              rekor_entry_id Nullable(String), signature String DEFAULT '', \
              signing_pubkey String DEFAULT '') \
             ENGINE = MergeTree() \
             PARTITION BY toYYYYMM(event_time) ORDER BY (tenant_id, seq) \
             SETTINGS index_granularity = 8192",
        ] {
            ch.query(stmt).execute().await.unwrap();
        }
    }

    /// Apply migration 11 (MergeTree → ReplacingMergeTree) statement-by-statement,
    /// stripping comment lines (mirrors `apply-migration-03.sh`).
    async fn apply_migration_11(ch: &ClickhouseClient) {
        let sql = include_str!(
            "../../../infra/dev/clickhouse/migrations/11_audit_log_replacingmergetree.sql"
        );
        // Strip line comments FIRST (a `;` inside a comment must not split a
        // statement), THEN split on `;`.
        let cleaned: String = sql
            .lines()
            .map(|l| match l.find("--") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n");
        for stmt in cleaned.split(';') {
            let stmt = stmt.trim();
            if stmt.is_empty() {
                continue;
            }
            ch.query(stmt).execute().await.unwrap();
        }
    }

    /// Read every row for `tenant` deduped via `FINAL` and assert the chain is
    /// (a) continuous — seq `0..expected_len`, zero dup, zero gap — AND (b)
    /// cryptographically valid — each `prev_hash` chains and each `row_hash`
    /// recomputes. The Rust-side equivalent of the TS verifier's
    /// `hash_chain_valid: true`, over real writes.
    async fn assert_chain_continuous_and_valid(
        ch: &ClickhouseClient,
        tenant: &TenantId,
        expected_len: u64,
    ) {
        #[derive(serde::Deserialize, clickhouse::Row)]
        struct R {
            seq: u64,
            event_type: String,
            actor: String,
            payload: String,
            prev_hash: String,
            row_hash: String,
        }
        let rows = ch
            .query(
                "SELECT seq, event_type, actor, payload, prev_hash, row_hash \
                 FROM audit_log FINAL WHERE tenant_id = ? ORDER BY seq ASC",
            )
            .bind(tenant.to_string())
            .fetch_all::<R>()
            .await
            .unwrap();
        assert_eq!(
            rows.len() as u64,
            expected_len,
            "deduped row count must equal appended count — no dup, no gap"
        );
        let mut prev = audit_format::genesis_prev_hash(tenant);
        for (expected_seq, r) in (0u64..).zip(rows) {
            assert_eq!(
                r.seq, expected_seq,
                "seq must be contiguous 0..N (no dup, no gap)"
            );
            let stored_prev = audit_format::hex_decode(&r.prev_hash).unwrap();
            assert_eq!(
                stored_prev, prev,
                "prev_hash at seq {} must chain from the prior row_hash",
                r.seq
            );
            let stored_row = audit_format::hex_decode(&r.row_hash).unwrap();
            let recomputed = audit_format::row_hash_v2(
                &prev,
                tenant,
                r.seq,
                &r.event_type,
                &r.actor,
                &r.payload,
            );
            assert_eq!(
                recomputed, stored_row,
                "row_hash at seq {} must recompute — the chain is tamper-evident-valid",
                r.seq
            );
            prev = stored_row;
        }
    }

    /// Restart-survival (ADR-042 bug #4, now ADR-065 F1): the tamper-evident
    /// chain seq MUST resume across a gateway restart — never reset to genesis.
    /// With the PG-serialized append the persisted head (`audit_chain_state`) is
    /// the source of truth, advanced synchronously per append; this asserts the
    /// PG head, not the (now-unused-on-the-PG-path) in-memory DashMap.
    ///
    ///   POSTGRES_TEST_URL=postgres://… cargo test -p gateway --bin gateway \
    ///     audit::tests::chain_seq_survives_restart -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn chain_seq_survives_restart() {
        let pool = pg_test_pool();
        crate::db::apply_migrations(&pool).await.unwrap();

        let t = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        seed_tenant(&pool, &t).await;
        let ev = || AuditEvent {
            tenant_id: t.clone(),
            event_type: "request",
            actor: "restart-test".into(),
            payload: json!({}),
        };

        // Boot 1: two appends (row seq 0, 1) → persisted last_seq = 1
        // (synchronously — the upsert is now inside the append transaction).
        let chain1 = AuditChain::with_pg_pool(100, None, None, Some(pool.clone())).unwrap();
        chain1.warm_from_postgres().await.unwrap();
        chain1.append(ev()).await.unwrap();
        chain1.append(ev()).await.unwrap();
        assert_eq!(
            pg_head_seq(&pool, &t).await,
            Some(1),
            "two appends → persisted head seq 1 (no spawn lag; the upsert is in-tx)"
        );
        drop(chain1); // simulated gateway restart

        // Boot 2: warm resumes; the next append continues the chain at seq 2.
        let chain2 = AuditChain::with_pg_pool(100, None, None, Some(pool.clone())).unwrap();
        chain2.warm_from_postgres().await.unwrap();
        chain2.append(ev()).await.unwrap();
        assert_eq!(
            pg_head_seq(&pool, &t).await,
            Some(2),
            "seq must RESUME from the persisted head (row seq 2), not reset to genesis"
        );
    }

    /// **B-108 cross-process seq race (the whole point of ADR-065 F1).**
    ///
    /// `audit_keys.rs` `get_or_create` anchor-KEY race (a different table,
    /// `tenant_audit_keys`, whose failure is a duplicate *keypair*, closed by
    /// `ON CONFLICT (tenant_id) DO NOTHING` + reload). Here, two co-running
    /// gateways (blue-green overlap) must never mint the same *seq* for two
    /// different events.
    ///
    /// TWO independent `AuditChain` instances share ONE Postgres pool — each has
    /// its OWN `DashMap`, so the intra-process `parking_lot::Mutex` is genuinely
    /// NOT shared; only the per-tenant `SELECT … FOR UPDATE` row lock serializes
    /// them. They hammer parallel appends for one tenant; we assert **zero
    /// duplicate seqs, zero gaps, and a continuous verifiable chain** — AND, on
    /// the RAW (non-`FINAL`) table, that no duplicate row was ever written (the
    /// fix PREVENTS the dup, it does not merely dedup it on read). Under the old
    /// process-local Mutex both processes would mint 0..N-1 → dup at every seq.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn b108_cross_process_seq_race() {
        let Some(url) = ch_test_url() else {
            eprintln!("skip b108_cross_process_seq_race: CLICKHOUSE_TEST_URL unset");
            return;
        };
        let pool = pg_test_pool();
        crate::db::apply_migrations(&pool).await.unwrap();
        let ch = ch_test_client(&url);
        ch_reset_replacing_audit_log(&ch).await;

        let tenant = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        seed_tenant(&pool, &tenant).await;
        // anchor_every huge → no anchoring fires during the race (seq integrity
        // is what we test; the anchor leaf-read is proved by GATE 2).
        let chain_a = Arc::new(
            AuditChain::with_pg_pool(1_000_000, None, Some(&url), Some(pool.clone())).unwrap(),
        );
        let chain_b = Arc::new(
            AuditChain::with_pg_pool(1_000_000, None, Some(&url), Some(pool.clone())).unwrap(),
        );

        const PER_PROCESS: u64 = 100;
        let mut handles = Vec::new();
        for chain in [chain_a, chain_b] {
            let tenant = tenant.clone();
            handles.push(tokio::spawn(async move {
                for i in 0..PER_PROCESS {
                    chain
                        .append(AuditEvent {
                            tenant_id: tenant.clone(),
                            event_type: "request",
                            actor: format!("actor-{i}"),
                            payload: json!({ "i": i }),
                        })
                        .await
                        .expect("append must succeed under cross-process contention");
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        let total = PER_PROCESS * 2;
        // (1) Continuous, cryptographically-valid chain (verifier-equivalent).
        assert_chain_continuous_and_valid(&ch, &tenant, total).await;

        // (2) RAW proof the fix PREVENTS the dup (not just dedups on read):
        //     the un-FINAL row count == appended count AND every seq is distinct.
        #[derive(serde::Deserialize, clickhouse::Row)]
        struct C {
            raw: u64,
            distinct: u64,
        }
        let counts = ch
            .query(
                "SELECT count() AS raw, uniqExact(seq) AS distinct \
                 FROM audit_log WHERE tenant_id = ?",
            )
            .bind(tenant.to_string())
            .fetch_one::<C>()
            .await
            .unwrap();
        assert_eq!(
            counts.raw, total,
            "RAW row count must equal appended count — NO duplicate row was written"
        );
        assert_eq!(
            counts.distinct, total,
            "every seq must be distinct — no seq was reused across processes"
        );

        // (3) The persisted head is the last assigned seq.
        let head = crate::db::audit_chain_state::load_all(&pool)
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.tenant_id == tenant)
            .expect("head row must exist");
        assert_eq!(head.last_seq, total - 1, "PG head == last assigned seq");
    }

    /// **B-108 crash-mid-append + restart reconcile (ADR-065 HOLE C).**
    ///
    /// Simulate a crash AFTER the durable ClickHouse write but BEFORE the
    /// Postgres head advance/commit: a durable CH row exists at seq N that
    /// chains from the persisted head, while PG still points at N-1. On restart,
    /// `warm_from_postgres` must ADOPT the durable row (advance PG to it), never
    /// orphan or reset it — and the next append continues at N+1 with no dup and
    /// no gap.
    #[tokio::test]
    #[ignore]
    async fn b108_crash_mid_append_reconcile() {
        let Some(url) = ch_test_url() else {
            eprintln!("skip b108_crash_mid_append_reconcile: CLICKHOUSE_TEST_URL unset");
            return;
        };
        let pool = pg_test_pool();
        crate::db::apply_migrations(&pool).await.unwrap();
        let ch = ch_test_client(&url);
        ch_reset_replacing_audit_log(&ch).await;

        let tenant = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        seed_tenant(&pool, &tenant).await;
        let chain =
            AuditChain::with_pg_pool(1_000_000, None, Some(&url), Some(pool.clone())).unwrap();
        chain.warm_from_postgres().await.unwrap();

        // 3 committed appends → head seq 2.
        for i in 0..3u64 {
            chain
                .append(AuditEvent {
                    tenant_id: tenant.clone(),
                    event_type: "request",
                    actor: "committed".into(),
                    payload: json!({ "i": i }),
                })
                .await
                .unwrap();
        }
        let head = crate::db::audit_chain_state::load_all(&pool)
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.tenant_id == tenant)
            .unwrap();
        assert_eq!(head.last_seq, 2);
        let h2 = head.last_row_hash;

        // SIMULATE the crash window: write a durable CH row at seq 3 that chains
        // from h2, but do NOT advance the PG head (the process "died" here).
        let payload3 = audit_format::canonical_payload(&tracelane_policy::pii::redact_json(
            &json!({ "i": 3 }),
        ));
        let h3 = audit_format::row_hash_v2(&h2, &tenant, 3, "request", "crash", &payload3);
        write_audit_row(
            &ch,
            AuditLogRow {
                tenant_id: tenant.to_string(),
                seq: 3,
                event_time: Utc::now().timestamp_micros(),
                event_type: "request".to_string(),
                actor: "crash".to_string(),
                payload: payload3,
                prev_hash: audit_format::hex_encode(&h2),
                row_hash: audit_format::hex_encode(&h3),
                rekor_entry_id: None,
                signature: String::new(),
                signing_pubkey: String::new(),
            },
        )
        .await
        .unwrap();

        // Restart: a fresh instance warm-reconciles → must adopt seq 3.
        let chain2 =
            AuditChain::with_pg_pool(1_000_000, None, Some(&url), Some(pool.clone())).unwrap();
        chain2.warm_from_postgres().await.unwrap();
        let head2 = crate::db::audit_chain_state::load_all(&pool)
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.tenant_id == tenant)
            .unwrap();
        assert_eq!(
            head2.last_seq, 3,
            "reconcile must ADOPT the durable CH row (seq 3)"
        );
        assert_eq!(
            head2.last_row_hash, h3,
            "adopted head hash == the durable row's hash"
        );

        // Next append continues at seq 4 — no dup at 3, no gap.
        chain2
            .append(AuditEvent {
                tenant_id: tenant.clone(),
                event_type: "request",
                actor: "post-restart".into(),
                payload: json!({ "i": 4 }),
            })
            .await
            .unwrap();
        assert_chain_continuous_and_valid(&ch, &tenant, 5).await;
    }

    /// **GATE 2 — a real (non-re-chained) anchored batch reconstructs to its
    /// stored `merkle_root` after the ReplacingMergeTree cutover.**
    ///
    /// Write a clean anchored batch to the PRE-migration MergeTree table, record
    /// the Merkle root, apply migration 11, then re-read the leaf set via the
    /// SAME deduped path the anchor uses (`read_batch_row_hashes`, `FINAL`) and
    /// assert the root reconstructs identically. If this failed, the migration
    /// would invalidate real anchors — STOP.
    #[tokio::test]
    #[ignore]
    async fn gate2_anchored_root_preserved_after_migration() {
        let Some(url) = ch_test_url() else {
            eprintln!("skip gate2: CLICKHOUSE_TEST_URL unset");
            return;
        };
        let ch = ch_test_client(&url);
        ch_reset_mergetree_audit_log(&ch).await;

        let tenant = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        const N: u64 = 8;
        let base_us = Utc::now().timestamp_micros();
        let mut prev = audit_format::genesis_prev_hash(&tenant);
        let mut leaves: Vec<audit_format::Hash> = Vec::new();
        for seq in 0..N {
            let payload = audit_format::canonical_payload(&json!({ "i": seq }));
            let rh = audit_format::row_hash_v2(&prev, &tenant, seq, "request", "u", &payload);
            write_audit_row(
                &ch,
                AuditLogRow {
                    tenant_id: tenant.to_string(),
                    seq,
                    event_time: base_us + seq as i64,
                    event_type: "request".to_string(),
                    actor: "u".to_string(),
                    payload,
                    prev_hash: audit_format::hex_encode(&prev),
                    row_hash: audit_format::hex_encode(&rh),
                    rekor_entry_id: None,
                    signature: String::new(),
                    signing_pubkey: String::new(),
                },
            )
            .await
            .unwrap();
            leaves.push(rh);
            prev = rh;
        }
        let root_before = audit_format::merkle_root_v2(&leaves);

        // Convert the crown-jewel table MergeTree → ReplacingMergeTree.
        apply_migration_11(&ch).await;

        // Re-read the batch leaf set (deduped) and re-verify the root.
        let hashes = read_batch_row_hashes(&ch, &tenant, 0, N - 1).await.unwrap();
        assert_eq!(
            hashes, leaves,
            "the deduped canonical leaf set must be byte-identical after the cutover"
        );
        let root_after = audit_format::merkle_root_v2(&hashes);
        assert_eq!(
            root_after, root_before,
            "a real anchored batch must reconstruct to its stored merkle_root after migration"
        );
    }

    #[tokio::test]
    async fn audit_chain_anchors_at_threshold() {
        let chain = AuditChain::new(2, None, None).unwrap();
        let ev = || AuditEvent {
            tenant_id: tenant(),
            event_type: "request",
            actor: "user1".into(),
            payload: json!({}),
        };
        chain.append(ev()).await.unwrap();
        chain.append(ev()).await.unwrap();

        let state = chain.states.get(&tenant()).unwrap();
        assert_eq!(state.lock().pending_hashes.len(), 0);
    }

    /// REAL Rekor entry but NEVER a `(no-key)` sentinel. `Meter::AuditAnchors`
    /// previously had NO call-site at all (the ADR-048 "Polar meters
    /// TokensProcessed + AuditAnchors" claim was false; the dashboard
    /// `audit_anchors` dimension was permanently 0). Now it is wired — but a
    /// `(no-key)` batch (no signing key configured) produced no Rekor entry, so
    /// metering it would over-charge a billed tenant whose key was mis-provisioned.
    /// Pure + deterministic: exercises the meter-vs-no-meter gate directly, with
    /// no Rekor round-trip. The append→anchor path that invokes this hook is
    /// covered by `audit_chain_anchors_at_threshold`.
    #[test]
    fn fire_anchor_hook_meters_real_entry_but_not_no_key() {
        let fired: Arc<Mutex<Vec<TenantId>>> = Arc::new(Mutex::new(Vec::new()));
        let f = fired.clone();
        let hook: Option<AnchorHook> = Some(Arc::new(move |tid: TenantId| f.lock().push(tid)));

        // A real Rekor entry uuid → meters exactly one anchor for the tenant.
        fire_anchor_hook(&hook, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", &tenant());
        assert_eq!(
            fired.lock().len(),
            1,
            "a real Rekor entry meters one anchor"
        );
        assert_eq!(
            fired.lock()[0],
            tenant(),
            "hook receives the anchoring tenant"
        );

        // The `(no-key)` sentinel produced no Rekor entry → MUST NOT meter.
        fired.lock().clear();
        fire_anchor_hook(&hook, "(no-key)", &tenant());
        assert!(
            fired.lock().is_empty(),
            "a (no-key) batch produced no anchor and must never be metered"
        );

        // No hook wired (billing unconfigured) → no-op, no panic.
        fire_anchor_hook(&None, "a1b2c3d4", &tenant());
    }

    /// unmetered anchoring (POLAR_ACCESS_TOKEN unset) must never break the ledger.
    #[tokio::test]
    async fn anchor_without_billing_hook_is_a_noop_not_a_panic() {
        let chain = AuditChain::new(1, None, None).unwrap(); // anchor every event
        chain
            .append(AuditEvent {
                tenant_id: tenant(),
                event_type: "request",
                actor: "u".into(),
                payload: json!({}),
            })
            .await
            .expect("append + anchor must succeed with no hook wired");
        // Yield so the fire-and-forget anchor task runs; no hook → nothing to do.
        tokio::task::yield_now().await;
        assert_eq!(
            chain
                .states
                .get(&tenant())
                .unwrap()
                .lock()
                .pending_hashes
                .len(),
            0,
            "the batch still anchored (pending drained) without a hook"
        );
    }

    #[tokio::test]
    async fn cross_tenant_appends_do_not_share_state() {
        // R1 H5 — under v1 a single mutex serialised all tenants AND
        // the seq counter was shared. v2 has per-tenant state.
        let chain = AuditChain::new(100, None, None).unwrap();
        let ev = |t: &TenantId| AuditEvent {
            tenant_id: t.clone(),
            event_type: "request",
            actor: "u".into(),
            payload: json!({}),
        };
        chain.append(ev(&tenant())).await.unwrap();
        chain.append(ev(&tenant2())).await.unwrap();

        let h1 = chain.states.get(&tenant()).unwrap().lock().prev_hash;
        let h2 = chain.states.get(&tenant2()).unwrap().lock().prev_hash;
        assert_ne!(h1, h2, "different tenants must derive different chains");
    }

    #[tokio::test]
    async fn first_append_uses_genesis_seed_not_zero() {
        let chain = AuditChain::new(100, None, None).unwrap();
        let ev = AuditEvent {
            tenant_id: tenant(),
            event_type: "request",
            actor: "u".into(),
            payload: json!({}),
        };
        chain.append(ev).await.unwrap();

        let expected_seed = audit_format::genesis_prev_hash(&tenant());
        let payload = audit_format::canonical_payload(&json!({}));
        let expected_row_hash =
            audit_format::row_hash_v2(&expected_seed, &tenant(), 0, "request", "u", &payload);
        let state = chain.states.get(&tenant()).unwrap();
        assert_eq!(state.lock().prev_hash, expected_row_hash);
    }

    #[tokio::test]
    async fn audit_redacts_pii_payload_into_chain_hash() {
        let chain_a = AuditChain::new(100, None, None).unwrap();
        let chain_b = AuditChain::new(100, None, None).unwrap();
        let t = tenant();
        chain_a
            .append(AuditEvent {
                tenant_id: t.clone(),
                event_type: "request",
                actor: "u".into(),
                payload: json!({"q": "user@example.com"}),
            })
            .await
            .unwrap();
        chain_b
            .append(AuditEvent {
                tenant_id: t.clone(),
                event_type: "request",
                actor: "u".into(),
                payload: json!({"q": "[REDACTED:email]"}),
            })
            .await
            .unwrap();
        let a = chain_a.states.get(&t).unwrap().lock().prev_hash;
        let b = chain_b.states.get(&t).unwrap().lock().prev_hash;
        assert_eq!(
            a, b,
            "pre-redaction must be byte-for-byte identical to a payload that was never raw"
        );
    }

    /// FT-06 chaos: Rekor outage does not affect the local hash chain.
    ///
    /// Un-skips `evals/fault-tolerance/FT-06`'s integration case. Rekor
    /// anchoring is a fire-and-forget `tokio::spawn` (see `append()`,
    /// audit.rs ~line 362): `append()` computes the row hash, advances the
    /// per-tenant chain under the parking_lot mutex, and returns `Ok` BEFORE
    /// the anchor task is polled. The anchor task's success or failure can
    /// therefore never propagate back into `append`.
    ///
    /// This test makes the outage concrete: with a real signing key and
    /// `anchor_every = 3`, appending 7 events fires TWO anchor batches (at
    /// seq 2 and seq 5). No reachable Rekor exists in the test sandbox, so
    /// every anchor attempt fails — yet all seven `append`s return `Ok`, the
    /// chain advances across both anchor boundaries (`seq == 7`, `prev_hash`
    /// well past genesis), and exactly one hash remains pending. A final
    /// append after the simulated outage still succeeds, proving the chain
    /// keeps advancing independent of Rekor availability (FT-06 invariant).
    #[tokio::test]
    async fn ft06_rekor_outage_does_not_break_local_chain() {
        let key_b64 = fresh_signing_key_b64();
        let chain = AuditChain::new(3, Some(&key_b64), None).unwrap();
        let t = tenant();
        let ev = || AuditEvent {
            tenant_id: t.clone(),
            event_type: "request",
            actor: "u".into(),
            payload: json!({"q": "ping"}),
        };

        // Seven appends → two anchor batches fire (and fail, no Rekor).
        for _ in 0..7 {
            chain
                .append(ev())
                .await
                .expect("append must succeed regardless of Rekor availability");
        }

        let genesis = audit_format::genesis_prev_hash(&t);
        {
            let state = chain.states.get(&t).unwrap();
            let guard = state.lock();
            assert_eq!(guard.seq, 7, "chain advanced across both anchor batches");
            assert_eq!(
                guard.pending_hashes.len(),
                1,
                "7 mod 3 → exactly one hash pending after two anchor flushes",
            );
            assert_ne!(
                guard.prev_hash, genesis,
                "prev_hash must be well past the genesis seed",
            );
        }

        // Post-outage append still succeeds and advances the chain.
        chain
            .append(ev())
            .await
            .expect("chain keeps advancing after the Rekor outage");
        assert_eq!(chain.states.get(&t).unwrap().lock().seq, 8);
    }
}

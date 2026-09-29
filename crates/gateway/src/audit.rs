//! Tamper-evident audit log (v2) with Ed25519 hash chain and Sigstore
//! Rekor anchoring.
//!
//! Closes, C2, C3, C4, C5, C6, H3, H4, H5 from the Phase-0
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
//!   gated on the Enterprise audit-export entitlement `f_audit_addon`).
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
use std::time::Duration;
//  B8: `parking_lot::Mutex` doesn't poison on panic, so a
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

/// Ledger content cap (ADR-068). The largest legit metadata value stored in the
/// ledger is a customer business reference (`MAX_BUSINESS_REFERENCE_LEN` = 256
/// chars); any string value longer than this is content, not metadata, and is
/// replaced at write time (see [`cap_ledger_content`]).
const LEDGER_MAX_VALUE_CHARS: usize = 256;

/// Replace any string VALUE with more than `max_chars` characters by a
/// `[content-redacted: len=N, sha256=<hex8>]` marker, recursively through arrays
/// and objects. Keeps the retained tamper-evident ledger metadata-only BY
/// CONSTRUCTION: raw prompt/response content (long) can never be stored, while
/// short metadata (model names, UUIDs, enums, prompt NAMES, business refs) is
/// unchanged. Runs AFTER `pii::redact_json` as the second, structural layer. The
/// hash/length preserve auditability (you can prove a specific long value was
/// present) without retaining the content itself.
fn cap_ledger_content(v: &serde_json::Value, max_chars: usize) -> serde_json::Value {
    use serde_json::Value;
    match v {
        Value::String(s) if s.chars().count() > max_chars => {
            let d = ring::digest::digest(&ring::digest::SHA256, s.as_bytes());
            let hex = hex::encode(d.as_ref());
            Value::String(format!(
                "[content-redacted: len={}, sha256={}]",
                s.chars().count(),
                &hex[..8]
            ))
        }
        Value::Array(a) => {
            Value::Array(a.iter().map(|x| cap_ledger_content(x, max_chars)).collect())
        }
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, x)| (k.clone(), cap_ledger_content(x, max_chars)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// An audit event.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub tenant_id: TenantId,
    pub event_type: &'static str,
    pub actor: String,
    pub payload: Value,
}

/// Wire form of an [`AuditEvent`] on the JetStream audit stream (ADR-069).
///
/// The domain `AuditEvent.event_type` is `&'static str` (not deserializable);
/// the wire carries an owned `event_type` + the **pre-canonicalized**
/// `payload_json` (so the consumer hashes exactly the bytes the publisher
/// redacted/capped — no double-processing) + the `event_id` used for the
/// idempotent-replay dedup.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditEventWire {
    pub event_id: String,
    pub tenant_id: uuid::Uuid,
    pub event_type: String,
    pub actor: String,
    pub payload_json: String,
}

static AUDIT_PUBLISH_OK_TOTAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static AUDIT_PUBLISH_FAILED_TOTAL: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Snapshot `(published_ok, publish_failed)` of the async audit publish path —
/// the loud `audit_publish_failed_total` signal (ADR-069 property 3).
#[must_use]
pub fn audit_publish_stats() -> (u64, u64) {
    use std::sync::atomic::Ordering;
    (
        AUDIT_PUBLISH_OK_TOTAL.load(Ordering::Relaxed),
        AUDIT_PUBLISH_FAILED_TOTAL.load(Ordering::Relaxed),
    )
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
        if !level.len().is_multiple_of(2) {
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

pub use crate::db::ledger::AuditLogRow;

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
    /// R21/R34 — the highest `batch_end_seq` this tenant has ever anchored, or `None`
    /// if it has never anchored. Feeds [`anchor_batch_start`] so the threshold and the
    /// age sweeper cannot produce overlapping batches.
    ///
    /// Seeded at [`AuditChain::warm_from_postgres`] from `audit_anchor_records`, NOT
    /// from process memory: a tenant may go quiet for days and the gateway redeploys
    /// often, so an in-memory-only value would reset to `None` on every restart and
    /// let the threshold path recompute `seq + 1 - n` — reintroducing exactly the
    /// overlap this field exists to prevent.
    last_anchored_end: Option<u64>,
}

impl TenantChainState {
    fn genesis(tenant_id: &TenantId) -> Self {
        Self {
            seq: 0,
            prev_hash: audit_format::genesis_prev_hash(tenant_id),
            pending_hashes: Vec::new(),
            batch_start_seq: 0,
            last_anchored_end: None,
        }
    }
}

pub struct AuditChain {
    /// Per-tenant locks.
    states: DashMap<TenantId, Mutex<TenantChainState>>,
    rekor_client: RekorClient,
    anchor_every: usize,
    clickhouse_client: Option<ClickhouseClient>,
    /// Postgres pool for the persistent chain-state table.
    pg_pool: Option<deadpool_postgres::Pool>,
    /// ADR-069: JetStream context for the async audit publish path. Set once at
    /// startup via [`set_jetstream`](Self::set_jetstream) AFTER NATS connects;
    /// unset = synchronous append (dev / no-NATS / self-host).
    jetstream: OnceLock<async_nats::jetstream::Context>,
    /// ADR-069/ADR-038: kill-switch handle so [`publish`](Self::publish) honours
    /// `kill.audit.async` — force the synchronous path fleet-wide, no redeploy.
    kill_switch: OnceLock<Arc<crate::kill_switch::KillSwitch>>,
    /// B-493: the self-host (no Postgres) ledger writer — ONE task, a bounded
    /// queue, batched INSERTs retried until they land. Started lazily by the
    /// first in-memory append (inside the runtime); never on the Postgres path.
    ledger_writer: OnceLock<LedgerWriter>,
}

// ---------------------------------------------------------------------------
// B-493 — the self-host ledger writer
// ---------------------------------------------------------------------------
//
// Reproduced 2026-09-21 with the published self-host ClickHouse config
// (`max_concurrent_queries` 20): the in-memory path spawned one single-row
// INSERT per ledger event and `warn!`ed when ClickHouse refused it, so a 30 s
// burst at ~200 rps (16 users) left 9,114 of 11,875 ledger rows unwritten while
// the chain state had advanced for every one — permanent holes in a chain the
// product calls tamper-evident — and the same storm refused ingest's span
// batches until the ingest process exited. Prod is untouched: with a control
// plane the ledger is canonical in Postgres and written by the head-writer in
// batches (ADR-078 B).
//
// The shape is the ingest writer's: rows ride a bounded queue to one task
// that batches them into ONE insert (B-378 `write_audit_rows`), retries a
// refused batch with back-off until it lands (never drops), and runs an
// anchor only after the rows it covers have landed — the signature backfill
// is an `ALTER … UPDATE` that finds nothing if it outruns them. When the
// queue is full the APPEND is refused (fail-closed, ADR-069 — the same 503
// `audit_unavailable` prod answers when its acked publish fails), and the
// refused event consumes no seq: the slot is reserved BEFORE the chain moves.

/// Rows the queue holds before an append is refused. ≈ 4 s of the burst that
/// found this (2,000 rows/s), ≈ 40 s at a self-hoster's 100 rps.
pub(crate) const LEDGER_WRITER_QUEUE_ROWS: usize = 8_192;
/// Rows per INSERT — the ingest writer's batch size, an upper bound: an anchor
/// request closes the batch early, so with the default `anchor_every` of 100
/// the effective batch is 100 rows (one INSERT per anchor batch).
pub(crate) const LEDGER_WRITER_BATCH_ROWS: usize = 2_000;
/// A partial batch flushes after this long — the ingest writer's cadence.
const LEDGER_WRITER_FLUSH_EVERY: Duration = Duration::from_millis(200);
/// Back-off between attempts on a refused batch: 100 ms doubling to this cap,
/// then flat, forever — the rows are the ledger and are never dropped.
const LEDGER_WRITER_BACKOFF_CAP: Duration = Duration::from_secs(8);
/// One INSERT attempt is bounded, so a ClickHouse that HANGS (paused, a wedged
/// disk) becomes a failed, retried attempt instead of a writer stuck forever
/// behind one request (run 3 of the B-493 repro, a 40 s `docker pause`).
const LEDGER_WRITER_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(20);

enum LedgerWrite {
    Row(AuditLogRow),
    /// Run [`anchor_task`] for this batch once every row queued before it has
    /// landed (the queue is FIFO, so ordering is the writer's).
    Anchor {
        tenant_id: TenantId,
        hashes: Vec<audit_format::Hash>,
        start_seq: u64,
        end_seq: u64,
    },
}

/// Counters the writer maintains; read by `/health` (`ledger_writer`) and tests.
#[derive(Default)]
struct LedgerWriterShared {
    queued: std::sync::atomic::AtomicU64,
    landed: std::sync::atomic::AtomicU64,
    batches: std::sync::atomic::AtomicU64,
    retried_batches: std::sync::atomic::AtomicU64,
    refused_appends: std::sync::atomic::AtomicU64,
    /// Set by a queue-full refusal, cleared (and `AuditAppendFailed` RESOLVED) by
    /// the next accepted append — so a queue that filled while ClickHouse was
    /// slow-but-accepting does not read "degraded" until restart (verifier, 2026-09-21).
    refused_open: std::sync::atomic::AtomicBool,
    /// Anchors the writer dispatched while a row they cover had NOT landed. The
    /// FIFO discipline in `append_in_memory` makes this impossible by construction;
    /// the writer checks anyway, because an ordering bug here is silent (the
    /// signature backfill just misses the row) and a counter is a discriminating
    /// field a test can read (0 with the fix, > 0 with the old shape planted).
    anchors_before_rows: std::sync::atomic::AtomicU64,
}

/// A point-in-time copy of [`LedgerWriterShared`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LedgerWriterStats {
    /// Rows accepted into the queue (every accepted in-memory append).
    pub queued: u64,
    /// Rows whose INSERT ClickHouse acknowledged.
    pub landed: u64,
    /// INSERTs acknowledged.
    pub batches: u64,
    /// Batches that were refused at least once before landing.
    pub retried_batches: u64,
    /// Appends refused because the queue was full (each was a 503 upstream).
    pub refused_appends: u64,
    /// Anchors dispatched before every row they cover had landed (an invariant
    /// violation; always 0 unless the FIFO discipline is broken).
    pub anchors_before_rows: u64,
}

impl LedgerWriterShared {
    fn snapshot(&self) -> LedgerWriterStats {
        use std::sync::atomic::Ordering::Relaxed;
        LedgerWriterStats {
            queued: self.queued.load(Relaxed),
            landed: self.landed.load(Relaxed),
            batches: self.batches.load(Relaxed),
            retried_batches: self.retried_batches.load(Relaxed),
            refused_appends: self.refused_appends.load(Relaxed),
            anchors_before_rows: self.anchors_before_rows.load(Relaxed),
        }
    }
}

struct LedgerWriter {
    tx: tokio::sync::mpsc::Sender<LedgerWrite>,
    shared: Arc<LedgerWriterShared>,
}

/// The process-wide writer's counters for `/health` — set by the first writer
/// started in this process (production has one chain). `None` = no self-host
/// writer runs here (the Postgres path, or no ClickHouse).
static LEDGER_WRITER_HEALTH: OnceLock<Arc<LedgerWriterShared>> = OnceLock::new();

/// Shutdown (B-377's contract, applied to the ledger — verifier, 2026-09-21): the
/// server drains this chain's writer with `drain_ledger_writer` under a bound and,
/// when that times out, logs the rows still unlanded — each a seq the chain
/// consumed whose row is now LOST — rather than assuming they were written.
impl AuditChain {
    /// Rows this chain's self-host ledger writer has accepted but ClickHouse has
    /// not acknowledged — `0` on the hosted path (no writer). Read by the shutdown
    /// drain after `drain_ledger_writer` times out, so the loss is a number.
    ///
    /// Per chain, never the process-global `/health` slot: in the test binary that
    /// slot belongs to whichever test started a writer first (one leaves a refusing
    /// mock with rows queued forever), and an unrelated shutdown test waited the
    /// whole bound on it. Production has one chain and one writer.
    pub(crate) fn ledger_writer_unlanded(&self) -> u64 {
        self.ledger_writer
            .get()
            .map(|w| {
                let s = w.shared.snapshot();
                s.queued.saturating_sub(s.landed)
            })
            .unwrap_or(0)
    }
}

/// The `ledger_writer` object on `/health`, or `null` off the self-host path.
pub(crate) fn ledger_writer_health_json() -> serde_json::Value {
    match LEDGER_WRITER_HEALTH.get() {
        Some(shared) => {
            let s = shared.snapshot();
            json!({
                "queued": s.queued,
                "landed": s.landed,
                "in_flight": s.queued.saturating_sub(s.landed),
                "batches": s.batches,
                "retried_batches": s.retried_batches,
                "refused_appends": s.refused_appends,
                "anchors_before_rows": s.anchors_before_rows,
            })
        }
        None => serde_json::Value::Null,
    }
}

impl LedgerWriter {
    fn start(ch: ClickhouseClient, rekor: RekorClient) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(LEDGER_WRITER_QUEUE_ROWS);
        let shared = Arc::new(LedgerWriterShared::default());
        let _ = LEDGER_WRITER_HEALTH.set(Arc::clone(&shared));
        tokio::spawn(ledger_writer_task(ch, rekor, rx, Arc::clone(&shared)));
        Self { tx, shared }
    }
}

/// The writer loop: fill a batch (up to [`LEDGER_WRITER_BATCH_ROWS`] rows or
/// [`LEDGER_WRITER_FLUSH_EVERY`], whichever first; an anchor request closes the
/// batch early), write it until it lands, then dispatch the anchors that were
/// queued behind those rows.
async fn ledger_writer_task(
    ch: ClickhouseClient,
    rekor: RekorClient,
    mut rx: tokio::sync::mpsc::Receiver<LedgerWrite>,
    shared: Arc<LedgerWriterShared>,
) {
    use std::sync::atomic::Ordering::Relaxed;
    let mut pending: Vec<AuditLogRow> = Vec::with_capacity(LEDGER_WRITER_BATCH_ROWS);
    let mut anchors: Vec<LedgerWrite> = Vec::new();
    // Next seq expected per tenant — rows arrive in seq order by construction, so
    // this is a contiguous landed watermark; the anchor check below reads it.
    let mut landed_next: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    loop {
        let Some(first) = rx.recv().await else {
            // Every sender dropped: flush what is held, then exit.
            if !pending.is_empty() {
                write_until_landed(&ch, &pending, &shared).await;
            }
            return;
        };
        let deadline = tokio::time::Instant::now() + LEDGER_WRITER_FLUSH_EVERY;
        fn take(msg: LedgerWrite, pending: &mut Vec<AuditLogRow>, anchors: &mut Vec<LedgerWrite>) {
            match msg {
                LedgerWrite::Row(row) => pending.push(row),
                anchor @ LedgerWrite::Anchor { .. } => anchors.push(anchor),
            }
        }
        take(first, &mut pending, &mut anchors);
        while pending.len() < LEDGER_WRITER_BATCH_ROWS && anchors.is_empty() {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(msg)) => take(msg, &mut pending, &mut anchors),
                Ok(None) | Err(_) => break,
            }
        }
        if !pending.is_empty() {
            write_until_landed(&ch, &pending, &shared).await;
            shared.landed.fetch_add(pending.len() as u64, Relaxed);
            for row in &pending {
                let next = landed_next.entry(row.tenant_id.clone()).or_insert(0);
                // The watermark only ever moves past what landed, so an anchor
                // for a range with a hole still trips the check below.
                *next = (*next).max(row.seq.saturating_add(1));
            }
            pending.clear();
        }
        // Only now — the rows an anchor covers are in ClickHouse, so the
        // signature/Rekor backfill mutations inside `anchor_task` find them.
        for anchor in anchors.drain(..) {
            if let LedgerWrite::Anchor {
                tenant_id,
                hashes,
                start_seq,
                end_seq,
            } = anchor
            {
                if landed_next
                    .get(&tenant_id.to_string())
                    .is_none_or(|next| *next <= end_seq)
                {
                    shared.anchors_before_rows.fetch_add(1, Relaxed);
                    tracing::error!(
                        tenant_id = %tenant_id, start_seq, end_seq,
                        "self-host ledger writer: an anchor reached the writer BEFORE every row it covers \
                         landed — the queue is no longer in seq order (an invariant violation; the \
                         signature backfill will miss rows)"
                    );
                }
                let rekor = rekor.clone();
                let ch = ch.clone();
                tokio::spawn(async move {
                    anchor_task(rekor, None, Some(ch), tenant_id, hashes, start_seq, end_seq).await;
                });
            }
        }
    }
}

/// ONE insert for the batch, retried with back-off until ClickHouse accepts it.
/// Never returns without the rows landed: on the self-host path these rows ARE
/// the ledger and there is no canonical store to re-copy them from.
async fn write_until_landed(
    ch: &ClickhouseClient,
    rows: &[AuditLogRow],
    shared: &LedgerWriterShared,
) {
    use std::sync::atomic::Ordering::Relaxed;
    let mut backoff = Duration::from_millis(100);
    let mut attempt: u64 = 0;
    loop {
        let attempt_result = match tokio::time::timeout(
            LEDGER_WRITER_ATTEMPT_TIMEOUT,
            write_audit_rows(ch, rows.to_vec()),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => Err(anyhow::anyhow!(
                "audit_log insert attempt timed out after {}s (the server hung)",
                LEDGER_WRITER_ATTEMPT_TIMEOUT.as_secs()
            )),
        };
        match attempt_result {
            Ok(()) => {
                shared.batches.fetch_add(1, Relaxed);
                if attempt > 0 {
                    shared.retried_batches.fetch_add(1, Relaxed);
                    tracelane_shared::degradation::resolve(
                        tracelane_shared::degradation::Degradation::AuditAppendFailed,
                    );
                    tracing::warn!(
                        rows = rows.len(),
                        attempts = attempt + 1,
                        "RECOVERED: self-host ledger batch landed after ClickHouse refused it"
                    );
                }
                return;
            }
            Err(err) => {
                attempt += 1;
                // The registry is the counter; the log line is the transition
                // (first refusal) plus a heartbeat every 10th attempt.
                tracelane_shared::degradation::note(
                    tracelane_shared::degradation::Degradation::AuditAppendFailed,
                );
                if attempt == 1 || attempt.is_multiple_of(10) {
                    tracing::warn!(
                        rows = rows.len(),
                        attempt,
                        next_backoff_ms = backoff.as_millis() as u64,
                        // `{err:#}` prints the anyhow CHAIN — the ClickHouse `Code: NNN …`
                        // reason sits one level below "insert end", and the operator of a
                        // wedged ledger needs that line, not the outer context.
                        error = format!("{err:#}"),
                        "self-host ledger batch refused by ClickHouse — holding the rows and retrying"
                    );
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(LEDGER_WRITER_BACKOFF_CAP);
            }
        }
    }
}

impl AuditChain {
    /// Test-only since B-390: production builds through `with_tenant_keys`.
    #[cfg(test)]
    pub fn new(
        anchor_every: usize,
        signing_key_b64: Option<&str>,
        clickhouse_url: Option<&str>,
    ) -> Result<Self> {
        Self::with_pg_pool(anchor_every, signing_key_b64, clickhouse_url, None)
    }

    #[cfg(test)]
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
            jetstream: OnceLock::new(),
            kill_switch: OnceLock::new(),
            ledger_writer: OnceLock::new(),
        })
    }

    /// B-493: the self-host ledger writer's counters (zero before the first
    /// in-memory append starts it). Production reads them on `/health`
    /// (`ledger_writer_health_json`); this per-chain view is for tests.
    #[cfg(test)]
    pub(crate) fn ledger_writer_stats(&self) -> LedgerWriterStats {
        self.ledger_writer
            .get()
            .map(|w| w.shared.snapshot())
            .unwrap_or_default()
    }

    /// B-493: wait until every row accepted into the self-host ledger queue has
    /// landed in ClickHouse, or `timeout` elapses. `Ok` = drained. Used by the
    /// server's shutdown drain (`server::drain_on_shutdown`) and the B-493 tests.
    pub(crate) async fn drain_ledger_writer(&self, timeout: Duration) -> Result<()> {
        let Some(w) = self.ledger_writer.get() else {
            return Ok(());
        };
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let s = w.shared.snapshot();
            if s.landed >= s.queued {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "self-host ledger writer did not drain: {} queued, {} landed",
                    s.queued,
                    s.landed
                );
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// R21 — read this tenant's anchor watermark. `None` = never anchored, or the
    /// tenant is unknown to this process (which is also "never" as far as the
    /// threshold path is concerned, and falls back to today's arithmetic).
    fn last_anchored_end(&self, tenant_id: &TenantId) -> Option<u64> {
        self.states
            .get(tenant_id)
            .and_then(|s| s.lock().last_anchored_end)
    }

    /// R21 — advance the watermark. Called at the moment an anchor is DISPATCHED, not
    /// when it completes: `anchor_batch_from_ch` is spawned, and two triggers racing on
    /// the same tenant must not both compute the same `batch_start`.
    fn set_last_anchored_end(&self, tenant_id: &TenantId, end_seq: u64) {
        // UPSERT, not set-if-present. On the PG path `states` holds only this watermark
        // (seq and prev_hash come from Postgres) and is populated solely by
        // `warm_from_postgres` at boot — so a tenant whose first event landed after the
        // last restart is absent, and the old `if let Some(..)` made this a silent no-op
        // for precisely the tenants the age sweep exists to serve. `or_insert_with` is
        // safe here because the entry is a watermark cache on this path, and on the
        // in-memory path the tenant is already present from its own append.
        let s = self
            .states
            .entry(tenant_id.clone())
            .or_insert_with(|| Mutex::new(TenantChainState::genesis(tenant_id)));
        let mut g = s.lock();
        // Monotonic: a late-arriving lower value must never rewind the watermark.
        if g.last_anchored_end.is_none_or(|prev| end_seq > prev) {
            g.last_anchored_end = Some(end_seq);
        }
    }

    /// R21/R32 — **anchor any tenant whose oldest un-anchored row is older than
    /// `max_age`, regardless of batch size.**
    ///
    /// Without this, `should_anchor` is a pure per-tenant COUNT threshold
    /// (`(seq + 1) % anchor_every == 0`) with no time component, so a tenant that never
    /// reaches `anchor_every` never signs and never anchors — **ever**. Measured
    /// 2026-08-14: 92 rows across 5 tenants, 100% unsigned and unanchored, permanently.
    /// Their hash chain is intact and verifies from genesis; what is missing is the
    /// Ed25519 signature and the Rekor anchor — the third-party-verifiable half, which
    /// is the differentiated claim.
    ///
    /// `max_age` is a PARAMETER, not a constant read inside, so a test can drive it with
    /// `Duration::ZERO` and with a large value and assert both directions
    /// (`TRAPS.md` §31 — prove both halves or the carve-out is indistinguishable from
    /// not scanning at all).
    ///
    /// Returns the number of batches dispatched.
    ///
    /// # Errors
    /// None — infallible by construction. This is a **fault-tolerance** path: a sweep
    /// that cannot read ClickHouse logs and skips that tenant; it must never take down
    /// the append path it runs beside.
    pub async fn flush_aged_batches(&self, max_age: Duration) -> usize {
        // ADR-078 (B): every question about what is and is not anchored is answered by
        // the CANONICAL store — Postgres. ClickHouse is not consulted here at all.
        // PG-PATH ONLY, and this is a correctness gate rather than a configuration nicety.
        // The sweep's whole model is the PG-serialized append's: the durable watermark
        // lives in `audit_anchor_records` and the leaf set is read back from ClickHouse.
        // The in-memory append path (`append_in_memory`, used when there is no pool) keeps
        // its OWN batch state in `pending_hashes` / `batch_start_seq` and is a THIRD
        // batch-start arithmetic that R34 did not unify. Running both against one tenant
        // produces exactly the overlap R34 exists to prevent — a duplicate anchor record
        // and a duplicate anchor (and hook firing) over the same rows.
        let Some(ref pool) = self.pg_pool else {
            return 0;
        };
        let max_age_secs = max_age.as_secs();
        // B-559: the skip count at the START of this pass. A pass that ends with the same
        // count read every tenant without a skip, which is proof the condition ended.
        let skips_before = tracelane_shared::degradation::count(
            tracelane_shared::degradation::Degradation::AuditAgeSweepSkipped,
        );

        // Enumerate from the DURABLE store, never from `self.states`.
        //
        // `self.states` is populated at exactly ONE non-test site — `warm_from_postgres`,
        // at boot. The prod append path (`append_pg_batch`) never inserts, so on the
        // PG path that map is a boot-time SNAPSHOT: sweeping it would silently exclude
        // every tenant onboarded since the last restart, i.e. exactly the new low-volume
        // customer this feature is for. It is a `GROUP BY` over one column every 15
        // minutes, which is nothing next to being wrong about who is covered.
        let tenants = match crate::db::ledger::tenants_with_rows(pool).await {
            Ok(t) => t,
            Err(err) => {
                Self::note_sweep_skip(&err, None);
                return 0;
            }
        };

        let mut anchored = 0usize;
        for tenant_id in tenants {
            // Everything the sweep decides on is read from the DURABLE store, every sweep
            // — never `self.last_anchored_end`. `warm_from_postgres` degrades a failed
            // watermark read to `None`, so the in-memory value can be `None` for a
            // fully-anchored tenant; trusting it would make the first sweep re-anchor an
            // already-anchored range, rewriting signatures and double-metering.
            // Re-reading also means a failed anchor is simply retried next sweep instead
            // of being remembered as done. (The watermark itself now rides inside the
            // probe below.)
            // B-483 (2026-09-21): the probe is HOLE-AWARE — the lowest seq inside NO anchor
            // batch, wherever it sits. Until this it was `seq > watermark`, and a batch
            // whose anchor task died mid-Rekor (rows 29700..29799 of the deploy-proof
            // tenant, a reboot two seconds in) sat BELOW the watermark the next batch
            // advanced past: the threshold floor skipped it by design and this sweep
            // never looked beneath the watermark. 100 rows, unsigned and un-anchored,
            // with every proof green over them.
            let probe = crate::db::ledger::oldest_uncovered(pool, &tenant_id).await;
            let Ok(Some(uncovered)) = probe else {
                if let Err(ref err) = probe {
                    Self::note_sweep_skip(err, Some(&tenant_id));
                }
                continue; // every row is inside an anchor batch, or unreadable
            };
            let head = uncovered.head;
            let age_secs = uncovered.age_secs;
            // A HOLE — rows below the watermark that no batch covers — is an anomaly,
            // never the ordinary tail: it is anchored on the NEXT sweep regardless of
            // age. The tail above the watermark keeps the age rule.
            let is_hole = uncovered.watermark.is_some_and(|w| uncovered.seq <= w);
            if !is_hole && age_secs < max_age_secs {
                continue;
            }

            // The floor is the ACTUAL uncovered row — deliberately NOT
            // `anchor_batch_start`. That rule takes `max(watermark + 1, end + 1 - n)`,
            // whose second term is a floor the THRESHOLD path needs and the sweep must
            // never apply: with a backlog larger than `anchor_every` it starts the batch
            // partway in, and the watermark then advances past the rows it skipped —
            // burying them, permanently, in the one mechanism that would have caught them.
            let batch_start = uncovered.seq;
            if batch_start > head {
                continue; // cannot happen (the probe read the row); stated, not assumed
            }
            // Bound the batch, and CHUNK FORWARD rather than skip: a backlog bigger than
            // this anchors its oldest rows now and the rest on subsequent sweeps. A hole
            // is additionally bounded by the NEXT existing batch's start, so the range is
            // by construction outside every existing batch (R34's no-overlap property).
            let mut batch_end = head.min(batch_start.saturating_add(MAX_SWEEP_BATCH - 1));
            match crate::db::ledger::next_anchor_start_after(pool, &tenant_id, batch_start).await {
                Ok(Some(next_start)) => {
                    batch_end = batch_end.min(next_start.saturating_sub(1));
                }
                Ok(None) => {}
                Err(err) => {
                    Self::note_sweep_skip(&err, Some(&tenant_id));
                    continue;
                }
            }
            if batch_end < batch_start {
                continue; // an adjacent batch starts right at the uncovered seq — cannot happen, stated
            }

            // Cross-process claim. The threshold path is serialized by the per-tenant
            // `SELECT … FOR UPDATE` on the chain head; the sweep touches no such row, so
            // without this two gateways sweep the same tenant and both anchor it. Two
            // processes co-ran by design under the blue-green deploy until 2026-09-12
            // (`docs/deploy/blue-green-superseded.md`); today's deploy runs ONE gateway
            // and this lock is what makes a second one (RI-04's replicas) safe — an
            // argument, not an observation, until that spec's guard is built (B-448 site 1).
            // A `try` lock, never a blocking one — losing the race means the other process
            // is already doing it, which is the outcome we wanted anyway. The transaction
            // exists ONLY to scope the lock; nothing is written through it.
            // B-428 (2026-09-19): every failure on the way to the claim used to read
            // as "another process holds it" and skip the tenant SILENTLY — the
            // fail-closed direction, which is right, but a Postgres that refuses the
            // pool, the transaction or the probe on every sweep would leave every
            // aged batch un-anchored forever with no line saying why. The direction
            // stays; the silence goes. Counted under `AuditAgeSweepSkipped`, the
            // kind that already means "the sweep could not do its job for a tenant".
            let mut claim_client = match pool.get().await {
                Ok(c) => c,
                Err(err) => {
                    tracing::warn!(tenant_id = %tenant_id, error = %err, "audit age-sweep: could not get a Postgres connection for the claim — skipping this tenant this sweep");
                    tracelane_shared::degradation::note(
                        tracelane_shared::degradation::Degradation::AuditAgeSweepSkipped,
                    );
                    continue;
                }
            };
            let claim_tx = match claim_client.transaction().await {
                Ok(tx) => tx,
                Err(err) => {
                    tracing::warn!(tenant_id = %tenant_id, error = %err, "audit age-sweep: could not open the claim transaction — skipping this tenant this sweep");
                    tracelane_shared::degradation::note(
                        tracelane_shared::degradation::Degradation::AuditAgeSweepSkipped,
                    );
                    continue;
                }
            };
            let claimed = claim_tx
                .query_one(
                    "SELECT pg_try_advisory_xact_lock($1)",
                    &[&tenant_advisory_key(&tenant_id)],
                )
                .await
                .map(|r| r.get::<_, bool>(0))
                .unwrap_or_else(|err| {
                    // A probe ERROR is not "held" — it is "cannot tell", and the
                    // only safe reading of that is to not anchor this tenant now.
                    tracing::warn!(tenant_id = %tenant_id, error = %err, "audit age-sweep: advisory-lock probe FAILED — treating as not claimed (cannot tell), skipping this tenant this sweep");
                    tracelane_shared::degradation::note(
                        tracelane_shared::degradation::Degradation::AuditAgeSweepSkipped,
                    );
                    false
                });
            if !claimed {
                continue; // another process is flushing this tenant right now
            }

            tracing::info!(
                tenant_id = %tenant_id, batch_start, batch_end, head, age_secs, max_age_secs,
                hole = is_hole,
                watermark = uncovered.watermark,
                "audit age-sweep: flushing an un-anchored batch (a HOLE below the watermark is \
                 anchored on sight; the tail past max_age)"
            );
            // AWAITED, not spawned. Sequential dispatch bounds the fan-out to one
            // in-flight anchor per process (the Postgres pool this shares is 16
            // connections and the FAIL-CLOSED audit append needs them), serializes this
            // process against itself, and — the reason that matters — lets a REFUSED
            // batch be observed, so the watermark cache below is advanced only for a
            // batch that was really anchored.
            let ok = anchor_batch_from_store(
                self.rekor_client.clone(),
                Some(pool.clone()),
                self.clickhouse_client.clone(),
                tenant_id.clone(),
                batch_start,
                batch_end,
            )
            .await;
            // Release the claim. A rollback, because the transaction wrote nothing and
            // exists only to bound the advisory lock's lifetime.
            let _ = claim_tx.rollback().await;

            if ok {
                // Keep the THRESHOLD path's in-memory cache in step, so a tenant this
                // sweep just anchored does not later recompute `seq + 1 - n` and overlap
                // it. Upserts, because a tenant that first appended after boot is not in
                // `states` at all and the old set-if-present was a silent no-op for
                // exactly the tenants the sweep serves.
                self.set_last_anchored_end(&tenant_id, batch_end);
                anchored += 1;
            }
        }
        Self::settle_sweep_skips(skips_before);
        anchored
    }

    /// B-559 — close `AuditAgeSweepSkipped` after a pass that skipped nothing.
    ///
    /// A skip is transient by construction: every pass re-reads the durable store and
    /// retries whatever the last one could not see. So a pass that got through every
    /// tenant without adding a skip proves the condition ended, and the kind must say so.
    /// Without this, one Postgres error (prod 2026-09-25 03:48, a Neon suspend) held
    /// `audit_attestation_healthy` false and the status page CRITICAL for 24 h+ over a
    /// ledger with no hole. A pass that DID skip leaves the kind open.
    fn settle_sweep_skips(skips_before: u64) {
        use tracelane_shared::degradation::{Degradation, count, resolve};
        if count(Degradation::AuditAgeSweepSkipped) == skips_before {
            resolve(Degradation::AuditAgeSweepSkipped);
        }
    }

    /// One place for "the sweep could not see, so it skipped" — counted, not just logged.
    ///
    /// A skipped tenant is silent by construction: its rows simply stay unsigned, and no
    /// other trigger will ever anchor them because a low-volume tenant never reaches the
    /// count threshold. A `warn!` per tenant per 15-minute sweep is the ingest LISTEN-loop
    /// shape (`.claude/rules/logging.md`) — 300,000 identical lines that told nobody
    /// anything — so the detail line is emitted only on the FIRST occurrence and the
    /// counter carries the rest, letting `open_for_secs` answer how long it has been open.
    fn note_sweep_skip(err: &anyhow::Error, tenant_id: Option<&TenantId>) {
        let first = tracelane_shared::degradation::note(
            tracelane_shared::degradation::Degradation::AuditAgeSweepSkipped,
        ) == 1;
        if first {
            tracing::warn!(
                error = %err,
                tenant_id = tenant_id.map(ToString::to_string).unwrap_or_else(|| "(all)".into()),
                "audit age-sweep: could not read un-anchored state — skipping. Further \
                 occurrences are counted, not logged (kind=audit_age_sweep_skipped)"
            );
        }
    }

    /// ADR-069: wire the async audit publish path. Sets the JetStream context +
    /// the kill-switch handle (`kill.audit.async`). Called once at startup after
    /// NATS connects; first set wins. Without it, [`publish`](Self::publish) runs
    /// the synchronous append (dev / no-NATS / self-host).
    pub fn set_jetstream(
        &self,
        ctx: async_nats::jetstream::Context,
        kill_switch: Arc<crate::kill_switch::KillSwitch>,
    ) {
        let _ = self.jetstream.set(ctx);
        let _ = self.kill_switch.set(kill_switch);
    }

    /// ADR-069: the hot-path entry. Durably CAPTURE the event (acked JetStream
    /// publish) and return — the head-advance runs off the request path in the
    /// consumer ([`crate::audit_consumer`]). Fail-CLOSED: an async publish/ack
    /// failure returns `Err` so the caller refuses the request (the audit product
    /// does not serve unrecorded requests). When the async path is unavailable
    /// (no JetStream context, or `kill.audit.async`), falls back to the
    /// SYNCHRONOUS [`append`](Self::append) — **also fail-closed since A2**.
    ///
    /// `kill.audit.async` may DEFER the record (force the sync path fleet-wide). It
    /// cannot SUPPRESS it: on either path, a request whose event was not recorded is
    /// refused. Dev / OSS self-host still never 503 here, because with no Postgres
    /// pool `append` takes the in-memory path, which does not return `Err`.
    ///
    /// # Errors
    /// **Fail-CLOSED on both paths** (security path, CLAUDE.md §10): an async
    /// publish/ack failure, or a sync append failure.
    #[instrument(skip(self, event), fields(
        tenant_id = %event.tenant_id,
        event_type = %event.event_type,
    ))]
    pub async fn publish(&self, event: AuditEvent) -> Result<()> {
        let async_killed = self
            .kill_switch
            .get()
            .map(|k| k.flag("kill.audit.async", false))
            .unwrap_or(false);
        let Some(js) = self.jetstream.get().filter(|_| !async_killed) else {
            // A2 — the sync fallback is FAIL-CLOSED, like the async path.
            //
            // It used to `warn!` and return `Ok(())`, so a failed append served the
            // request with NO audit record. That contradicted CLAUDE.md §2 and
            // docs/product/AUDIT.md §3 (both assert fail-closed) and it is why
            // LEGAL-REGISTER.md:58 had to strike "no asynchronous deferral that could
            // be selectively suppressed exists" — `kill.audit.async` was exactly such
            // a deferral, and on a failing append it became a DROP.
            //
            // The lever may still DEFER (force the synchronous path fleet-wide). It can
            // no longer SUPPRESS: whichever path runs, an unrecorded request is refused.
            //
            // Dev / OSS self-host (no Postgres pool): `append` takes
            // `append_in_memory`. Until B-493 (2026-09-21) its ClickHouse write was
            // spawned and warn-only and never returned `Err`, so this arm could not
            // 503 there — and a self-host ClickHouse refusing writes left silent
            // holes in the chain. Now the row rides a bounded writer queue that
            // batches and retries until it lands, and an append is refused ONLY
            // when that queue is full — the same fail-closed answer as the hosted
            // path, for the same reason: the audit product does not serve
            // unrecorded requests.
            //
            // Honest limit, unchanged: the no-Postgres "record" is a process-local
            // hash chain plus a ClickHouse table. A graceful shutdown drains the
            // writer with a bound (`AuditChain::drain_ledger_writer`) and logs what
            // it could not land; a crash, or ClickHouse refusing past that bound,
            // loses the queued rows (no canonical store to re-copy from), and a
            // batch ClickHouse will NEVER accept (schema drift, a full disk) wedges
            // the writer — every request 503s until the operator fixes the store.
            return self.append(event).await.inspect_err(|err| {
                tracing::error!(
                    error = %err,
                    "sync audit append failed — REFUSING the request (fail-closed); \
                     the audit product does not serve unrecorded requests"
                );
            });
        };

        // Same PII-free canonicalization as the sync path (ADR-068): redact →
        // cap → canonical, so the consumer hashes exactly these bytes.
        let redacted = tracelane_policy::pii::redact_json(&event.payload);
        let capped = cap_ledger_content(&redacted, LEDGER_MAX_VALUE_CHARS);
        let payload_json = audit_format::canonical_payload(&capped);
        let event_id = ulid::Ulid::new().to_string();
        let wire = AuditEventWire {
            event_id: event_id.clone(),
            tenant_id: *event.tenant_id.as_uuid(),
            event_type: event.event_type.to_string(),
            actor: event.actor.clone(),
            payload_json,
        };
        let bytes = serde_json::to_vec(&wire).context("serialize audit wire")?;
        let subject = format!("tracelane.audit.{}", event.tenant_id);

        // Nats-Msg-Id = event_id → JetStream transport-level dedup window; the
        // consumer's `audit_appended` INSERT is the durable backstop beyond it.
        let mut headers = async_nats::HeaderMap::new();
        headers.insert("Nats-Msg-Id", event_id.as_str());

        use std::sync::atomic::Ordering;
        // Acked publish: await the PublishAckFuture so "durably captured before
        // dispatch" holds — the caller only proceeds once JetStream persisted it.
        let ack_future = match js
            .publish_with_headers(subject, headers, bytes.into())
            .await
        {
            Ok(f) => f,
            Err(e) => {
                AUDIT_PUBLISH_FAILED_TOTAL.fetch_add(1, Ordering::Relaxed);
                return Err(anyhow::Error::new(e).context("audit jetstream publish"));
            }
        };
        match ack_future.await {
            Ok(_) => {
                AUDIT_PUBLISH_OK_TOTAL.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                AUDIT_PUBLISH_FAILED_TOTAL.fetch_add(1, Ordering::Relaxed);
                Err(anyhow::Error::new(e).context("audit jetstream publish ack"))
            }
        }
    }

    /// ADR-069: the consumer's append entry — reconstructs the serialized
    /// head-advance from the wire envelope (owned `event_type` + the
    /// pre-canonicalized `payload_json`), keyed on `event_id` for idempotent
    /// crash-replay. Requires a Postgres pool (the async path only runs in prod).
    /// Since B-378 the head-writer batches (`append_batch_from_wire`); only the
    /// hop measurement and tests still take the one-event form.
    #[cfg(test)]
    pub(crate) async fn append_from_wire(&self, wire: &AuditEventWire) -> Result<()> {
        self.append_batch_from_wire(std::slice::from_ref(wire))
            .await
    }

    /// **B-378** — append K wire events of ONE tenant in ONE transaction and ONE
    /// ClickHouse insert (`append_atomic_batch`). The batch must be homogeneous
    /// in tenant (the consumer groups by tenant before calling); a mixed batch
    /// is refused, because the row lock is per tenant and a second tenant's
    /// rows under the first's lock would be an unserialized append.
    ///
    /// # Errors
    ///
    /// Fail-closed: any PG / CH failure aborts the whole batch (no seq consumed,
    /// no head advance); the caller leaves every message unacked for
    /// redelivery, where `audit_appended` makes the replay a no-op.
    pub(crate) async fn append_batch_from_wire(&self, wires: &[AuditEventWire]) -> Result<()> {
        let Some(pool) = self.pg_pool.clone() else {
            anyhow::bail!("audit consumer requires a Postgres pool");
        };
        let Some(first) = wires.first() else {
            return Ok(());
        };
        let tenant_id = TenantId::from_jwt_claim(first.tenant_id);
        anyhow::ensure!(
            wires.iter().all(|w| w.tenant_id == first.tenant_id),
            "append_batch_from_wire: a batch must carry ONE tenant"
        );
        let items: Vec<PendingLedgerRow> = wires
            .iter()
            .map(|w| PendingLedgerRow {
                event_type: w.event_type.clone(),
                actor: w.actor.clone(),
                payload_json: w.payload_json.clone(),
            })
            .collect();
        let ids: Vec<String> = wires.iter().map(|w| w.event_id.clone()).collect();
        self.append_pg_batch(&pool, &tenant_id, items, Some(&ids))
            .await
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
    /// Is a Postgres control plane wired?
    ///
    /// **The ASYNC audit path (ADR-069) hard-requires one** — `append_from_wire`
    /// bails without it — while the SYNC path does not: `append()` falls back to
    /// `append_in_memory`, which hashes the chain and persists the `audit_log` row to
    /// ClickHouse. So this is the question "which append path can actually succeed
    /// here", and it must be asked ONCE AT BOOT rather than per message.
    #[must_use]
    pub(crate) fn has_pg_pool(&self) -> bool {
        self.pg_pool.is_some()
    }

    /// B-385 (2b): the tenant's in-memory chain head — how many rows the
    /// in-process ledger has appended for `tenant_id` (0 for a tenant it has
    /// never seen). `audit_publish_stats()` counts only the JetStream path, so
    /// a test with no NATS could assert "the ledger did not move" and be
    /// vacuously right; this reads the row count the sync path actually
    /// advanced. Test-only: production reads the chain through Postgres.
    #[cfg(test)]
    pub(crate) fn in_memory_seq(&self, tenant_id: &TenantId) -> u64 {
        self.states.get(tenant_id).map_or(0, |cell| cell.lock().seq)
    }

    /// Boot: seed every tenant's in-memory chain state from the persisted head, and
    /// reconcile the CANONICAL ledger rows (Postgres, ADR-078 B) with their ClickHouse
    /// copy in both directions. See [`Self::reconcile_ledger`] for the rules.
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
            match self
                .reconcile_ledger(pool, &r.tenant_id, head_seq, head_hash)
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
            // R21: seed the anchor watermark from the DURABLE record — the canonical
            // store — never from memory. A failure here yields `None`, which is the
            // safe direction: the threshold path then falls back to `seq + 1 - n`.
            let anchored_end = crate::db::ledger::last_anchored_end(pool, &r.tenant_id)
                .await
                .unwrap_or_else(|err| {
                    tracing::warn!(
                        error = %err, tenant_id = %r.tenant_id,
                        "audit warm: could not read last anchored batch — anchor watermark unset"
                    );
                    None
                });
            self.states.entry(r.tenant_id.clone()).or_insert_with(|| {
                Mutex::new(TenantChainState {
                    seq: head_seq + 1,
                    prev_hash: head_hash,
                    pending_hashes: Vec::with_capacity(self.anchor_every),
                    batch_start_seq: head_seq + 1,
                    last_anchored_end: anchored_end,
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

    /// **B-475 (REV-4, 2026-09-21): a copy row chains only if its CONTENT hashes to
    /// its stored `row_hash`.** Returns the verified row hash when `row.prev_hash`
    /// equals `running_prev` AND `row_hash_v2(prev, tenant, seq, event_type, actor,
    /// payload)` equals `row.row_hash`; `None` otherwise. Until this, both reconcile
    /// rules decoded the SUPPLIED hashes, compared `prev` to the running hash, and
    /// adopted — a copy row whose `payload` (or `actor`, or `event_type`) had been
    /// altered while its two hash fields were left intact chained perfectly and
    /// entered the canonical Postgres ledger, logged as "the gap was filled … and
    /// chains to the persisted head". The offline verifier would have caught it
    /// later; a recovery that imports unverified content into the evidence store is
    /// the wrong property for this product. `payload` is the verbatim canonical
    /// string in both stores (`apps/web/db/schema.ts`: TEXT, not jsonb, for exactly
    /// this reason) and every prod row is v2 (the v1 hasher is `dead_code`; the export
    /// self-verify recomputes v2 over the whole chain green), so the recomputation is
    /// byte-exact. A mismatch is logged ONCE at `error!` with the seq and the reason,
    /// so the RCA knows WHY the copy was refused.
    fn copy_row_chains(
        row: &AuditLogRow,
        tenant_id: &TenantId,
        running_prev: &audit_format::Hash,
    ) -> Option<audit_format::Hash> {
        let (Ok(prev), Ok(stored)) = (
            audit_format::hex_decode(&row.prev_hash),
            audit_format::hex_decode(&row.row_hash),
        ) else {
            tracing::error!(
                tenant_id = %tenant_id, seq = row.seq,
                "audit reconcile: copy row REFUSED — malformed hash field (not hex)"
            );
            return None;
        };
        if prev != *running_prev {
            return None; // a chain break, not tampering: the walk ends here, quietly
        }
        let recomputed = audit_format::row_hash_v2(
            &prev,
            tenant_id,
            row.seq,
            &row.event_type,
            &row.actor,
            &row.payload,
        );
        if recomputed != stored {
            tracing::error!(
                tenant_id = %tenant_id, seq = row.seq, reason = "content_hash_mismatch",
                "audit reconcile: copy row REFUSED — its content does not hash to its stored row_hash (the row was altered after it was hashed); nothing past it is adopted"
            );
            return None;
        }
        Some(stored)
    }

    /// **ADR-078 (B) — the boot reconcile between the canonical ledger (Postgres) and
    /// its ClickHouse copy, for one tenant.** Three rules, in this order, each of
    /// which only ever adopts a row that CHAINS (`prev_hash` equals the running hash
    /// AND, since B-475, whose content re-hashes to its stored `row_hash`)
    /// and is strictly the next `seq`:
    ///
    /// 1. **Canonical rows behind the head** (`max(seq)` in Postgres `<` the persisted
    ///    head): the head-ahead-of-rows case the ruling names. It arises from a
    ///    Postgres restore to an earlier point — and, once, from the migration window
    ///    (the previous binary wrote rows to ClickHouse only). The gap is filled FROM
    ///    THE COPY, row by row, only while each row chains and only up to the head;
    ///    if the copy cannot fill it, or the recovered row at the head does not hash
    ///    to the persisted `last_row_hash`, the head is **never reset** and no gap row
    ///    is written: `LedgerHeadAheadOfRows` is noted and that tenant's chain stays
    ///    RED for verifiers until the rows are recovered — an incident, not a repair.
    /// 2. **Copy ahead of the head** (ClickHouse rows with `seq >` head): the
    ///    direction the pre-B reconcile already adopted (ADR-065 HOLE C). Rows that
    ///    chain are written into Postgres and the head advances to them
    ///    (monotonic `upsert`). Returns the new `(seq, row_hash)`.
    /// 3. **Copy behind the canonical rows**: Postgres rows the copy lacks are
    ///    written to ClickHouse in pages (the derived copy rebuilt), and anchor
    ///    bundles the copy lacks likewise. Fail-open: a ClickHouse failure here is
    ///    `LedgerCopyFailed`, never a reason not to boot.
    async fn reconcile_ledger(
        &self,
        pool: &deadpool_postgres::Pool,
        tenant_id: &TenantId,
        head_seq: u64,
        head_hash: audit_format::Hash,
    ) -> Result<Option<(u64, audit_format::Hash)>> {
        const RECONCILE_LIMIT: u32 = 10_000;
        let pg_max = crate::db::ledger::max_seq(pool, tenant_id).await?;

        // ── Rule 1: canonical rows behind the head → fill from the copy, or RED. ──
        let rows_behind_head = pg_max.is_none_or(|m| m < head_seq);
        if rows_behind_head {
            // The row we chain FROM: the canonical row at pg_max, or genesis.
            let (mut from_seq, mut running_prev) = match pg_max {
                Some(m) => {
                    let last = crate::db::ledger::read_rows_from(pool, tenant_id, m, 1).await?;
                    let h = last
                        .first()
                        .map(|r| audit_format::hex_decode(&r.row_hash))
                        .transpose()
                        .map_err(|e| anyhow::anyhow!("canonical row_hash at seq {m}: {e}"))?
                        .context("canonical max row vanished between reads")?;
                    (m as i64, h)
                }
                None => (-1i64, audit_format::genesis_prev_hash(tenant_id)),
            };
            let mut recovered: Vec<AuditLogRow> = Vec::new();
            if let Some(ref ch) = self.clickhouse_client {
                loop {
                    let after = u64::try_from(from_seq).unwrap_or(0);
                    let page = if from_seq < 0 {
                        // `seq > -1` is not expressible as u64; genesis walks from 0.
                        read_full_rows_from(ch, tenant_id, 0, RECONCILE_LIMIT).await?
                    } else {
                        read_full_rows_after(ch, tenant_id, after, RECONCILE_LIMIT).await?
                    };
                    if page.is_empty() {
                        break;
                    }
                    let mut stop = false;
                    for r in page {
                        let expected = u64::try_from(from_seq + 1).unwrap_or(0);
                        if r.seq != expected || r.seq > head_seq {
                            stop = true;
                            break;
                        }
                        // A copy row that does not chain — malformed hashes, a
                        // prev_hash off the running hash, or (B-475) content that
                        // does not re-hash to its own row_hash — ends the walk; it
                        // never aborts the adoption of the rows that DID chain
                        // before it.
                        let Some(rh) = Self::copy_row_chains(&r, tenant_id, &running_prev) else {
                            stop = true;
                            break;
                        };
                        running_prev = rh;
                        from_seq = r.seq as i64;
                        recovered.push(r);
                        if from_seq as u64 == head_seq {
                            stop = true;
                            break;
                        }
                    }
                    if stop {
                        break;
                    }
                }
            }
            let filled = from_seq >= 0 && from_seq as u64 == head_seq && running_prev == head_hash;
            if !recovered.is_empty() {
                // Adopt what chained, even partially: every adopted row is a row the
                // verifier can now read from the canonical store.
                crate::db::ledger::insert_rows(pool, &recovered)
                    .await
                    .context("adopt copy rows into the canonical ledger")?;
            }
            if filled {
                tracing::warn!(
                    tenant_id = %tenant_id, from = pg_max, to = head_seq, rows = recovered.len(),
                    "audit reconcile: canonical rows were BEHIND the head; the gap was filled from the ClickHouse copy and chains to the persisted head"
                );
            } else if !crate::db::tenants::exists(pool, *tenant_id.as_uuid()).await? {
                // A tenant Neon no longer knows was PURGED. Its head is retained on
                // purpose (the ledger outlives the tenant) and its rows may be gone by
                // the same purge or by an earlier sweep — that is the expected end
                // state of a purged tenant, not an incident, and it must not hold the
                // platform DEGRADED forever. Found on the first ADR-078 boot on prod:
                // two ownerless heads (a purged tenant, a bench tenant) lit
                // `ledger_head_ahead_of_rows` for a chain nobody can export.
                tracing::info!(
                    tenant_id = %tenant_id, head_seq, canonical_max = ?pg_max,
                    "audit reconcile: a purged tenant's head is retained without rows — frozen as-is, not an incident"
                );
                return Ok(None);
            } else {
                tracelane_shared::degradation::note(
                    tracelane_shared::degradation::Degradation::LedgerHeadAheadOfRows,
                );
                tracing::error!(
                    tenant_id = %tenant_id, head_seq, canonical_max = ?pg_max, recovered = recovered.len(),
                    "audit reconcile: the persisted head is AHEAD of the canonical rows and the copy could not fill the gap with rows that chain — head NOT reset, no gap row written; this tenant's chain is RED for verifiers until the rows are recovered (the head-ahead rule; file an RCA)"
                );
                return Ok(None);
            }
        }

        // ── Rule 2: copy ahead of the head → adopt what chains, advance the head. ──
        let mut adopted_seq = head_seq;
        let mut running_prev = head_hash;
        let mut adopted: Vec<AuditLogRow> = Vec::new();
        if let Some(ref ch) = self.clickhouse_client {
            let rows = read_full_rows_after(ch, tenant_id, head_seq, RECONCILE_LIMIT).await?;
            for r in rows {
                if r.seq != adopted_seq + 1 {
                    break; // gap or reorder — stop adopting
                }
                // Malformed hashes, a chain break, or (B-475) content that does not
                // re-hash to its row_hash: stop, keep what chained so far.
                let Some(rh) = Self::copy_row_chains(&r, tenant_id, &running_prev) else {
                    break;
                };
                adopted_seq = r.seq;
                running_prev = rh;
                adopted.push(r);
            }
        }
        let outcome = if adopted_seq == head_seq {
            None
        } else {
            crate::db::ledger::insert_rows(pool, &adopted)
                .await
                .context("adopt ahead-of-head copy rows into the canonical ledger")?;
            crate::db::audit_chain_state::upsert(pool, tenant_id, adopted_seq, &running_prev)
                .await
                .context("reconcile upsert of adopted head")?;
            tracing::info!(
                tenant_id = %tenant_id,
                from_seq = head_seq,
                to_seq = adopted_seq,
                "audit reconcile adopted ClickHouse copy rows ahead of the persisted head into the canonical ledger"
            );
            Some((adopted_seq, running_prev))
        };

        // ── Rule 3: copy behind the canonical rows → rebuild the copy (fail-open). ──
        if let Some(ref ch) = self.clickhouse_client
            && let Err(err) = rebuild_copy_for_tenant(pool, ch, tenant_id, RECONCILE_LIMIT).await
        {
            tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::LedgerCopyFailed,
            );
            tracing::warn!(
                error = %err, tenant_id = %tenant_id,
                "audit reconcile: rebuilding the ClickHouse ledger copy failed — canonical rows are intact; retried at the next boot"
            );
        }
        Ok(outcome)
    }

    /// Append one audit event, advancing the tenant's tamper-evident hash chain.
    ///
    /// ** forward fix (ADR-065 F1):** when a Postgres pool is configured
    /// (always true in prod), seq assignment + chain-head advance are
    /// serialized **across processes** by a per-tenant `SELECT … FOR UPDATE`
    /// row lock ([`append_pg_batch`](Self::append_pg_batch)), and the
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
    /// seq). The in-memory path errors on a malformed payload and — B-493 —
    /// when its ledger writer's queue is full (ClickHouse not accepting
    /// `audit_log` writes): the event is refused and consumes no seq.
    #[instrument(skip(self, event), fields(
        tenant_id = %event.tenant_id,
        event_type = %event.event_type,
    ))]
    pub async fn append(&self, event: AuditEvent) -> Result<()> {
        // ADR-068 hardening: two layers before the payload is hashed + stored, so
        // the RETAINED tamper-evident ledger is PII-free BY CONSTRUCTION.
        //   (1) pii::redact_json — scrub email / SSN / phone / IP / API keys.
        //   (2) cap_ledger_content — replace any string VALUE longer than the
        //       largest legit metadata (a business reference, 256 chars) with a
        //       `[content-redacted: len, sha256]` marker. Raw prompt/response
        //       content (long) can therefore NEVER enter the retained ledger,
        //       even if a future event payload carries it; short metadata (model
        //       names, UUIDs, enums, prompt NAMES, business refs) passes
        //       unchanged. The chain hashes the capped payload, so it verifies
        //       consistently over exactly what is stored.
        let redacted = tracelane_policy::pii::redact_json(&event.payload);
        let capped = cap_ledger_content(&redacted, LEDGER_MAX_VALUE_CHARS);
        let payload_json = audit_format::canonical_payload(&capped);

        match self.pg_pool.clone() {
            Some(pool) => {
                self.append_pg_batch(
                    &pool,
                    &event.tenant_id,
                    vec![PendingLedgerRow {
                        event_type: event.event_type.to_string(),
                        actor: event.actor.clone(),
                        payload_json,
                    }],
                    None,
                )
                .await
            }
            None => self.append_in_memory(event, payload_json).await,
        }
    }

    /// **ADR-065 F1 (+ B-378 batching)** — the cross-process-safe append. One
    /// Postgres transaction per BATCH: `FOR UPDATE`-lock the tenant head, compute
    /// the K chained `row_hash`es, write the K ClickHouse rows durably in ONE
    /// insert (one MergeTree part instead of K), advance the head to the end of
    /// the batch, commit. The row lock is the cross-process serialization the
    /// Mutex could not provide; the batch changes how much work happens under it,
    /// never what it guards.
    ///
    /// Anchor batches are **seq-aligned** (`[k·N … (k+1)·N−1]`), not driven by a
    /// per-process in-memory counter: exactly one process commits each
    /// batch-final seq (seqs are globally serialized by the row lock), so it
    /// alone anchors that batch, and it rebuilds the leaf set by reading the
    /// contiguous rows back from ClickHouse (deduped) — never from a
    /// per-process `pending_hashes` that, under two co-running processes, would
    /// hold a non-contiguous subset and produce a Merkle root the verifier
    /// cannot reconstruct. A batch of K may straddle an anchor boundary, so the
    /// rule is applied to EVERY seq the batch committed, not only its last.
    async fn append_pg_batch(
        &self,
        pool: &deadpool_postgres::Pool,
        tenant_id: &TenantId,
        items: Vec<PendingLedgerRow>,
        event_ids: Option<&[String]>,
    ) -> Result<()> {
        let tenant_id = tenant_id.clone();
        let genesis = audit_format::genesis_prev_hash(&tenant_id);
        let count = items.len();

        // ADR-078 (B): the closure is PURE — it chains the row hashes over the
        // seqs the lock just claimed and returns the rows; `append_atomic_batch`
        // writes them into the canonical Postgres ledger INSIDE the head
        // transaction. `kept` names which of `items` survived dedup. The
        // ClickHouse copy happens below, after COMMIT, fail-open and counted.
        let outcome = crate::db::audit_chain_state::append_atomic_batch(
            pool,
            &tenant_id,
            genesis,
            event_ids,
            count,
            |first_seq, prev_hash, kept| {
                let mut prev = prev_hash;
                let mut rows = Vec::with_capacity(kept.len());
                let event_time = Utc::now().timestamp_micros();
                for (i, idx) in kept.iter().enumerate() {
                    let item = &items[*idx];
                    let seq = first_seq + i as u64;
                    let row_hash = audit_format::row_hash_v2(
                        &prev,
                        &tenant_id,
                        seq,
                        &item.event_type,
                        &item.actor,
                        &item.payload_json,
                    );
                    rows.push(AuditLogRow {
                        tenant_id: tenant_id.to_string(),
                        seq,
                        event_time,
                        event_type: item.event_type.clone(),
                        actor: item.actor.clone(),
                        payload: item.payload_json.clone(),
                        prev_hash: audit_format::hex_encode(&prev),
                        row_hash: audit_format::hex_encode(&row_hash),
                        rekor_entry_id: None,
                        // Backfilled per anchor batch by `backfill_signature`.
                        signature: String::new(),
                        signing_pubkey: String::new(),
                    });
                    prev = row_hash;
                }
                Ok(rows)
            },
        )
        .await?;

        // `None` = every event in the batch was a redelivery already appended —
        // nothing was written, nothing to anchor. (The sync path never dedups,
        // so it never sees this.)
        let Some(outcome) = outcome else {
            return Ok(());
        };
        // ADR-078 (B): the DERIVED copy — ClickHouse `audit_log`, which the
        // dashboards and the per-trace chain view read. After COMMIT, so the
        // canonical row exists whatever happens here; fail-OPEN and COUNTED, never
        // a reason to refuse the append (the chain is already durable). The boot
        // reconcile rebuilds whatever this misses (`reconcile_ledger_copy`).
        if let Some(ch) = self.clickhouse_client.clone()
            && let Err(err) = write_audit_rows(&ch, outcome.rows.clone()).await
        {
            tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::LedgerCopyFailed,
            );
            tracing::debug!(
                error = %err, tenant_id = %tenant_id, first_seq = outcome.first_seq,
                n = outcome.rows.len(),
                "ledger copy to ClickHouse failed — the canonical rows are committed; the boot reconcile will rebuild the copy"
            );
        }
        let n_appended = outcome.row_hashes.len() as u64;
        let last_seq = outcome.first_seq + n_appended - 1;
        tracing::debug!(
            prev_hash_hex = %audit_format::hex_encode(&outcome.prev_hash),
            head_hash_hex = %audit_format::hex_encode(&outcome.row_hashes[outcome.row_hashes.len() - 1]),
            first_seq = outcome.first_seq,
            last_seq,
            n_appended,
            n_deduped = count - outcome.kept.len(),
            "audit events hashed (pg-serialized batch)"
        );

        // Seq-aligned anchor batches. The append that commits a batch-final seq
        // (there is exactly one, seqs being globally serialized) anchors
        // `[batch_start … seq]`, reading the contiguous leaf set back from
        // ClickHouse. Requires a CH client; without one there are no rows to
        // anchor (dev). Off the hot path (spawned). Checked for EVERY seq this
        // batch committed — a batch of K can cross an anchor boundary.
        let n = self.anchor_every as u64;
        if n > 0 {
            for seq in outcome.first_seq..=last_seq {
                if !(seq + 1).is_multiple_of(n) {
                    continue;
                }
                // ADR-078 (B): the leaf set comes from the canonical store, so
                // anchoring no longer needs ClickHouse at all.
                // R34: the SAME rule the age sweeper uses. Never `seq + 1 - n`
                // directly — that is correct only if no batch was ever closed
                // early by age.
                let prev_end = self.last_anchored_end(&tenant_id);
                let batch_start = anchor_batch_start(prev_end, seq, n);
                self.set_last_anchored_end(&tenant_id, seq);
                let rekor = self.rekor_client.clone();
                let tid = tenant_id.clone();
                let pg = pool.clone();
                let ch = self.clickhouse_client.clone();
                tokio::spawn(async move {
                    anchor_batch_from_store(rekor, Some(pg), ch, tid, batch_start, seq).await;
                });
            }
        }

        Ok(())
    }

    /// In-memory append (no Postgres pool → single-process dev / OSS
    /// self-host). Advances the per-tenant `DashMap` chain state under a
    /// `parking_lot::Mutex`; the `audit_log` row and the anchor ride the B-493
    /// ledger writer's bounded FIFO queue (batched, retried until landed, the
    /// anchor after its rows). The cross-process race cannot arise without a
    /// shared Postgres. **Not used when `pg_pool` is set.**
    ///
    /// # Errors
    ///
    /// Fail-CLOSED when the writer's queue is full: TWO slots (the row and, in
    /// case this seq closes an anchor batch, its anchor) are reserved BEFORE the
    /// chain state moves, so a refused event consumes no seq (a seq without a
    /// row is the hole B-493 found) and an anchor-closing append never waits on
    /// the queue. Refused appends are counted (`refused_appends`) and noted as
    /// `AuditAppendFailed`, which the next accepted append resolves.
    async fn append_in_memory(&self, event: AuditEvent, payload_json: String) -> Result<()> {
        use std::sync::atomic::Ordering::Relaxed;
        // Started lazily so `AuditChain` construction needs no runtime; `append`
        // is async, so this runs inside one.
        let writer = self.clickhouse_client.as_ref().map(|ch| {
            self.ledger_writer
                .get_or_init(|| LedgerWriter::start(ch.clone(), self.rekor_client.clone()))
        });
        let permits = match writer {
            Some(w) => {
                let reserved =
                    w.tx.try_reserve()
                        .and_then(|row| w.tx.try_reserve().map(|anchor| (row, anchor)));
                match reserved {
                    Ok(pair) => {
                        if w.shared.refused_open.swap(false, Relaxed) {
                            tracelane_shared::degradation::resolve(
                                tracelane_shared::degradation::Degradation::AuditAppendFailed,
                            );
                        }
                        Some(pair)
                    }
                    Err(err) => {
                        w.shared.refused_appends.fetch_add(1, Relaxed);
                        w.shared.refused_open.store(true, Relaxed);
                        tracelane_shared::degradation::note(
                            tracelane_shared::degradation::Degradation::AuditAppendFailed,
                        );
                        // A closed channel is the writer task having died — a different
                        // fact from a full queue, and it says so (verifier, 2026-09-21).
                        // Both refusals are ADR-069's fail-closed rule; the ADR id stays
                        // here, not in the message a self-host operator reads.
                        if matches!(err, tokio::sync::mpsc::error::TrySendError::Closed(())) {
                            anyhow::bail!(
                                "self-host ledger writer task is GONE (its queue is closed) — \
                                 refusing the append (fail-closed); restart the gateway"
                            );
                        }
                        anyhow::bail!(
                            "self-host ledger writer saturated ({LEDGER_WRITER_QUEUE_ROWS} rows \
                             queued and ClickHouse is not accepting audit_log writes) — refusing \
                             the append (fail-closed)"
                        );
                    }
                }
            }
            None => None,
        };

        // Everything that orders the ledger happens UNDER the per-tenant lock: the seq
        // is taken, the row and (when this seq closes a batch) its anchor are pushed onto
        // the writer's FIFO through the pre-reserved permits (`Permit::send` is
        // synchronous and cannot block). Queue order therefore equals seq order per
        // tenant, an anchor always sits behind every row it covers, and no request
        // future awaits the queue after its seq is consumed — the hand-off cannot be
        // lost to a client hang-up or the router timeout. (Verifier, 2026-09-21: with
        // the sends outside the lock a preempted request could enqueue row N behind
        // the anchor for [..N], and an awaited anchor send was cancellable.)
        let (row_hash, seq, no_ch_anchor) = {
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

            let mut no_ch_anchor = None;
            match (permits, writer) {
                (Some((row_permit, anchor_permit)), Some(w)) => {
                    row_permit.send(LedgerWrite::Row(AuditLogRow {
                        tenant_id: event.tenant_id.to_string(),
                        seq,
                        event_time: Utc::now().timestamp_micros(),
                        event_type: event.event_type.to_string(),
                        actor: event.actor.clone(),
                        payload: payload_json,
                        prev_hash: audit_format::hex_encode(&prev_hash_snapshot),
                        row_hash: audit_format::hex_encode(&hash),
                        rekor_entry_id: None,
                        // Backfilled per anchor batch by `backfill_signature` (ADR-057).
                        signature: String::new(),
                        signing_pubkey: String::new(),
                    }));
                    w.shared.queued.fetch_add(1, Relaxed);
                    if should_anchor {
                        anchor_permit.send(LedgerWrite::Anchor {
                            tenant_id: event.tenant_id.clone(),
                            hashes: snapshot,
                            start_seq: batch_start,
                            end_seq: seq,
                        });
                    }
                    // else: `anchor_permit` drops here and its slot is released.
                }
                _ => {
                    if should_anchor {
                        no_ch_anchor = Some((snapshot, batch_start));
                    }
                }
            }
            (hash, seq, no_ch_anchor)
        };

        tracing::debug!(
            row_hash_hex = %audit_format::hex_encode(&row_hash),
            seq,
            "audit event hashed (in-memory)"
        );

        if let Some((pending_snapshot, batch_start)) = no_ch_anchor {
            // No ClickHouse at all (dev): the anchor still signs in memory.
            let rekor = self.rekor_client.clone();
            let tenant_id = event.tenant_id.clone();
            tokio::spawn(async move {
                anchor_task(
                    rekor,
                    None,
                    None,
                    tenant_id,
                    pending_snapshot,
                    batch_start,
                    seq,
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

/// One row in one insert — test fixtures only since B-493 (one spawned insert
/// per in-memory append was the storm; the self-host writer batches).
#[cfg(test)]
async fn write_audit_row(client: &ClickhouseClient, row: AuditLogRow) -> anyhow::Result<()> {
    write_audit_rows(client, vec![row]).await
}

/// B-378: K rows in ONE insert — one MergeTree part per batch instead of per
/// event.
async fn write_audit_rows(client: &ClickhouseClient, rows: Vec<AuditLogRow>) -> anyhow::Result<()> {
    let mut insert = client
        .insert("audit_log")
        .context("clickhouse audit_log insert init")?;
    for row in &rows {
        insert
            .write(row)
            .await
            .context("clickhouse audit_log insert write")?;
    }
    insert
        .end()
        .await
        .context("clickhouse audit_log insert end")?;
    Ok(())
}

/// One ledger row waiting for its seq — the per-event fields of an
/// [`AuditEvent`] after redaction/capping/canonicalisation, before the chain
/// assigns `(seq, prev_hash, row_hash)` under the row lock.
struct PendingLedgerRow {
    event_type: String,
    actor: String,
    payload_json: String,
}

pub(crate) use crate::db::ledger::AuditAnchorRecordRow;

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

/// Whether a `rekor_entry_id` denotes a REAL external Rekor anchor, vs a
/// sentinel: `(no-key)` (unsigned), `(no-rekor)` (signed but not externally
/// anchored, ADR-057), or `(unknown-uuid)` (Rekor response had no parseable
/// entry). Sentinels must never be reported as an anchor or backfilled as a UUID.
pub(crate) fn is_real_rekor_entry(entry_id: &str) -> bool {
    !matches!(entry_id, "(no-key)" | "(no-rekor)" | "(unknown-uuid)")
}

/// B-493 (verifier, 2026-09-21): the three ClickHouse ops an anchor spawns — the
/// anchor record and the two row backfills — were one-shot, so the same refusal
/// that lost ledger rows left a batch permanently unsigned. Each now retries across
/// this ladder (≈ 63 s, the ingest writer's) before it is counted as lost; on the
/// self-host path these ARE the store, on the hosted path the boot reconcile
/// re-copies whatever still failed.
#[cfg_attr(test, allow(dead_code))]
const ANCHOR_COPY_BACKOFF: [Duration; 7] = [
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
    Duration::from_secs(32),
];

/// The ladder `retry_copy_op` walks: production's above; in the test binary a
/// millisecond ladder of the SAME length, so a failing-write test still sees every
/// rung tried and the failure counted without waiting a minute.
fn anchor_copy_backoff() -> &'static [Duration] {
    #[cfg(test)]
    {
        static TINY: [Duration; 7] = [Duration::from_millis(2); 7];
        &TINY
    }
    #[cfg(not(test))]
    {
        &ANCHOR_COPY_BACKOFF
    }
}

async fn retry_copy_op<F, Fut>(what: &'static str, mut op: F) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    let mut last = None;
    for (attempt, wait) in anchor_copy_backoff()
        .iter()
        .map(Some)
        .chain(std::iter::once(None))
        .enumerate()
    {
        match op().await {
            Ok(()) => return Ok(()),
            Err(err) => {
                if let Some(wait) = wait {
                    tracing::debug!(
                        what,
                        attempt,
                        error = format!("{err:#}"),
                        "anchor copy op refused; retrying"
                    );
                    tokio::time::sleep(*wait).await;
                }
                last = Some(err);
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("{what}: no attempt ran")))
}

/// ADR-078 (B): `pg_pool` is the CANONICAL store for the anchor bundle and the row
/// backfills (signature, Rekor entry id); `clickhouse_client` receives the derived
/// COPY afterwards. A stack without Postgres (dev / OSS self-host) keeps its
/// ClickHouse-only behaviour — there is no canonical store to prefer.
/// AUD-29 — load the tenant's Ed25519 key, retrying a TRANSIENT failure on the same
/// ladder as the canonical anchor writes before giving up. `NotEntitledToTenantKey`
/// is not transient: the platform key is that tenant's signer, so `None` at once.
/// Only when every rung fails does the batch fall back to the platform key — counted
/// (`AuditPlatformKeyFallback`), because for a tenant that already has a key that
/// batch reads `platform_key_after_workspace_key` in every verifier, forever. The
/// anchor task is off the hot path; waiting here costs no request anything.
async fn tenant_key_with_retry(
    store: &TenantAuditKeyStore,
    tenant_id: &TenantId,
) -> Option<crate::audit_keys::TenantAuditKeypair> {
    let mut rungs = anchor_copy_backoff().iter();
    loop {
        match store.get_or_create(tenant_id).await {
            Ok(kp) => return Some(kp),
            Err(err)
                if err
                    .downcast_ref::<crate::audit_keys::NotEntitledToTenantKey>()
                    .is_some() =>
            {
                return None;
            }
            Err(err) => {
                if let Some(wait) = rungs.next() {
                    tracing::debug!(
                        error = format!("{err:#}"), tenant_id = %tenant_id,
                        "per-tenant Ed25519 lookup failed; retrying"
                    );
                    tokio::time::sleep(*wait).await;
                } else {
                    tracelane_shared::degradation::note(
                        tracelane_shared::degradation::Degradation::AuditPlatformKeyFallback,
                    );
                    tracing::warn!(
                        error = format!("{err:#}"), tenant_id = %tenant_id,
                        "per-tenant Ed25519 lookup failed on every retry; signing with the platform key"
                    );
                    return None;
                }
            }
        }
    }
}

async fn anchor_task(
    rekor_client: RekorClient,
    pg_pool: Option<deadpool_postgres::Pool>,
    clickhouse_client: Option<ClickhouseClient>,
    tenant_id: TenantId,
    hashes: Vec<audit_format::Hash>,
    start_seq: u64,
    end_seq: u64,
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

    // ADR-078 (B): the CANONICAL half first — the anchor bundle and the two row
    // backfills into Postgres. Awaited, not spawned: this task already runs off the
    // hot path, and a bundle that never reaches the canonical store is the ADR-062
    // loss (`AuditBackfillFailed`) whatever the copy does.
    if let Some(ref pool) = pg_pool {
        if outcome.is_signed() {
            let row = build_anchor_record(&tenant_id, &root, start_seq, end_seq, &outcome);
            if let Err(err) = crate::db::ledger::insert_anchor_record(pool, &row).await {
                tracelane_shared::degradation::note(
                    tracelane_shared::degradation::Degradation::AuditBackfillFailed,
                );
                tracing::warn!(
                    tenant_id = %tenant_id, start_seq, end_seq, error = %err,
                    "canonical audit_anchor_records write failed"
                );
            }
            if let Err(err) = crate::db::ledger::backfill_signature(
                pool,
                &tenant_id,
                &outcome.ed25519_sig_b64,
                &outcome.ed25519_pubkey_b64,
                start_seq,
                end_seq,
            )
            .await
            {
                tracelane_shared::degradation::note(
                    tracelane_shared::degradation::Degradation::AuditBackfillFailed,
                );
                tracing::warn!(
                    tenant_id = %tenant_id, start_seq, end_seq, error = %err,
                    "canonical audit signature backfill failed"
                );
            }
        }
        if is_real_rekor_entry(&entry_id)
            && let Err(err) = crate::db::ledger::backfill_rekor_entry_id(
                pool, &tenant_id, &entry_id, start_seq, end_seq,
            )
            .await
        {
            tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::AuditBackfillFailed,
            );
            tracing::warn!(
                rekor_entry_id = %entry_id, tenant_id = %tenant_id, start_seq, end_seq,
                error = %err, "canonical rekor_entry_id backfill failed"
            );
        }
    }

    // The derived COPY (or, with no Postgres, the only store — unchanged behaviour).
    // Under B a failure here is `LedgerCopyFailed`: the bundle is safe in Postgres
    // and the boot reconcile re-copies it; without Postgres it stays the ADR-062
    // loss it always was (`AuditBackfillFailed`).
    let copy_kind = if pg_pool.is_some() {
        tracelane_shared::degradation::Degradation::LedgerCopyFailed
    } else {
        tracelane_shared::degradation::Degradation::AuditBackfillFailed
    };
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
                if let Err(err) = retry_copy_op("audit_anchor_records", || {
                    write_anchor_record(&ch, row.clone())
                })
                .await
                {
                    // R17. The founder's ruling named the two backfills; this is the
                    // THIRD spawned fail-open in the same function with the same shape
                    // and the same consequence, and instrumenting two of three would
                    // be TRAPS §29 (a finding recorded at one call site is not
                    // recorded). Losing this row loses the ADR-062 offline bundle —
                    // the inclusion proof and checkpoint captured at anchor time are
                    // the ONLY offline-verification source, because Rekor v2 has no
                    // online lookup. So the batch anchored and cannot be proven to
                    // have anchored, which is the same customer-visible outcome.
                    tracelane_shared::degradation::note(copy_kind);
                    tracing::warn!(
                        tenant_id = %tid,
                        start_seq,
                        end_seq,
                        error = format!("{err:#}"),
                        "ClickHouse audit_anchor_records write failed after every retry"
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
                if let Err(err) = retry_copy_op("signature backfill", || {
                    backfill_signature(&ch, &tid, &sig, &pk, start_seq, end_seq)
                })
                .await
                {
                    // R17. This runs detached, so its Err reaches nobody: the append
                    // already reported success and `/health` is green. Left uncounted,
                    // the batch stays UNSIGNED forever with nothing to retry it — the
                    // ledger keeps its hash chain and quietly loses the property we
                    // actually sell. Count it so `open_for_secs` can answer TRAPS §16.
                    tracelane_shared::degradation::note(copy_kind);
                    tracing::warn!(
                        tenant_id = %tid,
                        start_seq,
                        end_seq,
                        error = format!("{err:#}"),
                        "ClickHouse audit signature backfill failed after every retry"
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
                if let Err(err) = retry_copy_op("rekor_entry_id backfill", || {
                    backfill_rekor_entry_id(&ch, &tid, &id, start_seq, end_seq)
                })
                .await
                {
                    // R17, same class as the signature backfill above: a REAL Rekor
                    // entry exists in the public log, and the rows that entry attests
                    // to will never name it. The anchor is not lost — it is
                    // unreachable from the product, which is indistinguishable from
                    // never having anchored for anyone reading the ledger.
                    tracelane_shared::degradation::note(copy_kind);
                    tracing::warn!(
                        rekor_entry_id = %id,
                        tenant_id = %tid,
                        start_seq,
                        end_seq,
                        error = format!("{err:#}"),
                        "ClickHouse rekor_entry_id backfill failed after every retry"
                    );
                }
            });
        }
    }
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
/// R32 — a batch older than this anchors regardless of size. **Founder-ruled 24 h**, and
/// the value is not arbitrary: it is the largest that still makes the customer-facing
/// statement true, and the smallest that costs the busiest tenant nothing. At the
/// measured 381 events/day, `a4037bef`'s 100-event threshold fires every ~6.3 h, so a
/// 24 h timer never wins and its metered-anchor count is unchanged (+0/day). A 1 h value
/// would flush it hourly — ~24 anchors/day against 3.8 today, a 6× cost for no benefit.
/// A 7 d value would leave a new customer un-attested for a week, which is the same
/// problem this fixes, slower.
pub const ANCHOR_MAX_BATCH_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// How often the age sweep runs. Well below [`ANCHOR_MAX_BATCH_AGE`] so the effective
/// flush latency is the age, not the interval.
pub const ANCHOR_SWEEP_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// How long after boot the FIRST sweep runs (B-483, 2026-09-22). It used to be one full
/// [`ANCHOR_SWEEP_INTERVAL`] — fifteen minutes in which a hole the last process left
/// (a batch whose anchor died mid-Rekor on a restart, the shape found on prod) stayed
/// unsigned, and in which the deploy's own ledger proof would read it and roll the
/// deploy back. The settle this used to buy is already guaranteed by ordering:
/// `warm_from_postgres` runs to completion before the sweeper is spawned, and the
/// hole probe reads Postgres, not the in-memory watermark. Ten seconds is for the
/// boot to finish its own logging, nothing more.
pub const ANCHOR_SWEEP_FIRST_PASS_DELAY: Duration = Duration::from_secs(10);

/// R21 — spawn the background age sweep.
///
/// A background task rather than a check inside `publish` **because an append-triggered
/// check cannot fix the tenants this exists for.** A tenant that appends 35 events and
/// goes quiet never appends again, so a condition evaluated on append never runs. That
/// is precisely the 92-row population: 35, 35, 12, 7 and 3 lifetime events, none of
/// which will ever reach the 100-event threshold.
pub fn spawn_anchor_age_sweeper(chain: Arc<AuditChain>) {
    tokio::spawn(async move {
        // `warm_from_postgres` has already seeded the anchor watermarks by the time the
        // server spawns this (it runs synchronously, earlier in boot), so the first pass
        // no longer waits a whole interval — see `ANCHOR_SWEEP_FIRST_PASS_DELAY`.
        tokio::time::sleep(ANCHOR_SWEEP_FIRST_PASS_DELAY).await;
        loop {
            let n = chain.flush_aged_batches(ANCHOR_MAX_BATCH_AGE).await;
            if n > 0 {
                tracing::info!(
                    batches = n,
                    "audit age-sweep: dispatched aged anchor batches"
                );
            }
            tokio::time::sleep(ANCHOR_SWEEP_INTERVAL).await;
        }
    });
}

/// R32/R34 — **the batch a given anchor covers. ONE rule, BOTH triggers.**
///
/// Before R21 the seq-aligned path computed `seq + 1 - n` directly. That is correct
/// only while every batch closes on the threshold, which stopped being true the moment
/// a time-based flush could close a batch early: an age-flushed `[0..36]` followed by
/// the threshold firing at seq 99 would have re-anchored `[0..99]`, **covering rows
/// 0–36 twice** — a second `audit_anchor_records` row over the same rows and a second
/// Rekor entry (and anchor-hook firing) for them.
///
/// Taking `max(last_anchored_end + 1, …)` makes a batch start where the previous one
/// ended, whichever trigger closed it. The founder's reasoning for collapsing them
/// rather than keeping two arithmetics (R34): **two triggers with different batch-start
/// arithmetic are two rules that must agree forever.** With one rule the threshold path
/// inherits this function's proof, and nobody can reintroduce the overlap by editing one
/// site and not the other.
///
/// Pure and total, so both directions are unit-falsifiable with no I/O:
/// * an age-flush followed by a threshold fire must produce **non-overlapping** ranges;
/// * a pure threshold sequence with no age-flush must produce **exactly** the batches it
///   produces today.
fn anchor_batch_start(last_anchored_end: Option<u64>, end_seq: u64, anchor_every: u64) -> u64 {
    // `saturating_sub`: a batch closed by AGE can end before `anchor_every` rows exist
    // at all (e.g. end_seq=4, n=100), where `end_seq + 1 - n` would underflow.
    let by_threshold = (end_seq + 1).saturating_sub(anchor_every);
    match last_anchored_end {
        Some(prev_end) => by_threshold.max(prev_end + 1),
        None => by_threshold,
    }
}

/// Returns `true` if the batch was well-formed and handed to [`anchor_task`], `false` if
/// it was refused. **R21 depends on this distinction:** the age sweep must not advance
/// its watermark cache for a batch that was never anchored, or those rows are buried —
/// the sweep is the only thing that would ever have come back for them.
/// ADR-078 (B): the leaf set is read from the CANONICAL store when there is one
/// (Postgres), else from ClickHouse (a stack with no control plane).
async fn anchor_batch_from_store(
    rekor_client: RekorClient,
    pg_pool: Option<deadpool_postgres::Pool>,
    clickhouse_client: Option<ClickhouseClient>,
    tenant_id: TenantId,
    start_seq: u64,
    end_seq: u64,
) -> bool {
    let read = match (&pg_pool, &clickhouse_client) {
        (Some(pool), _) => {
            crate::db::ledger::read_row_hashes(pool, &tenant_id, start_seq, end_seq).await
        }
        (None, Some(ch)) => read_batch_row_hashes(ch, &tenant_id, start_seq, end_seq).await,
        (None, None) => Err(anyhow::anyhow!(
            "no ledger store to read the batch leaf set from"
        )),
    };
    let hashes = match read {
        Ok(h) => h,
        Err(err) => {
            tracing::error!(
                error = %err, tenant_id = %tenant_id, start_seq, end_seq,
                "audit anchor: reading batch leaf set from the ledger store failed — skipping anchor"
            );
            return false;
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
        return false;
    }
    anchor_task(
        rekor_client,
        pg_pool,
        clickhouse_client,
        tenant_id,
        hashes,
        start_seq,
        end_seq,
    )
    .await;
    true
}

/// R21 — the largest batch one age flush will anchor. A backlog bigger than this is
/// anchored in CONSECUTIVE chunks over successive sweeps — **chunked forward, never
/// skipped**, because the sweep is the last mechanism that would come back for a row it
/// passed over. Sized to bound the leaf set held in memory and the `ALTER … UPDATE`
/// signature backfill's row count, not to match `anchor_every`.
const MAX_SWEEP_BATCH: u64 = 10_000;

/// R21 — a per-tenant Postgres advisory lock held for the duration of one age flush,
/// released on drop.
///
/// **Why a lock at all.** The threshold trigger is serialized across processes by the
/// per-tenant `SELECT … FOR UPDATE` on the chain head. The age sweep reads ClickHouse and
/// touches no such row, so two gateway processes sweeping the same tenant would both
/// compute the same batch and both anchor it — a duplicate `audit_anchor_records` row and
/// a duplicate Rekor entry over identical rows. Two processes is
/// the designed state, not an accident: `infra/prod/blue-green-deploy.sh:84-85` keeps the
/// BLUE pool running after the cutover for instant rollback.
///
/// **Why advisory and not `FOR UPDATE`.** The flush includes a Rekor round-trip. Holding
/// the chain-head row lock across it would block that tenant's appends — and the append
/// path is fail-CLOSED, so a slow Rekor would turn into customer-visible 503s. An advisory
/// lock is off to the side: it serializes sweepers against each other and nothing else.
///
/// **Why the TRANSACTION-scoped variant.** `pg_try_advisory_lock` is session-scoped, and
/// these connections are POOLED — returning one to the pool does not release its locks, so
/// a missed unlock (an early return, a panic mid-anchor) would leave that tenant claimed
/// for the life of the connection and silently exclude it from every future sweep. The
/// `_xact_` variant is released by COMMIT *or* ROLLBACK *or* the transaction being dropped,
/// so every exit path releases it without anything having to remember to.
fn tenant_advisory_key(tenant_id: &TenantId) -> i64 {
    const NAMESPACE: i64 = 0x746C_616E_6541_4E43; // "tlaneANC"
    let b = tenant_id.as_uuid().as_bytes();
    let mut k = [0u8; 8];
    k.copy_from_slice(&b[..8]);
    i64::from_le_bytes(k) ^ NAMESPACE
}

/// R21 — the highest `batch_end_seq` this tenant has ever anchored. `None` = never.
///
/// Read from `audit_anchor_records` rather than tracked in memory: the tenants this
/// feature exists for may not append for days, and the gateway redeploys far more often
/// than that.
async fn read_last_anchored_end(
    client: &ClickhouseClient,
    tenant_id: &TenantId,
) -> anyhow::Result<Option<u64>> {
    #[derive(Debug, serde::Deserialize, clickhouse::Row)]
    struct MaxRow {
        n: u64,
        present: u8,
    }
    // `max()` over an empty set returns 0, which is indistinguishable from "anchored
    // batch [x..0]" — so carry an explicit presence flag rather than treating 0 as a
    // sentinel. Same class as TRAPS §25: a value that happens to be zero.
    let row = client
        .query(&crate::clickhouse_query::ceiling(
            "SELECT toUInt64(max(batch_end_seq)) AS n, toUInt8(count() > 0) AS present \
             FROM audit_anchor_records WHERE tenant_id = ?",
        ))
        .bind(tenant_id.to_string())
        .fetch_one::<MaxRow>()
        .await?;
    Ok((row.present == 1).then_some(row.n))
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
        .query(&crate::clickhouse_query::ceiling(
            "SELECT seq, row_hash FROM audit_log FINAL \
             WHERE tenant_id = ? AND seq >= ? AND seq <= ? \
             ORDER BY seq ASC",
        ))
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

/// Read up to `limit` deduped rows with `seq > after_seq` for `tenant_id`,
/// ordered ascending, for warm-reconcile (HOLE C). `FINAL` picks the version
/// winner so a crash-retry orphan never masks the canonical row.
/// Full copy rows with `seq > after_seq`, seq-ascending, deduped by `FINAL` — the
/// reconcile's read of the ClickHouse copy (ADR-078 B). Column order is the
/// `AuditLogRow` field order: RowBinary is positional.
const COPY_ROW_COLUMNS: &str = "tenant_id, seq, event_time, event_type, actor, payload, \
                                prev_hash, row_hash, rekor_entry_id, signature, signing_pubkey";

async fn read_full_rows_after(
    client: &ClickhouseClient,
    tenant_id: &TenantId,
    after_seq: u64,
    limit: u32,
) -> anyhow::Result<Vec<AuditLogRow>> {
    client
        .query(&crate::clickhouse_query::ceiling(&format!(
            "SELECT {COPY_ROW_COLUMNS} FROM audit_log FINAL \
             WHERE tenant_id = ? AND seq > ? ORDER BY seq ASC LIMIT ?"
        )))
        .bind(tenant_id.to_string())
        .bind(after_seq)
        .bind(limit)
        .fetch_all::<AuditLogRow>()
        .await
        .context("read audit_log copy rows after seq")
}

/// Same, inclusive of `from_seq` (the genesis walk).
async fn read_full_rows_from(
    client: &ClickhouseClient,
    tenant_id: &TenantId,
    from_seq: u64,
    limit: u32,
) -> anyhow::Result<Vec<AuditLogRow>> {
    client
        .query(&crate::clickhouse_query::ceiling(&format!(
            "SELECT {COPY_ROW_COLUMNS} FROM audit_log FINAL \
             WHERE tenant_id = ? AND seq >= ? ORDER BY seq ASC LIMIT ?"
        )))
        .bind(tenant_id.to_string())
        .bind(from_seq)
        .bind(limit)
        .fetch_all::<AuditLogRow>()
        .await
        .context("read audit_log copy rows from seq")
}

/// `max(seq)` the ClickHouse copy holds for a tenant; `None` when it has none.
async fn read_ch_max_seq(
    client: &ClickhouseClient,
    tenant_id: &TenantId,
) -> anyhow::Result<Option<u64>> {
    #[derive(Debug, serde::Deserialize, clickhouse::Row)]
    struct MaxRow {
        n: u64,
        hi: u64,
    }
    let r = client
        .query(&crate::clickhouse_query::ceiling(
            "SELECT count() AS n, max(seq) AS hi FROM audit_log FINAL WHERE tenant_id = ?",
        ))
        .bind(tenant_id.to_string())
        .fetch_one::<MaxRow>()
        .await
        .context("read audit_log copy max seq")?;
    Ok((r.n > 0).then_some(r.hi))
}

/// ADR-078 (B), reconcile rule 3: write every canonical row and anchor bundle the
/// ClickHouse copy lacks, in pages. Rows: `seq > max(seq in copy)`. Anchors:
/// `batch_start_seq > max(batch_end_seq in copy)`. Idempotent on the copy side —
/// `audit_log` is a ReplacingMergeTree keyed `(tenant_id, seq)`.
async fn rebuild_copy_for_tenant(
    pool: &deadpool_postgres::Pool,
    ch: &ClickhouseClient,
    tenant_id: &TenantId,
    page: u32,
) -> anyhow::Result<u64> {
    let mut copied = 0u64;
    let mut from = match read_ch_max_seq(ch, tenant_id).await? {
        Some(hi) => hi.saturating_add(1),
        None => 0,
    };
    loop {
        let rows =
            crate::db::ledger::read_rows_from(pool, tenant_id, from, i64::from(page)).await?;
        let Some(last) = rows.last() else { break };
        let next = last.seq.saturating_add(1);
        copied += rows.len() as u64;
        write_audit_rows(ch, rows)
            .await
            .context("copy rows to ClickHouse")?;
        if next == from {
            break;
        }
        from = next;
    }
    // Anchor bundles the copy lacks.
    let ch_anchored_end = read_last_anchored_end(ch, tenant_id).await?;
    let anchors = crate::db::ledger::read_anchor_records_after(
        pool,
        tenant_id,
        ch_anchored_end,
        i64::from(page),
    )
    .await?;
    for a in anchors {
        write_anchor_record(ch, a)
            .await
            .context("copy anchor record to ClickHouse")?;
        copied += 1;
    }
    if copied > 0 {
        tracing::info!(tenant_id = %tenant_id, copied, "audit reconcile: ClickHouse ledger copy rebuilt from the canonical store");
    }
    Ok(copied)
}

/// Submits hashedrekord entries to Sigstore Rekor v2.
///
/// PKCS#8 bytes wrapped in `secrecy::SecretBox` so they
/// zeroize on drop. `ring::Ed25519KeyPair` itself is not zeroizable
/// upstream — the SecretBox is the canonical zero-on-process-exit
/// source of truth.
///
/// `tenant_keys` holds the optional per-tenant signing-key
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

/// AUD-29 — the public half of the global (PLATFORM) signing key, base64 raw 32
/// bytes, for `GET /v1/audit/platform-pubkey`. Parsed exactly as [`RekorClient::new`]
/// parses it, then PROVEN before it is published (the R47 pattern,
/// `audit_keys.rs` `derived_pubkey_verified`): a fixed probe is signed with the
/// private key and verified with the derived public one. A key that fails either
/// step publishes nothing — a wrong trust root is worse than an absent one.
#[must_use]
pub fn platform_pubkey_b64(signing_key_b64: &str) -> Option<String> {
    const PROBE: &[u8] = b"tracelane:aud29:platform-pubkey-selfcheck:v1";
    let mut der = B64.decode(signing_key_b64.trim()).ok()?;
    let parsed = signature::Ed25519KeyPair::from_pkcs8(&der)
        .or_else(|_| signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der));
    der.zeroize();
    let kp = parsed.ok()?;
    let public = kp.public_key().as_ref().to_vec();
    let sig = kp.sign(PROBE);
    signature::UnparsedPublicKey::new(&signature::ED25519, &public)
        .verify(PROBE, sig.as_ref())
        .ok()?;
    Some(B64.encode(public))
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
                // `from_pkcs8` wants PKCS#8 v2 (RFC 5958, seed + public key — what
                // ring generates). `openssl genpkey -algorithm ed25519`, the procedure
                // the self-hosting guide gave for two months, emits v1 (seed only),
                // which v2-only parsing refused with `VersionNotSupported` — a
                // documented setup that could not boot (2026-09-21). v1 carries the
                // same seed; ring derives the public key from it, and "unchecked"
                // means only that there is no embedded public key to cross-check.
                let kp = signature::Ed25519KeyPair::from_pkcs8(&der)
                    .or_else(|_| signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der))
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
            Some(store) => tenant_key_with_retry(store, tenant_id).await,
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

    // — sign-routing tests ------------------------------------
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

    /// AUD-29: the published platform pubkey is the public half of the configured
    /// key (it verifies a signature made with it), and garbage publishes nothing.
    #[test]
    fn platform_pubkey_is_the_verified_public_half_or_nothing() {
        let key = fresh_signing_key_b64();
        let published = platform_pubkey_b64(&key).expect("a valid key publishes");
        let der = B64.decode(&key).expect("b64");
        let kp = signature::Ed25519KeyPair::from_pkcs8(&der).expect("pkcs8");
        assert_eq!(published, B64.encode(kp.public_key().as_ref()));
        let sig = kp.sign(b"any message");
        let pk = B64.decode(&published).expect("b64");
        signature::UnparsedPublicKey::new(&signature::ED25519, &pk)
            .verify(b"any message", sig.as_ref())
            .expect("the published key verifies the configured key's signatures");
        assert_eq!(platform_pubkey_b64("not a key"), None);
        assert_eq!(platform_pubkey_b64(&B64.encode([0u8; 16])), None);
    }

    /// R17 FALSIFICATION — force REAL backfill failures and require the counter to move.
    ///
    /// The `health_body` unit test proves the FIELD is wired to the counter. It cannot
    /// prove the counter is wired to the failure, and those are the two halves that have
    /// to meet. This drives `anchor_task` — the actual production path — against an
    /// unreachable ClickHouse, so all three attestation writes genuinely fail.
    ///
    /// Asserting an EXACT count is a DECISION, not a measurement (TRAPS §27): the two
    /// writes this path reaches must both be counted. Dropping either turns this red —
    /// before R17 it would have read `before + 0` while the ledger silently stopped
    /// being third-party verifiable.
    ///
    /// # What this does NOT prove, stated rather than implied
    ///
    /// **Two of the three instrumented arms, not three.** The `rekor_entry_id` backfill
    /// is gated on `is_real_rekor_entry(&entry_id)`, which requires an outcome that
    /// actually anchored to a live transparency log. With `TRACELANE_REKOR_URL` unset —
    /// the only offline-safe fixture — the batch is signed but unanchored, so that arm
    /// is never entered. My first version of this test asserted 3 and went red for
    /// exactly that reason: TRAPS §22, a probe that cannot reach the code under test.
    /// The assertion was lowered to what the fixture genuinely exercises rather than the
    /// fixture being stretched to justify the number.
    ///
    /// So `note()` in the `backfill_rekor_entry_id` Err arm is **compile-checked and
    /// unproven**. Proving it needs a stub Rekor endpoint, which is a bigger fixture
    /// than this defect warrants. Recorded as a known gap rather than papered over.
    #[tokio::test]
    async fn failed_audit_backfill_increments_the_degradation_counter() {
        use tracelane_shared::degradation::{Degradation, count};

        let before = count(Degradation::AuditBackfillFailed);

        // Signed but never anchored: TRACELANE_REKOR_URL is unset in tests, so
        // `anchor_batch` signs locally and makes no network call. `is_signed()` is what
        // gates all three ClickHouse writes.
        let key_b64 = fresh_signing_key_b64();
        let rekor = RekorClient::new(Some(&key_b64), None).unwrap();

        // Port 1 refuses immediately — the failure is a fast connect error, not a hang,
        // so this test cannot become the slow one everybody disables.
        let ch = ClickhouseClient::default().with_url("http://127.0.0.1:1");

        // No Postgres here, so ClickHouse is the ONLY store and its failures keep
        // the ADR-062 meaning (`AuditBackfillFailed`); with a pool they would be
        // `LedgerCopyFailed` instead (ADR-078 B) — a separate claim, not this test's.
        anchor_task(
            rekor,
            None,
            Some(ch),
            TenantId::from_jwt_claim("a4037bef-e786-44e3-bfb6-88c93ba9d381".parse().unwrap()),
            vec![[9u8; 32]],
            1,
            1,
        )
        .await;

        // The writes are detached, so poll rather than sleeping a fixed amount.
        let mut after = count(Degradation::AuditBackfillFailed);
        for _ in 0..100 {
            if after >= before + 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            after = count(Degradation::AuditBackfillFailed);
        }

        // exact-delta-ok: the coverage claim below needs exactness. All three
        // AuditBackfillFailed noters sit in `anchor_task`'s backfill arms, and this
        // is the only test in the binary that calls `anchor_task` with failing writes
        // (`grep -n 'anchor_task(' crates/gateway/src/audit.rs`) — if this ever reads
        // 3 or 4 under a parallel run, look for a second caller before the arms.
        assert_eq!(
            after - before,
            2,
            "the two attestation writes this path reaches — the audit_anchor_records \
             row (the ADR-062 offline bundle) and the Ed25519 signature backfill — must \
             BOTH be counted when they fail. Exactly 2, not >=2: a third would mean the \
             rekor_entry_id arm became reachable, and this test's stated coverage claim \
             would be stale."
        );

        // And the counter must actually reach the operator surface: the /health field
        // goes red on exactly this value. Counter and field, joined.
        let body = crate::server::health_body(true, 0, after);
        assert_eq!(
            body["audit_attestation_healthy"], false,
            "/health must report attestation as unhealthy once a backfill has failed"
        );
        assert_eq!(
            body["capture_healthy"], true,
            "and it must NOT drag capture down with it — the operator has to be able to \
             tell which half broke"
        );
    }

    /// R34 direction 1 — **an age-flush followed by a threshold fire must produce
    /// NON-OVERLAPPING ranges.** This is the defect the unified rule exists to prevent:
    /// under the old `seq + 1 - n` arithmetic the threshold would have re-anchored from
    /// 0, covering the age-flushed rows a second time — a duplicate
    /// `audit_anchor_records` row and a duplicate Rekor entry over the SAME rows.
    #[test]
    fn age_flush_then_threshold_produces_non_overlapping_batches() {
        const N: u64 = 100;

        // The age sweeper closes [0..36] early (37 rows, well under the threshold).
        let first_start = anchor_batch_start(None, 36, N);
        assert_eq!(first_start, 0, "a first-ever batch starts at genesis");

        // Later the tenant reaches seq 99 and the threshold fires.
        let second_start = anchor_batch_start(Some(36), 99, N);
        assert_eq!(
            second_start, 37,
            "the threshold batch must RESUME where the age flush ended, not restart at \
             `seq + 1 - n` (which would be 0 and would re-cover rows 0..36)"
        );
        assert!(
            second_start > 36,
            "non-overlap is the property: batch 2 must start after batch 1 ended"
        );

        // And the old arithmetic really would have overlapped — pin the contrast so
        // this test cannot be satisfied by the bug returning.
        let old_arithmetic = (99 + 1) - N;
        assert_eq!(old_arithmetic, 0);
        assert_ne!(
            second_start, old_arithmetic,
            "if these ever agree, the unified rule has been reverted"
        );
    }

    /// R34 direction 2 — **a pure threshold sequence with NO age-flush must produce
    /// EXACTLY the batches it produces today.** Without this, direction 1 could be
    /// satisfied by a rule that changes normal batching, which would silently
    /// re-partition every existing tenant's future anchors.
    #[test]
    fn pure_threshold_sequence_is_byte_for_byte_todays_batching() {
        const N: u64 = 100;
        let mut watermark: Option<u64> = None;
        let mut got = Vec::new();
        // Ten consecutive threshold fires, exactly as the seq-aligned path drives them.
        for batch in 0..10u64 {
            let end = (batch + 1) * N - 1; // 99, 199, 299, …
            let start = anchor_batch_start(watermark, end, N);
            got.push((start, end));
            watermark = Some(end);
        }
        let want: Vec<(u64, u64)> = (0..10u64).map(|b| (b * N, (b + 1) * N - 1)).collect();
        assert_eq!(
            got, want,
            "with no age flush the unified rule must reproduce today's aligned width-100 \
             batches exactly — prod has 158 of these, contiguous and gapless"
        );
    }

    /// The underflow the `saturating_sub` guards: an age flush can close a batch before
    /// `anchor_every` rows exist at all. `end_seq + 1 - n` would panic in debug.
    #[test]
    fn age_flush_below_the_threshold_does_not_underflow() {
        assert_eq!(anchor_batch_start(None, 4, 100), 0);
        assert_eq!(anchor_batch_start(Some(1), 4, 100), 2);
    }

    // ── ADR-078 (ruled B, 2026-09-20) — the Tier-A proofs the ruling names ──────
    //
    // Both stores are REAL: `scripts/ci/run-ledger-integration.sh` starts a throwaway
    // Postgres AND a throwaway ClickHouse and runs `adr078_` with both URLs set. Until
    // that runner existed, the two `r21_*` tests below (also dual-store) had skipped in
    // EVERY gate — neither the Postgres nor the ClickHouse runner set both variables
    // (the founder's question B, 2026-09-20).

    async fn adr078_env() -> Option<(String, deadpool_postgres::Pool)> {
        let url = ch_test_url()?;
        std::env::var("POSTGRES_TEST_URL").ok()?;
        // The database first, with a client that names none — `ch_test_client`
        // targets `tracelane`, which does not exist on a fresh throwaway.
        ClickhouseClient::default()
            .with_url(&url)
            .query("CREATE DATABASE IF NOT EXISTS tracelane")
            .execute()
            .await
            .unwrap();
        Some((url, pg_test_pool()))
    }

    async fn adr078_append_n(chain: &AuditChain, tenant: &TenantId, n: usize) {
        for i in 0..n {
            chain
                .append(AuditEvent {
                    tenant_id: tenant.clone(),
                    event_type: "request",
                    actor: "it".into(),
                    payload: json!({ "i": i }),
                })
                .await
                .unwrap();
        }
    }

    #[derive(Debug, serde::Deserialize, clickhouse::Row)]
    struct CopyCount {
        n: u64,
    }
    async fn ch_copy_count(ch: &ClickhouseClient, tenant: &TenantId) -> u64 {
        ch.query("SELECT count() AS n FROM audit_log FINAL WHERE tenant_id = ?")
            .bind(tenant.to_string())
            .fetch_one::<CopyCount>()
            .await
            .unwrap()
            .n
    }

    /// The ruling's first proof: a "kill" between the Postgres COMMIT and the
    /// ClickHouse copy — simulated by a copy client that cannot connect — leaves the
    /// chain GREEN and complete in the canonical store, counts `LedgerCopyFailed`,
    /// serves the export from Postgres with ClickHouse dead, and the next boot's
    /// reconcile catches the copy up row for row.
    #[tokio::test]
    #[ignore = "needs a live ClickHouse + Postgres (CLICKHOUSE_TEST_URL, POSTGRES_TEST_URL)"]
    async fn adr078_a_copy_failure_leaves_the_chain_green_and_the_reconcile_rebuilds_the_copy() {
        let Some((url, pool)) = adr078_env().await else {
            eprintln!("skip adr078_copy_failure: needs CLICKHOUSE_TEST_URL + POSTGRES_TEST_URL");
            return;
        };
        let ch = ch_test_client(&url);
        ch_reset_replacing_audit_log(&ch).await;
        ch_reset_anchor_records(&ch).await;
        let tenant = TenantId::from_jwt_claim(uuid::Uuid::new_v4());

        // Port 1 refuses at once: every copy write fails, every canonical write lands.
        let dead =
            AuditChain::with_pg_pool(1000, None, Some("http://127.0.0.1:1"), Some(pool.clone()))
                .unwrap();
        let before = tracelane_shared::degradation::count(
            tracelane_shared::degradation::Degradation::LedgerCopyFailed,
        );
        adr078_append_n(&dead, &tenant, 5).await;
        let after = tracelane_shared::degradation::count(
            tracelane_shared::degradation::Degradation::LedgerCopyFailed,
        );
        // exact-delta-ok: `run-ledger-integration.sh` runs this binary's ignored
        // dual-store tests with `--test-threads=1`, and `LedgerCopyFailed` has exactly
        // two noters — `append_pg_batch`'s copy (this path) and the anchor task's copy,
        // which cannot fire here (anchor_every is 1000). Five appends, five counts.
        assert_eq!(
            after - before,
            5,
            "every failed copy is COUNTED, none refused the append"
        );

        // Canonical: 5 rows, head at 4, the leaf set chains to the head.
        let range = crate::db::ledger::ledger_range(&pool, &tenant)
            .await
            .unwrap();
        assert_eq!((range.from, range.to, range.total), (Some(0), Some(4), 5));
        let heads = crate::db::audit_chain_state::load_all(&pool).await.unwrap();
        let head = heads.iter().find(|h| h.tenant_id == tenant).unwrap();
        assert_eq!(head.last_seq, 4);
        let leaves = crate::db::ledger::read_row_hashes(&pool, &tenant, 0, 4)
            .await
            .unwrap();
        assert_eq!(
            leaves[4], head.last_row_hash,
            "the canonical row at the head IS the head"
        );
        assert_eq!(
            ch_copy_count(&ch, &tenant).await,
            0,
            "the copy has nothing yet"
        );

        // The export streams every row from the canonical store with the copy dead (Q2).
        let reader = crate::audit_export::PgExportReader::new(pool.clone());
        let rows = crate::audit_export::AuditExportReader::read_range(
            &reader,
            &tenant,
            Utc::now() - chrono::Duration::hours(1),
            Utc::now() + chrono::Duration::hours(1),
            100,
        )
        .await
        .unwrap();
        assert_eq!(
            rows.len(),
            5,
            "export = the canonical rows, ClickHouse never consulted"
        );
        assert_eq!(
            rows[4].row_hash,
            audit_format::hex_encode(&head.last_row_hash)
        );

        // Next boot, with the copy reachable: rule 3 rebuilds it.
        let live = AuditChain::with_pg_pool(1000, None, Some(&url), Some(pool.clone())).unwrap();
        live.warm_from_postgres().await.unwrap();
        assert_eq!(
            ch_copy_count(&ch, &tenant).await,
            5,
            "the copy caught up row for row"
        );
        let copy = read_full_rows_from(&ch, &tenant, 0, 100).await.unwrap();
        for (i, r) in copy.iter().enumerate() {
            assert_eq!(r.seq, i as u64);
            assert_eq!(
                r.row_hash,
                audit_format::hex_encode(&leaves[i]),
                "byte-identical hash in the copy"
            );
        }
    }

    /// B-513 / CX-14 (Codex dashboard-page review, 2026-09-21): the per-trace
    /// chain-status read (`ClickHouseTraceReader::trace_chain_status`, the
    /// trace-detail "in tamper-evident ledger" chip's data source) used to query
    /// ONLY the derived ClickHouse `audit_log` copy. That copy write is fail-open
    /// AFTER the canonical Postgres commit (`append_pg_batch`, this same kill —
    /// a copy client on `http://127.0.0.1:1` — as `adr078_a_copy_failure…`
    /// above) and repaired only by the next boot's reconcile, so for the whole
    /// `LedgerCopyFailed` window the chip told a customer a call was never
    /// proxied when the canonical ledger already held it. ADR-078 B made
    /// Postgres canonical; this proves the read now follows that store rather
    /// than the copy it demoted.
    #[tokio::test]
    #[ignore = "needs a live ClickHouse + Postgres (CLICKHOUSE_TEST_URL, POSTGRES_TEST_URL)"]
    async fn adr078_b_trace_chain_status_reads_canonical_when_the_copy_write_failed() {
        use crate::trace_reads::{ClickHouseTraceReader, TraceReader as _};

        let Some((url, pool)) = adr078_env().await else {
            eprintln!(
                "skip adr078_b_trace_chain_status: needs CLICKHOUSE_TEST_URL + POSTGRES_TEST_URL"
            );
            return;
        };
        let ch = ch_test_client(&url);
        ch_reset_replacing_audit_log(&ch).await;
        ch_reset_anchor_records(&ch).await;
        let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
        let trace_id = Uuid::new_v4().to_string();

        // Port 1 refuses at once: the copy write fails, the canonical write lands —
        // identical setup to `adr078_a_copy_failure…`.
        let dead =
            AuditChain::with_pg_pool(1000, None, Some("http://127.0.0.1:1"), Some(pool.clone()))
                .unwrap();
        dead.append(AuditEvent {
            tenant_id: tenant.clone(),
            event_type: "chat.completions.request",
            actor: "it".into(),
            payload: json!({ "trace_id": trace_id }),
        })
        .await
        .unwrap();

        // Precondition: the copy genuinely has nothing — a passing assertion below
        // must come from the canonical store, not a copy that happened to land.
        assert_eq!(
            ch_copy_count(&ch, &tenant).await,
            0,
            "precondition: the copy write failed, nothing landed in ClickHouse"
        );

        // A reader wired to the SAME canonical pool as the write — the ClickHouse
        // client is the real (working) test URL, which must never be consulted
        // for presence once a pg_pool is wired: the copy is empty and a read
        // against it would still say not-chained.
        let reader =
            ClickHouseTraceReader::new(ch_test_client(&url)).with_pg_pool(Some(pool.clone()));
        let status = reader
            .trace_chain_status(&tenant, &trace_id)
            .await
            .unwrap()
            .expect(
                "chained — the canonical Postgres ledger holds this trace_id's row \
                 even though the ClickHouse copy write failed",
            );
        assert!(status.chained);
        assert_eq!(status.seq, Some(0));
        assert!(
            !status.anchored,
            "written before any batch anchored — anchor_every is 1000"
        );
    }

    /// Rule 1 — the head-ahead-of-rows case the ruling names, in both outcomes:
    /// canonical rows lost behind the head are filled from a copy that chains; when
    /// the copy cannot fill them, the head is NOT reset, no gap row is written, and
    /// `LedgerHeadAheadOfRows` is noted (RED, an incident).
    #[tokio::test]
    #[ignore = "needs a live ClickHouse + Postgres (CLICKHOUSE_TEST_URL, POSTGRES_TEST_URL)"]
    async fn adr078_head_ahead_of_rows_is_filled_from_the_copy_or_left_red() {
        let Some((url, pool)) = adr078_env().await else {
            eprintln!("skip adr078_head_ahead: needs CLICKHOUSE_TEST_URL + POSTGRES_TEST_URL");
            return;
        };
        let ch = ch_test_client(&url);
        ch_reset_replacing_audit_log(&ch).await;
        ch_reset_anchor_records(&ch).await;
        let tenant = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        // A LIVE tenant — Neon knows it. The RED verdict below is for live tenants
        // only; a purged tenant's head-without-rows is frozen instead (second half).
        seed_tenant(&pool, &tenant).await;
        let chain = AuditChain::with_pg_pool(1000, None, Some(&url), Some(pool.clone())).unwrap();
        adr078_append_n(&chain, &tenant, 6).await;
        assert_eq!(ch_copy_count(&ch, &tenant).await, 6);
        let heads = crate::db::audit_chain_state::load_all(&pool).await.unwrap();
        let head = heads
            .iter()
            .find(|h| h.tenant_id == tenant)
            .unwrap()
            .clone();
        assert_eq!(head.last_seq, 5);

        // Lose the canonical rows 3..=5 while the head stays at 5 (the migration
        // window's shape; a Postgres restore of rows without the head cannot happen
        // under B, but the reconcile must still be correct if it did).
        let client = pool.get().await.unwrap();
        client
            .execute(
                "DELETE FROM audit_log_rows WHERE tenant_id = $1 AND seq >= 3",
                &[tenant.as_uuid()],
            )
            .await
            .unwrap();
        assert_eq!(
            crate::db::ledger::max_seq(&pool, &tenant).await.unwrap(),
            Some(2)
        );

        let boot = AuditChain::with_pg_pool(1000, None, Some(&url), Some(pool.clone())).unwrap();
        boot.warm_from_postgres().await.unwrap();
        assert_eq!(
            crate::db::ledger::max_seq(&pool, &tenant).await.unwrap(),
            Some(5),
            "the gap 3..=5 was filled from the copy"
        );
        let leaves = crate::db::ledger::read_row_hashes(&pool, &tenant, 0, 5)
            .await
            .unwrap();
        assert_eq!(
            leaves[5], head.last_row_hash,
            "and the recovered row at the head hashes to the head"
        );
        let heads = crate::db::audit_chain_state::load_all(&pool).await.unwrap();
        assert_eq!(
            heads
                .iter()
                .find(|h| h.tenant_id == tenant)
                .unwrap()
                .last_seq,
            5,
            "the head was never touched"
        );

        // Now lose them in BOTH stores: nothing can fill the gap → RED, head untouched.
        client
            .execute(
                "DELETE FROM audit_log_rows WHERE tenant_id = $1 AND seq >= 3",
                &[tenant.as_uuid()],
            )
            .await
            .unwrap();
        ch.query("ALTER TABLE audit_log DELETE WHERE tenant_id = ? AND seq >= 3 SETTINGS mutations_sync = 2")
            .bind(tenant.to_string())
            .execute()
            .await
            .unwrap();
        let before = tracelane_shared::degradation::count(
            tracelane_shared::degradation::Degradation::LedgerHeadAheadOfRows,
        );
        let boot2 = AuditChain::with_pg_pool(1000, None, Some(&url), Some(pool.clone())).unwrap();
        boot2.warm_from_postgres().await.unwrap();
        let after = tracelane_shared::degradation::count(
            tracelane_shared::degradation::Degradation::LedgerHeadAheadOfRows,
        );
        // exact-delta-ok: single-threaded under the ledger runner, and this is the only
        // tenant with a head ahead of its rows in that database at this point.
        assert_eq!(after - before, 1, "RED is COUNTED, once, for this tenant");
        assert_eq!(
            crate::db::ledger::max_seq(&pool, &tenant).await.unwrap(),
            Some(2),
            "no gap row was written"
        );
        let heads = crate::db::audit_chain_state::load_all(&pool).await.unwrap();
        assert_eq!(
            heads
                .iter()
                .find(|h| h.tenant_id == tenant)
                .unwrap()
                .last_seq,
            5,
            "the head is NEVER reset downward"
        );

        // A PURGED tenant in the same shape — head at 5, rows gone from both stores,
        // and NO `tenants` row (the purge deleted it). Frozen, not RED: the count
        // does not move, the head is untouched, no gap row is written. The live
        // tenant above is still head-ahead and would be counted AGAIN by this boot
        // (the registry counts per occurrence), so retire its head first — the
        // purged tenant must be the only head this boot reconciles.
        client
            .execute(
                "DELETE FROM audit_chain_state WHERE tenant_id = $1",
                &[tenant.as_uuid()],
            )
            .await
            .unwrap();
        let purged = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        let chain = AuditChain::with_pg_pool(1000, None, Some(&url), Some(pool.clone())).unwrap();
        adr078_append_n(&chain, &purged, 6).await;
        client
            .execute(
                "DELETE FROM audit_log_rows WHERE tenant_id = $1",
                &[purged.as_uuid()],
            )
            .await
            .unwrap();
        ch.query("ALTER TABLE audit_log DELETE WHERE tenant_id = ? SETTINGS mutations_sync = 2")
            .bind(purged.to_string())
            .execute()
            .await
            .unwrap();
        let before = tracelane_shared::degradation::count(
            tracelane_shared::degradation::Degradation::LedgerHeadAheadOfRows,
        );
        let boot3 = AuditChain::with_pg_pool(1000, None, Some(&url), Some(pool.clone())).unwrap();
        boot3.warm_from_postgres().await.unwrap();
        let after = tracelane_shared::degradation::count(
            tracelane_shared::degradation::Degradation::LedgerHeadAheadOfRows,
        );
        // exact-delta-ok: single-threaded under the ledger runner, and the purged
        // tenant is the only head-ahead head left in this database (see above).
        assert_eq!(
            after - before,
            0,
            "a purged tenant's frozen head is NOT an incident"
        );
        assert_eq!(
            crate::db::ledger::max_seq(&pool, &purged).await.unwrap(),
            None,
            "no gap row was written for the purged tenant"
        );
        let heads = crate::db::audit_chain_state::load_all(&pool).await.unwrap();
        assert_eq!(
            heads
                .iter()
                .find(|h| h.tenant_id == purged)
                .unwrap()
                .last_seq,
            5,
            "the purged tenant's head is retained as-is"
        );
    }

    /// Rule 2 — open question 7, confirmed rather than assumed: a Postgres restore to an
    /// earlier point (head AND rows back at seq 2) while the ClickHouse copy still holds
    /// 0..=5 → the copy rows that chain are adopted into the canonical store and the
    /// head advances to them. A row that does NOT chain is never adopted.
    #[tokio::test]
    #[ignore = "needs a live ClickHouse + Postgres (CLICKHOUSE_TEST_URL, POSTGRES_TEST_URL)"]
    async fn adr078_a_copy_ahead_of_a_restored_head_is_adopted_only_while_it_chains() {
        let Some((url, pool)) = adr078_env().await else {
            eprintln!("skip adr078_copy_ahead: needs CLICKHOUSE_TEST_URL + POSTGRES_TEST_URL");
            return;
        };
        let ch = ch_test_client(&url);
        ch_reset_replacing_audit_log(&ch).await;
        ch_reset_anchor_records(&ch).await;
        let tenant = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        let chain = AuditChain::with_pg_pool(1000, None, Some(&url), Some(pool.clone())).unwrap();
        adr078_append_n(&chain, &tenant, 6).await;
        let full = crate::db::ledger::read_row_hashes(&pool, &tenant, 0, 5)
            .await
            .unwrap();

        // "PITR to seq 2": rows AND head go back together.
        let client = pool.get().await.unwrap();
        client
            .execute(
                "DELETE FROM audit_log_rows WHERE tenant_id = $1 AND seq >= 3",
                &[tenant.as_uuid()],
            )
            .await
            .unwrap();
        crate::db::audit_chain_state::upsert(&pool, &tenant, 2, &full[2])
            .await
            .unwrap();
        // Rewrite the head in place (upsert is monotonic, so set it directly).
        client
            .execute(
                "UPDATE audit_chain_state SET last_seq = 2, last_row_hash = $2 WHERE tenant_id = $1",
                &[tenant.as_uuid(), &full[2].as_slice()],
            )
            .await
            .unwrap();
        // Corrupt the copy's row 5 so it does NOT chain: only 3 and 4 may be adopted.
        ch.query("ALTER TABLE audit_log UPDATE prev_hash = 'ff' WHERE tenant_id = ? AND seq = 5 SETTINGS mutations_sync = 2")
            .bind(tenant.to_string())
            .execute()
            .await
            .unwrap();

        let boot = AuditChain::with_pg_pool(1000, None, Some(&url), Some(pool.clone())).unwrap();
        boot.warm_from_postgres().await.unwrap();
        let heads = crate::db::audit_chain_state::load_all(&pool).await.unwrap();
        let head = heads.iter().find(|h| h.tenant_id == tenant).unwrap();
        assert_eq!(
            head.last_seq, 4,
            "adopted 3 and 4 from the copy; 5 did not chain"
        );
        assert_eq!(head.last_row_hash, full[4]);
        assert_eq!(
            crate::db::ledger::max_seq(&pool, &tenant).await.unwrap(),
            Some(4)
        );
        let leaves = crate::db::ledger::read_row_hashes(&pool, &tenant, 0, 4)
            .await
            .unwrap();
        assert_eq!(
            leaves,
            full[..5].to_vec(),
            "byte-identical hashes, seq 0..=4"
        );
    }

    /// **B-475 (REV-4), unit.** A row whose content re-hashes to its `row_hash` chains;
    /// the SAME row with one byte of payload changed — hash fields untouched — does not;
    /// a row whose `prev_hash` is off the running hash does not.
    #[test]
    fn b475_copy_row_chains_only_when_its_content_rehashes_to_its_row_hash() {
        let tenant = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        let genesis = audit_format::genesis_prev_hash(&tenant);
        let payload =
            audit_format::canonical_payload(&serde_json::json!({"model": "m", "trace_id": "t"}));
        let rh = audit_format::row_hash_v2(&genesis, &tenant, 0, "request", "u", &payload);
        let row = AuditLogRow {
            tenant_id: tenant.to_string(),
            seq: 0,
            event_time: 0,
            event_type: "request".into(),
            actor: "u".into(),
            payload: payload.clone(),
            prev_hash: audit_format::hex_encode(&genesis),
            row_hash: audit_format::hex_encode(&rh),
            rekor_entry_id: None,
            signature: String::new(),
            signing_pubkey: String::new(),
        };
        assert_eq!(
            AuditChain::copy_row_chains(&row, &tenant, &genesis),
            Some(rh)
        );
        let mut altered = row.clone();
        altered.payload = payload.replace("\"m\"", "\"n\""); // one byte of CONTENT
        assert_ne!(altered.payload, payload);
        assert_eq!(
            AuditChain::copy_row_chains(&altered, &tenant, &genesis),
            None,
            "altered content with intact hash fields must be REFUSED — this is B-475"
        );
        let mut off = row.clone();
        off.prev_hash = audit_format::hex_encode(&rh);
        assert_eq!(AuditChain::copy_row_chains(&off, &tenant, &genesis), None);
    }

    /// **B-475 (REV-4), dual-store — Rule 1.** Canonical rows 3..=5 deleted behind a
    /// head at 5; the copy's row 4 has its `payload` ALTERED with both hash fields
    /// intact (the exact tamper the old reconcile adopted). Now: row 3 is adopted,
    /// 4 is refused, the head is NOT reset, `LedgerHeadAheadOfRows` is noted — an
    /// incident, not a repair. Then Rule 2: rows 6..=7 exist only in the copy with
    /// row 7's `actor` altered → 6 adopted, 7 refused, head 6.
    #[tokio::test]
    #[ignore = "needs a live ClickHouse + Postgres (CLICKHOUSE_TEST_URL, POSTGRES_TEST_URL)"]
    async fn b475_the_reconcile_refuses_a_copy_row_whose_content_was_altered() {
        use tracelane_shared::degradation::{Degradation, count};
        let Some((url, pool)) = adr078_env().await else {
            eprintln!("skip b475: needs CLICKHOUSE_TEST_URL + POSTGRES_TEST_URL");
            return;
        };
        let ch = ch_test_client(&url);
        ch_reset_replacing_audit_log(&ch).await;
        ch_reset_anchor_records(&ch).await;
        let tenant = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        let chain = AuditChain::with_pg_pool(1000, None, Some(&url), Some(pool.clone())).unwrap();
        adr078_append_n(&chain, &tenant, 6).await;
        let full = crate::db::ledger::read_row_hashes(&pool, &tenant, 0, 5)
            .await
            .unwrap();
        // Seed a live tenant row so a refusal is RED (B-466 classifies an unknown
        // tenant as purged/frozen instead).
        seed_tenant(&pool, &tenant).await;
        let client = pool.get().await.unwrap();
        // Rule 1 setup: canonical rows 3..=5 gone, head stays at 5.
        client
            .execute(
                "DELETE FROM audit_log_rows WHERE tenant_id = $1 AND seq >= 3",
                &[tenant.as_uuid()],
            )
            .await
            .unwrap();
        // Tamper the COPY's row 4: payload altered, hash fields intact.
        ch.query("ALTER TABLE audit_log UPDATE payload = concat(payload, ' ') WHERE tenant_id = ? AND seq = 4 SETTINGS mutations_sync = 2")
            .bind(tenant.to_string())
            .execute()
            .await
            .unwrap();
        let before = count(Degradation::LedgerHeadAheadOfRows);
        let boot = AuditChain::with_pg_pool(1000, None, Some(&url), Some(pool.clone())).unwrap();
        boot.warm_from_postgres().await.unwrap();
        assert!(
            count(Degradation::LedgerHeadAheadOfRows) > before,
            "an altered copy row must leave the gap OPEN and RED — this is B-475"
        );
        assert_eq!(
            crate::db::ledger::max_seq(&pool, &tenant).await.unwrap(),
            Some(3),
            "row 3 (intact) adopted, row 4 (altered) refused, nothing past it"
        );
        let heads = crate::db::audit_chain_state::load_all(&pool).await.unwrap();
        let head = heads.iter().find(|h| h.tenant_id == tenant).unwrap();
        assert_eq!(head.last_seq, 5, "the head is never reset");
        assert_eq!(head.last_row_hash, full[5]);

        // Rule 2 setup: restore the canonical rows and head to 5 from the (now
        // untampered) copy rows 4..=5 by re-appending the copy's original content —
        // simplest: put the copy's row 4 back and let the reconcile fill, then add
        // copy rows 6..=7 with row 7's actor altered.
        ch.query("ALTER TABLE audit_log UPDATE payload = substring(payload, 1, length(payload) - 1) WHERE tenant_id = ? AND seq = 4 SETTINGS mutations_sync = 2")
            .bind(tenant.to_string())
            .execute()
            .await
            .unwrap();
        let boot2 = AuditChain::with_pg_pool(1000, None, Some(&url), Some(pool.clone())).unwrap();
        boot2.warm_from_postgres().await.unwrap();
        assert_eq!(
            crate::db::ledger::max_seq(&pool, &tenant).await.unwrap(),
            Some(5),
            "restored copy fills the gap"
        );
        // Two more rows the copy has and the canonical store does not (head at 5).
        let payload6 = audit_format::canonical_payload(&serde_json::json!({"model": "m6"}));
        let h6 = audit_format::row_hash_v2(&full[5], &tenant, 6, "request", "u", &payload6);
        let payload7 = audit_format::canonical_payload(&serde_json::json!({"model": "m7"}));
        let h7 = audit_format::row_hash_v2(&h6, &tenant, 7, "request", "u", &payload7);
        for (seq, prev, rh, payload, actor) in [
            (6u64, full[5], h6, payload6.clone(), "u"),
            (7u64, h6, h7, payload7.clone(), "ALTERED"), // hashes computed for actor "u"
        ] {
            ch.query(
                "INSERT INTO audit_log (tenant_id, seq, event_time, event_type, actor, payload, prev_hash, row_hash, signature, signing_pubkey) \
                 VALUES (?, ?, now64(6), 'request', ?, ?, ?, ?, '', '')",
            )
            .bind(tenant.to_string())
            .bind(seq)
            .bind(actor)
            .bind(payload)
            .bind(audit_format::hex_encode(&prev))
            .bind(audit_format::hex_encode(&rh))
            .execute()
            .await
            .unwrap();
        }
        let boot3 = AuditChain::with_pg_pool(1000, None, Some(&url), Some(pool.clone())).unwrap();
        boot3.warm_from_postgres().await.unwrap();
        let heads = crate::db::audit_chain_state::load_all(&pool).await.unwrap();
        let head = heads.iter().find(|h| h.tenant_id == tenant).unwrap();
        assert_eq!(
            head.last_seq, 6,
            "row 6 adopted; row 7 (actor altered, hashes intact) refused"
        );
        assert_eq!(head.last_row_hash, h6);
        assert_eq!(
            crate::db::ledger::max_seq(&pool, &tenant).await.unwrap(),
            Some(6)
        );
        let _ = client
            .execute("DELETE FROM tenants WHERE id = $1", &[tenant.as_uuid()])
            .await;
    }

    /// R21 — **a backlog larger than `anchor_every` must anchor from GENESIS, not from
    /// `head + 1 - anchor_every`.**
    ///
    /// The sweep originally reused `anchor_batch_start`, whose `max(…, end + 1 - n)` term
    /// is a floor the THRESHOLD path needs and the sweep must never apply. With 250
    /// un-anchored rows it yields `batch_start = 150`, so rows **0–149 are never covered**
    /// — and because the watermark then advances to 249, the sweep that exists to catch
    /// un-anchored rows becomes the thing that permanently buries them. Nothing else would
    /// ever come back for them: the count threshold only looks forward.
    ///
    /// Silent by construction — the ledger keeps its hash chain, `/health` stays green,
    /// and 150 rows simply never become third-party verifiable. So it gets its own test
    /// with an explicit assertion on the emitted RANGE, not on "an anchor happened".
    #[tokio::test]
    #[ignore = "needs a live ClickHouse + Postgres (CLICKHOUSE_TEST_URL, POSTGRES_TEST_URL)"]
    async fn r21_backlog_larger_than_anchor_every_anchors_from_genesis() {
        let Some(url) = ch_test_url() else {
            eprintln!("skip r21_backlog_larger: CLICKHOUSE_TEST_URL unset");
            return;
        };
        if std::env::var("POSTGRES_TEST_URL").is_err() {
            eprintln!("skip r21_backlog_larger: POSTGRES_TEST_URL unset");
            return;
        }
        ClickhouseClient::default()
            .with_url(&url)
            .query("CREATE DATABASE IF NOT EXISTS tracelane")
            .execute()
            .await
            .unwrap();
        let ch = ch_test_client(&url);
        ch_reset_replacing_audit_log(&ch).await;
        ch_reset_anchor_records(&ch).await;

        // 250: comfortably more than `anchor_every` (100), so the threshold floor and the
        // correct answer differ by a wide, unmistakable margin.
        const BACKLOG: u64 = 250;
        let pool = pg_test_pool();
        let tenant = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        seed_aged_rows(&pool, &ch, &tenant, BACKLOG, 2 * 24 * 60 * 60).await;

        let key = fresh_signing_key_b64();
        let chain =
            AuditChain::with_pg_pool(100, Some(&key), Some(&url), Some(pool.clone())).unwrap();
        let anchored = chain
            .flush_aged_batches(Duration::from_secs(24 * 60 * 60))
            .await;
        assert_eq!(anchored, 1, "the aged backlog must flush");

        #[derive(Debug, serde::Deserialize, clickhouse::Row)]
        struct AnchorRow {
            batch_start_seq: u64,
            batch_end_seq: u64,
        }
        let mut rows: Vec<AnchorRow> = Vec::new();
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(250)).await;
            rows = ch
                .query(
                    "SELECT batch_start_seq, batch_end_seq FROM audit_anchor_records \
                     WHERE tenant_id = ?",
                )
                .bind(tenant.to_string())
                .fetch_all::<AnchorRow>()
                .await
                .unwrap();
            if !rows.is_empty() {
                break;
            }
        }
        assert_eq!(rows.len(), 1, "exactly one anchor record for one flush");
        assert_eq!(
            (rows[0].batch_start_seq, rows[0].batch_end_seq),
            (0, BACKLOG - 1),
            "the flush must cover the WHOLE un-anchored backlog [0..249]. A start of 150 \
             means the threshold floor leaked into the sweep and rows 0-149 were buried"
        );

        // And the rows themselves — the end-state, not the record. If only the last 100
        // were covered, seq 0 is still unsigned and this is the assertion that says so.
        #[derive(Debug, serde::Deserialize, clickhouse::Row)]
        struct SigCount {
            signed: u64,
        }
        let mut signed = 0u64;
        for _ in 0..40 {
            signed = ch
                .query("SELECT countIf(signature != '') AS signed FROM audit_log FINAL WHERE tenant_id = ?")
                .bind(tenant.to_string())
                .fetch_one::<SigCount>()
                .await
                .unwrap()
                .signed;
            if signed == BACKLOG {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        assert_eq!(
            signed, BACKLOG,
            "all 250 rows must be signed; 100 means rows 0-149 were silently skipped"
        );
    }

    /// Drop + recreate `audit_anchor_records` for a fresh test. Destructive to the
    /// shared table, like [`ch_reset_replacing_audit_log`] — deliberate.
    async fn ch_reset_anchor_records(ch: &ClickhouseClient) {
        ch.query("CREATE DATABASE IF NOT EXISTS tracelane")
            .execute()
            .await
            .unwrap();
        for stmt in [
            "DROP TABLE IF EXISTS tracelane.audit_anchor_records",
            "CREATE TABLE tracelane.audit_anchor_records \
             (tenant_id String, batch_start_seq UInt64, batch_end_seq UInt64, \
              merkle_root String, anchor_state String, \
              ed25519_sig String DEFAULT '', ed25519_pubkey String DEFAULT '', \
              ecdsa_pubkey_spki String DEFAULT '', rekor_log_url String DEFAULT '', \
              rekor_log_index String DEFAULT '', canonicalized_body String DEFAULT '', \
              inclusion_proof String DEFAULT '', checkpoint_envelope String DEFAULT '', \
              anchored_at DateTime64(6,'UTC')) \
             ENGINE = MergeTree PARTITION BY toYYYYMM(anchored_at) \
             ORDER BY (tenant_id, batch_start_seq) SETTINGS index_granularity = 8192",
        ] {
            ch.query(stmt).execute().await.unwrap();
        }
    }

    /// Seed `n` correctly-chained `audit_log` rows for `tenant`, all stamped
    /// `age_secs` in the past, through the PRODUCTION row writer.
    /// Seed `n` chained rows aged `age_secs` into BOTH stores — the canonical
    /// Postgres ledger (ADR-078 B, which the age sweep reads) and the ClickHouse
    /// copy — plus the persisted head, exactly as `append_pg_batch` leaves them.
    async fn seed_aged_rows(
        pool: &deadpool_postgres::Pool,
        ch: &ClickhouseClient,
        tenant: &TenantId,
        n: u64,
        age_secs: i64,
    ) {
        let base_us = Utc::now().timestamp_micros() - age_secs * 1_000_000;
        let mut prev = audit_format::genesis_prev_hash(tenant);
        let mut rows = Vec::with_capacity(n as usize);
        for seq in 0..n {
            let payload = audit_format::canonical_payload(&json!({ "i": seq }));
            let rh = audit_format::row_hash_v2(&prev, tenant, seq, "request", "u", &payload);
            rows.push(AuditLogRow {
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
            });
            prev = rh;
        }
        crate::db::ledger::insert_rows(pool, &rows).await.unwrap();
        crate::db::audit_chain_state::upsert(pool, tenant, n - 1, &prev)
            .await
            .unwrap();
        write_audit_rows(ch, rows).await.unwrap();
    }

    /// **B-483 (2026-09-21) — the sweep recovers a HOLE below the watermark, and the old
    /// probe is the control that cannot see it.** Seeded: 300 aged rows; anchor records
    /// for `[0..99]` and `[200..299]` — the shape prod carried after the 09-20 reboot
    /// killed the anchor task for `29700..29799` two seconds in, with the next batch
    /// then advancing the watermark past the hole. The old probe (`seq > watermark`)
    /// returns `None` here — every row is "above nothing"; the hole-aware probe returns
    /// seq 100. The sweep must anchor EXACTLY `[100..199]` (the floor is the actual
    /// uncovered row, the ceiling the next existing batch's start — never overlapping
    /// either neighbour), stamp it with the REAL current time (never the rows' age —
    /// "anchored late" is evidence, not something to hide), and a second sweep must
    /// find nothing left.
    #[tokio::test]
    #[ignore = "needs a live ClickHouse + Postgres (CLICKHOUSE_TEST_URL, POSTGRES_TEST_URL)"]
    async fn b483_the_sweep_recovers_a_hole_below_the_watermark() {
        let Some(url) = ch_test_url() else {
            eprintln!("skip b483: CLICKHOUSE_TEST_URL unset");
            return;
        };
        if std::env::var("POSTGRES_TEST_URL").is_err() {
            eprintln!("skip b483: POSTGRES_TEST_URL unset");
            return;
        }
        ClickhouseClient::default()
            .with_url(&url)
            .query("CREATE DATABASE IF NOT EXISTS tracelane")
            .execute()
            .await
            .unwrap();
        let ch = ch_test_client(&url);
        ch_reset_replacing_audit_log(&ch).await;
        ch_reset_anchor_records(&ch).await;

        const N: u64 = 300;
        const DAY: i64 = 24 * 60 * 60;
        let pool = pg_test_pool();
        let tenant = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        seed_aged_rows(&pool, &ch, &tenant, N, 2 * DAY).await;
        let fixture_anchor = |start: u64, end: u64| AuditAnchorRecordRow {
            tenant_id: tenant.to_string(),
            batch_start_seq: start,
            batch_end_seq: end,
            merkle_root: "b483-fixture".repeat(4),
            anchor_state: "unanchored".to_string(),
            ed25519_sig: "b483-fixture".to_string(),
            ed25519_pubkey: "b483-fixture".to_string(),
            ecdsa_pubkey_spki: String::new(),
            rekor_log_url: String::new(),
            rekor_log_index: String::new(),
            canonicalized_body: String::new(),
            inclusion_proof: String::new(),
            checkpoint_envelope: String::new(),
            anchored_at: Utc::now().timestamp_micros() - 2 * DAY * 1_000_000,
        };
        for (a, b) in [(0u64, 99u64), (200, 299)] {
            crate::db::ledger::insert_anchor_record(&pool, &fixture_anchor(a, b))
                .await
                .unwrap();
        }

        // The CONTROL: the pre-B-483 probe sees nothing to do — the watermark is 299
        // and no row sits above it. This is exactly why the 100 rows on prod were
        // buried; a probe that returned Some here would mean the class was never real.
        let old = crate::db::ledger::oldest_unanchored(&pool, &tenant, Some(299))
            .await
            .unwrap();
        assert!(
            old.is_none(),
            "the old probe cannot see a hole below the watermark: {old:?}"
        );
        // The hole-aware probe sees the hole, and knows it IS a hole.
        let probe = crate::db::ledger::oldest_uncovered(&pool, &tenant)
            .await
            .unwrap()
            .expect("the hole-aware probe finds the uncovered row");
        assert_eq!(
            (probe.seq, probe.head, probe.watermark),
            (100, 299, Some(299))
        );

        let key = fresh_signing_key_b64();
        let chain =
            AuditChain::with_pg_pool(100, Some(&key), Some(&url), Some(pool.clone())).unwrap();
        // A hole is anchored regardless of max_age — pass a HUGE max_age so a pass
        // here cannot come from the age rule.
        let before = Utc::now().timestamp_micros();
        let anchored = chain
            .flush_aged_batches(Duration::from_secs(365 * DAY as u64))
            .await;
        assert_eq!(anchored, 1, "exactly one batch: the hole");

        let records = crate::db::ledger::read_anchor_records_after(&pool, &tenant, None, 100)
            .await
            .unwrap();
        let mut ranges: Vec<(u64, u64)> = records
            .iter()
            .map(|r| (r.batch_start_seq, r.batch_end_seq))
            .collect();
        ranges.sort_unstable();
        assert_eq!(
            ranges,
            vec![(0, 99), (100, 199), (200, 299)],
            "the hole is filled EXACTLY, overlapping neither neighbour"
        );
        let filled = records
            .iter()
            .find(|r| r.batch_start_seq == 100)
            .expect("the filled batch");
        assert!(
            filled.anchored_at >= before,
            "anchored_at is the REAL time of the late anchor ({}), never backdated to the rows' age",
            filled.anchored_at
        );
        assert!(
            !filled.ed25519_sig.is_empty() && filled.ed25519_sig != "b483-fixture",
            "the filled batch is really signed"
        );
        // Coverage is complete: a second sweep finds nothing, and the probe agrees.
        assert_eq!(
            chain
                .flush_aged_batches(Duration::from_secs(365 * DAY as u64))
                .await,
            0,
            "nothing left to anchor"
        );
        assert!(
            crate::db::ledger::oldest_uncovered(&pool, &tenant)
                .await
                .unwrap()
                .is_none(),
            "every row is inside an anchor batch"
        );
    }

    /// R21 — **`flush_aged_batches` itself, against a live ClickHouse, in BOTH
    /// directions within a SINGLE call.**
    ///
    /// The three tests above prove `anchor_batch_start`'s arithmetic, which is pure and
    /// has no I/O. **They cannot prove the sweep DISCRIMINATES.** A `flush_aged_batches`
    /// that flushed unconditionally, and one that never flushed at all, would both leave
    /// every one of them green — `TRAPS.md` §31: prove both halves, or the carve-out is
    /// indistinguishable from not scanning at all.
    ///
    /// So two tenants are seeded with an **identical** 37-row shape differing in exactly
    /// **one** variable — `event_time` — and ONE call to `flush_aged_batches(24 h)` must
    /// flush exactly the aged one. Asserting one call rather than two runs is deliberate:
    /// the discrimination is what is under test, not the two outcomes separately.
    ///
    /// It then asserts the **observable end-state, not the return count** — an
    /// `audit_anchor_records` row at `[0..36]` plus a signature on all 37 rows, written
    /// by the production writer (`anchor_batch_from_ch` → `anchor_task`). That makes this
    /// the end-to-end companion to the R35 fixture: **R35 proves the three reference
    /// verifiers ACCEPT a width-37 batch; this proves the product actually PRODUCES
    /// one**, through the real writer, with a real Ed25519 signing key.
    ///
    /// Run — **serially**, like the other CH-backed tests here: this and
    /// [`r21_backlog_larger_than_anchor_every_anchors_from_genesis`] both DROP and
    /// recreate the shared `audit_log` / `audit_anchor_records` tables, so in parallel
    /// they clobber each other and fail for a reason that has nothing to do with R21.
    /// ```text
    /// CLICKHOUSE_TEST_URL=http://localhost:8123 \
    /// POSTGRES_TEST_URL=postgres://…            \
    ///   cargo test -p gateway --bins r21_ -- --ignored --test-threads=1 --nocapture
    /// ```
    #[tokio::test]
    #[ignore = "needs a live ClickHouse + Postgres (CLICKHOUSE_TEST_URL, POSTGRES_TEST_URL)"]
    async fn r21_flush_aged_batches_discriminates_on_age_and_writes_a_partial_batch() {
        let Some(url) = ch_test_url() else {
            eprintln!("skip r21_flush_aged_batches: CLICKHOUSE_TEST_URL unset");
            return;
        };
        // Postgres is REQUIRED, not incidental: the sweep is PG-path-only by design, and
        // it takes a per-tenant advisory lock so two co-running gateways cannot both
        // anchor the same batch.
        if std::env::var("POSTGRES_TEST_URL").is_err() {
            eprintln!("skip r21_flush_aged_batches: POSTGRES_TEST_URL unset");
            return;
        }
        // The shared helpers use a client already SCOPED to `tracelane`, which cannot
        // create the database it is scoped to (Code 81 on a fresh server). Bootstrap it
        // with an unscoped client first so this test runs against a throwaway container,
        // not only against a dev stack that happens to have the database already.
        ClickhouseClient::default()
            .with_url(&url)
            .query("CREATE DATABASE IF NOT EXISTS tracelane")
            .execute()
            .await
            .unwrap();

        let ch = ch_test_client(&url);
        ch_reset_replacing_audit_log(&ch).await;
        ch_reset_anchor_records(&ch).await;

        // 37: not 100, not a power of two, and ODD — the same width R35 pins, so the
        // batch this produces exercises RFC6962's lone-odd-leaf promotion.
        const WIDTH: u64 = 37;
        const DAY: i64 = 24 * 60 * 60;

        let pool = pg_test_pool();
        let aged = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        let fresh = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        seed_aged_rows(&pool, &ch, &aged, WIDTH, 2 * DAY).await; // 48 h old — must flush
        seed_aged_rows(&pool, &ch, &fresh, WIDTH, 0).await; // just now  — must NOT flush

        // A signing key, because every write in `anchor_task` is gated on
        // `outcome.is_signed()`; with no key the batch produces no record and the
        // end-state assertions below would pass vacuously against a no-op.
        let key = fresh_signing_key_b64();
        let chain =
            AuditChain::with_pg_pool(100, Some(&key), Some(&url), Some(pool.clone())).unwrap();

        // NEITHER tenant is seeded into `chain.states`, and that is the point.
        // `states` is written at exactly one non-test site — `warm_from_postgres`, at
        // boot — so a sweep that enumerated it would cover only tenants that existed at
        // the last restart and would silently skip every tenant onboarded since. Leaving
        // the map empty here means a green can only come from the durable enumeration.
        assert!(
            chain.states.is_empty(),
            "precondition: the sweep must find these tenants without any in-memory state"
        );

        // B-559: a skip from an EARLIER pass (prod 2026-09-25 03:48: one transient
        // Postgres error on the tenant enumeration) must be closed by the next pass that
        // reads every tenant cleanly. Until the fix nothing resolved it, so
        // `audit_attestation_healthy` read false — and the status page CRITICAL — for
        // 24 h+ over a ledger whose only uncovered rows were the ordinary tail.
        tracelane_shared::degradation::note(
            tracelane_shared::degradation::Degradation::AuditAgeSweepSkipped,
        );
        assert!(
            tracelane_shared::degradation::is_open(
                tracelane_shared::degradation::Degradation::AuditAgeSweepSkipped
            ),
            "precondition: the planted earlier skip is open"
        );

        let anchored = chain
            .flush_aged_batches(Duration::from_secs(DAY as u64))
            .await;

        assert!(
            !tracelane_shared::degradation::is_open(
                tracelane_shared::degradation::Degradation::AuditAgeSweepSkipped
            ),
            "B-559: a sweep pass that read every tenant without a skip must RESOLVE the \
             earlier skip — otherwise one transient read error holds the ledger's \
             attestation health red until the process restarts"
        );

        assert_eq!(
            anchored, 1,
            "exactly ONE of two identically-shaped tenants must flush — the aged one. \
             0 means the sweep never fires (the 92 stay unsigned); 2 means it ignores \
             age entirely and would re-anchor every tenant every 15 minutes"
        );
        assert_eq!(
            chain.last_anchored_end(&aged),
            Some(WIDTH - 1),
            "the watermark cache must be UPSERTED for a tenant that was never in `states` \
             — otherwise the threshold path later recomputes `seq + 1 - n` and overlaps \
             the batch this sweep just anchored"
        );
        assert_eq!(
            chain.last_anchored_end(&fresh),
            None,
            "the fresh tenant must be untouched — not merely un-flushed, but with no \
             watermark written that would suppress its next legitimate flush"
        );

        // ---- the observable end-state, polled: the writes are spawned ----
        #[derive(Debug, serde::Deserialize, clickhouse::Row)]
        struct AnchorRow {
            batch_start_seq: u64,
            batch_end_seq: u64,
            anchor_state: String,
            ed25519_sig: String,
        }
        let mut found: Option<AnchorRow> = None;
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let rows = ch
                .query(
                    "SELECT batch_start_seq, batch_end_seq, anchor_state, ed25519_sig \
                     FROM audit_anchor_records WHERE tenant_id = ?",
                )
                .bind(aged.to_string())
                .fetch_all::<AnchorRow>()
                .await
                .unwrap();
            if let Some(r) = rows.into_iter().next() {
                found = Some(r);
                break;
            }
        }
        let rec = found.expect(
            "the aged tenant must gain an audit_anchor_records row — this is the prod \
             end-state R21 exists to produce, and 'the sweep returned 1' is not it",
        );
        assert_eq!(
            (rec.batch_start_seq, rec.batch_end_seq),
            (0, WIDTH - 1),
            "the anchored batch must be the PARTIAL range [0..36], width 37 — not a \
             width-100 range the tenant never reached"
        );
        assert!(
            !rec.ed25519_sig.is_empty(),
            "an anchor record with no Ed25519 signature is the half we actually sell"
        );
        assert_eq!(
            rec.anchor_state, "unanchored",
            "no Rekor URL is configured in this test, so the batch is signed but not \
             publicly anchored — and the record must SAY so rather than overclaim"
        );

        // The signature backfill is a separate spawned write; poll it separately so a
        // failure names which half broke.
        #[derive(Debug, serde::Deserialize, clickhouse::Row)]
        struct SigCount {
            signed: u64,
            total: u64,
        }
        let mut counts = SigCount {
            signed: 0,
            total: 0,
        };
        for _ in 0..40 {
            counts = ch
                .query(
                    "SELECT countIf(signature != '') AS signed, count() AS total \
                     FROM audit_log FINAL WHERE tenant_id = ?",
                )
                .bind(aged.to_string())
                .fetch_one::<SigCount>()
                .await
                .unwrap();
            if counts.signed == WIDTH {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        assert_eq!(
            (counts.signed, counts.total),
            (WIDTH, WIDTH),
            "all 37 rows must gain a signature — a partial backfill is the R17 failure \
             mode (chain intact, /health green, rows permanently unsigned)"
        );

        let fresh_sigs = ch
            .query(
                "SELECT countIf(signature != '') AS signed, count() AS total \
                    FROM audit_log FINAL WHERE tenant_id = ?",
            )
            .bind(fresh.to_string())
            .fetch_one::<SigCount>()
            .await
            .unwrap();
        assert_eq!(
            (fresh_sigs.signed, fresh_sigs.total),
            (0, WIDTH),
            "the fresh tenant's rows must be untouched — if these are signed too, the \
             age condition did nothing and the test above passed for the wrong reason"
        );
    }

    /// R35 — **emit a PARTIAL-WIDTH anchored batch fixture for the three reference
    /// verifiers.** Founder ruling: R21 does not merge until a batch whose width is not
    /// `anchor_every` is anchored and proven GREEN by Rust, Python AND TypeScript.
    ///
    /// The time-based flush (R32) closes batches early by construction, so every
    /// age-flushed batch has an arbitrary width. Today every one of prod's 158 anchor
    /// records is exactly width 100, so **no partial batch exists anywhere to test
    /// against** — which is precisely why this fixture has to be manufactured.
    ///
    /// **It is built with the PRODUCTION functions** — `audit_format::row_hash_v2`,
    /// `merkle_root_v2`, `genesis_prev_hash`, `anchor_commitment`, `local_attest_msg` —
    /// not a reimplementation. A fixture written to match the verifier would only prove
    /// my reconstruction agrees with the verifier, never that the product does
    /// (`TRAPS.md` §22).
    ///
    /// Ignored by default: it writes a file for an out-of-process check rather than
    /// asserting anything itself. Run:
    /// `cargo test -p gateway -- --ignored r35_emit_partial_width_anchor_fixture --nocapture`
    #[test]
    #[ignore = "fixture generator — writes NDJSON for the three verifiers to consume"]
    fn r35_emit_partial_width_anchor_fixture() {
        use ring::rand;

        // 37, deliberately: not 100, not a power of two, and ODD — so the RFC6962 root
        // exercises the lone-odd-leaf promotion path a width-100 batch never reaches.
        const WIDTH: u64 = 37;
        let tenant =
            TenantId::from_jwt_claim("00000000-0000-4000-8000-0000000000aa".parse().unwrap());

        let rng = rand::SystemRandom::new();
        let doc = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = signature::Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
        let pubkey_b64 = B64.encode(kp.public_key().as_ref());

        let mut prev = audit_format::genesis_prev_hash(&tenant);
        let mut leaves: Vec<audit_format::Hash> = Vec::new();
        let mut lines: Vec<String> = Vec::new();

        for seq in 0..WIDTH {
            let payload = format!("{{\"n\":{seq}}}");
            let rh = audit_format::row_hash_v2(
                &prev,
                &tenant,
                seq,
                "chat.completions.request",
                "apikey:r35",
                &payload,
            );
            lines.push(
                json!({
                    "format": "v2.1",
                    "tenant_id": tenant.to_string(),
                    "seq": seq,
                    // Fixed epoch + seq keeps the fixture byte-stable across runs.
                    "event_time": format!("2026-01-01T00:00:{:02}.000000Z", seq),
                    "event_type": "chat.completions.request",
                    "actor": "apikey:r35",
                    "payload": payload,
                    "prev_hash": audit_format::hex_encode(&prev),
                    "row_hash": audit_format::hex_encode(&rh),
                })
                .to_string(),
            );
            leaves.push(rh);
            prev = rh;
        }

        // Signed but NOT Rekor-anchored: commitment is the single 0x00 byte, which is
        // the state an age-flushed batch is in until (and if) Rekor accepts it.
        let root = audit_format::merkle_root_v2(&leaves);
        let commitment = anchor_commitment(None);
        let sig = kp.sign(&local_attest_msg(&root, &commitment));

        lines.push(
            json!({
                "type": "anchor",
                "tenant_id": tenant.to_string(),
                "batch_start_seq": 0,
                "batch_end_seq": WIDTH - 1,
                "merkle_root": audit_format::hex_encode(&root),
                "anchor_state": "unanchored",
                "ed25519": { "signature": B64.encode(sig.as_ref()), "pubkey": pubkey_b64 },
            })
            .to_string(),
        );

        let out = std::env::var("R35_OUT")
            .unwrap_or_else(|_| "/tmp/r35-partial-batch.ndjson".to_string());
        std::fs::write(&out, lines.join("\n") + "\n").unwrap();
        // Printed, not asserted: the verifiers are the assertion, out of process.
        println!("R35_FIXTURE={out}");
        println!("R35_PUBKEY_B64={pubkey_b64}");
        println!("R35_WIDTH={WIDTH}");
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

    /// An `openssl genpkey -algorithm ed25519` key (PKCS#8 **v1**: seed only, no
    /// public key) is accepted — the self-hosting guide's own procedure produced
    /// one, and `RekorClient::new` refused it with `VersionNotSupported` until
    /// 2026-09-21. The vector is the v1 DER prefix (`OneAsymmetricKey` v0,
    /// `id-Ed25519`, `CurvePrivateKey` OCTET STRING) over a fixed 32-byte seed.
    #[test]
    fn an_openssl_v1_pkcs8_ed25519_key_is_accepted() {
        let mut der = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        der.extend_from_slice(&[0x5a; 32]);
        let b64 = B64.encode(&der);
        let client = RekorClient::new(Some(&b64), None).expect("a v1 PKCS#8 key boots");
        assert!(client.signing.is_some(), "the key was loaded");
        // A truncated DER is still refused — leniency is about the VERSION, not the bytes.
        let broken = B64.encode(&der[..20]);
        assert!(RekorClient::new(Some(&broken), None).is_err());
    }

    /// Keygen utility — prints a fresh ring-generated **v2** PKCS#8 Ed25519 key for
    /// provisioning `TRACELANE_REKOR_SIGNING_KEY`. `openssl genpkey` emits v1 PKCS#8,
    /// accepted since 2026-09-21; this remains the reliable source for a v2 key.
    /// Run explicitly:
    ///   cargo test -p gateway --bin gateway print_signing_key -- --ignored --nocapture
    #[test]
    #[ignore = "keygen utility; prints key material — run explicitly"]
    fn print_signing_key() {
        println!("TRACELANE_REKOR_SIGNING_KEY={}", fresh_signing_key_b64());
    }

    /// On-node deploy proof: given a REAL prod signed audit row's
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

    // forward-fix integration harness (ADR-065 F1) ------------
    //
    // These `#[ignore]`d tests need a live Postgres (audit_chain_state) AND a
    // live ClickHouse (audit_log as ReplacingMergeTree). Run them from the dev
    // stack (`docker compose -f infra/dev/docker-compose.yml up -d`) serially —
    // GATE 1 / GATE 2 recreate the shared `audit_log` table:
    //   POSTGRES_TEST_URL=postgres://… CLICKHOUSE_TEST_URL=http://localhost:8123 \
    //     cargo test -p gateway --bin gateway audit::tests:: -- --ignored --nocapture

    // ── A2: the sync audit fallback is FAIL-CLOSED ──────────────────────────
    // It used to warn and return Ok(()), serving the request with no audit
    // record. These drive a REAL append failure (a pool aimed at a closed port,
    // so `pool.get()` cannot connect) rather than mocking the outcome — the
    // defect was in what publish() does with a genuine Err, so a test that
    // fabricates the Err would be testing the fabrication.

    /// A pool that is structurally valid and can never connect: port 1 is
    /// reserved and nothing listens there. No env var, no live database, so this
    /// runs on every `cargo test` — unlike the `--ignored` Postgres gates above,
    /// which is exactly why the fail-open path went unnoticed for so long.
    fn unreachable_pg_pool() -> deadpool_postgres::Pool {
        let mut cfg = deadpool_postgres::Config::new();
        cfg.host = Some("127.0.0.1".to_owned());
        cfg.port = Some(1);
        cfg.user = Some("nobody".to_owned());
        cfg.dbname = Some("nodb".to_owned());
        cfg.create_pool(
            Some(deadpool_postgres::Runtime::Tokio1),
            tokio_postgres::NoTls,
        )
        .expect("pool config is valid; it simply cannot connect")
    }

    fn a2_event(t: &TenantId) -> AuditEvent {
        AuditEvent {
            tenant_id: t.clone(),
            event_type: "request",
            actor: "u".into(),
            payload: json!({"q": "ping"}),
        }
    }

    /// THE DEFECT. No JetStream configured, so publish() takes the sync fallback;
    /// the append fails; the request must be REFUSED, not served unrecorded.
    #[tokio::test]
    async fn sync_fallback_fails_closed_when_the_append_fails() {
        let t = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        let chain = AuditChain::with_pg_pool(100, None, None, Some(unreachable_pg_pool())).unwrap();
        let verdict = chain.publish(a2_event(&t)).await;
        assert!(
            verdict.is_err(),
            "a failed sync append must return Err so the caller 503s — returning Ok \
             here is the A2 defect: the request is served with NO audit record"
        );
    }

    /// The operator lever may DEFER the record. It must not be able to SUPPRESS it.
    /// This is the specific shape LEGAL-REGISTER.md:58 had to strike a claim over.
    #[tokio::test]
    async fn kill_audit_async_cannot_suppress_the_record() {
        let t = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        let chain = AuditChain::with_pg_pool(100, None, None, Some(unreachable_pg_pool())).unwrap();
        // Pull the lever: force the synchronous path fleet-wide.
        let ks = std::sync::Arc::new(crate::kill_switch::KillSwitch::with_flags(
            [("kill.audit.async".to_owned(), true)]
                .into_iter()
                .collect(),
        ));
        let _ = chain.kill_switch.set(ks);

        assert!(
            chain.publish(a2_event(&t)).await.is_err(),
            "kill.audit.async may force the sync path; it must not turn a failed \
             append into a served, unrecorded request"
        );
    }

    /// The reason the fallback was fail-open in the first place, preserved: a
    /// deployment with NO control plane (dev / OSS self-host) takes the in-memory
    /// path, which does not error, so it keeps serving. If this ever starts
    /// failing, the fix above has bricked self-host and must be revisited.
    #[tokio::test]
    async fn no_control_plane_still_serves_and_does_not_503() {
        let t = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        let chain = AuditChain::new(100, None, None).unwrap();
        assert!(
            chain.publish(a2_event(&t)).await.is_ok(),
            "no Postgres pool => in-memory append => must NOT 503; fail-closed here \
             would brick every OSS self-host deployment"
        );
    }

    /// Build a deadpool from `POSTGRES_TEST_URL`.
    /// B-378 — the head-writer hop, MEASURED, same binary, two shapes.
    ///
    /// (a) the pre-B-378 shape: one `append_from_wire` per event, sequential —
    ///     one PG transaction + one ClickHouse insert (one part) per event;
    /// (b) the B-378 shape: `append_batch_from_wire` in batches of `BATCH_MAX`
    ///     for one tenant — one transaction + one insert per batch.
    ///
    /// Same tenant, same event count, real Postgres + real ClickHouse (the
    /// throwaway containers `run-postgres-integration.sh` /
    /// `run-clickhouse-integration.sh` start). Prints events/s for both and the
    /// ClickHouse PART count each produced — the two numbers the review said
    /// were never measured. Recorded in the B-378 row, never on a public
    /// surface: this box is not the CCX23 and the number is the RATIO.
    ///
    ///   POSTGRES_TEST_URL=… CLICKHOUSE_TEST_URL=… \
    ///   cargo test -p gateway --bin gateway -- b378_head_writer_hop_measured --ignored --nocapture
    #[tokio::test]
    #[ignore = "measurement — needs a live ClickHouse + Postgres (CLICKHOUSE_TEST_URL, POSTGRES_TEST_URL)"]
    async fn b378_head_writer_hop_measured() {
        let Some(url) = ch_test_url() else {
            eprintln!("skip: CLICKHOUSE_TEST_URL unset");
            return;
        };
        if std::env::var("POSTGRES_TEST_URL").is_err() {
            eprintln!("skip: POSTGRES_TEST_URL unset");
            return;
        }
        ClickhouseClient::default()
            .with_url(&url)
            .query("CREATE DATABASE IF NOT EXISTS tracelane")
            .execute()
            .await
            .unwrap();
        let ch = ch_test_client(&url);
        ch_reset_replacing_audit_log(&ch).await;
        let pool = pg_test_pool();
        // Fresh tables in the test DB: the integration DB may already have them.
        let client = pool.get().await.unwrap();
        client
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS audit_chain_state (tenant_id uuid PRIMARY KEY, \
                 last_seq bigint NOT NULL, last_row_hash bytea NOT NULL, \
                 updated_at timestamptz NOT NULL DEFAULT now()); \
                 CREATE TABLE IF NOT EXISTS audit_appended (event_id text PRIMARY KEY, \
                 appended_at timestamptz NOT NULL DEFAULT now());",
            )
            .await
            .unwrap();
        drop(client);
        // anchor_every = 0: no Rekor traffic inside the measurement.
        let chain = AuditChain::with_pg_pool(0, None, Some(&url), Some(pool)).unwrap();

        const N: usize = 320;
        let batch_max = crate::audit_consumer::BATCH_MAX;
        let wires = |tenant: uuid::Uuid, tag: &str| -> Vec<AuditEventWire> {
            (0..N)
                .map(|i| AuditEventWire {
                    event_id: format!("{tag}-{i}-{}", uuid::Uuid::new_v4()),
                    tenant_id: tenant,
                    event_type: "chat.completions.request".into(),
                    actor: "measure".into(),
                    payload_json: format!("{{\"i\":{i},\"model\":\"claude-sonnet-4-6\"}}"),
                })
                .collect()
        };
        async fn parts_written(ch: &ClickhouseClient, rows_per_part: u64) -> u64 {
            // `system.part_log` records every part CREATED by an insert, which is
            // the number that matters here — `system.parts` (active) undercounts
            // as soon as background merges absorb the small parts, and they do
            // within seconds. A part of `rows_per_part` rows is one insert of that
            // shape; the two phases use different sizes, so each is countable.
            // `part_log` is flushed on a timer (7.5 s by default) — force it.
            ch.query("SYSTEM FLUSH LOGS").execute().await.unwrap();
            ch.query(
                "SELECT count() FROM system.part_log WHERE database='tracelane' AND \
                 table='audit_log' AND event_type='NewPart' AND rows = ?",
            )
            .bind(rows_per_part)
            .fetch_one::<u64>()
            .await
            .unwrap_or(0)
        }

        // (a) sequential, one event per transaction.
        let t_a = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        let w_a = wires(*t_a.as_uuid(), "seq");
        let start = std::time::Instant::now();
        for w in &w_a {
            chain.append_from_wire(w).await.unwrap();
        }
        let dur_a = start.elapsed();
        let parts_a = parts_written(&ch, 1).await;

        // (b) batched, BATCH_MAX events per transaction.
        let t_b = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        let w_b = wires(*t_b.as_uuid(), "batch");
        let start = std::time::Instant::now();
        for chunk in w_b.chunks(batch_max) {
            chain.append_batch_from_wire(chunk).await.unwrap();
        }
        let dur_b = start.elapsed();
        let parts_b = parts_written(&ch, batch_max as u64).await;

        let eps = |d: std::time::Duration| N as f64 / d.as_secs_f64();
        eprintln!(
            "B378_MEASURED events={N} sequential={:.0} ev/s ({:?}, {parts_a} parts) \
             batched(K={batch_max})={:.0} ev/s ({:?}, {parts_b} parts) ratio={:.1}x",
            eps(dur_a),
            dur_a,
            eps(dur_b),
            dur_b,
            eps(dur_b) / eps(dur_a)
        );
        // The chain must be intact in BOTH shapes: N rows, seqs 0..N-1, no gaps.
        for t in [&t_a, &t_b] {
            let (n, max_seq): (u64, u64) = ch
                .query(
                    "SELECT count(), max(seq) FROM tracelane.audit_log FINAL WHERE tenant_id = ?",
                )
                .bind(t.to_string())
                .fetch_one::<(u64, u64)>()
                .await
                .unwrap();
            assert_eq!(n, N as u64);
            assert_eq!(max_seq, N as u64 - 1);
        }
        assert!(
            dur_b < dur_a,
            "batching must not be slower than one transaction per event"
        );
        assert_eq!(
            parts_a, N as u64,
            "the sequential shape writes one part per event"
        );
        assert_eq!(
            parts_b,
            (N / batch_max) as u64,
            "the batched shape writes one part per batch"
        );
    }

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

    /// ** cross-process seq race (the whole point of ADR-065 F1).**
    ///
    /// This is the audit-LOG seq-assignment race — DISTINCT from the
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

    /// ** crash-mid-append + restart reconcile (ADR-065 HOLE C).**
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

    /// The `(no-key)` / `(no-rekor)` / `(unknown-uuid)` sentinels produced NO
    /// Rekor entry and must never read as an anchor — the read side
    /// (`trace_reads.rs` chain status) and the backfill both gate on this.
    /// (Security-review HIGH, originally: when a Polar `audit_anchors` meter hung
    /// off the anchor path, a sentinel would have billed an anchor that never
    /// happened. That meter is gone — ADR-076 — the gate is still the truth.)
    #[test]
    fn sentinels_are_never_real_rekor_entries() {
        for sentinel in ["(no-key)", "(no-rekor)", "(unknown-uuid)"] {
            assert!(
                !is_real_rekor_entry(sentinel),
                "{sentinel} is not an anchor"
            );
        }
        assert!(is_real_rekor_entry("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"));
    }

    /// A chain with no billing wiring of any kind anchors without panicking —
    /// anchoring is included on every tier (ADR-076) and never depends on Polar.
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
        // V1 seeded prev_hash to "". v2 derives a per-tenant seed.
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

    #[test]
    fn cap_ledger_content_hashes_long_content_keeps_metadata() {
        // ADR-068: a future/accidental payload carrying raw prompt/response
        // content must NOT enter the retained ledger — it is capped to a
        // hash+len marker; short metadata passes unchanged.
        let long = "u".repeat(5000); // a prompt/response body
        let payload = serde_json::json!({
            "model": "claude-haiku-4-5",
            "trace_id": "3e6985ff-a748-4249-9284-ffb874a08afa",
            "messages": long,                    // simulated raw content
            "business_reference": "loan-12345",  // 256-char-bounded metadata
        });
        let capped = cap_ledger_content(&payload, LEDGER_MAX_VALUE_CHARS);
        let s = serde_json::to_string(&capped).unwrap();
        assert!(
            !s.contains(&"u".repeat(300)),
            "raw content leaked into ledger: {s}"
        );
        assert!(
            s.contains("[content-redacted: len=5000, sha256="),
            "no cap marker: {s}"
        );
        // Short metadata untouched — the ledger stays a useful audit record.
        assert!(s.contains("claude-haiku-4-5"));
        assert!(s.contains("loan-12345"));
        assert!(s.contains("3e6985ff-a748-4249-9284-ffb874a08afa"));
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

    // — B-493: the self-host (no Postgres) ledger writer ----------------------
    //
    // Reproduced 2026-09-21 on this box with the published self-host ClickHouse
    // config (`max_concurrent_queries` 20): 16 users for 30 s admitted 5,941
    // requests; the in-memory path spawned ONE single-row INSERT per ledger
    // event (~11,875 of them), ClickHouse refused them by the thousand
    // (`TOO_MANY_SIMULTANEOUS_QUERIES`), each refusal was a `warn!` — and
    // 9,114 of 11,875 ledger rows never landed. The chain state had advanced
    // for every one of them. The same storm refused ingest's span batches and
    // the ingest process exited (its own test is in `clickhouse_writer.rs`).
    //
    // These three tests pin the fix: rows ride a bounded queue to ONE writer
    // that batches, retries a refused batch until it lands, and refuses the
    // APPEND (fail-closed, ADR-069) when the queue is full — never dropping a
    // row whose seq the chain already consumed.

    /// A ClickHouse stand-in that refuses the first `refuse` requests with the
    /// exact error prod's self-host config produces, then accepts everything.
    struct RefuseFirst {
        seen: std::sync::atomic::AtomicUsize,
        refuse: usize,
    }

    impl wiremock::Respond for RefuseFirst {
        fn respond(&self, _req: &wiremock::Request) -> wiremock::ResponseTemplate {
            let n = self.seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n < self.refuse {
                wiremock::ResponseTemplate::new(503).set_body_string(
                    "Code: 202. DB::Exception: Too many simultaneous queries. Maximum: 20. \
                     (TOO_MANY_SIMULTANEOUS_QUERIES)",
                )
            } else {
                wiremock::ResponseTemplate::new(200)
            }
        }
    }

    /// Seqs in one `audit_log` INSERT body (inflated RowBinary, the `AuditLogRow`
    /// column order): `tenant_id` String · `seq` u64 · `event_time` i64 ·
    /// `event_type` · `actor` · `payload` · `prev_hash` · `row_hash` (Strings) ·
    /// `rekor_entry_id` Nullable(String) · `signature` · `signing_pubkey`.
    fn b493_seqs_in(body: &[u8]) -> Vec<u64> {
        let raw = b493_inflate(body);
        let mut at = 0usize;
        let mut seqs = Vec::new();
        fn varint(raw: &[u8], at: &mut usize) -> usize {
            let (mut n, mut shift) = (0usize, 0u32);
            loop {
                let b = raw[*at];
                *at += 1;
                n |= usize::from(b & 0x7f) << shift;
                if b & 0x80 == 0 {
                    return n;
                }
                shift += 7;
            }
        }
        fn skip_string(raw: &[u8], at: &mut usize) {
            let n = varint(raw, at);
            *at += n;
        }
        while at < raw.len() {
            skip_string(&raw, &mut at); // tenant_id
            seqs.push(u64::from_le_bytes(raw[at..at + 8].try_into().unwrap()));
            at += 8 + 8; // seq, event_time
            for _ in 0..5 {
                skip_string(&raw, &mut at); // event_type, actor, payload, prev_hash, row_hash
            }
            let null_flag = raw[at];
            at += 1;
            if null_flag == 0 {
                skip_string(&raw, &mut at); // rekor_entry_id
            }
            skip_string(&raw, &mut at); // signature
            skip_string(&raw, &mut at); // signing_pubkey
        }
        seqs
    }

    fn b493_event(i: usize) -> AuditEvent {
        AuditEvent {
            tenant_id: tenant(),
            event_type: "chat.completions.request",
            actor: "b493".into(),
            payload: json!({ "i": i }),
        }
    }

    /// The clickhouse crate ships INSERT bodies as ClickHouse compressed blocks
    /// (`[16 B checksum][0x82][u32 compressed incl. 9 B header][u32 raw][LZ4 block]`,
    /// repeated). Inflate them so the RowBinary is readable.
    fn b493_inflate(body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut at = 0usize;
        while at + 25 <= body.len() {
            let method = body[at + 16];
            let comp = u32::from_le_bytes(body[at + 17..at + 21].try_into().unwrap()) as usize;
            let raw = u32::from_le_bytes(body[at + 21..at + 25].try_into().unwrap()) as usize;
            assert_eq!(method, 0x82, "LZ4 block expected");
            let data = &body[at + 25..at + 16 + comp];
            out.extend(lz4_flex::block::decompress(data, raw).expect("lz4 block"));
            at += 16 + comp;
        }
        out
    }

    /// Rows per INSERT body = occurrences of the tenant id string (once per
    /// row; the payload `{"i":n}` never contains it).
    fn b493_rows_in(body: &[u8]) -> usize {
        let raw = b493_inflate(body);
        let needle = tenant().to_string();
        let needle = needle.as_bytes();
        raw.windows(needle.len()).filter(|w| *w == needle).count()
    }

    #[tokio::test]
    async fn b493_self_host_ledger_rows_are_batched_retried_and_never_dropped() {
        use wiremock::matchers::method;
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(method("POST"))
            .respond_with(RefuseFirst {
                seen: std::sync::atomic::AtomicUsize::new(0),
                refuse: 2,
            })
            .mount(&server)
            .await;
        let chain = AuditChain::new(1_000_000, None, Some(&server.uri())).unwrap();
        const N: usize = 500;
        for i in 0..N {
            chain.append(b493_event(i)).await.expect("append");
        }
        assert_eq!(chain.in_memory_seq(&tenant()), N as u64);
        chain
            .drain_ledger_writer(std::time::Duration::from_secs(20))
            .await
            .expect("every queued row lands within the drain window");
        let stats = chain.ledger_writer_stats();
        assert_eq!(
            stats.landed, N as u64,
            "every row the chain consumed landed"
        );
        assert!(
            stats.retried_batches >= 1,
            "a refused batch was retried, not dropped: {stats:?}"
        );
        // The wire: the retried body is byte-identical to the refused one, so
        // distinct bodies × their rows = N, and no row appears in two distinct
        // bodies (each seq is in exactly one batch).
        let reqs = server.received_requests().await.expect("recorded");
        let mut distinct: Vec<&[u8]> = Vec::new();
        for r in &reqs {
            if !distinct.contains(&r.body.as_slice()) {
                distinct.push(&r.body);
            }
        }
        let rows_on_the_wire: usize = distinct.iter().map(|b| b493_rows_in(b)).sum();
        assert_eq!(
            rows_on_the_wire, N,
            "each seq reached ClickHouse in exactly one batch"
        );
        assert!(
            reqs.len() <= N / 10,
            "rows were BATCHED: {} inserts for {N} rows (was one insert per row)",
            reqs.len()
        );
    }

    /// Every anchor record reaches ClickHouse only AFTER every row it covers was
    /// ACCEPTED (a 200, not merely attempted) — the signature backfill is an
    /// `ALTER … UPDATE` that finds nothing if it outruns them. Refused attempts
    /// are excluded from the count (the retried body is byte-identical), so a
    /// writer that dispatched the anchor after a REFUSED attempt would fail here.
    /// Then the same property under 16 CONCURRENT appenders with a signing key:
    /// queue order must equal seq order per tenant (the sends happen under the
    /// chain lock), so no row can land behind the anchor that covers it.
    #[tokio::test]
    async fn b493_a_refused_batch_is_retried_until_it_lands_and_the_anchor_waits_for_it() {
        use wiremock::matchers::method;
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(method("POST"))
            .respond_with(RefuseFirst {
                seen: std::sync::atomic::AtomicUsize::new(0),
                refuse: 3,
            })
            .mount(&server)
            .await;
        let key_b64 = fresh_signing_key_b64();
        let chain = AuditChain::new(4, Some(&key_b64), Some(&server.uri())).unwrap();
        for i in 0..8 {
            chain.append(b493_event(i)).await.expect("append");
        }
        chain
            .drain_ledger_writer(std::time::Duration::from_secs(20))
            .await
            .expect("drained");
        let stats = chain.ledger_writer_stats();
        assert_eq!(stats.landed, 8);
        assert!(stats.retried_batches >= 1, "{stats:?}");
        b493_assert_anchors_follow_their_rows(&server, 3, 4).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn b493_concurrent_appends_keep_every_anchor_behind_its_rows() {
        use wiremock::matchers::method;
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(method("POST"))
            .respond_with(RefuseFirst {
                seen: std::sync::atomic::AtomicUsize::new(0),
                refuse: 2,
            })
            .mount(&server)
            .await;
        let key_b64 = fresh_signing_key_b64();
        let chain = Arc::new(AuditChain::new(10, Some(&key_b64), Some(&server.uri())).unwrap());
        const USERS: usize = 16;
        const PER_USER: usize = 50;
        let mut tasks = Vec::new();
        for u in 0..USERS {
            let chain = Arc::clone(&chain);
            tasks.push(tokio::spawn(async move {
                for i in 0..PER_USER {
                    chain
                        .append(b493_event(u * PER_USER + i))
                        .await
                        .expect("append");
                }
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        chain
            .drain_ledger_writer(std::time::Duration::from_secs(30))
            .await
            .expect("drained");
        assert_eq!(
            chain.ledger_writer_stats().landed,
            (USERS * PER_USER) as u64
        );
        b493_assert_anchors_follow_their_rows(&server, 2, 10).await;
        assert_eq!(
            chain.ledger_writer_stats().anchors_before_rows,
            0,
            "the writer never saw an anchor ahead of a row it covers"
        );
    }

    /// The first `refused` recorded requests are the ones `RefuseFirst` refused
    /// (arrival order = record order). Walk the ACCEPTED requests in order: before
    /// the k-th anchor record, the accepted `audit_log` bodies must together hold
    /// every seq of batch k (`[k·n .. k·n+n-1]`), and the rows landed in seq order.
    async fn b493_assert_anchors_follow_their_rows(
        server: &wiremock::MockServer,
        refused: usize,
        anchor_every: u64,
    ) {
        let reqs = server.received_requests().await.expect("recorded");
        let q = |r: &wiremock::Request| r.url.query().unwrap_or_default().to_string();
        let mut landed: Vec<u64> = Vec::new();
        let mut anchors_seen = 0u64;
        for (i, r) in reqs.iter().enumerate() {
            if i < refused {
                continue;
            }
            let query = q(r);
            if query.contains("audit_anchor_records") {
                let (lo, hi) = (
                    anchors_seen * anchor_every,
                    anchors_seen * anchor_every + anchor_every - 1,
                );
                for seq in lo..=hi {
                    assert!(
                        landed.contains(&seq),
                        "anchor #{anchors_seen} for [{lo}..{hi}] reached ClickHouse before row {seq} was ACCEPTED \
                         (landed so far: {} rows)",
                        landed.len()
                    );
                }
                anchors_seen += 1;
            } else if query.contains("audit_log") {
                landed.extend(b493_seqs_in(&r.body));
            }
        }
        assert!(anchors_seen >= 1, "at least one anchor record was written");
        assert!(
            landed.windows(2).all(|w| w[1] == w[0] + 1),
            "rows reached ClickHouse in seq order: {landed:?}"
        );
    }

    #[tokio::test]
    async fn b493_a_saturated_self_host_ledger_writer_refuses_the_append_fail_closed() {
        use wiremock::matchers::method;
        let server = wiremock::MockServer::start().await;
        // ClickHouse never answers: the writer's in-flight batch never lands and
        // the queue fills. The append must then FAIL (503 upstream), and the chain
        // must not have consumed a seq for the refused event — a seq without a
        // row is the hole this test exists to forbid.
        wiremock::Mock::given(method("POST"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(300)),
            )
            .mount(&server)
            .await;
        let chain = AuditChain::new(1_000_000, None, Some(&server.uri())).unwrap();
        let mut ok = 0u64;
        let mut refused = false;
        for i in 0..(LEDGER_WRITER_QUEUE_ROWS + LEDGER_WRITER_BATCH_ROWS + 10) {
            match chain.append(b493_event(i)).await {
                Ok(()) => ok += 1,
                Err(err) => {
                    refused = true;
                    assert!(
                        err.to_string().contains("ledger writer"),
                        "the refusal names the writer: {err}"
                    );
                    break;
                }
            }
        }
        assert!(refused, "a full queue REFUSES the append (fail-closed)");
        assert_eq!(
            chain.in_memory_seq(&tenant()),
            ok,
            "the chain consumed a seq for every ACCEPTED append and none for the refused one"
        );
        // Two slots are reserved per append (row + a possible anchor), so the
        // refusal comes when ONE slot is left: capacity − 1 accepted at least.
        assert!(
            ok + 1 >= LEDGER_WRITER_QUEUE_ROWS as u64,
            "the queue holds its capacity before refusing: {ok}"
        );
    }
}

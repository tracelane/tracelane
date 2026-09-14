//! Persistent audit-chain state (per tenant).
//!
//! Closes R1 H4 from the Phase-0 audit-ledger review: previously the
//! `seq` counter and `prev_hash` were in-memory only, so a gateway
//! restart forked the chain. This module persists
//! `(tenant_id, last_seq, last_row_hash)` so restart resumes exactly.
//!
//! Operations:
//! - [`load_all`] — scan every row at startup. Returns the snapshot
//!   used to seed the in-memory `DashMap<TenantId, TenantChainState>`.
//! - [`upsert`] — write the latest `(last_seq, last_row_hash)` for
//!   one tenant after each successful append. ON CONFLICT DO UPDATE.
//! - [`append_atomic_batch`] — ** forward fix (ADR-065 F1), batched in B-378.**
//!   One lock, one ClickHouse insert, the head advanced to the end of the
//!   batch (K = 1 for the sync path). Claim + advance
//!   the chain head for one tenant inside a single Postgres transaction whose
//!   `SELECT … FOR UPDATE` row lock serializes concurrent appends for that
//!   tenant **across processes** (the process-local `parking_lot::Mutex` could
//!   not). The ClickHouse row is written durably *inside* the transaction,
//!   before the head advances and commits (CH-durable-before-PG-advance).
//!
//! The `audit_chain_state` table schema lives in the Drizzle migrations
//! (`apps/web/db/migrations/`, per ADR-040/ — Drizzle is authoritative).

use anyhow::{Context as _, Result};
use deadpool_postgres::Pool;
use tracing::instrument;
use uuid::Uuid;

use tracelane_shared::TenantId;

/// The `last_seq` sentinel meaning "genesis — no row written yet" (ADR-065 F1).
///
/// Stored transiently by [`append_atomic_batch`]'s genesis `INSERT` so the very first
/// assigned seq is `GENESIS_LAST_SEQ + 1 = 0`. It is advanced to `0` inside the
/// same transaction, so a committed `-1` never persists (a mid-append crash
/// rolls the whole transaction back). [`load_all`] already skips negative
/// `last_seq` defensively, so even a stray `-1` reads as "genesis".
const GENESIS_LAST_SEQ: i64 = -1;

/// One row in `audit_chain_state`.
#[derive(Debug, Clone)]
pub struct ChainStateRow {
    pub tenant_id: TenantId,
    pub last_seq: u64,
    /// Raw 32-byte SHA-256 of the most recent row hash.
    pub last_row_hash: [u8; 32],
}

/// Load the full chain-state table. Used at gateway startup to seed
/// `DashMap<TenantId, TenantChainState>` so every tenant resumes
/// from the correct `(seq, prev_hash)`.
///
/// Returns an empty Vec on a fresh database (no rows yet).
#[instrument(skip(pool))]
pub async fn load_all(pool: &Pool) -> Result<Vec<ChainStateRow>> {
    let client = pool.get().await.context("acquire pg client")?;
    let rows = client
        .query(
            "SELECT tenant_id, last_seq, last_row_hash FROM audit_chain_state",
            &[],
        )
        .await
        .context("SELECT audit_chain_state")?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let id: Uuid = r.get(0);
        let last_seq: i64 = r.get(1);
        // Opus-rereview LOW-3: refuse to interpret a negative `last_seq`
        // as `u64`. Schema CHECK should prevent it, but a future
        // operator running a recovery script could set it negative;
        // refuse rather than panic-cast.
        if last_seq < 0 {
            tracing::warn!(
                tenant_id = %id,
                last_seq,
                "audit_chain_state row has negative last_seq; skipping"
            );
            continue;
        }
        let last_row_hash_bytes: &[u8] = r.get(2);
        if last_row_hash_bytes.len() != 32 {
            // The schema enforces octet_length = 32; this branch is a
            // defence against schema drift. Skip the row and warn.
            tracing::warn!(
                tenant_id = %id,
                actual_len = last_row_hash_bytes.len(),
                "audit_chain_state row has malformed last_row_hash; skipping"
            );
            continue;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(last_row_hash_bytes);
        out.push(ChainStateRow {
            tenant_id: TenantId::from_jwt_claim(id),
            last_seq: last_seq as u64,
            last_row_hash: hash,
        });
    }
    Ok(out)
}

/// Persist the latest chain state for a single tenant.
///
/// **Monotonic write semantics (Phase 3 CRIT-1 fix).**
/// The caller spawns this in a detached `tokio::task::spawn`, so two
/// concurrent appends for the same tenant — at `seq=N` and `seq=N+1`
/// — can land in either order against Postgres. Without monotonic
/// guards, the late-arriving `seq=N` would overwrite the row that
/// already records `seq=N+1`. A subsequent crash + restart would
/// then resume at `seq=N+1` again, re-using the seq — the **exact
/// chain-fork attack the persistence layer was supposed to prevent**.
///
/// The fix is a `GREATEST`-guarded UPDATE: the persisted row only
/// advances. Stale writes are no-ops (UPDATE matches `WHERE` but
/// changes nothing because `EXCLUDED.last_seq` is not greater).
#[instrument(skip(pool, last_row_hash), fields(tenant_id = %tenant_id, last_seq))]
pub async fn upsert(
    pool: &Pool,
    tenant_id: &TenantId,
    last_seq: u64,
    last_row_hash: &[u8; 32],
) -> Result<()> {
    let client = pool.get().await.context("acquire pg client")?;
    client
        .execute(
            "INSERT INTO audit_chain_state (tenant_id, last_seq, last_row_hash) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (tenant_id) DO UPDATE \
             SET last_seq = GREATEST(audit_chain_state.last_seq, EXCLUDED.last_seq), \
                 last_row_hash = CASE \
                     WHEN EXCLUDED.last_seq > audit_chain_state.last_seq \
                     THEN EXCLUDED.last_row_hash \
                     ELSE audit_chain_state.last_row_hash \
                 END, \
                 updated_at = CASE \
                     WHEN EXCLUDED.last_seq > audit_chain_state.last_seq \
                     THEN now() \
                     ELSE audit_chain_state.updated_at \
                 END",
            &[
                tenant_id.as_uuid(),
                &(last_seq as i64),
                &last_row_hash.as_slice(),
            ],
        )
        .await
        .context("UPSERT audit_chain_state")?;
    Ok(())
}

/// The claimed range after one [`append_atomic_batch`] round-trip.
#[derive(Debug, Clone)]
pub struct AtomicBatchAppend {
    /// The seq of the first appended event (`last_seq + 1`, or `0` for genesis).
    pub first_seq: u64,
    /// The head the batch chains from (the prior head, or the genesis seed).
    pub prev_hash: [u8; 32],
    /// One `row_hash` per APPENDED event, in seq order — `row_hashes[i]` is the
    /// hash of seq `first_seq + i`, and the last one is the new persisted head.
    pub row_hashes: Vec<[u8; 32]>,
    /// Which of the caller's events were appended, as indices into the batch
    /// the caller passed, in order. Anything not listed was already appended
    /// (a redelivery) and consumed no seq.
    pub kept: Vec<usize>,
}

// B-390 (2026-09-12): the one-event `append_atomic` and its `AtomicAppend`
// result were DELETED — `append_atomic_batch` below is the transaction, and the
// K = 1 case is that function with `count = 1` (which is what the sync
// `AuditChain::append` path passes). Its ADR-065 F1 ordering (genesis insert →
// FOR UPDATE → durable CH write → head advance → COMMIT) is the batch's.

/// **B-378 (2026-09-12) — the batched form: K events of ONE tenant in ONE
/// transaction, ONE lock acquisition, ONE ClickHouse insert.**
///
/// The head-writer used to run this once per event: a Postgres
/// round-trip, a `FOR UPDATE` lock held across an awaited ClickHouse HTTP
/// insert, and one MergeTree part, per ledger event, sequentially for the whole
/// gateway. This keeps every invariant of the one-event form — the lock still
/// spans the CH write (that is what makes `(seq, prev_hash)` globally
/// serialized across processes), the CH rows are still durable before the head
/// advances, a redelivery still consumes no seq — and amortises the fixed costs
/// over the batch.
///
/// `dedup`: `Some(event_ids)` on the async consumer path — the ids are inserted
/// into `audit_appended` in one statement and ONLY the ones that were new are
/// appended (`kept`); an all-duplicate batch rolls back and returns `Ok(None)`.
/// `None` on the sync path, which never dedups (byte-unchanged behaviour).
///
/// `write_ch(first_seq, prev_hash, kept)` computes the K chained row hashes
/// (`row_hash_i = H(prev_i, …)`, `prev_{i+1} = row_hash_i`), writes ALL K rows
/// in one insert, awaited, and returns the K hashes in order. Returning a
/// different count is a fail-closed error — the head would otherwise advance
/// past rows that were never written.
///
/// # Errors
///
/// Fails **closed** (this is a security path): any PG error, a malformed
/// persisted `last_row_hash`, or a `write_ch` error aborts the transaction (no
/// seq is consumed, no head advance). The caller propagates the error; the audit
/// events are not recorded rather than recorded incorrectly.
pub async fn append_atomic_batch<F, Fut>(
    pool: &Pool,
    tenant_id: &TenantId,
    genesis_prev_hash: [u8; 32],
    dedup: Option<&[String]>,
    count: usize,
    write_ch: F,
) -> Result<Option<AtomicBatchAppend>>
where
    F: FnOnce(u64, [u8; 32], Vec<usize>) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<[u8; 32]>>>,
{
    if count == 0 {
        return Ok(None);
    }
    if let Some(ids) = dedup {
        anyhow::ensure!(
            ids.len() == count,
            "append_atomic_batch: {} event ids for {count} events",
            ids.len()
        );
    }
    let mut client = pool.get().await.context("acquire pg client")?;
    let tx = client
        .transaction()
        .await
        .context("begin audit append tx")?;

    // ADR-069 idempotency: on the async consumer path, dedup on `event_id` INSIDE
    // the tx so a JetStream redelivery consumes no seq and writes no row (the
    //  dup-seq class). ONE statement for the whole batch; `RETURNING` names
    // the ids that were actually new. The synchronous path passes `None` and
    // skips this block entirely, so its behavior is byte-unchanged.
    let kept: Vec<usize> = match dedup {
        Some(ids) => {
            // A batch may carry the same id twice (two redeliveries queued
            // together); the first occurrence wins, later ones are duplicates.
            let mut first_index = std::collections::HashMap::with_capacity(ids.len());
            for (i, id) in ids.iter().enumerate() {
                first_index.entry(id.as_str()).or_insert(i);
            }
            let unique: Vec<&str> = {
                let mut seen = std::collections::HashSet::with_capacity(ids.len());
                ids.iter()
                    .map(String::as_str)
                    .filter(|id| seen.insert(*id))
                    .collect()
            };
            let rows = tx
                .query(
                    "INSERT INTO audit_appended (event_id) \
                     SELECT unnest($1::text[]) ON CONFLICT DO NOTHING RETURNING event_id",
                    &[&unique],
                )
                .await
                .context("audit_appended dedup insert")?;
            let mut kept: Vec<usize> = rows
                .iter()
                .map(|r| {
                    let id: String = r.get(0);
                    first_index[id.as_str()]
                })
                .collect();
            kept.sort_unstable();
            if kept.is_empty() {
                tx.rollback().await.ok();
                return Ok(None);
            }
            kept
        }
        None => (0..count).collect(),
    };
    let n = kept.len();

    // (1) Ensure the chain-state row exists so FOR UPDATE locks a real row even
    //     for a tenant's first-ever append. The genesis sentinel makes the first
    //     assigned seq = 0; it is advanced in this same tx (never commits
    //     standalone). ON CONFLICT DO NOTHING serializes concurrent genesis
    //     inserts across processes.
    tx.execute(
        "INSERT INTO audit_chain_state (tenant_id, last_seq, last_row_hash) \
         VALUES ($1, $2, $3) ON CONFLICT (tenant_id) DO NOTHING",
        &[
            tenant_id.as_uuid(),
            &GENESIS_LAST_SEQ,
            &genesis_prev_hash.as_slice(),
        ],
    )
    .await
    .context("genesis insert audit_chain_state")?;

    // (2) Lock + read the head. FOR UPDATE holds the row lock until COMMIT.
    let row = tx
        .query_one(
            "SELECT last_seq, last_row_hash FROM audit_chain_state \
             WHERE tenant_id = $1 FOR UPDATE",
            &[tenant_id.as_uuid()],
        )
        .await
        .context("SELECT FOR UPDATE audit_chain_state")?;
    let last_seq: i64 = row.get(0);
    let last_row_hash_bytes: &[u8] = row.get(1);
    if last_row_hash_bytes.len() != 32 {
        // Never chain from a malformed head — fail closed.
        anyhow::bail!(
            "audit_chain_state.last_row_hash is {} bytes, expected 32",
            last_row_hash_bytes.len()
        );
    }
    let mut prev_hash = [0u8; 32];
    prev_hash.copy_from_slice(last_row_hash_bytes);
    // `last_seq + 1`: -1 -> 0 (genesis), N -> N+1. A negative other than -1
    // (corrupt) makes this negative -> try_into fails -> fail closed.
    let first_seq: u64 = (last_seq + 1)
        .try_into()
        .context("audit_chain_state.last_seq is corrupt (negative)")?;

    // (3) Durable CH write of ALL K rows BEFORE the head advances
    //     (CH-durable-before-PG).
    let row_hashes = write_ch(first_seq, prev_hash, kept.clone())
        .await
        .context("durable ClickHouse audit_log write")?;
    anyhow::ensure!(
        row_hashes.len() == n,
        "append_atomic_batch: write_ch returned {} hashes for {n} events — refusing to advance the head",
        row_hashes.len()
    );
    let last_seq_new = first_seq + (n as u64 - 1);
    let head = row_hashes[n - 1];

    // (4) Advance the head to the END of the batch.
    tx.execute(
        "UPDATE audit_chain_state \
         SET last_seq = $2, last_row_hash = $3, updated_at = now() \
         WHERE tenant_id = $1",
        &[
            tenant_id.as_uuid(),
            &(last_seq_new as i64),
            &head.as_slice(),
        ],
    )
    .await
    .context("advance audit_chain_state head")?;

    // (5) Commit — releases the FOR UPDATE lock.
    tx.commit().await.context("commit audit append tx")?;

    Ok(Some(AtomicBatchAppend {
        first_seq,
        prev_hash,
        row_hashes,
        kept,
    }))
}

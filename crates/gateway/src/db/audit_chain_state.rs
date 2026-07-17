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
//! - [`append_atomic`] — **B-108 forward fix (ADR-065 F1).** Claim + advance
//!   the chain head for one tenant inside a single Postgres transaction whose
//!   `SELECT … FOR UPDATE` row lock serializes concurrent appends for that
//!   tenant **across processes** (the process-local `parking_lot::Mutex` could
//!   not). The ClickHouse row is written durably *inside* the transaction,
//!   before the head advances and commits (CH-durable-before-PG-advance).
//!
//! The `audit_chain_state` table schema lives in the Drizzle migrations

use anyhow::{Context as _, Result};
use deadpool_postgres::Pool;
use tracing::instrument;
use uuid::Uuid;

use tracelane_shared::TenantId;

/// The `last_seq` sentinel meaning "genesis — no row written yet" (ADR-065 F1).
///
/// Stored transiently by [`append_atomic`]'s genesis `INSERT` so the very first
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

/// The claimed head after one [`append_atomic`] round-trip.
#[derive(Debug, Clone, Copy)]
pub struct AtomicAppend {
    /// The seq assigned to this event (`last_seq + 1`, or `0` for genesis).
    pub seq: u64,
    /// The `prev_hash` this event chains from (the prior head, or the genesis
    /// seed for the first event).
    pub prev_hash: [u8; 32],
    /// The `row_hash` returned by the durable-CH-write closure — now persisted
    /// as the new head.
    pub row_hash: [u8; 32],
}

/// **B-108 forward fix (ADR-065 F1) — per-tenant Postgres-serialized append.**
///
/// Claim the next seq for `tenant_id`, invoke `write_ch` to durably write the
/// ClickHouse row, then advance the persisted head — all inside ONE Postgres
/// transaction. The `SELECT … FOR UPDATE` row lock serializes concurrent
/// appends for this tenant **across processes**, which the process-local
/// `parking_lot::Mutex` could not: two co-running gateways (blue-green overlap)
/// or a restart with a lagged persist can no longer both mint the same seq.
///
/// Ordering (strict):
/// 1. `INSERT … ON CONFLICT DO NOTHING` a genesis row so `FOR UPDATE` has a real
///    row to lock even on a tenant's very first append. Concurrent genesis
///    inserts serialize: the loser blocks on the winner's uncommitted row, then
///    reads it.
/// 2. `SELECT last_seq, last_row_hash … FOR UPDATE` — acquire the per-tenant
///    lock and read the head. `seq = last_seq + 1`; `prev_hash = last_row_hash`.
/// 3. `write_ch(seq, prev_hash)` — the caller computes `row_hash` and writes the
///    ClickHouse row **durably (awaited)**. CH-durable-before-PG-advance: a crash
///    here rolls the transaction back; the orphan CH row (if it landed) is
///    superseded by the `ReplacingMergeTree` version winner on retry, or adopted
///    by warm-reconcile on restart.
/// 4. `UPDATE … SET last_seq, last_row_hash` — advance the head.
/// 5. `COMMIT` — release the lock.
///
/// This is one PG write **per audit event** (~1–2 per request), not per gateway
/// request — correctness dominates the hot-path budget on the zero-tolerance
/// integrity path by design (ADR-065).
///
/// # Errors
///
/// Fails **closed** (this is a security path): any PG error, a malformed
/// persisted `last_row_hash`, or a `write_ch` error aborts the transaction (no
/// seq is consumed, no head advance). The caller propagates the error; the audit
/// event is not recorded rather than recorded incorrectly.
pub async fn append_atomic<F, Fut>(
    pool: &Pool,
    tenant_id: &TenantId,
    genesis_prev_hash: [u8; 32],
    write_ch: F,
) -> Result<AtomicAppend>
where
    F: FnOnce(u64, [u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Result<[u8; 32]>>,
{
    let mut client = pool.get().await.context("acquire pg client")?;
    let tx = client
        .transaction()
        .await
        .context("begin audit append tx")?;

    // (1) Ensure the chain-state row exists so FOR UPDATE locks a real row even
    //     for a tenant's first-ever append. The genesis sentinel makes the first
    //     assigned seq = 0; it is advanced to 0 in this same tx (never commits
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
    let seq: u64 = (last_seq + 1)
        .try_into()
        .context("audit_chain_state.last_seq is corrupt (negative)")?;

    // (3) Durable CH write BEFORE the head advances (CH-durable-before-PG).
    let row_hash = write_ch(seq, prev_hash)
        .await
        .context("durable ClickHouse audit_log write")?;

    // (4) Advance the head.
    tx.execute(
        "UPDATE audit_chain_state \
         SET last_seq = $2, last_row_hash = $3, updated_at = now() \
         WHERE tenant_id = $1",
        &[tenant_id.as_uuid(), &(seq as i64), &row_hash.as_slice()],
    )
    .await
    .context("advance audit_chain_state head")?;

    // (5) Commit — releases the FOR UPDATE lock.
    tx.commit().await.context("commit audit append tx")?;

    Ok(AtomicAppend {
        seq,
        prev_hash,
        row_hash,
    })
}

//! The tamper-evident ledger's CANONICAL store — Postgres (ADR-078, ruled B, 2026-09-20).
//!
//! Chain rows (`audit_log_rows`) and per-batch anchor bundles (`audit_anchor_records`)
//! live here, in the same database — and for rows, in the same TRANSACTION — as the
//! head (`audit_chain_state`) and the dedup set (`audit_appended`). That is the whole
//! decision: one transaction, one store, so a restore can never leave the head ahead of
//! the rows. ClickHouse `tracelane.audit_log` / `audit_anchor_records` are a DERIVED
//! copy, written after commit by `crate::audit` and rebuilt by the boot reconcile.
//!
//! Byte identity (ADR-072): the column set mirrors the ClickHouse tables one for one;
//! `payload` is `text`, never `jsonb`, because `row_hash` covers the payload BYTES.
//!
//! # Errors
//! Every function here is on a **fail-CLOSED** path: the ledger publish is fail-closed
//! (ADR-069), so a Postgres error surfaces to the caller, which refuses the append
//! (`503 audit_unavailable`) rather than recording it incorrectly. Nothing here retries
//! or degrades — the ClickHouse COPY is the fail-open half and it lives in `audit.rs`.

use anyhow::{Context as _, Result};
use chrono::{DateTime, TimeZone as _, Utc};
use deadpool_postgres::Pool;
use tokio_postgres::Transaction;
use tracelane_shared::TenantId;

// ── The two row types, shared by the canonical store and the ClickHouse copy ──
// They live HERE (not in `audit.rs`) because the Postgres integration tests include
// `db/` by `#[path]` without the rest of the crate. `clickhouse::Row` derives are
// harmless in Postgres code; they make the same struct the copy's insert type.

/// One chain row — identical in the canonical store and the ClickHouse copy.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, clickhouse::Row)]
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

/// One per-batch anchor bundle (ADR-062 Amendment 1) — the offline-verifiable
/// record the export streams and the three verifiers check. Written once per
/// signed batch, anchored or not.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, clickhouse::Row)]
pub struct AuditAnchorRecordRow {
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

/// Decode a hex SHA-256 into raw bytes. Local so `db/` stays includable by the
/// integration tests without `crate::audit_format`.
pub fn decode_hash_hex(s: &str) -> Result<[u8; 32]> {
    anyhow::ensure!(s.len() == 64, "hash hex is {} chars, expected 64", s.len());
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char)
            .to_digit(16)
            .context("hash hex has a non-hex char")?;
        let lo = (chunk[1] as char)
            .to_digit(16)
            .context("hash hex has a non-hex char")?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

/// Cap on rows one read returns — bounded so a tenant with a million rows cannot pull
/// them into memory in one call. **Must be ≥ `audit_export::MAX_LIMIT`** (a `const _`
/// there asserts it): the export asks for `MAX_LIMIT` rows per page, and a reader that
/// quietly returns fewer than asked is how B-465 shipped — 10,000 here against 50,000
/// there, and a 29,691-row ledger exported as 10,000 rows with a green exit code.
pub const PAGE: i64 = 50_000;

fn micros_to_ts(micros: i64) -> DateTime<Utc> {
    Utc.timestamp_micros(micros)
        .single()
        .unwrap_or_else(|| Utc.timestamp_micros(0).single().unwrap_or_default())
}

fn tenant_uuid(tenant_id: &TenantId) -> uuid::Uuid {
    *tenant_id.as_uuid()
}

fn seq_i64(seq: u64) -> Result<i64> {
    i64::try_from(seq).context("ledger seq does not fit i64")
}

fn row_from_pg(r: &tokio_postgres::Row) -> AuditLogRow {
    let tenant: uuid::Uuid = r.get("tenant_id");
    let seq: i64 = r.get("seq");
    let et: DateTime<Utc> = r.get("event_time");
    AuditLogRow {
        tenant_id: tenant.to_string(),
        seq: u64::try_from(seq).unwrap_or(0),
        event_time: et.timestamp_micros(),
        event_type: r.get("event_type"),
        actor: r.get("actor"),
        payload: r.get("payload"),
        prev_hash: r.get("prev_hash"),
        row_hash: r.get("row_hash"),
        rekor_entry_id: r.get("rekor_entry_id"),
        signature: r.get("signature"),
        signing_pubkey: r.get("signing_pubkey"),
    }
}

fn anchor_from_pg(r: &tokio_postgres::Row) -> AuditAnchorRecordRow {
    let tenant: uuid::Uuid = r.get("tenant_id");
    let s: i64 = r.get("batch_start_seq");
    let e: i64 = r.get("batch_end_seq");
    let at: DateTime<Utc> = r.get("anchored_at");
    AuditAnchorRecordRow {
        tenant_id: tenant.to_string(),
        batch_start_seq: u64::try_from(s).unwrap_or(0),
        batch_end_seq: u64::try_from(e).unwrap_or(0),
        merkle_root: r.get("merkle_root"),
        anchor_state: r.get("anchor_state"),
        ed25519_sig: r.get("ed25519_sig"),
        ed25519_pubkey: r.get("ed25519_pubkey"),
        ecdsa_pubkey_spki: r.get("ecdsa_pubkey_spki"),
        rekor_log_url: r.get("rekor_log_url"),
        rekor_log_index: r.get("rekor_log_index"),
        canonicalized_body: r.get("canonicalized_body"),
        inclusion_proof: r.get("inclusion_proof"),
        checkpoint_envelope: r.get("checkpoint_envelope"),
        anchored_at: at.timestamp_micros(),
    }
}

const ROW_COLUMNS: &str = "tenant_id, seq, event_time, event_type, actor, payload, prev_hash, \
                           row_hash, rekor_entry_id, signature, signing_pubkey";

/// Write a batch of chain rows INSIDE the caller's transaction — the one that holds the
/// `FOR UPDATE` head lock and advances it. One multi-row `INSERT … SELECT unnest(…)`.
/// `ON CONFLICT DO NOTHING` on `(tenant_id, seq)`: a seq is minted exactly once under the
/// row lock, so a conflict can only mean the boot reconcile already adopted this row from
/// the ClickHouse copy — identical bytes, so nothing is lost by keeping the first.
pub async fn insert_rows_tx(tx: &Transaction<'_>, rows: &[AuditLogRow]) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut tenant_ids: Vec<uuid::Uuid> = Vec::with_capacity(rows.len());
    let mut seqs: Vec<i64> = Vec::with_capacity(rows.len());
    let mut times: Vec<DateTime<Utc>> = Vec::with_capacity(rows.len());
    let mut types: Vec<&str> = Vec::with_capacity(rows.len());
    let mut actors: Vec<&str> = Vec::with_capacity(rows.len());
    let mut payloads: Vec<&str> = Vec::with_capacity(rows.len());
    let mut prevs: Vec<&str> = Vec::with_capacity(rows.len());
    let mut hashes: Vec<&str> = Vec::with_capacity(rows.len());
    let mut rekors: Vec<Option<&str>> = Vec::with_capacity(rows.len());
    let mut sigs: Vec<&str> = Vec::with_capacity(rows.len());
    let mut pks: Vec<&str> = Vec::with_capacity(rows.len());
    for r in rows {
        tenant_ids.push(
            uuid::Uuid::parse_str(&r.tenant_id)
                .with_context(|| format!("ledger row tenant_id is not a uuid: {}", r.tenant_id))?,
        );
        seqs.push(seq_i64(r.seq)?);
        times.push(micros_to_ts(r.event_time));
        types.push(&r.event_type);
        actors.push(&r.actor);
        payloads.push(&r.payload);
        prevs.push(&r.prev_hash);
        hashes.push(&r.row_hash);
        rekors.push(r.rekor_entry_id.as_deref());
        sigs.push(&r.signature);
        pks.push(&r.signing_pubkey);
    }
    tx.execute(
        "INSERT INTO audit_log_rows (tenant_id, seq, event_time, event_type, actor, payload, \
                                     prev_hash, row_hash, rekor_entry_id, signature, signing_pubkey) \
         SELECT * FROM unnest($1::uuid[], $2::bigint[], $3::timestamptz[], $4::text[], $5::text[], \
                              $6::text[], $7::text[], $8::text[], $9::text[], $10::text[], $11::text[]) \
         ON CONFLICT (tenant_id, seq) DO NOTHING",
        &[
            &tenant_ids, &seqs, &times, &types, &actors, &payloads, &prevs, &hashes, &rekors,
            &sigs, &pks,
        ],
    )
    .await
    .context("audit_log_rows insert")?;
    Ok(())
}

/// Same insert, on a pooled client outside any transaction — the reconcile's "adopt
/// these rows from the ClickHouse copy" path. Idempotent for the same reason as above.
pub async fn insert_rows(pool: &Pool, rows: &[AuditLogRow]) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut client = pool.get().await.context("acquire pg client")?;
    let tx = client
        .transaction()
        .await
        .context("begin ledger adopt tx")?;
    insert_rows_tx(&tx, rows).await?;
    tx.commit().await.context("commit ledger adopt tx")?;
    Ok(())
}

/// The per-batch anchor bundle — written once per signed batch, canonical here.
pub async fn insert_anchor_record(pool: &Pool, row: &AuditAnchorRecordRow) -> Result<()> {
    let client = pool.get().await.context("acquire pg client")?;
    let tenant = uuid::Uuid::parse_str(&row.tenant_id).context("anchor tenant_id is not a uuid")?;
    client
        .execute(
            "INSERT INTO audit_anchor_records (tenant_id, batch_start_seq, batch_end_seq, merkle_root, \
                 anchor_state, ed25519_sig, ed25519_pubkey, ecdsa_pubkey_spki, rekor_log_url, \
                 rekor_log_index, canonicalized_body, inclusion_proof, checkpoint_envelope, anchored_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
             ON CONFLICT (tenant_id, batch_start_seq) DO NOTHING",
            &[
                &tenant,
                &seq_i64(row.batch_start_seq)?,
                &seq_i64(row.batch_end_seq)?,
                &row.merkle_root,
                &row.anchor_state,
                &row.ed25519_sig,
                &row.ed25519_pubkey,
                &row.ecdsa_pubkey_spki,
                &row.rekor_log_url,
                &row.rekor_log_index,
                &row.canonicalized_body,
                &row.inclusion_proof,
                &row.checkpoint_envelope,
                &micros_to_ts(row.anchored_at),
            ],
        )
        .await
        .context("audit_anchor_records insert")?;
    Ok(())
}

/// Per-batch signature backfill onto the rows — the canonical half of what
/// `audit.rs::backfill_signature` used to do to ClickHouse alone.
pub async fn backfill_signature(
    pool: &Pool,
    tenant_id: &TenantId,
    signature_b64: &str,
    pubkey_b64: &str,
    start_seq: u64,
    end_seq: u64,
) -> Result<u64> {
    let client = pool.get().await.context("acquire pg client")?;
    let n = client
        .execute(
            "UPDATE audit_log_rows SET signature = $2, signing_pubkey = $3 \
             WHERE tenant_id = $1 AND seq >= $4 AND seq <= $5",
            &[
                &tenant_uuid(tenant_id),
                &signature_b64,
                &pubkey_b64,
                &seq_i64(start_seq)?,
                &seq_i64(end_seq)?,
            ],
        )
        .await
        .context("audit_log_rows signature backfill")?;
    Ok(n)
}

/// Rekor entry id backfill onto the rows of an anchored batch.
pub async fn backfill_rekor_entry_id(
    pool: &Pool,
    tenant_id: &TenantId,
    entry_id: &str,
    start_seq: u64,
    end_seq: u64,
) -> Result<u64> {
    let client = pool.get().await.context("acquire pg client")?;
    let n = client
        .execute(
            "UPDATE audit_log_rows SET rekor_entry_id = $2 \
             WHERE tenant_id = $1 AND seq >= $3 AND seq <= $4",
            &[
                &tenant_uuid(tenant_id),
                &entry_id,
                &seq_i64(start_seq)?,
                &seq_i64(end_seq)?,
            ],
        )
        .await
        .context("audit_log_rows rekor_entry_id backfill")?;
    Ok(n)
}

/// The batch leaf set `[start_seq ..= end_seq]` as raw 32-byte hashes, in seq order —
/// what the anchor task builds its Merkle root from. Returns fewer than
/// `end - start + 1` when rows are missing; the caller refuses to anchor an incomplete
/// batch, exactly as it did against ClickHouse.
pub async fn read_row_hashes(
    pool: &Pool,
    tenant_id: &TenantId,
    start_seq: u64,
    end_seq: u64,
) -> Result<Vec<[u8; 32]>> {
    let client = pool.get().await.context("acquire pg client")?;
    let rows = client
        .query(
            "SELECT row_hash FROM audit_log_rows \
             WHERE tenant_id = $1 AND seq >= $2 AND seq <= $3 ORDER BY seq ASC",
            &[
                &tenant_uuid(tenant_id),
                &seq_i64(start_seq)?,
                &seq_i64(end_seq)?,
            ],
        )
        .await
        .context("audit_log_rows leaf read")?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let hex: String = r.get(0);
        let h = decode_hash_hex(&hex)
            .with_context(|| format!("audit_log_rows.row_hash is not a 32-byte hex hash: {hex}"))?;
        out.push(h);
    }
    Ok(out)
}

/// Rows in an `event_time` window with `seq > after_seq` (all when `None`),
/// seq-ascending, bounded — the export's page.
pub async fn read_rows_in_window(
    pool: &Pool,
    tenant_id: &TenantId,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
    after_seq: Option<u64>,
    limit: i64,
) -> Result<Vec<AuditLogRow>> {
    let client = pool.get().await.context("acquire pg client")?;
    let after: i64 = match after_seq {
        Some(a) => seq_i64(a)?,
        None => -1,
    };
    let rows = client
        .query(
            &format!(
                "SELECT {ROW_COLUMNS} FROM audit_log_rows \
                 WHERE tenant_id = $1 AND event_time >= $2 AND event_time <= $3 AND seq > $4 \
                 ORDER BY seq ASC LIMIT $5"
            ),
            &[
                &tenant_uuid(tenant_id),
                &since,
                &until,
                &after,
                &limit.clamp(1, PAGE),
            ],
        )
        .await
        .context("audit_log_rows window read")?;
    Ok(rows.iter().map(row_from_pg).collect())
}

/// The newest bounded window is selected backwards using the tenant/sequence key.
/// It is returned forwards because verification walks the chain in sequence order.
fn newest_rows_sql() -> String {
    format!(
        "SELECT {ROW_COLUMNS} FROM audit_log_rows \
             WHERE tenant_id = $1 AND event_time >= $2 AND event_time <= $3 \
             ORDER BY seq DESC LIMIT $4"
    )
}

pub async fn read_newest_rows_in_window(
    pool: &Pool,
    tenant_id: &TenantId,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
    limit: i64,
) -> Result<Vec<AuditLogRow>> {
    let client = pool.get().await.context("acquire pg client")?;
    let rows = client
        .query(
            &newest_rows_sql(),
            &[
                &tenant_uuid(tenant_id),
                &since,
                &until,
                &limit.clamp(1, PAGE),
            ],
        )
        .await
        .context("audit_log_rows newest window read")?;
    Ok(rows.iter().rev().map(row_from_pg).collect())
}

const SEQUENCE_ANCHORS_SQL: &str = "SELECT tenant_id, batch_start_seq, batch_end_seq, merkle_root, anchor_state, \
    ed25519_sig, ed25519_pubkey, ecdsa_pubkey_spki, rekor_log_url, rekor_log_index, \
    canonicalized_body, inclusion_proof, checkpoint_envelope, anchored_at \
    FROM audit_anchor_records WHERE tenant_id = $1 \
    AND batch_start_seq >= $2 AND batch_start_seq <= $3 AND batch_end_seq <= $3 \
    ORDER BY batch_start_seq ASC LIMIT $4";

/// Read candidate complete batches by sequence, not anchor time. A batch may be
/// recorded later than its events. The caller also checks every covered row exists.
pub async fn read_anchors_for_sequences(
    pool: &Pool,
    tenant_id: &TenantId,
    from: u64,
    through: u64,
    limit: i64,
) -> Result<Vec<AuditAnchorRecordRow>> {
    let client = pool.get().await.context("acquire pg client")?;
    let rows = client
        .query(
            SEQUENCE_ANCHORS_SQL,
            &[
                &tenant_uuid(tenant_id),
                &seq_i64(from)?,
                &seq_i64(through)?,
                &limit.clamp(1, PAGE),
            ],
        )
        .await
        .context("audit_anchor_records sequence read")?;
    Ok(rows.iter().map(anchor_from_pg).collect())
}

const TRACE_CHAIN_SQL: &str = "SELECT seq, rekor_entry_id \
FROM audit_log_rows \
WHERE tenant_id = $1 \
AND event_type IN ('chat.completions.request', 'messages.request', 'embeddings.request') \
AND payload::jsonb ->> 'trace_id' = $2 \
ORDER BY seq DESC LIMIT 1";

/// Per-trace ledger-row lookup by the `trace_id` JSON key embedded in `payload` — the
/// canonical-store half of the per-trace "in tamper-evident ledger" chip (B-513 / CX-14,
/// ADR-078 B). Pinned to the gateway-call event types (`chat.completions.request`,
/// `messages.request`, and `embeddings.request`) so a
/// `guardrail.verdict` / `eval.verdict` row is never mistaken for the call — mirrors
/// `trace_reads::TRACE_CHAIN_SQL` exactly, on the store that is now canonical. Newest row
/// wins (a `trace_id` is unique per request, but be defensive); one row max.
///
/// Reads Postgres directly rather than the ClickHouse copy: the copy write is fail-OPEN
/// after commit (`crate::audit::AuditChain::append_pg_batch`) and repaired only by the
/// boot reconcile, so a read against the copy answered "not chained" for a call the
/// canonical ledger already held, for as long as `LedgerCopyFailed` was open (CX-14).
pub async fn chain_row_by_trace_id(
    pool: &Pool,
    tenant_id: &TenantId,
    trace_id: &str,
) -> Result<Option<(u64, Option<String>)>> {
    let client = pool.get().await.context("acquire pg client")?;
    let row = client
        .query_opt(TRACE_CHAIN_SQL, &[&tenant_uuid(tenant_id), &trace_id])
        .await
        .context("audit_log_rows trace-id lookup")?;
    let Some(r) = row else {
        return Ok(None);
    };
    let seq: i64 = r.get(0);
    let rekor_entry_id: Option<String> = r.get(1);
    Ok(Some((u64::try_from(seq).unwrap_or(0), rekor_entry_id)))
}

/// Rows in an `event_time` window, counted — the self-verify surface's real total.
pub async fn count_rows_in_window(
    pool: &Pool,
    tenant_id: &TenantId,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
) -> Result<u64> {
    let client = pool.get().await.context("acquire pg client")?;
    let r = client
        .query_one(
            "SELECT count(*) FROM audit_log_rows \
             WHERE tenant_id = $1 AND event_time >= $2 AND event_time <= $3",
            &[&tenant_uuid(tenant_id), &since, &until],
        )
        .await
        .context("audit_log_rows window count")?;
    let n: i64 = r.get(0);
    Ok(u64::try_from(n).unwrap_or(0))
}

/// Rows from `from_seq` upward, seq-ascending, bounded — the reconcile's walk.
pub async fn read_rows_from(
    pool: &Pool,
    tenant_id: &TenantId,
    from_seq: u64,
    limit: i64,
) -> Result<Vec<AuditLogRow>> {
    let client = pool.get().await.context("acquire pg client")?;
    let rows = client
        .query(
            &format!(
                "SELECT {ROW_COLUMNS} FROM audit_log_rows \
                 WHERE tenant_id = $1 AND seq >= $2 ORDER BY seq ASC LIMIT $3"
            ),
            &[
                &tenant_uuid(tenant_id),
                &seq_i64(from_seq)?,
                &limit.clamp(1, PAGE),
            ],
        )
        .await
        .context("audit_log_rows seq read")?;
    Ok(rows.iter().map(row_from_pg).collect())
}

/// Anchor bundles whose `anchored_at` falls in the window and whose
/// `batch_start_seq > after_start` (all when `None`), by batch start.
pub async fn read_anchor_records_in_window(
    pool: &Pool,
    tenant_id: &TenantId,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
    after_start: Option<u64>,
    limit: i64,
) -> Result<Vec<AuditAnchorRecordRow>> {
    let client = pool.get().await.context("acquire pg client")?;
    let after: i64 = match after_start {
        Some(a) => seq_i64(a)?,
        None => -1,
    };
    let rows = client
        .query(
            "SELECT tenant_id, batch_start_seq, batch_end_seq, merkle_root, anchor_state, \
                    ed25519_sig, ed25519_pubkey, ecdsa_pubkey_spki, rekor_log_url, rekor_log_index, \
                    canonicalized_body, inclusion_proof, checkpoint_envelope, anchored_at \
             FROM audit_anchor_records \
             WHERE tenant_id = $1 AND anchored_at >= $2 AND anchored_at <= $3 AND batch_start_seq > $4 \
             ORDER BY batch_start_seq ASC LIMIT $5",
            &[&tenant_uuid(tenant_id), &since, &until, &after, &limit.clamp(1, PAGE)],
        )
        .await
        .context("audit_anchor_records window read")?;
    Ok(rows.iter().map(anchor_from_pg).collect())
}

/// Recorded ledger inventory and activity. Times are absent when no matching
/// record exists; `latest_anchor_at` considers only batches marked anchored.
#[derive(Debug, Clone, Default)]
pub struct LedgerRangeStats {
    pub from: Option<u64>,
    pub to: Option<u64>,
    pub total: u64,
    pub latest_event_at: Option<DateTime<Utc>>,
    pub latest_anchor_at: Option<DateTime<Utc>>,
}

const LEDGER_RANGE_SQL: &str = "SELECT min(seq), max(seq), count(*), max(event_time), \
    (SELECT max(anchored_at) FROM audit_anchor_records WHERE tenant_id = $1 AND anchor_state = 'anchored') \
    FROM audit_log_rows WHERE tenant_id = $1";

pub async fn ledger_range(pool: &Pool, tenant_id: &TenantId) -> Result<LedgerRangeStats> {
    let client = pool.get().await.context("acquire pg client")?;
    let r = client
        .query_one(LEDGER_RANGE_SQL, &[&tenant_uuid(tenant_id)])
        .await
        .context("audit ledger range and activity read")?;
    let lo: Option<i64> = r.get(0);
    let hi: Option<i64> = r.get(1);
    let n: i64 = r.get(2);
    Ok(LedgerRangeStats {
        from: lo.and_then(|v| u64::try_from(v).ok()),
        to: hi.and_then(|v| u64::try_from(v).ok()),
        total: u64::try_from(n).context("negative ledger count")?,
        latest_event_at: r.get(3),
        latest_anchor_at: r.get(4),
    })
}

/// `max(seq)` of a tenant's rows, `None` when it has none.
pub async fn max_seq(pool: &Pool, tenant_id: &TenantId) -> Result<Option<u64>> {
    let client = pool.get().await.context("acquire pg client")?;
    let r = client
        .query_one(
            "SELECT max(seq) FROM audit_log_rows WHERE tenant_id = $1",
            &[&tenant_uuid(tenant_id)],
        )
        .await
        .context("audit_log_rows max seq")?;
    let hi: Option<i64> = r.get(0);
    Ok(hi.and_then(|v| u64::try_from(v).ok()))
}

/// Every tenant that has at least one chain row.
pub async fn tenants_with_rows(pool: &Pool) -> Result<Vec<TenantId>> {
    let client = pool.get().await.context("acquire pg client")?;
    let rows = client
        .query("SELECT DISTINCT tenant_id FROM audit_log_rows", &[])
        .await
        .context("audit_log_rows tenant enumeration")?;
    Ok(rows
        .iter()
        .map(|r| TenantId::from_jwt_claim(r.get::<_, uuid::Uuid>(0)))
        .collect())
}

/// The end seq of the newest anchor bundle for a tenant — where the next seq-aligned
/// batch starts from after a restart.
pub async fn last_anchored_end(pool: &Pool, tenant_id: &TenantId) -> Result<Option<u64>> {
    let client = pool.get().await.context("acquire pg client")?;
    let r = client
        .query_one(
            "SELECT max(batch_end_seq) FROM audit_anchor_records WHERE tenant_id = $1",
            &[&tenant_uuid(tenant_id)],
        )
        .await
        .context("audit_anchor_records last end")?;
    let hi: Option<i64> = r.get(0);
    Ok(hi.and_then(|v| u64::try_from(v).ok()))
}

/// Anchor bundles whose `batch_start_seq` is beyond `after_end` (the copy's newest
/// `batch_end_seq`), by batch start — the reconcile's anchor copy.
pub async fn read_anchor_records_after(
    pool: &Pool,
    tenant_id: &TenantId,
    after_end: Option<u64>,
    limit: i64,
) -> Result<Vec<AuditAnchorRecordRow>> {
    let client = pool.get().await.context("acquire pg client")?;
    let after: i64 = match after_end {
        Some(e) => seq_i64(e)?,
        None => -1,
    };
    let rows = client
        .query(
            "SELECT tenant_id, batch_start_seq, batch_end_seq, merkle_root, anchor_state, \
                    ed25519_sig, ed25519_pubkey, ecdsa_pubkey_spki, rekor_log_url, rekor_log_index, \
                    canonicalized_body, inclusion_proof, checkpoint_envelope, anchored_at \
             FROM audit_anchor_records \
             WHERE tenant_id = $1 AND batch_start_seq > $2 \
             ORDER BY batch_start_seq ASC LIMIT $3",
            &[&tenant_uuid(tenant_id), &after, &limit.clamp(1, PAGE)],
        )
        .await
        .context("audit_anchor_records after read")?;
    Ok(rows.iter().map(anchor_from_pg).collect())
}

/// B-483 (2026-09-21) — the age sweep's probe, HOLE-AWARE. The lowest seq that sits
/// inside NO anchor batch for the tenant (a hole below the watermark, or the tail
/// above it), with the age of that row and the tenant's head; `None` when every row
/// is covered. `oldest_unanchored` below probed only `seq > watermark`, and a batch
/// whose anchor task died mid-Rekor (rows 29700..29799 of the deploy-proof tenant,
/// a reboot two seconds in) fell BELOW the watermark the next batch advanced past —
/// buried, with the threshold floor and the sweep both looking only above it.
///
/// `signature` is deliberately not consulted: the anchor record is the coverage
/// witness (`signature` is `''`, not NULL, on those rows — a probe on it would need
/// to know that), and a row inside a batch whose backfill failed is a different
/// finding (`AuditBackfillFailed`) from a row no batch ever covered.
pub struct UncoveredProbe {
    pub seq: u64,
    pub age_secs: u64,
    pub head: u64,
    /// The tenant's anchor watermark (`max(batch_end_seq)`), so the caller can tell
    /// a HOLE (`seq <= watermark`) from the ordinary un-anchored TAIL.
    pub watermark: Option<u64>,
}

pub async fn oldest_uncovered(pool: &Pool, tenant_id: &TenantId) -> Result<Option<UncoveredProbe>> {
    let client = pool.get().await.context("acquire pg client")?;
    let r = client
        .query_opt(
            "WITH u AS ( \
                 SELECT r.seq, r.event_time FROM audit_log_rows r \
                 WHERE r.tenant_id = $1 \
                   AND NOT EXISTS ( \
                     SELECT 1 FROM audit_anchor_records a \
                     WHERE a.tenant_id = r.tenant_id \
                       AND r.seq BETWEEN a.batch_start_seq AND a.batch_end_seq) \
                 ORDER BY r.seq ASC LIMIT 1) \
             SELECT u.seq, extract(epoch FROM now() - u.event_time)::float8, \
                    (SELECT max(seq) FROM audit_log_rows WHERE tenant_id = $1), \
                    (SELECT max(batch_end_seq) FROM audit_anchor_records WHERE tenant_id = $1) \
             FROM u",
            &[&tenant_uuid(tenant_id)],
        )
        .await
        .context("audit_log_rows oldest uncovered")?;
    let Some(r) = r else {
        return Ok(None);
    };
    let seq: i64 = r.get(0);
    let age: Option<f64> = r.get(1);
    let head: Option<i64> = r.get(2);
    let watermark: Option<i64> = r.get(3);
    Ok(Some(UncoveredProbe {
        seq: u64::try_from(seq).unwrap_or(0),
        age_secs: age.unwrap_or(0.0).max(0.0) as u64,
        head: head.and_then(|h| u64::try_from(h).ok()).unwrap_or(0),
        watermark: watermark.and_then(|w| u64::try_from(w).ok()),
    }))
}

/// The start of the first anchor batch strictly after `seq` — the ceiling a
/// hole-filling batch must stop below so it never overlaps an existing batch
/// (R34's no-overlap property, kept by construction).
pub async fn next_anchor_start_after(
    pool: &Pool,
    tenant_id: &TenantId,
    seq: u64,
) -> Result<Option<u64>> {
    let client = pool.get().await.context("acquire pg client")?;
    let r = client
        .query_one(
            "SELECT min(batch_start_seq) FROM audit_anchor_records WHERE tenant_id = $1 AND batch_start_seq > $2",
            &[&tenant_uuid(tenant_id), &seq_i64(seq)?],
        )
        .await
        .context("audit_anchor_records next start")?;
    let v: Option<i64> = r.get(0);
    Ok(v.and_then(|v| u64::try_from(v).ok()))
}

/// `(age of the oldest un-anchored row in seconds, head seq)` for rows with
/// `seq > watermark` — `None` when every row is anchored. The PRE-B-483 probe: it
/// cannot see a hole below the watermark, which is why the sweep no longer uses
/// it; kept under `cfg(test)` as the control the B-483 test contrasts against.
#[cfg(test)]
pub async fn oldest_unanchored(
    pool: &Pool,
    tenant_id: &TenantId,
    watermark: Option<u64>,
) -> Result<Option<(u64, u64)>> {
    let client = pool.get().await.context("acquire pg client")?;
    let after: i64 = match watermark {
        Some(w) => seq_i64(w)?,
        None => -1,
    };
    let r = client
        .query_one(
            "SELECT count(*), extract(epoch FROM now() - min(event_time))::float8, max(seq) \
             FROM audit_log_rows WHERE tenant_id = $1 AND seq > $2",
            &[&tenant_uuid(tenant_id), &after],
        )
        .await
        .context("audit_log_rows oldest unanchored")?;
    let n: i64 = r.get(0);
    if n == 0 {
        return Ok(None);
    }
    let age: Option<f64> = r.get(1);
    let head: Option<i64> = r.get(2);
    match (age, head) {
        (Some(a), Some(h)) => Ok(Some((a.max(0.0) as u64, u64::try_from(h).unwrap_or(0)))),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod membership_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "needs POSTGRES_TEST_URL; executes the production query against a CTE fixture without applying schema"]
    async fn ledger_membership_accepts_all_gateway_routes_and_rejects_other_events() {
        let url = std::env::var("POSTGRES_TEST_URL").expect("POSTGRES_TEST_URL required");
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .expect("local Postgres connection");
        let connection_task = tokio::spawn(connection);
        // Same production SELECT, with rows supplied by a CTE. This tests the
        // Postgres predicate and parameter types without creating/applying schema.
        let sql = format!(
            "WITH audit_log_rows AS (SELECT * FROM (VALUES \
             ($1::uuid, 7::bigint, $3::text, '{{\"trace_id\":\"request\"}}'::text, NULL::text), \
             ($1::uuid, 8::bigint, 'guardrail.verdict', '{{\"trace_id\":\"request\"}}', NULL), \
             ($4::uuid, 9::bigint, 'embeddings.request', '{{\"trace_id\":\"request\"}}', NULL), \
             ($1::uuid, 10::bigint, 'embeddings.request', '{{\"trace_id\":\"another\"}}', NULL)) \
             AS fixture(tenant_id,seq,event_type,payload,rekor_entry_id)) {TRACE_CHAIN_SQL}"
        );
        let tenant = uuid::Uuid::new_v4();
        let other = uuid::Uuid::new_v4();
        for event in [
            "chat.completions.request",
            "messages.request",
            "embeddings.request",
        ] {
            let row = client
                .query_opt(&sql, &[&tenant, &"request", &event, &other])
                .await
                .expect("membership SELECT");
            assert_eq!(
                row.map(|r| r.get::<_, i64>(0)),
                Some(7),
                "{event} must be in the ledger"
            );
        }
        for event in ["guardrail.verdict", "eval.verdict", "sdk.span"] {
            assert!(
                client
                    .query_opt(&sql, &[&tenant, &"request", &event, &other])
                    .await
                    .expect("membership SELECT")
                    .is_none(),
                "{event} must not count as a gateway call"
            );
        }
        connection_task.abort();
    }
}

#[cfg(test)]
mod recent_window_tests {
    use super::*;

    // SELECT-only proof: run the production SQL over CTE rows, never apply schema
    // or touch stored ledger data. The billion-sized sequence is sparse test data.
    #[tokio::test]
    #[ignore = "requires local POSTGRES_TEST_URL; read-only CTE fixtures"]
    async fn recent_window_queries_select_the_head_and_keep_tenant_and_time_bounds() {
        let url = std::env::var("POSTGRES_TEST_URL").expect("local POSTGRES_TEST_URL");
        let config: tokio_postgres::Config = url.parse().unwrap();
        assert!(config.get_hosts().iter().all(|h| matches!(h, tokio_postgres::config::Host::Tcp(host) if host == "localhost" || host == "127.0.0.1")), "local proof only");
        let (client, connection) = config.connect(tokio_postgres::NoTls).await.unwrap();
        let task = tokio::spawn(connection);
        let tenant = uuid::Uuid::new_v4();
        let other = uuid::Uuid::new_v4();
        let since: DateTime<Utc> = "2026-09-01T00:00:00Z".parse().unwrap();
        let until: DateTime<Utc> = "2026-09-24T00:00:00Z".parse().unwrap();
        let fixture = format!(
            "WITH audit_log_rows AS (SELECT t AS tenant_id, seq, at AS event_time, \
            'request'::text AS event_type, 'actor'::text AS actor, '{{}}'::text AS payload, \
            'prev'::text AS prev_hash, 'hash'::text AS row_hash, NULL::text AS rekor_entry_id, \
            NULL::text AS signature, NULL::text AS signing_pubkey FROM (VALUES \
            ($1::uuid, 0::bigint, $2::timestamptz), \
            ($1, 999999998, $3::timestamptz), ($1, 999999999, $3), \
            ($1, 1000000000, $3 + interval '1 day'), \
            ('{other}'::uuid, 1000000001, $3), \
            ($1, 999999997, $2 - interval '1 day')) AS f(t, seq, at)) "
        );
        let rows = client
            .query(
                &format!("{fixture}{}", newest_rows_sql()),
                &[&tenant, &since, &until, &2_i64],
            )
            .await
            .unwrap();
        assert_eq!(
            rows.iter()
                .map(|r| r.get::<_, i64>("seq"))
                .collect::<Vec<_>>(),
            [999_999_999, 999_999_998]
        );
        assert!(
            rows.iter()
                .all(|r| r.get::<_, uuid::Uuid>("tenant_id") == tenant)
        );
        task.abort();
    }

    #[tokio::test]
    #[ignore = "requires local POSTGRES_TEST_URL; read-only CTE fixtures"]
    async fn recent_window_anchor_and_activity_queries_preserve_scope_and_unknowns() {
        let url = std::env::var("POSTGRES_TEST_URL").expect("local POSTGRES_TEST_URL");
        let config: tokio_postgres::Config = url.parse().unwrap();
        assert!(config.get_hosts().iter().all(|h| matches!(h, tokio_postgres::config::Host::Tcp(host) if host == "localhost" || host == "127.0.0.1")), "local proof only");
        let (client, connection) = config.connect(tokio_postgres::NoTls).await.unwrap();
        let task = tokio::spawn(connection);
        let tenant = uuid::Uuid::new_v4();
        let other = uuid::Uuid::new_v4();
        let fixture = format!(
            "WITH audit_anchor_records AS (SELECT t AS tenant_id, lo AS batch_start_seq, hi AS batch_end_seq, \
            'root'::text AS merkle_root, state AS anchor_state, ''::text AS ed25519_sig, ''::text AS ed25519_pubkey, \
            ''::text AS ecdsa_pubkey_spki, ''::text AS rekor_log_url, ''::text AS rekor_log_index, \
            ''::text AS canonicalized_body, ''::text AS inclusion_proof, ''::text AS checkpoint_envelope, at AS anchored_at \
            FROM (VALUES \
            ($1::uuid, 999999900::bigint, 999999999::bigint, 'anchored', '2026-09-24T00:00:00Z'::timestamptz), \
            ($1, 999999899, 999999900, 'anchored', '2026-09-23T00:00:00Z'), \
            ($1, 1000000000, 1000000001, 'unanchored', '2026-09-25T00:00:00Z'), \
            ('{other}'::uuid, 999999950, 999999999, 'anchored', '2026-09-26T00:00:00Z')) AS f(t, lo, hi, state, at)), \
            audit_log_rows AS (SELECT $1::uuid AS tenant_id, 999999999::bigint AS seq, '2026-09-24T00:01:00Z'::timestamptz AS event_time) "
        );
        let rows = client
            .query(
                &format!("{fixture}{SEQUENCE_ANCHORS_SQL}"),
                &[&tenant, &999_999_900_i64, &999_999_999_i64, &1000_i64],
            )
            .await
            .unwrap();
        assert_eq!(
            rows.len(),
            1,
            "exclude partial batches and the other tenant"
        );
        assert_eq!(rows[0].get::<_, i64>("batch_start_seq"), 999_999_900);
        let r = client
            .query_one(&format!("{fixture}{LEDGER_RANGE_SQL}"), &[&tenant])
            .await
            .unwrap();
        assert_eq!(
            r.get::<_, Option<DateTime<Utc>>>(3).unwrap().to_rfc3339(),
            "2026-09-24T00:01:00+00:00"
        );
        assert_eq!(
            r.get::<_, Option<DateTime<Utc>>>(4).unwrap().to_rfc3339(),
            "2026-09-24T00:00:00+00:00",
            "unanchored records and other tenants must not advance last anchored"
        );
        let empty = "WITH audit_log_rows AS (SELECT NULL::uuid AS tenant_id, NULL::bigint AS seq, NULL::timestamptz AS event_time WHERE false), audit_anchor_records AS (SELECT NULL::uuid AS tenant_id, NULL::timestamptz AS anchored_at, NULL::text AS anchor_state WHERE false) ";
        let r = client
            .query_one(&format!("{empty}{LEDGER_RANGE_SQL}"), &[&tenant])
            .await
            .unwrap();
        assert_eq!(r.get::<_, i64>(2), 0);
        assert_eq!(r.get::<_, Option<DateTime<Utc>>>(3), None);
        assert_eq!(r.get::<_, Option<DateTime<Utc>>>(4), None);
        task.abort();
    }
}

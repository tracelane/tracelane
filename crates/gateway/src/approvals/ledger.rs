//! ACT-40: every default-path approval transition lands in the tenant's hash-chained,
//! batch-signed ledger, in the SAME Postgres transaction as the state change it records.
//!
//! The record schema is `tracelane_audit_verifier::approval::Record`, shared with the offline
//! verifier. It carries the keyed request fingerprint, never arguments or previews.
use crate::db::audit_chain_state::AtomicBatchAppend;
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio_postgres::Transaction;
use tracelane_audit_verifier::approval::{Kind, Record, Transition};
use tracelane_shared::TenantId;
use uuid::Uuid;

/// Transitions NOT recorded because the ledger lacks their predecessor (approvals opened
/// before ACT-40 deployed, or while it was reverted). Bounded: they drain within one TTL.
pub(crate) static LEGACY_SKIPPED: AtomicU64 = AtomicU64::new(0);
/// Transitions refused because their ledger record could not be written (fail-CLOSED).
pub(crate) static REFUSED: AtomicU64 = AtomicU64::new(0);

/// Approval columns a record needs, read back after the state change.
pub(crate) struct Row {
    pub args_fp: String,
    pub requester_sub: String,
    pub requester_creator: Option<String>,
    pub subject_kind: String,
    pub subject: String,
    pub server_id: Option<Uuid>,
    pub rule_id: Option<Uuid>,
    pub decided_by: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub grant_expires_at: Option<DateTime<Utc>>,
}

/// Pure: the record for one transition, validated exactly as the verifier will.
///
/// # Errors
/// Fail-CLOSED on any field the verifier would refuse.
pub(crate) fn build(
    tenant: &TenantId,
    id: Uuid,
    transition: Transition,
    at: DateTime<Utc>,
    row: Row,
) -> Result<Record> {
    let decided = matches!(transition, Transition::Approved | Transition::Denied);
    let expires_at = match transition {
        Transition::Requested => Some(row.expires_at),
        Transition::Approved => Some(row.grant_expires_at.context("approval has no grant")?),
        _ => None,
    };
    let record = Record {
        record: Kind::ToolApproval,
        v: 1,
        tenant_id: *tenant.as_uuid(),
        approval_id: id,
        transition,
        occurred_at: at,
        request_fingerprint: row.args_fp,
        requester: row.requester_sub,
        requester_creator: row.requester_creator,
        subject_kind: row.subject_kind,
        subject: row.subject,
        server_id: row.server_id,
        rule_id: row.rule_id,
        decided_by: if decided { row.decided_by } else { None },
        expires_at,
    };
    record.validate()?;
    Ok(record)
}

/// Pure: (event type, actor, JCS payload) — the exact bytes the row hash covers.
///
/// # Errors
/// Fail-CLOSED.
pub(crate) fn encode(record: &Record) -> Result<(String, String, String)> {
    let payload = crate::action_control::canonical(record)?;
    Ok((
        record.transition.event_type(),
        record.expected_actor().to_owned(),
        payload,
    ))
}

/// The dedup identity of one (approval, transition) record.
pub(crate) fn event_id(tenant: &TenantId, id: Uuid, transition: Transition) -> String {
    format!("tool_approval:{tenant}:{id}:{}", transition.as_str())
}

/// Pure: the record the ledger must already hold for `transition` to replay. `granted` is
/// whether the row carries a grant deadline (only an approval sets one), which is how an
/// expiry tells "lapsed grant" from "lapsed request" after the UPDATE has run.
pub(crate) fn predecessor(transition: Transition, granted: bool) -> Option<Transition> {
    match transition {
        Transition::Requested => None,
        Transition::Approved | Transition::Denied => Some(Transition::Requested),
        Transition::Consumed => Some(Transition::Approved),
        Transition::Expired if granted => Some(Transition::Approved),
        Transition::Expired => Some(Transition::Requested),
    }
}

/// The database clock inside the caller's transaction (every expiry predicate uses it).
pub(crate) async fn now(tx: &Transaction<'_>) -> Result<DateTime<Utc>> {
    crate::action_control::db_now(tx).await
}

/// Append one transition record on the caller's transaction.
///
/// # Errors
/// Fail-CLOSED (security path): the caller MUST roll back, so no transition commits without
/// its ledger row. Forward the returned candidate only after the outer COMMIT.
///
/// `Ok(None)`: the approval's earlier lifecycle is not on the ledger (opened before this
/// shipped, or while it was reverted). Writing this row would make the tenant's ledger fail
/// offline replay from genesis forever (rows are immutable), so the transition proceeds
/// off-ledger, exactly as before ACT-40 (the stated no-backfill boundary), and is counted.
/// This is NOT a fail-open of a ledgered approval: one whose predecessor IS recorded always
/// gets its row or rolls back.
#[tracing::instrument(skip_all, fields(tenant_id = %tenant))]
pub(crate) async fn record_tx(
    tx: &Transaction<'_>,
    tenant: &TenantId,
    id: Uuid,
    transition: Transition,
    at: DateTime<Utc>,
) -> Result<Option<AtomicBatchAppend>> {
    let result = append(tx, tenant, id, transition, at).await;
    match &result {
        Err(e) => {
            // Every refusal surfaces upstream as a 503; this makes a persistent one visible.
            REFUSED.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(event = "approval_ledger_refused", tenant_id = %tenant, approval_id = %id,
                transition = transition.as_str(), error = %e, "approval transition refused: ledger record not written");
        }
        Ok(None) => {
            LEGACY_SKIPPED.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(event = "approval_ledger_legacy_skip", tenant_id = %tenant, approval_id = %id,
                transition = transition.as_str(), "approval opened off-ledger; transition not recorded");
        }
        Ok(Some(_)) => {}
    }
    result
}

async fn append(
    tx: &Transaction<'_>,
    tenant: &TenantId,
    id: Uuid,
    transition: Transition,
    at: DateTime<Utc>,
) -> Result<Option<AtomicBatchAppend>> {
    let r = tx
        .query_one(
            "SELECT args_fp,requester_sub,requester_creator,subject_kind,subject,server_id,rule_id,decided_by,expires_at,grant_expires_at FROM approvals WHERE tenant_id=$1 AND id=$2 AND action_id IS NULL",
            &[tenant.as_uuid(), &id],
        )
        .await?;
    // `audit_appended` is the append-once set for every ledger row; nothing prunes it
    // (migration 0020; no DELETE anywhere in the tree), so absence means never recorded.
    if let Some(before) = predecessor(transition, r.get::<_, Option<DateTime<Utc>>>(9).is_some()) {
        let seen = tx
            .query_opt(
                "SELECT 1 FROM audit_appended WHERE event_id=$1",
                &[&event_id(tenant, id, before)],
            )
            .await?;
        if seen.is_none() {
            return Ok(None);
        }
    }
    let record = build(
        tenant,
        id,
        transition,
        at,
        Row {
            args_fp: r.get(0),
            requester_sub: r.get(1),
            requester_creator: r.get(2),
            subject_kind: r.get(3),
            subject: r.get(4),
            server_id: r.get(5),
            rule_id: r.get(6),
            decided_by: r.get(7),
            expires_at: r.get(8),
            grant_expires_at: r.get(9),
        },
    )?;
    let (event_type, actor, payload) = encode(&record)?;
    ensure!(
        payload.len() <= crate::mcp_policy::settings()?.limits.max_event_bytes,
        "approval record too large"
    );
    // One stable identity per (approval, transition): a replayed append consumes no seq,
    // and `kept` below refuses to let that silently stand in for a new transition.
    let ids = [event_id(tenant, id, transition)];
    let recording = crate::gateway_recording::Recording::parse(
        tenant,
        Some(&ids[0]),
        &event_type,
        &actor,
        &payload,
    )?;
    ensure!(recording.is_none(), "approval record carries a recording");
    let rows = crate::db::audit_chain_state::append_atomic_batch_tx(
        tx,
        tenant,
        crate::audit_format::genesis_prev_hash(tenant),
        Some(&ids),
        1,
        &[None],
        |seq, prev, kept| {
            ensure!(kept == [0], "approval record already appended");
            let hash =
                crate::audit_format::row_hash_v2(&prev, tenant, seq, &event_type, &actor, &payload);
            Ok(vec![crate::db::ledger::AuditLogRow {
                tenant_id: tenant.to_string(),
                seq,
                event_time: at.timestamp_micros(),
                event_type: event_type.clone(),
                actor: actor.clone(),
                payload: payload.clone(),
                prev_hash: hex::encode(prev),
                row_hash: hex::encode(hash),
                rekor_entry_id: None,
                signature: String::new(),
                signing_pubkey: String::new(),
            }])
        },
    )
    .await?
    .context("approval record unavailable")?;
    ensure!(rows.kept == [0], "approval record already appended");
    Ok(Some(rows))
}

/// Copy committed records to the derived store. Fail-OPEN: the canonical rows are durable.
pub(crate) fn forward(
    chain: Option<&std::sync::Arc<crate::audit::AuditChain>>,
    tenant: &TenantId,
    rows: Vec<AtomicBatchAppend>,
) {
    if rows.is_empty() {
        return;
    }
    let Ok(l) = crate::mcp_policy::settings() else {
        // Same signal as a stalled copy; recovery re-derives it from the canonical rows.
        tracelane_shared::degradation::note(
            tracelane_shared::degradation::Degradation::LedgerCopyFailed,
        );
        return;
    };
    let timeout = std::time::Duration::from_secs(l.limits.call_timeout_secs);
    crate::action_control::execution::after_commit_for_tenant(chain, tenant, rows, timeout);
}

#[cfg(test)]
#[path = "ledger_tests.rs"]
mod tests;

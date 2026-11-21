//! Canonical recording identity contracts. Producers remain disabled/unimplemented.
//! A high-water is an observation, never a claim that lower sequences are complete.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use tokio_postgres::Transaction;
use tracelane_shared::TenantId;
use uuid::Uuid;

/// An append failure that retrying can never clear: the message's own content is refused.
/// The audit consumer terminates such a message instead of redelivering it forever (which
/// would stall every other event co-batched for that tenant). Anything else stays transient.
#[derive(Debug, thiserror::Error)]
#[error("permanent audit rejection: {0}")]
pub struct PermanentRejection(pub &'static str);

/// A recording schema this build does not know. Transient on purpose: see `Recording::parse`.
#[derive(Debug, thiserror::Error)]
#[error("unsupported recording version {0}")]
pub struct UnsupportedVersion(pub u32);

/// True when any layer of `err` is a [`PermanentRejection`].
#[must_use]
pub fn is_permanent(err: &anyhow::Error) -> bool {
    // `downcast_ref` finds it as a context layer too (`chain()` yields anyhow's private
    // context wrapper type there, so `is::<_>()` alone misses a `.context(PermanentRejection)`).
    err.downcast_ref::<PermanentRejection>().is_some()
        || err.chain().any(|e| e.is::<PermanentRejection>())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    schema_version: u32,
    event_id: String,
    record_kind: String,
    occurred_at: String,
    emitter: Emitter,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Emitter {
    instance: String,
    epoch: Uuid,
    tenant: Uuid,
    seq: String,
}

/// Validated, tenant-bound identity prepared before a transaction's dedup decision.
#[derive(Clone, Debug)]
pub struct Recording {
    event_id: String,
    instance: String,
    epoch: Uuid,
    seq: i64,
    digest: String,
}

impl Recording {
    /// Legacy payloads have no reserved member. A present invalid member fails CLOSED.
    /// # Errors
    /// Fail-CLOSED: every refusal is a [`PermanentRejection`] (the content cannot change on retry).
    pub(crate) fn parse(
        tenant: &TenantId,
        expected_id: Option<&str>,
        event_type: &str,
        actor: &str,
        payload: &str,
    ) -> Result<Option<Self>> {
        Self::parse_inner(tenant, expected_id, event_type, actor, payload).map_err(|e| {
            // A newer schema is version skew (a producer ahead of this consumer during a
            // deploy), not bad content: it must redeliver until a consumer that knows it runs.
            if e.is::<UnsupportedVersion>() {
                e
            } else {
                e.context(PermanentRejection("invalid gateway recording"))
            }
        })
    }

    fn parse_inner(
        tenant: &TenantId,
        expected_id: Option<&str>,
        event_type: &str,
        actor: &str,
        payload: &str,
    ) -> Result<Option<Self>> {
        // Legacy payloads never carry the reserved member: skip the parse entirely, so a
        // legacy payload that is deep or not JSON is not newly refused (and terminated).
        // Any `\u` escape forces the full parse: a key spelled `\u0067ateway_recording`
        // decodes to the reserved member and must be validated, not waved through as legacy.
        if !payload.contains("gateway_recording") && !payload.contains("\\u") {
            return Ok(None);
        }
        // A payload serde cannot read (not JSON, or nested past its recursion limit) has no
        // member any reader could see (the reconcile check uses the same parser), and was
        // accepted before this slice: it stays legacy rather than being refused.
        let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) else {
            return Ok(None);
        };
        let Some(metadata) = value.get("gateway_recording") else {
            return Ok(None);
        };
        let m: Metadata = serde_json::from_value(metadata.clone())
            .context("invalid gateway recording metadata")?;
        if m.schema_version != 1 {
            return Err(UnsupportedVersion(m.schema_version).into());
        }
        ensure!(
            !m.event_id.trim().is_empty() && expected_id.is_none_or(|id| id == m.event_id),
            "recording event identity mismatch"
        );
        ensure!(
            m.emitter.tenant == *tenant.as_uuid()
                && !m.emitter.epoch.is_nil()
                && !m.emitter.instance.trim().is_empty(),
            "invalid recording emitter namespace"
        );
        chrono::DateTime::parse_from_rfc3339(&m.occurred_at)
            .context("invalid recording occurrence time")?;
        let seq: i64 = m
            .emitter
            .seq
            .parse()
            .context("invalid recording sequence")?;
        ensure!(
            seq >= 0 && seq.to_string() == m.emitter.seq,
            "noncanonical recording sequence"
        );
        let matching_kind = match m.record_kind.as_str() {
            "epoch_start" => seq == 0 && event_type == "gateway.epoch_start",
            "intent" => seq > 0 && (event_type.ends_with(".request") || event_type == "mcp.invoke"),
            "completion" => seq > 0 && event_type == "gateway.call_completed",
            "heartbeat" => seq > 0 && event_type == "gateway.heartbeat",
            "quiescent" => seq > 0 && event_type == "gateway.quiescent",
            "epoch_close" => seq > 0 && event_type == "gateway.epoch_close",
            _ => false,
        };
        ensure!(
            matching_kind,
            "recording kind does not match event type or sequence"
        );
        let bytes = serde_json::to_vec(&(
            "tracelane.recording-identity.v1",
            tenant.to_string(),
            event_type,
            actor,
            payload,
        ))?;
        Ok(Some(Self {
            event_id: m.event_id,
            instance: m.emitter.instance,
            epoch: m.emitter.epoch,
            seq,
            digest: hex::encode(ring::digest::digest(&ring::digest::SHA256, &bytes).as_ref()),
        }))
    }
}

/// Called after audit_appended reserves IDs and while the tenant head is locked.
/// Exact duplicates are no-ops; changed identity/sequence reuse fails CLOSED.
#[tracing::instrument(skip_all)]
pub(crate) async fn reserve_tx(
    tx: &Transaction<'_>,
    tenant: &TenantId,
    ids: &[String],
    recordings: &[Option<Recording>],
    kept: &[usize],
) -> Result<()> {
    // IDs are globally unique in the existing durable dedup table. This lookup checks
    // their namespace without exposing any other tenant's contents to a caller.
    let stored = tx.query(
        "SELECT dedup_id,tenant_id,event_digest,ledger_seq FROM gateway_recording_events WHERE dedup_id=ANY($1) AND tenant_id=$2",
        &[&ids, tenant.as_uuid()],
    ).await?;
    let mut existing = std::collections::HashMap::new();
    for row in stored {
        existing.insert(
            row.get::<_, String>(0),
            (
                row.get::<_, Uuid>(1),
                row.get::<_, String>(2),
                row.get::<_, Option<i64>>(3),
            ),
        );
    }
    // Kept contains only the first occurrence of an ID, but every input must be
    // compared: a conflicting duplicate later in this same batch is not a retry.
    for (index, (id, recording)) in ids.iter().zip(recordings).enumerate() {
        if let Some((bound_tenant, digest, _)) = existing.get(id) {
            if !recording
                .as_ref()
                .is_some_and(|r| bound_tenant == tenant.as_uuid() && r.digest == *digest)
            {
                return Err(PermanentRejection("recording identity conflict").into());
            }
            continue;
        }
        let Some(r) = recording else { continue };
        if kept.binary_search(&index).is_err() {
            return Err(
                PermanentRejection("recording identity conflicts with legacy dedup").into(),
            );
        }
        let inserted = tx.execute(
            "INSERT INTO gateway_recording_events (dedup_id,tenant_id,event_id,instance_id,boot_epoch,emitter_seq,event_digest) VALUES ($1,$2,$3,$4,$5,$6,$7)",
            &[id,tenant.as_uuid(),&r.event_id,&r.instance,&r.epoch,&r.seq,&r.digest],
        ).await;
        match inserted {
            Ok(_) => {}
            // A unique violation is a reused event id or emitter sequence: permanent.
            Err(e) if e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) => {
                return Err(anyhow::Error::new(e)
                    .context(PermanentRejection("recording sequence identity conflict")));
            }
            Err(e) => return Err(anyhow::Error::new(e).context("recording reservation insert")),
        }
        existing.insert(id.clone(), (*tenant.as_uuid(), r.digest.clone(), None));
    }
    Ok(())
}

/// Bind newly committed candidates to canonical positions and update observed high-waters.
/// Caller owns the outer transaction; errors fail CLOSED and require rollback.
#[tracing::instrument(skip_all)]
pub(crate) async fn project_tx(
    tx: &Transaction<'_>,
    tenant: &TenantId,
    ids: Option<&[String]>,
    recordings: &[Option<Recording>],
    kept: &[usize],
    rows: &[crate::db::ledger::AuditLogRow],
) -> Result<()> {
    for (index, row) in kept.iter().zip(rows) {
        let expected = &recordings[*index];
        let actual = Recording::parse(
            tenant,
            expected.as_ref().map(|r| r.event_id.as_str()),
            &row.event_type,
            &row.actor,
            &row.payload,
        )?;
        // A builder that changes identity is a code regression, not bad content: it fails the
        // transaction and redelivers (a fixed build appends it), never terminates the event.
        ensure!(
            actual.as_ref().map(|r| &r.digest) == expected.as_ref().map(|r| &r.digest),
            "canonical builder changed recording identity"
        );
        let Some(r) = expected else { continue };
        let id = &ids.context("recording requires stable dedup identity")?[*index];
        let seq = i64::try_from(row.seq)?;
        let updated = tx.execute(
            "UPDATE gateway_recording_events SET ledger_seq=$3 WHERE dedup_id=$1 AND tenant_id=$2 AND ledger_seq IS NULL",
            &[id,tenant.as_uuid(),&seq],
        ).await?;
        ensure!(updated == 1, "recording projection lacks reserved identity");
        tx.execute(
            "INSERT INTO gateway_emitter_heads (tenant_id,instance_id,boot_epoch,highest_emitter_seq,last_ledger_seq,recorded_events) VALUES ($1,$2,$3,$4,$5,1) ON CONFLICT (tenant_id,instance_id,boot_epoch) DO UPDATE SET highest_emitter_seq=GREATEST(gateway_emitter_heads.highest_emitter_seq,EXCLUDED.highest_emitter_seq),last_ledger_seq=GREATEST(gateway_emitter_heads.last_ledger_seq,EXCLUDED.last_ledger_seq),recorded_events=gateway_emitter_heads.recorded_events+1",
            &[tenant.as_uuid(),&r.instance,&r.epoch,&r.seq,&seq],
        ).await?;
    }
    Ok(())
}

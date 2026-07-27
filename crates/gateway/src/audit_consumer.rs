//! ADR-069: the async audit head-writer consumer.
//!
//! The gateway hot path publishes audit events to the durable `TRACELANE_AUDIT`
//! JetStream stream with an **acked** publish (durable capture before dispatch,
//! [`crate::audit::AuditChain::publish`]). This background task is the **sole
//! head-writer**: it pulls events (per-tenant ordered by subject) and runs the
//! existing serialized head-advance ([`AuditChain::append_from_wire`] →
//! `append_pg_serialized` → `append_atomic`: seq assignment under the per-tenant
//! `SELECT … FOR UPDATE`, CH row, PG head, COMMIT), acking the JetStream message
//! ONLY after the append COMMITs (ack-after-write).
//!
//! Crash safety: a crash between COMMIT and ack → JetStream redelivers → the
//! `audit_appended` dedup (migration 0020, threaded via `event_id`) makes the
//! replay a no-op: **no gap, no duplicate seq**. Retention is `WorkQueue` (a
//! message lives until acked, so consumer downtime never drops an event), capped
//! by a 30-day safety `max_age`.
//!
//! Mirrors the proven span path (`ingest::nats_consumer` + `SpanEnvelope`
//! ack-after-write, the FT-03 zero-loss guarantee).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use futures::StreamExt as _;
use uuid::Uuid;

use crate::audit::{AuditChain, AuditEventWire};
use tracelane_shared::TenantId;

const STREAM: &str = "TRACELANE_AUDIT";
const CONSUMER: &str = "tracelane-audit-head-writer";

/// The durable audit stream config. `WorkQueue` retention deletes a message once
/// the (single) head-writer acks it, so an un-acked message survives consumer
/// downtime instead of being aged out; the 30-day `max_age` is the absolute
/// safety cap. `duplicate_window` dedups double-publishes by `Nats-Msg-Id`
/// (= `event_id`) — the `audit_appended` table is the durable backstop beyond it.
fn audit_stream_config() -> async_nats::jetstream::stream::Config {
    async_nats::jetstream::stream::Config {
        name: STREAM.into(),
        subjects: vec!["tracelane.audit.>".into()],
        retention: async_nats::jetstream::stream::RetentionPolicy::WorkQueue,
        max_age: Duration::from_secs(30 * 24 * 60 * 60),
        duplicate_window: Duration::from_secs(120),
        ..Default::default()
    }
}

/// Create (or bind) the audit stream. Called ONCE at startup, BEFORE the server
/// serves, so the first `publish` has a stream to land in (a publish to a subject
/// no stream captures would error).
pub async fn ensure_audit_stream(js: &async_nats::jetstream::Context) -> Result<()> {
    js.get_or_create_stream(audit_stream_config())
        .await
        .context("get_or_create TRACELANE_AUDIT stream")?;
    Ok(())
}

/// Spawn the long-lived sole-head-writer consumer (reconnects on drop; the 30s
/// `ack_wait` bounds redelivery latency during a gap).
pub fn spawn(audit_chain: Arc<AuditChain>, client: async_nats::Client) {
    tokio::spawn(async move {
        loop {
            if let Err(err) = run_once(&audit_chain, &client).await {
                tracing::warn!(error = %err, "audit head-writer consumer error; reconnecting");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

async fn run_once(audit_chain: &Arc<AuditChain>, client: &async_nats::Client) -> Result<()> {
    let js = async_nats::jetstream::new(client.clone());
    // Idempotent — self-heals if the stream was reset while we were disconnected.
    let stream = js
        .get_or_create_stream(audit_stream_config())
        .await
        .context("bind TRACELANE_AUDIT stream")?;
    let consumer = stream
        .get_or_create_consumer(
            CONSUMER,
            async_nats::jetstream::consumer::pull::Config {
                durable_name: Some(CONSUMER.into()),
                ack_wait: Duration::from_secs(30),
                // No max_deliver cap: a valid audit event MUST eventually land
                // (retry until PG/CH recover). Poison messages are Term'd below,
                // so they never rely on a delivery cap to stop redelivering.
                ..Default::default()
            },
        )
        .await
        .context("get_or_create audit head-writer consumer")?;
    let mut messages = consumer
        .messages()
        .await
        .context("subscribe audit head-writer consumer")?;
    tracing::info!("audit head-writer consumer active on tracelane.audit.>");

    while let Some(msg) = messages.next().await {
        let msg = match msg {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, "audit JetStream message error");
                continue;
            }
        };

        // Trust the ACL-gated subject tenant. A subject that is not
        // `tracelane.audit.<uuid>` is malformed/hostile — Term it (never append).
        let Some(subj_tenant) = parse_tenant_from_audit_subject(&msg.subject) else {
            tracing::warn!(subject = %msg.subject, "audit msg subject not tracelane.audit.<uuid> — terminating");
            msg.ack_with(async_nats::jetstream::AckKind::Term)
                .await
                .ok();
            continue;
        };

        let wire = match serde_json::from_slice::<AuditEventWire>(&msg.payload) {
            Ok(w) => w,
            Err(e) => {
                // Poison (undeserializable) — Term so it doesn't redeliver forever.
                tracing::warn!(error = %e, "audit wire deserialize failed — terminating message");
                msg.ack_with(async_nats::jetstream::AckKind::Term)
                    .await
                    .ok();
                continue;
            }
        };

        // Integrity: on the audit path a subject/body tenant mismatch is a bug or
        // an attack — Term it (do NOT append a mislabeled tamper-evident event).
        if TenantId::from_jwt_claim(wire.tenant_id) != subj_tenant {
            tracing::error!(
                subject_tenant = %subj_tenant,
                body_tenant = %wire.tenant_id,
                "audit wire tenant != subject tenant — terminating (integrity)"
            );
            msg.ack_with(async_nats::jetstream::AckKind::Term)
                .await
                .ok();
            continue;
        }

        match audit_chain.append_from_wire(&wire).await {
            Ok(()) => {
                // Appended (or idempotently skipped) AND committed — ack now.
                // A failed ack leaves the message for redelivery; the replay is a
                // no-op via `audit_appended` (0020), so it is safe.
                if let Err(e) = msg.ack().await {
                    tracing::warn!(error = %e, "audit ack failed after commit; will redeliver (idempotent)");
                }
            }
            Err(e) => {
                // PG/CH outage — do NOT ack; JetStream redelivers after ack_wait
                // (no audit event lost). No Nak: the natural ack_wait backoff
                // avoids a hot retry spin during a sustained outage.
                tracing::error!(error = %e, "audit append failed — leaving unacked for redelivery");
            }
        }
    }
    Ok(())
}

/// `tracelane.audit.<uuid>` → `TenantId`; `None` for any other shape (mirrors the
/// span consumer's subject guard). No further dot segments allowed.
fn parse_tenant_from_audit_subject(subject: &str) -> Option<TenantId> {
    let rest = subject.strip_prefix("tracelane.audit.")?;
    if rest.contains('.') {
        return None;
    }
    Some(TenantId::from_jwt_claim(Uuid::parse_str(rest).ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_audit_subject() {
        let t =
            parse_tenant_from_audit_subject("tracelane.audit.00000000-0000-0000-0000-000000000001")
                .expect("should parse");
        assert_eq!(t.to_string(), "00000000-0000-0000-0000-000000000001");
    }

    #[test]
    fn rejects_non_audit_or_malformed_subject() {
        assert!(
            parse_tenant_from_audit_subject("tracelane.spans.00000000-0000-0000-0000-000000000001")
                .is_none()
        );
        assert!(parse_tenant_from_audit_subject("tracelane.audit.notauuid").is_none());
        assert!(parse_tenant_from_audit_subject("tracelane.audit.").is_none());
        assert!(
            parse_tenant_from_audit_subject(
                "tracelane.audit.00000000-0000-0000-0000-000000000001.x"
            )
            .is_none()
        );
    }
}

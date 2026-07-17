//! NATS JetStream consumer for span ingestion.
//!
//! Subscribes to `tracelane.spans.>` and deserializes JSON-encoded
//! `TracelaneSpan` messages published by the gateway's OTLP emit stub.
//!
//! JetStream provides durable at-least-once delivery with per-consumer
//! ack tracking. Unacked messages are redelivered after `ack_wait = 30s`.
//! The consumer group name is `tracelane-ingest` — do not change without
//! migrating the JetStream consumer definition.

use anyhow::{Context as _, Result};
use futures::StreamExt as _;
use tokio::sync::mpsc;
use tracing::instrument;
use uuid::Uuid;

use tracelane_shared::{TenantId, TracelaneSpan};

/// Start the NATS JetStream consumer.
///
/// Connects to NATS, creates (or binds to) the `TRACELANE_SPANS` stream,
/// and feeds deserialized spans into `span_tx`.
///
/// `single_tenant` — when `Some`, single-tenant self-host mode is active
/// (ADR-067): EVERY span is stamped with this one operator-configured tenant,
/// overriding whatever the NATS subject / body asserted. There is no second
/// tenant to spoof, so the subject-derived tenant is irrelevant. When `None`
/// (the hosted path) the trusted tenant comes from the NATS subject exactly as
/// before.
///
/// # Errors
/// Returns `Err` if NATS connection fails or the JetStream stream is
/// misconfigured (subject mismatch, wrong retention policy, etc.).
#[instrument(skip(span_tx, single_tenant), fields(nats_url = %nats_url))]
pub async fn run(
    nats_url: String,
    span_tx: mpsc::Sender<crate::span_envelope::SpanEnvelope>,
    single_tenant: Option<TenantId>,
) -> Result<()> {
    let client = async_nats::connect(&nats_url)
        .await
        .context("failed to connect to NATS")?;

    let jetstream = async_nats::jetstream::new(client);

    // Ensure the stream exists. In production this is created by the Helm chart.
    let stream = jetstream
        .get_or_create_stream(async_nats::jetstream::stream::Config {
            name: "TRACELANE_SPANS".into(),
            subjects: vec!["tracelane.spans.>".into()],
            // Limits-based retention: 90-day hot window mirrors ClickHouse TTL
            max_age: std::time::Duration::from_secs(90 * 24 * 60 * 60),
            ..Default::default()
        })
        .await
        .context("failed to get or create TRACELANE_SPANS JetStream stream")?;

    let consumer = stream
        .get_or_create_consumer(
            "tracelane-ingest",
            async_nats::jetstream::consumer::pull::Config {
                durable_name: Some("tracelane-ingest".into()),
                ack_wait: std::time::Duration::from_secs(30),
                max_deliver: 5,
                ..Default::default()
            },
        )
        .await
        .context("failed to create NATS JetStream consumer")?;

    let mut messages = consumer
        .messages()
        .await
        .context("failed to subscribe to JetStream messages")?;

    tracing::info!("NATS JetStream consumer started on tracelane.spans.>");

    while let Some(msg) = messages.next().await {
        let msg = match msg {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, "JetStream message error");
                continue;
            }
        };

        // Resolve the trusted tenant for this message (see
        // [`resolve_trusted_tenant`]). Single-tenant self-host stamps the one
        // operator-configured tenant; hosted derives it from the NATS subject.
        // A `None` here (hosted only) means the subject is not tenant-prefixed
        // — misconfigured or hostile, so drop the message.
        let trusted_tenant = match resolve_trusted_tenant(single_tenant.as_ref(), &msg.subject) {
            Some(t) => t,
            None => {
                tracing::warn!(
                    subject = %msg.subject,
                    "rejecting NATS span: subject does not carry a UUID tenant prefix"
                );
                msg.ack_with(async_nats::jetstream::AckKind::Term)
                    .await
                    .ok();
                continue;
            }
        };

        match serde_json::from_slice::<TracelaneSpan>(&msg.payload) {
            Ok(mut span) => {
                // Overwrite the body-asserted tenant_id with the subject-
                // derived one. The body might claim anything — we believe
                // the subject (which is gated by NATS ACL upstream).
                if span.tenant_id != trusted_tenant {
                    tracing::warn!(
                        subject_tenant = %trusted_tenant,
                        body_tenant = %span.tenant_id,
                        "NATS span body tenant_id != subject tenant_id; rebinding to subject"
                    );
                    span.tenant_id = trusted_tenant;
                }
                // Ack-after-write (#81): hand the message to the ClickHouse
                // writer, which acks it ONLY after the row is durably written.
                // Do NOT ack here — a write failure must leave the message
                // unacked so JetStream redelivers it (no span lost).
                if span_tx
                    .send(crate::span_envelope::SpanEnvelope::nats(span, msg))
                    .await
                    .is_err()
                {
                    tracing::warn!("span channel closed; stopping NATS consumer");
                    return Ok(());
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to deserialize span; nacking");
                msg.ack_with(async_nats::jetstream::AckKind::Nak(None))
                    .await
                    .ok();
            }
        }
    }

    Ok(())
}

/// Resolve the trusted tenant for an incoming NATS span.
///
/// - `single_tenant = Some(t)` (single-tenant self-host, ADR-067): always
///   returns that one tenant — the subject is NOT consulted. Every span is
///   stamped with the fixed operator-configured tenant, so a mislabeled subject
///   cannot smuggle in a different tenant (there is none to smuggle to).
/// - `single_tenant = None` (hosted): derives the tenant from the subject shape
///   `tracelane.spans.<uuid>` via [`parse_tenant_from_subject`]; `None` if the
///   subject is not tenant-prefixed (the caller then drops the message).
fn resolve_trusted_tenant(single_tenant: Option<&TenantId>, subject: &str) -> Option<TenantId> {
    match single_tenant {
        Some(t) => Some(t.clone()),
        None => parse_tenant_from_subject(subject),
    }
}

/// Extract the trusted `TenantId` from a NATS subject of the form
/// `tracelane.spans.<uuid>` (matching the gateway's publish format in
/// `otlp_emit::publish_span`). Returns `None` for any other shape so
/// the consumer drops the message. The UUID must be syntactically valid
/// — there's no cross-check against a tenants table here, only a shape
/// guard. Real authorization is the NATS-level ACL the operator
/// configures (the runbook calls this out).
fn parse_tenant_from_subject(subject: &str) -> Option<TenantId> {
    let rest = subject.strip_prefix("tracelane.spans.")?;
    // Must be exactly the UUID, no further dot segments.
    if rest.contains('.') {
        return None;
    }
    let uuid = Uuid::parse_str(rest).ok()?;
    Some(TenantId::from_jwt_claim(uuid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_subject() {
        let s = "tracelane.spans.00000000-0000-0000-0000-000000000001";
        let t = parse_tenant_from_subject(s).expect("should parse");
        assert_eq!(t.to_string(), "00000000-0000-0000-0000-000000000001");
    }

    #[test]
    fn rejects_missing_prefix() {
        assert!(parse_tenant_from_subject("not.tracelane.spans.uuid").is_none());
        assert!(parse_tenant_from_subject("tracelane.audit.uuid").is_none());
    }

    #[test]
    fn rejects_non_uuid_segment() {
        assert!(parse_tenant_from_subject("tracelane.spans.attacker").is_none());
        assert!(parse_tenant_from_subject("tracelane.spans.").is_none());
    }

    #[test]
    fn rejects_extra_subject_segments() {
        // A subject like `tracelane.spans.<uuid>.attacker_payload`
        // must be rejected — defense against subject-smuggling.
        let s = "tracelane.spans.00000000-0000-0000-0000-000000000001.extra";
        assert!(parse_tenant_from_subject(s).is_none());
    }

    // ── ADR-067 single-tenant self-host override ────────────────────────────

    fn single(uuid: &str) -> TenantId {
        TenantId::from_self_host_config(Uuid::parse_str(uuid).unwrap())
    }

    #[test]
    fn self_host_stamps_only_the_single_tenant_ignoring_subject() {
        // Even if the subject names a DIFFERENT tenant, single-tenant mode stamps
        // the one configured tenant — no cross-tenant smuggling is possible.
        let fixed = single("00000000-0000-0000-0000-000000000001");
        let subject = "tracelane.spans.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        let resolved = resolve_trusted_tenant(Some(&fixed), subject).expect("always Some");
        assert_eq!(
            resolved, fixed,
            "self-host must stamp the fixed tenant, not the subject's"
        );
    }

    #[test]
    fn self_host_stamps_single_tenant_even_for_malformed_subject() {
        // A subject that hosted mode would reject still yields the fixed tenant
        // under single-tenant self-host (the subject is not consulted at all).
        let fixed = single("00000000-0000-0000-0000-000000000001");
        let resolved = resolve_trusted_tenant(Some(&fixed), "garbage.subject");
        assert_eq!(resolved, Some(fixed));
    }

    #[test]
    fn hosted_still_derives_tenant_from_subject() {
        // None (hosted) is unchanged: subject-derived tenant, reject on bad shape.
        let subject = "tracelane.spans.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        assert_eq!(
            resolve_trusted_tenant(None, subject).map(|t| t.to_string()),
            Some("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".to_string())
        );
        assert!(resolve_trusted_tenant(None, "garbage.subject").is_none());
    }
}

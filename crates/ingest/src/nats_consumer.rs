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

/// Byte ceiling on the spans delivery stream — 4 GiB.
///
/// SRE register #50 (2026-09-04, fixed 2026-09-05): the stream was byte-UNBOUNDED
/// (`max_bytes: -1` on prod, created 2026-06-07 before any bound existed in source) on the
/// one un-replicated volume that also holds ClickHouse and the audit ledger. Its `max_age`
/// bounds TIME, not bytes: at 1,000 spans/s of ~880 B each even a 3-day window is ~230 GB, so
/// only a byte cap turns an ingest stall into a bounded loss instead of ENOSPC that takes
/// ClickHouse and the ledger down together.
///
/// 4 GiB is ~4.9 M spans at the measured prod size — at 1,000 spans/s that is ~80 minutes
/// of ingest outage before the OLDEST un-consumed span is dropped (`DiscardPolicy::Old`,
/// the fail-OPEN posture capture already has: the gateway counts `spans_dropped`, it never
/// blocks a chat on it). Under normal operation the consumer acks after every ClickHouse
/// flush and the stream sits near empty (prod: 21 MB), so this never binds.
pub const SPANS_STREAM_MAX_BYTES: i64 = 4 << 30;

/// The spans stream config — the source of truth `jetstream_limits::ensure_stream`
/// reconciles the live stream to at every ingest boot.
pub fn spans_stream_config() -> async_nats::jetstream::stream::Config {
    async_nats::jetstream::stream::Config {
        name: "TRACELANE_SPANS".into(),
        subjects: vec!["tracelane.spans.>".into()],
        // Limits-based retention: a 3-DAY replay window — down from 90 days on
        // 2026-09-12, for a reason the 90-day comment could not have known.
        //
        // JetStream is a DELIVERY BUFFER, not a second store, and a replay
        // window longer than the shortest retention window makes it one: on
        // 2026-09-12 the ingest's durable was recreated after a grant outage,
        // the default `DeliverPolicy::All` replayed every message still in the
        // stream, and 25k spans the retention sweep had DELETED that hour came
        // back into ClickHouse (and re-summed 66 traces' span counts through
        // the MV). The privacy promise is only as good as the shortest buffer
        // holding the data. Three days covers any consumer outage the 4 GiB
        // bound would survive anyway, and is under Free's 7-day window, so a
        // replay can never resurrect what a sweep removed. `ensure_stream`
        // applies this to prod's EXISTING stream on the next ingest boot
        // (`limits_drift` compares `max_age`), which purges the backlog older
        // than three days at that moment — intended.
        max_age: std::time::Duration::from_secs(3 * 24 * 60 * 60),
        max_bytes: SPANS_STREAM_MAX_BYTES,
        discard: async_nats::jetstream::stream::DiscardPolicy::Old,
        ..Default::default()
    }
}

/// The durable pull consumer config. `jetstream_limits::ensure_pull_consumer` reconciles
/// the EXISTING durable on the server to this — a plain get-or-create returned prod's
/// pre-#29 consumer (`max_ack_pending: 1000`) untouched.
pub fn ingest_consumer_config(batch_size: usize) -> async_nats::jetstream::consumer::pull::Config {
    async_nats::jetstream::consumer::pull::Config {
        durable_name: Some("tracelane-ingest".into()),
        ack_wait: std::time::Duration::from_secs(30),
        max_deliver: 5,
        // SRE audit finding 29, 2026-09-04. This was the NATS server default
        // (1000) while INGEST_BATCH_SIZE is 2000, and the two interact: the
        // writer acks only AFTER the ClickHouse flush (`clickhouse_writer.rs`,
        // "Do NOT ack here"), so UNACKED-IN-FLIGHT is the batch's entire
        // supply. Capped below the batch size, the NATS path could never fill
        // one — every flush was cut short by the 200 ms timeout instead of by
        // being full. Not a stall (the timeout always broke the loop), but it
        // silently halved the effective batching the writer was tuned for.
        //
        // Tied to the batch size STRUCTURALLY rather than by a comment, so the
        // next change to INGEST_BATCH_SIZE cannot re-open the gap. Headroom of
        // 2x leaves room for a second batch to accumulate while one flushes.
        max_ack_pending: i64::try_from(batch_size.saturating_mul(2)).unwrap_or(i64::MAX),
        ..Default::default()
    }
}

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
// B-383 (b): the URL may carry a credential — the span field is the credential-free form.
#[instrument(
    skip(span_tx, single_tenant, shutdown),
    fields(nats_url = %tracelane_shared::nats_connect::NatsConnect::split(&nats_url).url)
)]
pub async fn run(
    nats_url: String,
    span_tx: mpsc::Sender<crate::span_envelope::SpanEnvelope>,
    single_tenant: Option<TenantId>,
    batch_size: usize,
    mut shutdown: crate::shutdown::Signal,
) -> Result<()> {
    // B-383 (b): the credential is lifted OUT of the URL (async-nats does not
    // honour `user:pass@` — `tracelane_shared::nats_connect` says why) and the
    // URL that is dialled and logged is the credential-free one.
    let nc = tracelane_shared::nats_connect::NatsConnect::from_url(&nats_url);
    let client = nc
        .options()
        .connect(&nc.url)
        .await
        .with_context(|| format!("failed to connect to NATS at {}", nc.url))?;

    let jetstream = async_nats::jetstream::new(client);

    // Create-or-reconcile the stream and the durable consumer. NOT a plain
    // get-or-create: that binds to an EXISTING object without re-applying config, so
    // neither the byte bound below nor the `max_ack_pending` fix would ever have reached
    // prod's stream (created 2026-06-07) or its consumer — see
    // `tracelane_shared::jetstream_limits`.
    let stream =
        tracelane_shared::jetstream_limits::ensure_stream(&jetstream, spans_stream_config())
            .await
            .context("failed to ensure TRACELANE_SPANS JetStream stream")?;

    let consumer = tracelane_shared::jetstream_limits::ensure_pull_consumer(
        &stream,
        ingest_consumer_config(batch_size),
    )
    .await
    .context("failed to ensure NATS JetStream consumer")?;

    let mut messages = consumer
        .messages()
        .await
        .context("failed to subscribe to JetStream messages")?;

    tracing::info!("NATS JetStream consumer started on tracelane.spans.>");

    loop {
        // B-377: race the next message against the shutdown signal. On shutdown
        // this returns, dropping `span_tx`, which is what lets the ClickHouse
        // writer see a closed channel and flush-then-ack its last batch. A
        // message pulled but not yet handed over is simply not acked — JetStream
        // redelivers it to the next process, so nothing is lost here.
        let msg = tokio::select! {
            next = messages.next() => match next {
                Some(m) => m,
                None => break,
            },
            () = shutdown.wait() => {
                tracing::info!("shutdown: NATS consumer stopped pulling; releasing the span channel");
                return Ok(());
            }
        };
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

#[cfg(test)]
mod stream_limits_tests {
    use super::*;
    use async_nats::jetstream::stream::DiscardPolicy;

    #[test]
    fn spans_stream_is_byte_bounded_and_fails_open_at_the_ceiling() {
        let cfg = spans_stream_config();
        assert_eq!(cfg.max_bytes, 4 << 30);
        assert!(
            cfg.max_bytes > 0,
            "an unbounded spans stream is the SRE #50 defect"
        );
        // Capture is fail-OPEN: the oldest un-consumed span goes, the publish never fails.
        assert_eq!(cfg.discard, DiscardPolicy::Old);
        // The replay window must stay UNDER the shortest retention window (Free,
        // 7 days) — a longer one let a durable recreate resurrect swept rows
        // (2026-09-12).
        assert_eq!(
            cfg.max_age,
            std::time::Duration::from_secs(3 * 24 * 60 * 60)
        );
        assert!(cfg.max_age < std::time::Duration::from_secs(7 * 24 * 60 * 60));
    }

    #[test]
    fn consumer_max_ack_pending_tracks_batch_size() {
        assert_eq!(ingest_consumer_config(2000).max_ack_pending, 4000);
        assert_eq!(ingest_consumer_config(1).max_ack_pending, 2);
        assert_eq!(
            ingest_consumer_config(2000).durable_name.as_deref(),
            Some("tracelane-ingest")
        );
    }

    /// B-383 (b): the `ingest` NATS user can do EXACTLY the ingest's job against a
    /// server running the prod `nats.conf` — ensure its stream and durable, pull a
    /// span, ack it — and nothing more: it cannot publish into the ledger's subject
    /// and cannot read the audit stream. Driven through the same helpers `run`
    /// calls, because the permission list is a list of the JetStream API subjects
    /// those helpers emit. Run by `scripts/ci/check-nats-auth.sh`.
    #[tokio::test]
    #[ignore = "needs NATS_TEST_URL_{INGEST,OPS} — run scripts/ci/check-nats-auth.sh"]
    async fn b383_ingest_nats_user_can_do_exactly_its_job() {
        use futures::StreamExt as _;
        let Ok(url) = std::env::var("NATS_TEST_URL_INGEST") else {
            panic!("NATS_TEST_URL_INGEST not set — this test cannot run, which is not a pass");
        };
        let ops_url = std::env::var("NATS_TEST_URL_OPS").expect("NATS_TEST_URL_OPS");
        let nc = tracelane_shared::nats_connect::NatsConnect::from_url(&url);
        let client = nc
            .options()
            .connect(&nc.url)
            .await
            .expect("ingest connects");
        let js = async_nats::jetstream::new(client.clone());
        let stream = tracelane_shared::jetstream_limits::ensure_stream(&js, spans_stream_config())
            .await
            .expect("ingest ensures TRACELANE_SPANS");
        let consumer = tracelane_shared::jetstream_limits::ensure_pull_consumer(
            &stream,
            ingest_consumer_config(2000),
        )
        .await
        .expect("ingest ensures its durable");
        // A span arrives from the gateway; ops stands in for it here.
        let ops_nc = tracelane_shared::nats_connect::NatsConnect::from_url(&ops_url);
        let ops = async_nats::jetstream::new(
            ops_nc
                .options()
                .connect(&ops_nc.url)
                .await
                .expect("ops connect"),
        );
        let tenant = uuid::Uuid::new_v4();
        ops.publish(format!("tracelane.spans.{tenant}"), "s".into())
            .await
            .expect("sent")
            .await
            .expect("acked");
        let mut messages = consumer.messages().await.expect("subscribe");
        let msg = tokio::time::timeout(std::time::Duration::from_secs(5), messages.next())
            .await
            .expect("a message within 5 s")
            .expect("stream open")
            .expect("message");
        assert_eq!(msg.subject.as_str(), format!("tracelane.spans.{tenant}"));
        msg.ack().await.expect("ack after write");
        // And NOT. A publish the server refuses gets no responder — the ack future
        // errs; a stream it may not see reads as absent.
        let mut ops_audit = ops
            .get_or_create_stream(async_nats::jetstream::stream::Config {
                name: "TRACELANE_AUDIT".into(),
                subjects: vec!["tracelane.audit.>".into()],
                ..Default::default()
            })
            .await
            .expect("ops creates TRACELANE_AUDIT");
        let forged = js
            .publish(format!("tracelane.audit.{tenant}"), "forged".into())
            .await;
        let landed = match forged {
            Ok(ack) => ack.await.is_ok(),
            Err(_) => false,
        };
        assert!(
            !landed,
            "the ingest user published into the LEDGER's subject"
        );
        assert_eq!(
            ops_audit.info().await.expect("info").state.messages,
            0,
            "a forged audit event reached TRACELANE_AUDIT"
        );
        assert!(
            js.get_stream("TRACELANE_AUDIT").await.is_err(),
            "ingest read the audit stream"
        );
        assert!(
            js.delete_stream("TRACELANE_SPANS").await.is_err(),
            "ingest deleted its stream"
        );
        let _ = ops.delete_stream("TRACELANE_SPANS").await;
        let _ = ops.delete_stream("TRACELANE_AUDIT").await;
    }
}

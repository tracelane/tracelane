//! ADR-069: the async audit head-writer consumer.
//!
//! The gateway hot path publishes audit events to the durable `TRACELANE_AUDIT`
//! JetStream stream with an **acked** publish (durable capture before dispatch,
//! [`crate::audit::AuditChain::publish`]). This background task is the **sole
//! head-writer**: it pulls events (per-tenant ordered by subject) and runs the
//! existing serialized head-advance ([`AuditChain::append_from_wire`] →
//! `append_pg_batch` → `append_atomic_batch`: seq assignment under the per-tenant
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

/// Byte ceiling on the audit stream — 1 GiB.
///
/// SRE register #50 (2026-09-04, fixed 2026-09-05): every JetStream stream on tl-node-1
/// was byte-UNBOUNDED (`max_bytes: -1`, read from `jsz`), on the one un-replicated volume
/// that also holds ClickHouse and the ledger. The audit stream is a WORK QUEUE that drains
/// to zero on every ack (prod: `messages: 0`), so this bound binds only during a
/// head-writer outage — 1 GiB is roughly a million backlogged events, an outage that is
/// already an incident. `DiscardPolicy::New` at the ceiling FAILS CLOSED: the publish is
/// refused, which `server.rs` already answers with `503 audit_unavailable`. Never `Old`,
/// which would silently drop the oldest un-written ledger event to make room.
///
/// Applied to the EXISTING prod stream by `jetstream_limits::ensure_stream`, not by this
/// literal alone — a plain get-or-create never re-reads config (see that module).
pub const AUDIT_STREAM_MAX_BYTES: i64 = 1 << 30;

/// The durable audit stream config. `WorkQueue` retention deletes a message once
/// the (single) head-writer acks it, so an un-acked message survives consumer
/// downtime instead of being aged out; the 30-day `max_age` is the absolute
/// safety cap. `duplicate_window` dedups double-publishes by `Nats-Msg-Id`
/// (= `event_id`) — the `audit_appended` table is the durable backstop beyond it.
pub fn audit_stream_config() -> async_nats::jetstream::stream::Config {
    async_nats::jetstream::stream::Config {
        name: STREAM.into(),
        subjects: vec!["tracelane.audit.>".into()],
        retention: async_nats::jetstream::stream::RetentionPolicy::WorkQueue,
        max_age: Duration::from_secs(30 * 24 * 60 * 60),
        max_bytes: AUDIT_STREAM_MAX_BYTES,
        discard: async_nats::jetstream::stream::DiscardPolicy::New,
        duplicate_window: Duration::from_secs(120),
        ..Default::default()
    }
}

/// Create (or bind) the audit stream. Called ONCE at startup, BEFORE the server
/// serves, so the first `publish` has a stream to land in (a publish to a subject
/// no stream captures would error).
pub async fn ensure_audit_stream(js: &async_nats::jetstream::Context) -> Result<()> {
    tracelane_shared::jetstream_limits::ensure_stream(js, audit_stream_config())
        .await
        .context("ensure TRACELANE_AUDIT stream")?;
    Ok(())
}

/// B-378: how many tenant-affine shard workers run the head-advance in
/// parallel. The per-tenant `FOR UPDATE` row lock is what makes cross-shard
/// parallelism safe; tenant affinity (`shard_for`) is what keeps one tenant's
/// events in arrival order. A constant rather than an env knob: nothing has
/// measured a reason to tune it per deployment yet, and an unmeasured knob is
/// a guess with a name.
pub(crate) const HEAD_WRITER_SHARDS: usize = 8;
/// Bounded queue per shard. A full queue makes the dispatcher `await`, which
/// stops it pulling; JetStream holds the rest (the 1 GiB stream bound is the
/// only place a message can be REFUSED, exactly as before).
const SHARD_QUEUE_DEPTH: usize = 64;
/// The most events one shard appends in ONE transaction / ONE ClickHouse insert.
pub(crate) const BATCH_MAX: usize = 32;
/// `max_ack_pending` for the durable consumer: every shard queue full plus
/// one batch in flight per shard. Applied through `ensure_pull_consumer`, so the
/// EXISTING prod consumer actually receives it (the get-or-create class).
const MAX_ACK_PENDING: i64 = (HEAD_WRITER_SHARDS * (SHARD_QUEUE_DEPTH + BATCH_MAX)) as i64;
/// Time a delivered message may sit queued behind a shard before JetStream
/// redelivers it. Redelivery is idempotent (`audit_appended`) but wasteful, so
/// this is sized for a full queue draining at a slow ~10 batches/s, not the
/// 30 s the single-task loop used.
const ACK_WAIT: Duration = Duration::from_secs(60);
/// How often the backlog poller reads `consumer.info()`.
const BACKLOG_POLL: Duration = Duration::from_secs(10);
/// `pending + ack_pending` at or above this is DEGRADED — about ten seconds of
/// the published 5,000 rps, and ~1 % of the ~1M events the 1 GiB bound holds.
pub(crate) const BACKLOG_UNHEALTHY: u64 = 10_000;
/// A backlog reading older than this is reported UNHEALTHY, never as zero:
/// "I cannot see" is not "nothing is wrong" (CLAUDE.md §14).
pub(crate) const BACKLOG_STALE_AFTER: Duration = Duration::from_secs(30);

static BACKLOG_PENDING: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static BACKLOG_ACK_PENDING: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Unix seconds of the last successful `consumer.info()`; 0 = never.
static BACKLOG_READ_AT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// What `/health` publishes about the audit queue (B-378).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BacklogSnapshot {
    /// Delivered to no one yet.
    pub pending: u64,
    /// Delivered to a shard, not yet committed + acked.
    pub ack_pending: u64,
    /// Age of the reading; `None` when nothing has ever been read.
    pub read_secs_ago: Option<u64>,
    /// `pending + ack_pending < BACKLOG_UNHEALTHY` AND the reading is fresh.
    pub healthy: bool,
}

/// The pure verdict, so the threshold and the staleness rule are testable
/// without a NATS server.
#[must_use]
pub(crate) fn backlog_verdict(
    pending: u64,
    ack_pending: u64,
    read_secs_ago: Option<u64>,
) -> BacklogSnapshot {
    let fresh = read_secs_ago.is_some_and(|s| s <= BACKLOG_STALE_AFTER.as_secs());
    BacklogSnapshot {
        pending,
        ack_pending,
        read_secs_ago,
        healthy: fresh && pending.saturating_add(ack_pending) < BACKLOG_UNHEALTHY,
    }
}

/// Current backlog reading for `/health` and `/metrics`.
#[must_use]
pub fn backlog_snapshot() -> BacklogSnapshot {
    use std::sync::atomic::Ordering::Relaxed;
    let read_at = BACKLOG_READ_AT.load(Relaxed);
    let now = unix_now();
    let age = (read_at > 0).then(|| now.saturating_sub(read_at));
    backlog_verdict(
        BACKLOG_PENDING.load(Relaxed),
        BACKLOG_ACK_PENDING.load(Relaxed),
        age,
    )
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Which shard owns a tenant. Stable for the life of the process; a tenant
/// always lands on the same shard, so its events keep their arrival order.
#[must_use]
pub(crate) fn shard_for(tenant_id: &TenantId) -> usize {
    use std::hash::{Hash as _, Hasher as _};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    tenant_id.as_uuid().hash(&mut h);
    (h.finish() % HEAD_WRITER_SHARDS as u64) as usize
}

/// One delivered, parsed, subject-checked event waiting for its shard.
struct Queued {
    msg: async_nats::jetstream::Message,
    wire: AuditEventWire,
}

/// Spawn the long-lived head-writer: ONE pull subscription feeding
/// `HEAD_WRITER_SHARDS` tenant-affine workers (B-378). Reconnects on any
/// error; a shard that dies takes the dispatcher down with it (closed channel)
/// so the whole thing restarts as a unit rather than running short-handed.
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

/// The head-writer's durable pull consumer. One function so the B-383 (b) live
/// test drives the EXACT config `run_once` ensures — the JetStream API subjects a
/// consumer create emits depend on it, and those subjects are what the NATS
/// permission list allows.
pub fn head_writer_consumer_config() -> async_nats::jetstream::consumer::pull::Config {
    async_nats::jetstream::consumer::pull::Config {
        durable_name: Some(CONSUMER.into()),
        ack_wait: ACK_WAIT,
        max_ack_pending: MAX_ACK_PENDING,
        // No max_deliver cap: a valid audit event MUST eventually land
        // (retry until PG/CH recover). Poison messages are Term'd in
        // `run_once`, so they never rely on a delivery cap to stop redelivering.
        ..Default::default()
    }
}

async fn run_once(audit_chain: &Arc<AuditChain>, client: &async_nats::Client) -> Result<()> {
    let js = async_nats::jetstream::new(client.clone());
    // Idempotent — self-heals if the stream was reset while we were disconnected, and
    // re-applies the byte bound if the stream came back without it.
    let stream = tracelane_shared::jetstream_limits::ensure_stream(&js, audit_stream_config())
        .await
        .context("bind TRACELANE_AUDIT stream")?;
    // `ensure_pull_consumer`, NOT `get_or_create_consumer`: the latter returns
    // the EXISTING consumer's config untouched, so the `max_ack_pending` and
    // `ack_wait` below would never have reached prod's consumer.
    let consumer = tracelane_shared::jetstream_limits::ensure_pull_consumer(
        &stream,
        head_writer_consumer_config(),
    )
    .await
    .context("ensure audit head-writer consumer")?;
    let mut messages = consumer
        .messages()
        .await
        .context("subscribe audit head-writer consumer")?;

    // The backlog poller. Aborted when this function returns (the guard drops).
    let poller = tokio::spawn({
        let consumer = consumer.clone();
        async move {
            loop {
                match consumer.clone().info().await {
                    Ok(info) => {
                        use std::sync::atomic::Ordering::Relaxed;
                        BACKLOG_PENDING.store(info.num_pending, Relaxed);
                        BACKLOG_ACK_PENDING.store(info.num_ack_pending as u64, Relaxed);
                        BACKLOG_READ_AT.store(unix_now(), Relaxed);
                        if !backlog_snapshot().healthy {
                            tracelane_shared::degradation::note(
                                tracelane_shared::degradation::Degradation::AuditBacklog,
                            );
                        } else {
                            // B-437: a healthy reading ends the episode (no-op when
                            // none is open).
                            tracelane_shared::degradation::resolve(
                                tracelane_shared::degradation::Degradation::AuditBacklog,
                            );
                        }
                    }
                    Err(e) => {
                        // Leave the last reading in place; its age is what
                        // `/health` reports, and a stale reading is unhealthy —
                        // noted as a degradation once it is, so the watchdog's
                        // `degraded_open` rule pages on "cannot see" too.
                        tracing::warn!(error = %e, "audit backlog: consumer.info() failed");
                        if !backlog_snapshot().healthy {
                            tracelane_shared::degradation::note(
                                tracelane_shared::degradation::Degradation::AuditBacklog,
                            );
                        }
                    }
                }
                tokio::time::sleep(BACKLOG_POLL).await;
            }
        }
    });
    let _poller_guard = AbortOnDrop(poller);

    // The shards.
    let mut senders = Vec::with_capacity(HEAD_WRITER_SHARDS);
    let mut workers = Vec::with_capacity(HEAD_WRITER_SHARDS);
    for shard in 0..HEAD_WRITER_SHARDS {
        let (tx, rx) = tokio::sync::mpsc::channel::<Queued>(SHARD_QUEUE_DEPTH);
        senders.push(tx);
        workers.push(AbortOnDrop(tokio::spawn(shard_worker(
            shard,
            rx,
            Arc::clone(audit_chain),
        ))));
    }
    tracing::info!(
        shards = HEAD_WRITER_SHARDS,
        batch_max = BATCH_MAX,
        max_ack_pending = MAX_ACK_PENDING,
        "audit head-writer consumer active on tracelane.audit.>"
    );

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

        // Hand it to the tenant's shard. A full queue parks the dispatcher
        // here — backpressure, not a drop. A closed channel means the shard
        // died; return so `spawn` restarts the whole head-writer.
        let shard = shard_for(&subj_tenant);
        if senders[shard].send(Queued { msg, wire }).await.is_err() {
            anyhow::bail!("audit head-writer shard {shard} is gone; restarting the consumer");
        }
    }
    Ok(())
}

/// Aborts the spawned task when dropped, so a returning `run_once` never leaves
/// a shard or the poller running against a subscription that no longer exists.
struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// One shard: drain what is queued (up to `BATCH_MAX`), group by tenant in
/// arrival order, append each tenant's group as ONE transaction, ack after
/// COMMIT. A failed group leaves its messages unacked for redelivery (no Nak:
/// the natural `ack_wait` backoff avoids a hot retry spin during an outage).
async fn shard_worker(
    shard: usize,
    mut rx: tokio::sync::mpsc::Receiver<Queued>,
    audit_chain: Arc<AuditChain>,
) {
    while let Some(first) = rx.recv().await {
        let mut batch = Vec::with_capacity(BATCH_MAX);
        batch.push(first);
        while batch.len() < BATCH_MAX {
            match rx.try_recv() {
                Ok(q) => batch.push(q),
                Err(_) => break,
            }
        }
        for group in group_by_tenant(batch) {
            let wires: Vec<AuditEventWire> = group.iter().map(|q| q.wire.clone()).collect();
            match audit_chain.append_batch_from_wire(&wires).await {
                Ok(()) => {
                    // Appended (or idempotently skipped) AND committed — ack now.
                    // A failed ack leaves the message for redelivery; the replay
                    // is a no-op via `audit_appended` (0020), so it is safe.
                    for q in group {
                        if let Err(e) = q.msg.ack().await {
                            tracing::warn!(error = %e, shard, "audit ack failed after commit; will redeliver (idempotent)");
                        }
                    }
                }
                Err(e) => {
                    // PG/CH outage — do NOT ack; JetStream redelivers after
                    // ack_wait. ONE counter, not one line per event: how long
                    // this has been open is the fact that matters.
                    let n = tracelane_shared::degradation::note(
                        tracelane_shared::degradation::Degradation::AuditAppendFailed,
                    );
                    tracing::error!(
                        error = %e,
                        shard,
                        events = group.len(),
                        failures_total = n,
                        "audit batch append failed — leaving unacked for redelivery"
                    );
                }
            }
        }
    }
}

/// Split one drained batch into per-tenant groups, each in arrival order, the
/// groups themselves in first-arrival order. Pure, so it is testable.
fn group_by_tenant(batch: Vec<Queued>) -> Vec<Vec<Queued>> {
    let mut groups: Vec<(Uuid, Vec<Queued>)> = Vec::new();
    for q in batch {
        let t = q.wire.tenant_id;
        match groups.iter_mut().find(|(g, _)| *g == t) {
            Some((_, v)) => v.push(q),
            None => groups.push((t, vec![q])),
        }
    }
    groups.into_iter().map(|(_, v)| v).collect()
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

    // ── B-378 ──

    #[test]
    fn shard_is_tenant_affine_and_in_range() {
        for _ in 0..10_000 {
            let t = TenantId::from_jwt_claim(Uuid::new_v4());
            let a = shard_for(&t);
            assert!(a < HEAD_WRITER_SHARDS);
            assert_eq!(
                a,
                shard_for(&t),
                "the same tenant must map to the same shard"
            );
        }
    }

    #[test]
    fn shards_spread_tenants() {
        // 1,000 random tenants over 8 shards: every shard gets some. A degenerate
        // hash would put everything on one shard and silently serialise again.
        let mut counts = [0usize; HEAD_WRITER_SHARDS];
        for _ in 0..1_000 {
            counts[shard_for(&TenantId::from_jwt_claim(Uuid::new_v4()))] += 1;
        }
        assert!(counts.iter().all(|&c| c > 50), "{counts:?}");
    }

    #[test]
    fn backlog_verdict_thresholds_and_staleness() {
        assert!(backlog_verdict(0, 0, Some(1)).healthy);
        assert!(backlog_verdict(BACKLOG_UNHEALTHY - 1, 0, Some(1)).healthy);
        assert!(
            !backlog_verdict(BACKLOG_UNHEALTHY, 0, Some(1)).healthy,
            "at the threshold"
        );
        assert!(
            !backlog_verdict(BACKLOG_UNHEALTHY / 2, BACKLOG_UNHEALTHY / 2, Some(1)).healthy,
            "pending + ack_pending together"
        );
        assert!(
            !backlog_verdict(0, 0, None).healthy,
            "never read is NOT healthy"
        );
        assert!(
            !backlog_verdict(0, 0, Some(BACKLOG_STALE_AFTER.as_secs() + 1)).healthy,
            "a stale zero is not a zero"
        );
        assert!(backlog_verdict(0, 0, Some(BACKLOG_STALE_AFTER.as_secs())).healthy);
        assert!(
            !backlog_verdict(u64::MAX, u64::MAX, Some(1)).healthy,
            "saturating add"
        );
    }

    #[test]
    fn max_ack_pending_covers_every_queue_plus_a_batch_in_flight() {
        assert_eq!(
            MAX_ACK_PENDING as usize,
            HEAD_WRITER_SHARDS * (SHARD_QUEUE_DEPTH + BATCH_MAX)
        );
    }

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

#[cfg(test)]
mod stream_limits_tests {
    use super::*;
    use async_nats::jetstream::stream::{DiscardPolicy, RetentionPolicy};

    /// The bound is a property of the SOURCE literal; prod inherits it via
    /// `jetstream_limits::ensure_stream`. A future edit that drops the field back to the
    /// unbounded default must fail here, not be discovered by `df`.
    #[test]
    fn audit_stream_is_byte_bounded_and_fails_closed_at_the_ceiling() {
        let cfg = audit_stream_config();
        assert_eq!(cfg.max_bytes, 1 << 30);
        assert!(
            cfg.max_bytes > 0,
            "an unbounded audit stream is the SRE #50 defect"
        );
        assert_eq!(
            cfg.discard,
            DiscardPolicy::New,
            "Old would drop ledger events silently"
        );
        assert_eq!(cfg.retention, RetentionPolicy::WorkQueue);
    }

    /// B-383 (b): the `gateway` NATS user can do EXACTLY the gateway's job against a
    /// server running the prod `nats.conf`, and nothing more — driven through the
    /// same `ensure_stream` / `ensure_pull_consumer` / `publish` calls the process
    /// makes, because the permission list is a list of the JetStream API subjects
    /// those calls emit and a hand-written `nats pub` proves a different thing.
    /// Run by `scripts/ci/check-nats-auth.sh`, which starts the throwaway server.
    #[tokio::test]
    #[ignore = "needs NATS_TEST_URL_{GATEWAY,OPS,ANON} — run scripts/ci/check-nats-auth.sh"]
    async fn b383_gateway_nats_user_can_do_exactly_its_job() {
        use futures::StreamExt as _;
        let Ok(gw_url) = std::env::var("NATS_TEST_URL_GATEWAY") else {
            panic!("NATS_TEST_URL_GATEWAY not set — this test cannot run, which is not a pass");
        };
        let ops_url = std::env::var("NATS_TEST_URL_OPS").expect("NATS_TEST_URL_OPS");
        let anon_url = std::env::var("NATS_TEST_URL_ANON").expect("NATS_TEST_URL_ANON");

        // (0) No credential, no connection — the whole point of the block.
        let anon = async_nats::connect(&anon_url).await;
        assert!(
            anon.is_err(),
            "an unauthenticated client CONNECTED: {anon:?}"
        );

        // The spans stream exists on prod (ingest owns it); ops stands in for that here
        // so the gateway's span publish has a stream to land in.
        let ops_nc = tracelane_shared::nats_connect::NatsConnect::from_url(&ops_url);
        let ops = async_nats::jetstream::new(
            ops_nc
                .options()
                .connect(&ops_nc.url)
                .await
                .expect("ops connect"),
        );
        ops.get_or_create_stream(async_nats::jetstream::stream::Config {
            name: "TRACELANE_SPANS".into(),
            subjects: vec!["tracelane.spans.>".into()],
            ..Default::default()
        })
        .await
        .expect("ops creates TRACELANE_SPANS");

        let nc = tracelane_shared::nats_connect::NatsConnect::from_url(&gw_url);
        let client = nc
            .options()
            .connect(&nc.url)
            .await
            .expect("gateway connects");
        let js = async_nats::jetstream::new(client.clone());
        // (1) Its own stream, its own consumer — the exact calls `run_once` makes.
        let stream = tracelane_shared::jetstream_limits::ensure_stream(&js, audit_stream_config())
            .await
            .expect("gateway ensures TRACELANE_AUDIT");
        let consumer = tracelane_shared::jetstream_limits::ensure_pull_consumer(
            &stream,
            head_writer_consumer_config(),
        )
        .await
        .expect("gateway ensures the head-writer consumer");
        // (2) Publishes an audit event and a span, each ACKED by the server.
        let tenant = uuid::Uuid::new_v4();
        js.publish(format!("tracelane.audit.{tenant}"), "e".into())
            .await
            .expect("audit publish sent")
            .await
            .expect("audit publish ACKED");
        js.publish(format!("tracelane.spans.{tenant}"), "s".into())
            .await
            .expect("span publish sent")
            .await
            .expect("span publish ACKED");
        // (3) Pulls its own message back and acks it; reads the backlog.
        let mut messages = consumer.messages().await.expect("subscribe");
        let msg = tokio::time::timeout(Duration::from_secs(5), messages.next())
            .await
            .expect("a message within 5 s")
            .expect("stream open")
            .expect("message");
        assert!(msg.subject.starts_with("tracelane.audit."));
        msg.ack().await.expect("ack");
        let mut consumer = consumer;
        let pending = consumer.info().await.expect("consumer info").num_pending;
        assert_eq!(pending, 0);
        // (4) And NOT: it cannot read the spans stream, delete its own stream, or
        // touch the server's system account. Each is a JetStream API subject the
        // list does not carry; the server answers with no responder.
        assert!(
            js.get_stream("TRACELANE_SPANS").await.is_err(),
            "gateway read TRACELANE_SPANS"
        );
        assert!(
            js.delete_stream("TRACELANE_AUDIT").await.is_err(),
            "gateway DELETED the ledger stream"
        );
        assert!(
            tokio::time::timeout(
                Duration::from_secs(3),
                client.request("$SYS.REQ.SERVER.PING", "".into())
            )
            .await
            .map(|r| r.is_err())
            .unwrap_or(true),
            "gateway reached $SYS"
        );
        let _ = ops.delete_stream("TRACELANE_SPANS").await;
        let _ = ops.delete_stream("TRACELANE_AUDIT").await;
    }
}

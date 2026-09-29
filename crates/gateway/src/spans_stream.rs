//! RI-06 / B-449 — the live view of the spans JetStream boundary on `/health`.
//!
//! Ingest counts spans lost at the stream boundary EXACTLY (`crates/ingest/src/gap_tracker.rs`),
//! but ingest cannot report while it is down — and that is precisely when the loss grows.
//! This poller mirrors the audit backlog poller (`audit_consumer.rs`, B-378): every
//! [`POLL`] it reads `TRACELANE_SPANS`'s `stream.info()` and the `tracelane-ingest`
//! consumer's info and publishes `first_seq`, `last_seq`, `ack_floor`, `num_pending` and
//! the derived `visible_gap` on `/health.spans_stream`.
//!
//! **Honest limit, stated on the field:** `visible_gap = first_seq − (ack_floor + 1)` is
//! exact only while the consumer is NOT acking. Once ingest resumes and acks one post-gap
//! message, JetStream's ack floor jumps past the never-delivered sequences and the gauge
//! returns to 0 — the exact count lives in ingest's counter and in
//! `tracelane.capture_gaps`. A stale reading is UNHEALTHY, never a zero (CLAUDE.md §14).
//!
//! Grants: the gateway NATS user needs `$JS.API.STREAM.INFO.TRACELANE_SPANS` and
//! `$JS.API.CONSUMER.INFO.TRACELANE_SPANS.*` (`infra/prod/nats/nats.conf`); it must still
//! be refused `MSG.NEXT` / `STREAM.UPDATE` on the spans stream — both directions are in
//! `b383_gateway_nats_user_can_do_exactly_its_job`. No Postgres, no ClickHouse: this
//! poller wakes nothing that can sleep (B-442).

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;

/// The stream ingest consumes and the durable it consumes with — the names
/// `crates/ingest/src/nats_consumer.rs` declares (`spans_stream_config`,
/// `ingest_consumer_config`).
pub const SPANS_STREAM: &str = "TRACELANE_SPANS";
pub const INGEST_DURABLE: &str = "tracelane-ingest";
/// How often the poller reads; the audit backlog's cadence.
const POLL: Duration = Duration::from_secs(10);
/// A reading older than this is UNHEALTHY regardless of its numbers.
pub(crate) const STALE_AFTER: Duration = Duration::from_secs(60);

static FIRST_SEQ: AtomicU64 = AtomicU64::new(0);
static LAST_SEQ: AtomicU64 = AtomicU64::new(0);
static ACK_FLOOR: AtomicU64 = AtomicU64::new(0);
static NUM_PENDING: AtomicU64 = AtomicU64::new(0);
/// Unix seconds of the last successful read of BOTH infos; 0 = never.
static READ_AT: AtomicU64 = AtomicU64::new(0);

/// What `/health` publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpansStreamSnapshot {
    pub first_seq: u64,
    pub last_seq: u64,
    pub ack_floor: u64,
    pub num_pending: u64,
    /// Spans the stream has trimmed past the consumer's acked prefix, as visible NOW.
    pub visible_gap: u64,
    /// Age of the reading; `None` when nothing has ever been read.
    pub read_secs_ago: Option<u64>,
    /// Fresh AND `visible_gap == 0`.
    pub healthy: bool,
}

/// The pure arithmetic: how many sequences sit between the acked prefix and the stream's
/// first retained message. `ack_floor == 0` is a brand-new durable and says nothing.
#[must_use]
pub(crate) const fn visible_gap(first_seq: u64, ack_floor: u64) -> u64 {
    if ack_floor == 0 {
        return 0;
    }
    first_seq.saturating_sub(ack_floor + 1)
}

/// The pure verdict, testable without a server: fresh and gap-free is healthy; a
/// never-read or stale reading is not, whatever its numbers say.
#[must_use]
pub(crate) fn verdict(
    first_seq: u64,
    last_seq: u64,
    ack_floor: u64,
    num_pending: u64,
    read_secs_ago: Option<u64>,
) -> SpansStreamSnapshot {
    let gap = visible_gap(first_seq, ack_floor);
    let fresh = matches!(read_secs_ago, Some(age) if age <= STALE_AFTER.as_secs());
    SpansStreamSnapshot {
        first_seq,
        last_seq,
        ack_floor,
        num_pending,
        visible_gap: gap,
        read_secs_ago,
        healthy: fresh && gap == 0,
    }
}

#[must_use]
pub fn snapshot() -> SpansStreamSnapshot {
    let read_at = READ_AT.load(Relaxed);
    let age = (read_at > 0).then(|| unix_now().saturating_sub(read_at));
    verdict(
        FIRST_SEQ.load(Relaxed),
        LAST_SEQ.load(Relaxed),
        ACK_FLOOR.load(Relaxed),
        NUM_PENDING.load(Relaxed),
        age,
    )
}

/// The `/health.spans_stream` object.
#[must_use]
pub fn health_json() -> serde_json::Value {
    let s = snapshot();
    serde_json::json!({
        "first_seq": s.first_seq,
        "last_seq": s.last_seq,
        "ack_floor": s.ack_floor,
        "num_pending": s.num_pending,
        "visible_gap": s.visible_gap,
        "read_secs_ago": s.read_secs_ago,
        "healthy": s.healthy,
    })
}

/// Spawn the poller. Fail-OPEN: a read error leaves the last reading in place and lets
/// `read_secs_ago` grow — `healthy` goes false on staleness, never on a guess.
pub fn spawn(nats: async_nats::Client) {
    tokio::spawn(async move {
        let js = async_nats::jetstream::new(nats);
        let mut warned = false;
        loop {
            match read_once(&js).await {
                Ok((first, last, floor, pending)) => {
                    FIRST_SEQ.store(first, Relaxed);
                    LAST_SEQ.store(last, Relaxed);
                    ACK_FLOOR.store(floor, Relaxed);
                    NUM_PENDING.store(pending, Relaxed);
                    READ_AT.store(unix_now(), Relaxed);
                    warned = false;
                    // The page rule is `degraded_open`: a visible gap opens the kind, a
                    // healthy reading ends the episode (B-437; no-op when none is open).
                    use tracelane_shared::degradation::{self, Degradation::SpansStreamGap};
                    if snapshot().healthy {
                        degradation::resolve(SpansStreamGap);
                    } else {
                        degradation::note(SpansStreamGap);
                    }
                }
                Err(e) => {
                    // Once per outage, not per tick (logging.md): the staleness on
                    // /health is the ongoing signal — and once the reading is stale the
                    // kind is noted, so the watchdog pages on "cannot see" too.
                    if !warned {
                        tracing::warn!(error = %e, "spans stream poller: info read failed; /health.spans_stream goes stale");
                        warned = true;
                    }
                    if !snapshot().healthy {
                        tracelane_shared::degradation::note(
                            tracelane_shared::degradation::Degradation::SpansStreamGap,
                        );
                    }
                }
            }
            tokio::time::sleep(POLL).await;
        }
    });
}

async fn read_once(js: &async_nats::jetstream::Context) -> anyhow::Result<(u64, u64, u64, u64)> {
    let mut stream = js.get_stream(SPANS_STREAM).await?;
    let sinfo = stream.info().await?;
    let (first, last) = (sinfo.state.first_sequence, sinfo.state.last_sequence);
    let cinfo = stream.consumer_info(INGEST_DURABLE).await?;
    Ok((
        first,
        last,
        cinfo.ack_floor.stream_sequence,
        cinfo.num_pending,
    ))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visible_gap_is_the_trim_past_the_acked_prefix_and_zero_for_a_new_durable() {
        assert_eq!(
            visible_gap(19, 3),
            15,
            "4..=18 trimmed past an ack floor of 3"
        );
        assert_eq!(
            visible_gap(4, 3),
            0,
            "first retained = floor + 1: nothing trimmed"
        );
        assert_eq!(
            visible_gap(40, 100),
            0,
            "the stream still holds older messages"
        );
        assert_eq!(visible_gap(50, 0), 0, "a brand-new durable says nothing");
    }

    #[test]
    fn a_stale_or_never_read_snapshot_is_unhealthy_even_at_zero_gap() {
        assert!(
            !verdict(4, 4, 3, 0, None).healthy,
            "never read is not a zero"
        );
        assert!(
            !verdict(4, 4, 3, 0, Some(STALE_AFTER.as_secs() + 1)).healthy,
            "stale is not a zero"
        );
        assert!(verdict(4, 4, 3, 0, Some(5)).healthy);
        assert!(
            !verdict(19, 41, 3, 22, Some(5)).healthy,
            "a fresh reading with a gap is unhealthy"
        );
    }

    #[test]
    fn health_json_carries_every_field_the_status_page_reads() {
        let v = health_json();
        for k in [
            "first_seq",
            "last_seq",
            "ack_floor",
            "num_pending",
            "visible_gap",
            "read_secs_ago",
            "healthy",
        ] {
            assert!(v.get(k).is_some(), "missing {k}");
        }
        assert_eq!(
            v["healthy"],
            serde_json::json!(false),
            "a process that never polled is not healthy"
        );
    }
}

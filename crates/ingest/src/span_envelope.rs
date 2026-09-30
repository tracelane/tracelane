//! The unit carried on the ingest span channel: a span plus an optional
//! durability acknowledgement.
//!
//! #81 durability gap: the NATS consumer used to ack the JetStream message as
//! soon as it pushed the span onto the in-process channel — BEFORE the ClickHouse
//! writer committed the row. A write failure (or a crash) after that point lost
//! the span even though the message was already acked. `SpanEnvelope` carries the
//! ack handle through to the writer, which acks ONLY after the row is durably
//! written — so a failed write leaves the message unacked and JetStream
//! redelivers it (ack-after-write; preserves the FT-03 zero-loss guarantee).

use tracelane_shared::TracelaneSpan;

/// A span in flight from a source to the ClickHouse writer.
///
/// `ack` is `Some` for NATS-sourced spans (the writer acks the JetStream message
/// after the durable write; an unacked message is redelivered). It is `None` for
/// OTLP-sourced spans — push delivery, already acknowledged to the SDK at the
/// receiver, with no redelivery semantics to manage here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanSource {
    Nats,
    OtlpDirect,
}

pub struct SpanEnvelope {
    pub span: TracelaneSpan,
    pub source: SpanSource,
    pub ack: Option<async_nats::jetstream::Message>,
}

impl SpanEnvelope {
    /// An OTLP-sourced span (no JetStream message to ack).
    #[must_use]
    pub fn otlp(span: TracelaneSpan) -> Self {
        Self {
            span,
            ack: None,
            source: SpanSource::OtlpDirect,
        }
    }

    /// A NATS-sourced span carrying its JetStream message for ack-after-write.
    #[must_use]
    pub fn nats(span: TracelaneSpan, msg: async_nats::jetstream::Message) -> Self {
        Self {
            span,
            ack: Some(msg),
            source: SpanSource::Nats,
        }
    }
}

/// The stream sequences this process holds but has not acked — in the channel or
/// in the writer's batch. B-493 run 4 (2026-09-21): while the writer held one batch
/// through a ClickHouse stall and progress-acked it, the NEXT batch sat in the
/// channel with nobody to progress-ack it, JetStream redelivered it at `ack_wait`
/// (3,936 redeliveries) and the copies were queued behind the originals — each an
/// extra INSERT the `mv_*` views count. A redelivery of a sequence this process
/// still holds is a duplicate by definition (the original will be acked, which acks
/// the message whatever its delivery count) and is dropped at the consumer instead.
/// Process-local on purpose: after a crash the set is gone and the redelivery is
/// the real recovery path.
mod held {
    use std::collections::HashSet;
    use std::sync::{LazyLock, Mutex};

    static HELD: LazyLock<Mutex<HashSet<u64>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

    /// Record `seq` as held; `false` if this process already holds it.
    pub fn hold(seq: u64) -> bool {
        HELD.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(seq)
    }

    /// The message was acked (or terminally handled) — its sequence is no longer held.
    pub fn release(seq: u64) {
        HELD.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&seq);
    }
}

pub use held::{hold, release};

#[cfg(test)]
mod held_tests {
    #[test]
    fn a_sequence_is_held_once_until_released() {
        assert!(super::hold(9_000_001));
        assert!(
            !super::hold(9_000_001),
            "a redelivery of a held sequence is refused"
        );
        super::release(9_000_001);
        assert!(super::hold(9_000_001), "released, it can be held again");
        super::release(9_000_001);
    }
}

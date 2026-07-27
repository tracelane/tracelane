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
pub struct SpanEnvelope {
    pub span: TracelaneSpan,
    pub ack: Option<async_nats::jetstream::Message>,
}

impl SpanEnvelope {
    /// An OTLP-sourced span (no JetStream message to ack).
    #[must_use]
    pub fn otlp(span: TracelaneSpan) -> Self {
        Self { span, ack: None }
    }

    /// A NATS-sourced span carrying its JetStream message for ack-after-write.
    #[must_use]
    pub fn nats(span: TracelaneSpan, msg: async_nats::jetstream::Message) -> Self {
        Self {
            span,
            ack: Some(msg),
        }
    }
}

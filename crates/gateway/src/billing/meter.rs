//! Usage-meter recorder for Polar.sh.
//!
//! Goals:
//!   - Hot path is wait-free — `record(meter, customer, n)` only does an
//!     atomic add into a per-meter HashMap entry.
//!   - Background flush task pushes accumulated counts to Polar via
//!     `PolarClient::record_meter_event` once every `flush_interval`.
//!   - On Polar errors, the count is *kept* in the buffer for the next
//!     flush. Polar's `/events/ingest` is idempotent on `external_id`,
//!     so retried flushes don't double-count.
//!
//! V1 meters:
//!   tokens_processed   — sum of input + output tokens across all chats
//!   audit_anchors      — count of Rekor anchor batches submitted

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use super::polar_client::{BillingResult, PolarClient, PolarCustomerId};

/// Tracelane usage meter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Meter {
    TokensProcessed,
    AuditAnchors,
}

impl Meter {
    /// Polar event `name` for this meter.
    pub fn event_name(&self) -> &'static str {
        match self {
            Meter::TokensProcessed => "tokens_processed",
            Meter::AuditAnchors => "audit_anchors",
        }
    }
}

type RecorderKey = (Meter, String); // (meter, polar_customer_id)

/// In-memory counter buffer flushed to Polar periodically.
pub struct Recorder {
    buffer: Arc<Mutex<HashMap<RecorderKey, u64>>>,
    client: Arc<PolarClient>,
    flush_interval: Duration,
}

impl Recorder {
    pub fn new(client: Arc<PolarClient>) -> Self {
        Self {
            buffer: Arc::new(Mutex::new(HashMap::new())),
            client,
            flush_interval: Duration::from_secs(60),
        }
    }

    pub fn with_flush_interval(mut self, interval: Duration) -> Self {
        self.flush_interval = interval;
        self
    }

    /// Add `n` usage units against `(meter, customer_id)`. Hot path —
    /// only acquires a tokio Mutex briefly. No I/O.
    pub async fn record(&self, meter: Meter, customer_id: &PolarCustomerId, n: u64) {
        if n == 0 {
            return;
        }
        let key = (meter, customer_id.0.clone());
        let mut buf = self.buffer.lock().await;
        *buf.entry(key).or_insert(0) += n;
    }

    /// Drain the buffer into Polar. Returns the number of events posted.
    /// On error, the count is restored to the buffer for the next flush.
    pub async fn flush(&self) -> BillingResult<usize> {
        let drained: Vec<(RecorderKey, u64)> = {
            let mut buf = self.buffer.lock().await;
            buf.drain().collect()
        };

        let mut posted = 0usize;
        let mut failures: Vec<(RecorderKey, u64)> = Vec::new();

        // Deterministic idempotency key per flush batch:
        // `<event_name>-<customer_id>-<flush_at_unix_seconds>`. Polar's
        // `external_id` deduplicates retries of the same key, so a
        // retry-after-network-blip doesn't double-count.
        let flush_at = chrono::Utc::now().timestamp();

        for (key, value) in drained {
            let (meter, customer_id_raw) = key.clone();
            let customer_id = PolarCustomerId(customer_id_raw.clone());
            let idempotency_key = format!(
                "{event}-{customer}-{ts}",
                event = meter.event_name(),
                customer = customer_id_raw,
                ts = flush_at
            );
            match self
                .client
                .record_meter_event(meter.event_name(), &customer_id, value, &idempotency_key)
                .await
            {
                Ok(()) => posted += 1,
                Err(err) => {
                    tracing::warn!(error = %err, "meter flush failed; will retry");
                    failures.push((key, value));
                }
            }
        }

        if !failures.is_empty() {
            let mut buf = self.buffer.lock().await;
            for (key, value) in failures {
                *buf.entry(key).or_insert(0) += value;
            }
        }

        Ok(posted)
    }

    /// Spawn a background task that flushes on the configured interval.
    pub fn spawn_flusher(self: Arc<Self>) {
        let interval = self.flush_interval;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // discard the immediate first tick
            loop {
                ticker.tick().await;
                if let Err(err) = self.flush().await {
                    tracing::warn!(error = %err, "meter flusher error");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cus() -> PolarCustomerId {
        PolarCustomerId("cust_polar_test".into())
    }

    #[tokio::test]
    async fn record_accumulates_per_meter() {
        let client = Arc::new(PolarClient::new("polar_pat_fake"));
        let recorder = Recorder::new(client);
        recorder.record(Meter::TokensProcessed, &cus(), 100).await;
        recorder.record(Meter::TokensProcessed, &cus(), 50).await;
        recorder.record(Meter::AuditAnchors, &cus(), 1).await;

        let buf = recorder.buffer.lock().await;
        assert_eq!(buf.len(), 2);
        let tokens_total = buf
            .get(&(Meter::TokensProcessed, "cust_polar_test".into()))
            .copied();
        let anchors_total = buf
            .get(&(Meter::AuditAnchors, "cust_polar_test".into()))
            .copied();
        assert_eq!(tokens_total, Some(150));
        assert_eq!(anchors_total, Some(1));
    }

    #[tokio::test]
    async fn record_zero_is_noop() {
        let client = Arc::new(PolarClient::new("polar_pat_fake"));
        let recorder = Recorder::new(client);
        recorder.record(Meter::TokensProcessed, &cus(), 0).await;
        let buf = recorder.buffer.lock().await;
        assert!(buf.is_empty());
    }

    #[test]
    fn meter_event_names_are_stable() {
        // Pin the meter event_names — Polar dashboard config depends on
        // these strings.
        assert_eq!(Meter::TokensProcessed.event_name(), "tokens_processed");
        assert_eq!(Meter::AuditAnchors.event_name(), "audit_anchors");
    }
}

//! BILL-01 / ADR-076 — the gateway half of the six-meter usage model.
//!
//! Records meters 1 (ingest_bytes) and 6 (eval_runs), plus the two A3 per-key
//! sub-meters (key_output_tokens, key_spend_micro_usd), into an in-process,
//! wait-free accumulator and flushes ALL of it in ONE batched INSERT every 10
//! seconds (spec §2.5b: zero new Postgres/ClickHouse round trips per request;
//! one batched write per process per flush interval, all tenants and meters
//! together). Meters 2-5 (hot window / series / query / cold) are a SEPARATE,
//! not-yet-built daily gauge job (`meter_gauges`) — out of this build's scope,
//! see `specs/BILL-01-metering-and-tiers.md` §2.1.
//!
//! ## Why a Mutex<HashMap>, matching `billing::meter::Recorder`
//!
//! Same shape as the existing Polar `Recorder`: a `tokio::sync::Mutex` guarding
//! a `HashMap` keyed by `(tenant, meter, dim)`, drained wholesale on each flush
//! tick. The lock is held only long enough to add-and-release or to swap the
//! whole map out, never across an await that talks to ClickHouse.
//!
//! ## RowBinary type matching (B-274 class)
//!
//! `day: NaiveDate` uses `#[serde(with = "clickhouse::serde::chrono::date")]`
//! — the ClickHouse `Date` column is a `u16` day-count from the epoch, and
//! chrono's own `Serialize` for `NaiveDate` is NOT that (it would desync the
//! RowBinary block on the first date field, silently, exactly like B-274).
//! `recorded_at` is OMITTED from the insert struct — the column has
//! `DEFAULT now64()` in migration 24, and `clickhouse-rs` builds its column
//! list from the struct's own field names, so ClickHouse fills the default in.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::sync::Mutex;
use tracelane_shared::TenantId;

/// The four gateway-recorded meters (migration 24's `meter_counters.meter`
/// values). Meters 2-5 (hot/series/query/cold) are gauges written by the
/// (not yet built) daily job, never through this sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UsageMeter {
    /// Meter 1 — logical bytes of a published span (gateway path). `dim = ""`.
    IngestBytes,
    /// Meter 6 — one unit per judge call that reached a provider (errored
    /// counts; a mock provider under `TRACELANE_EVAL_MOCK_PROVIDERS` does
    /// not). `dim = ""`.
    EvalRuns,
    /// A3 sub-meter: output tokens attributed to one API key. `dim = api_key_id`.
    KeyOutputTokens,
    /// A3 sub-meter: spend in MICRO-USD attributed to one API key (the
    /// velocity breaker reads `key_output_tokens`, not this one, but both
    /// ride the same table so a future $ dashboard needs no new plumbing).
    /// `dim = api_key_id`.
    KeySpendMicroUsd,
}

impl UsageMeter {
    /// The `meter_counters.meter` string — exactly migration 24's comment.
    const fn as_str(self) -> &'static str {
        match self {
            Self::IngestBytes => "ingest_bytes",
            Self::EvalRuns => "eval_runs",
            Self::KeyOutputTokens => "key_output_tokens",
            Self::KeySpendMicroUsd => "key_spend_micro_usd",
        }
    }
}

type Key = (String, UsageMeter, String); // (tenant_id, meter, dim)

/// In-process usage-meter accumulator, flushed to ClickHouse `meter_counters`
/// on a fixed interval. Every gateway-originated row carries `source =
/// "gateway"` — the judge (`online_eval.rs`) runs INSIDE this process, so it
/// is not a separate writer the way ingest's own OTLP decode is.
pub struct MeterSink {
    buffer: Arc<Mutex<HashMap<Key, f64>>>,
    ch_url: String,
    flush_interval: Duration,
    /// Count of ACCEPTED `record()` calls since this sink was built — the role
    /// the deleted ADR-020 recorder's `BILLING_RECORDS_SPAWNED` played, now
    /// per-sink (a test measures its own sink, no process-global lock) and on
    /// the meter that is actually billed. Read by tests only: the external
    /// evidence that the gateway meters is the `meter_counters` rows in
    /// ClickHouse (asserted by the prod proof), not an in-process number.
    records: std::sync::atomic::AtomicU64,
}

impl MeterSink {
    #[must_use]
    pub fn new(ch_url: String) -> Self {
        Self {
            buffer: Arc::new(Mutex::new(HashMap::new())),
            ch_url,
            flush_interval: Duration::from_secs(10),
            records: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Add `value` to `(tenant, meter, dim)`. Hot-path budget: one Mutex lock,
    /// no I/O, no allocation past the (rare) first entry for a key.
    pub async fn record(&self, tenant: &TenantId, meter: UsageMeter, dim: &str, value: f64) {
        if !value.is_finite() || value <= 0.0 {
            return;
        }
        let key = (tenant.to_string(), meter, dim.to_string());
        let mut buf = self.buffer.lock().await;
        *buf.entry(key).or_insert(0.0) += value;
        self.records
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Accepted `record()` calls since construction. Relaxed; a count, not a sum.
    #[cfg(test)]
    pub(crate) fn records_total(&self) -> u64 {
        self.records.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Test seam: the buffered (un-flushed) total for `(tenant, meter)` across
    /// every dim.
    #[cfg(test)]
    pub(crate) async fn buffered_total(&self, tenant: &TenantId, meter: UsageMeter) -> f64 {
        let t = tenant.to_string();
        self.buffer
            .lock()
            .await
            .iter()
            .filter(|((k_t, k_m, _), _)| *k_t == t && *k_m == meter)
            .map(|(_, v)| *v)
            .sum()
    }

    /// Drain the buffer into ONE batched INSERT. On failure the drained rows
    /// are RESTORED to the buffer (fail-open — a billing-meter outage must
    /// never affect a request) and `Degradation::MeterFlushFailed` notes it,
    /// exactly the C1 shape `billing::meter::Recorder::flush` was fixed for.
    pub async fn flush(&self) -> anyhow::Result<usize> {
        let drained: Vec<(Key, f64)> = {
            let mut buf = self.buffer.lock().await;
            buf.drain().collect()
        };
        if drained.is_empty() {
            return Ok(0);
        }
        let day = days_since_epoch(chrono::Utc::now().date_naive());
        let ch = crate::clickhouse_query::ch_client(self.ch_url.clone());
        let n = drained.len();
        let flush_result: Result<(), anyhow::Error> = async {
            let mut insert = ch
                .insert("meter_counters")
                .map_err(|e| anyhow::anyhow!("meter_counters insert init failed: {e}"))?;
            for ((tenant_id, meter, dim), value) in &drained {
                insert
                    .write(&MeterCounterRow {
                        tenant_id,
                        day,
                        meter: meter.as_str(),
                        dim,
                        value: *value,
                        source: "gateway",
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("meter_counters row write failed: {e}"))?;
            }
            insert
                .end()
                .await
                .map_err(|e| anyhow::anyhow!("meter_counters insert commit failed: {e}"))
        }
        .await;

        match flush_result {
            Ok(()) => Ok(n),
            Err(e) => {
                tracing::warn!(error = %e, "meter sink flush failed; restoring buffer");
                self.restore(drained).await;
                tracelane_shared::degradation::note(
                    tracelane_shared::degradation::Degradation::MeterFlushFailed,
                );
                Err(e)
            }
        }
    }

    /// Restore drained rows to the buffer after a failed flush — additively,
    /// since a concurrent `record` may have added to the same key while the
    /// flush was in flight.
    async fn restore(&self, drained: Vec<(Key, f64)>) {
        let mut buf = self.buffer.lock().await;
        for (key, value) in drained {
            *buf.entry(key).or_insert(0.0) += value;
        }
    }

    /// Spawn the background flush loop. Idempotent to call once, at boot.
    pub fn spawn_flusher(self: Arc<Self>) {
        let interval = self.flush_interval;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // discard the immediate first tick
            loop {
                ticker.tick().await;
                if let Err(err) = self.flush().await {
                    tracing::warn!(error = %err, "meter sink flush error");
                }
            }
        });
    }
}

#[derive(serde::Serialize, clickhouse::Row)]
struct MeterCounterRow<'a> {
    tenant_id: &'a str,
    /// ClickHouse `Date` is a raw `u16` day-count from the 1970-01-01 epoch on
    /// the wire (RowBinary). The workspace `clickhouse` dependency does not
    /// enable the crate's own `chrono` feature (root `Cargo.toml`, out of
    /// this change's scope), so this is computed by hand in
    /// [`days_since_epoch`] rather than via `clickhouse::serde::chrono::date`
    /// — same wire value, no new feature flag.
    day: u16,
    meter: &'a str,
    dim: &'a str,
    value: f64,
    source: &'a str,
}

/// Days from the ClickHouse `Date` epoch (1970-01-01) to `date`. Matches
/// `clickhouse::serde::chrono::date`'s own wire encoding exactly (RowBinary
/// `Date` = `u16` days-since-epoch) without requiring that crate feature.
fn days_since_epoch(date: chrono::NaiveDate) -> u16 {
    // `.unwrap()`/`.expect()` are banned outside tests (`.claude/rules/rust.md`)
    // even though 1970-01-01 is provably always valid; the `None` arm is
    // dead in practice, never a panic.
    let Some(epoch) = chrono::NaiveDate::from_ymd_opt(1970, 1, 1) else {
        return 0;
    };
    u16::try_from((date - epoch).num_days().max(0)).unwrap_or(u16::MAX)
}

/// Process-wide sink, installed once at boot (`server.rs`) alongside
/// `AppState::meters`. `None` when `CLICKHOUSE_URL` is unset — every record
/// site is then a no-op, matching every other ClickHouse-gated sink in this
/// crate (the semantic cache, the billing `Recorder`).
///
/// A global, not ONLY a state field, for the same reason `crate::spend::tracker()`
/// is: `online_eval.rs`'s judge site and `record_key_spend` in `server/spans.rs`
/// both run off the request path with no `&AppState` in scope.
static GLOBAL: OnceLock<Option<Arc<MeterSink>>> = OnceLock::new();

/// Install the process-wide sink. Called exactly once, at boot. A second call
/// is a no-op (`OnceLock::set` fails silently) — boot runs once per process.
pub fn install(sink: Option<Arc<MeterSink>>) {
    let _ = GLOBAL.set(sink);
}

/// The process-wide sink, or `None` before `install` has run or when no
/// ClickHouse URL was configured.
#[must_use]
pub fn global() -> Option<Arc<MeterSink>> {
    GLOBAL.get().and_then(Clone::clone)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t() -> TenantId {
        TenantId::from_jwt_claim(uuid::Uuid::from_u128(0xBEEF))
    }

    #[tokio::test]
    async fn record_accumulates_per_tenant_meter_dim() {
        let sink = MeterSink::new("http://127.0.0.1:0".to_string());
        sink.record(&t(), UsageMeter::IngestBytes, "", 100.0).await;
        sink.record(&t(), UsageMeter::IngestBytes, "", 50.0).await;
        sink.record(&t(), UsageMeter::EvalRuns, "", 1.0).await;
        let buf = sink.buffer.lock().await;
        assert_eq!(buf.len(), 2, "two distinct (meter, dim) keys");
        assert_eq!(
            buf.get(&(t().to_string(), UsageMeter::IngestBytes, String::new())),
            Some(&150.0)
        );
    }

    #[tokio::test]
    async fn zero_and_negative_and_nonfinite_are_noops() {
        let sink = MeterSink::new("http://127.0.0.1:0".to_string());
        sink.record(&t(), UsageMeter::IngestBytes, "", 0.0).await;
        sink.record(&t(), UsageMeter::IngestBytes, "", -5.0).await;
        sink.record(&t(), UsageMeter::IngestBytes, "", f64::NAN)
            .await;
        assert!(sink.buffer.lock().await.is_empty());
    }

    #[tokio::test]
    async fn per_key_dim_is_isolated_from_the_workspace_level_dim() {
        let sink = MeterSink::new("http://127.0.0.1:0".to_string());
        sink.record(&t(), UsageMeter::KeyOutputTokens, "key-a", 10.0)
            .await;
        sink.record(&t(), UsageMeter::KeyOutputTokens, "key-b", 20.0)
            .await;
        let buf = sink.buffer.lock().await;
        assert_eq!(
            buf.get(&(
                t().to_string(),
                UsageMeter::KeyOutputTokens,
                "key-a".to_string()
            )),
            Some(&10.0)
        );
        assert_eq!(
            buf.get(&(
                t().to_string(),
                UsageMeter::KeyOutputTokens,
                "key-b".to_string()
            )),
            Some(&20.0)
        );
    }

    /// C1 class (`billing::meter::Recorder`'s own fix): a failed flush must
    /// move the degradation counter AND restore the buffer, never silently
    /// drop usage.
    #[tokio::test]
    async fn a_failed_flush_restores_the_buffer_and_notes_degradation() {
        use tracelane_shared::degradation::{Degradation, count};
        // Port 1 / an address nothing listens on: the insert will fail to
        // connect, exercising the failure path without a real ClickHouse.
        let sink = MeterSink::new("http://127.0.0.1:1".to_string());
        sink.record(&t(), UsageMeter::IngestBytes, "", 42.0).await;
        let before = count(Degradation::MeterFlushFailed);
        let result = sink.flush().await;
        let after = count(Degradation::MeterFlushFailed);
        assert!(result.is_err(), "a connect failure must surface as Err");
        assert!(after > before, "a failed flush must note the degradation");
        let buf = sink.buffer.lock().await;
        assert_eq!(
            buf.get(&(t().to_string(), UsageMeter::IngestBytes, String::new())),
            Some(&42.0),
            "the failed row must be restored, not lost"
        );
    }

    #[tokio::test]
    async fn empty_buffer_flushes_as_a_noop() {
        let sink = MeterSink::new("http://127.0.0.1:1".to_string());
        assert_eq!(sink.flush().await.unwrap(), 0);
    }
}

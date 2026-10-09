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
//! ## Immutable batches + a dedup token per batch (B-469, REV-1, 2026-09-20)
//!
//! `meter_counters` is a `SummingMergeTree` with NO batch identity in its key,
//! and ClickHouse documents that an INSERT can COMMIT and still report failure
//! (a timeout, a connection dropped after the server finished). The old flush
//! restored a failed batch's amounts into the live buffer and re-sent them
//! merged with newer records — a lost response therefore counted the batch
//! TWICE, and no counter could tell that from a clean retry. Now every flush
//! is an immutable [`MeterBatch`] with its own `insert_deduplication_token`;
//! a failed batch waits in `pending` and is retried UNCHANGED (same rows, same
//! day, same token), and the server dedups by token within the table's
//! `non_replicated_deduplication_window` (migration 28). The live buffer is
//! never merged into a failed batch. The queue is bounded; overflow drops the
//! OLDEST batch and counts it (`MeterBatchDropped`) — an outage longer than a
//! day loses meter data in the customer's favour and says so on `/health`.
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

use std::collections::{HashMap, VecDeque};
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

/// One drained flush, frozen: the rows, the day they were drained on, and the
/// `insert_deduplication_token` every retry of it carries. Never mutated after
/// construction — that immutability is the whole B-469 guarantee.
#[derive(Debug, Clone)]
pub(crate) struct MeterBatch {
    pub(crate) token: String,
    pub(crate) day: u16,
    pub(crate) rows: Vec<(Key, f64)>,
}

/// Failed batches held for retry, at most this many (24 h of 10 s flushes).
/// Beyond it the OLDEST is dropped and counted — bounded memory, never a
/// double count.
pub(crate) const PENDING_BATCH_CAP: usize = 8_640;

/// In-process usage-meter accumulator, flushed to ClickHouse `meter_counters`
/// on a fixed interval. Every gateway-originated row carries `source =
/// "gateway"` — the judge (`online_eval.rs`) runs INSIDE this process, so it
/// is not a separate writer the way ingest's own OTLP decode is.
pub struct MeterSink {
    buffer: Arc<Mutex<HashMap<Key, f64>>>,
    /// B-469: batches whose INSERT did not report success, oldest first,
    /// retried unchanged ahead of the next drain. See the module doc.
    pending: Mutex<VecDeque<MeterBatch>>,
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
            pending: Mutex::new(VecDeque::new()),
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

    /// Batches waiting for retry (test seam).
    #[cfg(test)]
    pub(crate) async fn pending_batches(&self) -> Vec<MeterBatch> {
        self.pending.lock().await.iter().cloned().collect()
    }

    /// Flush: retry every pending batch UNCHANGED (oldest first, stopping at
    /// the first failure so order is kept), then drain the live buffer into a
    /// NEW batch and insert it. A batch that fails goes to `pending` as-is —
    /// never back into the live buffer — and `Degradation::MeterFlushFailed`
    /// notes it (fail-open: a billing-meter outage must never affect a
    /// request). Returns the number of rows accepted this call.
    ///
    /// # Errors
    /// The LAST insert failure of this call, after the failed batch has been
    /// queued; nothing is lost on `Err` short of the queue cap.
    pub async fn flush(&self) -> anyhow::Result<usize> {
        let ch = crate::clickhouse_query::ch_client(self.ch_url.clone());
        let mut accepted = 0usize;
        let mut last_err: Option<anyhow::Error> = None;

        // 1. Retries, oldest first, each with the token it was born with.
        loop {
            let Some(batch) = self.pending.lock().await.front().cloned() else {
                break;
            };
            match insert_batch(&ch, &batch).await {
                Ok(()) => {
                    accepted += batch.rows.len();
                    self.pending.lock().await.pop_front();
                }
                Err(e) => {
                    last_err = Some(e);
                    break; // keep order: nothing newer is sent past a stuck batch
                }
            }
        }

        // 2. The live buffer, as a fresh immutable batch.
        let drained: Vec<(Key, f64)> = {
            let mut buf = self.buffer.lock().await;
            buf.drain().collect()
        };
        if !drained.is_empty() {
            let batch = MeterBatch {
                token: uuid::Uuid::new_v4().to_string(),
                day: days_since_epoch(chrono::Utc::now().date_naive()),
                rows: drained,
            };
            // A stuck retry means the server is not taking writes: queue this
            // one behind it rather than jump the line (a later batch landing
            // before an earlier one is harmless to a Summing table, but one
            // path is easier to reason about than two).
            let result = if last_err.is_some() {
                Err(anyhow::anyhow!("pending batch retry failed first"))
            } else {
                insert_batch(&ch, &batch).await
            };
            match result {
                Ok(()) => accepted += batch.rows.len(),
                Err(e) => {
                    self.enqueue_failed(batch).await;
                    if last_err.is_none() {
                        last_err = Some(e);
                    }
                }
            }
        }

        match last_err {
            None => {
                tracelane_shared::degradation::resolve(
                    tracelane_shared::degradation::Degradation::MeterFlushFailed,
                );
                Ok(accepted)
            }
            Some(e) => {
                tracing::warn!(error = %e, "meter sink flush failed; batch held for an unchanged retry");
                tracelane_shared::degradation::note(
                    tracelane_shared::degradation::Degradation::MeterFlushFailed,
                );
                Err(e)
            }
        }
    }

    /// Queue a failed batch for retry, bounded — the OLDEST is dropped and
    /// counted when the cap is hit.
    async fn enqueue_failed(&self, batch: MeterBatch) {
        let mut q = self.pending.lock().await;
        if q.len() >= PENDING_BATCH_CAP {
            q.pop_front();
            tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::MeterBatchDropped,
            );
        }
        q.push_back(batch);
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

/// ONE INSERT for one immutable batch, carrying its dedup token. ClickHouse
/// dedups a repeated token within `meter_counters`' `non_replicated_deduplication_window`
/// (migration 28) — the retry of a batch whose first attempt committed but
/// lost its response is accepted and discarded server-side.
///
/// # Errors
/// The insert's init / row-write / commit error, unchanged.
async fn insert_batch(ch: &clickhouse::Client, batch: &MeterBatch) -> anyhow::Result<()> {
    let mut insert = ch
        .insert("meter_counters")
        .map_err(|e| anyhow::anyhow!("meter_counters insert init failed: {e}"))?
        .with_option("insert_deduplication_token", batch.token.as_str());
    for ((tenant_id, meter, dim), value) in &batch.rows {
        insert
            .write(&MeterCounterRow {
                tenant_id,
                day: batch.day,
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
    static METER_EPISODE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
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

    /// C1 class (`billing::meter::Recorder`'s own fix) + B-469: a failed flush
    /// must move the degradation counter AND keep the batch — as an IMMUTABLE
    /// pending batch with its token, never merged back into the live buffer
    /// (that merge is how a committed-but-unacknowledged insert was counted
    /// twice).
    #[tokio::test]
    async fn a_failed_flush_holds_the_batch_unchanged_and_notes_degradation() {
        use tracelane_shared::degradation::{Degradation, count};
        let _episode_guard = METER_EPISODE_TEST_LOCK.lock().await;
        // Port 1 / an address nothing listens on: the insert will fail to
        // connect, exercising the failure path without a real ClickHouse.
        let sink = MeterSink::new("http://127.0.0.1:1".to_string());
        sink.record(&t(), UsageMeter::IngestBytes, "", 42.0).await;
        let before = count(Degradation::MeterFlushFailed);
        let result = sink.flush().await;
        let after = count(Degradation::MeterFlushFailed);
        assert!(result.is_err(), "a connect failure must surface as Err");
        assert!(after > before, "a failed flush must note the degradation");
        assert!(
            sink.buffer.lock().await.is_empty(),
            "the failed rows must NOT be merged back into the live buffer"
        );
        let pending = sink.pending_batches().await;
        assert_eq!(pending.len(), 1, "the failed batch waits for retry");
        let first = &pending[0];
        assert_eq!(first.rows.len(), 1);
        assert_eq!(first.rows[0].1, 42.0);
        assert_eq!(first.token.len(), 36, "a uuid token travels with the batch");

        // A second failed flush with NEW usage: a second batch, a different
        // token, the first batch byte-identical — nothing merged.
        sink.record(&t(), UsageMeter::IngestBytes, "", 8.0).await;
        assert!(sink.flush().await.is_err());
        let pending = sink.pending_batches().await;
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].token, first.token);
        assert_eq!(pending[0].rows, first.rows);
        assert_ne!(pending[1].token, first.token);
        assert_eq!(pending[1].rows[0].1, 8.0);
    }

    /// **B-469 / founder 1b (2026-09-21): the retried batch is BYTE-IDENTICAL on the
    /// wire.** A mock ClickHouse records two `insert_batch` calls for ONE
    /// `MeterBatch`; the request bodies (the RowBinary block, LZ4-framed by the
    /// client) and the `insert_deduplication_token` query parameter must be equal
    /// byte for byte. Dedup by TOKEN does not strictly need identical bytes — the
    /// server keys on the token within the partition — but identical bytes are
    /// what make the token honest: a retry that re-derived the day or re-drained
    /// the buffer would carry the same token over DIFFERENT rows, which is a
    /// silent under- or over-count the server would happily accept. The batch's
    /// `day` is frozen for the same reason: `PARTITION BY toYYYYMM(day)` and the
    /// server dedups within a partition, so a retry across a month boundary that
    /// re-read the clock would leave the window and be summed twice.
    #[tokio::test]
    async fn a_retried_batch_is_byte_identical_on_the_wire_with_the_same_token() {
        use wiremock::matchers::method;
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let ch = crate::clickhouse_query::ch_client(server.uri());
        let batch = MeterBatch {
            token: uuid::Uuid::new_v4().to_string(),
            day: days_since_epoch(chrono::Utc::now().date_naive()),
            rows: vec![
                (
                    (t().to_string(), UsageMeter::IngestBytes, String::new()),
                    1234.0,
                ),
                (
                    (
                        t().to_string(),
                        UsageMeter::KeyOutputTokens,
                        "key-a".to_string(),
                    ),
                    56.0,
                ),
            ],
        };
        insert_batch(&ch, &batch).await.expect("first insert");
        insert_batch(&ch, &batch).await.expect("the retry");
        let reqs = server.received_requests().await.expect("recorded");
        assert_eq!(reqs.len(), 2, "two INSERTs reached the server");
        let (a, b) = (&reqs[0], &reqs[1]);
        assert_eq!(
            a.url.query(),
            b.url.query(),
            "same query string (same statement, same token)"
        );
        let q = a.url.query().unwrap_or_default();
        assert!(
            q.contains(&format!("insert_deduplication_token={}", batch.token)),
            "the dedup token rides as a query parameter: {q}"
        );
        assert!(!a.body.is_empty(), "a RowBinary body was sent");
        assert_eq!(
            a.body, b.body,
            "the retried body is byte-identical to the first"
        );
        // Negative control: a DIFFERENT batch with the same rows but a fresh token is
        // told apart by the token, never by the bytes — that is the server's key.
        let other = MeterBatch {
            token: uuid::Uuid::new_v4().to_string(),
            ..batch.clone()
        };
        insert_batch(&ch, &other).await.expect("third insert");
        let reqs = server.received_requests().await.expect("recorded");
        assert_eq!(reqs[2].body, a.body, "same rows ⇒ same bytes …");
        assert_ne!(
            reqs[2].url.query(),
            a.url.query(),
            "… only the token differs"
        );
    }

    /// The queue is bounded: the OLDEST batch is dropped and COUNTED, the
    /// newest kept.
    #[tokio::test]
    async fn the_pending_queue_drops_the_oldest_batch_at_the_cap_and_counts_it() {
        use tracelane_shared::degradation::{Degradation, count};
        let sink = MeterSink::new("http://127.0.0.1:1".to_string());
        for i in 0..PENDING_BATCH_CAP {
            sink.enqueue_failed(MeterBatch {
                token: format!("t{i}"),
                day: 0,
                rows: vec![],
            })
            .await;
        }
        let before = count(Degradation::MeterBatchDropped);
        sink.enqueue_failed(MeterBatch {
            token: "newest".into(),
            day: 0,
            rows: vec![],
        })
        .await;
        let after = count(Degradation::MeterBatchDropped);
        assert!(after > before, "the overflow is counted");
        let q = sink.pending_batches().await;
        assert_eq!(q.len(), PENDING_BATCH_CAP);
        assert_eq!(q[0].token, "t1", "t0 — the oldest — was the one dropped");
        assert_eq!(q[PENDING_BATCH_CAP - 1].token, "newest");
    }

    #[tokio::test]
    async fn empty_buffer_flushes_as_a_noop() {
        let _episode_guard = METER_EPISODE_TEST_LOCK.lock().await;
        let sink = MeterSink::new("http://127.0.0.1:1".to_string());
        assert_eq!(sink.flush().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn recovered_meter_flush_closes_episode_after_pending_batch_lands() {
        use tracelane_shared::degradation::{Degradation, is_open, note, resolve};
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let _episode_guard = METER_EPISODE_TEST_LOCK.lock().await;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let sink = MeterSink::new(server.uri());
        sink.pending.lock().await.push_back(MeterBatch {
            token: "b602-retry".into(),
            day: 1,
            rows: vec![(
                (t().to_string(), UsageMeter::IngestBytes, String::new()),
                42.0,
            )],
        });
        let kind = Degradation::MeterFlushFailed;
        resolve(kind);
        note(kind);
        assert_eq!(sink.flush().await.unwrap(), 1);
        assert!(sink.pending.lock().await.is_empty());
        assert!(
            !is_open(kind),
            "accepted pending batch closes the meter episode"
        );
    }

    /// **B-469 proof, both directions, on a real server.** The same immutable
    /// batch inserted twice with the same `insert_deduplication_token` — the
    /// "committed, response lost, retried unchanged" path — sums ONCE on the
    /// real `meter_counters` (migration 28's window), and TWICE on a clone of
    /// the table with the window at 0, proving the table SETTING is the
    /// control and the token alone is not. Then the sink itself: a batch that
    /// already landed, queued as if its response had been lost, is retried by
    /// `flush` and does not double.
    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn rev1_a_retried_batch_with_the_same_token_is_counted_once() {
        let Ok(url) = std::env::var("CLICKHOUSE_TEST_URL") else {
            panic!("CLICKHOUSE_TEST_URL not set — this test cannot run, which is not a pass");
        };
        let root = clickhouse::Client::default().with_url(&url);
        root.query("CREATE DATABASE IF NOT EXISTS tracelane")
            .execute()
            .await
            .expect("create database");
        let ch = clickhouse::Client::default()
            .with_url(&url)
            .with_database("tracelane");
        for sql in [
            include_str!("../../../../infra/dev/clickhouse/schema.sql"),
            include_str!(
                "../../../../infra/dev/clickhouse/migrations/24_bill01_meters_blobs_tiering.sql"
            ),
            include_str!(
                "../../../../infra/dev/clickhouse/migrations/28_rev1_meter_counters_dedup_window.sql"
            ),
        ] {
            for stmt in crate::clickhouse_query::split_migration_statements(sql) {
                let _ = ch.query(&stmt).execute().await;
            }
        }
        // The setting is ON the table — read from the server, not assumed from
        // the DDL file.
        let window: String = ch
            .query(
                "SELECT toString(value) FROM system.merge_tree_settings_by_table \
                 WHERE database = 'tracelane' AND table = 'meter_counters' AND name = 'non_replicated_deduplication_window'",
            )
            .fetch_one()
            .await
            .unwrap_or_else(|_| "unreadable".to_string());
        // Older servers lack that system table; fall back to SHOW CREATE.
        if window == "unreadable" {
            let ddl: String = ch
                .query("SHOW CREATE TABLE tracelane.meter_counters")
                .fetch_one()
                .await
                .expect("show create");
            assert!(
                ddl.contains("non_replicated_deduplication_window = 1000"),
                "migration 28 must be applied on the table: {ddl}"
            );
        } else {
            assert_eq!(window, "1000", "migration 28 must be applied on the table");
        }

        let tenant = t().to_string();
        let batch = MeterBatch {
            token: uuid::Uuid::new_v4().to_string(),
            day: days_since_epoch(chrono::Utc::now().date_naive()),
            rows: vec![(
                (tenant.clone(), UsageMeter::IngestBytes, String::new()),
                1000.0,
            )],
        };
        insert_batch(&ch, &batch).await.expect("first insert");
        insert_batch(&ch, &batch)
            .await
            .expect("the retry is ACCEPTED (and discarded)");
        let sum: f64 = ch
            .query("SELECT sum(value) FROM tracelane.meter_counters WHERE tenant_id = ? AND meter = 'ingest_bytes'")
            .bind(&tenant)
            .fetch_one()
            .await
            .unwrap();
        assert_eq!(
            sum, 1000.0,
            "the same token twice must count ONCE — this is B-469"
        );

        // Negative: the SAME rows + token against a clone with no dedup window
        // sum twice — the setting is the control.
        root.query("DROP TABLE IF EXISTS tracelane.meter_counters_nodedup")
            .execute()
            .await
            .unwrap();
        root.query(
            "CREATE TABLE tracelane.meter_counters_nodedup AS tracelane.meter_counters \
             ENGINE = SummingMergeTree(value) PARTITION BY toYYYYMM(day) \
             ORDER BY (tenant_id, day, meter, dim, source)",
        )
        .execute()
        .await
        .expect("clone without the window");
        for _ in 0..2 {
            let mut insert = ch
                .insert("meter_counters_nodedup")
                .unwrap()
                .with_option("insert_deduplication_token", batch.token.as_str());
            for ((tenant_id, meter, dim), value) in &batch.rows {
                insert
                    .write(&MeterCounterRow {
                        tenant_id,
                        day: batch.day,
                        meter: meter.as_str(),
                        dim,
                        value: *value,
                        source: "gateway",
                    })
                    .await
                    .unwrap();
            }
            insert.end().await.unwrap();
        }
        let doubled: f64 = ch
            .query("SELECT sum(value) FROM tracelane.meter_counters_nodedup WHERE tenant_id = ?")
            .bind(&tenant)
            .fetch_one()
            .await
            .unwrap();
        assert_eq!(
            doubled, 2000.0,
            "without the window the token is ignored — the setting is the control"
        );
        root.query("DROP TABLE tracelane.meter_counters_nodedup")
            .execute()
            .await
            .unwrap();

        // The sink: a batch that landed but whose response was "lost" sits in
        // `pending`; `flush` retries it unchanged and the total does not move.
        let sink = MeterSink::new(url.clone());
        let landed = MeterBatch {
            token: uuid::Uuid::new_v4().to_string(),
            day: batch.day,
            rows: vec![((tenant.clone(), UsageMeter::EvalRuns, String::new()), 7.0)],
        };
        let ch_default = crate::clickhouse_query::ch_client(url.clone());
        insert_batch(&ch_default, &landed).await.expect("landed");
        sink.enqueue_failed(landed.clone()).await; // as if the response had been lost
        sink.record(&t(), UsageMeter::EvalRuns, "", 2.0).await; // new usage meanwhile
        let accepted = sink.flush().await.expect("retry + new batch both accepted");
        assert_eq!(accepted, 2, "one retried row + one new row");
        assert!(sink.pending_batches().await.is_empty());
        let evals: f64 = ch
            .query("SELECT sum(value) FROM tracelane.meter_counters WHERE tenant_id = ? AND meter = 'eval_runs'")
            .bind(&tenant)
            .fetch_one()
            .await
            .unwrap();
        assert_eq!(evals, 9.0, "7 (once, not twice) + 2");
    }
}

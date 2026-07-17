//! ClickHouse batch writer — drains the span channel into ClickHouse.
//!
//! Batches spans for up to `batch_size` items or `batch_timeout_ms`
//! milliseconds, then flushes with a single `INSERT INTO tracelane.spans`.
//! Batching is critical for ClickHouse write throughput; individual inserts
//! saturate the merge tree far faster than the ReplacingMergeTree can merge.
//!
//! On ClickHouse downtime the batch accumulates in the channel (bounded at
//! 64K) then back-pressures to the receivers. Fault tolerance eval FT-03
//! verifies this behaviour.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use clickhouse::Client;
use serde::Serialize;
use tokio::sync::mpsc;
use tracing::instrument;

use tracelane_shared::TracelaneSpan;

use crate::per_trace_ceiling::{CeilingDecision, PerTraceCeiling};
use crate::tail_sampler::{SampleDecision, SamplingPolicy, TailSampler};
use crate::tenant_config::TenantConfigCache;

/// How long a force-kept trace may sit untouched before `prune()` evicts it.
/// A trace quiet for longer than this is assumed closed (tail-window bound).
const SAMPLER_MAX_TRACE_WINDOW: Duration = Duration::from_secs(600);
/// Cadence of the (O(n)) prune sweep over the sampler's sticky map — coarse so
/// it is not paid per batch.
const SAMPLER_PRUNE_INTERVAL: Duration = Duration::from_secs(60);

/// Span row as stored in ClickHouse.
/// Must match `infra/dev/clickhouse/schema.sql` column order.
#[derive(Debug, Serialize, clickhouse::Row)]
struct SpanRow {
    tenant_id: String,
    trace_id: String,
    span_id: String,
    parent_span_id: Option<String>,
    name: String,
    start_time: i64,
    end_time: i64,
    status_code: u8,
    status_message: String,
    attributes: String,
}

impl From<TracelaneSpan> for SpanRow {
    fn from(s: TracelaneSpan) -> Self {
        // A6: PII redaction on every span attribute payload before any
        // external write. The gateway already redacts audit-row payloads
        // (see `crates/gateway/src/audit.rs::AuditEvent::redact_payload`);
        // ingest must do the same on the span path because span content
        // flows to ClickHouse (and downstream R2). 100%-recall PII +
        // credential rule set lives in `tracelane_policy::pii`.
        let attrs_json = serde_json::to_value(&s.attributes).unwrap_or(serde_json::Value::Null);
        let redacted = tracelane_policy::pii::redact_json(&attrs_json);

        Self {
            tenant_id: s.tenant_id.to_string(),
            trace_id: s.trace_id.to_string(),
            span_id: s.span_id.to_string(),
            parent_span_id: s.parent_span_id.map(|id| id.to_string()),
            name: tracelane_policy::pii::redact(&s.name),
            start_time: s.start_time.timestamp_micros(),
            end_time: s.end_time.map(|t| t.timestamp_micros()).unwrap_or(0),
            status_code: s.status.code as u8,
            status_message: tracelane_policy::pii::redact(&s.status.message.unwrap_or_default()),
            attributes: serde_json::to_string(&redacted).unwrap_or_else(|err| {
                tracing::warn!(
                    span_id = %s.span_id,
                    error = %err,
                    "span attributes serialization failed after PII redact — stored empty"
                );
                String::new()
            }),
        }
    }
}

/// Start the ClickHouse batch writer.
///
/// Drains `span_rx` in batches of up to 2000 spans or 200ms, whichever
/// comes first, then issues a single INSERT.
///
/// # Errors
/// Returns `Err` only on unrecoverable ClickHouse errors. Transient errors
/// are retried up to 3 times with 500ms backoff before propagating.
/// Build the ClickHouse client. Centralised so it ALWAYS authenticates as the
/// configured `CLICKHOUSE_USER`, never the default user — connecting as default
/// silently fails inserts against a credentialed server and crash-loops this
/// writer (ADR-042; the parked Phase-8 smoke first surfaced it). Regression
/// test: `ch_client_sends_configured_user`.
pub(crate) fn ch_client(url: &str, user: &str, password: &str, db: &str) -> Client {
    Client::default()
        .with_url(url)
        .with_user(user)
        .with_password(password)
        .with_database(db)
}

#[instrument(
    skip(
        sampler,
        tenant_cfg,
        ceiling,
        span_rx,
        clickhouse_user,
        clickhouse_password,
        clickhouse_db
    ),
    fields(clickhouse_url = %clickhouse_url)
)]
pub async fn run(
    clickhouse_url: String,
    clickhouse_user: String,
    clickhouse_password: String,
    clickhouse_db: String,
    sampler: Arc<TailSampler>,
    tenant_cfg: Arc<TenantConfigCache>,
    ceiling: Arc<PerTraceCeiling>,
    mut span_rx: mpsc::Receiver<crate::span_envelope::SpanEnvelope>,
    batch_size: usize,
    batch_timeout: std::time::Duration,
) -> Result<()> {
    let client = ch_client(
        &clickhouse_url,
        &clickhouse_user,
        &clickhouse_password,
        &clickhouse_db,
    );

    tracing::info!("ClickHouse batch writer started");

    // batch_size / batch_timeout come from Config (INGEST_BATCH_SIZE /
    // INGEST_BATCH_TIMEOUT_MS). L3 sweep 2026-07-03: these knobs were
    // parsed + validated but ignored — the writer hardcoded 2000/200ms,
    // so an operator's tuning was a silent no-op.
    let mut last_prune = Instant::now();

    loop {
        let mut batch: Vec<SpanRow> = Vec::with_capacity(batch_size);
        // Ack handles for the NATS-sourced spans in `batch`. Acked ONLY after a
        // durable flush (#81 ack-after-write) — so a failed write leaves them
        // unacked and JetStream redelivers. OTLP spans contribute no handle.
        let mut pending_acks: Vec<async_nats::jetstream::Message> = Vec::new();
        let mut dropped = 0usize;
        let deadline = tokio::time::Instant::now() + batch_timeout;

        // Collect spans until batch is full or timeout fires
        loop {
            match tokio::time::timeout_at(deadline, span_rx.recv()).await {
                Ok(Some(crate::span_envelope::SpanEnvelope { span, ack })) => {
                    // ADR-048: resolve the tenant's capture policy. `Full` keeps
                    // every span (Business/Enterprise/Audit-SKU); `Tail`
                    // rate-samples. Cache hit is in-memory; a miss costs one
                    // resolve then caches. Fail-safe to Tail.
                    let trace_id = span.trace_id; // Copy before `span` is moved
                    let tenant_uuid = *span.tenant_id.as_uuid(); // Copy before move
                    let policy = tenant_cfg.policy_for(tenant_uuid).await;
                    // PP-O2 tail sampling — keep every error/intervention trace,
                    // rate-sample the rest. Dropped spans are never written.
                    match sample_one(&sampler, span, policy) {
                        Some(row) => {
                            // ADR-048 D4.3: the per-trace ceiling clips a runaway
                            // trace's tail even when sampling (or Full) kept it —
                            // bounds the fat-trace cost class on ALL tiers. An
                            // over-ceiling span is an INTENTIONAL, counted drop
                            // (not the #81 silent drop): ack it so JetStream
                            // doesn't redeliver, and never write it.
                            if ceiling.check_and_record(
                                tenant_uuid,
                                trace_id,
                                row_byte_estimate(&row),
                            ) == CeilingDecision::Exceeded
                            {
                                // tenant_id included so the COGS live eval can
                                // trace one tenant's span end-to-end in the logs.
                                tracing::debug!(
                                    tenant_id = %tenant_uuid,
                                    %trace_id,
                                    ?policy,
                                    "writer span decision: DROPPED (per-trace ceiling exceeded, counted)"
                                );
                                if let Some(m) = ack {
                                    ack_one(m).await;
                                }
                                dropped += 1;
                            } else {
                                tracing::debug!(
                                    tenant_id = %tenant_uuid,
                                    %trace_id,
                                    ?policy,
                                    "writer span decision: KEPT → batched for ClickHouse"
                                );
                                batch.push(row);
                                if let Some(m) = ack {
                                    pending_acks.push(m);
                                }
                                if batch.len() >= batch_size {
                                    break;
                                }
                            }
                        }
                        None => {
                            // Sampled out: an intentional drop, never written —
                            // ack now so JetStream doesn't redeliver a span we
                            // deliberately chose to skip.
                            tracing::debug!(
                                tenant_id = %tenant_uuid,
                                %trace_id,
                                ?policy,
                                "writer span decision: DROPPED (tail-sampled out)"
                            );
                            if let Some(m) = ack {
                                ack_one(m).await;
                            }
                            dropped += 1;
                        }
                    }
                }
                Ok(None) => {
                    // Channel closed — flush remaining and exit
                    if !batch.is_empty() {
                        match flush(&client, &batch).await {
                            Ok(()) => {
                                ack_all(pending_acks).await;
                                // fail-open — same as the steady-state path.
                                crate::federation::write_signals(&client, &federation_rows(&batch))
                                    .await;
                            }
                            Err(err) => tracing::error!(
                                error = %err,
                                spans = batch.len(),
                                "final ClickHouse flush on shutdown failed — messages left UNACKED for JetStream redelivery"
                            ),
                        }
                    }
                    tracing::info!("span channel closed; batch writer exiting");
                    return Ok(());
                }
                Err(_) => break, // timeout
            }
        }

        if !batch.is_empty() {
            let n = batch.len();
            // TODO(T9): per-tenant retention — the global 90d `tracelane.spans` TTL silently evicts any span arriving with an old start_time (replay / backfill / clock-skew) on the next TTL merge, even though the insert succeeds; T9 must make retention per-tenant instead of one global TTL.
            // Durable-then-ack (#81): if flush fails, `?` propagates BEFORE the
            // acks, so the messages stay unacked and JetStream redelivers them
            // (zero-loss, FT-03). A redelivered duplicate is idempotent — the
            // spans table collapses it on merge (ReplacingMergeTree).
            flush(&client, &batch)
                .await
                .context("ClickHouse batch flush failed")?;
            ack_all(pending_acks).await;
            // signal aggregates from the spans just durably written. Best-effort
            // + fail-open — never affects span durability or the acks above.
            crate::federation::write_signals(&client, &federation_rows(&batch)).await;
            tracing::debug!(spans = n, dropped, "flushed batch to ClickHouse");
        }

        // Bound the sampler's sticky map. Cheap vs the flush and only every
        // SAMPLER_PRUNE_INTERVAL, so the O(n) sweep isn't paid per batch.
        if last_prune.elapsed() >= SAMPLER_PRUNE_INTERVAL {
            sampler.prune(SAMPLER_MAX_TRACE_WINDOW);
            ceiling.prune(SAMPLER_MAX_TRACE_WINDOW);
            last_prune = Instant::now();
        }
    }
}

/// Apply the tail-sampling gate to one span. Returns `Some(row)` to keep (push
/// to the batch) or `None` to drop.
///
/// unit-testable without a live ClickHouse: a test asserts a 0%-rate sampler
/// drops a clean span here but keeps an error span — which fails if this gate
/// is ever removed (the bug this fixes was that the sampler was never called).
fn sample_one(
    sampler: &TailSampler,
    span: TracelaneSpan,
    policy: SamplingPolicy,
) -> Option<SpanRow> {
    let kept = sampler.evaluate(&span, policy) == SampleDecision::Keep;
    // Sampler-verdict log (kept across the #81 cleanup; the rest of the DIAG
    // instrumentation was removed). DEBUG, not info: it fires per span, so it is
    // off in prod (RUST_LOG=info) and on-demand for debugging drops. `kept=false`
    // ⇒ the span is intentionally dropped here and never written (the silent
    // tail-sampling drop that masqueraded as a write failure in #81).
    tracing::debug!(
        span_id = %span.span_id,
        trace_id = %span.trace_id,
        kept,
        "tail-sampler verdict"
    );
    kept.then(|| SpanRow::from(span))
}

/// Extract the anonymized federation signals from a durably-flushed span batch
/// extra query — and keeps only spans that carry a `tracelane_aft_id`.
fn federation_rows(batch: &[SpanRow]) -> Vec<crate::federation::FederationRow> {
    batch
        .iter()
        .filter_map(|r| {
            crate::federation::row_from(&r.tenant_id, &r.attributes, r.start_time, &r.name)
        })
        .collect()
}

/// Cheap byte estimate for a kept span row, feeding the per-trace byte ceiling
/// (ADR-048 D4.3). Sums the variable-length text fields plus a fixed overhead
/// for ids / timestamps / status_code — not the exact ClickHouse-stored size,
/// but a stable, allocation-free proxy for how much a trace is costing.
fn row_byte_estimate(row: &SpanRow) -> u64 {
    const FIXED_OVERHEAD: u64 = 128; // ids + two i64 times + status_code
    (row.attributes.len()
        + row.name.len()
        + row.status_message.len()
        + row.parent_span_id.as_ref().map_or(0, |s| s.len())) as u64
        + FIXED_OVERHEAD
}

/// Ack one JetStream message (best-effort). A failed ack ⇒ redelivery ⇒ a
/// duplicate insert, which the spans ReplacingMergeTree collapses on merge.
async fn ack_one(msg: async_nats::jetstream::Message) {
    if let Err(e) = msg.ack().await {
        tracing::warn!(error = %e, "JetStream ack failed after durable write; message may redeliver (idempotent insert)");
    }
}

/// Ack every message whose span was durably written this batch (#81).
async fn ack_all(msgs: Vec<async_nats::jetstream::Message>) {
    for m in msgs {
        ack_one(m).await;
    }
}

/// Flush a batch of span rows to ClickHouse with up to 3 retries.
///
/// Treats the entire write phase (all `insert.write()` calls + `insert.end()`)
/// as one atomic attempt so that a transient write failure is retried rather
/// than propagating immediately via `?`.
async fn flush(client: &Client, rows: &[SpanRow]) -> Result<()> {
    for attempt in 0..3u32 {
        let result: Result<()> = async {
            let mut insert = client
                .insert("tracelane.spans")
                .context("ClickHouse insert init")?;
            for row in rows {
                insert.write(row).await.context("ClickHouse row write")?;
            }
            insert.end().await.context("ClickHouse insert end")?;
            Ok(())
        }
        .await;

        match result {
            Ok(()) => return Ok(()),
            Err(e) if attempt < 2 => {
                tracing::warn!(attempt, error = %e, "ClickHouse insert failed, retrying");
                tokio::time::sleep(std::time::Duration::from_millis(
                    500 * u64::from(attempt + 1),
                ))
                .await;
            }
            // Surface the failure LOUDLY before propagating (#81 P0: a write that
            // dies must never be silent). The caller's `?` then crashes the
            // process via try_join!; with ack-after-write the messages stay
            // unacked and JetStream redelivers them — no span is lost.
            Err(e) => {
                tracing::error!(
                    error = %e,
                    rows = rows.len(),
                    "ClickHouse insert FAILED after 3 attempts — spans NOT written; surfacing and propagating (messages stay unacked for JetStream redelivery)"
                );
                return Err(e);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_row() -> SpanRow {
        SpanRow {
            tenant_id: "00000000-0000-0000-0000-000000000001".into(),
            trace_id: "trace-1".into(),
            span_id: "span-1".into(),
            parent_span_id: None,
            name: "llm.chat".into(),
            start_time: 1,
            end_time: 2,
            status_code: 0,
            status_message: String::new(),
            attributes: "{}".into(),
        }
    }

    fn client_for(url: &str) -> Client {
        Client::default().with_url(url).with_database("tracelane")
    }

    fn tspan(code: tracelane_shared::SpanStatusCode) -> TracelaneSpan {
        use tracelane_shared::{SpanAttributes, SpanStatus, TenantId};
        TracelaneSpan {
            span_id: uuid::Uuid::new_v4(),
            trace_id: uuid::Uuid::new_v4(),
            parent_span_id: None,
            tenant_id: TenantId::from_jwt_claim(uuid::Uuid::from_u128(1)),
            name: "op".into(),
            start_time: chrono::Utc::now(),
            end_time: None,
            attributes: SpanAttributes::default(),
            status: SpanStatus {
                code,
                message: None,
            },
        }
    }

    /// sampler. With a 0% baseline a clean span is dropped (never written) while
    /// error / intervention spans are kept — exercising the exact gate the recv
    /// loop calls, so removing the sampler wiring breaks this test.
    #[test]
    fn writer_gate_applies_tail_sampling() {
        use tracelane_shared::{Intervention, SpanStatusCode};
        let sampler = TailSampler::with_rate(0);

        assert!(
            sample_one(&sampler, tspan(SpanStatusCode::Ok), SamplingPolicy::Tail).is_none(),
            "0%-rate clean span must be dropped under Tail"
        );
        assert!(
            sample_one(&sampler, tspan(SpanStatusCode::Error), SamplingPolicy::Tail).is_some(),
            "error span must be kept"
        );

        let mut iv = tspan(SpanStatusCode::Ok);
        iv.attributes.tracelane_intervention = Some(Intervention::Block);
        assert!(
            sample_one(&sampler, iv, SamplingPolicy::Tail).is_some(),
            "intervention span must be kept"
        );

        // ADR-048: the SAME 0%-rate clean span that Tail drops is KEPT under
        // Full — proving the policy actually gates the writer's persist path.
        assert!(
            sample_one(&sampler, tspan(SpanStatusCode::Ok), SamplingPolicy::Full).is_some(),
            "Full capture must keep a clean span the tail rate would drop"
        );
    }

    #[tokio::test]
    async fn ch_client_sends_configured_user() {
        // Regression (ADR-042): the writer MUST authenticate as CLICKHOUSE_USER,
        // not the default user. Connecting as default silently fails inserts on a
        // credentialed ClickHouse and crash-loops the batch writer — no traces
        // persist (the Phase-8 smoke finding). Assert the configured user reaches
        // the wire.
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let client = ch_client(
            &server.uri(),
            "tracelane-regress",
            "pw-regress",
            "tracelane",
        );
        let _ = client.query("SELECT 1").execute().await;
        let reqs = server.received_requests().await.unwrap();
        assert!(!reqs.is_empty(), "CH client made no request");
        let r = &reqs[0];
        let url = r.url.to_string();
        let headers = format!("{:?}", r.headers);
        assert!(
            url.contains("tracelane-regress") || headers.contains("tracelane-regress"),
            "CH client did not send the configured user (default?): url={url} headers={headers}"
        );
    }

    /// FT-03 chaos: ClickHouse is unreachable for the first insert attempts
    /// (transient downtime / network partition), then recovers. The writer's
    /// retry loop (3 attempts, 500ms backoff) must NOT drop the batch — it
    /// retries and the rows land once ClickHouse is back. This is the
    /// zero-span-loss guarantee FT-03 documents (NATS holds the unacked
    /// message until this write finally succeeds).
    #[tokio::test]
    async fn ft03_clickhouse_retry_recovers_after_transient_outage() {
        let server = MockServer::start().await;

        // First insert: 503 (ClickHouse down). Subsequent inserts: 200.
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503).set_body_string("service unavailable"))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client = client_for(&server.uri());
        flush(&client, &[sample_row()])
            .await
            .expect("retry loop must recover the batch once ClickHouse is back");

        // The down attempt + the successful retry both hit the server, so the
        // batch was retried rather than dropped.
        let hits = server.received_requests().await.unwrap().len();
        assert!(
            hits >= 2,
            "expected a retry after the 503, saw {hits} request(s)"
        );
    }

    /// FT-03 chaos: a persistent ClickHouse outage exhausts the 3 attempts and
    /// propagates `Err` rather than silently dropping the batch. The caller
    /// (`run`) then leaves the NATS message unacked so it is redelivered — no
    /// span is lost, the failure is surfaced for the operator.
    #[tokio::test]
    async fn ft03_persistent_clickhouse_outage_propagates_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let client = client_for(&server.uri());
        let result = flush(&client, &[sample_row()]).await;
        assert!(
            result.is_err(),
            "a persistent outage must surface as Err, not a silent drop",
        );
        let hits = server.received_requests().await.unwrap().len();
        assert!(hits >= 3, "all 3 attempts must be made, saw {hits}");
    }

    /// Regression for #81 (the REAL cause): a consumed clean span must reach a
    /// ClickHouse INSERT. The bug was the tail sampler (default 10%) silently
    /// dropping benign spans before any insert — "consumed but not written",
    /// no flush, no error. At 100% the clean span MUST produce an insert; at the
    /// 0% baseline the SAME span produces NONE (the silent drop), which the
    /// contrast pins. Both rates are deterministic (0 / ≥100 short-circuit the
    /// per-trace hash), so this is not flaky.
    async fn insert_requests_for_rate(rate: u8) -> usize {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let (tx, rx) = mpsc::channel::<crate::span_envelope::SpanEnvelope>(8);
        let sampler = Arc::new(TailSampler::with_rate(rate));
        // default_tail → every tenant resolves Tail, so the `rate` arg governs
        // keep/drop exactly as before this wiring (non-regressing).
        let tenant_cfg = Arc::new(crate::tenant_config::TenantConfigCache::default_tail());
        // Generous default ceiling — does not interfere with the 1-span tests.
        let ceiling = Arc::new(crate::per_trace_ceiling::PerTraceCeiling::new());
        let url = server.uri();
        let handle = tokio::spawn(async move {
            run(
                url,
                "default".into(),
                String::new(),
                "tracelane".into(),
                sampler,
                tenant_cfg,
                ceiling,
                rx,
                2000,
                std::time::Duration::from_millis(200),
            )
            .await
        });
        // One clean (Ok, no-intervention) span — exactly the GC-TRACE-LOOP shape.
        // OTLP-style envelope (ack=None): exercises the write path without a real
        // JetStream message (the ack-after-write path needs the live ci/ stack).
        tx.send(crate::span_envelope::SpanEnvelope::otlp(tspan(
            tracelane_shared::SpanStatusCode::Ok,
        )))
        .await
        .unwrap();
        drop(tx); // close the channel → run() flushes the remainder + exits Ok
        handle.await.unwrap().expect("writer run should exit Ok");
        server.received_requests().await.unwrap().len()
    }

    /// Build a writer-test cache whose resolver pins ONE tenant to an explicit
    /// [`SamplingPolicy`] (every other tenant → Tail). Lets a `run()`-level test
    /// drive the writer's *policy* gate — not just the sampler rate or the pure
    /// `sample_one` — so a regression in the policy→persist path is caught in CI.
    fn cache_resolving(tenant: uuid::Uuid, policy: SamplingPolicy) -> Arc<TenantConfigCache> {
        use crate::tenant_config::{ResolveFn, TenantConfig};
        let resolver: ResolveFn = Arc::new(move |t: uuid::Uuid| {
            Box::pin(async move {
                if t == tenant {
                    TenantConfig {
                        policy,
                        monthly_span_quota: 0, // unlimited — isolate the policy gate
                        billing_email: None,
                    }
                } else {
                    TenantConfig::default() // Tail
                }
            })
        });
        Arc::new(TenantConfigCache::new(
            resolver,
            std::time::Duration::from_secs(300),
        ))
    }

    /// Drive the writer `run()` once with a chosen sampler `rate` + tenant-config
    /// `cache`, send one clean (Ok, no-intervention) span for `tspan()`'s tenant,
    /// and return how many ClickHouse inserts hit the mock — the live COGS eval's
    /// `chCount` observable, at the ingest layer.
    async fn insert_requests_with(rate: u8, tenant_cfg: Arc<TenantConfigCache>) -> usize {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let (tx, rx) = mpsc::channel::<crate::span_envelope::SpanEnvelope>(8);
        let sampler = Arc::new(TailSampler::with_rate(rate));
        let ceiling = Arc::new(crate::per_trace_ceiling::PerTraceCeiling::new());
        let url = server.uri();
        let handle = tokio::spawn(async move {
            run(
                url,
                "default".into(),
                String::new(),
                "tracelane".into(),
                sampler,
                tenant_cfg,
                ceiling,
                rx,
                2000,
                std::time::Duration::from_millis(200),
            )
            .await
        });
        tx.send(crate::span_envelope::SpanEnvelope::otlp(tspan(
            tracelane_shared::SpanStatusCode::Ok,
        )))
        .await
        .unwrap();
        drop(tx);
        handle.await.unwrap().expect("writer run should exit Ok");
        server.received_requests().await.unwrap().len()
    }

    /// Writer **admit** gate (not a persistence proof): with the tail rate pinned
    /// to 0 — so tail would drop EVERY clean span — a tenant the resolver makes
    /// `Full` keeps its clean span and ISSUES a ClickHouse insert. SCOPE LIMIT:
    /// the mock CH 200s any POST, so this proves the writer *attempts* the insert,
    /// NOT that a real ClickHouse accepts it and the row *persists* — a mock can't
    /// model server-side TTL/merge eviction (the COGS-eval bug where a born-expired
    /// span committed then vanished). **Persistence is proven only by the live COGS
    /// eval asserting `count() >= 1` against real ClickHouse** (ci/run-cogs.sh) —
    /// that is the gate, not this test.
    #[tokio::test]
    async fn full_policy_clean_span_reaches_clickhouse_at_tail_rate_zero() {
        let tenant = uuid::Uuid::from_u128(1); // matches tspan()'s tenant
        let cache = cache_resolving(tenant, SamplingPolicy::Full);
        assert!(
            insert_requests_with(0, cache).await >= 1,
            "a Full-policy tenant's clean span at tail rate 0 must produce a ClickHouse insert \
             (COGS assertion A — Full keeps a span tail would drop)"
        );
    }

    /// COGS eval **assertion B** at the ingest layer: the SAME clean span under a
    /// `Tail`-resolved tenant at rate 0 is dropped before any insert — proving it
    /// is the writer's POLICY gate (not the rate alone) that governs persistence.
    #[tokio::test]
    async fn tail_policy_clean_span_is_dropped_at_tail_rate_zero() {
        let tenant = uuid::Uuid::from_u128(1);
        let cache = cache_resolving(tenant, SamplingPolicy::Tail);
        assert_eq!(
            insert_requests_with(0, cache).await,
            0,
            "a Tail-policy tenant's clean span at rate 0 is sampled out before any insert"
        );
    }

    #[tokio::test]
    async fn consumed_clean_span_at_full_rate_reaches_clickhouse_insert() {
        assert!(
            insert_requests_for_rate(100).await >= 1,
            "a consumed clean span at 100% sampling must produce a ClickHouse insert \
             (the #81 bug produced zero — sampled out before the insert)"
        );
    }

    #[tokio::test]
    async fn clean_span_at_zero_baseline_is_dropped_before_insert() {
        assert_eq!(
            insert_requests_for_rate(0).await,
            0,
            "a clean span at the 0% baseline is tail-sampled out before any insert \
             — this is the silent drop that masquerades as a write failure (#81)"
        );
    }
}

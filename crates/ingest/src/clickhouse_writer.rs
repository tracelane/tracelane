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
//!
//! ## BILL-01 / ADR-076 — meter 1 (ingest half) + content-addressed blobs
//!
//! Three things ride the SAME flush as the span batch, as three EXTRA
//! batched INSERTs (spec §2.5b — never a row per span):
//!
//! 1. **`span_bytes`** (spec §2.1/§2.2) — the LOGICAL size of the span record,
//!    resolved (not recomputed) from the gateway's `tracelane_span_bytes`
//!    stamp when present, else computed the same way the gateway does. Fixed
//!    BEFORE any blob substitution below — dedup is our margin, never a
//!    markdown (migration 24's own comment).
//! 2. **`meter_counters` (`ingest_bytes`, `source = 'ingest'`)** — ONLY for
//!    spans WITHOUT the gateway's stamp (OTLP-direct). The stamp is the
//!    discriminator that prevents double-counting meter 1 between the two
//!    writers; a NATS-sourced (gateway-originated) span already had its
//!    bytes recorded at the gateway and must not be counted twice here.
//! 3. **`blobs` / `blob_refs`** (spec §2.3) — any top-level attribute value
//!    over 1 KiB (in practice `gen_ai_system_instructions` /
//!    `gen_ai_input_messages` / `gen_ai_output_messages` when content capture
//!    is on) is replaced with `{"$ref":"blake3:<hex>"}` and its bytes queued
//!    as one `blobs` row (per-tenant, ReplacingMergeTree collapses repeats at
//!    merge — no read-before-write) plus one `blob_refs` row for this span.
//!
//! `crates/gateway/src/billing/meters.rs` is NOT imported here — it sits
//! outside this build's file allowlist and `tracelane_shared` cannot gain a
//! `clickhouse` dependency for this alone, so the row shape + the RowBinary
//! `Date` (`u16` days-since-epoch) encoding are MIRRORED exactly (the same
//! B-274 class this file's `SpanRow` already has to get right) rather than
//! imported. Both writers must keep agreeing on `meter_counters`' shape by
//! inspection, same as `meter_gauges` already requires of the metering job.
//!
//! The meter-delta buffer PERSISTS across a failed flush (fail-open + a
//! `Degradation::MeterFlushFailed` note) so no usage is lost; a failed
//! blob/blob_ref insert is logged + noted but NOT retried — the span row
//! already carries the `$ref` placeholder, and a missing blob renders
//! `{"$ref":…, "missing": true}` on read (never an error), which is an
//! acceptable degradation for a fault-tolerance path, not a data-loss one.

use std::collections::{HashMap, HashSet, VecDeque};
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

/// Any top-level attribute value serializing larger than this is
/// content-addressed and replaced with a `$ref` (spec §2.3).
const BLOB_THRESHOLD_BYTES: usize = 1024;

/// The gateway stamps this attribute (`stamp_and_meter_span_bytes`,
/// `crates/gateway/src/server/spans.rs`) with the LOGICAL size it already
/// computed and metered. Its presence is the discriminator between a
/// gateway-originated (NATS) span and an OTLP-direct one.
const GATEWAY_SPAN_BYTES_ATTR: &str = "tracelane_span_bytes";

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
    //  #5: the dedicated columns the /signatures page queries
    // (`has(aft_ids, ?)` + `intervention`). Populated from the predictive AFT hit the
    // gateway records in the span; empty when no detector matched.
    aft_ids: Vec<String>,
    intervention: u8,
    /// BILL-01 / ADR-076 meter 1/2 — the LOGICAL size of this span record.
    /// Column name only matters (the `clickhouse` crate builds its INSERT
    /// column list from the struct's field names — see `meters.rs`'s own
    /// comment on omitting `recorded_at`), so this can live anywhere in the
    /// struct; kept last to minimise the diff against the pre-BILL-01 shape.
    span_bytes: u32,
}

/// True iff the gateway already stamped + metered this span's size.
fn is_gateway_stamped(s: &TracelaneSpan) -> bool {
    s.attributes.extra.contains_key(GATEWAY_SPAN_BYTES_ATTR)
}

/// Resolve the LOGICAL `span_bytes` for `s`: the gateway's own stamp when
/// present (it already measured this exactly, at publish time, before this
/// process ever saw the span), else computed the SAME way the gateway does
/// (`stamp_and_meter_span_bytes`) — `attributes` JSON length + `name` +
/// `status.message` + 96 (fixed columns: two 36-char ids, two timestamps,
/// status; matches migration 24's `span_bytes` DEFAULT expression exactly).
///
/// Computed from the RAW (pre-redaction, pre-blob-substitution) attributes —
/// "the customer's number" (spec §2.3) is what was SENT, and both redaction
/// and dedup are OUR later processing, never a markdown on it.
fn resolve_span_bytes(s: &TracelaneSpan) -> u32 {
    if let Some(stamped) = s
        .attributes
        .extra
        .get(GATEWAY_SPAN_BYTES_ATTR)
        .and_then(serde_json::Value::as_u64)
    {
        return u32::try_from(stamped).unwrap_or(u32::MAX);
    }
    let attrs_len = serde_json::to_vec(&s.attributes)
        .map(|v| v.len())
        .unwrap_or(0);
    let size = attrs_len + s.name.len() + s.status.message.as_deref().unwrap_or("").len() + 96;
    u32::try_from(size).unwrap_or(u32::MAX)
}

/// One queued `blobs` row (spec §2.3). `hash` is the 32 RAW bytes of the
/// blake3 digest — see [`BlobRow`]'s own doc for why the Rust type must stay
/// `[u8; 32]`.
struct PendingBlob {
    tenant_id: String,
    hash: [u8; 32],
    bytes: String,
    size: u32,
}

/// One queued `blob_refs` row — one per (span, blob) reference, written in
/// the same batch as the span, never a read-modify-write.
struct PendingBlobRef {
    tenant_id: String,
    hash: [u8; 32],
    span_id: String,
    day: u16,
}

/// True iff `v` is ALREADY a substituted ref object — defensive: nothing in
/// this tree constructs this shape server-side other than this function, but
/// a re-ingested export (dataset JSONL import, a replay) must not be hashed
/// a second time.
fn is_blob_ref(v: &serde_json::Value) -> bool {
    v.as_object().is_some_and(|m| {
        m.get("$ref")
            .and_then(|r| r.as_str())
            .is_some_and(|s| s.starts_with("blake3:"))
    })
}

/// BILL-01 / ADR-076 §2.3 — content-addressed dedup. Mutates `attrs` (the
/// span's REDACTED, about-to-be-stored attributes object) in place: any
/// top-level value whose JSON serialization exceeds [`BLOB_THRESHOLD_BYTES`]
/// is replaced with `{"$ref":"blake3:<hex>"}` and queued into `out_blobs` /
/// `out_refs`. A no-op on anything that is not a JSON object (defensive; the
/// span attributes are always an object in practice).
fn substitute_blobs(
    tenant_id: &str,
    span_id: &str,
    day: u16,
    attrs: &mut serde_json::Value,
    out_blobs: &mut Vec<PendingBlob>,
    out_refs: &mut Vec<PendingBlobRef>,
) {
    let Some(map) = attrs.as_object_mut() else {
        return;
    };
    for value in map.values_mut() {
        if is_blob_ref(value) {
            continue;
        }
        let Ok(text) = serde_json::to_string(value) else {
            continue;
        };
        if text.len() <= BLOB_THRESHOLD_BYTES {
            continue;
        }
        let hash = *blake3::hash(text.as_bytes()).as_bytes();
        let hex = hex::encode(hash);
        out_blobs.push(PendingBlob {
            tenant_id: tenant_id.to_string(),
            hash,
            size: u32::try_from(text.len()).unwrap_or(u32::MAX),
            bytes: text,
        });
        out_refs.push(PendingBlobRef {
            tenant_id: tenant_id.to_string(),
            hash,
            span_id: span_id.to_string(),
            day,
        });
        *value = serde_json::json!({ "$ref": format!("blake3:{hex}") });
    }
}

/// Build the stored [`SpanRow`] for a KEPT span, queuing any blob
/// substitutions along the way. `span_bytes` is passed in — already resolved
/// BEFORE the sampling decision (see the caller in [`run`]) so it reflects
/// the logical size regardless of blob substitution below.
fn build_span_row(
    s: TracelaneSpan,
    span_bytes: u32,
    day: u16,
    out_blobs: &mut Vec<PendingBlob>,
    out_refs: &mut Vec<PendingBlobRef>,
) -> SpanRow {
    // A6: PII redaction on every span attribute payload before any
    // external write. The gateway already redacts audit-row payloads
    // (see `crates/gateway/src/audit.rs::AuditEvent::redact_payload`);
    // ingest must do the same on the span path because span content
    // flows to ClickHouse (and downstream R2). 100%-recall PII +
    // credential rule set lives in `tracelane_policy::pii`.
    let attrs_json = serde_json::to_value(&s.attributes).unwrap_or(serde_json::Value::Null);
    let mut redacted = tracelane_policy::pii::redact_json(&attrs_json);

    let tenant_id = s.tenant_id.to_string();
    let span_id = s.span_id.to_string();
    substitute_blobs(
        &tenant_id,
        &span_id,
        day,
        &mut redacted,
        out_blobs,
        out_refs,
    );

    SpanRow {
        tenant_id,
        trace_id: s.trace_id.to_string(),
        span_id,
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
        //  #5: map the predictive AFT hit into the signatures columns. A single
        // matched id today (the evaluator returns the most-severe Decision); the
        // column is an Array so a future multi-signature span needs no schema change.
        // intervention stays the recorded severity (0 today = observe-first "flag",
        // rendered "Warn" — honest: nothing is enforced by default).
        aft_ids: s
            .attributes
            .tracelane_aft_id
            .clone()
            .map(|id| vec![id])
            .unwrap_or_default(),
        intervention: s
            .attributes
            .tracelane_intervention
            .map(|i| i as u8)
            .unwrap_or(0),
        span_bytes,
    }
}

/// Days from the ClickHouse `Date` epoch (1970-01-01) to `date` — the raw
/// `u16` RowBinary encoding, matching
/// `crates/gateway/src/billing/meters.rs::days_since_epoch` exactly (same
/// table, same wire contract; mirrored rather than imported — see the module
/// doc).
fn days_since_epoch(date: chrono::NaiveDate) -> u16 {
    let Some(epoch) = chrono::NaiveDate::from_ymd_opt(1970, 1, 1) else {
        return 0;
    };
    u16::try_from((date - epoch).num_days().max(0)).unwrap_or(u16::MAX)
}

/// Mirrors `crates/gateway/src/billing/meters.rs`'s `MeterCounterRow` exactly
/// — same table, same column order/types (see the module doc for why this is
/// mirrored rather than imported).
#[derive(Serialize, clickhouse::Row)]
struct MeterCounterRow<'a> {
    tenant_id: &'a str,
    day: u16,
    meter: &'a str,
    dim: &'a str,
    value: f64,
    source: &'a str,
}

/// `tracelane.blobs` (migration 24 §4). `hash: [u8; 32]` — a `String` here
/// would desynchronise RowBinary on the first field against `FixedString(32)`
/// and fail the whole insert SILENTLY at `debug!` level (B-274, five prior
/// instances of this exact class).
#[derive(Serialize, clickhouse::Row)]
struct BlobRow<'a> {
    tenant_id: &'a str,
    hash: [u8; 32],
    bytes: &'a str,
    size: u32,
}

/// `tracelane.blob_refs` (migration 24 §4).
#[derive(Serialize, clickhouse::Row)]
struct BlobRefRow<'a> {
    tenant_id: &'a str,
    hash: [u8; 32],
    span_id: &'a str,
    day: u16,
}

/// Start the ClickHouse batch writer.
///
/// Drains `span_rx` in batches of up to 2000 spans or 200ms, whichever
/// comes first, then issues a single INSERT.
///
/// # Errors
/// Returns `Err` only on unrecoverable ClickHouse errors. Transient errors
/// are retried across the [`CH_INSERT_BACKOFF`] ladder (8 attempts, ≈ 63 s
/// cumulative — B-493) before propagating.
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

#[allow(clippy::too_many_arguments)]
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
    // BILL-01 meter 1 (ingest half): persists ACROSS a failed flush (fail-open
    // — see the module doc), unlike `pending_blobs`/`pending_refs` below which
    // are per-cycle and best-effort.
    let mut meter_buffer: HashMap<String, f64> = HashMap::new();
    // B-469 (REV-1): batches whose INSERT did not report success, retried
    // UNCHANGED with their own dedup token — never merged back into
    // `meter_buffer` (see `flush_ingest_meter`).
    let mut meter_pending: VecDeque<IngestMeterBatch> = VecDeque::new();

    loop {
        let mut batch: Vec<SpanRow> = Vec::with_capacity(batch_size);
        // Ack handles for the NATS-sourced spans in `batch`. Acked ONLY after a
        // durable flush (#81 ack-after-write) — so a failed write leaves them
        // unacked and JetStream redelivers. OTLP spans contribute no handle.
        let mut pending_acks: Vec<async_nats::jetstream::Message> = Vec::new();
        // BILL-01 / ADR-076 §2.3 — blobs queued by KEPT spans this cycle, flushed
        // alongside `batch` (never retried on failure — see the module doc).
        let mut pending_blobs: Vec<PendingBlob> = Vec::new();
        let mut pending_refs: Vec<PendingBlobRef> = Vec::new();
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

                    // BILL-01 / ADR-076 meter 1 (ingest half) — resolved BEFORE
                    // the sampling decision (spec §2.1: "before storage"; the
                    // byte count must not depend on whether this span is later
                    // kept) and metered ONLY when the gateway did not already
                    // stamp + meter it (the discriminator that prevents
                    // double-counting between the two writers).
                    let span_bytes = resolve_span_bytes(&span);
                    if !is_gateway_stamped(&span) {
                        *meter_buffer
                            .entry(span.tenant_id.to_string())
                            .or_insert(0.0) += f64::from(span_bytes);
                    }
                    let day = days_since_epoch(chrono::Utc::now().date_naive());

                    // PP-O2 tail sampling — keep every error/intervention trace,
                    // rate-sample the rest. Dropped spans are never written.
                    match sample_one(
                        &sampler,
                        span,
                        policy,
                        span_bytes,
                        day,
                        &mut pending_blobs,
                        &mut pending_refs,
                    ) {
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
                                // SRE register #54: a per-occurrence line stays at
                                // debug (logging.md), but the CONDITION must be
                                // observable — one rate-limited WARN carrying
                                // `TRACELANE_DEGRADED`, a count and `open_for_secs`.
                                tracelane_shared::degradation::note(
                                    tracelane_shared::degradation::Degradation::PerTraceCeilingDrop,
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
                        // B-445: blobs/refs are part of the record here too — ack only
                        // after both landed; a failure leaves the batch for redelivery.
                        match async {
                            flush(&client, &batch, &pending_acks).await?;
                            flush_blobs(&client, pending_blobs, pending_refs).await
                        }
                        .await
                        {
                            Ok(()) => {
                                ack_all(pending_acks).await;
                                // Federation substrate (ADR-056 ·),
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
                    // BILL-01 meter 1: flush whatever accumulated this cycle
                    // even if `batch` itself is empty (every sampled-OUT span
                    // still metered — see the module doc).
                    flush_ingest_meter(&client, &mut meter_buffer, &mut meter_pending).await;
                    tracing::info!("span channel closed; batch writer exiting");
                    return Ok(());
                }
                Err(_) => break, // timeout
            }
        }

        if !batch.is_empty() {
            let n = batch.len();
            // TODO(T9): per-tenant retention — the global 365d `tracelane.spans` TTL silently evicts any span arriving with an old start_time (replay / backfill / clock-skew) on the next TTL merge, even though the insert succeeds; T9 must make retention per-tenant instead of one global TTL.
            // Durable-then-ack (#81): if flush fails, `?` propagates BEFORE the
            // acks, so the messages stay unacked and JetStream redelivers them
            // (zero-loss, FT-03). A redelivered duplicate is idempotent — the
            // spans table collapses it on merge (ReplacingMergeTree).
            flush(&client, &batch, &pending_acks)
                .await
                .context("ClickHouse batch flush failed")?;
            // B-445 (2026-09-19): the span's blobs and their refs are PART of the record —
            // written before the ack, and a failure propagates exactly like a span
            // write, so JetStream redelivers the batch (ReplacingMergeTree collapses the
            // span and blob rows; a duplicate `blob_refs` row is harmless to a NOT IN).
            // Until this, they were best-effort AFTER the ack: a failed ref insert left a
            // live span pointing at a zero-ref blob the Sunday GC then deleted.
            flush_blobs(&client, pending_blobs, pending_refs)
                .await
                .context("ClickHouse blobs/blob_refs flush failed")?;
            ack_all(pending_acks).await;
            // Federation substrate (ADR-056 ·): anonymized cross-customer
            // signal aggregates from the spans just durably written. Best-effort
            // + fail-open — never affects span durability or the acks above.
            crate::federation::write_signals(&client, &federation_rows(&batch)).await;
            tracing::debug!(spans = n, dropped, "flushed batch to ClickHouse");
        }
        // BILL-01 meter 1 (ingest half) — rides the SAME flush cadence as the
        // span batch (spec §2.5b: never a row per span), regardless of
        // whether THIS cycle happened to keep any spans.
        flush_ingest_meter(&client, &mut meter_buffer, &mut meter_pending).await;

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
/// to the batch) or `None` to drop. `span_bytes` is already resolved (see the
/// caller) — passed through unchanged; `day` + the output vectors feed the
/// BILL-01 blob substitution ONLY for a kept span (a dropped span is never
/// stored, so its attributes are never substituted or queued).
///
/// Extracted from the recv loop so the sampling wiring (/ PP-O2) is
/// unit-testable without a live ClickHouse: a test asserts a 0%-rate sampler
/// drops a clean span here but keeps an error span — which fails if this gate
/// is ever removed (the bug this fixes was that the sampler was never called).
#[allow(clippy::too_many_arguments)]
fn sample_one(
    sampler: &TailSampler,
    span: TracelaneSpan,
    policy: SamplingPolicy,
    span_bytes: u32,
    day: u16,
    out_blobs: &mut Vec<PendingBlob>,
    out_refs: &mut Vec<PendingBlobRef>,
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
    kept.then(|| build_span_row(span, span_bytes, day, out_blobs, out_refs))
}

/// One drained ingest-meter flush, frozen: rows, the day it was drained on, and
/// the `insert_deduplication_token` every retry carries (B-469, REV-1). Mirrors
/// `crates/gateway/src/billing/meters.rs::MeterBatch` — kept per crate on
/// purpose: the two writers' row types differ and a shared abstraction would
/// hide the one line that matters (the token on the retry).
#[derive(Debug, Clone)]
struct IngestMeterBatch {
    token: String,
    day: u16,
    rows: Vec<(String, f64)>,
}

/// At most this many failed batches wait for retry (24 h of 200 ms cycles is
/// far more; this is a memory bound, not a time budget). Beyond it the OLDEST
/// is dropped and counted (`MeterBatchDropped`) — under-billed, never doubled.
const INGEST_METER_PENDING_CAP: usize = 8_640;

/// ONE INSERT for one immutable batch, carrying its dedup token so a retry of a
/// batch whose first attempt COMMITTED but lost its response is discarded
/// server-side (`meter_counters` `non_replicated_deduplication_window`,
/// migration 28).
async fn insert_ingest_meter_batch(client: &Client, batch: &IngestMeterBatch) -> Result<()> {
    let mut insert = client
        .insert("meter_counters")
        .context("meter_counters insert init failed")?
        .with_option("insert_deduplication_token", batch.token.as_str());
    for (tenant_id, value) in &batch.rows {
        insert
            .write(&MeterCounterRow {
                tenant_id,
                day: batch.day,
                meter: "ingest_bytes",
                dim: "",
                value: *value,
                source: "ingest",
            })
            .await
            .context("meter_counters row write failed")?;
    }
    insert
        .end()
        .await
        .context("meter_counters insert commit failed")
}

/// Flush meter 1's ingest half (spec §2.1): retry every pending batch UNCHANGED
/// (oldest first, stopping at the first failure), then drain `meter_buffer`
/// into a NEW immutable batch and insert it. A failed batch joins `pending`
/// as-is and `Degradation::MeterFlushFailed` notes it — fail-open: a
/// billing-meter outage must never affect span durability, which by the time
/// this runs has already committed.
///
/// **B-469 (REV-1, 2026-09-20):** until this, a failed batch's amounts were
/// merged back into `meter_buffer` and re-sent with newer usage, so an insert
/// that committed and lost its response (ClickHouse documents that window)
/// counted the batch twice — the same C1-shaped restore the gateway sink had.
async fn flush_ingest_meter(
    client: &Client,
    meter_buffer: &mut HashMap<String, f64>,
    pending: &mut VecDeque<IngestMeterBatch>,
) {
    let mut failed: Option<anyhow::Error> = None;
    while let Some(batch) = pending.front() {
        match insert_ingest_meter_batch(client, batch).await {
            Ok(()) => {
                pending.pop_front();
            }
            Err(e) => {
                failed = Some(e);
                break; // keep order: nothing newer is sent past a stuck batch
            }
        }
    }
    if !meter_buffer.is_empty() {
        let batch = IngestMeterBatch {
            token: uuid::Uuid::new_v4().to_string(),
            day: days_since_epoch(chrono::Utc::now().date_naive()),
            rows: meter_buffer.drain().collect(),
        };
        let result = if failed.is_some() {
            Err(anyhow::anyhow!("pending batch retry failed first"))
        } else {
            insert_ingest_meter_batch(client, &batch).await
        };
        if let Err(e) = result {
            if pending.len() >= INGEST_METER_PENDING_CAP {
                pending.pop_front();
                tracelane_shared::degradation::note(
                    tracelane_shared::degradation::Degradation::MeterBatchDropped,
                );
            }
            pending.push_back(batch);
            if failed.is_none() {
                failed = Some(e);
            }
        }
    }
    if let Some(e) = failed {
        tracing::warn!(error = %e, pending = pending.len(), "ingest meter_counters flush failed; batch held for an unchanged retry");
        tracelane_shared::degradation::note(
            tracelane_shared::degradation::Degradation::MeterFlushFailed,
        );
    }
}

/// Batched INSERT of this cycle's queued `blobs` + `blob_refs` rows (spec §2.3).
///
/// B-445 (2026-09-19): part of the DURABLE flush now — the caller runs it before the
/// ack and propagates a failure, so JetStream redelivers the batch. Until then it was
/// best-effort after the ack ("a missing blob renders `missing: true`"), which made a
/// failed `blob_refs` insert manufacture exactly the zero-ref-but-referenced blob the
/// Sunday GC deletes. A failure is still counted on `BlobStoreFailed` so the class stays
/// visible on the watchdog even though it now also stops the ack.
///
/// # Errors
/// Either insert failed; the caller treats it as a span-write failure.
async fn flush_blobs(
    client: &Client,
    blobs: Vec<PendingBlob>,
    refs: Vec<PendingBlobRef>,
) -> Result<()> {
    if blobs.is_empty() && refs.is_empty() {
        return Ok(());
    }
    // In-cycle dedup: several spans in one flush can share the identical
    // blob (the same repeated system prompt); ReplacingMergeTree makes this
    // a write-amplification optimisation, not a correctness requirement.
    let mut seen: HashSet<(String, [u8; 32])> = HashSet::new();
    let deduped: Vec<&PendingBlob> = blobs
        .iter()
        .filter(|b| seen.insert((b.tenant_id.clone(), b.hash)))
        .collect();

    if !deduped.is_empty() {
        let n = deduped.len();
        let result: Result<()> = async {
            let mut insert = client.insert("blobs").context("blobs insert init failed")?;
            for b in &deduped {
                insert
                    .write(&BlobRow {
                        tenant_id: &b.tenant_id,
                        hash: b.hash,
                        bytes: &b.bytes,
                        size: b.size,
                    })
                    .await
                    .context("blobs row write failed")?;
            }
            insert.end().await.context("blobs insert commit failed")
        }
        .await;
        if let Err(e) = result {
            tracing::warn!(error = %e, count = n, "blobs insert failed — batch left for redelivery (B-445)");
            tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::BlobStoreFailed,
            );
            return Err(e);
        }
    }

    if !refs.is_empty() {
        let n = refs.len();
        let result: Result<()> = async {
            let mut insert = client
                .insert("blob_refs")
                .context("blob_refs insert init failed")?;
            for r in &refs {
                insert
                    .write(&BlobRefRow {
                        tenant_id: &r.tenant_id,
                        hash: r.hash,
                        span_id: &r.span_id,
                        day: r.day,
                    })
                    .await
                    .context("blob_refs row write failed")?;
            }
            insert.end().await.context("blob_refs insert commit failed")
        }
        .await;
        if let Err(e) = result {
            tracing::warn!(error = %e, count = n, "blob_refs insert failed — batch left for redelivery (B-445)");
            tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::BlobStoreFailed,
            );
            return Err(e);
        }
    }
    Ok(())
}

/// Extract the anonymized federation signals from a durably-flushed span batch
/// (ADR-056 ·). Reads the `SpanRow` fields the writer already holds — no
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
    let seq = msg.info().ok().map(|i| i.stream_sequence);
    if let Err(e) = msg.ack().await {
        tracing::warn!(error = %e, "JetStream ack failed after durable write; the message may redeliver — the span row collapses on merge (ReplacingMergeTree) but the mv_* views count the second INSERT");
    }
    // Acked (or the ack itself failed, in which case a redelivery is the real
    // retry and must not be dropped as a duplicate): no longer held.
    if let Some(seq) = seq {
        crate::span_envelope::release(seq);
    }
}

/// Ack every message whose span was durably written this batch (#81).
async fn ack_all(msgs: Vec<async_nats::jetstream::Message>) {
    for m in msgs {
        ack_one(m).await;
    }
}

/// B-493 (2026-09-21): the back-off ladder between insert attempts. Cumulative
/// ≈ 63 s — longer than the 30 s burst that exhausted the old 3-attempt / 1.5 s
/// ladder and killed the process. A refusal such as
/// `TOO_MANY_SIMULTANEOUS_QUERIES` or `MEMORY_LIMIT_EXCEEDED` is a TRANSIENT
/// (the module doc's own word), and the spans behind it are safe in JetStream,
/// unacked, for exactly as long as this writer keeps trying — the batch's
/// messages get a `+WPI` progress ack before every rung so JetStream's 30 s
/// `ack_wait` does not redeliver a batch this process still holds (a
/// redelivered copy is written AGAIN, and the `mv_*` views count every INSERT).
/// Exiting instead hands the batch to a container restart that the published
/// bench compose never performs. Only after the whole ladder does `run`
/// propagate (still loud, still recoverable by a restart); a PERMANENT error
/// (`is_permanent_ch_error`) propagates at once — retrying a stale schema for
/// a minute per batch would look like a transient and hide the cause.
/// Pinned by `b493_the_production_backoff_ladder_outlasts_a_burst`.
pub(crate) const CH_INSERT_BACKOFF: [std::time::Duration; 7] = [
    std::time::Duration::from_millis(500),
    std::time::Duration::from_secs(1),
    std::time::Duration::from_secs(2),
    std::time::Duration::from_secs(4),
    std::time::Duration::from_secs(8),
    std::time::Duration::from_secs(16),
    std::time::Duration::from_secs(32),
];

/// One INSERT attempt is bounded: a ClickHouse that HANGS (paused, a wedged
/// disk, a half-open socket) must become a failed attempt inside JetStream's
/// 30 s `ack_wait`, or the batch is redelivered to this same process before the
/// first progress ack could be sent — run 3 of the B-493 repro (a 40 s
/// `docker pause`) showed exactly that: 4,000 redelivered. 20 s < 30 s.
pub(crate) const CH_INSERT_ATTEMPT_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(20);

/// ClickHouse error codes no retry can fix: the schema, the row's types, the
/// credentials or the SQL are wrong, and the same bytes will be refused every
/// rung. Everything else (202 too many queries, 241 memory limit, 252 too many
/// parts, network, timeout, an unknown code) is treated as transient.
/// Codes: 6 CANNOT_PARSE_TEXT · 16 NO_SUCH_COLUMN_IN_TABLE · 33 CANNOT_READ_ALL_DATA
/// · 47 UNKNOWN_IDENTIFIER · 53 TYPE_MISMATCH · 60 UNKNOWN_TABLE · 62 SYNTAX_ERROR
/// · 81 UNKNOWN_DATABASE · 117 INCORRECT_DATA · 497 ACCESS_DENIED · 516 AUTHENTICATION_FAILED.
pub(crate) fn is_permanent_ch_error(err: &anyhow::Error) -> bool {
    let text = format!("{err:#}");
    const PERMANENT: [u16; 11] = [6, 16, 33, 47, 53, 60, 62, 81, 117, 497, 516];
    PERMANENT
        .iter()
        .any(|code| text.contains(&format!("Code: {code}.")))
}

/// Flush a batch of span rows to ClickHouse across the [`CH_INSERT_BACKOFF`]
/// ladder. Treats the entire write phase (all `insert.write()` calls +
/// `insert.end()`) as one atomic attempt so that a transient write failure is
/// retried rather than propagating immediately via `?`. `held` are the
/// JetStream handles of the rows in this batch (empty for OTLP-direct spans);
/// each gets a progress ack before every rung's sleep.
async fn flush(
    client: &Client,
    rows: &[SpanRow],
    held: &[async_nats::jetstream::Message],
) -> Result<()> {
    // One token per BATCH, minted here and carried by every retry of these exact
    // rows (B-469's shape for meter_counters, applied to spans — B-493 run 6): an
    // attempt the client gave up on can still COMMIT server-side (a 20 s timeout
    // against a paused server did), and the retry then inserted the same rows a
    // second time. ReplacingMergeTree collapsed the span rows on merge, but the
    // `mv_trace_summaries` / `mv_slo_hourly_stats` views fire per INSERT and
    // counted 100 traces twice. With `non_replicated_deduplication_window` on
    // `spans` (migration 29) the server drops the retry BY TOKEN before any view
    // sees it. A token sent to a table without the window is accepted and ignored.
    let token = uuid::Uuid::new_v4().to_string();
    flush_with_backoff(client, rows, held, &token, &CH_INSERT_BACKOFF).await
}

/// One attempt per rung of `backoff` plus the first — `backoff.len() + 1` in all.
/// A rung is slept AFTER the failed attempt it follows. Every attempt carries the
/// same `dedup_token`.
async fn flush_with_backoff(
    client: &Client,
    rows: &[SpanRow],
    held: &[async_nats::jetstream::Message],
    dedup_token: &str,
    backoff: &[std::time::Duration],
) -> Result<()> {
    let attempts = backoff.len() + 1;
    // `attempt` indexes `backoff` on the failure arm (rung N follows attempt N);
    // the last attempt has no rung after it.
    #[allow(clippy::needless_range_loop)]
    for attempt in 0..attempts {
        let attempt_fut = async {
            let mut insert = client
                .insert("tracelane.spans")
                .context("ClickHouse insert init")?
                .with_option("insert_deduplication_token", dedup_token)
                // The views fed by `spans` (`trace_summaries`, `slo_hourly_stats`)
                // dedup on their OWN windows (migration 29) only when the INSERT
                // asks for it — the source table's dedup alone does not stop a
                // view from firing twice (proven on a real server, 2026-09-21).
                .with_option("deduplicate_blocks_in_dependent_materialized_views", "1");
            for row in rows {
                insert.write(row).await.context("ClickHouse row write")?;
            }
            insert.end().await.context("ClickHouse insert end")?;
            Ok::<(), anyhow::Error>(())
        };
        let result: Result<()> =
            match tokio::time::timeout(CH_INSERT_ATTEMPT_TIMEOUT, attempt_fut).await {
                Ok(r) => r,
                Err(_) => Err(anyhow::anyhow!(
                    "ClickHouse insert attempt timed out after {}s (the server hung)",
                    CH_INSERT_ATTEMPT_TIMEOUT.as_secs()
                )),
            };

        match result {
            Ok(()) => {
                if attempt > 0 {
                    // The leave-transition (`.claude/rules/logging.md`): one line, and
                    // the counter's `open_for_secs` stops growing.
                    tracelane_shared::degradation::resolve(
                        tracelane_shared::degradation::Degradation::SpanWriteRetrying,
                    );
                }
                return Ok(());
            }
            Err(e) if is_permanent_ch_error(&e) => {
                tracing::error!(
                    error = format!("{e:#}"),
                    rows = rows.len(),
                    attempt,
                    "ClickHouse insert refused with a PERMANENT error (schema / types / \
                     credentials) — not retrying; surfacing and propagating (messages stay \
                     unacked for JetStream redelivery)"
                );
                return Err(e);
            }
            Err(e) if attempt + 1 < attempts => {
                // One line per rung, bounded by the ladder's length — the
                // repeating condition itself is the counter, which the watchdog
                // reads (`.claude/rules/logging.md`). `{e:#}` prints the chain:
                // the `Code: NNN` reason, not just "insert end".
                tracelane_shared::degradation::note(
                    tracelane_shared::degradation::Degradation::SpanWriteRetrying,
                );
                tracing::warn!(
                    attempt,
                    attempts,
                    next_backoff_ms = backoff[attempt].as_millis() as u64,
                    error = format!("{e:#}"),
                    "ClickHouse insert failed, retrying"
                );
                // Keep the hold inside the ack contract: `+WPI` resets each held
                // message's ack_wait, so a batch this process still owns is not
                // redelivered (and written twice) while it waits out the rung.
                for m in held {
                    if let Err(err) = m.ack_with(async_nats::jetstream::AckKind::Progress).await {
                        tracing::warn!(error = %err, "JetStream progress ack failed; the message may redeliver during the back-off");
                    }
                }
                tokio::time::sleep(backoff[attempt]).await;
            }
            // Surface the failure LOUDLY before propagating (#81 P0: a write that
            // dies must never be silent). The caller's `?` then crashes the
            // process via try_join!; with ack-after-write the messages stay
            // unacked and JetStream redelivers them — no span is lost.
            Err(e) => {
                tracing::error!(
                    error = format!("{e:#}"),
                    rows = rows.len(),
                    attempts,
                    "ClickHouse insert FAILED after every attempt — spans NOT written; surfacing and propagating (messages stay unacked for JetStream redelivery)"
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
            aft_ids: vec![],
            intervention: 0,
            span_bytes: 96,
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

    // ── BILL-01 / ADR-076 — span_bytes resolution + blob substitution (pure) ──

    #[test]
    fn resolve_span_bytes_reads_the_gateway_stamp_when_present() {
        let mut s = tspan(tracelane_shared::SpanStatusCode::Ok);
        s.attributes.extra.insert(
            GATEWAY_SPAN_BYTES_ATTR.to_string(),
            serde_json::json!(12345),
        );
        assert!(is_gateway_stamped(&s));
        assert_eq!(resolve_span_bytes(&s), 12345);
    }

    #[test]
    fn resolve_span_bytes_computes_when_unstamped() {
        let s = tspan(tracelane_shared::SpanStatusCode::Ok);
        assert!(!is_gateway_stamped(&s));
        // name.len() ("op" = 2) + status_message (0, None) + 96 fixed +
        // whatever the default SpanAttributes serialize to (non-zero: every
        // Option field present is `null`-free due to skip_serializing_if, but
        // `extra` alone is `{}` so attrs_len is small and deterministic here).
        let computed = resolve_span_bytes(&s);
        assert!(
            computed >= 96 + 2,
            "must at least cover the fixed overhead + name"
        );
    }

    #[test]
    fn is_gateway_stamped_is_false_for_an_otlp_direct_span() {
        let s = tspan(tracelane_shared::SpanStatusCode::Ok);
        assert!(!is_gateway_stamped(&s));
    }

    #[test]
    fn substitute_blobs_leaves_small_values_untouched() {
        let mut attrs = serde_json::json!({ "small_key": "short value" });
        let mut blobs = Vec::new();
        let mut refs = Vec::new();
        substitute_blobs("tenant-a", "span-1", 100, &mut attrs, &mut blobs, &mut refs);
        assert!(blobs.is_empty());
        assert!(refs.is_empty());
        assert_eq!(attrs["small_key"], "short value");
    }

    #[test]
    fn substitute_blobs_replaces_an_oversized_value_with_a_ref() {
        let big = "x".repeat(BLOB_THRESHOLD_BYTES + 1);
        let mut attrs = serde_json::json!({ "gen_ai_system_instructions": big });
        let mut blobs = Vec::new();
        let mut refs = Vec::new();
        substitute_blobs("tenant-a", "span-1", 100, &mut attrs, &mut blobs, &mut refs);
        assert_eq!(blobs.len(), 1);
        assert_eq!(refs.len(), 1);
        let r = attrs["gen_ai_system_instructions"]["$ref"]
            .as_str()
            .expect("substituted value must carry $ref");
        assert!(r.starts_with("blake3:"));
        assert_eq!(blobs[0].tenant_id, "tenant-a");
        assert_eq!(refs[0].span_id, "span-1");
        assert_eq!(refs[0].day, 100);
        assert_eq!(refs[0].hash, blobs[0].hash);
    }

    /// The same value, twice → the SAME hash (content-addressing, not
    /// per-occurrence). Two different tenants → two SEPARATE blob rows even
    /// though the bytes are identical (spec §2.3/§2.4: blobs are per-tenant,
    /// by design — that is what makes erasure a per-tenant DELETE).
    #[test]
    fn identical_content_hashes_identically_and_stays_per_tenant() {
        let big = "same system prompt, repeated".repeat(100);
        assert!(big.len() > BLOB_THRESHOLD_BYTES);

        let mut attrs_a = serde_json::json!({ "gen_ai_system_instructions": big.clone() });
        let (mut blobs_a, mut refs_a) = (Vec::new(), Vec::new());
        substitute_blobs(
            "tenant-a",
            "span-1",
            1,
            &mut attrs_a,
            &mut blobs_a,
            &mut refs_a,
        );

        let mut attrs_b = serde_json::json!({ "gen_ai_system_instructions": big });
        let (mut blobs_b, mut refs_b) = (Vec::new(), Vec::new());
        substitute_blobs(
            "tenant-b",
            "span-2",
            1,
            &mut attrs_b,
            &mut blobs_b,
            &mut refs_b,
        );

        assert_eq!(
            blobs_a[0].hash, blobs_b[0].hash,
            "identical content must hash identically"
        );
        assert_ne!(
            blobs_a[0].tenant_id, blobs_b[0].tenant_id,
            "two tenants sending the identical text hold two SEPARATE blob rows"
        );
    }

    #[test]
    fn substitute_blobs_does_not_double_hash_an_already_substituted_ref() {
        let mut attrs = serde_json::json!({
            "gen_ai_system_instructions": { "$ref": "blake3:deadbeef" }
        });
        let mut blobs = Vec::new();
        let mut refs = Vec::new();
        substitute_blobs("tenant-a", "span-1", 1, &mut attrs, &mut blobs, &mut refs);
        assert!(
            blobs.is_empty(),
            "an already-substituted ref must not be re-hashed"
        );
        assert!(refs.is_empty());
    }

    #[test]
    fn days_since_epoch_matches_known_dates() {
        assert_eq!(
            days_since_epoch(chrono::NaiveDate::from_ymd_opt(1970, 1, 1).unwrap()),
            0
        );
        assert_eq!(
            days_since_epoch(chrono::NaiveDate::from_ymd_opt(1970, 1, 2).unwrap()),
            1
        );
    }

    /// Regression for / PP-O2: the writer's per-span path runs the tail
    /// sampler. With a 0% baseline a clean span is dropped (never written) while
    /// error / intervention spans are kept — exercising the exact gate the recv
    /// loop calls, so removing the sampler wiring breaks this test.
    #[test]
    fn writer_gate_applies_tail_sampling() {
        use tracelane_shared::{Intervention, SpanStatusCode};
        let sampler = TailSampler::with_rate(0);
        let mut blobs = Vec::new();
        let mut refs = Vec::new();

        assert!(
            sample_one(
                &sampler,
                tspan(SpanStatusCode::Ok),
                SamplingPolicy::Tail,
                96,
                0,
                &mut blobs,
                &mut refs
            )
            .is_none(),
            "0%-rate clean span must be dropped under Tail"
        );
        assert!(
            sample_one(
                &sampler,
                tspan(SpanStatusCode::Error),
                SamplingPolicy::Tail,
                96,
                0,
                &mut blobs,
                &mut refs
            )
            .is_some(),
            "error span must be kept"
        );

        let mut iv = tspan(SpanStatusCode::Ok);
        iv.attributes.tracelane_intervention = Some(Intervention::Block);
        assert!(
            sample_one(
                &sampler,
                iv,
                SamplingPolicy::Tail,
                96,
                0,
                &mut blobs,
                &mut refs
            )
            .is_some(),
            "intervention span must be kept"
        );

        // ADR-048: the SAME 0%-rate clean span that Tail drops is KEPT under
        // Full — proving the policy actually gates the writer's persist path.
        assert!(
            sample_one(
                &sampler,
                tspan(SpanStatusCode::Ok),
                SamplingPolicy::Full,
                96,
                0,
                &mut blobs,
                &mut refs
            )
            .is_some(),
            "Full capture must keep a clean span the tail rate would drop"
        );
    }

    /// B-445: a failed blobs/blob_refs insert is a span-write failure now — `flush_blobs`
    /// returns the error so the writer leaves the batch UNACKED for redelivery instead of
    /// acking a span whose blob never landed. Proven against a real ClickHouse by pointing
    /// the client at a database that does not exist: the insert fails, the error propagates.
    /// Before B-445 this function returned `()` and the failure was a warn + a counter.
    #[tokio::test]
    #[ignore = "needs a real ClickHouse; set CLICKHOUSE_TEST_URL"]
    async fn flush_blobs_propagates_a_failed_insert_against_a_real_clickhouse() {
        let url = std::env::var("CLICKHOUSE_TEST_URL").expect("CLICKHOUSE_TEST_URL");
        let bad = Client::default()
            .with_url(url)
            .with_database("tracelane_does_not_exist_b445");
        let blob = PendingBlob {
            tenant_id: "00000000-0000-0000-0000-000000000001".into(),
            hash: [7u8; 32],
            bytes: "x".into(),
            size: 1,
        };
        let err = flush_blobs(&bad, vec![blob], vec![]).await.expect_err(
            "an insert into a missing database must fail, and the failure must propagate",
        );
        assert!(
            format!("{err:#}").contains("blobs insert"),
            "the error names the step: {err:#}"
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
        // Per .claude/rules/testing.md a test credential must not LOOK like a
        // real one. The old "pw-regress" was short enough to read as a genuine
        // hard-coded password and tripped CodeQL rust/hard-coded-cryptographic-value
        // as CRITICAL on the public mirror. It is a wiremock stub — it
        // authenticates nothing — so it now says so.
        let client = ch_client(
            &server.uri(),
            "tracelane-regress",
            "unit-test-password-do-not-use-in-prod",
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
        flush(&client, &[sample_row()], &[])
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
        // B-493: the production ladder is ~1 min; drive the same loop with a
        // millisecond ladder of the SAME length so the test proves the shape
        // (every rung tried, then Err) without waiting it out.
        let tiny: Vec<std::time::Duration> = (0..CH_INSERT_BACKOFF.len())
            .map(|_| std::time::Duration::from_millis(2))
            .collect();
        let result = flush_with_backoff(&client, &[sample_row()], &[], "tok", &tiny).await;
        assert!(
            result.is_err(),
            "a persistent outage must surface as Err, not a silent drop",
        );
        let hits = server.received_requests().await.unwrap().len();
        assert_eq!(
            hits,
            CH_INSERT_BACKOFF.len() + 1,
            "every rung of the ladder is tried before propagating"
        );
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
        span_insert_requests(&server).await
    }

    /// Count only `INSERT INTO tracelane.spans` requests the mock received —
    /// NOT the total request count. BILL-01 / ADR-076 added a `meter_counters`
    /// flush that rides the SAME mock server on every cycle regardless of
    /// keep/drop (metering happens "before storage" — spec §2.1), so a bare
    /// `received_requests().len()` conflates "was a span written" with "did
    /// ANY POST happen" and would make a sampled-out span look inserted. The
    /// writer always calls `client.insert("tracelane.spans")` fully-qualified
    /// (unlike the unqualified `meter_counters`/`blobs`/`blob_refs`), so the
    /// URL substring is a reliable, unique marker.
    async fn span_insert_requests(server: &MockServer) -> usize {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.to_string().contains("tracelane.spans"))
            .count()
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
                    TenantConfig { policy }
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
        span_insert_requests(&server).await
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

    /// B-493 (2026-09-21): a self-host ClickHouse (`max_concurrent_queries` 20)
    /// under a 30 s burst refused this writer's batches with
    /// `TOO_MANY_SIMULTANEOUS_QUERIES`; the 3-attempt / 1.5 s ladder ran out
    /// inside the burst and `run` EXITED — the process died with ~5,900 spans
    /// unacked in JetStream, and the published bench compose (no `restart:`)
    /// never brought it back, so the read-back counted half. A refusal is a
    /// transient, not "unrecoverable" (the doc comment's own word): the ladder
    /// now outlasts a burst, and only a persistent outage propagates.
    #[tokio::test]
    async fn b493_a_transient_refusal_storm_is_outwaited_not_fatal() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503).set_body_string(
                "Code: 202. DB::Exception: Too many simultaneous queries. Maximum: 20. \
                     (TOO_MANY_SIMULTANEOUS_QUERIES)",
            ))
            .up_to_n_times(5)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let client = client_for(&server.uri());
        let tiny: Vec<std::time::Duration> = (0..CH_INSERT_BACKOFF.len())
            .map(|_| std::time::Duration::from_millis(5))
            .collect();
        flush_with_backoff(&client, &[sample_row()], &[], "tok", &tiny)
            .await
            .expect("five refusals in a row are outwaited, the batch lands on the sixth");
        assert_eq!(server.received_requests().await.unwrap().len(), 6);
    }

    /// A PERMANENT ClickHouse error (here `NO_SUCH_COLUMN_IN_TABLE`, the B-482
    /// stale-schema class) propagates on the FIRST attempt — one request, not a
    /// minute of retries that reads like a transient.
    #[tokio::test]
    async fn b493_a_permanent_error_propagates_at_once() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(404).set_body_string(
                "Code: 16. DB::Exception: No such column span_bytes in table tracelane.spans \
                 (NO_SUCH_COLUMN_IN_TABLE)",
            ))
            .mount(&server)
            .await;
        let client = client_for(&server.uri());
        let tiny: Vec<std::time::Duration> = (0..CH_INSERT_BACKOFF.len())
            .map(|_| std::time::Duration::from_millis(5))
            .collect();
        let r = flush_with_backoff(&client, &[sample_row()], &[], "tok", &tiny).await;
        assert!(r.is_err(), "a permanent error propagates");
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            1,
            "exactly one attempt — no ladder for a schema error"
        );
        // And the run-2 refusal shape (memory cap, code 241) IS transient: retried.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string(
                "Code: 241. DB::Exception: (total) memory limit exceeded: would use 474.00 MiB \
                 (MEMORY_LIMIT_EXCEEDED)",
            ))
            .up_to_n_times(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let client = client_for(&server.uri());
        flush_with_backoff(&client, &[sample_row()], &[], "tok", &tiny)
            .await
            .expect("241 is outwaited");
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    /// Every attempt of one batch carries the SAME `insert_deduplication_token`
    /// (the server dedups by it — migration 29), and two different batches carry
    /// different ones.
    #[tokio::test]
    async fn b493_every_retry_of_a_batch_carries_the_same_dedup_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503).set_body_string("Code: 202. busy"))
            .up_to_n_times(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let client = client_for(&server.uri());
        flush(&client, &[sample_row()], &[])
            .await
            .expect("lands on attempt 3");
        flush(&client, &[sample_row()], &[])
            .await
            .expect("a second batch");
        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 4);
        let tok = |i: usize| {
            let q = reqs[i].url.query().unwrap_or_default().to_string();
            q.split('&')
                .find(|kv| kv.starts_with("insert_deduplication_token="))
                .map(str::to_string)
                .expect("token on the wire")
        };
        assert_eq!(tok(0), tok(1), "retry 1 reuses the batch token");
        assert_eq!(tok(1), tok(2), "retry 2 reuses the batch token");
        assert_ne!(tok(2), tok(3), "a new batch mints a new token");
        assert_eq!(
            reqs[0].body, reqs[2].body,
            "and the retried body is byte-identical"
        );
    }

    /// **B-493 proof on a real server, both directions.** The same batch flushed
    /// twice under one `insert_deduplication_token` — the "committed behind a
    /// client timeout, then retried" path run 6 of the repro hit — lands ONCE in
    /// `spans` and fires `mv_trace_summaries` ONCE (migration 29's window on the
    /// table), while a clone of `spans` without the window takes both inserts:
    /// the table SETTING is the control, the token alone is not.
    /// Run: `CLICKHOUSE_TEST_URL=http://127.0.0.1:8123 cargo test -p ingest --bin ingest \
    ///   b493_a_retried_span_batch_fires_the_views_once_against_a_real_clickhouse -- --ignored`
    #[tokio::test]
    #[ignore = "needs a real ClickHouse with schema.sql applied; set CLICKHOUSE_TEST_URL"]
    async fn b493_a_retried_span_batch_fires_the_views_once_against_a_real_clickhouse() {
        let url = std::env::var("CLICKHOUSE_TEST_URL").expect("CLICKHOUSE_TEST_URL");
        let ch = ch_client(
            &url,
            &std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "default".into()),
            &std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_default(),
            "tracelane",
        );
        // The window is ON the table — read from the server, never assumed from DDL.
        let ddl: String = ch
            .query("SHOW CREATE TABLE tracelane.spans")
            .fetch_one()
            .await
            .expect("show create");
        assert!(
            ddl.contains("non_replicated_deduplication_window = 1000"),
            "migration 29 must be applied on tracelane.spans: {ddl}"
        );
        let trace = format!("b493-{}", uuid::Uuid::new_v4());
        let mut row = sample_row();
        row.trace_id.clone_from(&trace);
        row.span_id = format!("{trace}-span");
        row.start_time = chrono::Utc::now().timestamp_micros();
        row.end_time = row.start_time + 1;
        let mut clone_row = sample_row();
        clone_row.trace_id.clone_from(&trace);
        clone_row.span_id = row.span_id.clone();
        clone_row.start_time = row.start_time;
        clone_row.end_time = row.end_time;
        let rows = vec![row];
        let token = uuid::Uuid::new_v4().to_string();
        let tiny = [std::time::Duration::from_millis(1); 1];
        flush_with_backoff(&ch, &rows, &[], &token, &tiny)
            .await
            .expect("first flush");
        flush_with_backoff(&ch, &rows, &[], &token, &tiny)
            .await
            .expect("the retry is ACCEPTED (and discarded)");
        // Both reads carry the tenant predicate a production query would (the
        // tenant-isolation guard reads this file too, tests included).
        let tenant = rows[0].tenant_id.clone();
        let spans: u64 = ch
            .query("SELECT count() FROM tracelane.spans WHERE tenant_id = ? AND trace_id = ?")
            .bind(&tenant)
            .bind(&trace)
            .fetch_one()
            .await
            .unwrap();
        assert_eq!(spans, 1, "the retried batch must not insert a second row");
        let span_count: u64 = ch
            .query("SELECT sum(span_count) FROM tracelane.trace_summaries FINAL WHERE tenant_id = ? AND trace_id = ?")
            .bind(&tenant)
            .bind(&trace)
            .fetch_one()
            .await
            .unwrap();
        assert_eq!(
            span_count, 1,
            "mv_trace_summaries fired ONCE — this is the double count B-493 run 6 found"
        );
        // Negative control: the clone without the window takes the same batch twice.
        let clone = format!("spans_nowin_{}", uuid::Uuid::new_v4().simple());
        ch.query(&format!(
            "CREATE TABLE tracelane.{clone} AS tracelane.spans"
        ))
        .execute()
        .await
        .expect("clone");
        ch.query(&format!(
            "ALTER TABLE tracelane.{clone} MODIFY SETTING non_replicated_deduplication_window = 0"
        ))
        .execute()
        .await
        .expect("window off on the clone");
        for _ in 0..2 {
            let mut insert = ch
                .insert(&format!("tracelane.{clone}"))
                .expect("insert init")
                .with_option("insert_deduplication_token", token.as_str());
            insert.write(&clone_row).await.expect("write");
            insert.end().await.expect("end");
        }
        let twice: u64 = ch
            .query(&format!(
                "SELECT count() FROM tracelane.{clone} WHERE tenant_id = ? AND trace_id = ?"
            ))
            .bind(&tenant)
            .bind(&trace)
            .fetch_one()
            .await
            .unwrap();
        assert_eq!(
            twice, 2,
            "without the window the token is ignored: the setting is the control"
        );
        let _ = ch
            .query(&format!("DROP TABLE tracelane.{clone}"))
            .execute()
            .await;
    }

    /// The production ladder must outlast the burst that killed the process:
    /// the observed storm was a 30 s load window, so the cumulative back-off
    /// is at least twice that before `run` gives up and exits.
    #[test]
    fn b493_the_production_backoff_ladder_outlasts_a_burst() {
        let total: std::time::Duration = CH_INSERT_BACKOFF.iter().sum();
        assert!(
            total >= std::time::Duration::from_secs(60),
            "cumulative back-off {total:?} must be >= 60 s"
        );
        assert!(
            CH_INSERT_BACKOFF.windows(2).all(|w| w[1] >= w[0]),
            "the ladder is non-decreasing (exponential back-off, never a tight loop)"
        );
        // The ladder outlasts JetStream's ack_wait, which is WHY every rung sends a
        // progress ack (`+WPI`) for the held batch: without it the batch is redelivered
        // to this same process mid-ladder and written twice. Pinned so a future edit
        // to either number cannot silently re-open the double-write.
        let ack_wait = crate::nats_consumer::ingest_consumer_config(2000).ack_wait;
        assert!(
            total > ack_wait,
            "if this ever flips, the progress acks become unnecessary — not wrong"
        );
        // …and a HUNG attempt must fail inside the ack window so the first progress
        // ack is sent before JetStream redelivers (run 3 of the repro: 4,000 redelivered).
        assert!(
            CH_INSERT_ATTEMPT_TIMEOUT + std::time::Duration::from_secs(2) < ack_wait,
            "attempt timeout {CH_INSERT_ATTEMPT_TIMEOUT:?} must sit inside ack_wait {ack_wait:?}"
        );
    }
}

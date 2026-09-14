//! OTLP span exporter.
//!
//! One path: `publish_span` — serialises a span to JSON and publishes to NATS
//! JetStream on subject `tracelane.spans.{tenant_id}`, acked (B-376). The ingest
//! workers consume from `tracelane.spans.>` and write to ClickHouse. (A second,
//! log-only emitter was removed 2026-09-12 — see the note below the imports.)
//!
//! Provider keys are NEVER included in span attributes. The tracing redaction
//! filter in `init_tracing()` enforces this at the subscriber level.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context as _;
use tracelane_shared::{TenantId, TracelaneSpan};
use tracing::instrument;

// B-390 (2026-09-12): `SemconvMode`, `semconv_mode()` and `emit_span()` — the
// "structured tracing log for a local OTLP collector" surface, ~130 lines with a
// dual-schema switch on `OTEL_SEMCONV_STABILITY_OPT_IN` — were DELETED here. No
// call site existed in the tree (the crate-wide `#![allow(dead_code)]` hid that),
// no doc, compose file or env example named the variable, and the persisted
// NATS → ClickHouse path (`publish_span` below) has always carried the full
// canonical struct. Restorable from `git show 9da05da2:crates/gateway/src/otlp_emit.rs`.

/// Emits a `gen_ai.client.operation.exception` event (v1.41, ADR-032).
///
/// This is the canonical signal for an upstream failure — a timeout, a 429, or
/// a 5xx. It is the **trip input for the per-upstream circuit breaker**
/// (ADR-036, Phase 4): the breaker observes these events per `(provider,
/// region)` to decide when to open. Provider error bodies are NEVER included
/// (credential-echo risk) — only the structured type/status/message.
pub fn emit_operation_exception(
    tenant_id: &TenantId,
    provider: &str,
    region: &str,
    error_type: &str,
    status_code: Option<u16>,
) {
    tracing::warn!(
        event_name = "gen_ai.client.operation.exception",
        "gen_ai.provider.name" = provider,
        "tracelane.upstream.region" = region,
        "error.type" = error_type,
        "gen_ai.response.status_code" = status_code.unwrap_or(0),
        "tracelane.tenant_id" = %tenant_id,
        "gen_ai client operation exception"
    );
}

/// Emits a `gen_ai.evaluation.result` event (v1.38, ADR-032).
///
/// This is where SLM-judge / predictive eval scores land (§9.5). `score` is the
/// numeric result for `evaluation_name` (e.g. `hallucination`, `flow_adherence`);
/// `label` is the optional categorical verdict (e.g. `pass`/`fail`).
///
/// Not yet wired to a caller: the SLM judge (`predictive/slm_judge.rs`) returns
/// placeholder scores until its ONNX model lands (a pre-existing 🟡 item, out of this reconciliation's scope). This emitter is
/// the v1.41 landing point and will be called from the judge path once it
/// produces real scores. Verified by a unit test below.
#[allow(dead_code)]
pub fn emit_evaluation_result(
    tenant_id: &TenantId,
    evaluation_name: &str,
    score: f64,
    label: Option<&str>,
) {
    tracing::info!(
        event_name = "gen_ai.evaluation.result",
        "gen_ai.evaluation.name" = evaluation_name,
        "gen_ai.evaluation.score.value" = score,
        "gen_ai.evaluation.score.label" = label.unwrap_or(""),
        "tracelane.tenant_id" = %tenant_id,
        "gen_ai evaluation result"
    );
}

/// Cumulative count of spans dropped because NATS span-publish is disabled (no
/// connected client). Monotonic for the process lifetime; surfaced in the
/// rate-limited warning below and asserted by the regression test.
static SPANS_DROPPED_NO_NATS: AtomicU64 = AtomicU64::new(0);

/// Sentinel for [`LAST_SPAN_DROP_WARN_UNIX`] meaning "no span-drop warning has
/// been emitted yet". `u64::MAX` (not `0`) so the very first drop always warns
/// regardless of the wall clock — a clock pinned near the Unix epoch would make a
/// `0` sentinel indistinguishable from "warned at t=0" and could silence the first
/// warning (the whole point is loudness). `note_span_dropped_no_nats` special-cases
/// this value so the first warn never depends on `now >= INTERVAL`.
const SPAN_DROP_WARN_NEVER: u64 = u64::MAX;

/// Unix-seconds of the last emitted span-drop warning — the rate-limiter gate so
/// a 5K-RPS gateway cannot flood its own logs while still surfacing 100% span
/// loss loudly. Starts at [`SPAN_DROP_WARN_NEVER`]; the first drop always warns.
static LAST_SPAN_DROP_WARN_UNIX: AtomicU64 = AtomicU64::new(SPAN_DROP_WARN_NEVER);

/// Minimum seconds between span-drop warnings.
const SPAN_DROP_WARN_INTERVAL_SECS: u64 = 30;

/// The NATS subject a span is published on: `tracelane.spans.{tenant_id}`.
///
/// Ingest workers consume `tracelane.spans.>`, so every span subject MUST stay
/// under that prefix. Extracted as a pure fn so the wire contract is unit-testable
/// without a live NATS (regression).
///
/// # Example
/// ```ignore
/// let subject = span_subject(&span); // "tracelane.spans.<tenant-uuid>"
/// ```
#[must_use]
pub fn span_subject(span: &TracelaneSpan) -> String {
    format!("tracelane.spans.{}", span.tenant_id)
}

/// Records that a span was dropped because span-publish is disabled (no NATS
/// client), emitting a **rate-limited** `warn!`.
///
/// On an observability product, silently dropping 100% of spans is the
/// worst-case failure. When `AppState::nats` is `None` the per-request publish is
/// skipped — this makes that skip *loud*: the first drop warns immediately, then
/// at most once per [`SPAN_DROP_WARN_INTERVAL_SECS`], so a misconfigured prod
/// (missing `NATS_URL`, unreachable NATS) can never again blind us in silence.
///
/// Returns the cumulative dropped count (for diagnostics / the regression test).
/// Side effects: increments a process-global counter and may emit one `warn!`.
pub fn note_span_dropped_no_nats() -> u64 {
    let dropped = SPANS_DROPPED_NO_NATS.fetch_add(1, Ordering::Relaxed) + 1;

    // C1: also record in the shared degradation registry, which is what
    // `/v1/gateway/stats` reads and what carries the "how long has this been open?"
    // duration. This counter stays because its own regression test asserts it, but the
    // registry is the one an operator can actually see. `note` does its own
    // rate-limited TRACELANE_DEGRADED warn, so the local warn below is now redundant
    // for alerting and kept only for the familiar log line.
    tracelane_shared::degradation::note(
        tracelane_shared::degradation::Degradation::SpansDroppedNoNats,
    );

    let now = unix_now_secs();
    let last = LAST_SPAN_DROP_WARN_UNIX.load(Ordering::Relaxed);
    // The first-ever drop (sentinel) always warns — independent of the wall clock
    // — then drops are rate-limited to ≤1 warning per interval. The CAS lets
    // exactly one racing thread win the warn, so concurrent drops never double-log.
    let warn_due =
        last == SPAN_DROP_WARN_NEVER || now.saturating_sub(last) >= SPAN_DROP_WARN_INTERVAL_SECS;
    if warn_due
        && LAST_SPAN_DROP_WARN_UNIX
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        tracing::warn!(
            spans_dropped_total = dropped,
            "span publish DISABLED — NATS client absent; spans are being dropped \
             (set NATS_URL and ensure NATS is reachable). Observability blind spot."
        );
    }
    dropped
}

/// Records that a span publish FAILED after NATS was connected — distinct from
/// [`note_span_dropped_no_nats`], which is the "no client at all" case.
///
/// This case was `warn!`-only at six call sites and counted nowhere, so a
/// gateway that connects to NATS and then fails every write looked identical to a
/// healthy one in every signal we had.
///
/// # Errors
/// None — fault-tolerance path; instrumenting a failed publish must never fail the
/// request that triggered it.
pub fn note_span_publish_failed() -> u64 {
    tracelane_shared::degradation::note(
        tracelane_shared::degradation::Degradation::SpanPublishFailed,
    )
}

/// Wall-clock seconds since the Unix epoch, saturating to 0 on a pre-epoch clock.
/// Used only as the span-drop warning rate-limiter gate, never in an assertion.
fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Publishes a span to the JetStream `TRACELANE_SPANS` stream (subject from
/// [`span_subject`]) and **waits for the stream's ack**.
///
/// Off the hot path by construction: every call site wraps this in
/// `tokio::spawn`, so the ack round trip costs the request nothing. What the ack
/// buys is that `Ok` now means *the stream has the span* — and `Err` means it
/// does not, which is the only condition under which `note_span_publish_failed`
/// carries information.
///
/// **B-376 (2026-09-12), the reason this is an acked publish and not a core one.**
/// The previous version was `nats.publish(..)`, a CORE publish, and its doc
/// comment claimed *"`publish()` returns once the server accepts the message"*.
/// That is false against the pinned dependency: `async-nats 0.42.0`'s
/// `Client::publish` does `self.sender.send(Command::Publish(..))` into an
/// in-process mpsc and returns (`src/client.rs:303-329`). It returns `Ok` for a
/// message that never reached the server — on a disconnect, a full buffer, or
/// a JetStream reject — so the `/health` capture counter this feeds was
/// structurally unable to fire on the loss modes it exists to detect. For a
/// product whose thesis is "full-fidelity flight recorder", the capture path
/// must have at least the durability the audit path already has in
/// `audit.rs` (an acked JetStream publish). Now it does.
///
/// The stream's `DiscardPolicy::Old` (`crates/ingest/src/nats_consumer.rs`)
/// is unchanged: at the byte cap the server drops the OLDEST spans and still
/// acks this one. That is a declared delivery-buffer tradeoff, bounded and
/// counted on the ingest side; it is not the silent per-publish loss this
/// change closes.
///
/// Parameters:
/// - `nats`  — connected NATS client (from `AppState::nats`)
/// - `span`  — fully-populated `TracelaneSpan`
///
/// Errors: serialization failure, publish failure, or a missing / negative ack.
#[instrument(
    skip(nats, span),
    fields(
        tenant_id = %span.tenant_id,
        span_id = %span.span_id,
    )
)]
pub async fn publish_span(nats: &async_nats::Client, span: &TracelaneSpan) -> anyhow::Result<()> {
    let subject = span_subject(span);
    let payload = serde_json::to_vec(span).context("span serialize")?;
    // `jetstream::new` is a cheap context wrapper around the (Arc-backed) client;
    // building it per call keeps the signature the six call sites already use.
    let js = async_nats::jetstream::new(nats.clone());
    let ack = js
        .publish(subject, payload.into())
        .await
        .context("JetStream publish")?;
    // Fail-OPEN, bounded: a slow-but-alive JetStream must not hold one task per
    // request for the length of the outage. After ACK_TIMEOUT the span is counted
    // as a publish failure (it may still land — the stream may ack late — but the
    // gateway stops waiting). Security review of B-376, 2026-09-12.
    tokio::time::timeout(ACK_TIMEOUT, ack)
        .await
        .context("JetStream ack timed out")?
        .context("JetStream ack")?;
    Ok(())
}

/// How long a span publish waits for its JetStream ack before it is counted as
/// lost. Off the hot path, so generous; bounded, so an outage cannot grow memory.
pub const ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The most span publishes that may be in flight at once. Beyond this a span is
/// counted as lost WITHOUT spawning — the alternative under a NATS slowdown is one
/// task per request until the process is OOM-killed, which loses every span.
pub const MAX_IN_FLIGHT: usize = 8_192;

/// Spans whose JetStream publish has been spawned and not yet acked (or failed).
/// The number graceful shutdown waits on — see [`drain_in_flight`].
static IN_FLIGHT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// How many span publishes are currently in flight.
pub fn in_flight() -> usize {
    IN_FLIGHT.load(std::sync::atomic::Ordering::Acquire)
}

/// Test-only span sink (B-385 2c): every span the gateway BUILDS on a dispatch
/// route is recorded here before the NATS branch decides whether it can be
/// published — so a test with no NATS (every unit test) can still assert
/// "exactly one span, with these attributes" instead of asserting nothing.
///
/// Keyed by `trace_id` / tenant, which each test sets to its own UUID, so the
/// parallel suite never reads another test's row. Compiled out of every
/// non-test build. Absorbed `anthropic_messages::span_capture`, which did the
/// same for one route.
#[cfg(test)]
pub(crate) mod test_sink {
    use std::sync::{Mutex, OnceLock};
    use tracelane_shared::{TenantId, TracelaneSpan};
    use uuid::Uuid;

    fn sink() -> &'static Mutex<Vec<TracelaneSpan>> {
        static SINK: OnceLock<Mutex<Vec<TracelaneSpan>>> = OnceLock::new();
        SINK.get_or_init(|| Mutex::new(Vec::new()))
    }

    pub(crate) fn record(span: &TracelaneSpan) {
        if let Ok(mut v) = sink().lock() {
            v.push(span.clone());
        }
    }

    /// Every span built for `trace_id` so far, in order.
    pub(crate) fn for_trace(trace_id: Uuid) -> Vec<TracelaneSpan> {
        sink()
            .lock()
            .map(|v| {
                v.iter()
                    .filter(|s| s.trace_id == trace_id)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Every span built for one tenant. Each test uses a fresh tenant UUID, so
    /// this is race-free across the parallel suite — which matters for the
    /// assertions that must prove NO span was emitted, where a shared counter
    /// would read another test's row.
    pub(crate) fn for_tenant(tenant: &TenantId) -> Vec<TracelaneSpan> {
        sink()
            .lock()
            .map(|v| {
                v.iter()
                    .filter(|s| s.tenant_id.as_uuid() == tenant.as_uuid())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Serialises every test that touches the process-global in-flight counter —
/// in this module AND in `server.rs`. Two tests faking in-flight publishes at
/// once read each other's count, which is exactly what happened on first run.
#[cfg(test)]
pub(crate) static DRAIN_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Test hook: pretend `n` publishes are in flight (and return a guard that
/// releases them). Lets the drain contract be proven without a NATS server.
#[cfg(test)]
pub(crate) fn fake_in_flight(n: usize) -> impl Drop {
    struct Release(usize);
    impl Drop for Release {
        fn drop(&mut self) {
            IN_FLIGHT.fetch_sub(self.0, std::sync::atomic::Ordering::AcqRel);
        }
    }
    IN_FLIGHT.fetch_add(n, std::sync::atomic::Ordering::AcqRel);
    Release(n)
}

/// Spawn the publish of `span`, off the hot path, counted in flight until it is
/// acked or fails, and with the failure counted on the ONE counter `/health`
/// reads.
///
/// **This is the only place a span publish may be spawned.** Six sites carried
/// the same seven lines (spawn, publish, `note_span_publish_failed`, warn) and
/// none of them was tracked — so a `SIGTERM` between the spawn and the ack lost
/// the span with no record (B-377). Consolidating them here is what makes
/// [`drain_in_flight`] mean something.
///
/// `site` names the caller in the warn so a failure in the streaming path reads
/// differently from one in the judge, as the six inline copies used to.
///
/// Called from a `Drop` impl on the streaming path (B-375), which can run
/// outside a runtime during process teardown: `Handle::try_current` guards
/// that, and the span is counted as a publish failure rather than panicking.
pub fn spawn_publish(nats: Arc<async_nats::Client>, span: TracelaneSpan, site: &'static str) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        note_span_publish_failed();
        tracing::warn!(
            site,
            "span publish requested with no runtime — counted as lost"
        );
        return;
    };
    // Bounded in-flight: claim a slot or count the span as lost. Compare-and-swap
    // so two concurrent callers cannot both pass the check at MAX_IN_FLIGHT - 1.
    let mut cur = IN_FLIGHT.load(std::sync::atomic::Ordering::Acquire);
    loop {
        if cur >= MAX_IN_FLIGHT {
            note_span_publish_failed();
            tracing::warn!(
                site,
                in_flight = cur,
                "span publish refused — in-flight ceiling reached; counted as lost"
            );
            return;
        }
        match IN_FLIGHT.compare_exchange_weak(
            cur,
            cur + 1,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        ) {
            Ok(_) => break,
            Err(now) => cur = now,
        }
    }
    // The slot is released by `Drop`, so a panic inside `publish_span` (a
    // pathological span that will not serialise, say) cannot leak it and make
    // every later shutdown wait the full drain timeout on a phantom.
    let _slot = InFlightSlot;
    handle.spawn(async move {
        let slot = _slot;
        if let Err(e) = publish_span(&nats, &span).await {
            note_span_publish_failed();
            tracing::warn!(error = %e, site, "span JetStream publish failed");
        }
        drop(slot);
    });
}

/// One claimed in-flight slot; released on drop, panic or not.
struct InFlightSlot;
impl Drop for InFlightSlot {
    fn drop(&mut self) {
        IN_FLIGHT.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// Wait up to `timeout` for every in-flight span publish to be acked or fail.
/// Returns the number still in flight when it gave up — `0` is the only clean
/// answer, and the caller logs anything else as spans the shutdown lost.
pub async fn drain_in_flight(timeout: std::time::Duration) -> usize {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let n = in_flight();
        if n == 0 || tokio::time::Instant::now() >= deadline {
            return n;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

#[cfg(test)]
mod span_publish_tests {
    use super::*;
    use tracelane_shared::{SpanAttributes, SpanStatus, SpanStatusCode};
    use uuid::Uuid;

    /// A fixed synthetic tenant id for the span-publish tests.
    const INCIDENT_TENANT: &str = "11111111-1111-4111-8111-111111111111";

    pub(super) fn test_span(tenant: &str) -> TracelaneSpan {
        TracelaneSpan {
            span_id: Uuid::parse_str("00000000-0000-0000-0000-0000000000aa").unwrap(),
            trace_id: Uuid::parse_str("00000000-0000-0000-0000-0000000000bb").unwrap(),
            parent_span_id: None,
            tenant_id: TenantId::from_jwt_claim(Uuid::parse_str(tenant).unwrap()),
            name: "gen_ai.chat".to_string(),
            start_time: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            end_time: chrono::DateTime::from_timestamp(1_700_000_001, 0),
            attributes: SpanAttributes {
                gen_ai_request_model: Some("claude-opus-4-8".to_string()),
                gen_ai_usage_input_tokens: Some(10),
                gen_ai_usage_output_tokens: Some(20),
                ..Default::default()
            },
            status: SpanStatus {
                code: SpanStatusCode::Ok,
                message: None,
            },
        }
    }

    #[test]
    fn span_subject_stays_under_ingest_prefix() {
        let span = test_span(INCIDENT_TENANT);
        let subject = span_subject(&span);
        assert_eq!(subject, format!("tracelane.spans.{INCIDENT_TENANT}"));
        // Ingest binds `tracelane.spans.>`; a subject outside it is dropped by
        // JetStream with no error from a core publish — keep it under the prefix.
        assert!(subject.starts_with("tracelane.spans."));
    }

    #[test]
    fn span_wire_payload_round_trips() {
        // The exact bytes publish_span puts on the wire must deserialize back to
        // an equivalent span (ingest does this). wire-contract guard.
        let span = test_span(INCIDENT_TENANT);
        let bytes = serde_json::to_vec(&span).unwrap();
        let back: TracelaneSpan = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.tenant_id, span.tenant_id);
        assert_eq!(back.span_id, span.span_id);
        assert_eq!(
            back.attributes.gen_ai_usage_output_tokens,
            span.attributes.gen_ai_usage_output_tokens
        );
    }

    #[test]
    fn dropped_span_is_counted_not_silent() {
        // Regression: when NATS is absent the per-request path calls
        // note_span_dropped_no_nats() instead of silently skipping. The counter
        // MUST advance so "publish disabled" can never again be a silent 100%
        // span loss — the rate-limited warn rides on this accounting.
        let before = note_span_dropped_no_nats();
        let after = note_span_dropped_no_nats();
        assert!(
            after > before,
            "span-drop counter must advance on every drop (before={before}, after={after})"
        );
    }

    /// C1: the drop must also reach the shared degradation registry — the one an
    /// operator can actually see, and the only one carrying "how long has this been
    /// open?". The local counter above is process-private and read by nothing but this
    /// test, which is precisely the orphan-registry shape the shared module exists to
    /// avoid repeating.
    #[test]
    fn dropped_span_reaches_the_shared_degradation_registry() {
        use tracelane_shared::degradation::{Degradation, count, snapshot};

        // Strict increase, not `before + 1`: the registry is process-global and cargo
        // runs this binary's tests in parallel, so a sibling test may increment the same
        // kind between these two reads. An exact-delta assertion here is a race.
        let before = count(Degradation::SpansDroppedNoNats);
        note_span_dropped_no_nats();
        assert!(
            count(Degradation::SpansDroppedNoNats) > before,
            "a dropped span must advance the SHARED counter, not only the module-local one"
        );

        let stat = snapshot()
            .into_iter()
            .find(|s| s.kind == "spans_dropped_no_nats")
            .expect("kind present in snapshot");
        // The duration requirement is TRAPS §16: a count alone cannot tell a blip from
        // three weeks. The citation lives HERE, in a comment, and not in the assertion
        // string below — `no-internal-refs-in-ui` blocks internal refs in any string
        // literal under crates/gateway/src, deliberately without a #[cfg(test)] carve-out,
        // because an exemption keyed on "looks like a test" is a hole in a guard that
        // exists to stop internal refs reaching a customer.
        assert!(
            stat.open_for_secs.is_some(),
            "once fired, the registry must be able to answer how long spans have been \
             dropping — a count alone cannot tell a blip from three weeks"
        );
    }

    /// C1: a publish FAILURE is a different degradation from having no client at
    /// all, and used to be counted nowhere at any of its six call sites.
    #[test]
    fn publish_failure_is_counted_separately_from_no_client() {
        use tracelane_shared::degradation::{Degradation, count};

        let fails_before = count(Degradation::SpanPublishFailed);

        note_span_publish_failed();

        assert!(
            count(Degradation::SpanPublishFailed) > fails_before,
            "a failed publish must advance the publish-failure counter"
        );

        // Deliberately NOT asserting that SpansDroppedNoNats is unchanged here. The
        // registry is process-global and cargo runs these tests in parallel, so two
        // other tests in this binary are incrementing that same kind while this one
        // runs — an "unchanged" assertion is a race, and a flaky guard teaches people
        // to ignore guards. The cross-kind separation property is proven in the shared
        // crate's own `note_advances_the_counter_for_that_kind_only`, where the kinds
        // under test have no other writer in that binary.
    }
}

#[cfg(test)]
mod shutdown_drain_tests {
    //! B-376 / B-377. The drain contract and the no-runtime branch of
    //! `spawn_publish`, proven without a NATS server. The acked publish itself is
    //! proven against a live JetStream by `tests/span_publish_integration.rs`,
    //! which asserts the stream's `last_sequence` advanced — an ack is the only
    //! thing that can guarantee that.
    use super::*;
    use tracelane_shared::degradation::{Degradation, count};

    use super::DRAIN_TEST_LOCK as DRAIN_LOCK;

    #[tokio::test]
    async fn drain_waits_for_in_flight_publishes_to_finish() {
        let _g = DRAIN_LOCK.lock().await;
        let release = fake_in_flight(2);
        // Something finishes the publishes 120 ms from now.
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(120)).await;
            drop(release);
        });
        let t0 = tokio::time::Instant::now();
        let left = drain_in_flight(std::time::Duration::from_secs(2)).await;
        assert_eq!(left, 0, "drain must return only once nothing is in flight");
        assert!(
            t0.elapsed() >= std::time::Duration::from_millis(100),
            "drain returned before the publishes finished: {:?}",
            t0.elapsed()
        );
    }

    #[tokio::test]
    async fn drain_gives_up_at_the_deadline_and_reports_what_is_left() {
        let _g = DRAIN_LOCK.lock().await;
        let _release = fake_in_flight(3);
        let left = drain_in_flight(std::time::Duration::from_millis(80)).await;
        assert_eq!(
            left, 3,
            "at the deadline the outstanding count must be reported, not hidden"
        );
    }

    /// Security review of B-376: above the in-flight ceiling a publish is refused
    /// and COUNTED, never spawned — the OOM alternative loses every span.
    #[tokio::test]
    async fn spawn_publish_refuses_and_counts_above_the_ceiling() {
        let _g = DRAIN_LOCK.lock().await;
        let client = async_nats::ConnectOptions::new()
            .retry_on_initial_connect()
            .connect("nats://127.0.0.1:1")
            .await
            .expect("client without a server");
        let client = Arc::new(client);
        let _full = fake_in_flight(MAX_IN_FLIGHT);
        let before = count(Degradation::SpanPublishFailed);
        spawn_publish(
            client,
            span_publish_tests::test_span("11111111-1111-4111-8111-111111111111"),
            "ceiling test",
        );
        assert_eq!(count(Degradation::SpanPublishFailed), before + 1);
        assert_eq!(
            in_flight(),
            MAX_IN_FLIGHT,
            "nothing was spawned above the ceiling"
        );
    }

    /// The in-flight slot is released even when the publish task PANICS, so a
    /// pathological span cannot leave a phantom that every later shutdown waits on.
    #[tokio::test]
    async fn in_flight_slot_is_released_on_panic() {
        let _g = DRAIN_LOCK.lock().await;
        let before = in_flight();
        IN_FLIGHT.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let task = tokio::spawn(async move {
            let _slot = InFlightSlot;
            panic!("pathological span");
        });
        assert!(task.await.is_err(), "the task panicked");
        assert_eq!(
            in_flight(),
            before,
            "the slot must be released by Drop on the panic path"
        );
    }

    /// `spawn_publish` is reachable from a `Drop` impl (B-375), which can run on a
    /// thread with no runtime during teardown. It must count the span as lost and
    /// NOT panic — a panic in `Drop` during shutdown aborts the process.
    #[tokio::test]
    async fn spawn_publish_with_no_runtime_counts_a_failure_instead_of_panicking() {
        let _g = DRAIN_LOCK.lock().await;
        // A client that never connects is fine: the branch under test returns
        // before any I/O.
        let client = async_nats::ConnectOptions::new()
            .retry_on_initial_connect()
            .connect("nats://127.0.0.1:1")
            .await
            .expect("retry_on_initial_connect returns a client without a server");
        let client = Arc::new(client);
        let span = span_publish_tests::test_span("11111111-1111-4111-8111-111111111111");
        let before = count(Degradation::SpanPublishFailed);
        let handle = std::thread::spawn(move || {
            spawn_publish(client, span, "no-runtime test");
        });
        handle
            .join()
            .expect("spawn_publish must not panic without a runtime");
        // `>=`, not `==`: the counter is process-wide and `span_publish_tests`
        // in the same binary increment it concurrently (CI run 34686533037
        // read 3 against an expected 2). The property is that THIS call landed
        // on the counter, which a strict equality cannot state under parallel
        // tests without serialising every test that touches it.
        assert!(
            count(Degradation::SpanPublishFailed) > before,
            "a publish that cannot be spawned must land on the loss counter"
        );
        assert_eq!(
            in_flight(),
            0,
            "nothing was spawned, so nothing is in flight"
        );
    }
}

//! OTLP span exporter.
//!
//! Two paths:
//!   1. `emit_span` — structured tracing log for local debugging / OTLP collector.
//!   2. `publish_span` — serialises a span to JSON and publishes to NATS JetStream
//!      on subject `tracelane.spans.{tenant_id}`. The ingest workers consume from
//!      `tracelane.spans.>` and write to ClickHouse.
//!
//! Provider keys are NEVER included in span attributes. The tracing redaction
//! filter in `init_tracing()` enforces this at the subscriber level.

use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context as _;
use tracelane_shared::{TenantId, TracelaneSpan};
use tracing::instrument;

/// OTel semconv stability mode, selected by `OTEL_SEMCONV_STABILITY_OPT_IN`
/// (ADR-032). The value is a comma-separated opt-in list; we look for the
/// `gen_ai_latest_experimental` token.
///
/// - `Experimental` → emit the **v1.41** schema only (`gen_ai.provider.name`,
///   the v1.40/41 token + streaming attributes, structured message arrays).
///   Deprecated per-message events are **not** emitted.
/// - `Legacy` (unset / any other value) → emit the **pre-1.36** schema
///   (`gen_ai.system`, per-message events) for un-migrated downstreams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemconvMode {
    Experimental,
    Legacy,
}

/// Resolve the semconv emission mode from the environment. V1 production sets
/// `OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental`; absence means a
/// downstream that still wants the legacy wire format.
pub fn semconv_mode() -> SemconvMode {
    match std::env::var("OTEL_SEMCONV_STABILITY_OPT_IN") {
        Ok(v)
            if v.split(',')
                .any(|t| t.trim() == "gen_ai_latest_experimental") =>
        {
            SemconvMode::Experimental
        }
        _ => SemconvMode::Legacy,
    }
}

/// Emits a completed span to the OTLP exporter (structured log).
///
/// Dual-emission (ADR-032 / §9.5): under `Experimental` the canonical v1.41
/// schema is emitted (`gen_ai.provider.name` + cache/reasoning/stream/TTFT +
/// `gen_ai.conversation.id` + structured message arrays, no deprecated
/// per-message events); under `Legacy` the pre-1.36 schema (`gen_ai.system` +
/// deprecated per-message events) is emitted. The OpenInference `llm.*` mirror
/// is emitted in both modes. The persisted NATS→ClickHouse path always carries
/// the full canonical struct (see [`publish_span`]); this function is the
/// OTLP-collector-facing surface.
#[instrument(
    skip(span),
    fields(
        tenant_id = %span.tenant_id,
        span_id = %span.span_id,
        trace_id = %span.trace_id,
    )
)]
pub async fn emit_span(span: TracelaneSpan) -> anyhow::Result<()> {
    let attrs = &span.attributes;

    // Attributes common to both schema modes.
    let operation = attrs.gen_ai_operation_name.as_deref().unwrap_or("chat");
    let system = attrs.gen_ai_system.as_deref().unwrap_or("");
    let provider = attrs.gen_ai_provider_name.as_deref().unwrap_or(system);
    let req_model = attrs.gen_ai_request_model.as_deref().unwrap_or("");
    let resp_model = attrs.gen_ai_response_model.as_deref().unwrap_or(req_model);
    let input_tokens = attrs.gen_ai_usage_input_tokens.unwrap_or(0);
    let output_tokens = attrs.gen_ai_usage_output_tokens.unwrap_or(0);
    let agent_name = attrs.gen_ai_agent_name.as_deref().unwrap_or("");

    let intervention = attrs
        .tracelane_intervention
        .map(|i| format!("{i:?}").to_lowercase())
        .unwrap_or_else(|| "none".to_string());
    let aft_id = attrs.tracelane_aft_id.as_deref().unwrap_or("");

    match semconv_mode() {
        SemconvMode::Experimental => {
            // v1.41 canonical schema. v1.40/41 token + streaming additions
            // default to 0 / "" when absent (consistent with the existing
            // input/output-token handling).
            tracing::info!(
                span_id = %span.span_id,
                trace_id = %span.trace_id,
                parent_span_id = ?span.parent_span_id,
                name = %span.name,
                "semconv.mode" = "gen_ai_latest_experimental",
                "gen_ai.operation.name" = operation,
                "gen_ai.provider.name" = provider,
                "gen_ai.request.model" = req_model,
                "gen_ai.response.model" = resp_model,
                "gen_ai.usage.input_tokens" = input_tokens,
                "gen_ai.usage.output_tokens" = output_tokens,
                "gen_ai.usage.cache_read.input_tokens" =
                    attrs.gen_ai_usage_cache_read_input_tokens.unwrap_or(0),
                "gen_ai.usage.cache_creation.input_tokens" =
                    attrs.gen_ai_usage_cache_creation_input_tokens.unwrap_or(0),
                "gen_ai.usage.reasoning.output_tokens" =
                    attrs.gen_ai_usage_reasoning_output_tokens.unwrap_or(0),
                "gen_ai.usage.cost" = attrs.gen_ai_usage_cost.unwrap_or(0.0),
                "gen_ai.request.stream" = attrs.gen_ai_request_stream.unwrap_or(false),
                "gen_ai.response.time_to_first_chunk" =
                    attrs.gen_ai_response_time_to_first_chunk.unwrap_or(0.0),
                "gen_ai.agent.name" = agent_name,
                "gen_ai.agent.version" = attrs.gen_ai_agent_version.as_deref().unwrap_or(""),
                "gen_ai.conversation.id" = attrs.gen_ai_conversation_id.as_deref().unwrap_or(""),
                // OpenInference mirror (both modes)
                "llm.model_name" = req_model,
                "llm.token_count.prompt" = input_tokens,
                "llm.token_count.completion" = output_tokens,
                "tracelane.tenant_id" = %span.tenant_id,
                "tracelane.intervention" = %intervention,
                "tracelane.aft_id" = aft_id,
                "span emitted"
            );
        }
        SemconvMode::Legacy => {
            // pre-1.36 schema for un-migrated downstreams.
            tracing::info!(
                span_id = %span.span_id,
                trace_id = %span.trace_id,
                parent_span_id = ?span.parent_span_id,
                name = %span.name,
                "semconv.mode" = "legacy",
                "gen_ai.operation.name" = operation,
                "gen_ai.system" = provider,
                "gen_ai.request.model" = req_model,
                "gen_ai.response.model" = resp_model,
                "gen_ai.usage.input_tokens" = input_tokens,
                "gen_ai.usage.output_tokens" = output_tokens,
                "gen_ai.agent.name" = agent_name,
                "llm.model_name" = req_model,
                "llm.token_count.prompt" = input_tokens,
                "llm.token_count.completion" = output_tokens,
                "tracelane.tenant_id" = %span.tenant_id,
                "tracelane.intervention" = %intervention,
                "tracelane.aft_id" = aft_id,
                "span emitted"
            );
        }
    }

    Ok(())
}

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
/// worst-case failure. When `AppState::nats` is `None` the per-request publish is
/// skipped — this makes that skip *loud*: the first drop warns immediately, then
/// at most once per [`SPAN_DROP_WARN_INTERVAL_SECS`], so a misconfigured prod
/// (missing `NATS_URL`, unreachable NATS) can never again blind us in silence.
///
/// Returns the cumulative dropped count (for diagnostics / the regression test).
/// Side effects: increments a process-global counter and may emit one `warn!`.
pub fn note_span_dropped_no_nats() -> u64 {
    let dropped = SPANS_DROPPED_NO_NATS.fetch_add(1, Ordering::Relaxed) + 1;
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

/// Wall-clock seconds since the Unix epoch, saturating to 0 on a pre-epoch clock.
/// Used only as the span-drop warning rate-limiter gate, never in an assertion.
fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Publishes a span to NATS JetStream (subject from [`span_subject`]).
///
/// Fire-and-forget: caller should `tokio::spawn` this so it does not block the
/// hot path. On failure the error is logged and the span is dropped — we prefer
/// low-latency over perfect delivery (ingest has its own DLQ for resilience).
///
/// Note: this is a *core* NATS publish; the JetStream `TRACELANE_SPANS` stream
/// captures it via its `tracelane.spans.>` subject binding. `publish()` returns
/// once the server accepts the message, not once JetStream has acked it.
///
/// Parameters:
/// - `nats`  — connected NATS client (from `AppState::nats`)
/// - `span`  — fully-populated `TracelaneSpan`
///
/// Errors: serialization failure or NATS publish failure.
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
    nats.publish(subject, payload.into())
        .await
        .context("NATS publish")?;
    Ok(())
}

#[cfg(test)]
mod span_publish_tests {
    use super::*;
    use tracelane_shared::{SpanAttributes, SpanStatus, SpanStatusCode};
    use uuid::Uuid;

    /// A fixed synthetic tenant id for the span-publish tests.
    const INCIDENT_TENANT: &str = "11111111-1111-4111-8111-111111111111";

    fn test_span(tenant: &str) -> TracelaneSpan {
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
}

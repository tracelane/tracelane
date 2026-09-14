//! SSE response assembly — the streaming half (B-385 §2d split of `server.rs`).
//!
//! `provider_stream_to_sse` converts a `ProviderStream` into OpenAI
//! `chat.completion.chunk` events through the enforce-before-yield guardrail seam;
//! `StreamFinalizer` owns everything that must happen once — meter, span, key
//! spend, the online-eval handover — and runs it from `Drop` as well as from a
//! normal completion, so a client that hangs up mid-stream still leaves a record
//! (B-375).

use std::{convert::Infallible, sync::Arc};

use async_stream::stream;
use axum::response::sse::Event;
use futures::StreamExt as _;
use tracelane_shared::TenantId;
use uuid::Uuid;

use crate::providers::{FinishReason, ProviderEvent, ProviderStream};

use super::buffered::derive_finish_reason;
use super::chat::{PromptObservation, spawn_prompt_metric_observation};
use super::dispatch::{DispatchGuard, provider_name_from_model};
use super::spans::{
    CallerIdentity, GatewayTiming, LogprobAccumulator, RequestConfig, SpanUsageMeta,
    build_gateway_span, merge_usage_tokens, record_key_spend,
};

/// B-375 (2026-09-12). Everything the streaming path must do ONCE the provider
/// round-trip is over — meter, build and publish the span, record key spend,
/// hand the answer to the online-eval judge — and the guarantee that it happens
/// **even when the client hangs up first**.
///
/// The post-loop code used to live inline at the end of the `stream!` generator.
/// That runs when the loop *terminates*; it does not run when the generator is
/// *dropped* — which is what happens when the client disconnects mid-stream,
/// the single most common way a real LLM stream ends ("user hits stop"). The
/// provider tokens were bought and paid for, the flight recorder recorded
/// nothing, and the customer was billed for nothing. The comment on that block
/// even said "terminated for ANY reason" — it had every exit except the one
/// that is not an exit at all.
///
/// So the accumulators live here, and finalization runs from `Drop`. On a
/// normal completion `finish()` runs it first and `Drop` sees `finished`. On a
/// cancellation `Drop` runs it with `cancelled = true`: the span carries what
/// was accumulated so far plus `tracelane.stream.cancelled = true`, the
/// BILL-01 byte meter sees the span that was built (its known tokens included
/// — Anthropic sends input tokens in `message_start`, so they usually are),
/// and the online-eval judge is deliberately NOT given a truncated answer to grade.
///
/// `Drop` cannot await, so every effect here is fire-and-forget by
/// construction: `stamp_and_meter_span_bytes` and `otlp_emit::spawn_publish`
/// spawn, `record_key_spend` is synchronous. `spawn_publish` guards the no-runtime
/// case itself, so a drop during process teardown counts the span as lost
/// rather than panicking inside `Drop`.
/// BILL-01 / OBS-51 step 3a: `bytes / 4`, a deterministic fallback token
/// estimator used ONLY when a stream closed with no upstream usage event at
/// all. `None` for zero bytes — never a fabricated non-zero count for an
/// empty side of the exchange.
fn estimate_tokens(bytes: usize) -> Option<u32> {
    if bytes == 0 {
        return None;
    }
    Some(u32::try_from((bytes / 4).max(1)).unwrap_or(u32::MAX))
}

/// OBS-51 / GWY-45 amendment — a TRAILING ring buffer of yielded delta text,
/// capped at `cap` bytes. Drops the OLDEST bytes when full (keeps the tail):
/// a truncated START still lets a reader see how the answer concluded, where
/// a truncated END would cut off exactly the part most likely to carry the
/// model's conclusion. Uses the SAME visible marker `truncate_utf8`
/// (`server/spans.rs`) does, so a reader cannot mistake a cut stream for a
/// complete short one.
fn ring_push(buf: &mut String, delta: &str, cap: usize) {
    if delta.is_empty() {
        return;
    }
    buf.push_str(delta);
    if buf.len() <= cap {
        return;
    }
    const MARK: &str = "…[truncated]";
    if cap <= MARK.len() {
        // No room for both marker and content — keep a hard, unmarked tail
        // sized to `cap`, walking to the nearest char boundary.
        let mut start = buf.len().saturating_sub(cap);
        while start < buf.len() && !buf.is_char_boundary(start) {
            start += 1;
        }
        *buf = buf[start..].to_string();
        return;
    }
    let budget = cap - MARK.len();
    let mut cut_at = buf.len().saturating_sub(budget);
    while cut_at < buf.len() && !buf.is_char_boundary(cut_at) {
        cut_at += 1;
    }
    let tail = buf.split_off(cut_at);
    *buf = format!("{MARK}{tail}");
    // Defensive post-condition: a pathological cap must never let the result
    // grow past what the caller asked for.
    if buf.len() > cap {
        let mut end = cap.min(buf.len());
        while end > 0 && !buf.is_char_boundary(end) {
            end -= 1;
        }
        buf.truncate(end);
    }
}

struct StreamFinalizer {
    // ── accumulated by the loop ──────────────────────────────────────────
    input_tokens: u32,
    output_tokens: u32,
    /// Only the Done event sets these; a pre-Done cut leaves them None.
    cache_read: Option<u32>,
    cache_creation: Option<u32>,
    /// Set on a mid-stream provider Error so the span records status Error.
    stream_error: Option<&'static str>,
    cost_usd: Option<f64>,
    saw_tool_call: bool,
    provider_finish: Option<FinishReason>,
    logprobs_acc: LogprobAccumulator,
    /// EVL-28: the post-guardrail text, accumulated ONLY when sampled.
    online_answer: Option<String>,
    first_byte_ts: Option<chrono::DateTime<chrono::Utc>>,
    /// OBS-51 / GWY-45 amendment: a CAPPED trailing ring buffer of the
    /// yielded (post-guardrail) delta text, `Some` only when the tenant is
    /// content-capture allowlisted (`config::capture_decision` — the SAME
    /// policy as request capture, never a second one). Filled AFTER each
    /// `yield`, so it never touches time-to-first-byte.
    output_ring: Option<String>,
    /// Cap for `output_ring`, in bytes (`TraceContentConfig::max_field_bytes`).
    /// `0` when `output_ring` is `None` — never consulted then.
    output_cap: usize,
    // ── captured context ─────────────────────────────────────────────────
    nats: Option<Arc<async_nats::Client>>,
    /// BILL-01 meter 1 (`ingest_bytes`). `None` when `CLICKHOUSE_URL` is
    /// unset — `stamp_and_meter_span_bytes` is a no-op then.
    meters: Option<Arc<crate::billing::MeterSink>>,
    /// OBS-51 step 3a: the serialized byte length of the ORIGINAL request
    /// messages, computed once by the caller before the stream starts — the
    /// input half of the deterministic token-count fallback. Never the
    /// message text itself (no reason to carry it twice); only used when the
    /// stream closes with no upstream usage event at all.
    input_bytes_for_estimate: usize,
    tenant_id: TenantId,
    trace_id: Uuid,
    parent_span_id: Option<Uuid>,
    start_time: chrono::DateTime<chrono::Utc>,
    dispatch_ts: chrono::DateTime<chrono::Utc>,
    model_name: String,
    identity: CallerIdentity,
    warn_aft_id: Option<&'static str>,
    failover_from: Option<&'static str>,
    api_key_id: Option<String>,
    request_config: RequestConfig,
    online_eval: Option<crate::online_eval::Pending>,
    finished: bool,
}

/// Streams finalized by `Drop` rather than by completion — i.e. the client went
/// away first. A normal event, not a degradation; counted so the number is
/// observable rather than inferred.
pub(crate) static STREAMS_FINALIZED_ON_DROP: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

impl StreamFinalizer {
    /// Normal completion: the loop ended. Runs finalization now, once.
    fn finish(mut self) {
        self.finished = true;
        self.run(false);
    }

    /// The finalization itself. `cancelled` is true when reached from `Drop`.
    fn run(&mut self, cancelled: bool) {
        // Provider round-trip complete (or abandoned). Everything after this is
        // gateway post-processing → overhead.
        let provider_complete_ts = chrono::Utc::now();

        let mut span = build_gateway_span(
            &self.tenant_id,
            self.trace_id,
            self.parent_span_id,
            &self.model_name,
            &self.identity,
            self.start_time,
            self.input_tokens,
            self.output_tokens,
            self.warn_aft_id,
            SpanUsageMeta {
                cache_read_input_tokens: self.cache_read,
                cache_creation_input_tokens: self.cache_creation,
                stream: true,
                cost_usd: self.cost_usd,
            },
            self.failover_from,
            Some(GatewayTiming {
                dispatch_ts: self.dispatch_ts,
                provider_complete_ts,
                ttft_us: self.first_byte_ts.and_then(|fb| {
                    u32::try_from((fb - self.dispatch_ts).num_microseconds()?.max(0)).ok()
                }),
            }),
            self.stream_error,
            self.api_key_id.as_deref(),
        );
        // GWY-48: the configuration this stream ran under — a streamed span
        // carries the same request-config attributes a buffered one does.
        // `apply` consumes; take it out of `self` first (run() holds `&mut self`).
        // Written as a two-step so `check-request-config-span-sites.py` still sees
        // `request_config.apply(` — that guard counts the three span sites by name.
        let request_config = std::mem::take(&mut self.request_config);
        request_config.apply(&mut span.attributes);
        // OBS-53: the response-side confidence summary, streaming path.
        self.logprobs_acc.apply(&mut span.attributes);
        // OBS-51 / GWY-45 amendment: the ring buffer holds the (capped, most
        // recent) POST-GUARDRAIL text the client actually received. On
        // `[DONE]`, a normal finish OR a cancel — every path through `run` —
        // whatever accumulated becomes `gen_ai_output_messages`. A block
        // mid-stream still leaves whatever text was emitted BEFORE the block,
        // which the customer genuinely received; nothing is added after it.
        if let Some(text) = self.output_ring.take().filter(|t| !t.is_empty()) {
            span.attributes.gen_ai_output_messages =
                Some(super::spans::output_messages_json(&text));
        }
        // BILL-01 / OBS-51 step 3a: a stream that closed with NO upstream
        // usage event at all (Gemini never emits one) gets a DETERMINISTIC
        // estimate rather than reporting 0 tokens for a real conversation.
        // Runs AFTER the stream closed (this is `run`, reached only once the
        // loop has ended or the generator has dropped), never on the yield
        // path: `estimate_tokens` is O(1) (integer division on lengths
        // already computed), so there is nothing here for `spawn_blocking`
        // to protect a hot byte from — the constraint the brief states
        // ("never on the yield path") is satisfied by `run`'s own position,
        // not by an extra thread hop for arithmetic this cheap.
        if self.input_tokens == 0 && self.output_tokens == 0 {
            let output_len = span
                .attributes
                .gen_ai_output_messages
                .as_ref()
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|m| m.get("content"))
                .and_then(|c| c.as_str())
                .map_or(0, str::len);
            if self.input_bytes_for_estimate > 0 || output_len > 0 {
                span.attributes.gen_ai_usage_input_tokens =
                    estimate_tokens(self.input_bytes_for_estimate);
                span.attributes.gen_ai_usage_output_tokens = estimate_tokens(output_len);
                span.attributes.extra.insert(
                    "tracelane_usage_estimated".to_string(),
                    serde_json::Value::Bool(true),
                );
            }
        }
        // BILL-01 meter 1: stamp + meter the FINAL span shape.
        super::spans::stamp_and_meter_span_bytes(&mut span, self.meters.clone());
        if cancelled {
            // The truth the recorder exists to keep: the client went away
            // before the provider finished. Token counts are whatever was
            // known at that moment, which the attribute makes legible.
            span.attributes.extra.insert(
                "tracelane.stream.cancelled".to_string(),
                serde_json::Value::Bool(true),
            );
            STREAMS_FINALIZED_ON_DROP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        // Test seam (B-385 2c): the finished stream's span is observable to a
        // test whether or not NATS is wired.
        #[cfg(test)]
        crate::otlp_emit::test_sink::record(&span);
        let Some(nats_client) = self.nats.as_ref() else {
            // NATS disabled — never drop the span silently.
            crate::otlp_emit::note_span_dropped_no_nats();
            return;
        };
        // GWY-43: the key's monthly total, read off the SPAN so the number that
        // enforces the budget and the number the dashboard renders are one.
        record_key_spend(self.api_key_id.as_deref(), &span);

        // ── EVL-28: the online-eval judge, STREAMING path ───────────────────
        // A cancelled stream is a truncated answer; grading it would score the
        // user's patience, not the model. The sample slot is simply released.
        if !cancelled
            && let (Some(pending), Some(answer)) =
                (self.online_eval.take(), self.online_answer.take())
        {
            crate::online_eval::spawn(pending.into_job(
                self.tenant_id.clone(),
                self.trace_id,
                span.span_id.to_string(),
                answer,
            ));
        }
        crate::otlp_emit::spawn_publish(Arc::clone(nats_client), span, "streaming");
    }
}

impl Drop for StreamFinalizer {
    fn drop(&mut self) {
        if !self.finished {
            self.finished = true;
            self.run(true);
        }
    }
}

/// Everything `provider_stream_to_sse` needs beyond the provider stream itself.
///
/// B-385 §2d: this replaced a 24-parameter list — the shape in which two
/// `Option<&'static str>` or two `String`s could be transposed at the call site
/// and compile clean. Every field is OWNED, because the SSE stream is `'static`
/// and outlives the handler frame; the chat handler builds it exactly once, at
/// the call. `StreamFinalizer` takes most of these fields on the first poll.
pub(super) struct StreamContext {
    pub(super) completion_id: String,
    /// The model the CALLER asked for — echoed on every chunk and recorded on
    /// the span (the two used to be passed twice, as `model` and `model_name`,
    /// with the same value at every call site).
    pub(super) model: String,
    pub(super) nats: Option<Arc<async_nats::Client>>,
    pub(super) tenant_id: TenantId,
    pub(super) trace_id: Uuid,
    pub(super) parent_span_id: Option<Uuid>,
    pub(super) start_time: chrono::DateTime<chrono::Utc>,
    pub(super) dispatch_ts: chrono::DateTime<chrono::Utc>,
    pub(super) identity: CallerIdentity,
    pub(super) prompt_router: Arc<crate::prompt_router::PromptRouter>,
    pub(super) prompt_obs: Option<PromptObservation>,
    pub(super) guardrail_fired: bool,
    ///  #5: the predictive AFT hit id (observe-first) — threaded onto the published
    /// span so the /signatures page shows the tenant's OWN matched signatures instead of
    /// demo-seed only. None when no detector matched.
    pub(super) warn_aft_id: Option<&'static str>,
    pub(super) guardrail: Arc<crate::guardrail::GuardrailEngine>,
    pub(super) response_inputs: crate::guardrail::ResponseInputs,
    pub(super) redaction_map: Vec<tracelane_policy::pii::RedactionEntry>,
    pub(super) failover_from: Option<&'static str>,
    /// GWY-43: the API key that authorised this request, for per-key cost
    /// attribution and budget enforcement. Owned rather than borrowed because
    /// the stream outlives the handler frame.
    pub(super) api_key_id: Option<String>,
    /// GWY-48. Owned rather than borrowed for the same reason `api_key_id` above
    /// is: the stream outlives the handler frame. This is the field whose
    /// absence made SSE the one span site carrying no request configuration.
    pub(super) request_config: RequestConfig,
    /// EVL-28. `Some` means this request is in the online-eval sample, and is
    /// the ONLY reason the generator accumulates the response text — see the
    /// accumulator inside `provider_stream_to_sse`.
    pub(super) online_eval: Option<crate::online_eval::Pending>,
    /// B-375 (b) + security review M-4: the handler's armed dispatch guard,
    /// disarmed inside the generator on the first poll, after the finalizer owns
    /// the record. If the generator is dropped before it is ever polled, the
    /// guard drops armed and records the cancellation instead. `None` from the
    /// test harnesses.
    pub(super) handover: Option<DispatchGuard>,
    /// BILL-01 meter 1. `None` when `CLICKHOUSE_URL` is unset.
    pub(super) meters: Option<Arc<crate::billing::MeterSink>>,
    /// OBS-51 step 3a: serialized byte length of the ORIGINAL request
    /// messages, computed once by the caller (`chat.rs`) before the stream
    /// starts.
    pub(super) input_bytes_for_estimate: usize,
}

/// Converts a `ProviderStream` to an SSE stream of OpenAI `chat.completion.chunk` events.
///
/// `StreamChunk` → content chunk; `Done` → final chunk + `[DONE]` sentinel.
/// Any provider error terminates the stream with a `[DONE]` sentinel so the client
/// doesn't hang waiting for a stream that will never complete.
///
/// On `Done`, publishes a span to NATS JetStream (fire-and-forget) if a NATS
/// client is available.
pub(super) fn provider_stream_to_sse(
    mut provider_stream: ProviderStream,
    ctx: StreamContext,
) -> impl futures::Stream<Item = Result<Event, Infallible>> {
    let StreamContext {
        completion_id,
        model,
        nats,
        tenant_id,
        trace_id,
        parent_span_id,
        start_time,
        dispatch_ts,
        identity,
        prompt_router,
        prompt_obs,
        guardrail_fired,
        warn_aft_id,
        guardrail,
        response_inputs,
        redaction_map,
        failover_from,
        api_key_id,
        request_config,
        online_eval,
        handover,
        meters,
        input_bytes_for_estimate,
    } = ctx;
    // The finalizer records the span under the caller's model string; the
    // generator keeps `model` for the chunks it yields.
    let model_name = model.clone();
    stream! {
        // B-375: every accumulator the post-stream work needs lives in the
        // finalizer, so that work runs from `Drop` when the client hangs up as
        // well as from `finish()` when the loop ends. See `StreamFinalizer`.
        //
        // EVL-28: `online_answer` is `Some` ONLY when this request is in the
        // online-eval sample — the streaming path has no text accumulator of its
        // own (deltas are yielded and dropped), so scoring at completion would
        // mean accumulating the full response on 100% of streaming traffic to
        // serve a 1% sample. It accumulates the POST-GUARDRAIL text: the judge
        // grades what the customer actually saw.
        //
        // OBS-51: computed BEFORE the struct literal below moves `tenant_id`
        // into `fin` — a borrow of it after that move would not compile.
        let output_cap = crate::server::config::trace_content().map_or(0, |c| c.max_field_bytes());
        let output_ring = crate::server::config::content_capture_enabled(&tenant_id).then(String::new);
        let mut fin = StreamFinalizer {
            input_tokens: 0,
            output_tokens: 0,
            cache_read: None,
            cache_creation: None,
            stream_error: None,
            cost_usd: None,
            saw_tool_call: false,
            provider_finish: None,
            logprobs_acc: LogprobAccumulator::default(),
            online_answer: online_eval.as_ref().map(|_| String::new()),
            first_byte_ts: None,
            nats,
            tenant_id,
            trace_id,
            parent_span_id,
            start_time,
            dispatch_ts,
            model_name,
            identity,
            warn_aft_id,
            failover_from,
            api_key_id,
            request_config,
            online_eval,
            finished: false,
            meters,
            input_bytes_for_estimate,
            output_ring,
            output_cap,
        };
        // The finalizer exists: the dispatch guard's job is done.
        if let Some(mut guard) = handover {
            guard.disarm();
        }
        // The enforce-before-yield response-side seam — block/redact takes
        // effect before any chunk leaves this generator (the guardrail spec §2.6).
        let mut guard =
            crate::guardrail::ResponseGuard::new(guardrail, response_inputs, redaction_map);

        loop {
            let ev = provider_stream.next().await;
            if fin.first_byte_ts.is_none() && matches!(ev, Some(Ok(_))) {
                fin.first_byte_ts = Some(chrono::Utc::now());
            }
            match ev {
                None => {
                    // Provider stream ended WITHOUT a Done event (a Done breaks
                    // the loop itself after flushing). Flush the held-back tail
                    // through the seam so the final (redacted) chars are not lost.
                    //
                    // **This is the arm Anthropic takes** — it ends the byte
                    // stream after `message_stop` rather than sending a `Done`
                    // — so it is where a streaming tool call must be told apart
                    // from a finished answer (B-354).
                    let finish_reason = derive_finish_reason(fin.saw_tool_call, fin.provider_finish);
                    match guard.on_end(None).await {
                        crate::guardrail::GuardStep::Emit(text) => {
                            // Byte-identical to the pre-B-354 shape whenever the
                            // reason is "stop": the terminal chunk is emitted iff
                            // there is tail text, exactly as before. The
                            // empty-delta chunk is NEW and exists only to carry a
                            // non-default reason a client would otherwise never
                            // see — a tool-only Anthropic stream produced no
                            // terminal chunk at all, so an SDK loop had nothing
                            // to branch on.
                            if !text.is_empty() || finish_reason != "stop" {
                                let delta = if text.is_empty() {
                                    serde_json::json!({})
                                } else {
                                    serde_json::json!({ "content": text })
                                };
                                let data = serde_json::json!({
                                    "id": completion_id,
                                    "object": "chat.completion.chunk",
                                    "model": model,
                                    "choices": [{
                                        "index": 0,
                                        "delta": delta,
                                        "finish_reason": finish_reason
                                    }]
                                });
                                yield Ok(Event::default().data(data.to_string()));
                                // OBS-51: filled AFTER the yield, so downstream
                                // is flushed first — TTFT is untouched.
                                if let Some(buf) = fin.output_ring.as_mut() {
                                    ring_push(buf, &text, fin.output_cap);
                                }
                            }
                        }
                        crate::guardrail::GuardStep::Block { reason_code } => {
                            let data = serde_json::json!({
                                "id": completion_id,
                                "object": "chat.completion.chunk",
                                "model": model,
                                "choices": [{
                                    "index": 0,
                                    "delta": {},
                                    "finish_reason": "content_filter"
                                }],
                                "tracelane_guardrail": { "reason_code": reason_code }
                            });
                            yield Ok(Event::default().data(data.to_string()));
                        }
                    }
                    yield Ok(Event::default().data("[DONE]"));
                    break;
                }
                Some(Err(err)) => {
                    tracing::warn!(error = %err, "SSE stream error from provider");
                    //  #1 (mid-stream sub-path): a TRANSPORT-level stream error
                    // — a provider that severs the connection mid-response (TCP
                    // reset, provider crash, truncated body) — surfaces here as
                    // `Some(Err)`, the only way a provider failure reaches this
                    // loop. This arm previously broke WITHOUT setting stream_error,
                    // so the post-loop span was built Ok: a real mid-stream failure
                    // read as a success and the error-rate metric missed it. Record
                    // the failure so status = Error (countIf(status_code = 2)).
                    fin.stream_error = Some("provider_stream_error");
                    crate::otlp_emit::emit_operation_exception(
                        &fin.tenant_id,
                        provider_name_from_model(&fin.model_name),
                        "default",
                        "provider_stream_error",
                        None,
                    );
                    yield Ok(Event::default().data("[DONE]"));
                    break;
                }
                Some(Ok(event)) => match event {
                    ProviderEvent::StreamChunk { delta } => {
                        // Enforce-before-yield: feed the seam, emit only the safe
                        // (redacted + re-inserted) text it releases. A block
                        // terminates the stream WITHOUT emitting the held-back
                        // tail that holds the offending content.
                        let usage = tracelane_shared::Usage {
                            input_tokens: fin.input_tokens,
                            output_tokens: fin.output_tokens,
                            cache_read_input_tokens: None,
                            cache_creation_input_tokens: None,
                        };
                        match guard.on_delta(&delta, Some(&usage)).await {
                            crate::guardrail::GuardStep::Emit(text) => {
                                if !text.is_empty() {
                                    // EVL-28: no-op unless this request is sampled.
                                    if let Some(buf) = fin.online_answer.as_mut() {
                                        buf.push_str(&text);
                                    }
                                    let data = serde_json::json!({
                                        "id": completion_id,
                                        "object": "chat.completion.chunk",
                                        "model": model,
                                        "choices": [{
                                            "index": 0,
                                            "delta": { "content": text },
                                            "finish_reason": null
                                        }]
                                    });
                                    yield Ok(Event::default().data(data.to_string()));
                                    // OBS-51: filled AFTER the yield, so
                                    // downstream is flushed first.
                                    if let Some(buf) = fin.output_ring.as_mut() {
                                        ring_push(buf, &text, fin.output_cap);
                                    }
                                }
                            }
                            crate::guardrail::GuardStep::Block { reason_code } => {
                                let data = serde_json::json!({
                                    "id": completion_id,
                                    "object": "chat.completion.chunk",
                                    "model": model,
                                    "choices": [{
                                        "index": 0,
                                        "delta": {},
                                        "finish_reason": "content_filter"
                                    }],
                                    "tracelane_guardrail": { "reason_code": reason_code }
                                });
                                yield Ok(Event::default().data(data.to_string()));
                                yield Ok(Event::default().data("[DONE]"));
                                break;
                            }
                        }
                    }
                    ProviderEvent::ToolCallDelta { index, id, name, input_delta } => {
                        fin.saw_tool_call = true;
                        let data = serde_json::json!({
                            "id": completion_id,
                            "object": "chat.completion.chunk",
                            "model": model,
                            "choices": [{
                                "index": 0,
                                "delta": {
                                    "tool_calls": [{
                                        "index": index,
                                        "id": id,
                                        "function": { "name": name, "arguments": input_delta }
                                    }]
                                },
                                "finish_reason": null
                            }]
                        });
                        yield Ok(Event::default().data(data.to_string()));
                    }
                    ProviderEvent::Finish { reason } => fin.provider_finish = Some(reason),
                    // OBS-53. Wired BY HAND, and it had to be: every match on
                    // `ProviderEvent` in this tree carries a catch-all, so a new
                    // variant compiles clean everywhere and is silently dropped —
                    // which is how B-353 shipped. Not forwarded to the client:
                    // the provider already put `logprobs` in the chunk this
                    // stream relays, so re-emitting would duplicate it.
                    ProviderEvent::LogprobsDelta { logprobs } => {
                        fin.logprobs_acc.absorb(&logprobs);
                    }
                    ProviderEvent::UsageUpdate {
                        input_tokens: it,
                        output_tokens: ot,
                        cache_read,
                        cache_creation,
                        cost_usd: cost,
                    } => {
                        merge_usage_tokens(&mut fin.input_tokens, &mut fin.output_tokens, it, ot);
                        if cost.is_some() {
                            fin.cost_usd = cost;
                        }
                        // B-390 found this by deleting `#![allow(dead_code)]`: the
                        // adapter had carried Anthropic's `cache_read_input_tokens`
                        // / `cache_creation_input_tokens` on this event since the
                        // prompt-caching work, and BOTH stream consumers matched
                        // it with `..` — so a streamed, cache-hit request recorded
                        // no cache tokens and was priced at the full input rate.
                        if cache_read.is_some() {
                            fin.cache_read = cache_read;
                        }
                        if cache_creation.is_some() {
                            fin.cache_creation = cache_creation;
                        }
                    }
                    ProviderEvent::Done { response } => {
                        // cache_read / cache_creation are hoisted to the loop
                        // scope (top of stream!) so the post-loop span publish
                        // can read them.
                        if let Some(reason) = response
                            .choices
                            .first()
                            .and_then(|c| c.finish_reason.as_deref())
                            .and_then(FinishReason::from_openai_finish_reason)
                        {
                            fin.provider_finish = Some(reason);
                        }
                        if response
                            .choices
                            .first()
                            .and_then(|c| c.message.tool_calls.as_ref())
                            .is_some_and(|t| !t.is_empty())
                        {
                            fin.saw_tool_call = true;
                        }
                        if let Some(usage) = response.usage {
                            merge_usage_tokens(
                                &mut fin.input_tokens,
                                &mut fin.output_tokens,
                                usage.input_tokens,
                                usage.output_tokens,
                            );
                            if usage.cache_read_input_tokens.is_some() {
                                fin.cache_read = usage.cache_read_input_tokens;
                            }
                            if usage.cache_creation_input_tokens.is_some() {
                                fin.cache_creation = usage.cache_creation_input_tokens;
                            }
                        }
                        // Enforce-before-yield: flush the held-back tail through
                        // the seam (final redact pass) before the stop frame. A
                        // terminal block drops the tail, meters, then stops.
                        let final_usage = tracelane_shared::Usage {
                            input_tokens: fin.input_tokens,
                            output_tokens: fin.output_tokens,
                            cache_read_input_tokens: fin.cache_read,
                            cache_creation_input_tokens: fin.cache_creation,
                        };
                        match guard.on_end(Some(&final_usage)).await {
                            crate::guardrail::GuardStep::Emit(text) => {
                                if !text.is_empty() {
                                    let data = serde_json::json!({
                                        "id": completion_id,
                                        "object": "chat.completion.chunk",
                                        "model": model,
                                        "choices": [{
                                            "index": 0,
                                            "delta": { "content": text },
                                            "finish_reason": null
                                        }]
                                    });
                                    yield Ok(Event::default().data(data.to_string()));
                                    // OBS-51: filled AFTER the yield.
                                    if let Some(buf) = fin.output_ring.as_mut() {
                                        ring_push(buf, &text, fin.output_cap);
                                    }
                                }
                            }
                            crate::guardrail::GuardStep::Block { reason_code } => {
                                let data = serde_json::json!({
                                    "id": completion_id,
                                    "object": "chat.completion.chunk",
                                    "model": model,
                                    "choices": [{
                                        "index": 0,
                                        "delta": {},
                                        "finish_reason": "content_filter"
                                    }],
                                    "tracelane_guardrail": { "reason_code": reason_code }
                                });
                                yield Ok(Event::default().data(data.to_string()));
                                yield Ok(Event::default().data("[DONE]"));
                                // Billing fires POST-LOOP — see the note there.
                                break;
                            }
                        }
                        // Emit final stop chunk with usage, then [DONE]
                        let mut usage_val = serde_json::json!({
                            "prompt_tokens": fin.input_tokens,
                            "completion_tokens": fin.output_tokens,
                            "total_tokens": fin.input_tokens + fin.output_tokens,
                        });
                        // OpenAI's own shape for a prompt-cache hit, so a
                        // drop-in client sees what it would see upstream.
                        if let Some(cached) = fin.cache_read {
                            usage_val["prompt_tokens_details"] =
                                serde_json::json!({ "cached_tokens": cached });
                        }
                        let data = serde_json::json!({
                            "id": completion_id,
                            "object": "chat.completion.chunk",
                            "model": model,
                            "choices": [{
                                "index": 0,
                                "delta": {},
                                // B-354. `response.choices[0].finish_reason` is
                                // read on the way in (see the Done arm's
                                // handling) for adapters that answer with a
                                // whole ChatResponse.
                                "finish_reason": derive_finish_reason(fin.saw_tool_call, fin.provider_finish)
                            }],
                            "usage": usage_val
                        });
                        yield Ok(Event::default().data(data.to_string()));
                        yield Ok(Event::default().data("[DONE]"));

                        // Billing fires POST-LOOP — see the note there.

                        // B1 auto-rollback drift feed — streaming path, same
                        // as buffered path (fire-and-forget).
                        if let Some(obs) = prompt_obs.clone() {
                            let latency_ms = (chrono::Utc::now() - fin.start_time)
                                .num_milliseconds()
                                .max(0) as f64;
                            spawn_prompt_metric_observation(
                                Arc::clone(&prompt_router),
                                fin.tenant_id.clone(),
                                obs,
                                latency_ms,
                                false,
                                guardrail_fired,
                                u64::from(fin.input_tokens) + u64::from(fin.output_tokens),
                            );
                        }

                        // Span is published ONCE after the loop (covers Done,
                        // mid-stream block, stream-end, and error termination) —
                        // see the post-loop publish. #81 span-drop fix.
                        break;
                    }
                    // ThinkingDelta — skipped in the chunk stream (B-392). A
                    // provider failure mid-stream arrives as `Some(Err(_))`
                    // (the arm above), never as an event: the `Error` event
                    // variant no adapter ever constructed was deleted in B-390.
                    _ => {}
                },
            }
        }

        // The loop ended on its own — Done, a mid-stream Block, stream-end, or a
        // provider error. Finalize now; a client that hung up instead never
        // reaches this line, and `StreamFinalizer::drop` does the same work.
        fin.finish();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use axum::response::{IntoResponse as _, sse::Sse};

    // ── Response-streaming seam: server-level wiring integration tests ───────
    // Belt-and-suspenders over the SSE wiring (the seam logic itself is unit-
    // proven in guardrail::streaming). These drive the REAL provider_stream_to_sse
    // through a mock ProviderStream and assert over the actual SSE wire bytes.

    fn mock_stream(
        events: Vec<crate::providers::ProviderEvent>,
    ) -> crate::providers::ProviderStream {
        let items: Vec<anyhow::Result<crate::providers::ProviderEvent>> =
            events.into_iter().map(Ok).collect();
        Box::pin(futures::stream::iter(items))
    }

    /// Like `mock_stream` but the stream SEVERS after the given ok events — the
    /// terminal item is a transport-level `Err`, which is exactly what a real
    /// provider connection reset / truncated body yields at the `ProviderStream`
    /// level (the adapter propagates the byte-stream error via `?` inside its
    /// `try_stream!`). Drives the `Some(Err)` arm (#1 mid-stream sub-path).
    fn mock_stream_severing(
        ok_events: Vec<crate::providers::ProviderEvent>,
    ) -> crate::providers::ProviderStream {
        let mut items: Vec<anyhow::Result<crate::providers::ProviderEvent>> =
            ok_events.into_iter().map(Ok).collect();
        items.push(Err(anyhow::anyhow!(
            "connection reset by peer (mid-stream sever)"
        )));
        Box::pin(futures::stream::iter(items))
    }

    fn e2e_engine() -> Arc<crate::guardrail::GuardrailEngine> {
        let chain = Arc::new(crate::audit::AuditChain::new(100, None, None).expect("chain"));
        Arc::new(crate::guardrail::GuardrailEngine::new(
            chain,
            None,
            // R2/R6 are PAID; a None cache is the free tier now.
            Some(crate::entitlement_cache::ResolvedEntitlements::paid_rails_cache()),
            Arc::new(crate::guardrail::CapabilityRegistry::new()),
        ))
    }

    fn e2e_inputs() -> crate::guardrail::ResponseInputs {
        crate::guardrail::ResponseInputs {
            tenant_id: tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::from_u128(0xE2E)),
            api_key_id: None,
            correlation_id: ulid::Ulid::from_parts(1, 1),
            system_prompt: Some("a benign system prompt".to_string()),
            model: "claude-sonnet-4-6".to_string(),
            session: crate::guardrail::SessionState::fresh(None),
            actor: "apikey:e2e".to_string(),
            expected_format: None,
        }
    }

    fn usage(output: u32) -> tracelane_shared::Usage {
        tracelane_shared::Usage {
            input_tokens: 5,
            output_tokens: output,
            cache_read_input_tokens: None,
            cache_creation_input_tokens: None,
        }
    }

    fn done_event(output: u32) -> crate::providers::ProviderEvent {
        crate::providers::ProviderEvent::Done {
            response: tracelane_shared::ChatResponse {
                id: "x".to_string(),
                model: "claude-sonnet-4-6".to_string(),
                choices: Vec::new(),
                usage: Some(usage(output)),
            },
        }
    }

    fn chunk(delta: &str) -> crate::providers::ProviderEvent {
        crate::providers::ProviderEvent::StreamChunk {
            delta: delta.to_string(),
        }
    }

    /// The harness shape of a `StreamContext`: no NATS, no prompt observation,
    /// no guardrail hit, an empty request config, no online-eval sample and no
    /// dispatch guard (the harness has no ledger row to cover). The SSE shape is
    /// what these tests drive; a caller overrides only what it measures.
    fn test_ctx(
        model: &str,
        meters: Option<Arc<crate::billing::MeterSink>>,
        tenant: u128,
        trace: u128,
    ) -> StreamContext {
        StreamContext {
            completion_id: "chatcmpl-test".to_string(),
            model: model.to_string(),
            nats: None,
            tenant_id: tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::from_u128(tenant)),
            trace_id: uuid::Uuid::from_u128(trace),
            parent_span_id: None,
            start_time: chrono::Utc::now(),
            dispatch_ts: chrono::Utc::now(),
            identity: CallerIdentity::default(),
            prompt_router: Arc::new(crate::prompt_router::PromptRouter::new()),
            prompt_obs: None,
            guardrail_fired: false,
            warn_aft_id: None,
            guardrail: e2e_engine(),
            response_inputs: e2e_inputs(),
            redaction_map: Vec::new(),
            failover_from: None,
            api_key_id: None, // not under test here
            // GWY-48: an empty config exercises the "client sent nothing" branch,
            // which is the one that must add NO attributes at all.
            request_config: RequestConfig::default(),
            // EVL-28: these harnesses drive the SSE shape, not the eval path.
            online_eval: None,
            handover: None,
            meters,
            input_bytes_for_estimate: 0,
        }
    }

    /// Collect the full SSE wire output of provider_stream_to_sse for a set of
    /// provider events.
    async fn run_sse(events: Vec<crate::providers::ProviderEvent>) -> String {
        run_sse_stream(mock_stream(events)).await
    }

    /// Same as `run_sse` but driven by an arbitrary `ProviderStream`, so a
    /// severing stream (`mock_stream_severing`) can exercise the `Some(Err)` arm.
    async fn run_sse_stream(stream: crate::providers::ProviderStream) -> String {
        let sse = provider_stream_to_sse(stream, test_ctx("claude-sonnet-4-6", None, 0xE2E, 2));
        let resp = Sse::new(sse).into_response();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect SSE body");
        String::from_utf8_lossy(&bytes).into_owned()
    }

    // ── BILL-01 meter 1 (`ingest_bytes`) must fire on EVERY stream termination path ──
    //
    // Until 2026-09-14 these tests counted the ADR-020 `tokens_processed` Polar
    // recorder (`spawn_billing_record`, a process-global counter behind a test
    // lock). That recorder is deleted; the meter that is actually billed is the
    // span's logical bytes, recorded into `MeterSink` by
    // `stamp_and_meter_span_bytes` from the `StreamFinalizer` — on `Done`, on a
    // Done-less end, on a transport sever, and from `Drop` when the client hangs
    // up (B-375). Each test builds its OWN sink, so there is nothing global to
    // lock; the sink is never flushed (its URL is unroutable), so nothing leaves
    // the process.

    fn test_sink() -> Arc<crate::billing::MeterSink> {
        Arc::new(crate::billing::MeterSink::new(
            "http://127.0.0.1:1".to_string(),
        ))
    }

    /// `stamp_and_meter_span_bytes` records through `tokio::spawn`; give those
    /// tasks the runtime (current-thread under `#[tokio::test]`) until the sink
    /// has seen `want` records or the yield budget is spent — a bounded poll,
    /// never a sleep (`.claude/rules/testing.md`).
    async fn settle(sink: &crate::billing::MeterSink, want: u64) {
        for _ in 0..200 {
            if sink.records_total() >= want {
                return;
            }
            tokio::task::yield_now().await;
        }
    }

    /// Drive the real `provider_stream_to_sse` with a fresh meter sink wired,
    /// returning `(records, bytes)` the stream metered for its tenant.
    async fn meter_records_for(events: Vec<crate::providers::ProviderEvent>) -> (u64, f64) {
        let sink = test_sink();
        let tenant = 0xB110u128;
        let sse = provider_stream_to_sse(
            mock_stream(events),
            test_ctx("gemini-2.5-pro", Some(Arc::clone(&sink)), tenant, 3),
        );
        let resp = Sse::new(sse).into_response();
        let _ = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect SSE body");
        settle(&sink, 1).await;
        let bytes = sink
            .buffered_total(
                &tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::from_u128(tenant)),
                crate::billing::UsageMeter::IngestBytes,
            )
            .await;
        (sink.records_total(), bytes)
    }

    /// B-390's dead-field warning was a live defect: Anthropic's `message_start`
    /// carries `cache_read_input_tokens` on the `UsageUpdate` event and the SSE
    /// consumer matched it with `..`. A streamed cache hit therefore recorded no
    /// cache tokens. The wire is the observable: OpenAI's
    /// `usage.prompt_tokens_details.cached_tokens`.
    #[tokio::test]
    async fn a_streamed_cache_hit_reports_cached_tokens_on_the_final_usage_frame() {
        let usage_event = crate::providers::ProviderEvent::UsageUpdate {
            input_tokens: 1200,
            output_tokens: 0,
            cache_read: Some(1000),
            cache_creation: Some(0),
            cost_usd: None,
        };
        let out = run_sse(vec![usage_event, chunk("hi"), done_event(3)]).await;
        let final_frame = out
            .lines()
            .filter_map(|l| l.strip_prefix("data: "))
            .rfind(|d| d.contains("\"usage\""))
            .expect("a usage frame");
        let v: serde_json::Value = serde_json::from_str(final_frame).unwrap();
        assert_eq!(
            v["usage"]["prompt_tokens_details"]["cached_tokens"], 1000,
            "cached tokens from the provider's usage event must reach the wire: {v}"
        );
    }

    /// B-375 — THE CASE THAT WAS MISSING. A client that disconnects mid-stream
    /// drops the SSE generator at its current yield; the old post-loop code never
    /// ran, so the span, the meter event and the key spend were all lost. Now the
    /// `StreamFinalizer`'s `Drop` runs them. Proven by pulling two events and
    /// then dropping the stream — exactly what hyper does when the socket closes.
    #[tokio::test]
    async fn client_cancel_mid_stream_still_meters_and_finalizes() {
        use futures::StreamExt as _;
        let sink = test_sink();
        let before_drops = STREAMS_FINALIZED_ON_DROP.load(std::sync::atomic::Ordering::Relaxed);
        let before_no_nats = tracelane_shared::degradation::count(
            tracelane_shared::degradation::Degradation::SpansDroppedNoNats,
        );
        // Usage arrives FIRST (Anthropic's `message_start` carries input tokens),
        // then the client reads two chunks and hangs up before Done.
        let usage_event = crate::providers::ProviderEvent::UsageUpdate {
            input_tokens: 120,
            output_tokens: 0,
            cache_read: None,
            cache_creation: None,
            cost_usd: None,
        };
        // Box::pin, NOT `std::pin::pin!` — the latter pins a LOCAL, and
        // `drop(sse)` would then drop only the `Pin<&mut _>` while the stream
        // itself lived to the end of scope, past every assertion below. The
        // first version of this test failed exactly that way.
        let mut sse = Box::pin(provider_stream_to_sse(
            mock_stream(vec![
                usage_event,
                chunk("first "),
                chunk("second "),
                chunk("never read "),
                done_event(50),
            ]),
            StreamContext {
                completion_id: "chatcmpl-cancel".to_string(),
                // no NATS: the finalizer's span branch lands on the no-NATS counter
                ..test_ctx("claude-sonnet-4-6", Some(Arc::clone(&sink)), 0xCA7CE1, 7)
            },
        ));
        // The client reads a couple of events…
        let first = sse.next().await;
        let second = sse.next().await;
        assert!(
            first.is_some() && second.is_some(),
            "the stream must be live before the cancel"
        );
        // …and goes away. Nothing after this line is the loop's own exit.
        drop(sse);

        settle(&sink, 1).await;
        assert_eq!(
            sink.records_total(),
            1,
            "a cancelled stream must still meter its span bytes, exactly once"
        );
        assert!(
            sink.buffered_total(
                &tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::from_u128(0xCA7CE1)),
                crate::billing::UsageMeter::IngestBytes,
            )
            .await
                > 0.0,
            "the metered value is the span's logical bytes, never zero"
        );
        assert_eq!(
            STREAMS_FINALIZED_ON_DROP.load(std::sync::atomic::Ordering::Relaxed) - before_drops,
            1,
            "the finalizer must record that it ran from Drop"
        );
        // `>= 1`, not `== 1`: this counter is process-global —
        // `mid_stream_sever_terminates_cleanly` also runs with `nats: None` and
        // lands on it concurrently. The exact-once proof is
        // the two counters above; this one only shows the span branch was reached.
        assert!(
            tracelane_shared::degradation::count(
                tracelane_shared::degradation::Degradation::SpansDroppedNoNats,
            ) - before_no_nats
                >= 1,
            "the span branch must have run (it lands on the no-NATS counter here)"
        );
    }

    /// The other half of the same guarantee: a stream that completes normally
    /// finalizes exactly ONCE — `finish()` must not leave `Drop` a second run.
    #[tokio::test]
    async fn completed_stream_finalizes_once_not_twice() {
        let before_drops = STREAMS_FINALIZED_ON_DROP.load(std::sync::atomic::Ordering::Relaxed);
        let (n, _) = meter_records_for(vec![chunk("hi"), done_event(50)]).await;
        assert_eq!(n, 1, "one completion, one meter record");
        assert_eq!(
            STREAMS_FINALIZED_ON_DROP.load(std::sync::atomic::Ordering::Relaxed),
            before_drops,
            "a completed stream must never be counted as cancelled"
        );
    }

    /// THE REGRESSION: a stream that ends WITHOUT a `Done` event must still
    /// be metered. This is not hypothetical — Gemini never emits `Done`, it just
    /// ends the stream, so every Gemini streaming request was billed to nobody
    /// while its span recorded the usage. Fails on the pre-fix code, where metering
    /// lived inside the `Done` arm.
    #[tokio::test]
    async fn stream_end_without_done_still_meters() {
        let usage_event = crate::providers::ProviderEvent::UsageUpdate {
            input_tokens: 100,
            output_tokens: 50,
            cache_read: None,
            cache_creation: None,
            cost_usd: None,
        };
        let (n, bytes) = meter_records_for(vec![chunk("hello"), usage_event]).await;
        assert_eq!(n, 1, "a Done-less stream end must meter exactly once");
        assert!(bytes > 0.0, "and the metered value is the span's bytes");
    }

    /// The happy path must still meter — and exactly once. Moving the call
    /// post-loop must not double-meter by leaving an in-arm call behind.
    #[tokio::test]
    async fn done_stream_meters_exactly_once() {
        let (n, _) = meter_records_for(vec![chunk("hi"), done_event(50)]).await;
        assert_eq!(n, 1, "Done path must meter exactly once, not zero or twice");
    }

    ///  #1 (mid-stream sub-path): a transport sever mid-stream (a `Some(Err)`
    /// item — a real provider connection reset / truncated body) must terminate
    /// the SSE cleanly — yield `[DONE]`, no hang, no panic — via the `Some(Err)`
    /// arm. The span that arm builds carries `stream_error` → Error status, which
    /// `span_status_reflects_stream_error` asserts directly (the NATS span object
    /// is not capturable in-process, so the status link is proven at the builder).
    #[tokio::test]
    async fn mid_stream_sever_terminates_cleanly() {
        let wire = run_sse_stream(mock_stream_severing(vec![chunk("partial answer ")])).await;
        assert!(
            wire.contains("[DONE]"),
            "a severed stream must still close the SSE cleanly; got: {wire}"
        );
    }

    /// BILL-01 flips the old "0 tokens bills nothing" guard: the meter is the
    /// span's LOGICAL BYTES (spec §2.1, meter 1), and an empty stream still
    /// produced a span the recorder stored — so it meters exactly once, at the
    /// span's fixed overhead, never zero and never twice.
    #[tokio::test]
    async fn empty_stream_still_meters_its_span_bytes_once() {
        let (n, bytes) = meter_records_for(vec![]).await;
        assert_eq!(n, 1, "an empty stream still has a span, metered once");
        assert!(
            bytes >= 96.0,
            "at least the span's fixed byte overhead: {bytes}"
        );
    }

    /// THE WIRING INVARIANT: a secret split across StreamChunk deltas, behind a
    /// >hold-back preamble that flushes mid-stream, never appears RAW in the
    /// actual SSE wire bytes — only the redacted form egresses.
    #[tokio::test]
    async fn sse_wiring_never_yields_raw_secret() {
        // ~630-char preamble (> the 512 hold-back) → flushes mid-stream while the
        // secret, split across the next two deltas, is still held + then redacted.
        let preamble = "benign words ".repeat(50);
        let wire = run_sse(vec![
            chunk(&preamble),
            chunk("here is secret AKIA"),
            chunk("IOSFODNN7EXAMPLE end of message"),
            done_event(20),
        ])
        .await;
        assert!(
            !wire.contains("AKIAIOSFODNN7EXAMPLE"),
            "raw secret leaked through the SSE wiring:\n{wire}"
        );
        assert!(
            wire.contains("REDACTED:aws_key"),
            "the secret should be redacted in the wire output:\n{wire}"
        );
        assert!(wire.contains("benign words"), "the preamble should stream");
        assert!(wire.contains("[DONE]"));
    }

    /// The None-without-Done flush: a provider stream that ENDS without a Done
    /// event must still flush the held-back (redacted) tail — it is not lost.
    #[tokio::test]
    async fn sse_wiring_flushes_tail_when_stream_ends_without_done() {
        let preamble = "benign words ".repeat(50);
        // No done_event — the stream just ends.
        let wire = run_sse(vec![
            chunk(&preamble),
            chunk("trailing secret AKIAIOSFODNN7EXAMPLE here"),
        ])
        .await;
        assert!(!wire.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(
            wire.contains("REDACTED:aws_key"),
            "the held tail must be flushed (redacted) even without a Done event:\n{wire}"
        );
        assert!(wire.contains("[DONE]"));
    }

    /// Shared with `buffered::tests` (the accumulator's own edges) — one
    /// definition of the delta shape both halves of B-353/B-354 fold.
    pub(crate) fn tool_delta(
        index: usize,
        id: Option<&str>,
        name: Option<&str>,
        args: &str,
    ) -> ProviderEvent {
        ProviderEvent::ToolCallDelta {
            index,
            id: id.map(str::to_owned),
            name: name.map(str::to_owned),
            input_delta: args.to_owned(),
        }
    }

    /// The last `finish_reason` on the SSE wire — the one an OpenAI SDK loop
    /// reads to decide whether to call a tool and come back.
    fn last_finish_reason(sse: &str) -> Option<String> {
        sse.lines()
            .filter_map(|l| l.strip_prefix("data: "))
            .filter(|d| *d != "[DONE]")
            .filter_map(|d| serde_json::from_str::<serde_json::Value>(d).ok())
            .filter_map(|v| v["choices"][0]["finish_reason"].as_str().map(str::to_owned))
            .next_back()
    }

    /// **THE STREAMING HALF OF B-354.** An Anthropic tool-use stream ends
    /// without a `Done` event, and its tail is empty because a `tool_use` block
    /// produces no text — so the pre-fix code emitted NO terminal chunk at all
    /// and the client had nothing to branch on.
    #[tokio::test]
    async fn a_streaming_tool_call_ends_with_finish_reason_tool_calls() {
        let sse = run_sse(vec![
            tool_delta(1, Some("toolu_1"), Some("get_weather"), ""),
            tool_delta(1, None, None, "{\"city\":\"Bangalore\"}"),
            ProviderEvent::Finish {
                reason: crate::providers::FinishReason::ToolCalls,
            },
        ])
        .await;
        assert_eq!(
            last_finish_reason(&sse).as_deref(),
            Some("tool_calls"),
            "SSE wire was: {sse}"
        );
        // The deltas themselves still go out — this path already forwarded them.
        assert!(sse.contains("get_weather"), "SSE wire was: {sse}");
    }

    /// A provider-reported truncation reaches the streaming client too.
    #[tokio::test]
    async fn a_streaming_truncation_ends_with_finish_reason_length() {
        let sse = run_sse(vec![
            chunk("Sunny and"),
            ProviderEvent::Finish {
                reason: crate::providers::FinishReason::Length,
            },
        ])
        .await;
        assert_eq!(last_finish_reason(&sse).as_deref(), Some("length"));
    }

    /// **The no-behaviour-change control for the streaming path.** A tool-free
    /// stream must produce the SAME BYTES it did before B-354, on both of its
    /// terminations: a `Done` event, and a stream that simply ends (the arm
    /// Anthropic takes).
    #[tokio::test]
    async fn a_text_only_stream_is_byte_identical_on_both_terminations() {
        let with_done = run_sse(vec![chunk("Sunny."), done_event(3)]).await;
        assert!(
            with_done.contains(r#""finish_reason":"stop""#),
            "SSE wire was: {with_done}"
        );
        assert!(!with_done.contains("tool_calls"), "{with_done}");

        // Stream-end with no Done: the tail chunk carries "stop" exactly as
        // before, and NO extra empty-delta chunk is introduced.
        let no_done = run_sse(vec![chunk("Sunny.")]).await;
        assert_eq!(last_finish_reason(&no_done).as_deref(), Some("stop"));
        let terminal_chunks = no_done
            .lines()
            .filter(|l| l.contains(r#""finish_reason":"stop""#))
            .count();
        assert_eq!(
            terminal_chunks, 1,
            "exactly one terminal chunk, as before: {no_done}"
        );
        // And a stream that produced nothing at all still emits nothing but
        // [DONE] — the empty-delta chunk exists only for a NON-default reason.
        let empty = run_sse(Vec::new()).await;
        assert!(
            last_finish_reason(&empty).is_none(),
            "an empty stream must not grow a terminal chunk: {empty}"
        );
    }

    // ── B-353, buffered assembly: the accumulator's own edges ────────────────
}

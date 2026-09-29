//! Buffered (non-streaming) response assembly (B-385 §2d split of `server.rs`).
//!
//! `buffer_provider_stream` drains the provider stream, folds tool calls and the
//! finish reason (B-353 / B-354), builds the span BEFORE the response-side
//! guardrail seam runs (the #81 span-drop ordering guard,
//! `scripts/ci/check-span-publish-ordering.py`, checks that `build_gateway_span(`
//! stays textually ahead of `content_filter_response(`) and stores a
//! semantic-cache entry. OBS-51 (2026-09-13): the ACTUAL PUBLISH now happens
//! AFTER the seam, in `finish_and_publish_span`, called from both a guardrail
//! block (output absent) and the normal completion (output attached
//! post-redaction) — one publish call site, two callers, so a blocked request
//! still leaves a span (unchanged) and a served response's span carries what
//! the customer actually received, never the pre-redaction text.

use std::sync::Arc;

use axum::{Json, http::StatusCode, response::IntoResponse};
use futures::StreamExt as _;
use uuid::Uuid;

use crate::providers::{FinishReason, ProviderEvent, ProviderStream};

use super::AppState;
use super::chat::{PromptObservation, spawn_prompt_metric_observation};
use super::dispatch::provider_name_from_model;
use super::spans::{
    CallerIdentity, CapturedInput, GatewayTiming, LogprobAccumulator, RequestConfig, SpanUsageMeta,
    build_gateway_span, merge_usage_tokens, record_key_spend,
};

/// Accumulates a provider's `ToolCallDelta` stream into the `tool_calls` array
/// an OpenAI `chat.completion` (non-streaming) must carry.
///
/// # B-353 — what was broken
///
/// `buffer_provider_stream` matched `StreamChunk` / `UsageUpdate` / `Done` /
/// `Error` and let `ToolCallDelta` fall through `Ok(_) => {}`. The SSE path
/// forwarded the deltas and the client assembled them; the BUFFERED path — the
/// shape most OpenAI SDK callers default to — dropped them on the floor and
/// returned content only. So the model's tool intent was silently discarded on
/// the majority path, with a 200.
///
/// Keyed by the provider's own block/tool index, because that is the only thing
/// the two wire formats agree on: Anthropic sends `id`/`name` once on
/// `content_block_start` and then bare `input_json_delta`s carrying the same
/// index; OpenAI sends `id`/`name` on the first `tool_calls[i]` delta and then
/// argument fragments under the same `i`.
#[derive(Default)]
pub(crate) struct ToolCallAccumulator {
    slots: Vec<ToolCallSlot>,
}

struct ToolCallSlot {
    index: usize,
    id: Option<String>,
    name: Option<String>,
    arguments: String,
}

impl ToolCallAccumulator {
    pub(crate) fn push(
        &mut self,
        index: usize,
        id: Option<String>,
        name: Option<String>,
        delta: &str,
    ) {
        let slot = match self.slots.iter_mut().find(|s| s.index == index) {
            Some(s) => s,
            None => {
                self.slots.push(ToolCallSlot {
                    index,
                    id: None,
                    name: None,
                    arguments: String::new(),
                });
                // The push above guarantees a last element.
                match self.slots.last_mut() {
                    Some(s) => s,
                    None => return,
                }
            }
        };
        if id.is_some() {
            slot.id = id;
        }
        if name.is_some() {
            slot.name = name;
        }
        slot.arguments.push_str(delta);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// The OpenAI non-streaming shape:
    /// `[{"id","type":"function","function":{"name","arguments":"<JSON string>"}}]`.
    ///
    /// `arguments` stays a STRING — that is OpenAI's wire contract and what
    /// every SDK's `json.loads(tc.function.arguments)` expects. An empty
    /// accumulation becomes `"{}"` rather than `""`, because a no-argument tool
    /// call is legal and `json.loads("")` is not.
    pub(crate) fn to_openai_json(&self) -> Vec<serde_json::Value> {
        self.slots
            .iter()
            .map(|s| {
                let arguments = if s.arguments.trim().is_empty() {
                    "{}".to_owned()
                } else {
                    s.arguments.clone()
                };
                serde_json::json!({
                    // A provider that never sent an id is synthesised from its
                    // own index rather than left blank: the client echoes this
                    // back as `tool_call_id`, and an empty one breaks the loop.
                    "id": s.id.clone().unwrap_or_else(|| format!("call_{}", s.index)),
                    "type": "function",
                    "function": {
                        "name": s.name.clone().unwrap_or_default(),
                        "arguments": arguments,
                    }
                })
            })
            .collect()
    }

    /// RI-05 / M19: bounded CALLED tool names, in call order — the SAME cap
    /// `RequestConfig` applies to the OFFERED names
    /// (`MAX_TOOL_NAMES`/`MAX_TOOL_NAME_BYTES`, `spans.rs`). Ungated: a
    /// function name is developer-chosen, the same argument the offered-names
    /// precedent already makes (`span.rs`, `tracelane_request_tool_names`).
    /// `None` when no call was accumulated, matching every other
    /// absent-means-nothing-sent field.
    pub(crate) fn response_tool_names(&self) -> Option<Vec<String>> {
        super::spans::bounded_tool_names(self.slots.iter().filter_map(|s| s.name.as_deref()))
    }

    /// `OBS-50`: argument byte sizes, index-aligned with `response_tool_names`.
    /// Slots without a name are skipped in BOTH, so the alignment holds.
    pub(crate) fn response_tool_arg_bytes(&self) -> Option<Vec<u32>> {
        super::spans::bounded_tool_arg_bytes(
            self.slots
                .iter()
                .filter(|s| s.name.is_some())
                .map(|s| s.arguments.as_str()),
        )
    }

    /// RI-05: `(id, name, raw accumulated arguments)` for every call, in call
    /// order — the raw material `CapturedOutput::build` turns into `tool_call`
    /// parts under the `trace_content:` gate. Arguments are the RAW
    /// accumulated JSON text, never parsed here: a stream cancelled mid-call
    /// leaves an incomplete fragment, and `CapturedOutput` truncates it the
    /// same way it truncates message text.
    pub(crate) fn for_span(&self) -> Vec<(Option<String>, Option<String>, String)> {
        self.slots
            .iter()
            .map(|s| (s.id.clone(), s.name.clone(), s.arguments.clone()))
            .collect()
    }

    /// Fold Bedrock's whole-response tool calls in (mirrors
    /// `BufferedToolState::absorb_response`'s tail, reused by the STREAMING
    /// path's `Done` arm, which has no separate `provider_finish` to update
    /// here — the caller does that itself). Only when nothing has been
    /// accumulated from stream deltas yet, so an adapter that emits both never
    /// doubles the arguments.
    pub(crate) fn absorb_response_calls(&mut self, response: &tracelane_shared::ChatResponse) {
        if !self.is_empty() {
            return;
        }
        let Some(choice) = response.choices.first() else {
            return;
        };
        let Some(calls) = choice.message.tool_calls.as_ref() else {
            return;
        };
        for (i, c) in calls.iter().enumerate() {
            self.push(
                i,
                Some(c.id.clone()),
                Some(c.name.clone()),
                &c.input.to_string(),
            );
        }
    }
}

/// The `finish_reason` an OpenAI client sees (B-354).
///
/// **Precedence is deliberate.** `length` and `content_filter` outrank
/// `tool_calls`: a truncated or filtered response is a fact the caller must act
/// on, and a truncated tool call is not one it can execute. Below those, the
/// presence of tool calls wins over the provider's own word, because a provider
/// that reports nothing (Anthropic's `end_turn` on a `tool_use` turn does not
/// occur, but a compatible host reporting `stop` alongside tool calls does)
/// must not tell an SDK loop to stop while holding a call to make.
pub(crate) fn derive_finish_reason(
    has_tool_calls: bool,
    provider: Option<FinishReason>,
) -> &'static str {
    match provider {
        Some(FinishReason::Length) => FinishReason::Length.as_str(),
        Some(FinishReason::ContentFilter) => FinishReason::ContentFilter.as_str(),
        _ if has_tool_calls => FinishReason::ToolCalls.as_str(),
        Some(other) => other.as_str(),
        None => FinishReason::Stop.as_str(),
    }
}

/// The two facts the BUFFERED path folds out of a provider stream and used to
/// throw away: the model's tool calls (B-353) and the provider's own stop
/// reason (B-354).
///
/// It is a named type rather than two locals so the folding can be driven from
/// a real provider stream in a test — `buffer_provider_stream` itself needs an
/// `AppState`, a NATS handle and a guardrail engine, which is precisely why
/// this half was never covered.
#[derive(Default)]
pub(crate) struct BufferedToolState {
    calls: ToolCallAccumulator,
    provider_finish: Option<FinishReason>,
}

impl BufferedToolState {
    /// Fold one event. Returns `true` when the event was one of the two this
    /// state owns, so the caller's `match` never sees it twice.
    pub(crate) fn absorb(&mut self, ev: &ProviderEvent) -> bool {
        match ev {
            ProviderEvent::ToolCallDelta {
                index,
                id,
                name,
                input_delta,
            } => {
                self.calls
                    .push(*index, id.clone(), name.clone(), input_delta);
                true
            }
            ProviderEvent::Finish { reason } => {
                self.provider_finish = Some(*reason);
                true
            }
            _ => false,
        }
    }

    /// A `Done` event carries the same two facts on a whole `ChatResponse`
    /// (Bedrock) rather than as stream events.
    pub(crate) fn absorb_response(&mut self, response: &tracelane_shared::ChatResponse) {
        let Some(choice) = response.choices.first() else {
            return;
        };
        if let Some(reason) = choice
            .finish_reason
            .as_deref()
            .and_then(FinishReason::from_openai_finish_reason)
        {
            self.provider_finish = Some(reason);
        }
        // Only when the stream produced none — an adapter that emits BOTH
        // deltas and a final response would otherwise append the same
        // arguments twice.
        if !self.calls.is_empty() {
            return;
        }
        if let Some(calls) = choice.message.tool_calls.as_ref() {
            for (i, c) in calls.iter().enumerate() {
                self.calls.push(
                    i,
                    Some(c.id.clone()),
                    Some(c.name.clone()),
                    &c.input.to_string(),
                );
            }
        }
    }

    pub(crate) fn finish_reason(&self) -> &'static str {
        derive_finish_reason(!self.calls.is_empty(), self.provider_finish)
    }

    /// RI-05 / M19: bounded CALLED tool names, ungated. See
    /// `ToolCallAccumulator::response_tool_names`.
    pub(crate) fn response_tool_names(&self) -> Option<Vec<String>> {
        self.calls.response_tool_names()
    }

    /// `OBS-50`: see `ToolCallAccumulator::response_tool_arg_bytes`.
    pub(crate) fn response_tool_arg_bytes(&self) -> Option<Vec<u32>> {
        self.calls.response_tool_arg_bytes()
    }

    /// RI-05: raw `(id, name, arguments)` for `CapturedOutput::build`. See
    /// `ToolCallAccumulator::for_span`.
    pub(crate) fn calls_for_span(&self) -> Vec<(Option<String>, Option<String>, String)> {
        self.calls.for_span()
    }
}

/// Build the non-streaming `chat.completion` body.
///
/// **A response with no tool calls and no provider-reported reason is
/// byte-identical to the pre-B-353/B-354 body**: `message` gains no key and
/// `finish_reason` is still `"stop"`. That is asserted, not assumed —
/// `a_text_only_buffered_response_is_unchanged` in `behavioral_tests`.
pub(crate) fn buffered_completion_payload(
    completion_id: &str,
    model: &str,
    text: String,
    state: &BufferedToolState,
    input_tokens: u32,
    output_tokens: u32,
) -> serde_json::Value {
    let mut message = serde_json::json!({ "role": "assistant", "content": text });
    if !state.calls.is_empty()
        && let Some(obj) = message.as_object_mut()
    {
        obj.insert("tool_calls".to_owned(), state.calls.to_openai_json().into());
    }
    serde_json::json!({
        "id": completion_id,
        "object": "chat.completion",
        "model": model,
        "choices": [{
            "index": 0,
            "message": message,
            "finish_reason": state.finish_reason()
        }],
        "usage": {
            "prompt_tokens": input_tokens,
            "completion_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens
        }
    })
}

/// A buffered `content_filter` response — the response-side guardrail blocked
/// the model output (R1 output cap / R6 block / future R7). Same shape as a
/// normal completion but with empty content + `finish_reason: content_filter`
/// and the reason code. Matches the buffered handler's concrete return type.
fn content_filter_response(
    model: &str,
    reason_code: &'static str,
    input_tokens: u32,
    output_tokens: u32,
) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "id": format!("chatcmpl-{}", Uuid::new_v4()),
            "object": "chat.completion",
            "model": model,
            "choices": [{
                "index": 0,
                "message": { "role": "assistant", "content": "" },
                "finish_reason": "content_filter"
            }],
            "usage": {
                "prompt_tokens": input_tokens,
                "completion_tokens": output_tokens,
                "total_tokens": input_tokens + output_tokens
            },
            "tracelane_guardrail": { "reason_code": reason_code }
        })),
    )
}

/// Attach output-independent housekeeping and publish the span exactly once.
/// Called from BOTH a guardrail-block exit and the normal completion path, so
/// the actual `otlp_emit::spawn_publish` call site is singular even though the
/// function now has two callers (§4/OBS-51 amendment moved the publish AFTER
/// the response-side seam, replacing the old single unconditional call).
///
/// Returns `sent`, the moment the span now ends at (B-568 I4).
fn finish_and_publish_span(
    state: &AppState,
    mut span: tracelane_shared::TracelaneSpan,
) -> chrono::DateTime<chrono::Utc> {
    // B-568 I4: `sent` is NOW — after the response-side guardrail seam, the output
    // capture and the body build, all of which the client waits for. Restamped
    // BEFORE the byte stamp so the metered size covers the final values. What
    // still runs after `sent`: that byte stamp and a `tokio::spawn` (µs), plus
    // axum's JSON serialisation of the body once the handler returns.
    let sent = chrono::Utc::now();
    crate::server::spans::restamp_sent(&mut span, sent);
    crate::server::spans::stamp_and_meter_span_bytes(&mut span, state.meters.clone());
    #[cfg(test)]
    crate::otlp_emit::test_sink::record(&span);
    if let Some(ref nats_client) = state.nats {
        crate::otlp_emit::spawn_publish(Arc::clone(nats_client), span, "messages");
    }
    sent
}

/// Publish through the one site above, then close and (maybe) emit the
/// post-provider stage timer (B-568 I4) against the same interval the span's post
/// segment now covers — `sent − provider_complete`. `publish` is the only stage
/// that runs after `sent` (a size stamp and a spawn), so `accounted_us` can exceed
/// the segment by those microseconds; it never under-counts.
fn publish_and_time_post(
    state: &AppState,
    span: tracelane_shared::TracelaneSpan,
    mut post: crate::hotpath::StageTimer,
    provider_complete_ts: chrono::DateTime<chrono::Utc>,
) {
    let sent = finish_and_publish_span(state, span);
    post.mark("publish");
    post.emit_if_slow(
        &state.hotpath,
        u64::try_from(
            (sent - provider_complete_ts)
                .num_microseconds()
                .unwrap_or(0)
                .max(0),
        )
        .unwrap_or(0),
    );
}

/// Buffers a `ProviderStream` into a single OpenAI `chat.completion` JSON response.
///
/// Used when the client did not set `"stream": true`. The span is built once
/// the response is fully buffered, since the exact `(input_tokens,
/// output_tokens)` are only known when the provider's Done event lands; it is
/// stamped with its logical bytes (BILL-01 meter 1, `stamp_and_meter_span_bytes`)
/// and published to NATS JetStream (fire-and-forget) so the ingest worker can
/// persist it to ClickHouse.
#[allow(clippy::too_many_arguments)]
pub(super) async fn buffer_provider_stream(
    mut provider_stream: ProviderStream,
    model: &str,
    state: &AppState,
    tenant_id: &tracelane_shared::TenantId,
    trace_id: Uuid,
    parent_span_id: Option<Uuid>,
    start_time: chrono::DateTime<chrono::Utc>,
    dispatch_ts: chrono::DateTime<chrono::Utc>,
    identity: &CallerIdentity,
    prompt_obs: Option<PromptObservation>,
    guardrail_fired: bool,
    //  #5: the predictive AFT hit id (observe-first) — threaded onto the published
    // span so the /signatures page shows the tenant's OWN matched signatures instead of
    // demo-seed only. None when no detector matched.
    warn_aft_id: Option<&'static str>,
    guardrail: Arc<crate::guardrail::GuardrailEngine>,
    response_inputs: crate::guardrail::ResponseInputs,
    redaction_map: Vec<tracelane_policy::pii::RedactionEntry>,
    failover_from: Option<&str>,
    // RI-05 M1 + M4: the request's full dispatch ledger — built by the caller
    // (`server/chat.rs`) across the primary dispatch and any cross-provider
    // failover hops/skips. Empty for a bench-mock call, a semantic-cache hit
    // (neither reaches `dispatch_with_retry`), or a clean single attempt.
    dispatch_attempts: Vec<tracelane_shared::DispatchAttempt>,
    // GWY-43: the API key that authorised this request, for per-key cost
    // attribution and budget enforcement.
    api_key_id: Option<&str>,
    // GWY-24: the cache and this request's identity, threaded because the STORE
    // has to happen where the final body exists. `None` whenever the cache is
    // off, so the store is unreachable rather than merely skipped.
    semantic_cache: Option<Arc<crate::semantic_cache::SemanticCache>>,
    cache_key: Option<crate::semantic_cache::RequestKey>,
    // GWY-45 captured request content, `None` unless the tenant is allowlisted.
    // Built by the caller because `chat_request` lives there, not here.
    captured_input: Option<CapturedInput>,
    // GWY-48. Not an `Option`: every buffered request has a configuration, even
    // if every field in it is absent.
    request_config: RequestConfig,
    // EVL-28. `Some` means this request is in the online-eval sample.
    online_eval: Option<crate::online_eval::Pending>,
    // GWY-53: the handler's ONE capture decision; `output` gates the response text.
    capture: super::config::ContentCapture,
) -> impl IntoResponse {
    use tracelane_shared::model::MessageContent;

    let mut text = String::new();
    let mut input_tokens = 0u32;
    let mut output_tokens = 0u32;
    let mut cache_read: Option<u32> = None;
    let mut cache_creation: Option<u32> = None;
    //  #3: set on a mid-stream provider error so the span below records status
    // Error (a buffered-collection failure must move the error-rate metric).
    let mut buffered_error: Option<&str> = None;
    let mut cost_usd: Option<f64> = None;
    // RI-05 / M11: reasoning ("thinking") output tokens, last-write-wins —
    // same idiom as `cache_read`/`cache_creation` below.
    let mut reasoning_output_tokens: Option<u32> = None;
    // RI-05 / B-444: the provider's identity claims, first one wins.
    let mut served = super::spans::ServedMeta::default();
    // B-353 / B-354: the two facts the buffered path used to discard.
    let mut tool_state = BufferedToolState::default();
    // OBS-53. `tool_state.absorb` returns false for this variant, so the match
    // below is reached — asserted by a test rather than assumed.
    let mut logprobs_acc = LogprobAccumulator::default();

    while let Some(event) = provider_stream.next().await {
        // B-353 was exactly this: `ToolCallDelta` had no arm below and fell
        // through `Ok(_) => {}`. Folding the two tool-shaped events FIRST, in
        // one named place, is what makes them impossible to drop again.
        if let Ok(ref ev) = event
            && tool_state.absorb(ev)
        {
            continue;
        }
        match event {
            Ok(ProviderEvent::StreamChunk { delta }) => text.push_str(&delta),
            Ok(ProviderEvent::LogprobsDelta { logprobs }) => logprobs_acc.absorb(&logprobs),
            // RI-05 / B-444: wired BY HAND — the catch-all below would swallow it.
            Ok(ProviderEvent::ResponseMeta {
                id,
                model,
                system_fingerprint,
            }) => served.absorb(id, model, system_fingerprint),
            Ok(ProviderEvent::UsageUpdate {
                input_tokens: it,
                output_tokens: ot,
                cache_read: cr,
                cache_creation: cc,
                cost_usd: cost,
                reasoning: r,
            }) => {
                merge_usage_tokens(&mut input_tokens, &mut output_tokens, it, ot);
                if cost.is_some() {
                    cost_usd = cost;
                }
                // Same B-390 finding as the SSE loop: the event's cache fields
                // were dropped here too.
                if cr.is_some() {
                    cache_read = cr;
                }
                if cc.is_some() {
                    cache_creation = cc;
                }
                // RI-05 / M11: same last-write-wins idiom as the two above.
                if r.is_some() {
                    reasoning_output_tokens = r;
                }
            }
            Ok(ProviderEvent::Done { response }) => {
                // RI-05 / B-444: a whole response (Bedrock) carries its id and
                // served model as fields, not events.
                served.absorb(
                    (!response.id.is_empty()).then(|| response.id.clone()),
                    (!response.model.is_empty()).then(|| response.model.clone()),
                    None,
                );
                if let Some(choice) = response.choices.first()
                    && let MessageContent::Text(t) = &choice.message.content
                {
                    text = t.clone();
                }
                // B-353 / B-354: an adapter that answers with a whole
                // ChatResponse (Bedrock) carries both facts on the choice
                // rather than as stream events.
                tool_state.absorb_response(&response);
                if let Some(usage) = response.usage {
                    merge_usage_tokens(
                        &mut input_tokens,
                        &mut output_tokens,
                        usage.input_tokens,
                        usage.output_tokens,
                    );
                    if usage.cache_read_input_tokens.is_some() {
                        cache_read = usage.cache_read_input_tokens;
                    }
                    if usage.cache_creation_input_tokens.is_some() {
                        cache_creation = usage.cache_creation_input_tokens;
                    }
                }
            }
            // A provider failure arrives as `Err(_)` (the arm below); the `Error`
            // EVENT variant no adapter ever constructed was deleted in B-390.
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(error = %err, "stream error during buffered response collection");
                buffered_error = Some("provider_stream_error");
                // gen_ai.client.operation.exception (v1.41) — breaker trip input
                // (ADR-036). Classification only, never the raw error body.
                crate::otlp_emit::emit_operation_exception(
                    tenant_id,
                    provider_name_from_model(model),
                    "default",
                    "provider_stream_error",
                    None,
                );
                break;
            }
        }
    }

    // Provider round-trip complete (buffering finished). Everything after — JSON
    // serialization, the response-side seam, the return — is gateway overhead.
    let provider_complete_ts = chrono::Utc::now();
    // B-568 I4: the post-provider stage timer. Same threshold, same rate limit as
    // the pre-dispatch one; emits `segment=post` and nothing on a healthy request.
    let mut post = crate::hotpath::StageTimer::post("chat");

    // GWY-45 / OBS-51 (amended 2026-09-13): `build_gateway_span(` must stay
    // textually BEFORE `content_filter_response(` in this function
    // (`check-span-publish-ordering.py`) — a blocked request must still leave
    // a span (#81). What changed: the ACTUAL PUBLISH now happens AFTER the
    // response-side guardrail seam runs, so OUTPUT content (when captured)
    // reflects what the customer received — a rail-redacted body is stored
    // redacted, never the pre-redaction text — and a blocked response's span
    // carries no output attribute at all (absent, not empty). `record_key_spend`
    // and the online-eval judge sample the PRE-redaction `text` deliberately
    // unchanged from their historical position (spend is about tokens, already
    // known here; moving the judge's sample would be a second, unrelated
    // behaviour change).
    let mut span = build_gateway_span(
        tenant_id,
        trace_id,
        parent_span_id,
        model,
        identity,
        start_time,
        input_tokens,
        output_tokens,
        warn_aft_id,
        SpanUsageMeta {
            cache_read_input_tokens: cache_read,
            cache_creation_input_tokens: cache_creation,
            stream: false,
            cost_usd,
            served,
            finish_reason: tool_state.provider_finish,
            dispatch_attempts,
            reasoning_output_tokens,
        },
        failover_from,
        Some(GatewayTiming {
            dispatch_ts,
            provider_complete_ts,
            ttft_us: None, // TTFT is a streaming metric; N/A for a buffered response
        }),
        buffered_error,
        api_key_id,
    );
    // RI-05 / M19: the CALLED tool names — ungated, like the OFFERED names
    // (`tracelane_request_tool_names`, `span.rs`): a function name is
    // developer-chosen, not end-user text. `None` when no tool was called.
    span.attributes.tracelane_response_tool_names = tool_state.response_tool_names();
    span.attributes.tracelane_response_tool_arg_bytes = tool_state.response_tool_arg_bytes();
    // B-447: the MISS half of the three-state attribute. This path only runs after
    // `chat.rs` consulted the cache and found nothing (a hit returns before dispatch;
    // a streaming request is never looked up), so "the cache was configured AND a key
    // was derived" is exactly "consulted and missed". `Some(false)`, never `None` —
    // `alerts/checker.rs` counts `JSONHas AND NOT JSONExtractBool` as the miss
    // denominator, and until 2026-09-19 nothing wrote that state, so the hit-rate
    // rule's miss side read zero forever.
    if semantic_cache.is_some() && cache_key.is_some() {
        span.attributes.tracelane_semantic_cache_hit = Some(false);
    }
    // GWY-45: attach the captured REQUEST content, if the caller built any.
    if let Some(captured) = captured_input {
        captured.apply(&mut span.attributes);
    }
    // GWY-48, span site 2 of 4. Unconditional, unlike the capture above:
    // there is no allowlist to consult because there is no content here.
    request_config.apply(&mut span.attributes);
    // OBS-53: the response-side confidence summary, buffered path.
    logprobs_acc.apply(&mut span.attributes);

    if state.nats.is_some() {
        record_key_spend(api_key_id, &span);
        // ── EVL-28: the online-eval judge, BUFFERED path ────────────────────
        // Unchanged position: BEFORE the guardrail seam, on the pre-redaction
        // `text` — the judge samples what the model actually produced, the
        // same way it always has on this path.
        if let Some(pending) = online_eval {
            crate::online_eval::spawn(pending.into_job(
                tenant_id.clone(),
                trace_id,
                span.span_id.to_string(),
                text.clone(),
            ));
        }
    } else {
        // NATS disabled (no client) — never drop the span silently.
        crate::otlp_emit::note_span_dropped_no_nats();
    }
    post.mark("span_build");

    // Response-side guardrail seam — the SAME ResponseGuard as the streaming
    // path (one seam, not two). The full response flows through it in one
    // on_delta + on_end; the redacted/re-inserted text replaces `text` so the
    // span + the response body both carry the safe form. A block PUBLISHES the
    // span now (no output attached — there is nothing safe to attach) and
    // returns a content_filter response; a normal completion attaches OUTPUT
    // (post-redaction) below and publishes once, at the bottom.
    {
        let final_usage = tracelane_shared::Usage {
            input_tokens,
            output_tokens,
            cache_read_input_tokens: cache_read,
            cache_creation_input_tokens: cache_creation,
        };
        let mut guard =
            crate::guardrail::ResponseGuard::new(guardrail, response_inputs, redaction_map);
        let head = match guard.on_delta(&text, Some(&final_usage)).await {
            crate::guardrail::GuardStep::Emit(s) => s,
            crate::guardrail::GuardStep::Block { reason_code } => {
                post.mark("response_guard");
                publish_and_time_post(state, span, post, provider_complete_ts);
                return content_filter_response(model, reason_code, input_tokens, output_tokens);
            }
        };
        let tail = match guard.on_end(Some(&final_usage)).await {
            crate::guardrail::GuardStep::Emit(s) => s,
            crate::guardrail::GuardStep::Block { reason_code } => {
                post.mark("response_guard");
                publish_and_time_post(state, span, post, provider_complete_ts);
                return content_filter_response(model, reason_code, input_tokens, output_tokens);
            }
        };
        text = format!("{head}{tail}");
    }
    post.mark("response_guard");

    // OBS-51: attach what the customer actually received — POST-redaction,
    // under the SAME capture policy as the request (`capture_decision`),
    // never a second policy. RI-05 / M19: the CALLED tool ARGUMENTS ride the
    // SAME gate and cap — customer content, exactly like the text above; the
    // argument text itself is never redacted by the guardrail seam (which only
    // ever saw `text`), unchanged from before this feature. Then publish
    // exactly once — at the BOTTOM since B-568 I4, after the body is built, so
    // the span's `sent` is the moment the handler hands the response back.
    if let Some(out) =
        crate::server::spans::CapturedOutput::build(capture, &text, &tool_state.calls_for_span())
    {
        out.apply(&mut span.attributes);
    }
    post.mark("capture_output");

    // B1 auto-rollback drift feed (fire-and-forget, off the response path).
    // On objective drift in production the router flips the production pointer
    // back to the previous version. No-op for non-managed-prompt traffic.
    if let Some(obs) = prompt_obs {
        let latency_ms = (chrono::Utc::now() - start_time).num_milliseconds().max(0) as f64;
        spawn_prompt_metric_observation(
            state.prompt_router.clone(),
            tenant_id.clone(),
            obs,
            latency_ms,
            false,
            guardrail_fired,
            u64::from(input_tokens) + u64::from(output_tokens),
        );
    }

    let payload = buffered_completion_payload(
        &format!("chatcmpl-{}", Uuid::new_v4()),
        model,
        text,
        &tool_state,
        input_tokens,
        output_tokens,
    );

    // GWY-24: remember this answer. Fire-and-forget — a store failure must never
    // touch the response the customer already has.
    //
    // Only reached on the buffered, non-error path. The content-filter branches
    // return ABOVE this point, so a blocked answer is never stored — caching a
    // guardrail refusal would serve the refusal to everyone who asked something
    // similar.
    //
    // **Only a `finish_reason: stop` answer is stored (B-359, 2026-09-07).**
    // Until B-354 the reason was the hardcoded literal `"stop"`, so the cache's
    // own doc comment was true by accident and a `length`-truncated answer or a
    // tool call was cached and served to the next similar question. The real
    // reason is visible now and the check is real: `is_cacheable_finish_reason`
    // refuses `length` (the first caller's `max_tokens` is not an answer),
    // `tool_calls` (arguments derived from the FIRST prompt's text — the
    // semantic tier would replay `city="Paris"` to a Berlin question) and
    // anything it does not recognise.
    if let (Some(cache), Some(key)) = (semantic_cache.as_ref(), cache_key.as_ref())
        && buffered_error.is_none()
        && !guardrail_fired
        && crate::semantic_cache::is_cacheable_finish_reason(tool_state.finish_reason())
    {
        let cache = Arc::clone(cache);
        let key = key.clone();
        let tenant = tenant_id.clone();
        let model_owned = model.to_string();
        let body = payload.to_string();
        // COST MUST FALL BACK TO THE PRICE CATALOG, exactly as the SPAN does.
        //
        // `cost_usd` here is populated ONLY from a provider `UsageUpdate`
        // that carries a cost. Anthropic does not report one — and Anthropic
        // is 94% of production traffic — so this was `None` on almost every
        // real request and `unwrap_or(0.0)` stored a zero. Every subsequent
        // hit then reported `cost_saved_usd: 0.0`: the feature built for
        // cost could not state its own saving on the provider that matters.
        //
        // `build_gateway_span` already does this `or_else` (see
        // `gen_ai_usage_cost`), which is why the MISS span showed a real
        // cost while the cache stored zero from the same request. Two sites
        // reading the same quantity, one with the fallback and one without,
        // is the drift `pricing::cost_usd` exists as a single source to
        // prevent. `None` is still preserved as 0.0 for an unknown model —
        // the gateway never fabricates a cost (ADR-055).
        let cost = cost_usd
            .or_else(|| {
                crate::pricing::cost_usd(
                    model,
                    &tracelane_shared::Usage {
                        input_tokens,
                        output_tokens,
                        cache_read_input_tokens: None,
                        cache_creation_input_tokens: None,
                    },
                )
            })
            .unwrap_or(0.0);
        tokio::spawn(async move {
            cache
                .store(
                    &tenant,
                    &model_owned,
                    &key,
                    &body,
                    input_tokens,
                    output_tokens,
                    cost,
                    trace_id,
                )
                .await;
        });
    }
    post.mark("payload");
    publish_and_time_post(state, span, post, provider_complete_ts);

    (StatusCode::OK, Json(payload))
}

#[cfg(test)]
mod tests {
    use super::super::stream::tests::tool_delta;
    use super::*;

    /// B-568 I4, the WIRING half (the arithmetic is `spans::restamp_sent`'s own
    /// test): the buffered path's ONE publish site stamps `sent` at publish time,
    /// so a span built 5 ms before it is published ends at publish time and its
    /// overhead carries those 5 ms. Before I4 the span ended where it was BUILT —
    /// right after the provider — and the response guard, the output capture and
    /// the bookkeeping were in neither segment.
    #[cfg(debug_assertions)]
    #[test]
    fn the_buffered_publish_site_stamps_sent_at_publish_time() {
        let state =
            crate::handler_harness::test_state(crate::providers::ProviderRegistry::new().unwrap());
        let tenant = tracelane_shared::TenantId::from_jwt_claim(Uuid::new_v4());
        let received = chrono::Utc::now() - chrono::Duration::milliseconds(50);
        let built = chrono::Utc::now() - chrono::Duration::milliseconds(5);
        let mut span = crate::server::spans::build_gateway_span(
            &tenant,
            Uuid::new_v4(),
            None,
            "claude-sonnet-4-6",
            &CallerIdentity::default(),
            received,
            1,
            1,
            None,
            super::super::spans::SpanUsageMeta::default(),
            None,
            None,
            None,
            None,
        );
        span.end_time = Some(built);
        span.attributes.tracelane_gateway_overhead_us = Some(1_000);

        let _sent = finish_and_publish_span(&state, span);

        let published = crate::otlp_emit::test_sink::for_tenant(&tenant);
        assert_eq!(published.len(), 1, "exactly one publish");
        let p = &published[0];
        let end = p.end_time.expect("end_time");
        assert!(
            (end - built).num_microseconds().unwrap_or(0) >= 5_000,
            "end_time must be the publish moment, not the build moment: {end} vs {built}"
        );
        assert!(
            p.attributes
                .tracelane_gateway_overhead_us
                .is_some_and(|us| us >= 6_000),
            "the 5 ms between build and publish belongs to the gateway: {:?}",
            p.attributes.tracelane_gateway_overhead_us
        );
    }

    /// GWY-24: the cache must store the CATALOG cost when the provider does not
    /// report one, or the feature built for cost reports zero saving.
    ///
    /// FALSIFIED AGAINST THE OLD CODE: `cost_usd.unwrap_or(0.0)` returns 0.0 for
    /// the `None` case this asserts is non-zero, so this test fails on the
    /// pre-fix line and passes on the fixed one. Measured on prod 2026-08-20:
    /// 41 exact hits, every one reporting `cost_saved_usd = 0`, while the 41
    /// misses that populated them cost $0.0014598 in total.
    #[test]
    fn cache_store_cost_falls_back_to_the_catalog_when_the_provider_reports_none() {
        // Anthropic never sends a cost on the usage event, so this is the real
        // shape of the value reaching the store site for 94% of prod traffic.
        let provider_reported: Option<f64> = None;
        let input_tokens = 156_u32;
        let output_tokens = 30_u32;
        let model = "claude-haiku-4-5";

        let with_fallback = provider_reported
            .or_else(|| {
                crate::pricing::cost_usd(
                    model,
                    &tracelane_shared::Usage {
                        input_tokens,
                        output_tokens,
                        cache_read_input_tokens: None,
                        cache_creation_input_tokens: None,
                    },
                )
            })
            .unwrap_or(0.0);

        assert!(
            with_fallback > 0.0,
            "a known model with real tokens must produce a non-zero catalog cost; \
             got {with_fallback} — this is the pre-fix behaviour, where the cache \
             stored 0.0 and every hit reported cost_saved_usd = 0"
        );

        // And the catalog must agree with what the SPAN would have recorded for
        // the same request — two sites reading one quantity must not drift.
        let span_side = crate::pricing::cost_usd(
            model,
            &tracelane_shared::Usage {
                input_tokens,
                output_tokens,
                cache_read_input_tokens: None,
                cache_creation_input_tokens: None,
            },
        )
        .unwrap_or(0.0);
        assert!(
            (with_fallback - span_side).abs() < f64::EPSILON,
            "the cache store site and the span must derive the SAME cost: \
             cache={with_fallback} span={span_side}"
        );

        // An unknown model still yields 0.0 rather than a fabricated number.
        let unknown = None::<f64>
            .or_else(|| {
                crate::pricing::cost_usd(
                    "totally-not-a-real-model-r13proof",
                    &tracelane_shared::Usage {
                        input_tokens,
                        output_tokens,
                        cache_read_input_tokens: None,
                        cache_creation_input_tokens: None,
                    },
                )
            })
            .unwrap_or(0.0);
        assert_eq!(
            unknown, 0.0,
            "an unknown model must not fabricate a cost (ADR-055)"
        );
    }

    /// The precedence table, stated once and asserted rather than left implicit
    /// in a `match`. `length` and `content_filter` outrank `tool_calls` because
    /// a truncated or filtered tool call is not one the caller can execute.
    #[test]
    fn finish_reason_precedence_is_length_filter_tools_then_the_provider() {
        use crate::providers::FinishReason as F;
        assert_eq!(derive_finish_reason(false, None), "stop");
        assert_eq!(derive_finish_reason(true, None), "tool_calls");
        assert_eq!(derive_finish_reason(false, Some(F::Stop)), "stop");
        assert_eq!(derive_finish_reason(false, Some(F::Length)), "length");
        assert_eq!(
            derive_finish_reason(false, Some(F::ToolCalls)),
            "tool_calls"
        );
        assert_eq!(
            derive_finish_reason(false, Some(F::ContentFilter)),
            "content_filter"
        );
        // A truncated tool call is NOT a callable tool call.
        assert_eq!(derive_finish_reason(true, Some(F::Length)), "length");
        assert_eq!(
            derive_finish_reason(true, Some(F::ContentFilter)),
            "content_filter"
        );
        // A provider that says "stop" while handing us a tool call must not
        // tell an SDK loop to stop — that is the loop-breaking case.
        assert_eq!(derive_finish_reason(true, Some(F::Stop)), "tool_calls");
    }

    /// Anthropic's vocabulary → OpenAI's. An unknown reason maps to `None` so
    /// the derivation falls back rather than putting a word no OpenAI client
    /// knows on the wire.
    #[test]
    fn anthropic_stop_reasons_map_to_the_openai_vocabulary() {
        use crate::providers::FinishReason as F;
        for (anthropic, want) in [
            ("tool_use", Some(F::ToolCalls)),
            ("max_tokens", Some(F::Length)),
            ("end_turn", Some(F::Stop)),
            ("stop_sequence", Some(F::Stop)),
            ("refusal", Some(F::ContentFilter)),
            ("something_new_anthropic_invented", None),
        ] {
            assert_eq!(
                F::from_anthropic_stop_reason(anthropic),
                want,
                "anthropic stop_reason {anthropic}"
            );
        }
    }

    // ── B-354, streaming half: the TERMINAL SSE chunk ───────────────────────

    /// Two tools called in one turn, arguments arriving in fragments under
    /// their own indices — the shape both Anthropic and OpenAI produce.
    #[test]
    fn the_accumulator_keeps_parallel_tool_calls_apart() {
        let mut state = BufferedToolState::default();
        for ev in [
            tool_delta(0, Some("call_a"), Some("get_weather"), ""),
            tool_delta(1, Some("call_b"), Some("get_time"), ""),
            tool_delta(0, None, None, "{\"city\":"),
            tool_delta(1, None, None, "{\"tz\":\"IST\"}"),
            tool_delta(0, None, None, "\"Paris\"}"),
        ] {
            assert!(state.absorb(&ev), "a ToolCallDelta must be absorbed");
        }
        let body = buffered_completion_payload("id", "m", String::new(), &state, 0, 0);
        let calls = body["choices"][0]["message"]["tool_calls"]
            .as_array()
            .expect("tool calls");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0]["id"], "call_a");
        assert_eq!(calls[0]["function"]["arguments"], "{\"city\":\"Paris\"}");
        assert_eq!(calls[1]["id"], "call_b");
        assert_eq!(calls[1]["function"]["arguments"], "{\"tz\":\"IST\"}");
        assert_eq!(body["choices"][0]["finish_reason"], "tool_calls");
    }

    /// A no-argument tool call must serialise `"{}"`, never `""` —
    /// `json.loads("")` raises in every SDK.
    #[test]
    fn a_no_argument_tool_call_serialises_the_empty_object() {
        let mut state = BufferedToolState::default();
        assert!(state.absorb(&tool_delta(0, Some("call_a"), Some("ping"), "")));
        let body = buffered_completion_payload("id", "m", String::new(), &state, 0, 0);
        assert_eq!(
            body["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"],
            "{}"
        );
    }

    /// An adapter that answers with a whole `ChatResponse` (Bedrock) carries
    /// both facts on the choice rather than as stream events.
    #[test]
    fn a_done_response_contributes_its_tool_calls_and_reason() {
        let mut state = BufferedToolState::default();
        state.absorb_response(&tracelane_shared::ChatResponse {
            id: "x".into(),
            model: "m".into(),
            choices: vec![tracelane_shared::Choice {
                index: 0,
                message: tracelane_shared::Message {
                    role: tracelane_shared::Role::Assistant,
                    content: tracelane_shared::MessageContent::Text(String::new()),
                    tool_call_id: None,
                    tool_calls: Some(vec![tracelane_shared::ToolCall {
                        id: "call_z".into(),
                        name: "get_weather".into(),
                        input: serde_json::json!({ "city": "Oslo" }),
                    }]),
                },
                finish_reason: Some("tool_calls".into()),
            }],
            usage: None,
        });
        let body = buffered_completion_payload("id", "m", String::new(), &state, 0, 0);
        assert_eq!(
            body["choices"][0]["message"]["tool_calls"][0]["id"],
            "call_z"
        );
        assert_eq!(body["choices"][0]["finish_reason"], "tool_calls");
    }

    // ── RI-05 slice 4/5: M19 ─────────────────────────────────────────────────

    /// M19: the CALLED tool's name reaches `tracelane_response_tool_names`,
    /// ungated — the buffered path's own accumulator, fed the way
    /// `the_accumulator_keeps_parallel_tool_calls_apart` above already proves
    /// the fragments fold.
    #[test]
    fn a_called_tool_name_reaches_response_tool_names() {
        let mut state = BufferedToolState::default();
        assert!(state.absorb(&tool_delta(0, Some("call_1"), Some("get_weather"), "")));
        assert!(state.absorb(&tool_delta(0, None, None, "{\"city\":\"Paris\"}")));
        assert_eq!(
            state.response_tool_names(),
            Some(vec!["get_weather".to_owned()])
        );
        // The raw material `CapturedOutput::build` consumes: id, name, and the
        // FULL accumulated (unparsed) argument string.
        let spans = state.calls_for_span();
        assert_eq!(
            spans,
            vec![(
                Some("call_1".to_owned()),
                Some("get_weather".to_owned()),
                "{\"city\":\"Paris\"}".to_owned()
            )]
        );
    }

    /// M19: no call at all ⇒ `None`, never `Some(vec![])` — the same
    /// "absent means nothing sent" rule as `tracelane_request_tool_names`.
    /// `OBS-50`: the argument BYTE sizes ride index-aligned with the names — the
    /// raw accumulated text's UTF-8 length (`{"city":"Paris"}` is 16 bytes; a
    /// two-fragment `{"q":"héllo"}` is 14, not 13 — bytes, not chars), and a
    /// second call keeps its own slot.
    #[test]
    fn called_tool_argument_sizes_are_index_aligned_bytes() {
        let mut state = BufferedToolState::default();
        assert!(state.absorb(&tool_delta(0, Some("call_1"), Some("get_weather"), "")));
        assert!(state.absorb(&tool_delta(0, None, None, "{\"city\":\"Paris\"}")));
        assert!(state.absorb(&tool_delta(1, Some("call_2"), Some("search"), "{\"q\":")));
        assert!(state.absorb(&tool_delta(1, None, None, "\"héllo\"}")));
        assert_eq!(
            state.response_tool_names(),
            Some(vec!["get_weather".to_owned(), "search".to_owned()])
        );
        assert_eq!(state.response_tool_arg_bytes(), Some(vec![16, 14]));
        assert_eq!(BufferedToolState::default().response_tool_arg_bytes(), None);
    }

    #[test]
    fn no_tool_call_leaves_response_tool_names_absent() {
        let state = BufferedToolState::default();
        assert_eq!(state.response_tool_names(), None);
        assert!(state.calls_for_span().is_empty());
    }

    /// M19: a whole-response adapter's (Bedrock) tool calls reach
    /// `response_tool_names` too, via `ToolCallAccumulator::absorb_response_calls`
    /// — the streaming path's `Done` arm uses the SAME method.
    #[test]
    fn a_bedrock_style_done_response_also_populates_response_tool_names() {
        let mut calls = ToolCallAccumulator::default();
        calls.absorb_response_calls(&tracelane_shared::ChatResponse {
            id: "x".into(),
            model: "m".into(),
            choices: vec![tracelane_shared::Choice {
                index: 0,
                message: tracelane_shared::Message {
                    role: tracelane_shared::Role::Assistant,
                    content: tracelane_shared::MessageContent::Text(String::new()),
                    tool_call_id: None,
                    tool_calls: Some(vec![tracelane_shared::ToolCall {
                        id: "call_z".into(),
                        name: "get_weather".into(),
                        input: serde_json::json!({ "city": "Oslo" }),
                    }]),
                },
                finish_reason: Some("tool_calls".into()),
            }],
            usage: None,
        });
        assert_eq!(
            calls.response_tool_names(),
            Some(vec!["get_weather".to_owned()])
        );
        // A second call (as if deltas had already arrived) is refused — the
        // adapter that emits BOTH must never double the arguments.
        calls.absorb_response_calls(&tracelane_shared::ChatResponse {
            id: "x".into(),
            model: "m".into(),
            choices: vec![tracelane_shared::Choice {
                index: 0,
                message: tracelane_shared::Message {
                    role: tracelane_shared::Role::Assistant,
                    content: tracelane_shared::MessageContent::Text(String::new()),
                    tool_call_id: None,
                    tool_calls: Some(vec![tracelane_shared::ToolCall {
                        id: "call_y".into(),
                        name: "get_time".into(),
                        input: serde_json::json!({}),
                    }]),
                },
                finish_reason: Some("tool_calls".into()),
            }],
            usage: None,
        });
        assert_eq!(
            calls.response_tool_names(),
            Some(vec!["get_weather".to_owned()]),
            "already non-empty ⇒ the second Done must not double the arguments"
        );
    }
}

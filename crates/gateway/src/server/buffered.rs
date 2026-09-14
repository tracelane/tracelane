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
fn finish_and_publish_span(state: &AppState, mut span: tracelane_shared::TracelaneSpan) {
    crate::server::spans::stamp_and_meter_span_bytes(&mut span, state.meters.clone());
    #[cfg(test)]
    crate::otlp_emit::test_sink::record(&span);
    if let Some(ref nats_client) = state.nats {
        crate::otlp_emit::spawn_publish(Arc::clone(nats_client), span, "messages");
    }
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
            Ok(ProviderEvent::UsageUpdate {
                input_tokens: it,
                output_tokens: ot,
                cache_read: cr,
                cache_creation: cc,
                cost_usd: cost,
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
            }
            Ok(ProviderEvent::Done { response }) => {
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
                finish_and_publish_span(state, span);
                return content_filter_response(model, reason_code, input_tokens, output_tokens);
            }
        };
        let tail = match guard.on_end(Some(&final_usage)).await {
            crate::guardrail::GuardStep::Emit(s) => s,
            crate::guardrail::GuardStep::Block { reason_code } => {
                finish_and_publish_span(state, span);
                return content_filter_response(model, reason_code, input_tokens, output_tokens);
            }
        };
        text = format!("{head}{tail}");
    }

    // OBS-51: attach what the customer actually received — POST-redaction,
    // under the SAME capture policy as the request (`capture_decision`),
    // never a second policy. Then publish exactly once.
    if let Some(out) = crate::server::spans::CapturedOutput::build(tenant_id, &text) {
        out.apply(&mut span.attributes);
    }
    finish_and_publish_span(state, span);

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

    (StatusCode::OK, Json(payload))
}

#[cfg(test)]
mod tests {
    use super::super::stream::tests::tool_delta;
    use super::*;

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
}

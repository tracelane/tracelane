//! The gateway span — how a request becomes a `TracelaneSpan` (B-385 §2d split of `server.rs`).
//!
//! `build_gateway_span` is the ONE span builder (chat, embeddings, eval and the
//! Anthropic-native route all call it); `CallerIdentity`, `RequestConfig`,
//! `CapturedInput` and `SpanUsageMeta` are what it is built from; the publish,
//! billing-meter and key-spend spawns are the fire-and-forget tails every
//! finished request runs.

use std::sync::Arc;

use axum::http::HeaderMap;
use tracelane_shared::{
    TenantId, TracelaneSpan,
    span::{SpanAttributes, SpanStatus, SpanStatusCode},
};
use uuid::Uuid;

use super::AppState;
use super::dispatch::provider_name_from_model;

/// Publish a span to NATS off the response path. No-op when `NATS_URL` is unset
/// — which drops the span while the request still succeeds (`server.rs:331-357`).
pub(crate) fn spawn_span_publish(state: &AppState, mut span: TracelaneSpan) {
    // BILL-01 meter 1 (ingest_bytes): stamp + meter at the LAST possible
    // moment before publish, when every attribute mutation is final.
    stamp_and_meter_span_bytes(&mut span, state.meters.clone());
    // Test seam (B-385 2c): the span is observable to a test whether or not
    // NATS is wired. Compiled out of every non-test build.
    #[cfg(test)]
    crate::otlp_emit::test_sink::record(&span);
    let Some(nats_client) = state.nats.as_ref() else {
        // C1: this early return DROPPED THE SPAN SILENTLY. The two chat paths
        // call note_span_dropped_no_nats() on the same condition; this one — the
        // embeddings path — returned with no counter and no log, so an embeddings-only
        // tenant could lose 100% of its spans while every signal we had stayed clean.
        crate::otlp_emit::note_span_dropped_no_nats();
        return;
    };
    crate::otlp_emit::spawn_publish(Arc::clone(nats_client), span, "chat");
}

/// BILL-01 / ADR-076 meter 1 (`ingest_bytes`) — the LOGICAL size of the span
/// record as published: `serde_json::to_vec(&attributes).len() + name.len() +
/// status_message.len() + 96` (the 96 covers the fixed columns — two 36-char
/// ids, two timestamps, status — matching migration 24's `span_bytes` DEFAULT
/// expression exactly, so ingest's column and this meter describe the SAME
/// number without ingest recomputing it).
///
/// Stamps the number onto the span itself as `tracelane_span_bytes` (so
/// ingest can read it rather than recompute it) AND records it into the
/// gateway's own meter sink. Must run AFTER every attribute mutation
/// (captured input/output, request config, logprobs) — call this immediately
/// before publish, never inside `build_gateway_span` itself, which runs
/// before those callers finish mutating `span.attributes`.
pub(crate) fn stamp_and_meter_span_bytes(
    span: &mut TracelaneSpan,
    sink: Option<Arc<crate::billing::MeterSink>>,
) {
    let attrs_len = serde_json::to_vec(&span.attributes)
        .map(|v| v.len())
        .unwrap_or(0);
    let size =
        attrs_len + span.name.len() + span.status.message.as_deref().unwrap_or("").len() + 96;
    span.attributes.extra.insert(
        "tracelane_span_bytes".to_string(),
        serde_json::Value::Number(size.into()),
    );
    if let Some(sink) = sink {
        let tenant = span.tenant_id.clone();
        tokio::spawn(async move {
            sink.record(
                &tenant,
                crate::billing::UsageMeter::IngestBytes,
                "",
                size as f64,
            )
            .await;
        });
    }
}

/// Merge a usage event's token counts into the running per-request totals.
///
/// Token counts are monotonic within a single request, and providers may split
/// them across stream events — Anthropic reports `input_tokens` on
/// `message_start` and the final `output_tokens` on `message_delta`, where its
/// `input_tokens` is hardcoded `0`. A plain overwrite therefore lets the later
/// `message_delta` clobber the real input count back to `0`. Keeping the
/// max makes the merge order-independent and correct for both split-usage
/// providers and single-event providers (OpenAI/Azure/Google/Cohere/Bedrock,
/// which report both counts in one event).
pub(super) fn merge_usage_tokens(
    acc_input: &mut u32,
    acc_output: &mut u32,
    ev_input: u32,
    ev_output: u32,
) {
    *acc_input = (*acc_input).max(ev_input);
    *acc_output = (*acc_output).max(ev_output);
}

/// Token usage and streaming metadata threaded onto the gateway span. Keeps
/// `build_gateway_span`'s argument list bounded while carrying the v1.41
/// cache/streaming/conversation attributes (ADR-032).
/// RI-05 / B-444: what the provider said about its own response — kept as the
/// FIRST `ProviderEvent::ResponseMeta` a consumer saw. Every field absent when the
/// provider sent none; never filled from the request.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ServedMeta {
    pub(crate) id: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) system_fingerprint: Option<String>,
}

impl ServedMeta {
    /// Keep the first non-empty claim; a later frame never overwrites it.
    pub(crate) fn absorb(&mut self, id: Option<String>, model: Option<String>, fp: Option<String>) {
        if self.id.is_none() {
            self.id = id;
        }
        if self.model.is_none() {
            self.model = model;
        }
        if self.system_fingerprint.is_none() {
            self.system_fingerprint = fp;
        }
    }
}

/// RI-05 / B-444: why the served model differs from the requested one. Pure.
/// `None` when they are equal or the served model is unknown — a substitution is
/// never inferred, only observed.
#[must_use]
pub(crate) fn substitution(
    requested: &str,
    served: Option<&str>,
    alias_applied: bool,
    failover: bool,
) -> Option<&'static str> {
    let served = served?;
    if served == requested {
        return None;
    }
    Some(match (alias_applied, failover) {
        (true, true) => "alias+failover",
        (true, false) => "alias",
        (false, true) => "failover",
        (false, false) => "provider",
    })
}

#[derive(Debug, Default, Clone)]
pub(crate) struct SpanUsageMeta {
    pub(crate) cache_read_input_tokens: Option<u32>,
    pub(crate) cache_creation_input_tokens: Option<u32>,
    pub(crate) stream: bool,
    /// Upstream-reported cost in USD; `Some` only when the provider
    /// put a cost on the wire. When `None`, `build_gateway_span` derives the
    /// cost from the model price catalog (`crate::pricing`). Lands as
    /// `gen_ai.usage.cost`.
    pub(crate) cost_usd: Option<f64>,
    /// RI-05 / B-444: the provider's own claims about the response (first
    /// `ResponseMeta`); `Default` = nothing claimed.
    pub(crate) served: ServedMeta,
    /// B-354's normalised stop reason, now also recorded on the span
    /// (`gen_ai.response.finish_reasons`).
    pub(crate) finish_reason: Option<crate::providers::FinishReason>,
    /// RI-05 M1 + M4: the request's full dispatch ledger — same-provider
    /// retries then failover hops/skips, in order. `Default` = empty, which
    /// is what a bench-mock call, a semantic-cache hit and a clean single
    /// attempt all pass; `build_gateway_span` decides whether an empty or
    /// single-clean-element ledger is WRITTEN at all
    /// (`tracelane_shared::span::dispatch_attempts_worth_recording`).
    pub(crate) dispatch_attempts: Vec<tracelane_shared::DispatchAttempt>,
    /// RI-05 / M11: reasoning ("thinking") output tokens, broken out from the
    /// (still-inclusive) `output_tokens` total. `None` when the provider
    /// reported no such field (Anthropic; a non-thinking OpenAI/Gemini model).
    pub(crate) reasoning_output_tokens: Option<u32>,
}

/// GWY-45: the captured request content for one span, already truncated.
///
/// **Built ONLY when `ContentCapture::input` is set** — the operator's
/// `trace_content:` allowlist OR the workspace owner's opt-in (GWY-53), decided
/// once per request by `config::capture_decision`. The check is a bool read before
/// any allocation, so a workspace that did not opt in pays nothing else.
///
/// The RESPONSE half is [`CapturedOutput`], built after the response-side guardrail
/// seam (OBS-51) — never here, where the text would be pre-redaction.
#[derive(Debug, Clone)]
pub(crate) struct CapturedInput {
    /// Serialized `Vec<tracelane_shared::model::Message>` — the SAME type
    /// `prompt_eval.rs:509` deserializes, so producer and consumer agree by
    /// construction rather than by convention. Deliberately NOT the canonical
    /// OTel v1.37 `parts` shape, which our own consumer cannot parse; see
    /// `specs/GWY-45` §3.
    messages: serde_json::Value,
    /// The top-level `system` field, which is a DIFFERENT inbound shape from a
    /// `role: "system"` message and is what Anthropic-style callers use. Missing
    /// it would have left system instructions empty for most of prod.
    system: Option<serde_json::Value>,
    /// GWY-53: the OLDEST messages left out so the field fits its cap; recorded
    /// on the span as `tracelane_input_messages_omitted` when non-zero.
    omitted: usize,
}

impl CapturedInput {
    /// Returns `None` unless `capture.input` — the early return IS the hot-path
    /// guarantee. `capture` is the caller's ONE `config::capture_decision` for this
    /// request (B-299; GWY-53 added the workspace half).
    pub(crate) fn build(
        capture: super::config::ContentCapture,
        req: &tracelane_shared::ChatRequest,
    ) -> Option<Self> {
        if !capture.input {
            return None;
        }
        let cap = capture.max_field_bytes;

        // Truncate DURING construction, not after: serializing a 10 MB prompt and
        // then throwing it away still cost the 10 MB. GWY-53: EVERY string a message
        // can carry is capped — text parts, tool results, tool-call arguments, image
        // URLs — not only plain text, which was the one shape our dogfood sent.
        let mut msgs = req.messages.clone();
        for m in &mut msgs {
            cap_message(m, cap);
            bound_parts(m, cap);
        }

        // GWY-53: `gen_ai_input_messages` is ONE field, so the cap bounds the whole
        // array. An over-size span is refused by NATS whole (no payload check in
        // `otlp_emit::publish_span`), so a long agent history would otherwise cost the
        // customer the trace itself. Keep the NEWEST turns that fit — always at least
        // the last one, which is itself within the cap — and COUNT what was left out.
        let mut kept: Vec<serde_json::Value> = Vec::new();
        let mut used = 2; // `[` and `]`
        for m in msgs.iter().rev() {
            let v = serde_json::to_value(m).ok()?;
            let len = v.to_string().len() + usize::from(!kept.is_empty());
            if !kept.is_empty() && used + len > cap {
                break;
            }
            used += len;
            kept.push(v);
        }
        let omitted = msgs.len() - kept.len();
        kept.reverse();

        let system = req.system.as_ref().map(|sys| {
            let mut s = sys.clone();
            store_safe(&mut s, cap);
            serde_json::Value::String(s)
        });

        Some(Self {
            messages: serde_json::Value::Array(kept),
            system,
            omitted,
        })
    }

    /// Post-construction mutation, matching the two existing precedents in this
    /// file (the semantic-cache hit at the `tracelane_semantic_cache_*` fields,
    /// and `build_embeddings_span`'s name override). Keeps five other
    /// `build_gateway_span` call sites at a zero-line diff.
    pub(crate) fn apply(self, attrs: &mut tracelane_shared::SpanAttributes) {
        attrs.gen_ai_input_messages = Some(self.messages);
        attrs.gen_ai_system_instructions = self.system;
        if self.omitted > 0 {
            attrs.extra.insert(
                "tracelane_input_messages_omitted".to_string(),
                serde_json::Value::from(self.omitted),
            );
        }
    }
}

/// Security review 2026-09-28 (M-1): one captured message may serialize to at most this
/// many field caps. Every string is capped, but a message with many parts is not, and
/// NATS refuses an over-size span whole. At the default 64 KiB cap this is 512 KiB,
/// under NATS's 1 MiB `max_payload`. A format bound, not a tunable.
const MESSAGE_BYTES_MULTIPLE: usize = 8;

/// Security review 2026-09-28 (H-1 / H-2): the ONE way a captured string is stored.
/// Redact FIRST with the policy crate's detector set (credentials + structured PII,
/// `[REDACTED:<category>]` markers), then cap. This runs on every plan and every route,
/// independent of the R2 rail: R2 rewrites what is SENT, this bounds what is KEPT.
/// Only reached when the workspace or the operator opted into capture.
fn store_safe(s: &mut String, cap: usize) {
    *s = tracelane_policy::pii::redact(s);
    truncate_utf8(s, cap);
}

/// Redact every string leaf of a structured value (a tool call's JSON input) in place.
fn redact_json(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::String(s) => *s = tracelane_policy::pii::redact(s),
        serde_json::Value::Array(a) => a.iter_mut().for_each(redact_json),
        serde_json::Value::Object(o) => o.values_mut().for_each(redact_json),
        _ => {}
    }
}

/// Security review 2026-09-28 (M-1): if one message still serializes past
/// `MESSAGE_BYTES_MULTIPLE × cap`, drop its OLDEST parts until it fits, keeping the
/// newest, and say so in a leading text part — never a silent cut.
fn bound_parts(m: &mut tracelane_shared::model::Message, cap: usize) {
    use tracelane_shared::model::{ContentPart, MessageContent};
    let limit = MESSAGE_BYTES_MULTIPLE.saturating_mul(cap);
    let MessageContent::Parts(parts) = &mut m.content else {
        return;
    };
    let size = |p: &ContentPart| serde_json::to_string(p).map_or(0, |j| j.len() + 1);
    let mut total: usize = parts.iter().map(size).sum();
    let mut dropped = 0usize;
    while total > limit && parts.len() > 1 {
        total -= size(&parts.remove(0));
        dropped += 1;
    }
    if dropped > 0 {
        parts.insert(
            0,
            ContentPart::Text {
                text: format!("…[{dropped} earlier parts omitted]"),
                cache_control: None,
            },
        );
    }
}

/// GWY-53: cap every customer string one message can carry, each at `cap` bytes with
/// the visible `…[truncated]` marker. A `data:` image URL keeps its media type and
/// drops its bytes — a truncated base64 prefix is not an image, only weight.
fn cap_message(m: &mut tracelane_shared::model::Message, cap: usize) {
    use tracelane_shared::model::{ContentPart, MessageContent};
    match &mut m.content {
        MessageContent::Text(t) => store_safe(t, cap),
        MessageContent::Parts(parts) => {
            for p in parts {
                match p {
                    ContentPart::Text { text, .. } => store_safe(text, cap),
                    ContentPart::ToolResult { content, .. } => store_safe(content, cap),
                    ContentPart::ToolUse { input, .. } => cap_json(input, cap),
                    ContentPart::ImageUrl { image_url } => {
                        if image_url.url.starts_with("data:")
                            && let Some(comma) = image_url.url.find(',')
                        {
                            image_url.url.truncate(comma + 1);
                            image_url.url.push_str("…[omitted]");
                        }
                        store_safe(&mut image_url.url, cap);
                    }
                }
            }
        }
    }
    if let Some(calls) = m.tool_calls.as_mut() {
        for c in calls {
            cap_json(&mut c.input, cap);
        }
    }
}

/// A JSON value over the cap becomes its own serialized text, truncated and marked —
/// the same treatment `CapturedOutput` gives tool arguments (a string survives a cut;
/// a half-object does not parse).
fn cap_json(v: &mut serde_json::Value, cap: usize) {
    redact_json(v);
    let s = v.to_string();
    if s.len() > cap {
        let mut s = s;
        truncate_utf8(&mut s, cap);
        *v = serde_json::Value::String(s);
    }
}

/// OBS-51 / GWY-45 amendment (2026-09-13): the captured RESPONSE content for
/// one span, gated by the SAME `capture_decision` policy as [`CapturedInput`]
/// — never a second policy.
///
/// **Callers MUST build this from what the customer actually RECEIVED —
/// after the response-side guardrail seam has run, never before.** A
/// rail-redacted body is stored redacted; on a BLOCKED response there is
/// nothing to build (the caller does not call `build` at all), so the span
/// carries no output attribute rather than the pre-redaction text the
/// guardrail existed to remove.
#[derive(Debug, Clone)]
pub(crate) struct CapturedOutput {
    messages: serde_json::Value,
}

impl CapturedOutput {
    /// `None` unless the tenant is allowlisted, OR both `text` is empty AND
    /// `tool_calls` is empty (nothing to attach — a fully content-filtered
    /// response, or a call that named no tool, for instance).
    ///
    /// RI-05 / M19: `tool_calls` — `(id, name, raw accumulated arguments)`,
    /// from `ToolCallAccumulator::for_span` on both the buffered and the
    /// streaming path — are customer content exactly like `text`, so they ride
    /// the SAME gate and the SAME `max_field_bytes` cap, never a second one.
    pub(crate) fn build(
        capture: super::config::ContentCapture,
        text: &str,
        tool_calls: &[(Option<String>, Option<String>, String)],
    ) -> Option<Self> {
        if !capture.output || (text.is_empty() && tool_calls.is_empty()) {
            return None;
        }
        Some(Self::from_config(text, tool_calls, capture.max_field_bytes))
    }

    /// The gate decision split from the SHAPE-BUILDING, so the truncation and
    /// tool-call-part logic is unit-testable against a REAL, YAML-parsed
    /// `TraceContentConfig` without touching the process-global `CONFIG` slot
    /// — which is write-once for the whole test binary
    /// (`config::install_for_test`'s own doc comment says so, and
    /// `embeddings.rs`'s alias test already claims that one slot).
    fn from_config(
        text: &str,
        tool_calls: &[(Option<String>, Option<String>, String)],
        cap: usize,
    ) -> Self {
        let mut t = text.to_string();
        store_safe(&mut t, cap);
        // RI-05 / M19: arguments stay a STRING, never parsed — the same
        // contract OpenAI's own wire uses (`ToolCallAccumulator::to_openai_json`'s
        // doc). Parsing a truncated argument fragment would either fail
        // outright or silently swallow the `…[truncated]` marker; a string
        // survives truncation exactly like message text does.
        let calls: Vec<tracelane_shared::ToolCall> = tool_calls
            .iter()
            .enumerate()
            .map(|(i, (id, name, args))| {
                let mut a = args.clone();
                store_safe(&mut a, cap);
                tracelane_shared::ToolCall {
                    id: id.clone().unwrap_or_else(|| format!("call_{i}")),
                    name: name.clone().unwrap_or_default(),
                    input: serde_json::Value::String(a),
                }
            })
            .collect();
        Self {
            messages: output_messages_json(&t, calls),
        }
    }

    pub(crate) fn apply(self, attrs: &mut tracelane_shared::SpanAttributes) {
        attrs.gen_ai_output_messages = Some(self.messages);
    }
}

/// The `gen_ai.output.messages` shape both the buffered path
/// ([`CapturedOutput`]) and the streaming path (`StreamFinalizer`, via
/// [`CapturedOutput::build`]) render into — ONE shape, so a consumer reading
/// either path's span sees the same structure OTel's `gen_ai_input_messages`
/// already uses (a single-element message array), and RI-05's tool-call parts
/// ride the SAME `Message`/`ToolCall` types `gen_ai_input_messages` already
/// carries on an assistant turn that replays a prior tool call — one message
/// shape for input and output, not two.
pub(crate) fn output_messages_json(
    text: &str,
    tool_calls: Vec<tracelane_shared::ToolCall>,
) -> serde_json::Value {
    serde_json::json!([tracelane_shared::Message {
        role: tracelane_shared::Role::Assistant,
        content: tracelane_shared::MessageContent::Text(text.to_string()),
        tool_call_id: None,
        tool_calls: (!tool_calls.is_empty()).then_some(tool_calls),
    }])
}

/// Truncate a `String` to at most `max` BYTES without splitting a UTF-8 char,
/// appending a visible marker so a reader can tell a cut prompt from a short one.
///
/// A silent truncation would produce eval cases that look complete and are not —
/// the marker is what makes that detectable downstream.
fn truncate_utf8(s: &mut String, max: usize) {
    if s.len() <= max {
        return;
    }
    const MARK: &str = "…[truncated]";

    // THE POST-CONDITION IS `s.len() <= max`, ALWAYS. When `max` is smaller than
    // the marker itself there is no room to say "this was cut", so cut hard
    // rather than emit a string LONGER than the cap — which is what the first
    // version of this function did, and what its own test caught.
    //
    // Unreachable in production: `build_trace_content` refuses a
    // `max_field_bytes` under 1 KiB. Handled anyway, because a helper that
    // silently violates its stated contract is a defect waiting for its second
    // caller.
    let mut cut = |limit: usize| {
        let mut end = limit.min(s.len());
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    };

    if max <= MARK.len() {
        cut(max);
        return;
    }
    cut(max - MARK.len());
    s.push_str(MARK);
}

/// GWY-48: how many tool NAMES a span may carry, and how many bytes each may be.
///
/// The count is the disclosure, not the cap: `tracelane_request_tool_count` is
/// ALWAYS the true number, so `count > names.len()` is the machine-checkable
/// signal that the list was cut. Worst case added to a span is ~2.6 KB, which is
/// what keeps this inside the NATS payload limit GWY-45 warns about — an
/// oversized span is dropped WHOLE, losing the trace rather than the text.
const MAX_TOOL_NAMES: usize = 32;
const MAX_TOOL_NAME_BYTES: usize = 64;

/// RI-05 / M19: bound a tool-name list the SAME way `RequestConfig::build`
/// bounds the OFFERED names above (`MAX_TOOL_NAMES` / `MAX_TOOL_NAME_BYTES`) —
/// reused here for the CALLED names (`tracelane_response_tool_names`,
/// `ToolCallAccumulator::response_tool_names`) so the two populations share
/// one cap rather than drifting apart. `None` for an empty input, matching
/// every other "absent means nothing sent" field in this file.
/// `OBS-50`: the argument sizes that ride beside [`bounded_tool_names`] — one
/// `u32` per called tool, in call order, the same `MAX_TOOL_NAMES` cap, `None`
/// for no calls. Sizes are of the RAW accumulated arguments (before the content
/// gate's truncation), so a cut argument still reports what the model produced.
pub(crate) fn bounded_tool_arg_bytes<'a>(args: impl Iterator<Item = &'a str>) -> Option<Vec<u32>> {
    let out: Vec<u32> = args
        .take(MAX_TOOL_NAMES)
        .map(|a| u32::try_from(a.len()).unwrap_or(u32::MAX))
        .collect();
    (!out.is_empty()).then_some(out)
}

pub(crate) fn bounded_tool_names<'a>(names: impl Iterator<Item = &'a str>) -> Option<Vec<String>> {
    let out: Vec<String> = names
        .filter(|n| !n.is_empty())
        .take(MAX_TOOL_NAMES)
        .map(|n| {
            let mut n = n.to_owned();
            truncate_utf8(&mut n, MAX_TOOL_NAME_BYTES);
            n
        })
        .collect();
    (!out.is_empty()).then_some(out)
}

/// Everything the CALLER told us about WHO and WHAT this request belongs to.
///
/// Five values, all customer-supplied, all optional, all bounded at the trust
/// boundary by [`CallerIdentity::from_headers`]. They travel together because
/// they are the same KIND of thing and because keeping them apart caused two
/// defects at once:
///
/// **B-367 — the error path had none of them.** `build_error_span` and
/// the blocked-span builder (since merged into it) took no caller identity at all, so an errored or
/// guardrail-blocked request answered *"who initiated this"* and *"which session
/// was this"* with nothing — on exactly the request a customer opens Tracelane to
/// investigate. Passing five more `Option<&str>` down two more call chains to fix
/// that would have made the second defect worse.
///
/// **B-368 — three of the five were unbounded.** `x-agent-id`,
/// `x-human-authorizer` and `x-conversation-id` were read raw
/// (`headers.get(..).and_then(to_str).map(to_owned)`) while `x-business-reference`
/// three lines below them was length-bounded. Reading them in THREE places — the
/// chat handler, the embeddings handler and the Anthropic-native route — is what
/// let the two rules diverge and stay diverged. There is now ONE reader.
///
/// **And it removes a hazard rather than adding one.** `build_gateway_span` had
/// eight `Option<&str>` parameters in a row; transposing any two compiled clean
/// and every test passed. Collapsing five of them into this struct takes that
/// function from 19 parameters to 15 and makes the five that are most alike
/// impossible to transpose, because they are named fields. The
/// `each_caller_identity_lands_in_its_own_attribute_and_none_are_transposed` test
/// still guards the three that remain.
///
/// Owned `String`s, not borrows: the streaming path moves this into a spawned
/// task that outlives the request scope. It is built ONCE per request and cloned
/// once for that task — strictly fewer allocations than the five separate
/// `.clone()` calls it replaces.
#[derive(Clone, Default)]
pub(crate) struct CallerIdentity {
    pub(crate) agent_name: Option<String>,
    pub(crate) client_name: Option<String>,
    /// `x-agent-id` — KYA. Which agent made this call.
    pub(crate) agent_id: Option<String>,
    /// `x-human-authorizer` — KYA. Who approved this agent to run. NOT the end
    /// user; see `end_user_id`.
    pub(crate) human_authorizer: Option<String>,
    /// `x-business-reference` — a loan id, transaction ref, case number.
    pub(crate) business_reference: Option<String>,
    /// `OBS-20`. `x-tracelane-user-id` (alias `x-user-id`), or the request body's
    /// OpenAI `user` / `safety_identifier`, or Anthropic's `metadata.user_id`.
    /// The customer's own end user — a fourth population from the three things
    /// this repo already calls an "actor".
    pub(crate) end_user_id: Option<String>,
    /// `x-conversation-id`, falling back to `x-session-id`. Groups turns.
    pub(crate) conversation_id: Option<String>,
    /// RI-05 / B-444: the model string the CALLER sent, taken at admission BEFORE
    /// the `tracelane.yaml` alias rewrite and never reassigned by failover — so
    /// `gen_ai_request_model` says what was asked for even when `model` (the
    /// routing/billing attribution) was rewritten or replaced.
    pub(crate) requested_model: Option<String>,
    /// RI-05 M18 (follow-up, 2026-09-20): `x-tracelane-step-index` — the caller's own
    /// position in its agent loop, a small integer. Parsed, never echoed as text; an
    /// unparseable value is ABSENT, not an error (the proxy cannot know the step). The
    /// OTLP path sets the same span field from the `tracelane.agent.step_index` attribute.
    pub(crate) agent_step_index: Option<u32>,
    /// GWY-27: the caller's model string was one of this WORKSPACE's aliases and was
    /// resolved to its target at hot-path entry. Makes `tracelane_model_substitution`
    /// read `"alias"` exactly as an operator (`tracelane.yaml`) alias does.
    pub(crate) tenant_alias_applied: bool,
    /// B-568 I5: this request made a control-plane round trip before dispatch
    /// (auth cold branch, BYOK cache miss, entitlement blocking resolve, JWT bridge
    /// miss). Set by admission and the handlers from `StageTimer::is_cold`, never
    /// from a header. Rides the span as `tracelane_gateway_cold_start = true`, and
    /// only when the span also carries a measured overhead.
    pub(crate) cold_start: bool,
}

/// `Debug` that prints PRESENCE, never VALUES.
///
/// All five fields are customer-supplied identity — an end-user id, a business
/// reference, the human who authorised an agent. `.claude/rules/logging.md` bans
/// credentials and PII at any level, and a derived `Debug` would put every one of
/// them verbatim into any `?identity` or `{:?}` that some future edit adds.
///
/// Nothing formats this today — the chat, embeddings and Anthropic handlers all
/// `#[instrument(skip(...))]` their sources and no log line reads `identity.*`, which
/// `security-reviewer` confirmed on 2026-09-10. This exists so that stays true by
/// CONSTRUCTION rather than by everyone remembering: the struct now cannot leak even
/// if someone logs it.
impl std::fmt::Debug for CallerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let p = |v: &Option<String>| if v.is_some() { "set" } else { "unset" };
        f.debug_struct("CallerIdentity")
            .field("agent_name", &p(&self.agent_name))
            .field("client_name", &p(&self.client_name))
            .field("agent_id", &p(&self.agent_id))
            .field("human_authorizer", &p(&self.human_authorizer))
            .field("business_reference", &p(&self.business_reference))
            .field("end_user_id", &p(&self.end_user_id))
            .field("conversation_id", &p(&self.conversation_id))
            .field("agent_step_index", &self.agent_step_index.is_some())
            .finish()
    }
}

impl CallerIdentity {
    pub(crate) fn assignment_key(&self) -> Option<String> {
        self.end_user_id
            .as_ref()
            .map(|v| format!("user:{v}"))
            .or_else(|| {
                self.conversation_id
                    .as_ref()
                    .map(|v| format!("conversation:{v}"))
            })
            .or_else(|| self.agent_id.as_ref().map(|v| format!("agent:{v}")))
    }

    /// Read all five from request headers, bounded, at the trust boundary.
    ///
    /// **Correlation ids are length-bounded and DROPPED rather than truncated above
    /// the cap** — `bounded_end_user_id`'s doc says why: a truncated id is a
    /// *wrong* id, and a wrong id silently attributes one request to another
    /// agent, person or session. Absence is recoverable; misattribution is not.
    /// The optional agent display name is separately truncated to the catalog cap.
    ///
    /// The body-sourced end-user spellings (OpenAI's `user`, Anthropic's
    /// `metadata.user_id`) are NOT read here — they need the parsed body, which
    /// arrives later — so callers that support them fill `end_user_id` in
    /// afterwards via [`CallerIdentity::or_body_end_user`]. Header wins.
    pub(crate) fn from_headers(headers: &HeaderMap) -> Self {
        let h = |name: &str| -> Option<String> {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .and_then(tracelane_shared::span::bounded_end_user_id)
        };
        Self {
            agent_name: headers
                .get("x-tracelane-agent-name")
                .and_then(|v| v.to_str().ok())
                .and_then(crate::kya_identity::bounded_agent_name),
            client_name: headers
                .get("user-agent")
                .and_then(|v| v.to_str().ok())
                .and_then(crate::kya_identity::classify_client),
            agent_id: h("x-agent-id"),
            human_authorizer: h("x-human-authorizer"),
            business_reference: headers
                .get("x-business-reference")
                .and_then(|v| v.to_str().ok())
                .and_then(tracelane_shared::span::bounded_business_reference),
            end_user_id: h("x-tracelane-user-id").or_else(|| h("x-user-id")),
            conversation_id: h("x-conversation-id").or_else(|| h("x-session-id")),
            // RI-05: set by `with_requested_model` from the body, never from a header.
            requested_model: None,
            // GWY-27: set by the handler that resolves a workspace alias, never here.
            tenant_alias_applied: false,
            // B-568 I5: set by admission / the handler from the stage timer, never here.
            cold_start: false,
            agent_step_index: headers
                .get("x-tracelane-step-index")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<u32>().ok()),
        }
    }

    /// `OBS-20`. Fill `end_user_id` from the request BODY when no header supplied
    /// one. Header wins — it is the explicit signal, and the only one a customer
    /// can set without touching a body their SDK owns.
    /// RI-05 / B-444: the body's `model` string, verbatim. Absent when the body has
    /// none (embeddings bodies do; `/v1/messages` does) — then `build_gateway_span`
    /// falls back to the routing model, as before.
    pub(crate) fn with_requested_model(mut self, body: &serde_json::Value) -> Self {
        if self.requested_model.is_none() {
            self.requested_model = body
                .get("model")
                .and_then(serde_json::Value::as_str)
                .filter(|m| !m.is_empty())
                .map(str::to_owned);
        }
        self
    }

    pub(crate) fn or_body_end_user(mut self, body: &serde_json::Value) -> Self {
        if self.end_user_id.is_none() {
            self.end_user_id = ["user", "safety_identifier"]
                .iter()
                .find_map(|k| body.get(*k).and_then(|v| v.as_str()))
                .or_else(|| body.pointer("/metadata/user_id").and_then(|v| v.as_str()))
                .and_then(tracelane_shared::span::bounded_end_user_id);
        }
        self
    }
}

/// GWY-48: the request CONFIGURATION for one span — the sampling parameters and
/// the tool surface the client chose. `CapturedInput` above carries the message
/// TEXT; this carries the settings the run happened under, and the two are
/// deliberately separate because they have different privacy postures.
///
/// **NO CONTENT GATE, and that is the whole difference from `CapturedInput`.**
/// These are numbers and interface identifiers the DEVELOPER chose, not text the
/// END USER wrote — an `f32` cannot carry a prompt. The `trace_content:`
/// allowlist exists to gate customer message text (`config::trace_content`), and
/// putting a temperature behind it would ship this feature INVISIBLE on prod,
/// where that allowlist names one dogfood tenant and nobody else. Tool NAMES are
/// the one judgement call: R3 already made it, in writing, and stores tool names
/// per tenant with no content gate (`crate::db::observed_tools`), so this reuses
/// that policy rather than inventing a second one — bounded, and with ingest's
/// `pii::redact_json` as the backstop.
///
/// **The span records what the CLIENT sent, ALWAYS** — including a `seed` sent to
/// a provider that has no seed concept. That is not a lie; it is the first honest
/// surfacing of a real client misconfiguration, and `OBS-52` is where we say so
/// out loud.
///
/// Applied at FOUR span sites (semantic-cache hit, buffered, streaming, and the
/// Anthropic-native route). The streaming one is the one that did not previously
/// carry request content at all, and it is not optional: if streamed spans carry
/// no `gen_ai_request_max_tokens`, OBS-52's `missing_max_tokens` check fires on
/// every streamed request, and a detector that flags the absence of its own
/// instrumentation is worse than no detector.
#[derive(Debug, Clone, Default)]
pub(crate) struct RequestConfig {
    temperature: Option<f32>,
    top_p: Option<f32>,
    max_tokens: Option<u32>,
    seed: Option<u64>,
    tool_choice_mode: Option<String>,
    tool_choice_function: Option<String>,
    tool_count: Option<u32>,
    tool_names: Option<Vec<String>>,
    tool_definitions_hash: Option<String>,
    deployment_id: Option<String>,
    /// OBS-52. Populated by [`RequestConfig::with_policy_flags`], never by
    /// `build` — a detector's verdict is not request configuration, and keeping
    /// them in one struct only because they travel together would let a future
    /// reader think the gateway flagged something it merely recorded.
    misconfig_flags: Option<Vec<String>>,
    /// `GWY-49`. Populated by [`RequestConfig::with_zdr`] once routing has judged the
    /// constraint — request configuration in the literal sense: the caller asked for it.
    zdr_required: Option<bool>,
    zdr_eligible_providers: Option<Vec<String>>,
}

impl RequestConfig {
    /// `GWY-49`: record that the request carried `x-tracelane-zdr: required` and which
    /// providers passed the check (primary first). Called only under the constraint.
    pub(crate) fn with_zdr(mut self, eligible_providers: Vec<String>) -> Self {
        self.zdr_required = Some(true);
        self.zdr_eligible_providers = Some(eligible_providers);
        self
    }

    /// Read the configuration off the inbound request. Infallible and total:
    /// there is no tenant gate and no early return, because there is nothing
    /// here to gate (see the type doc).
    ///
    /// Cost is field reads plus, ONLY when tools are present, one `def_hash` per
    /// tool. The guardrail engine computes the same hash per tool when R3 is
    /// active, so this is a second computation of one value — accepted rather
    /// than shared because R3 is entitlement-gated and may not run at all, and a
    /// span attribute that appears only for entitled tenants is the
    /// invisible-gated-surface class. **The FUNCTION is shared even though the
    /// call is not**, which is what makes a customer's join to
    /// `observed_tools.def_hash` sound. Guarded by the standing Proof E latency
    /// gate on every deploy.
    pub(crate) fn build(req: &tracelane_shared::ChatRequest) -> Self {
        let (tool_choice_mode, tool_choice_function) = match &req.tool_choice {
            None => (None, None),
            Some(tracelane_shared::model::ToolChoice::Auto) => (Some("auto".to_owned()), None),
            Some(tracelane_shared::model::ToolChoice::None) => (Some("none".to_owned()), None),
            Some(tracelane_shared::model::ToolChoice::Required) => {
                (Some("required".to_owned()), None)
            }
            Some(tracelane_shared::model::ToolChoice::Function { name }) => {
                let mut n = name.clone();
                truncate_utf8(&mut n, MAX_TOOL_NAME_BYTES);
                (Some("function".to_owned()), Some(n))
            }
        };

        let (tool_count, tool_names, tool_definitions_hash) = match &req.tools {
            None => (None, None, None),
            Some(tools) => {
                // The TRUE count, before any cap. See MAX_TOOL_NAMES.
                let count = u32::try_from(tools.len()).unwrap_or(u32::MAX);
                let names: Vec<String> = tools
                    .iter()
                    .take(MAX_TOOL_NAMES)
                    .map(|t| {
                        let mut n = t.name.clone();
                        truncate_utf8(&mut n, MAX_TOOL_NAME_BYTES);
                        n
                    })
                    .collect();
                // SORTED before hashing, so two requests offering the same tools
                // in a different order produce the same set hash — the identity
                // being captured is "which tool definitions", not "in what order".
                let mut per_tool: Vec<String> = tools
                    .iter()
                    .map(|t| {
                        crate::guardrail::capability::def_hash(
                            &t.name,
                            &t.input_schema,
                            t.description.as_deref().unwrap_or(""),
                        )
                        .to_hex()
                        .to_string()
                    })
                    .collect();
                per_tool.sort_unstable();
                let mut h = blake3::Hasher::new();
                for d in &per_tool {
                    // Length-prefixed, matching `def_hash`'s own framing, so two
                    // different tool sets cannot collide across a field boundary.
                    h.update(&(d.len() as u64).to_be_bytes());
                    h.update(d.as_bytes());
                }
                let set_hash = h.finalize().to_hex().to_string();
                // An EMPTY `tools: []` is a real and different fact from no
                // `tools` key: count 0, no names, and no hash to speak of.
                let names = if names.is_empty() { None } else { Some(names) };
                let set_hash = if tools.is_empty() {
                    None
                } else {
                    Some(set_hash)
                };
                (Some(count), names, set_hash)
            }
        };

        Self {
            temperature: req.temperature,
            top_p: req.top_p,
            max_tokens: req.max_tokens,
            seed: req.seed,
            tool_choice_mode,
            tool_choice_function,
            tool_count,
            tool_names,
            tool_definitions_hash,
            deployment_id: deployment_identity(&req.model),
            misconfig_flags: None,
            zdr_required: None,
            zdr_eligible_providers: None,
        }
    }

    /// OBS-52. Evaluate the operator's `model_policy:` block against what was
    /// recorded, and attach the flags.
    ///
    /// **OBSERVE-ONLY.** It never blocks, never fails a request and never changes
    /// a status code — ADR-055's founder amendment governs the product lead, and
    /// a temperature of 1.4 is a STYLE, not an attack. CLAUDE.md §21 (a consumer
    /// of LLM output that decides must fail closed) does not reach this: the
    /// input is request configuration the developer wrote, not model output, and
    /// no promotion, gate, label or artifact turns on the result.
    ///
    /// **But the DETECTOR fails closed on unknowns — three states, never two.**
    /// A check whose attribute is absent produces NO verdict, never `ok`. That is
    /// the same distinction `cost_usd_present` had to learn: a read path that
    /// renders an honestly-unknown value as a confident zero is worse than one
    /// that renders nothing.
    ///
    /// No `model_policy:` block ⇒ no checks run at all: no config, no opinion.
    pub(crate) fn with_policy_flags(mut self) -> Self {
        let Some(policy) = super::config::model_policy() else {
            return self;
        };
        let mut flags: Vec<String> = Vec::new();

        if let (Some(t), Some(max)) = (self.temperature, policy.temperature_max())
            && t > max
        {
            flags.push("temperature_out_of_range".to_owned());
        }
        if let (Some(p), Some(max)) = (self.top_p, policy.top_p_max())
            && p > max
        {
            flags.push("top_p_out_of_range".to_owned());
        }
        // THE SINGLE MOST IMPORTANT LINE IN OBS-52. This is the one check whose
        // subject IS an absence, so it must prove the span was written by an
        // instrumented build before it fires — otherwise it flags every span
        // written before this deploy, and every OTLP span from a customer SDK
        // that emits no request config at all.
        if policy.require_max_tokens() && self.max_tokens.is_none() && self.is_instrumented() {
            flags.push("missing_max_tokens".to_owned());
        }

        if !flags.is_empty() {
            self.misconfig_flags = Some(flags);
        }
        self
    }

    /// True when at least one GWY-48 attribute other than `max_tokens` is
    /// present — i.e. this request was seen by a build that records request
    /// configuration. See `with_policy_flags`.
    fn is_instrumented(&self) -> bool {
        self.temperature.is_some()
            || self.top_p.is_some()
            || self.seed.is_some()
            || self.tool_choice_mode.is_some()
            || self.tool_count.is_some()
            || self.deployment_id.is_some()
    }

    /// Post-construction mutation, matching `CapturedInput::apply` and the
    /// semantic-cache attributes — it keeps `build_gateway_span`'s argument list
    /// bounded rather than growing it by ten.
    pub(crate) fn apply(self, attrs: &mut tracelane_shared::SpanAttributes) {
        attrs.gen_ai_request_temperature = self.temperature;
        attrs.gen_ai_request_top_p = self.top_p;
        attrs.gen_ai_request_max_tokens = self.max_tokens;
        attrs.gen_ai_request_seed = self.seed;
        attrs.tracelane_request_tool_choice_mode = self.tool_choice_mode;
        attrs.tracelane_request_tool_choice_function = self.tool_choice_function;
        attrs.tracelane_request_tool_count = self.tool_count;
        attrs.tracelane_request_tool_names = self.tool_names;
        attrs.tracelane_request_tool_definitions_hash = self.tool_definitions_hash;
        attrs.tracelane_request_deployment_id = self.deployment_id;
        attrs.tracelane_misconfig_flags = self.misconfig_flags;
        attrs.tracelane_zdr_required = self.zdr_required;
        attrs.tracelane_zdr_eligible_providers = self.zdr_eligible_providers;
    }
}

/// GWY-48: the provider-specific deployment identity carried inside a model
/// string, or `None` when the model carries none.
///
/// **THE PROVIDER DECISION IS DELEGATED, NEVER RE-DERIVED.** A first draft matched
/// `azure/`, `ft:` and `arn:` on literal prefixes here and
/// `check-provider-mapping-single-source.py` refused it — correctly: this repo has
/// exactly ONE model→provider map (`ProviderRegistry::provider_id_for_model`) and a
/// second one drifts silently. So the provider comes from that map and only the
/// SHAPE is read here.
///
/// **TWO SHAPES THE SPEC LISTED CANNOT REACH THIS FUNCTION AT ALL, and finding that
/// out is worth more than the code:** an OpenAI fine-tune (`ft:gpt-4o-…`) and a BARE
/// Bedrock ARN (`arn:aws:bedrock:…`) both resolve to `None` in the canonical map —
/// no native prefix matches them and no catalog row starts that way — so the gateway
/// refuses them upstream with `unroutable_model` and no span is ever written. They
/// are not handled here because handling them would be dead code that reads as
/// coverage. A Bedrock ARN reaches us only as `bedrock/arn:…`, which IS handled.
///
/// `None` rather than `Some("")`: an empty string renders as a value and would make
/// "this is an ordinary model" indistinguishable from "we failed to parse it".
fn deployment_identity(model: &str) -> Option<String> {
    match crate::providers::ProviderRegistry::provider_id_for_model(model)? {
        // `azure/prod-gpt4o` → `prod-gpt4o`. The scheme is checked rather than
        // stripped-with-a-fallback: `provider_id_for_model` also answers "azure"
        // for a `tracelane.yaml` ALIAS, and an alias name is not a deployment id.
        "azure" => model
            .split_once('/')
            .filter(|(scheme, deployment)| *scheme == "azure" && !deployment.is_empty())
            .map(|(_, deployment)| deployment.to_owned()),
        // `bedrock/arn:aws:bedrock:…` → the ARN. A `bedrock/` model that is a plain
        // model id, not an ARN, has no deployment identity and returns `None`.
        "bedrock" => {
            let after = model.split_once('/').map_or(model, |(_, rest)| rest);
            after
                .split_once(':')
                .filter(|(scheme, _)| *scheme == "arn")
                .map(|_| after.to_owned())
        }
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
/// Segment timestamps for the gateway-overhead split (§ latency framing). The
/// span's `start_time` = gateway-received and `end_time` = gateway-response-sent
/// bracket the whole request; these two interior marks bracket the provider
/// round-trip, so `gateway_overhead = (dispatch − received) + (sent − provider
/// complete)` and `provider = total − gateway_overhead` — the two segments sum
/// to total with NO unattributed bucket. `ttft_us` (dispatch → provider first
/// byte) is streaming-only.
#[derive(Clone, Copy)]
pub(crate) struct GatewayTiming {
    pub(crate) dispatch_ts: chrono::DateTime<chrono::Utc>,
    pub(crate) provider_complete_ts: chrono::DateTime<chrono::Utc>,
    pub(crate) ttft_us: Option<u32>,
}

/// Gateway-overhead microseconds = `(dispatch − received) + (sent − provider
/// complete)` — the time the gateway adds, EXCLUDING the provider round-trip.
/// Pure so the split math is unit-testable: with `total = sent − received`,
/// `provider = total − overhead`, and `overhead + provider == total` exactly
/// (no unattributed bucket). `None` if any interval underflows the μs range.
fn gateway_overhead_us(
    received: chrono::DateTime<chrono::Utc>,
    dispatch: chrono::DateTime<chrono::Utc>,
    provider_complete: chrono::DateTime<chrono::Utc>,
    sent: chrono::DateTime<chrono::Utc>,
) -> Option<u32> {
    let pre = (dispatch - received).num_microseconds()?;
    let post = (sent - provider_complete).num_microseconds()?;
    u32::try_from((pre + post).max(0)).ok()
}

/// B-568 I4: move a built span's `end_time` to the moment the response actually
/// leaves, and charge the gap to the gateway overhead.
///
/// `build_gateway_span` stamps `end_time = now()` on the line after
/// `provider_complete_ts`, so on the buffered path the response-side guardrail
/// seam, the output capture and the span bookkeeping all ran AFTER the span
/// ended and were counted in neither segment — client-visible latency no number
/// showed. With `overhead = pre + (end − provider_complete)`, moving `end` by `d`
/// moves overhead by exactly `d` and leaves `provider = total − overhead`
/// untouched, so the two segments still sum to the total to the microsecond.
///
/// A span with no measured overhead keeps `None` (nothing is invented), and a
/// `sent` earlier than the recorded end (a wall-clock step backwards) changes
/// nothing rather than shortening the span.
pub(crate) fn restamp_sent(span: &mut TracelaneSpan, sent: chrono::DateTime<chrono::Utc>) {
    let Some(built) = span.end_time else {
        return;
    };
    let Some(gap_us) = (sent - built).num_microseconds().filter(|us| *us > 0) else {
        return;
    };
    span.end_time = Some(sent);
    if let Some(oh) = span.attributes.tracelane_gateway_overhead_us {
        span.attributes.tracelane_gateway_overhead_us =
            Some(oh.saturating_add(u32::try_from(gap_us).unwrap_or(u32::MAX)));
    }
}

/// Build a `TracelaneSpan` from gateway request/response metadata.
///
/// Called after the provider responds (or errors) to record the full round-trip.
/// All timing is wall-clock UTC; `end_time` is set at call time.
///
/// Parameters match OTel GenAI semconv v1.27.
///
/// R81: `pub(crate)` so `prompt_eval` builds its spans with the SAME function the
/// chat path uses. A second span builder for eval traffic would be a second source
/// of truth for "what a gateway span is", and the two would drift on the next
/// column — which is the failure `S2`/one-execution-engine exists to prevent.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_gateway_span(
    tenant_id: &TenantId,
    trace_id: Uuid,
    parent_span_id: Option<Uuid>,
    model: &str,
    // All five caller-supplied identity values, together — see `CallerIdentity`
    // for why they travel as one struct rather than as five `Option<&str>` in a
    // row (B-367, B-368, and the transposition hazard that guarded them).
    identity: &CallerIdentity,
    start_time: chrono::DateTime<chrono::Utc>,
    input_tokens: u32,
    output_tokens: u32,
    aft_id: Option<&str>,
    usage_meta: SpanUsageMeta,
    failover_from: Option<&str>,
    timing: Option<GatewayTiming>,
    error_reason: Option<&str>,
    api_key_id: Option<&str>,
) -> TracelaneSpan {
    let provider = provider_name_from_model(model);
    let end_time = chrono::Utc::now();
    let requested_model: &str = identity.requested_model.as_deref().unwrap_or(model);
    // A `tracelane.yaml` alias on the requested string means the upstream saw a
    // different model by our doing (GWY-39); `config::alias` is one `OnceLock` read.
    let alias_applied =
        identity.tenant_alias_applied || super::config::alias(requested_model).is_some();
    // Gateway overhead = time Tracelane adds, EXCLUDING the provider round-trip:
    // (dispatch − received) + (sent − provider-complete). `None` when there was
    // no measured provider round-trip (dispatch failures / guardrail blocks).
    let gateway_overhead_us = timing.and_then(|t| {
        gateway_overhead_us(start_time, t.dispatch_ts, t.provider_complete_ts, end_time)
    });
    let ttft_secs = timing
        .and_then(|t| t.ttft_us)
        .map(|us| f64::from(us) / 1_000_000.0);
    TracelaneSpan {
        span_id: Uuid::new_v4(),
        trace_id,
        // ADR-075 / B-311: the caller's `traceparent` span, when it sent one. Was
        // hardcoded `None` — the reason a base-URL swap could never join a framework trace.
        parent_span_id,
        tenant_id: tenant_id.clone(),
        name: "gen_ai.chat".to_string(),
        start_time,
        end_time: Some(end_time),
        attributes: SpanAttributes {
            gen_ai_operation_name: Some("chat".to_string()),
            // Canonical v1.41 provider field; `gen_ai_system` kept for
            // legacy-downstream round-trip (ADR-032).
            gen_ai_system: Some(provider.to_string()),
            gen_ai_provider_name: Some(provider.to_string()),
            // RI-05 / B-444: the REQUESTED string is the caller's (pre-alias,
            // pre-failover) when admission recorded it; `model` — the routing and
            // billing attribution, rewritten by failover — is the fallback for the
            // routes that do not record it (embeddings, /v1/messages).
            gen_ai_request_model: Some(requested_model.to_string()),
            // The SERVED model is the provider's own claim — ABSENT when it sent
            // none. Until 2026-09-19 this was a copy of the requested string, so the
            // two columns could never disagree and read paths trusted the copy as
            // the served model (B-444).
            gen_ai_response_model: usage_meta.served.model.clone(),
            gen_ai_response_id: usage_meta.served.id.clone(),
            gen_ai_response_finish_reasons: usage_meta
                .finish_reason
                .map(|r| vec![r.as_str().to_string()]),
            tracelane_model_substitution: substitution(
                requested_model,
                usage_meta.served.model.as_deref(),
                alias_applied,
                failover_from.is_some(),
            )
            .map(str::to_owned),
            gen_ai_usage_input_tokens: Some(input_tokens),
            gen_ai_usage_output_tokens: Some(output_tokens),
            gen_ai_usage_cache_read_input_tokens: usage_meta.cache_read_input_tokens,
            gen_ai_usage_cache_creation_input_tokens: usage_meta.cache_creation_input_tokens,
            // RI-05 / M11: broken out from the still-inclusive `output_tokens`
            // above (cost/billing parity unchanged, `google.rs`'s rule).
            gen_ai_usage_reasoning_output_tokens: usage_meta.reasoning_output_tokens,
            // Provider-reported cost when present; otherwise derive it from the
            // token counts + the model price catalog. `None` (unknown model) is
            // preserved — the gateway never fabricates a cost (ADR-055).
            gen_ai_usage_cost: usage_meta.cost_usd.or_else(|| {
                crate::pricing::cost_usd(
                    model,
                    &tracelane_shared::Usage {
                        input_tokens,
                        output_tokens,
                        cache_read_input_tokens: usage_meta.cache_read_input_tokens,
                        cache_creation_input_tokens: usage_meta.cache_creation_input_tokens,
                    },
                )
            }),
            gen_ai_request_stream: Some(usage_meta.stream),
            gen_ai_response_time_to_first_chunk: ttft_secs,
            tracelane_gateway_overhead_us: gateway_overhead_us,
            // B-568 I5: present only when true AND beside a measured overhead —
            // the dashboard splits the overhead population, so a flag with no
            // number behind it would count a sample the quantile never saw.
            tracelane_gateway_cold_start: (identity.cold_start && gateway_overhead_us.is_some())
                .then_some(true),
            gen_ai_conversation_id: identity.conversation_id.clone(),
            tracelane_aft_id: aft_id.map(str::to_owned),
            tracelane_kya_agent_id: identity.agent_id.clone(),
            tracelane_agent_step_index: identity.agent_step_index,
            tracelane_kya_human_authorizer: identity.human_authorizer.clone(),
            tracelane_business_reference: identity.business_reference.clone(),
            user_id: identity.end_user_id.clone(),
            gen_ai_agent_name: identity.agent_name.clone(),
            tracelane_client_name: identity.client_name.clone(),
            tracelane_agent_name_source: identity.agent_name.as_ref().map(|_| "header".into()),
            // Present only when a cross-provider failover served this
            // request. The rollup counts `countIf(tracelane_failover_activated)`;
            // `tracelane_failover_from` names the primary provider that errored.
            tracelane_failover_activated: failover_from.map(|_| true),
            tracelane_failover_from: failover_from.map(str::to_owned),
            // RI-05 M1 + M4: absent unless the ledger is worth recording —
            // more than one attempt, or any attempt that errored (spec §2.1).
            // A clean single attempt writes nothing, which together with
            // `gen_ai_response_id` distinguishes a verified-clean span from a
            // pre-RI-05 one that never carried this field at all.
            tracelane_dispatch_attempts: {
                let write = tracelane_shared::span::dispatch_attempts_worth_recording(
                    &usage_meta.dispatch_attempts,
                );
                write.then_some(usage_meta.dispatch_attempts)
            },
            // GWY-43: which API key paid for this. `None` for a JWT session.
            tracelane_api_key_id: api_key_id.map(str::to_owned),
            // RI-05 M5: OpenAI's `system_fingerprint`, spelled as the OTLP passthrough
            // spells it (`decode.rs` maps `gen_ai.openai.*` → `openai.*` into `extra`).
            extra: usage_meta
                .served
                .system_fingerprint
                .as_ref()
                .map(|fp| {
                    std::collections::HashMap::from([(
                        "openai.response.system_fingerprint".to_string(),
                        serde_json::Value::String(fp.clone()),
                    )])
                })
                .unwrap_or_default(),
            ..Default::default()
        },
        // A FAILED request (upstream 4xx/5xx/timeout, mid-stream provider error, or
        // dispatch exhaustion) MUST record status Error — otherwise /slo's
        // countIf(status_code = 2) error rate is STRUCTURALLY pinned at ~0% for all
        // gateway-proxied traffic (#3: every span was hardcoded Ok, so a real
        // provider outage read as "0% errors · no errors in window"). Ok is emitted
        // only on a genuinely successful round-trip.
        status: match error_reason {
            Some(reason) => SpanStatus {
                code: SpanStatusCode::Error,
                message: Some(reason.to_string()),
            },
            None => SpanStatus {
                code: SpanStatusCode::Ok,
                message: None,
            },
        },
    }
}

/// Add a completed request's cost to its API key's monthly total.
///
/// Reads the cost off the SPAN, not from a second `pricing::cost_usd` call: the
/// budget and the dashboard must agree about what a request cost, and the only
/// way to guarantee that is for both to read one value. A `None` cost — a model
/// with no known price — adds nothing rather than zero (see `spend.rs`).
///
/// A non-UUID key id cannot happen (`claims.api_key_id()` returns the
/// `api_keys.id` it read from Postgres) but is ignored rather than unwrapped:
/// this runs on the response path and must not be able to panic a stream.
pub(crate) fn record_key_spend(api_key_id: Option<&str>, span: &TracelaneSpan) {
    let cost = span.attributes.gen_ai_usage_cost;
    let tracker = crate::spend::tracker();
    // The workspace total counts EVERY request, keyed or not — a session-driven
    // request spends the workspace's money too, and exempting it would make the
    // workspace cap quietly smaller than it says.
    tracker.record(
        crate::spend::Subject::Workspace(*span.tenant_id.as_uuid()),
        cost,
    );
    let Some(id) = api_key_id else { return };
    let Ok(uuid) = Uuid::parse_str(id) else {
        return;
    };
    tracker.record(crate::spend::Subject::Key(uuid), cost);

    // BILL-01 A3 sub-meters (`key_output_tokens`, `key_spend_micro_usd`) —
    // the velocity breaker's own data source. Fire-and-forget: `MeterSink
    // ::record` is async and this function is not, matching
    // `stamp_and_meter_span_bytes`'s same pattern.
    if let Some(sink) = crate::billing::meters::global() {
        let tenant = span.tenant_id.clone();
        let key_id = id.to_string();
        let output_tokens = span.attributes.gen_ai_usage_output_tokens;
        tokio::spawn(async move {
            if let Some(tokens) = output_tokens.filter(|t| *t > 0) {
                sink.record(
                    &tenant,
                    crate::billing::UsageMeter::KeyOutputTokens,
                    &key_id,
                    f64::from(tokens),
                )
                .await;
            }
            if let Some(usd) = cost.filter(|c| c.is_finite() && *c > 0.0) {
                sink.record(
                    &tenant,
                    crate::billing::UsageMeter::KeySpendMicroUsd,
                    &key_id,
                    usd * 1_000_000.0,
                )
                .await;
            }
        });
    }
}

/// `OBS-53`. Folds a stream of per-token logprobs into the THREE numbers a span
/// carries, and never the distribution itself.
///
/// **Why a summary and not the payload.** Per-token logprobs for a 2,000-token
/// completion at `top_logprobs: 5` is tens of kilobytes of nested JSON per span,
/// and the token strings in it ARE the model's output text — i.e. content, which
/// would need the `trace_content:` gate and would make this feature invisible on
/// prod. Three floats reveal nothing quotable, so they are ungated.
///
/// **What the mean is NOT:** not a probability, not a calibrated confidence, and
/// not comparable between models. Every surface rendering it must say so, and
/// the label is *"mean token logprob"* — never bare "confidence".
#[derive(Debug, Default, Clone)]
pub(crate) struct LogprobAccumulator {
    sum: f64,
    min: Option<f64>,
    count: u32,
}

/// Cap on how many tokens one span's summary covers. `token_count` reports what
/// was ACTUALLY summarised, so a capped summary is never presented as a
/// whole-response one — the count is the disclosure, exactly as
/// `tracelane_request_tool_count` is for a truncated tool-name list.
const MAX_LOGPROB_TOKENS: u32 = 2_048;

impl LogprobAccumulator {
    pub(crate) fn absorb(&mut self, logprobs: &[f64]) {
        for lp in logprobs {
            if self.count >= MAX_LOGPROB_TOKENS {
                return;
            }
            // Non-finite values were already filtered at the parser, but a second
            // provider adapter could feed this later; a NaN here would poison the
            // mean silently and render as "null" rather than as an error.
            if !lp.is_finite() {
                continue;
            }
            self.sum += *lp;
            self.min = Some(self.min.map_or(*lp, |m: f64| m.min(*lp)));
            self.count += 1;
        }
    }

    /// Writes nothing at all when no logprobs were seen. **Absent must stay
    /// absent**: a span with a `logprob_mean` of `0.0` would read as a perfectly
    /// confident response, when `0.0` is in fact the maximum possible logprob —
    /// the single most misleading default this feature could ship.
    pub(crate) fn apply(&self, attrs: &mut tracelane_shared::SpanAttributes) {
        if self.count == 0 {
            return;
        }
        attrs.tracelane_response_logprob_mean = Some(self.sum / f64::from(self.count));
        attrs.tracelane_response_logprob_min = self.min;
        attrs.tracelane_response_logprob_token_count = Some(self.count);
    }
}

/// A prompt resolution is an observed operation, with no invented model usage.
pub(crate) fn build_prompt_resolution_span(
    tenant: &TenantId,
    name: &str,
    resolution: &crate::prompt_router::PromptResolution,
    identity: &CallerIdentity,
) -> TracelaneSpan {
    let now = chrono::Utc::now();
    let mut extra = std::collections::HashMap::from([
        ("tracelane.prompt.name".into(), serde_json::json!(name)),
        (
            "tracelane.prompt.version_id".into(),
            serde_json::json!(resolution.version.prompt_version_id),
        ),
        (
            "tracelane.prompt.arm".into(),
            serde_json::json!(resolution.arm),
        ),
    ]);
    if let Some(id) = resolution.canary_id {
        extra.insert("tracelane.prompt.canary_id".into(), serde_json::json!(id));
    }
    TracelaneSpan {
        span_id: Uuid::new_v4(),
        trace_id: Uuid::new_v4(),
        parent_span_id: None,
        tenant_id: tenant.clone(),
        name: "prompt.resolve".into(),
        start_time: now,
        end_time: Some(now),
        attributes: SpanAttributes {
            gen_ai_operation_name: Some("prompt.resolve".into()),
            user_id: identity.end_user_id.clone(),
            gen_ai_agent_name: identity.agent_name.clone(),
            tracelane_client_name: identity.client_name.clone(),
            tracelane_agent_name_source: identity.agent_name.as_ref().map(|_| "header".into()),
            gen_ai_conversation_id: identity.conversation_id.clone(),
            tracelane_kya_agent_id: identity.agent_id.clone(),
            extra,
            ..Default::default()
        },
        status: SpanStatus {
            code: SpanStatusCode::Ok,
            message: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kya_attributes(headers: HeaderMap) -> serde_json::Value {
        let span = build_gateway_span(
            &TenantId::from_jwt_claim(uuid::Uuid::from_u128(7)),
            uuid::Uuid::from_u128(1),
            None,
            "claude-haiku-4-5",
            &CallerIdentity::from_headers(&headers),
            chrono::Utc::now(),
            1,
            1,
            None,
            SpanUsageMeta::default(),
            None,
            None,
            None,
            None,
        );
        serde_json::to_value(span.attributes).unwrap()
    }

    #[test]
    fn kya_header_names_the_agent_and_records_its_source() {
        let mut h = HeaderMap::new();
        h.insert("x-tracelane-agent-name", "  KYA-Proof  ".parse().unwrap());
        let a = kya_attributes(h);
        assert_eq!(a["gen_ai_agent_name"], "kya-proof");
        assert_eq!(a["tracelane_agent_name_source"], "header");
    }

    #[test]
    fn kya_name_is_printable_and_truncated_at_64_characters() {
        let mut h = HeaderMap::new();
        h.insert("x-tracelane-agent-name", "a".repeat(70).parse().unwrap());
        assert_eq!(kya_attributes(h)["gen_ai_agent_name"], "a".repeat(64));
        for raw in ["", "   ", "bad\tname"] {
            let mut h = HeaderMap::new();
            h.insert("x-tracelane-agent-name", raw.parse().unwrap());
            assert!(kya_attributes(h).get("gen_ai_agent_name").is_none());
        }
    }

    #[test]
    fn kya_observed_clients_are_classified_without_retaining_user_agent() {
        // Product tokens observed from local requests by the installed CLIs.
        // The synthetic suffix probes privacy without preserving host metadata.
        for (token, client) in [
            ("claude-cli/2.1.281", "claude-code"),
            ("codex_exec/0.155.1", "codex"),
        ] {
            let ua = format!("{token} private-machine-metadata");
            let mut h = HeaderMap::new();
            h.insert("user-agent", ua.parse().unwrap());
            let a = kya_attributes(h);
            assert_eq!(a["tracelane_client_name"], client);
            assert!(!a.to_string().contains(&ua));
            assert!(!a.to_string().contains("private-machine"));
            assert!(a.get("gen_ai_agent_name").is_none());
        }
        for ua in ["unknown/1", "xclaude-cli/2.1.281", "codex/1", ""] {
            let mut h = HeaderMap::new();
            h.insert("user-agent", ua.parse().unwrap());
            assert!(kya_attributes(h).get("tracelane_client_name").is_none());
        }
    }

    /// RI-05 M18 follow-up: the proxy header is a small integer or nothing. Garbage,
    /// negatives and empties are ABSENT — never an error, never echoed as text.
    #[test]
    fn step_index_header_parses_a_small_integer_and_drops_everything_else() {
        let mut h = HeaderMap::new();
        h.insert("x-tracelane-step-index", " 3 ".parse().unwrap());
        assert_eq!(CallerIdentity::from_headers(&h).agent_step_index, Some(3));
        for bad in ["-1", "three", "", "3.5", "99999999999"] {
            let mut h = HeaderMap::new();
            h.insert("x-tracelane-step-index", bad.parse().unwrap());
            assert_eq!(
                CallerIdentity::from_headers(&h).agent_step_index,
                None,
                "{bad:?} must not parse"
            );
        }
        assert_eq!(
            CallerIdentity::from_headers(&HeaderMap::new()).agent_step_index,
            None
        );
    }

    /// `OBS-20`. **The hazard this test exists for is transposition, not absence.**
    ///
    /// `build_gateway_span` now takes EIGHT `Option<&str>` parameters in a row —
    /// agent_id, human_authorizer, business_reference, end_user_id,
    /// conversation_id, failover_from, error_reason, api_key_id. Swap any two of
    /// them at any of the ten call sites and it compiles clean, every existing
    /// test still passes, and one customer's traces get attributed to another's
    /// identity field. The compiler cannot see it because the types are
    /// identical.
    ///
    /// So this passes a DISTINGUISHABLE value for each and asserts each one
    /// lands in its own attribute. It fails the moment two are swapped, which is
    /// the only failure mode worth a test here.
    /// RI-05 / B-444 — RED against the pre-2026-09-19 builder, which wrote the
    /// requested string into `gen_ai_response_model` on every span. A span built
    /// from a call the provider said NOTHING about must not claim a served model.
    #[test]
    fn a_span_never_copies_the_requested_model_into_the_served_column() {
        let tenant = TenantId::from_jwt_claim(uuid::Uuid::from_u128(7));
        let span = build_gateway_span(
            &tenant,
            uuid::Uuid::from_u128(1),
            None,
            "claude-sonnet-4-6",
            &CallerIdentity::default(),
            chrono::Utc::now(),
            1,
            1,
            None,
            SpanUsageMeta::default(),
            None,
            None,
            None,
            None,
        );
        assert_eq!(
            span.attributes.gen_ai_request_model.as_deref(),
            Some("claude-sonnet-4-6")
        );
        assert!(
            span.attributes.gen_ai_response_model.is_none(),
            "nothing was served, so the served column must be ABSENT, not a copy of the request (B-444)"
        );
    }

    #[test]
    fn substitution_is_observed_never_inferred() {
        assert_eq!(
            substitution("gpt-4o", None, false, false),
            None,
            "served unknown → none"
        );
        assert_eq!(
            substitution("gpt-4o", Some("gpt-4o"), true, true),
            None,
            "equal → none"
        );
        assert_eq!(
            substitution("my-alias", Some("gpt-4o-2024-08-06"), true, false),
            Some("alias")
        );
        assert_eq!(
            substitution("gpt-4o", Some("claude-sonnet-4-6"), false, true),
            Some("failover")
        );
        assert_eq!(
            substitution("a", Some("b"), true, true),
            Some("alias+failover")
        );
        assert_eq!(
            substitution("gpt-4o", Some("gpt-4o-2024-08-06"), false, false),
            Some("provider"),
            "neither we nor a failover changed it: the silent-substitution signal"
        );
    }

    #[test]
    fn the_served_model_id_fingerprint_and_finish_reason_land_and_a_caller_string_survives() {
        let tenant = TenantId::from_jwt_claim(uuid::Uuid::from_u128(7));
        let identity = CallerIdentity {
            requested_model: Some("gpt-4o".into()),
            ..Default::default()
        };
        let span = build_gateway_span(
            &tenant,
            uuid::Uuid::from_u128(1),
            None,
            "claude-sonnet-4-6", // the routing/billing attribution AFTER a failover
            &identity,
            chrono::Utc::now(),
            1,
            1,
            None,
            SpanUsageMeta {
                served: ServedMeta {
                    id: Some("chatcmpl-abc".into()),
                    model: Some("claude-sonnet-4-6-20260301".into()),
                    system_fingerprint: Some("fp_123".into()),
                },
                finish_reason: Some(crate::providers::FinishReason::Length),
                ..Default::default()
            },
            Some("openai"),
            None,
            None,
            None,
        );
        let a = &span.attributes;
        assert_eq!(
            a.gen_ai_request_model.as_deref(),
            Some("gpt-4o"),
            "the CALLER's string, not the failover model"
        );
        assert_eq!(
            a.gen_ai_response_model.as_deref(),
            Some("claude-sonnet-4-6-20260301"),
            "the provider's own string"
        );
        assert_eq!(a.gen_ai_response_id.as_deref(), Some("chatcmpl-abc"));
        assert_eq!(
            a.gen_ai_response_finish_reasons,
            Some(vec!["length".to_string()])
        );
        assert_eq!(a.tracelane_model_substitution.as_deref(), Some("failover"));
        assert_eq!(
            a.extra.get("openai.response.system_fingerprint"),
            Some(&serde_json::Value::String("fp_123".into()))
        );
    }

    #[test]
    fn served_meta_keeps_the_first_claim() {
        let mut m = ServedMeta::default();
        m.absorb(Some("id-1".into()), None, None);
        m.absorb(Some("id-2".into()), Some("m-2".into()), Some("fp-2".into()));
        assert_eq!(
            m.id.as_deref(),
            Some("id-1"),
            "a later frame never overwrites"
        );
        assert_eq!(
            m.model.as_deref(),
            Some("m-2"),
            "but fills what was still empty"
        );
        assert_eq!(m.system_fingerprint.as_deref(), Some("fp-2"));
    }

    #[test]
    fn each_caller_identity_lands_in_its_own_attribute_and_none_are_transposed() {
        let tenant = TenantId::from_jwt_claim(uuid::Uuid::from_u128(7));
        let span = build_gateway_span(
            &tenant,
            uuid::Uuid::from_u128(1),
            None,
            "claude-sonnet-4-6",
            &CallerIdentity {
                agent_id: Some("AGENT".into()),
                human_authorizer: Some("AUTHORIZER".into()),
                business_reference: Some("BUSINESS".into()),
                end_user_id: Some("ENDUSER".into()),
                conversation_id: Some("CONVERSATION".into()),
                requested_model: None,
                agent_step_index: Some(7),
                ..CallerIdentity::default()
            },
            chrono::Utc::now(),
            1,
            1,
            None,
            SpanUsageMeta {
                cache_read_input_tokens: None,
                cache_creation_input_tokens: None,
                stream: false,
                cost_usd: None,
                served: ServedMeta::default(),
                finish_reason: None,
                dispatch_attempts: Vec::new(),
                reasoning_output_tokens: None,
            },
            Some("FAILOVERFROM"),
            None,
            Some("ERRORREASON"),
            Some("APIKEY"),
        );
        let a = &span.attributes;
        assert_eq!(a.tracelane_kya_agent_id.as_deref(), Some("AGENT"));
        assert_eq!(
            a.tracelane_agent_step_index,
            Some(7),
            "the header rides onto the span"
        );
        assert_eq!(
            a.tracelane_kya_human_authorizer.as_deref(),
            Some("AUTHORIZER")
        );
        assert_eq!(a.tracelane_business_reference.as_deref(), Some("BUSINESS"));
        assert_eq!(a.user_id.as_deref(), Some("ENDUSER"));
        assert_eq!(a.gen_ai_conversation_id.as_deref(), Some("CONVERSATION"));
        assert_eq!(a.tracelane_failover_from.as_deref(), Some("FAILOVERFROM"));
        assert_eq!(a.tracelane_api_key_id.as_deref(), Some("APIKEY"));
        assert_eq!(span.status.message.as_deref(), Some("ERRORREASON"));
    }
    /// GWY-45. `truncate_utf8` must cut on a CHARACTER boundary and say that it
    /// cut. A silent truncation produces eval cases that look complete and are
    /// not; a byte-boundary cut produces invalid UTF-8 and loses the whole span
    /// at serialization.
    #[test]
    fn truncate_utf8_cuts_on_a_char_boundary_and_marks_the_cut() {
        // Multi-byte throughout, so a naive byte cut would split a char.
        let mut s = "héllo wörld ünicode".repeat(20);
        let original = s.clone();
        truncate_utf8(&mut s, 40);
        assert!(s.len() <= 40, "must respect the byte cap, got {}", s.len());
        assert!(
            s.ends_with("…[truncated]"),
            "a cut MUST be visible — a silent one yields eval cases that look              complete and are not; got {s:?}"
        );
        // The real assertion: it is still valid UTF-8. `String` guarantees this,
        // so the way this fails is a PANIC inside truncate_utf8, not a bad value.
        assert!(s.chars().count() > 0);

        // Under the cap it must be untouched — no marker, no allocation churn.
        let mut short = "hi".to_owned();
        truncate_utf8(&mut short, 40);
        assert_eq!(short, "hi", "a string under the cap must be left alone");

        // THE POST-CONDITION, asserted at the boundary that broke it: the result
        // is NEVER longer than the cap. The first version of this function
        // appended a 14-byte marker to a 3-byte budget and returned 14 bytes for
        // max=3 — longer than the input limit, from the function whose job is to
        // enforce it. Unreachable in prod (the config floor is 1 KiB) and fixed
        // anyway.
        for cap in [0, 1, 3, 13, 14, 15, 64] {
            let mut tiny = original.clone();
            truncate_utf8(&mut tiny, cap);
            assert!(
                tiny.len() <= cap,
                "truncate_utf8 must never exceed its cap: cap={cap} produced {} bytes ({tiny:?})",
                tiny.len()
            );
        }
    }

    /// **THE HOT-PATH GUARANTEE.** With no `trace_content:` block installed —
    /// which is every deployment today, and the fail-CLOSED default — capture
    /// must return `None` without touching the request.
    ///
    /// This is the test that would catch content leaking for a tenant nobody
    /// allowlisted, which is the only way this feature can do harm.
    #[test]
    fn capture_is_none_when_no_trace_content_block_is_installed() {
        let tenant = tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::from_u128(7));
        let req = tracelane_shared::ChatRequest {
            top_p: None,
            seed: None,
            logprobs: None,
            top_logprobs: None,
            model: "claude-haiku-4-5".to_owned(),
            messages: vec![tracelane_shared::model::Message {
                role: tracelane_shared::model::Role::User,
                content: tracelane_shared::model::MessageContent::Text(
                    "a secret prompt nobody allowlisted".to_owned(),
                ),
                tool_call_id: None,
                tool_calls: None,
            }],
            tools: None,
            tool_choice: None,
            max_tokens: None,
            temperature: None,
            stream: None,
            system: None,
            metadata: None,
        };
        // No operator block AND no control plane: the decision the OSS self-host makes.
        let capture = crate::server::config::capture_decision(None, None, &tenant);
        assert!(
            CapturedInput::build(capture, &req).is_none(),
            "with no trace_content block installed, capture MUST be off — an              absent config is the unprivileged state (.claude/rules/tenancy.md)"
        );
    }

    // ── GWY-53 — the cap holds for EVERY shape a customer can send ───────────
    //
    // Until GWY-53 only our dogfood's short text prompts were captured, so only
    // `MessageContent::Text` was truncated. A customer sends multimodal parts,
    // tool results and long agent histories — and `otlp_emit::publish_span` has no
    // payload check, so an over-size span is refused by NATS WHOLE: the customer
    // who opted in to MORE data would lose the trace entirely.

    fn gwy53_on(cap: usize) -> crate::server::config::ContentCapture {
        crate::server::config::ContentCapture {
            input: true,
            output: true,
            max_field_bytes: cap,
        }
    }

    fn gwy53_req(messages: Vec<tracelane_shared::model::Message>) -> tracelane_shared::ChatRequest {
        tracelane_shared::ChatRequest {
            top_p: None,
            seed: None,
            logprobs: None,
            top_logprobs: None,
            model: "gpt-4o".to_owned(),
            messages,
            tools: None,
            tool_choice: None,
            max_tokens: None,
            temperature: None,
            stream: None,
            system: None,
            metadata: None,
        }
    }

    fn gwy53_msg(
        content: tracelane_shared::model::MessageContent,
    ) -> tracelane_shared::model::Message {
        tracelane_shared::model::Message {
            role: tracelane_shared::model::Role::User,
            content,
            tool_call_id: None,
            tool_calls: None,
        }
    }

    // Security review 2026-09-28 (H-1 / H-2): the stored copy is redacted on EVERY plan,
    // not only when the R2 rail is entitled and not only on the chat route — an owner who
    // consented to capture did not consent to storing their own users' secrets.
    // AWS's own documented example key — accepted by `.gitleaks.toml`, never a real credential.
    const GWY53_SECRET: &str = "AKIAIOSFODNN7EXAMPLE";

    #[test]
    fn gwy53_stored_input_is_redacted_on_every_plan_not_only_under_r2() {
        use tracelane_shared::model::{ContentPart, MessageContent};
        let mut req = gwy53_req(vec![
            gwy53_msg(MessageContent::Text(format!(
                "my aws key is {GWY53_SECRET}"
            ))),
            gwy53_msg(MessageContent::Parts(vec![ContentPart::ToolResult {
                tool_use_id: "t1".into(),
                content: format!("found {GWY53_SECRET}"),
                cache_control: None,
            }])),
        ]);
        req.system = Some(format!("system {GWY53_SECRET}"));
        let mut attrs = tracelane_shared::SpanAttributes::default();
        CapturedInput::build(gwy53_on(4096), &req)
            .expect("capture on")
            .apply(&mut attrs);
        let stored = format!(
            "{}{}",
            attrs.gen_ai_input_messages.expect("messages"),
            attrs.gen_ai_system_instructions.expect("system")
        );
        assert!(
            !stored.contains(GWY53_SECRET),
            "a secret was stored: {stored}"
        );
        assert!(stored.contains("[REDACTED:aws_key]"), "{stored}");
    }

    #[test]
    fn gwy53_secrets_inside_tool_call_json_are_redacted_even_under_the_cap() {
        use tracelane_shared::model::{ContentPart, MessageContent};
        let req = gwy53_req(vec![gwy53_msg(MessageContent::Parts(vec![
            ContentPart::ToolUse {
                id: "t2".into(),
                name: "deploy".into(),
                input: serde_json::json!({ "creds": { "aws": GWY53_SECRET } }),
            },
        ]))]);
        let mut attrs = tracelane_shared::SpanAttributes::default();
        CapturedInput::build(gwy53_on(4096), &req)
            .expect("capture on")
            .apply(&mut attrs);
        let stored = attrs.gen_ai_input_messages.expect("messages").to_string();
        assert!(!stored.contains(GWY53_SECRET), "{stored}");
    }

    #[test]
    fn gwy53_stored_output_and_tool_arguments_are_redacted() {
        let out = CapturedOutput::build(
            gwy53_on(4096),
            &format!("here it is: {GWY53_SECRET}"),
            &[(
                Some("c1".into()),
                Some("f".into()),
                format!("{{\"k\":\"{GWY53_SECRET}\"}}"),
            )],
        )
        .expect("capture on");
        let mut attrs = tracelane_shared::SpanAttributes::default();
        out.apply(&mut attrs);
        let stored = attrs.gen_ai_output_messages.expect("output").to_string();
        assert!(!stored.contains(GWY53_SECRET), "{stored}");
        assert!(stored.contains("[REDACTED:aws_key]"), "{stored}");
    }

    // Security review 2026-09-28 (M-1): one message with many parts was bounded only
    // per string, so it could still outgrow the NATS payload and lose the span whole.
    #[test]
    fn gwy53_one_message_with_many_parts_is_bounded_and_says_what_it_dropped() {
        use tracelane_shared::model::{ContentPart, MessageContent};
        let cap = 1024;
        let parts: Vec<ContentPart> = (0..40)
            .map(|i| ContentPart::Text {
                text: format!("part-{i:02}-{}", "y".repeat(2_000)),
                cache_control: None,
            })
            .collect();
        let req = gwy53_req(vec![gwy53_msg(MessageContent::Parts(parts))]);
        let mut attrs = tracelane_shared::SpanAttributes::default();
        CapturedInput::build(gwy53_on(cap), &req)
            .expect("capture on")
            .apply(&mut attrs);
        let stored = attrs.gen_ai_input_messages.expect("messages").to_string();
        assert!(
            stored.len() <= MESSAGE_BYTES_MULTIPLE * cap + 512,
            "one message must stay within the per-message bound — got {} bytes",
            stored.len()
        );
        assert!(stored.contains("part-39-"), "the newest part is kept");
        assert!(
            stored.contains("earlier parts omitted"),
            "{}",
            &stored[..200]
        );
    }

    #[test]
    fn gwy53_every_string_in_a_multimodal_message_is_capped_and_image_bytes_are_not_kept() {
        use tracelane_shared::model::{ContentPart, ImageUrl, MessageContent};
        let cap = 1024;
        let big = "x".repeat(5_000);
        let image = format!("data:image/png;base64,{}", "A".repeat(200_000));
        let req = gwy53_req(vec![gwy53_msg(MessageContent::Parts(vec![
            ContentPart::Text {
                text: big.clone(),
                cache_control: None,
            },
            ContentPart::ImageUrl {
                image_url: ImageUrl {
                    url: image,
                    detail: None,
                },
            },
            ContentPart::ToolResult {
                tool_use_id: "t1".into(),
                content: big.clone(),
                cache_control: None,
            },
            ContentPart::ToolUse {
                id: "t2".into(),
                name: "search".into(),
                input: serde_json::json!({ "q": big }),
            },
        ]))]);
        let mut attrs = tracelane_shared::SpanAttributes::default();
        CapturedInput::build(gwy53_on(cap), &req)
            .expect("capture on")
            .apply(&mut attrs);
        let stored = attrs.gen_ai_input_messages.expect("messages").to_string();
        assert!(
            stored.len() < 6 * cap,
            "four parts, each within the cap, plus JSON overhead — got {} bytes",
            stored.len()
        );
        assert!(!stored.contains(&"A".repeat(2_000)), "no image bytes kept");
        assert!(
            stored.contains("data:image/png;base64,"),
            "the media type stays"
        );
        assert!(stored.contains("…[truncated]"), "every cut is marked");
    }

    #[test]
    fn gwy53_a_long_history_keeps_the_newest_messages_within_one_field_cap() {
        use tracelane_shared::model::MessageContent;
        let cap = 4_096;
        let mut msgs: Vec<_> = (0..40)
            .map(|i| {
                gwy53_msg(MessageContent::Text(format!(
                    "turn {i:02} {}",
                    "y".repeat(1_000)
                )))
            })
            .collect();
        msgs.push(gwy53_msg(MessageContent::Text(
            "the newest question".into(),
        )));
        let mut attrs = tracelane_shared::SpanAttributes::default();
        CapturedInput::build(gwy53_on(cap), &gwy53_req(msgs))
            .expect("capture on")
            .apply(&mut attrs);
        let stored = attrs.gen_ai_input_messages.expect("messages");
        let len = stored.to_string().len();
        assert!(
            len <= cap,
            "the whole field is bounded by the cap, got {len}"
        );
        let kept = stored.as_array().expect("array");
        assert_eq!(
            kept.last().and_then(|m| m["content"].as_str()),
            Some("the newest question"),
            "the NEWEST turn is always kept"
        );
        assert!(kept.len() < 41);
        // Still the consumer's shape: `prompt_eval.rs` deserializes Vec<Message>.
        let _: Vec<tracelane_shared::model::Message> =
            serde_json::from_value(stored.clone()).expect("still Vec<Message>");
        assert_eq!(
            attrs.extra.get("tracelane_input_messages_omitted"),
            Some(&serde_json::json!(41 - kept.len())),
            "what was left out is COUNTED, never silent"
        );
    }

    // ── GWY-48 / OBS-52 / OBS-53 ────────────────────────────────────────────

    /// A `ChatRequest` with every GWY-48-relevant field set. Built as a helper so
    /// each test below varies ONE thing.
    fn cfg_request() -> tracelane_shared::ChatRequest {
        tracelane_shared::ChatRequest {
            model: "gpt-4o".to_owned(),
            messages: vec![tracelane_shared::model::Message {
                role: tracelane_shared::model::Role::User,
                content: tracelane_shared::model::MessageContent::Text("hi".to_owned()),
                tool_call_id: None,
                tool_calls: None,
            }],
            tools: None,
            tool_choice: None,
            max_tokens: None,
            temperature: None,
            top_p: None,
            seed: None,
            logprobs: None,
            top_logprobs: None,
            stream: None,
            system: None,
            metadata: None,
        }
    }

    fn tool(name: &str, description: &str) -> tracelane_shared::model::Tool {
        tracelane_shared::model::Tool {
            name: name.to_owned(),
            description: Some(description.to_owned()),
            input_schema: serde_json::json!({"type": "object", "properties": {}}),
        }
    }

    /// PROOF 1 in unit form: every field the client sent reaches the span, with
    /// the value it was sent with.
    #[test]
    fn every_request_config_field_lands_on_the_span() {
        let mut req = cfg_request();
        req.temperature = Some(0.7);
        req.top_p = Some(0.9);
        req.max_tokens = Some(512);
        req.seed = Some(42);
        req.tool_choice = Some(tracelane_shared::model::ToolChoice::Required);
        req.tools = Some(vec![tool("get_weather", "look up the weather")]);

        let mut attrs = tracelane_shared::SpanAttributes::default();
        RequestConfig::build(&req).apply(&mut attrs);

        assert_eq!(attrs.gen_ai_request_temperature, Some(0.7));
        assert_eq!(attrs.gen_ai_request_top_p, Some(0.9));
        assert_eq!(attrs.gen_ai_request_max_tokens, Some(512));
        assert_eq!(attrs.gen_ai_request_seed, Some(42));
        assert_eq!(
            attrs.tracelane_request_tool_choice_mode.as_deref(),
            Some("required")
        );
        assert_eq!(attrs.tracelane_request_tool_count, Some(1));
        assert_eq!(
            attrs.tracelane_request_tool_names.as_deref(),
            Some(["get_weather".to_owned()].as_slice())
        );
        assert_eq!(
            attrs
                .tracelane_request_tool_definitions_hash
                .as_deref()
                .map(str::len),
            Some(64),
            "the tool-set hash must be 64 hex chars"
        );
    }

    /// **THE ZERO-VS-UNKNOWN PROOF.** A request that sent nothing must land NO
    /// attributes — not `0.0`, not `0`, not `""`. `0.0` is a legal temperature
    /// and `0` a legal tool count, so a default substituted for an absence is
    /// indistinguishable from a real value the customer chose.
    ///
    /// Asserted on the SERIALIZED JSON, not the struct: `skip_serializing_if` is
    /// what actually keeps the key out of ClickHouse, and a struct-level
    /// assertion would pass even if that attribute were dropped.
    #[test]
    fn a_request_with_no_config_lands_no_attributes_not_zeros() {
        let mut attrs = tracelane_shared::SpanAttributes::default();
        RequestConfig::build(&cfg_request()).apply(&mut attrs);

        let json = serde_json::to_string(&attrs).expect("attributes serialise");
        for key in [
            "gen_ai_request_temperature",
            "gen_ai_request_top_p",
            "gen_ai_request_max_tokens",
            "gen_ai_request_seed",
            "tracelane_request_tool_choice_mode",
            "tracelane_request_tool_count",
            "tracelane_request_tool_names",
            "tracelane_request_tool_definitions_hash",
            "tracelane_request_deployment_id",
            "tracelane_misconfig_flags",
        ] {
            assert!(
                !json.contains(key),
                "`{key}` must be ABSENT when the client sent nothing — got {json}"
            );
        }
    }

    /// **THE CONTENT-SAFETY PROOF.** A tool's description and schema must never
    /// reach the span; only its name and a one-way digest. Asserted on the
    /// serialized attributes, because that is the byte sequence ingest writes.
    #[test]
    fn tool_capture_records_names_and_a_hash_but_never_a_schema_body() {
        const SENTINEL: &str = "SENTINEL-do-not-store-this-description";
        let mut req = cfg_request();
        req.tools = Some(vec![tracelane_shared::model::Tool {
            name: "lookup".to_owned(),
            description: Some(SENTINEL.to_owned()),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {"secret_field_name": {"type": "string"}}
            }),
        }]);

        let mut attrs = tracelane_shared::SpanAttributes::default();
        RequestConfig::build(&req).apply(&mut attrs);
        let json = serde_json::to_string(&attrs).expect("attributes serialise");

        assert!(
            !json.contains(SENTINEL),
            "a tool DESCRIPTION must never reach the span"
        );
        assert!(
            !json.contains("secret_field_name"),
            "a tool SCHEMA must never reach the span"
        );
        assert!(json.contains("lookup"), "the tool NAME is captured");
        assert!(
            json.contains("tracelane_request_tool_definitions_hash"),
            "the hash is present even though the text is not"
        );
    }

    /// PROOF 4 in unit form: the span's hash is derived from R3's OWN `def_hash`,
    /// sorted — so a customer can join a span to `observed_tools.def_hash`. If
    /// this ever computes a second, private hash, the join silently returns
    /// nothing and nobody finds out.
    #[test]
    fn the_tool_set_hash_equals_blake3_of_the_sorted_per_tool_def_hashes() {
        let a = tool("alpha", "first");
        let b = tool("beta", "second");
        let mut req = cfg_request();
        req.tools = Some(vec![a.clone(), b.clone()]);

        let mut attrs = tracelane_shared::SpanAttributes::default();
        RequestConfig::build(&req).apply(&mut attrs);

        let mut per_tool: Vec<String> = [&a, &b]
            .iter()
            .map(|t| {
                crate::guardrail::capability::def_hash(
                    &t.name,
                    &t.input_schema,
                    t.description.as_deref().unwrap_or(""),
                )
                .to_hex()
                .to_string()
            })
            .collect();
        per_tool.sort_unstable();
        let mut h = blake3::Hasher::new();
        for d in &per_tool {
            h.update(&(d.len() as u64).to_be_bytes());
            h.update(d.as_bytes());
        }
        assert_eq!(
            attrs.tracelane_request_tool_definitions_hash,
            Some(h.finalize().to_hex().to_string())
        );

        // ORDER-INDEPENDENT: the identity captured is "which definitions", not
        // "in what order the client listed them".
        let mut swapped = cfg_request();
        swapped.tools = Some(vec![b, a]);
        let mut attrs2 = tracelane_shared::SpanAttributes::default();
        RequestConfig::build(&swapped).apply(&mut attrs2);
        assert_eq!(
            attrs.tracelane_request_tool_definitions_hash,
            attrs2.tracelane_request_tool_definitions_hash
        );
    }

    /// The cap discloses itself: the NAME list is cut at 32, the COUNT stays
    /// true, so `count > names.len()` is machine-checkable.
    #[test]
    fn a_tool_name_over_64_bytes_is_truncated_with_the_marker_and_the_count_stays_true() {
        let long = "x".repeat(200);
        let mut tools: Vec<tracelane_shared::model::Tool> = vec![tool(&long, "d")];
        for i in 0..40 {
            tools.push(tool(&format!("t{i}"), "d"));
        }
        let mut req = cfg_request();
        req.tools = Some(tools);

        let mut attrs = tracelane_shared::SpanAttributes::default();
        RequestConfig::build(&req).apply(&mut attrs);

        let names = attrs
            .tracelane_request_tool_names
            .as_ref()
            .expect("names present");
        assert_eq!(names.len(), 32, "the name list is capped at 32");
        assert_eq!(
            attrs.tracelane_request_tool_count,
            Some(41),
            "the COUNT is the TRUE count, which is what makes the cut visible"
        );
        assert!(names[0].ends_with("…[truncated]"), "got {}", names[0]);
        assert!(
            names[0].len() <= 64,
            "the post-condition is <= 64 BYTES, got {}",
            names[0].len()
        );
    }

    /// An explicitly EMPTY `tools: []` is a different fact from no `tools` key,
    /// and the span must be able to tell them apart.
    #[test]
    fn an_empty_tools_array_is_a_count_of_zero_not_an_absence() {
        let mut req = cfg_request();
        req.tools = Some(vec![]);
        let mut attrs = tracelane_shared::SpanAttributes::default();
        RequestConfig::build(&req).apply(&mut attrs);
        assert_eq!(attrs.tracelane_request_tool_count, Some(0));
        assert_eq!(attrs.tracelane_request_tool_names, None);
        assert_eq!(attrs.tracelane_request_tool_definitions_hash, None);
    }

    /// The deployment identity is derived from the model string, delegating the
    /// PROVIDER decision to the one canonical map, and is `None` — never `""` — when
    /// the model carries no deployment.
    #[test]
    fn deployment_identity_is_some_only_for_a_real_deployment() {
        assert_eq!(
            deployment_identity("azure/prod-gpt4o"),
            Some("prod-gpt4o".to_owned())
        );
        assert_eq!(
            deployment_identity("bedrock/arn:aws:bedrock:us-east-1:1:model/x"),
            Some("arn:aws:bedrock:us-east-1:1:model/x".to_owned())
        );
        // Plain models on a routable provider: no deployment identity.
        assert_eq!(deployment_identity("gpt-4o"), None);
        assert_eq!(deployment_identity("claude-sonnet-4-5"), None);
        assert_eq!(deployment_identity("bedrock/anthropic.claude-v2"), None);
        assert_eq!(
            deployment_identity("azure/"),
            None,
            "an empty name is not an id"
        );
    }

    /// **THE FINDING, PINNED SO IT CANNOT BE QUIETLY "FIXED" BACK.** The spec listed
    /// an OpenAI fine-tune (`ft:…`) and a BARE Bedrock ARN as deployment shapes to
    /// capture. Neither can reach a span: `provider_id_for_model` returns `None` for
    /// both — no native prefix matches and no catalog row starts that way — so the
    /// gateway refuses them with `unroutable_model` before any span is written.
    ///
    /// Handling them in `deployment_identity` would be dead code that reads as
    /// coverage. If this assertion ever fails, the ROUTING changed and the
    /// deployment-identity arm should be added back in the same change — not before.
    #[test]
    fn an_openai_fine_tune_and_a_bare_arn_do_not_route_so_they_have_no_span() {
        for model in [
            "ft:gpt-4o-2024-08-06:acme::9xYz",
            "arn:aws:bedrock:us-east-1:1:model/x",
        ] {
            assert_eq!(
                crate::providers::ProviderRegistry::provider_id_for_model(model),
                None,
                "`{model}` is expected to be unroutable — if it now routes, \
                 `deployment_identity` needs an arm for it"
            );
            assert_eq!(deployment_identity(model), None);
        }
    }

    /// **THE CROSS-PATH PARITY PROOF, unit half.** Streaming and buffered spans
    /// go through the SAME `apply`, so the way they can diverge is a field added
    /// to `RequestConfig` and forgotten in `apply` — which would be invisible to
    /// every other test here, because each one asserts the fields it knows about.
    ///
    /// This pins the whole set. The OTHER half — that all four span sites
    /// actually CALL it — is not expressible in a unit test and is held by
    /// `scripts/ci/check-request-config-span-sites.py` plus the prod proof.
    #[test]
    fn apply_writes_every_field_the_config_holds() {
        let mut req = cfg_request();
        req.model = "azure/prod-gpt4o".to_owned();
        req.temperature = Some(1.9);
        req.top_p = Some(0.9);
        req.max_tokens = Some(10);
        req.seed = Some(3);
        req.tool_choice = Some(tracelane_shared::model::ToolChoice::Function {
            name: "pick_me".to_owned(),
        });
        req.tools = Some(vec![tool("pick_me", "d")]);

        let mut cfg = RequestConfig::build(&req);
        cfg.misconfig_flags = Some(vec!["temperature_out_of_range".to_owned()]);

        let mut attrs = tracelane_shared::SpanAttributes::default();
        cfg.apply(&mut attrs);
        let json = serde_json::to_string(&attrs).expect("serialises");

        for key in [
            "gen_ai_request_temperature",
            "gen_ai_request_top_p",
            "gen_ai_request_max_tokens",
            "gen_ai_request_seed",
            "tracelane_request_tool_choice_mode",
            "tracelane_request_tool_choice_function",
            "tracelane_request_tool_count",
            "tracelane_request_tool_names",
            "tracelane_request_tool_definitions_hash",
            "tracelane_request_deployment_id",
            "tracelane_misconfig_flags",
        ] {
            assert!(json.contains(key), "`{key}` never reached the span: {json}");
        }
        assert_eq!(
            attrs.tracelane_request_deployment_id.as_deref(),
            Some("prod-gpt4o")
        );
        assert_eq!(
            attrs.tracelane_request_tool_choice_function.as_deref(),
            Some("pick_me")
        );
    }

    /// **OBS-52's most important property.** With no `model_policy:` installed —
    /// which is every deployment until an operator writes one — no flag is ever
    /// written, and in particular `missing_max_tokens` does NOT fire on a request
    /// that simply did not send one.
    #[test]
    fn misconfig_flags_are_absent_on_a_span_with_no_request_config() {
        let mut attrs = tracelane_shared::SpanAttributes::default();
        RequestConfig::build(&cfg_request())
            .with_policy_flags()
            .apply(&mut attrs);
        assert_eq!(
            attrs.tracelane_misconfig_flags, None,
            "no policy installed means no verdict at all — never an `ok` one"
        );
    }

    /// The `is_instrumented` guard, tested directly because it is the line that
    /// stops OBS-52 flagging every pre-deploy span and every OTLP span from an
    /// SDK that emits no request config.
    #[test]
    fn missing_max_tokens_needs_evidence_the_span_was_instrumented() {
        // Nothing at all was sent: not instrumented, so no verdict is possible.
        let bare = RequestConfig::build(&cfg_request());
        assert!(!bare.is_instrumented());

        // One other config field present: now an absent `max_tokens` is a real
        // absence rather than an unknown.
        let mut req = cfg_request();
        req.temperature = Some(0.5);
        assert!(RequestConfig::build(&req).is_instrumented());
    }

    /// OBS-53: three numbers, and NOTHING when the provider returned none.
    #[test]
    fn the_logprob_summary_is_absent_unless_tokens_were_seen() {
        let mut attrs = tracelane_shared::SpanAttributes::default();
        LogprobAccumulator::default().apply(&mut attrs);
        let json = serde_json::to_string(&attrs).expect("serialises");
        assert!(
            !json.contains("tracelane_response_logprob"),
            "a zero mean would read as a perfectly confident answer; absent must stay absent"
        );

        let mut acc = LogprobAccumulator::default();
        acc.absorb(&[-0.1, -2.5, -0.4]);
        acc.apply(&mut attrs);
        assert_eq!(attrs.tracelane_response_logprob_token_count, Some(3));
        assert_eq!(attrs.tracelane_response_logprob_min, Some(-2.5));
        let mean = attrs.tracelane_response_logprob_mean.expect("mean present");
        assert!((mean - (-1.0)).abs() < 1e-9, "got {mean}");
    }

    /// The sample cap discloses itself through `token_count`, exactly as the tool
    /// cap does through `tool_count`.
    #[test]
    fn the_logprob_summary_caps_the_token_sample_and_reports_what_it_covered() {
        let mut acc = LogprobAccumulator::default();
        let many = vec![-0.5_f64; 5_000];
        acc.absorb(&many);
        let mut attrs = tracelane_shared::SpanAttributes::default();
        acc.apply(&mut attrs);
        assert_eq!(
            attrs.tracelane_response_logprob_token_count,
            Some(MAX_LOGPROB_TOKENS)
        );
    }

    /// Latency split: gateway_overhead + provider == total, to the µs, with NO
    /// unattributed bucket (the founder's hard rule). Deterministic timestamps.
    #[test]
    fn gateway_overhead_plus_provider_equals_total() {
        let received = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let dispatch = received + chrono::Duration::milliseconds(3); // 3ms gateway pre-work
        let complete = dispatch + chrono::Duration::milliseconds(500); // 500ms provider
        let sent = complete + chrono::Duration::milliseconds(2); // 2ms gateway post-work
        let overhead_us = gateway_overhead_us(received, dispatch, complete, sent).unwrap();
        let total_us = (sent - received).num_microseconds().unwrap() as u32;
        let provider_us = total_us - overhead_us; // the derived provider segment
        assert_eq!(overhead_us, 5_000); // (3ms pre) + (2ms post)
        assert_eq!(provider_us, 500_000); // complete − dispatch
        assert_eq!(overhead_us + provider_us, total_us); // sums to total, exactly
        assert_eq!(total_us, 505_000);
        // A backwards interval (clock skew) never panics — clamps, stays Some/None-safe.
        assert!(gateway_overhead_us(sent, received, complete, dispatch).is_some());
    }

    #[test]
    fn merge_usage_tokens_survives_anthropic_split_usage() {
        // Regression (input-token clobber): Anthropic streams input on
        // `message_start` then final output on `message_delta` (input hardcoded 0).
        // A plain overwrite clobbered input back to 0 — the max merge must keep
        // it. This is the fold assertion tests never had.
        let (mut input, mut output) = (0u32, 0u32);
        merge_usage_tokens(&mut input, &mut output, 42, 0); // message_start
        merge_usage_tokens(&mut input, &mut output, 0, 17); // message_delta
        assert_eq!(
            (input, output),
            (42, 17),
            "message_delta's input=0 must not clobber the real input count"
        );

        // Order-independent (defensive against event reordering).
        let (mut i2, mut o2) = (0u32, 0u32);
        merge_usage_tokens(&mut i2, &mut o2, 0, 17);
        merge_usage_tokens(&mut i2, &mut o2, 42, 0);
        assert_eq!((i2, o2), (42, 17));

        // Single-event providers (OpenAI/Azure/Google/Cohere/Bedrock report both
        // counts in one event) are unaffected — one merge yields both.
        let (mut i3, mut o3) = (0u32, 0u32);
        merge_usage_tokens(&mut i3, &mut o3, 100, 50);
        assert_eq!((i3, o3), (100, 50));
    }

    // ── B-568 I5: the cold-start attribute ────────────────────────────────

    fn span_with(identity: &CallerIdentity, timing: Option<GatewayTiming>) -> TracelaneSpan {
        build_gateway_span(
            &TenantId::from_jwt_claim(uuid::Uuid::from_u128(7)),
            uuid::Uuid::from_u128(1),
            None,
            "claude-sonnet-4-6",
            identity,
            chrono::Utc::now(),
            1,
            1,
            None,
            SpanUsageMeta::default(),
            None,
            timing,
            None,
            None,
        )
    }

    fn now_timing() -> Option<GatewayTiming> {
        let now = chrono::Utc::now();
        Some(GatewayTiming {
            dispatch_ts: now,
            provider_complete_ts: now,
            ttft_us: None,
        })
    }

    /// `true` and PRESENT on a cold request with a measured overhead; ABSENT on a
    /// warm one (never `Some(false)` — the key's presence IS the fact, which keeps
    /// the warm majority of spans byte-identical to before); ABSENT on a cold
    /// request with no measured overhead, because the dashboard splits the
    /// OVERHEAD population and a flag with no number behind it would count a
    /// sample the quantile never saw.
    #[test]
    fn cold_start_is_present_only_when_true_and_measured() {
        let cold = CallerIdentity {
            cold_start: true,
            ..CallerIdentity::default()
        };
        assert_eq!(
            span_with(&cold, now_timing())
                .attributes
                .tracelane_gateway_cold_start,
            Some(true)
        );
        assert_eq!(
            span_with(&CallerIdentity::default(), now_timing())
                .attributes
                .tracelane_gateway_cold_start,
            None,
            "a warm span must not carry the key at all"
        );
        assert_eq!(
            span_with(&cold, None)
                .attributes
                .tracelane_gateway_cold_start,
            None,
            "no measured overhead ⇒ no cold flag"
        );
        let json = serde_json::to_string(&span_with(&CallerIdentity::default(), now_timing()))
            .expect("serialise");
        assert!(
            !json.contains("tracelane_gateway_cold_start"),
            "absent must mean absent on the wire, not null: {json}"
        );
    }

    // ── B-568 I4: an honest `sent` ────────────────────────────────────────

    /// Restamping `sent` moves `end_time` AND grows the overhead by exactly the
    /// interval the gateway kept the client waiting after the span was built —
    /// so `overhead + provider == total` still holds to the microsecond.
    #[test]
    fn restamp_sent_moves_end_time_and_charges_the_gap_to_overhead() {
        let received = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let dispatch = received + chrono::Duration::milliseconds(3);
        let complete = dispatch + chrono::Duration::milliseconds(500);
        let built = complete + chrono::Duration::microseconds(40);
        let sent = built + chrono::Duration::milliseconds(7); // response guard etc.
        let mut span = span_with(&CallerIdentity::default(), None);
        span.start_time = received;
        span.end_time = Some(built);
        span.attributes.tracelane_gateway_overhead_us =
            gateway_overhead_us(received, dispatch, complete, built);
        assert_eq!(span.attributes.tracelane_gateway_overhead_us, Some(3_040));

        restamp_sent(&mut span, sent);

        assert_eq!(span.end_time, Some(sent));
        assert_eq!(
            span.attributes.tracelane_gateway_overhead_us,
            gateway_overhead_us(received, dispatch, complete, sent),
            "the restamped number must equal the one computed at `sent`"
        );
        assert_eq!(span.attributes.tracelane_gateway_overhead_us, Some(10_040));
        let total = u32::try_from((sent - received).num_microseconds().unwrap()).unwrap();
        let provider = total - span.attributes.tracelane_gateway_overhead_us.unwrap();
        assert_eq!(provider, 500_000, "the provider segment must not move");
    }

    /// A span with no measured overhead (a dispatch failure) keeps `None` — the
    /// restamp must not invent a number — and a wall clock that stepped BACK
    /// never shortens the span or the overhead.
    #[test]
    fn restamp_sent_never_invents_or_shrinks() {
        let t0 = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let mut span = span_with(&CallerIdentity::default(), None);
        span.start_time = t0;
        span.end_time = Some(t0 + chrono::Duration::milliseconds(10));
        restamp_sent(&mut span, t0 + chrono::Duration::milliseconds(12));
        assert_eq!(span.attributes.tracelane_gateway_overhead_us, None);
        assert_eq!(span.end_time, Some(t0 + chrono::Duration::milliseconds(12)));

        span.attributes.tracelane_gateway_overhead_us = Some(2_000);
        restamp_sent(&mut span, t0 + chrono::Duration::milliseconds(5));
        assert_eq!(span.end_time, Some(t0 + chrono::Duration::milliseconds(12)));
        assert_eq!(span.attributes.tracelane_gateway_overhead_us, Some(2_000));
    }

    // ── RI-05 slices 4-5 ──────────────────────────────────────────────────

    /// M11: `SpanUsageMeta.reasoning_output_tokens` lands on
    /// `gen_ai_usage_reasoning_output_tokens`, and is ABSENT (not `0`) when
    /// nothing was reported.
    #[test]
    fn reasoning_output_tokens_land_on_the_span_and_absence_stays_absent() {
        let tenant = TenantId::from_jwt_claim(uuid::Uuid::from_u128(7));
        let with_reasoning = build_gateway_span(
            &tenant,
            uuid::Uuid::from_u128(1),
            None,
            "gpt-5-thinking",
            &CallerIdentity::default(),
            chrono::Utc::now(),
            10,
            50,
            None,
            SpanUsageMeta {
                reasoning_output_tokens: Some(7),
                ..Default::default()
            },
            None,
            None,
            None,
            None,
        );
        assert_eq!(
            with_reasoning
                .attributes
                .gen_ai_usage_reasoning_output_tokens,
            Some(7)
        );
        // `output_tokens` (the second positional `u32` argument) is UNCHANGED
        // by reasoning — it stays the inclusive total, exactly as before this
        // field existed (`google.rs`'s rule, mirrored at the gateway span).
        assert_eq!(
            with_reasoning.attributes.gen_ai_usage_output_tokens,
            Some(50)
        );

        let without = build_gateway_span(
            &tenant,
            uuid::Uuid::from_u128(2),
            None,
            "claude-sonnet-4-6",
            &CallerIdentity::default(),
            chrono::Utc::now(),
            10,
            50,
            None,
            SpanUsageMeta::default(),
            None,
            None,
            None,
            None,
        );
        assert_eq!(
            without.attributes.gen_ai_usage_reasoning_output_tokens, None,
            "no provider claim ⇒ absent, never a fabricated 0"
        );
    }

    /// M19: `bounded_tool_names` caps count and per-name bytes the SAME way
    /// `RequestConfig` bounds the OFFERED names — one shared function, so the
    /// two populations cannot drift apart.
    #[test]
    fn bounded_tool_names_caps_count_and_bytes_and_drops_empties() {
        // Over MAX_TOOL_NAMES (32): only the first 32 survive.
        let many: Vec<String> = (0..40).map(|i| format!("tool_{i}")).collect();
        let bounded = bounded_tool_names(many.iter().map(String::as_str)).unwrap();
        assert_eq!(bounded.len(), MAX_TOOL_NAMES);
        assert_eq!(bounded[0], "tool_0");

        // Over MAX_TOOL_NAME_BYTES (64): truncated with the visible marker,
        // never silently.
        let long_name = "x".repeat(100);
        let bounded = bounded_tool_names(std::iter::once(long_name.as_str())).unwrap();
        assert!(bounded[0].len() <= MAX_TOOL_NAME_BYTES);
        assert!(bounded[0].ends_with("…[truncated]"));

        // Empty input and an all-empty-string input both yield `None`, never
        // `Some(vec![])` — the same "absent means nothing sent" rule as
        // `tracelane_request_tool_names`.
        assert_eq!(bounded_tool_names(std::iter::empty()), None);
        assert_eq!(bounded_tool_names(std::iter::once("")), None);
    }

    /// M19 — THE GATE-OFF PROOF, the same fail-closed shape
    /// `capture_is_none_when_no_trace_content_block_is_installed` already
    /// proves for `CapturedInput`: with no `trace_content:` block installed
    /// (every deployment today), `CapturedOutput::build` returns `None` even
    /// when tool calls WERE made — the arguments must not leak just because a
    /// tool happened to be involved.
    #[test]
    fn captured_output_is_none_when_no_trace_content_block_is_installed_even_with_tool_calls() {
        let tenant = tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::from_u128(7));
        let calls = vec![(
            Some("call_1".to_owned()),
            Some("get_weather".to_owned()),
            r#"{"city":"Bangalore"}"#.to_owned(),
        )];
        let capture = crate::server::config::capture_decision(None, None, &tenant);
        assert!(
            CapturedOutput::build(capture, "", &calls).is_none(),
            "with no trace_content block installed, capture MUST be off — \
             an absent config is the unprivileged state (.claude/rules/tenancy.md)"
        );
        assert!(
            CapturedOutput::build(capture, "some text", &[]).is_none(),
            "same gate, no tool calls either — unchanged from before RI-05"
        );
        assert!(
            CapturedOutput::build(capture, "", &[]).is_none(),
            "nothing to attach at all"
        );
        // GWY-53: input-only opt-in must not capture OUTPUT.
        let input_only = crate::server::config::capture_decision(
            None,
            Some(crate::db::workspace_capture::WorkspaceCapture {
                input: true,
                output: false,
            }),
            &tenant,
        );
        assert!(
            CapturedOutput::build(input_only, "some text", &calls).is_none(),
            "an input-only opt-in must never record the response"
        );
    }

    /// M19 — THE GATE-ON SHAPE, proven against a REAL, YAML-parsed
    /// `TraceContentConfig` rather than the process-global `CONFIG` slot,
    /// which is write-once for the whole test binary
    /// (`config::install_for_test`'s doc: "Returns `false` if a config was
    /// already installed"; `embeddings.rs`'s alias test already claims that
    /// one slot). `CapturedOutput::from_config` is the gate decision split
    /// from the shape-building for exactly this reason.
    #[test]
    fn captured_output_from_config_carries_tool_call_parts_truncated_at_the_cap() {
        // The parser's own floor is 1024 bytes — small enough to force
        // truncation with a short fixture string.
        let parsed = crate::server::config::parse(
            "trace_content:\n  tenants: a4037bef-e786-44e3-bfb6-88c93ba9d381\n  max_field_bytes: 1024\n",
        )
        .expect("a well-formed trace_content block must parse");
        let cfg = parsed.trace_content().expect("block present");
        assert_eq!(cfg.max_field_bytes(), 1024);

        // A normal-sized call: present, untouched.
        let calls = vec![(
            Some("call_1".to_owned()),
            Some("get_weather".to_owned()),
            r#"{"city":"Bangalore"}"#.to_owned(),
        )];
        let out =
            CapturedOutput::from_config("the weather is sunny", &calls, cfg.max_field_bytes());
        let mut attrs = tracelane_shared::SpanAttributes::default();
        out.apply(&mut attrs);
        let msgs = attrs.gen_ai_output_messages.expect("messages present");
        let msg = &msgs[0];
        assert_eq!(msg["role"], "assistant");
        assert_eq!(msg["content"], "the weather is sunny");
        let tc = &msg["tool_calls"][0];
        assert_eq!(tc["id"], "call_1");
        assert_eq!(tc["name"], "get_weather");
        assert_eq!(tc["input"], r#"{"city":"Bangalore"}"#);

        // An over-cap argument string is truncated WITH the visible marker —
        // the same treatment message text gets, never a second gate.
        let huge_args = format!(r#"{{"city":"{}"}}"#, "x".repeat(2000));
        let calls = vec![(None, Some("lookup".to_owned()), huge_args)];
        let out = CapturedOutput::from_config("", &calls, cfg.max_field_bytes());
        let mut attrs = tracelane_shared::SpanAttributes::default();
        out.apply(&mut attrs);
        let msgs = attrs.gen_ai_output_messages.expect("messages present");
        let tc = &msgs[0]["tool_calls"][0];
        let stored = tc["input"].as_str().expect("arguments stored as a string");
        assert!(
            stored.len() <= cfg.max_field_bytes(),
            "must respect the byte cap: got {} bytes",
            stored.len()
        );
        assert!(
            stored.ends_with("…[truncated]"),
            "a cut argument string must say so, exactly like a cut message"
        );
        // A call with no id is synthesised one from its position, never blank.
        assert_eq!(tc["id"], "call_0");
        // The empty TEXT half still renders as `content: ""` (`MessageContent`
        // is a required field, never `Option`) — the tool call is what makes
        // this message worth attaching at all, and it is present.
        assert_eq!(msgs[0]["role"], "assistant");
        assert_eq!(msgs[0]["content"], "");
    }

    /// M19 — a response with NO text and only a tool call is not silently
    /// suppressed: `CapturedOutput::build` used to early-return on
    /// `text.is_empty()` alone (the pre-RI-05 shape), which would have thrown
    /// away exactly the common case of a tool-only turn.
    #[test]
    fn captured_output_from_config_keeps_tool_calls_when_text_is_empty() {
        let parsed = crate::server::config::parse(
            "trace_content:\n  tenants: a4037bef-e786-44e3-bfb6-88c93ba9d381\n",
        )
        .expect("parses");
        let cfg = parsed.trace_content().expect("block present");
        let calls = vec![(
            Some("call_1".to_owned()),
            Some("get_weather".to_owned()),
            "{}".to_owned(),
        )];
        let out = CapturedOutput::from_config("", &calls, cfg.max_field_bytes());
        let mut attrs = tracelane_shared::SpanAttributes::default();
        out.apply(&mut attrs);
        let msgs = attrs.gen_ai_output_messages.expect("messages present");
        assert_eq!(msgs[0]["tool_calls"][0]["name"], "get_weather");
    }
}

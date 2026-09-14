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
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct SpanUsageMeta {
    pub(crate) cache_read_input_tokens: Option<u32>,
    pub(crate) cache_creation_input_tokens: Option<u32>,
    pub(crate) stream: bool,
    /// Upstream-reported cost in USD; `Some` only when the provider
    /// put a cost on the wire. When `None`, `build_gateway_span` derives the
    /// cost from the model price catalog (`crate::pricing`). Lands as
    /// `gen_ai.usage.cost`.
    pub(crate) cost_usd: Option<f64>,
}

/// GWY-45: the captured request content for one span, already truncated.
///
/// **Built ONLY when the tenant is on the `trace_content:` allowlist.** The gate
/// is a single `OnceLock` read (`config::trace_content()`), evaluated before any
/// allocation, so a non-allowlisted tenant — which is every tenant today — pays
/// one atomic load and nothing else.
///
/// v1 is INPUT ONLY. Output is deliberately absent: the span is published BEFORE
/// the response-side guardrail seam so that a BLOCKED request still produces a
/// span (the #81 span-drop), and the comment at that call site justifies the
/// ordering with "the span carries NO response body". Attaching output there
/// would make that false and would persist exactly the text the seam redacts.
/// `prompt_eval.rs` reads only `gen_ai_input_messages`, so input alone is the
/// whole unblock.
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
}

impl CapturedInput {
    /// Returns `None` unless the tenant is allowlisted — the early return IS the
    /// hot-path guarantee.
    pub(crate) fn build(
        tenant_id: &tracelane_shared::TenantId,
        req: &tracelane_shared::ChatRequest,
    ) -> Option<Self> {
        let cfg = super::config::trace_content()?;
        // B-299: the ONE policy, shared with the judge and dataset export.
        if !super::config::capture_decision(Some(cfg), tenant_id) {
            return None;
        }
        let cap = cfg.max_field_bytes();

        // Truncate DURING construction, not after: serializing a 10 MB prompt and
        // then throwing it away still cost the 10 MB.
        let mut msgs = req.messages.clone();
        for m in &mut msgs {
            if let tracelane_shared::model::MessageContent::Text(t) = &mut m.content {
                truncate_utf8(t, cap);
            }
        }
        let messages = serde_json::to_value(&msgs).ok()?;

        let system = req.system.as_ref().map(|sys| {
            let mut s = sys.clone();
            truncate_utf8(&mut s, cap);
            serde_json::Value::String(s)
        });

        Some(Self { messages, system })
    }

    /// Post-construction mutation, matching the two existing precedents in this
    /// file (the semantic-cache hit at the `tracelane_semantic_cache_*` fields,
    /// and `build_embeddings_span`'s name override). Keeps five other
    /// `build_gateway_span` call sites at a zero-line diff.
    pub(crate) fn apply(self, attrs: &mut tracelane_shared::SpanAttributes) {
        attrs.gen_ai_input_messages = Some(self.messages);
        attrs.gen_ai_system_instructions = self.system;
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
    /// `None` unless the tenant is allowlisted, OR the text is empty (nothing
    /// to attach — a fully content-filtered response, for instance).
    pub(crate) fn build(tenant_id: &tracelane_shared::TenantId, text: &str) -> Option<Self> {
        if text.is_empty() {
            return None;
        }
        let cfg = super::config::trace_content()?;
        if !super::config::capture_decision(Some(cfg), tenant_id) {
            return None;
        }
        let mut t = text.to_string();
        truncate_utf8(&mut t, cfg.max_field_bytes());
        Some(Self {
            messages: output_messages_json(&t),
        })
    }

    pub(crate) fn apply(self, attrs: &mut tracelane_shared::SpanAttributes) {
        attrs.gen_ai_output_messages = Some(self.messages);
    }
}

/// The `gen_ai.output.messages` shape both the buffered path
/// ([`CapturedOutput`]) and the streaming path (`StreamFinalizer`'s ring
/// buffer, `server/stream.rs`) render into — ONE shape, so a consumer reading
/// either path's span sees the same structure OTel's `gen_ai_input_messages`
/// already uses (a single-element message array).
pub(crate) fn output_messages_json(text: &str) -> serde_json::Value {
    serde_json::json!([{ "role": "assistant", "content": text }])
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
            .field("agent_id", &p(&self.agent_id))
            .field("human_authorizer", &p(&self.human_authorizer))
            .field("business_reference", &p(&self.business_reference))
            .field("end_user_id", &p(&self.end_user_id))
            .field("conversation_id", &p(&self.conversation_id))
            .finish()
    }
}

impl CallerIdentity {
    /// Read all five from request headers, bounded, at the trust boundary.
    ///
    /// **Every value is length-bounded and DROPPED rather than truncated above
    /// the cap** — `bounded_end_user_id`'s doc says why: a truncated id is a
    /// *wrong* id, and a wrong id silently attributes one request to another
    /// agent, person or session. Absence is recoverable; misattribution is not.
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
            agent_id: h("x-agent-id"),
            human_authorizer: h("x-human-authorizer"),
            business_reference: headers
                .get("x-business-reference")
                .and_then(|v| v.to_str().ok())
                .and_then(tracelane_shared::span::bounded_business_reference),
            end_user_id: h("x-tracelane-user-id").or_else(|| h("x-user-id")),
            conversation_id: h("x-conversation-id").or_else(|| h("x-session-id")),
        }
    }

    /// `OBS-20`. Fill `end_user_id` from the request BODY when no header supplied
    /// one. Header wins — it is the explicit signal, and the only one a customer
    /// can set without touching a body their SDK owns.
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
}

impl RequestConfig {
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
            gen_ai_request_model: Some(model.to_string()),
            gen_ai_response_model: Some(model.to_string()),
            gen_ai_usage_input_tokens: Some(input_tokens),
            gen_ai_usage_output_tokens: Some(output_tokens),
            gen_ai_usage_cache_read_input_tokens: usage_meta.cache_read_input_tokens,
            gen_ai_usage_cache_creation_input_tokens: usage_meta.cache_creation_input_tokens,
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
            gen_ai_conversation_id: identity.conversation_id.clone(),
            tracelane_aft_id: aft_id.map(str::to_owned),
            tracelane_kya_agent_id: identity.agent_id.clone(),
            tracelane_kya_human_authorizer: identity.human_authorizer.clone(),
            tracelane_business_reference: identity.business_reference.clone(),
            user_id: identity.end_user_id.clone(),
            // Present only when a cross-provider failover served this
            // request. The rollup counts `countIf(tracelane_failover_activated)`;
            // `tracelane_failover_from` names the primary provider that errored.
            tracelane_failover_activated: failover_from.map(|_| true),
            tracelane_failover_from: failover_from.map(str::to_owned),
            // GWY-43: which API key paid for this. `None` for a JWT session.
            tracelane_api_key_id: api_key_id.map(str::to_owned),
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

#[cfg(test)]
mod tests {
    use super::*;

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
            },
            Some("FAILOVERFROM"),
            None,
            Some("ERRORREASON"),
            Some("APIKEY"),
        );
        let a = &span.attributes;
        assert_eq!(a.tracelane_kya_agent_id.as_deref(), Some("AGENT"));
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
        assert!(
            CapturedInput::build(&tenant, &req).is_none(),
            "with no trace_content block installed, capture MUST be off — an              absent config is the unprivileged state (.claude/rules/tenancy.md)"
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
}

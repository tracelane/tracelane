//! `OG-05` §3.4 — the chat → Responses bridge (OpenAI only).
//!
//! Some OpenAI models cannot be served by `/v1/chat/completions`: the
//! Responses-only ones (`gpt-5.5-pro`, `gpt-5.3-codex`, ...), and `gpt-6-astra` /
//! `gpt-6.1-sol` when the request carries tools. The reference list is
//! `crates/gateway/translation_policy.v1.json` (`responses_bridge`), read through
//! [`super::translation_policy::responses_bridge_applies`].
//!
//! This module is the INVERSE of `OG-01`'s mode T (`openai_responses.rs`, which
//! turns a Responses request into a `ChatRequest`):
//!
//! * [`build_body`] — `ChatRequest` → the Responses request body (pure);
//! * [`FrameState::events_for_frame`] — one Responses SSE frame → the gateway's
//!   own [`ProviderEvent`]s (pure), so everything downstream — the SSE chunk
//!   emitter, the buffered fold, guardrails, the breaker, failover, spans — is
//!   the code path every other provider already takes. The bridge lives inside
//!   `OpenAiProvider::chat`, which is why none of those can differ.
//!
//! Framing and usage reuse `OG-01`'s parsers (`split_sse_frame`, `sse_frame_data`,
//! `responses_usage`) rather than re-deriving them.
//!
//! **Fail direction: CLOSED.** A field the Responses wire cannot honour (`stop`,
//! `seed`, repetition penalties, logprobs, unmodelled top-level fields, audio and
//! file parts) is refused up front by [`check`] — the same `400
//! unsupported_parameter` / `unsupported_content` every other adapter gives —
//! and [`build_body`] errors on them again as defence in depth. A stream that
//! ends without `response.completed` is an error, never a silently short answer.
//!
//! **`store: false` is always sent.** The Responses API stores responses by
//! default; Chat Completions does not. A bridged request must not start
//! retaining a customer's prompt at the provider that the equivalent chat
//! request would not have.

use std::collections::{HashMap, HashSet};

use anyhow::{Context as _, Result, anyhow, bail};
use serde_json::{Value, json};
use tracelane_shared::{ChatRequest, ContentPart, MessageContent, Role, ToolChoice};

use crate::providers::{FinishReason, ProviderEvent};

/// The span attribute value (`tracelane.bridge`) for a bridged request.
pub(crate) const BRIDGE_NAME: &str = "chat_to_responses";

/// Largest single SSE frame accepted from the upstream. A frame that never
/// terminates would otherwise grow the buffer without bound.
const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Does this request, for this provider, take the bridge?
#[must_use]
pub(crate) fn applies(provider_id: &str, req: &ChatRequest) -> bool {
    provider_id == "openai"
        && super::translation_policy::responses_bridge_applies(
            &req.model,
            req.tools.as_ref().is_some_and(|t| !t.is_empty()),
        )
}

/// What the Responses wire cannot honour, as `(param, why)`. `None` = bridgeable.
/// The first offender wins, in a fixed order, so the 400 is deterministic.
#[must_use]
pub(crate) fn first_unsupported(req: &ChatRequest) -> Option<(String, &'static str)> {
    let no = |p: &str, why: &'static str| Some((p.to_owned(), why));
    if req.stop.is_some() {
        return no("stop", "the Responses API has no stop sequences");
    }
    if req.seed.is_some() {
        return no("seed", "the Responses API has no seed");
    }
    if req.presence_penalty.is_some_and(|v| v != 0.0) {
        return no(
            "presence_penalty",
            "the Responses API has no repetition penalties",
        );
    }
    if req.frequency_penalty.is_some_and(|v| v != 0.0) {
        return no(
            "frequency_penalty",
            "the Responses API has no repetition penalties",
        );
    }
    if req.logprobs == Some(true) || req.top_logprobs.is_some() {
        return no(
            "logprobs",
            "the Responses API does not return logprobs here",
        );
    }
    if req.n.is_some_and(|n| n > 1) {
        return no("n", "the Responses API returns one completion");
    }
    if let Some(k) = req.extra.keys().min() {
        return Some((
            k.clone(),
            "unmodelled top-level fields are not forwarded to the Responses API",
        ));
    }
    None
}

/// A part the Responses `input` cannot carry, as `(message index, part index)`.
#[must_use]
pub(crate) fn first_unsupported_part(req: &ChatRequest) -> Option<(usize, usize)> {
    for (mi, m) in req.messages.iter().enumerate() {
        if let MessageContent::Parts(parts) = &m.content {
            for (pi, p) in parts.iter().enumerate() {
                if matches!(p, ContentPart::InputAudio { .. } | ContentPart::File { .. }) {
                    return Some((mi, pi));
                }
            }
        }
    }
    None
}

fn text_of(content: &MessageContent) -> String {
    match content {
        MessageContent::Text(t) => t.clone(),
        MessageContent::Parts(parts) => parts
            .iter()
            .filter_map(|p| match p {
                ContentPart::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

/// Translate the caller's chat request into a Responses request body.
///
/// # Errors
/// Fails CLOSED on anything the Responses wire cannot carry
/// ([`first_unsupported`], [`first_unsupported_part`]) and on a tool-role message
/// with no `tool_call_id`. `check_supported` refuses the first two before
/// dispatch; this is the second line.
pub(crate) fn build_body(req: &ChatRequest) -> Result<Value> {
    if let Some((param, why)) = first_unsupported(req) {
        bail!("`{param}` cannot be bridged to the Responses API: {why}");
    }
    if let Some((mi, pi)) = first_unsupported_part(req) {
        bail!("messages[{mi}].content[{pi}] cannot be bridged to the Responses API");
    }

    let mut input: Vec<Value> = Vec::new();
    for m in &req.messages {
        match &m.role {
            Role::Tool => {
                let call_id = m
                    .tool_call_id
                    .as_deref()
                    .context("a tool message carries no tool_call_id")?;
                input.push(json!({
                    "type": "function_call_output",
                    "call_id": call_id,
                    "output": text_of(&m.content),
                }));
            }
            role => {
                let assistant = *role == Role::Assistant;
                let role_name = match role {
                    Role::System => "system",
                    Role::User => "user",
                    _ => "assistant",
                };
                let mut content: Vec<Value> = Vec::new();
                let mut after: Vec<Value> = Vec::new();
                match &m.content {
                    MessageContent::Text(t) => {
                        if !t.is_empty() {
                            content.push(text_part(assistant, t));
                        }
                    }
                    MessageContent::Parts(parts) => {
                        for p in parts {
                            match p {
                                ContentPart::Text { text, .. } => {
                                    content.push(text_part(assistant, text));
                                }
                                ContentPart::ImageUrl { image_url } => {
                                    let mut img = json!({
                                        "type": "input_image",
                                        "image_url": image_url.url,
                                    });
                                    if let Some(d) = &image_url.detail {
                                        img["detail"] = json!(d);
                                    }
                                    content.push(img);
                                }
                                ContentPart::ToolUse { id, name, input } => {
                                    after.push(function_call(id, name, input));
                                }
                                ContentPart::ToolResult {
                                    tool_use_id,
                                    content: out,
                                    ..
                                } => after.push(json!({
                                    "type": "function_call_output",
                                    "call_id": tool_use_id,
                                    "output": out,
                                })),
                                // Refused above; unreachable, kept exhaustive.
                                ContentPart::InputAudio { .. } | ContentPart::File { .. } => {}
                            }
                        }
                    }
                }
                if !content.is_empty() {
                    input.push(json!({ "type": "message", "role": role_name, "content": content }));
                }
                input.extend(after);
                for tc in m.tool_calls.iter().flatten() {
                    input.push(function_call(&tc.id, &tc.name, &tc.input));
                }
            }
        }
    }

    let mut body = serde_json::Map::new();
    body.insert("model".into(), json!(model_name(&req.model)));
    body.insert("input".into(), Value::Array(input));
    body.insert("stream".into(), json!(true));
    // See the module doc: chat completions do not retain; neither may the bridge.
    body.insert("store".into(), json!(false));
    if let Some(s) = req.system.as_deref().filter(|s| !s.is_empty()) {
        body.insert("instructions".into(), json!(s));
    }
    if let Some(tools) = req.tools.as_ref().filter(|t| !t.is_empty()) {
        let list: Vec<Value> = tools
            .iter()
            .map(|t| {
                let mut o = json!({
                    "type": "function",
                    "name": t.name,
                    "parameters": t.input_schema,
                });
                if let Some(d) = &t.description {
                    o["description"] = json!(d);
                }
                o
            })
            .collect();
        body.insert("tools".into(), Value::Array(list));
    }
    if let Some(tc) = &req.tool_choice {
        body.insert(
            "tool_choice".into(),
            match tc {
                ToolChoice::Auto => json!("auto"),
                ToolChoice::None => json!("none"),
                ToolChoice::Required => json!("required"),
                ToolChoice::Function { name } => json!({ "type": "function", "name": name }),
            },
        );
    }
    if let Some(n) = req.max_completion_tokens.or(req.max_tokens) {
        body.insert("max_output_tokens".into(), json!(n));
    }
    if let Some(v) = req.temperature {
        body.insert("temperature".into(), json!(v));
    }
    if let Some(v) = req.top_p {
        body.insert("top_p".into(), json!(v));
    }
    if let Some(e) = &req.reasoning_effort {
        body.insert("reasoning".into(), json!({ "effort": e }));
    }
    if let Some(fmt) = req.response_format.as_ref().and_then(text_format) {
        body.insert("text".into(), json!({ "format": fmt }));
    }
    if let Some(v) = req.parallel_tool_calls {
        body.insert("parallel_tool_calls".into(), json!(v));
    }
    if let Some(u) = &req.user {
        body.insert("user".into(), json!(u));
    }
    if let Some(t) = &req.service_tier {
        body.insert("service_tier".into(), json!(t));
    }
    Ok(Value::Object(body))
}

fn model_name(model: &str) -> &str {
    model.strip_prefix("openai/").unwrap_or(model)
}

fn text_part(assistant: bool, text: &str) -> Value {
    json!({ "type": if assistant { "output_text" } else { "input_text" }, "text": text })
}

fn function_call(id: &str, name: &str, input: &Value) -> Value {
    json!({
        "type": "function_call",
        "call_id": id,
        "name": name,
        "arguments": input.to_string(),
    })
}

/// Chat `response_format` → Responses `text.format`. The chat `json_schema` form
/// nests `{name, schema, strict}` under `json_schema`; Responses flattens it.
fn text_format(rf: &Value) -> Option<Value> {
    match rf.get("type").and_then(Value::as_str)? {
        "json_schema" => {
            let js = rf.get("json_schema")?;
            let mut o = json!({
                "type": "json_schema",
                "name": js.get("name").cloned().unwrap_or_else(|| json!("response")),
                "schema": js.get("schema").cloned().unwrap_or_else(|| json!({})),
            });
            if let Some(s) = js.get("strict") {
                o["strict"] = s.clone();
            }
            Some(o)
        }
        "json_object" => Some(json!({ "type": "json_object" })),
        "text" => Some(json!({ "type": "text" })),
        _ => None,
    }
}

/// What a stream of Responses frames has told us so far.
#[derive(Debug, Default)]
pub(crate) struct FrameState {
    meta_sent: bool,
    /// Responses `output_index` -> chat tool-call index (0, 1, ... in order).
    tool_index: HashMap<u64, usize>,
    /// `output_index`es whose arguments arrived as deltas.
    args_streamed: HashSet<u64>,
    saw_tool_call: bool,
    /// A terminal frame (`response.completed` / `.incomplete`) was seen.
    pub(crate) finished: bool,
}

fn safe_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

impl FrameState {
    fn tool_slot(&mut self, output_index: u64) -> (usize, bool) {
        if let Some(i) = self.tool_index.get(&output_index) {
            return (*i, false);
        }
        let i = self.tool_index.len();
        self.tool_index.insert(output_index, i);
        self.saw_tool_call = true;
        (i, true)
    }

    fn terminal(&mut self, resp: &Value, incomplete: bool) -> Vec<ProviderEvent> {
        self.finished = true;
        let reason = if incomplete {
            match resp
                .pointer("/incomplete_details/reason")
                .and_then(Value::as_str)
            {
                Some("content_filter") => FinishReason::ContentFilter,
                _ => FinishReason::Length,
            }
        } else if self.saw_tool_call {
            FinishReason::ToolCalls
        } else {
            FinishReason::Stop
        };
        let mut out = vec![ProviderEvent::Finish { reason }];
        if let Some(u) = resp.get("usage").filter(|u| !u.is_null()) {
            let acc = crate::openai_responses::responses_usage(u);
            out.push(ProviderEvent::UsageUpdate {
                input_tokens: acc.input,
                output_tokens: acc.output,
                // `input_tokens` is INCLUSIVE of the cached prefix, exactly as the
                // chat adapter records it; reporting a cache counter too would
                // double-count it in `pricing::cost_usd`.
                cache_read: None,
                cache_creation: None,
                cost_usd: None,
                reasoning: acc.reasoning,
            });
        }
        out
    }

    /// One Responses SSE `data:` payload -> zero or more provider events.
    ///
    /// # Errors
    /// `response.failed` / `error` frames, and a payload that is not JSON. The
    /// message carries only the upstream's own SAFE error token, never its text.
    pub(crate) fn events_for_frame(&mut self, data: &str) -> Result<Vec<ProviderEvent>> {
        let v: Value = serde_json::from_str(data).context("invalid Responses SSE JSON")?;
        let ty = v.get("type").and_then(Value::as_str).unwrap_or_default();
        let out_idx = v.get("output_index").and_then(Value::as_u64).unwrap_or(0);
        let mut out = Vec::new();
        match ty {
            "response.created" | "response.in_progress" => {
                let r = v.get("response").unwrap_or(&Value::Null);
                let id = r.get("id").and_then(Value::as_str).map(str::to_owned);
                let model = r.get("model").and_then(Value::as_str).map(str::to_owned);
                if !self.meta_sent && (id.is_some() || model.is_some()) {
                    self.meta_sent = true;
                    out.push(ProviderEvent::ResponseMeta {
                        id,
                        model,
                        system_fingerprint: None,
                    });
                }
            }
            "response.output_text.delta" | "response.refusal.delta" => {
                if let Some(d) = v
                    .get("delta")
                    .and_then(Value::as_str)
                    .filter(|d| !d.is_empty())
                {
                    out.push(ProviderEvent::StreamChunk {
                        delta: d.to_owned(),
                    });
                }
            }
            "response.output_item.added" => {
                let item = v.get("item").unwrap_or(&Value::Null);
                if item.get("type").and_then(Value::as_str) == Some("function_call") {
                    let (index, _) = self.tool_slot(out_idx);
                    out.push(ProviderEvent::ToolCallDelta {
                        index,
                        id: item
                            .get("call_id")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                        name: item.get("name").and_then(Value::as_str).map(str::to_owned),
                        input_delta: String::new(),
                    });
                }
            }
            "response.function_call_arguments.delta" => {
                if let Some(d) = v
                    .get("delta")
                    .and_then(Value::as_str)
                    .filter(|d| !d.is_empty())
                {
                    let (index, _) = self.tool_slot(out_idx);
                    self.args_streamed.insert(out_idx);
                    out.push(ProviderEvent::ToolCallDelta {
                        index,
                        id: None,
                        name: None,
                        input_delta: d.to_owned(),
                    });
                }
            }
            "response.output_item.done" => {
                let item = v.get("item").unwrap_or(&Value::Null);
                if item.get("type").and_then(Value::as_str) == Some("function_call") {
                    let (index, fresh) = self.tool_slot(out_idx);
                    // Arguments that never streamed (a host that sends the whole
                    // call at once) arrive here, complete.
                    if !self.args_streamed.contains(&out_idx) {
                        out.push(ProviderEvent::ToolCallDelta {
                            index,
                            id: fresh
                                .then(|| {
                                    item.get("call_id")
                                        .and_then(Value::as_str)
                                        .map(str::to_owned)
                                })
                                .flatten(),
                            name: fresh
                                .then(|| {
                                    item.get("name").and_then(Value::as_str).map(str::to_owned)
                                })
                                .flatten(),
                            input_delta: item
                                .get("arguments")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_owned(),
                        });
                        self.args_streamed.insert(out_idx);
                    }
                }
            }
            "response.completed" => {
                out.extend(self.terminal(v.get("response").unwrap_or(&Value::Null), false));
            }
            "response.incomplete" => {
                out.extend(self.terminal(v.get("response").unwrap_or(&Value::Null), true));
            }
            "response.failed" | "error" => {
                let code = v
                    .pointer("/response/error/code")
                    .or_else(|| v.get("code"))
                    .and_then(Value::as_str)
                    .filter(|c| safe_token(c));
                return Err(anyhow!(
                    "the Responses API reported a failure{}",
                    code.map(|c| format!(" (code {c})")).unwrap_or_default()
                ));
            }
            _ => {}
        }
        Ok(out)
    }
}

/// Drain complete frames out of `buf` into events.
///
/// # Errors
/// An over-long frame, or a frame [`FrameState::events_for_frame`] rejects.
pub(crate) fn drain_frames(buf: &mut Vec<u8>, st: &mut FrameState) -> Result<Vec<ProviderEvent>> {
    let mut out = Vec::new();
    while let Some(frame) = crate::openai_responses::split_sse_frame(buf) {
        let Some(data) = crate::openai_responses::sse_frame_data(&frame) else {
            continue;
        };
        if data.trim() == "[DONE]" {
            continue;
        }
        out.extend(st.events_for_frame(data)?);
    }
    if buf.len() > MAX_FRAME_BYTES {
        bail!("a Responses SSE frame exceeded {MAX_FRAME_BYTES} bytes");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracelane_shared::{ImageUrl, Message, Tool, ToolCall};

    fn req(model: &str) -> ChatRequest {
        ChatRequest {
            model: model.into(),
            messages: vec![Message {
                role: Role::User,
                content: MessageContent::Text("hi".into()),
                tool_call_id: None,
                tool_calls: None,
            }],
            ..Default::default()
        }
    }

    fn weather_tool() -> Tool {
        Tool {
            name: "get_weather".into(),
            description: Some("weather".into()),
            input_schema: json!({"type":"object","properties":{"city":{"type":"string"}}}),
        }
    }

    #[test]
    fn applies_only_to_openai_and_only_per_the_policy_list() {
        assert!(applies("openai", &req("gpt-5.5-pro")));
        assert!(!applies("azure", &req("gpt-5.5-pro")));
        assert!(!applies("openai", &req("gpt-5.5")));
        // tools gate the "tools need Responses" models.
        assert!(!applies("openai", &req("gpt-6-astra")));
        let mut r = req("gpt-6-astra");
        r.tools = Some(vec![weather_tool()]);
        assert!(applies("openai", &r));
    }

    #[test]
    fn body_has_the_responses_shape_and_never_stores() {
        let mut r = req("gpt-5.5-pro");
        r.messages.insert(
            0,
            Message {
                role: Role::System,
                content: MessageContent::Text("be brief".into()),
                tool_call_id: None,
                tool_calls: None,
            },
        );
        r.max_tokens = Some(64);
        r.temperature = Some(0.2);
        r.reasoning_effort = Some("high".into());
        r.tools = Some(vec![weather_tool()]);
        r.tool_choice = Some(ToolChoice::Function {
            name: "get_weather".into(),
        });
        let b = build_body(&r).unwrap();
        assert_eq!(b["model"], "gpt-5.5-pro");
        assert_eq!(b["stream"], true);
        assert_eq!(b["store"], false, "the bridge must not retain the prompt");
        assert_eq!(b["max_output_tokens"], 64);
        assert_eq!(b["reasoning"]["effort"], "high");
        assert_eq!(b["input"][0]["role"], "system");
        assert_eq!(b["input"][1]["role"], "user");
        assert_eq!(b["input"][1]["content"][0]["type"], "input_text");
        // Flat tool + flat tool_choice (not the nested chat shapes).
        assert_eq!(b["tools"][0]["type"], "function");
        assert_eq!(b["tools"][0]["name"], "get_weather");
        assert!(b["tools"][0].get("function").is_none());
        assert_eq!(b["tool_choice"]["name"], "get_weather");
        assert!(b.get("messages").is_none() && b.get("max_tokens").is_none());
    }

    #[test]
    fn a_tool_round_trip_history_maps_to_function_call_items() {
        let mut r = req("gpt-6-astra");
        r.tools = Some(vec![weather_tool()]);
        r.messages.push(Message {
            role: Role::Assistant,
            content: MessageContent::Text(String::new()),
            tool_call_id: None,
            tool_calls: Some(vec![ToolCall {
                id: "call_1".into(),
                name: "get_weather".into(),
                input: json!({"city":"Paris"}),
            }]),
        });
        r.messages.push(Message {
            role: Role::Tool,
            content: MessageContent::Text("sunny".into()),
            tool_call_id: Some("call_1".into()),
            tool_calls: None,
        });
        let b = build_body(&r).unwrap();
        let input = b["input"].as_array().unwrap();
        assert_eq!(input[1]["type"], "function_call");
        assert_eq!(input[1]["call_id"], "call_1");
        assert_eq!(input[1]["arguments"], "{\"city\":\"Paris\"}");
        assert_eq!(input[2]["type"], "function_call_output");
        assert_eq!(input[2]["call_id"], "call_1");
        assert_eq!(input[2]["output"], "sunny");
    }

    #[test]
    fn images_and_response_format_translate() {
        let mut r = req("gpt-5.5-pro");
        r.messages[0].content = MessageContent::Parts(vec![
            ContentPart::Text {
                text: "what is this".into(),
                cache_control: None,
            },
            ContentPart::ImageUrl {
                image_url: ImageUrl {
                    url: "data:image/png;base64,AAAA".into(),
                    detail: Some("low".into()),
                },
            },
        ]);
        r.response_format = Some(json!({
            "type": "json_schema",
            "json_schema": {"name": "out", "schema": {"type":"object"}, "strict": true}
        }));
        let b = build_body(&r).unwrap();
        assert_eq!(b["input"][0]["content"][1]["type"], "input_image");
        assert_eq!(b["input"][0]["content"][1]["detail"], "low");
        assert_eq!(b["text"]["format"]["type"], "json_schema");
        assert_eq!(b["text"]["format"]["name"], "out");
        assert_eq!(b["text"]["format"]["strict"], true);
    }

    /// The guard BLOCKS: each field the Responses wire cannot honour is refused,
    /// never dropped, and the control case (none of them) builds.
    #[test]
    fn unsupported_fields_and_parts_are_refused_not_dropped() {
        assert!(build_body(&req("gpt-5.5-pro")).is_ok(), "control");
        type Mutation = Box<dyn Fn(&mut ChatRequest)>;
        let cases: Vec<(&str, Mutation)> = vec![
            (
                "stop",
                Box::new(|r| r.stop = Some(tracelane_shared::Stop::One("x".into()))),
            ),
            ("seed", Box::new(|r| r.seed = Some(1))),
            (
                "presence_penalty",
                Box::new(|r| r.presence_penalty = Some(0.5)),
            ),
            (
                "frequency_penalty",
                Box::new(|r| r.frequency_penalty = Some(0.5)),
            ),
            ("logprobs", Box::new(|r| r.logprobs = Some(true))),
            ("n", Box::new(|r| r.n = Some(2))),
            (
                "logit_bias",
                Box::new(|r| {
                    r.extra.insert("logit_bias".into(), json!({}));
                }),
            ),
        ];
        for (param, mutate) in cases {
            let mut r = req("gpt-5.5-pro");
            mutate(&mut r);
            assert_eq!(
                first_unsupported(&r).map(|(p, _)| p).as_deref(),
                Some(param),
                "{param}"
            );
            assert!(build_body(&r).is_err(), "{param} must not build");
        }
        // Default-valued penalties are not an offence.
        let mut r = req("gpt-5.5-pro");
        r.presence_penalty = Some(0.0);
        assert!(first_unsupported(&r).is_none());
        // Audio / file parts.
        let mut r = req("gpt-5.5-pro");
        r.messages[0].content = MessageContent::Parts(vec![ContentPart::InputAudio {
            input_audio: tracelane_shared::InputAudio {
                data: "AAAA".into(),
                format: "wav".into(),
            },
        }]);
        assert_eq!(first_unsupported_part(&r), Some((0, 0)));
        assert!(build_body(&r).is_err());
    }

    fn run(frames: &[&str]) -> (Vec<ProviderEvent>, FrameState) {
        let mut st = FrameState::default();
        let mut buf: Vec<u8> = frames
            .iter()
            .map(|f| format!("event: x\ndata: {f}\n\n"))
            .collect::<String>()
            .into_bytes();
        let ev = drain_frames(&mut buf, &mut st).unwrap();
        (ev, st)
    }

    #[test]
    fn text_stream_becomes_chunks_then_finish_then_usage() {
        let (ev, st) = run(&[
            r#"{"type":"response.created","response":{"id":"resp_1","model":"gpt-5.5-pro-2026-10-01"}}"#,
            r#"{"type":"response.output_text.delta","delta":"Hel"}"#,
            r#"{"type":"response.output_text.delta","delta":"lo"}"#,
            r#"{"type":"response.completed","response":{"usage":{"input_tokens":12,"output_tokens":5,"input_tokens_details":{"cached_tokens":4},"output_tokens_details":{"reasoning_tokens":3}}}}"#,
        ]);
        assert!(st.finished);
        assert!(matches!(
            &ev[0],
            ProviderEvent::ResponseMeta { id: Some(i), model: Some(m), .. }
                if i == "resp_1" && m == "gpt-5.5-pro-2026-10-01"
        ));
        let text: String = ev
            .iter()
            .filter_map(|e| match e {
                ProviderEvent::StreamChunk { delta } => Some(delta.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(text, "Hello");
        assert!(ev.iter().any(|e| matches!(
            e,
            ProviderEvent::Finish {
                reason: FinishReason::Stop
            }
        )));
        // Usage: input inclusive of the cached prefix, NO cache counter.
        assert!(ev.iter().any(|e| matches!(
            e,
            ProviderEvent::UsageUpdate {
                input_tokens: 12,
                output_tokens: 5,
                cache_read: None,
                reasoning: Some(3),
                ..
            }
        )));
    }

    #[test]
    fn a_tool_call_streams_as_indexed_deltas_and_finishes_as_tool_calls() {
        let (ev, _) = run(&[
            r#"{"type":"response.output_item.added","output_index":1,"item":{"type":"function_call","call_id":"call_9","name":"get_weather","arguments":""}}"#,
            r#"{"type":"response.function_call_arguments.delta","output_index":1,"delta":"{\"city\":"}"#,
            r#"{"type":"response.function_call_arguments.delta","output_index":1,"delta":"\"Paris\"}"}"#,
            r#"{"type":"response.output_item.done","output_index":1,"item":{"type":"function_call","call_id":"call_9","name":"get_weather","arguments":"{\"city\":\"Paris\"}"}}"#,
            r#"{"type":"response.completed","response":{"usage":{"input_tokens":1,"output_tokens":1}}}"#,
        ]);
        let calls: Vec<_> = ev
            .iter()
            .filter_map(|e| match e {
                ProviderEvent::ToolCallDelta {
                    index,
                    id,
                    name,
                    input_delta,
                } => Some((*index, id.clone(), name.clone(), input_delta.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(
            calls.len(),
            3,
            "added + 2 deltas; `done` adds nothing: {calls:?}"
        );
        assert_eq!(
            calls[0],
            (
                0,
                Some("call_9".into()),
                Some("get_weather".into()),
                String::new()
            )
        );
        let args: String = calls.iter().map(|c| c.3.as_str()).collect();
        assert_eq!(args, "{\"city\":\"Paris\"}");
        assert!(ev.iter().any(|e| matches!(
            e,
            ProviderEvent::Finish {
                reason: FinishReason::ToolCalls
            }
        )));
    }

    #[test]
    fn a_call_sent_whole_arrives_on_item_done() {
        let (ev, _) = run(&[
            r#"{"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","call_id":"c1","name":"f","arguments":"{\"a\":1}"}}"#,
            r#"{"type":"response.completed","response":{}}"#,
        ]);
        assert!(ev.iter().any(|e| matches!(
            e,
            ProviderEvent::ToolCallDelta { index: 0, id: Some(i), name: Some(n), input_delta }
                if i == "c1" && n == "f" && input_delta == "{\"a\":1}"
        )));
    }

    #[test]
    fn incomplete_maps_to_length_and_failure_is_an_error_without_upstream_text() {
        let (ev, st) = run(&[
            r#"{"type":"response.incomplete","response":{"incomplete_details":{"reason":"max_output_tokens"},"usage":{"input_tokens":1,"output_tokens":9}}}"#,
        ]);
        assert!(st.finished);
        assert!(ev.iter().any(|e| matches!(
            e,
            ProviderEvent::Finish {
                reason: FinishReason::Length
            }
        )));
        let mut st = FrameState::default();
        let e = st
            .events_for_frame(
                r#"{"type":"response.failed","response":{"error":{"code":"server_error","message":"sk-SECRET-KEY-echo"}}}"#,
            )
            .unwrap_err()
            .to_string();
        assert!(e.contains("server_error"));
        assert!(
            !e.contains("sk-SECRET"),
            "upstream error text must not leak: {e}"
        );
        // An unsafe code token is dropped, not echoed.
        let e = st
            .events_for_frame(r#"{"type":"error","code":"Bearer sk-XYZ"}"#)
            .unwrap_err()
            .to_string();
        assert!(!e.contains("sk-XYZ"), "{e}");
    }

    #[test]
    fn frames_split_across_chunks_reassemble() {
        let mut st = FrameState::default();
        let mut buf =
            b"event: x\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"a".to_vec();
        assert!(drain_frames(&mut buf, &mut st).unwrap().is_empty());
        buf.extend_from_slice(b"b\"}\n\n");
        let ev = drain_frames(&mut buf, &mut st).unwrap();
        assert!(matches!(&ev[0], ProviderEvent::StreamChunk { delta } if delta == "ab"));
    }
}

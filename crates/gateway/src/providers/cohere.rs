//! Cohere Chat adapter — the **v2** wire (`POST {base}/chat`, base `https://api.cohere.com/v2`).
//!
//! `D9` (ONE GATEWAY): this adapter claimed v2 in its base URL but sent a v1-shaped body
//! (`message` + `chat_history`): tool calls were dropped from history, the `tool` role went
//! as plain text, and a trailing tool result became `message`. Every field below is checked
//! against docs.cohere.com/reference/chat and /reference/chat-stream (2026-10-01):
//!
//!   - `messages[]` with roles `system | user | assistant | tool`;
//!   - assistant `tool_calls: [{id, type:"function", function:{name, arguments:<JSON string>}}]`,
//!     with the model's pre-call text as `tool_plan`;
//!   - tool result `{role:"tool", tool_call_id, content}`;
//!   - `tools: [{type:"function", function:{name, description, parameters}}]`;
//!   - `response_format: {type:"json_object"}` or `{type:"json_object", schema}` (there is no
//!     `json_schema` key on Cohere's wire — the OpenAI `json_schema.schema` is mapped to it);
//!   - images as `{type:"image_url", image_url:{url, detail}}` on vision models only;
//!   - the stream is SSE whose `data:` JSON carries `type`: `message-start`, `content-start|
//!     delta|end`, `tool-plan-delta`, `tool-call-start|delta|end`, `citation-*`, `message-end`
//!     (usage + `finish_reason` live ONLY in `message-end.delta`).
//!
//! Configuration env vars:
//!   COHERE_API_KEY   — Cohere API key
//!   COHERE_BASE_URL  — defaults to https://api.cohere.com/v2

use anyhow::{Context as _, Result};
use async_stream::try_stream;
use reqwest::Client;
use serde_json::Value;
use tracing::instrument;

use crate::providers::{ProviderEvent, ProviderStream};
use tracelane_shared::{ChatRequest, ContentPart, Message, MessageContent, Role, TenantId};

pub struct CohereProvider {
    client: Client,
    base_url: String,
}

impl CohereProvider {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            client: crate::ssrf_guard::safe_client_builder()
                .timeout(std::time::Duration::from_secs(300))
                .build()
                .context("build Cohere reqwest client")?,
            base_url: std::env::var("COHERE_BASE_URL")
                .unwrap_or_else(|_| "https://api.cohere.com/v2".into()),
        })
    }

    /// Construct against an explicit base URL, reading no process env. Used by
    /// `providers::smoke_tests` so the parallel suite never mutates env.
    #[cfg(test)]
    pub(crate) fn for_base_url(base_url: impl Into<String>) -> anyhow::Result<Self> {
        Ok(Self {
            client: crate::ssrf_guard::safe_client_builder()
                .timeout(std::time::Duration::from_secs(300))
                .build()
                .context("build Cohere reqwest client")?,
            base_url: base_url.into(),
        })
    }

    /// The configured base URL (`…/v2`), for the rerank route (`{base}/rerank`).
    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Universal messages → Cohere v2 `messages[]`.
    ///
    /// # Errors
    /// Fail-CLOSED on a part Cohere v2 cannot carry (audio, file) or an image on a model
    /// the table does not list as vision-capable — never dropped.
    fn translate_messages(request: &ChatRequest) -> Result<Vec<Value>> {
        let vision = crate::providers::translation_policy::cohere_is_vision_model(&request.model);
        let mut out: Vec<Value> = Vec::with_capacity(request.messages.len() + 1);
        if let Some(sys) = request.system.as_deref().filter(|s| !s.is_empty()) {
            out.push(serde_json::json!({ "role": "system", "content": sys }));
        }
        for m in &request.messages {
            match m.role {
                Role::System => out.push(serde_json::json!({
                    "role": "system",
                    "content": text_of(&m.content),
                })),
                Role::User => Self::push_user(&mut out, m, vision)?,
                Role::Assistant => out.push(Self::assistant(m)),
                Role::Tool => out.push(serde_json::json!({
                    "role": "tool",
                    "tool_call_id": m.tool_call_id.clone().unwrap_or_default(),
                    "content": text_of(&m.content),
                })),
            }
        }
        Ok(out)
    }

    /// A user turn: plain text stays a string; images make it a content array. Anthropic-style
    /// `tool_result` parts become `tool` messages ahead of the user text, in order.
    fn push_user(out: &mut Vec<Value>, m: &Message, vision: bool) -> Result<()> {
        let MessageContent::Parts(parts) = &m.content else {
            out.push(serde_json::json!({ "role": "user", "content": text_of(&m.content) }));
            return Ok(());
        };
        let mut content: Vec<Value> = Vec::new();
        for p in parts {
            match p {
                ContentPart::Text { text, .. } => {
                    content.push(serde_json::json!({ "type": "text", "text": text }));
                }
                ContentPart::ImageUrl { image_url } => {
                    if !vision {
                        anyhow::bail!("the Cohere model does not take images — use a vision model");
                    }
                    let mut img = serde_json::json!({ "url": image_url.url });
                    if let Some(d) = image_url.detail.as_deref() {
                        img["detail"] = Value::String(d.to_owned());
                    }
                    content.push(serde_json::json!({ "type": "image_url", "image_url": img }));
                }
                ContentPart::ToolResult {
                    tool_use_id,
                    content: result,
                    ..
                } => out.push(serde_json::json!({
                    "role": "tool",
                    "tool_call_id": tool_use_id,
                    "content": result,
                })),
                ContentPart::ToolUse { .. } => {}
                ContentPart::InputAudio { .. } | ContentPart::File { .. } => {
                    anyhow::bail!("the Cohere adapter takes text and images only");
                }
            }
        }
        if !content.is_empty() {
            out.push(serde_json::json!({ "role": "user", "content": content }));
        }
        Ok(())
    }

    /// An assistant turn. Its tool calls ride `tool_calls` (arguments as a JSON STRING); text
    /// that accompanied them is the call's `tool_plan`, the field Cohere's own response uses.
    fn assistant(m: &Message) -> Value {
        let mut calls: Vec<Value> = m
            .tool_calls
            .iter()
            .flatten()
            .map(|c| call_json(&c.id, &c.name, &c.input))
            .collect();
        if let MessageContent::Parts(parts) = &m.content {
            for p in parts {
                if let ContentPart::ToolUse { id, name, input } = p {
                    calls.push(call_json(id, name, input));
                }
            }
        }
        let text = text_of(&m.content);
        if calls.is_empty() {
            return serde_json::json!({ "role": "assistant", "content": text });
        }
        let mut msg = serde_json::json!({ "role": "assistant", "tool_calls": calls });
        if !text.is_empty() {
            msg["tool_plan"] = Value::String(text);
        }
        msg
    }

    /// The v2 request body for `request`.
    ///
    /// # Errors
    /// See [`Self::translate_messages`]; also a `response_format` or `tool_choice` the v2 wire
    /// has no equivalent for.
    fn build_body(request: &ChatRequest) -> Result<Value> {
        let model = request
            .model
            .strip_prefix("cohere/")
            .unwrap_or(&request.model)
            .to_owned();
        let mut body = serde_json::json!({
            "model": model,
            "messages": Self::translate_messages(request)?,
            "stream": true,
        });
        // Inserted ONLY when present, so a request that omits them sends no null.
        if let Some(n) = request.max_completion_tokens.or(request.max_tokens) {
            body["max_tokens"] = serde_json::json!(n);
        }
        if let Some(t) = request.temperature {
            body["temperature"] = serde_json::json!(t);
        }
        // GWY-48. Cohere spells nucleus sampling `p`, not `top_p`.
        if let Some(p) = request.top_p {
            body["p"] = serde_json::json!(p);
        }
        if let Some(stop) = request.stop.as_ref() {
            body["stop_sequences"] = serde_json::json!(stop.sequences());
        }
        if let Some(v) = request.presence_penalty {
            body["presence_penalty"] = serde_json::json!(v);
        }
        if let Some(v) = request.frequency_penalty {
            body["frequency_penalty"] = serde_json::json!(v);
        }
        if let Some(tools) = request.tools.as_ref().filter(|t| !t.is_empty()) {
            body["tools"] = Value::Array(tools.iter().map(translate_tool).collect());
            match request.tool_choice.as_ref() {
                Some(tracelane_shared::ToolChoice::Required) => {
                    body["tool_choice"] = Value::String("REQUIRED".into());
                }
                Some(tracelane_shared::ToolChoice::None) => {
                    body["tool_choice"] = Value::String("NONE".into());
                }
                Some(tracelane_shared::ToolChoice::Function { .. }) => {
                    anyhow::bail!("Cohere v2 cannot force one named tool");
                }
                Some(tracelane_shared::ToolChoice::Auto) | None => {}
            }
        }
        if let Some(rf) = request.response_format.as_ref() {
            match rf.get("type").and_then(Value::as_str).unwrap_or("text") {
                "text" => {}
                "json_object" => {
                    body["response_format"] = serde_json::json!({ "type": "json_object" });
                }
                "json_schema" => {
                    let Some(schema) = rf.pointer("/json_schema/schema").filter(|s| s.is_object())
                    else {
                        anyhow::bail!("response_format.json_schema.schema is required");
                    };
                    body["response_format"] =
                        serde_json::json!({ "type": "json_object", "schema": schema });
                }
                other => anyhow::bail!("response_format.type `{other}` has no Cohere equivalent"),
            }
        }
        Ok(body)
    }

    #[instrument(skip(self, request, api_key), fields(tenant_id = %tenant_id, provider = "cohere"))]
    pub async fn chat(
        &self,
        request: ChatRequest,
        api_key: &str,
        tenant_id: &TenantId,
    ) -> Result<ProviderStream> {
        let body = Self::build_body(&request)?;
        let url = format!("{}/chat", self.base_url);

        // SSRF: validate before the POST (reviewer).
        crate::ssrf_guard::validate_url(&url)
            .await
            .context("SSRF guard rejected Cohere base URL")?;

        let response = crate::routing::deadlines::send(
            self.client
                .post(&url)
                .bearer_auth(api_key)
                .header("accept", "text/event-stream")
                .json(&body),
        )
        .await
        .context("cohere request")?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            // SECURITY: the body is scrubbed by `ProviderHttpError` — Cohere 401/403
            // bodies can echo the Bearer token.
            let retry_after = crate::providers::retry_after_from(response.headers());
            let body = crate::routing::deadlines::error_text(response).await?;
            tracing::warn!(status, "Cohere API error");
            // B-391: typed, so `classify_dispatch_error` sees a 401 as a rejected key and a
            // 429 as a rate limit. OG-03 §3.4: a relayable 4xx carries the scrubbed message.
            return Err(crate::providers::ProviderHttpError::from_response(
                "cohere", status, None, &body, api_key,
            )
            .with_retry_after(retry_after)
            .into());
        }

        let mut byte_stream = response.bytes_stream();
        let stream = try_stream! {
            use futures::StreamExt as _;
            // Bytes, not text: a chunk boundary can fall inside a character.
            let mut lines = super::sse_lines::LineBuffer::default();
            while let Some(chunk) = byte_stream.next().await {
                use bytes::Bytes;
                let chunk: Bytes = chunk.map_err(reqwest::Error::without_url).context("stream chunk")?;
                lines.push(&chunk);
                while let Some(line) = lines.next_line_lossy() {
                    // SSE: `event:` names are redundant with `data.type`; a bare JSON line
                    // (NDJSON) is tolerated for proxies that strip the framing.
                    let line = line.trim();
                    let payload = line.strip_prefix("data:").map_or(line, str::trim);
                    if payload.is_empty() || !payload.starts_with('{') { continue; }
                    let Ok(v) = serde_json::from_str::<Value>(payload) else { continue };
                    for ev in parse_event(&v)? {
                        let done = matches!(ev, ProviderEvent::UsageUpdate { .. });
                        yield ev;
                        if done { return; }
                    }
                }
            }
        };
        Ok(Box::pin(stream))
    }
}

fn text_of(c: &MessageContent) -> String {
    match c {
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

fn call_json(id: &str, name: &str, input: &Value) -> Value {
    serde_json::json!({
        "id": id,
        "type": "function",
        "function": { "name": name, "arguments": input.to_string() },
    })
}

/// Fold one v2 stream event into provider events. `message-end` carries usage and the stop
/// reason; the finish event goes FIRST so the consumer has it before the stream is closed.
///
/// # Errors
/// Fail-CLOSED on `finish_reason` `ERROR` / `TIMEOUT`: the upstream did not complete.
fn parse_event(v: &Value) -> Result<Vec<ProviderEvent>> {
    use crate::providers::FinishReason;
    let mut out = Vec::new();
    match v["type"].as_str().unwrap_or("") {
        "message-start" => {
            if let Some(id) = v["id"].as_str() {
                out.push(ProviderEvent::ResponseMeta {
                    id: Some(id.to_owned()),
                    model: None,
                    system_fingerprint: None,
                });
            }
        }
        "content-delta" => {
            if let Some(t) = v["delta"]["message"]["content"]["text"].as_str() {
                out.push(ProviderEvent::StreamChunk {
                    delta: t.to_owned(),
                });
            }
        }
        // The model's pre-call reasoning text: visible output, surfaced as text and replayed
        // as `tool_plan` (see `assistant`).
        "tool-plan-delta" => {
            if let Some(t) = v["delta"]["message"]["tool_plan"].as_str() {
                out.push(ProviderEvent::StreamChunk {
                    delta: t.to_owned(),
                });
            }
        }
        "tool-call-start" => {
            let call = &v["delta"]["message"]["tool_calls"];
            out.push(ProviderEvent::ToolCallDelta {
                index: usize::try_from(v["index"].as_u64().unwrap_or(0)).unwrap_or(0),
                id: call["id"].as_str().map(str::to_owned),
                name: call["function"]["name"].as_str().map(str::to_owned),
                input_delta: call["function"]["arguments"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            });
        }
        "tool-call-delta" => {
            out.push(ProviderEvent::ToolCallDelta {
                index: usize::try_from(v["index"].as_u64().unwrap_or(0)).unwrap_or(0),
                id: None,
                name: None,
                input_delta: v["delta"]["message"]["tool_calls"]["function"]["arguments"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            });
        }
        "message-end" => {
            let d = &v["delta"];
            match d["finish_reason"].as_str().unwrap_or("COMPLETE") {
                "ERROR" | "TIMEOUT" => anyhow::bail!("cohere stream ended without completing"),
                "MAX_TOKENS" => out.push(ProviderEvent::Finish {
                    reason: FinishReason::Length,
                }),
                "TOOL_CALL" => out.push(ProviderEvent::Finish {
                    reason: FinishReason::ToolCalls,
                }),
                _ => out.push(ProviderEvent::Finish {
                    reason: FinishReason::Stop,
                }),
            }
            // `tokens` is what the model processed; `billed_units` is the invoice and can
            // differ (the 2026-10-01 docs list both). Usage is `tokens`, as v1's was.
            let u = &d["usage"];
            let tok =
                |k: &str| u32::try_from(u["tokens"][k].as_u64().unwrap_or(0)).unwrap_or(u32::MAX);
            out.push(ProviderEvent::UsageUpdate {
                input_tokens: tok("input_tokens"),
                output_tokens: tok("output_tokens"),
                cache_read: u["cached_tokens"]
                    .as_u64()
                    .and_then(|n| u32::try_from(n).ok()),
                cache_creation: None,
                cost_usd: None,
                // Cohere reports no reasoning-token split on this wire (RI-05 / M11).
                reasoning: None,
            });
        }
        _ => {}
    }
    Ok(out)
}

/// Universal `Tool` → Cohere v2 `tools[]` entry: OpenAI's function shape, with the JSON
/// schema passed through as `parameters`.
fn translate_tool(tool: &tracelane_shared::Tool) -> Value {
    serde_json::json!({
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description.as_deref().unwrap_or(""),
            "parameters": tool.input_schema,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracelane_shared::{ImageUrl, ToolChoice};

    fn req(model: &str, messages: Vec<Message>) -> ChatRequest {
        ChatRequest {
            model: model.into(),
            messages,
            ..Default::default()
        }
    }

    fn user_parts(parts: Vec<ContentPart>) -> Message {
        Message {
            role: Role::User,
            content: MessageContent::Parts(parts),
            tool_call_id: None,
            tool_calls: None,
        }
    }

    fn png() -> ContentPart {
        ContentPart::ImageUrl {
            image_url: ImageUrl {
                url: "data:image/png;base64,AAAA".into(),
                detail: Some("low".into()),
            },
        }
    }

    #[test]
    fn a_vision_model_gets_an_image_url_part_and_any_other_model_is_refused() {
        let parts = vec![
            ContentPart::Text {
                text: "what is this?".into(),
                cache_control: None,
            },
            png(),
        ];
        let body = CohereProvider::build_body(&req(
            "command-a-vision-07-2025",
            vec![user_parts(parts.clone())],
        ))
        .expect("vision model");
        assert_eq!(
            body["messages"][0]["content"],
            serde_json::json!([
                {"type": "text", "text": "what is this?"},
                {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA", "detail": "low"}}
            ])
        );
        assert!(
            CohereProvider::build_body(&req("command-a-03-2025", vec![user_parts(parts)])).is_err(),
            "a text-only model must refuse the image, not drop it"
        );
    }

    #[test]
    fn audio_and_file_parts_are_refused_never_dropped() {
        let audio = ContentPart::InputAudio {
            input_audio: tracelane_shared::InputAudio {
                data: "AAAA".into(),
                format: "wav".into(),
            },
        };
        assert!(
            CohereProvider::build_body(&req(
                "command-a-vision-07-2025",
                vec![user_parts(vec![audio])]
            ))
            .is_err()
        );
    }

    #[test]
    fn response_format_maps_to_cohere_json_object_with_an_optional_schema() {
        let mut r = req("command-a-03-2025", vec![]);
        r.response_format = Some(serde_json::json!({"type": "json_object"}));
        let b = CohereProvider::build_body(&r).expect("json_object");
        assert_eq!(
            b["response_format"],
            serde_json::json!({"type": "json_object"})
        );

        r.response_format = Some(serde_json::json!({
            "type": "json_schema",
            "json_schema": {"name": "x", "schema": {"type": "object", "properties": {}}}
        }));
        let b = CohereProvider::build_body(&r).expect("json_schema");
        assert_eq!(
            b["response_format"],
            serde_json::json!({"type": "json_object", "schema": {"type": "object", "properties": {}}})
        );
        assert!(b["response_format"].get("json_schema").is_none());

        r.response_format = Some(serde_json::json!({"type": "json_schema", "json_schema": {}}));
        assert!(
            CohereProvider::build_body(&r).is_err(),
            "a schema-less json_schema must be refused"
        );
        r.response_format = Some(serde_json::json!({"type": "text"}));
        assert!(
            CohereProvider::build_body(&r)
                .expect("text")
                .get("response_format")
                .is_none()
        );
    }

    #[test]
    fn tool_choice_maps_required_and_none_and_refuses_a_named_tool() {
        let tool = tracelane_shared::Tool {
            name: "f".into(),
            description: None,
            input_schema: serde_json::json!({"type": "object"}),
        };
        let mut r = req("command-a-03-2025", vec![]);
        r.tools = Some(vec![tool]);
        r.tool_choice = Some(ToolChoice::Required);
        assert_eq!(
            CohereProvider::build_body(&r).expect("required")["tool_choice"],
            "REQUIRED"
        );
        r.tool_choice = Some(ToolChoice::None);
        assert_eq!(
            CohereProvider::build_body(&r).expect("none")["tool_choice"],
            "NONE"
        );
        r.tool_choice = Some(ToolChoice::Auto);
        assert!(
            CohereProvider::build_body(&r)
                .expect("auto")
                .get("tool_choice")
                .is_none()
        );
        r.tool_choice = Some(ToolChoice::Function { name: "f".into() });
        assert!(CohereProvider::build_body(&r).is_err());
    }

    #[test]
    fn a_request_without_sampling_fields_sends_no_nulls() {
        let b = CohereProvider::build_body(&req("command-a-03-2025", vec![])).expect("body");
        for k in ["max_tokens", "temperature", "p", "stop_sequences", "tools"] {
            assert!(b.get(k).is_none(), "{k} must be omitted, not null");
        }
    }

    #[test]
    fn message_end_error_or_timeout_fails_the_stream_closed() {
        for reason in ["ERROR", "TIMEOUT"] {
            let ev = serde_json::json!({
                "type": "message-end",
                "delta": {"finish_reason": reason, "usage": {"tokens": {"input_tokens": 1, "output_tokens": 1}}}
            });
            assert!(parse_event(&ev).is_err(), "{reason}");
        }
        let ok = serde_json::json!({
            "type": "message-end",
            "delta": {"finish_reason": "MAX_TOKENS", "usage": {"tokens": {"input_tokens": 3, "output_tokens": 4}}}
        });
        let evs = parse_event(&ok).expect("complete");
        assert!(matches!(
            evs[0],
            ProviderEvent::Finish {
                reason: crate::providers::FinishReason::Length
            }
        ));
    }

    #[test]
    fn an_assistant_turn_with_text_and_calls_sends_the_text_as_tool_plan() {
        let m = Message {
            role: Role::Assistant,
            content: MessageContent::Text("checking".into()),
            tool_call_id: None,
            tool_calls: Some(vec![tracelane_shared::ToolCall {
                id: "c1".into(),
                name: "f".into(),
                input: serde_json::json!({"a": 1}),
            }]),
        };
        let v = CohereProvider::assistant(&m);
        assert_eq!(v["tool_plan"], "checking");
        assert!(v.get("content").is_none());
        assert_eq!(v["tool_calls"][0]["function"]["arguments"], "{\"a\":1}");
    }
}

//! Anthropic Claude API adapter.
//!
//! Supports all Claude models via the Messages API with SSE streaming.
//! Extended thinking (interleaved-thinking-2025-05-14 beta) is enabled by default.
//! Prompt caching: `cache_control` markers on message content blocks (text /
//! tool_result) are preserved verbatim through the universal request into the
//! Anthropic blocks (/ PP-G8). NOTE: cache_control on the *system* prompt
//! is not yet preserved — system messages merge into Anthropic's top-level
//! `system` string, which carries no per-block marker (documented follow-up).
//!
//! Provider keys are never logged; `tracing::instrument` redacts `api_key`.

use anyhow::{Context as _, Result, bail};
use async_stream::try_stream;
use bytes::Bytes;
use futures::Stream;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::instrument;

use tracelane_shared::{ChatRequest, ContentPart, MessageContent, Role, TenantId, ToolChoice};

use crate::providers::translation_policy::AnthropicThinking;
use crate::providers::{FinishReason, ProviderEvent, ProviderStream};

/// `max_tokens` is REQUIRED by Anthropic; this is what the adapter sends when the caller
/// sent neither `max_tokens` nor `max_completion_tokens` (pre-existing value, now named so
/// `request_support` clamps a reasoning budget against the same number).
pub(crate) const DEFAULT_MAX_TOKENS: u32 = 4096;

/// Anthropic Messages API provider adapter.
///
/// Translates Tracelane's universal ChatRequest to Anthropic's messages format,
/// streams SSE events back as ProviderEvents, and emits OTLP spans.
///
/// Provider API keys are:
/// - Never logged (tracing::Span fields exclude them by design)
/// - Never included in span attributes (CLAUDE.md security contract)
/// - Passed as a function argument only, never stored in self
pub struct AnthropicProvider {
    client: Client,
    base_url: String,
}

impl AnthropicProvider {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            client: crate::ssrf_guard::safe_client_builder()
                .timeout(std::time::Duration::from_secs(300))
                .build()
                .context("build Anthropic reqwest client")?,
            base_url: std::env::var("ANTHROPIC_BASE_URL")
                .unwrap_or_else(|_| "https://api.anthropic.com".into()),
        })
    }

    /// The resolved Anthropic origin this adapter talks to (`ANTHROPIC_BASE_URL`
    /// or the public API). GWY-47's `/v1/messages` relay forwards the customer's
    /// ORIGINAL body bytes rather than a translated `ChatRequest`, so it makes its
    /// own HTTP call — and it must reach the SAME origin this adapter would, or a
    /// self-hosted / proxied deployment would have two different upstreams for the
    /// same provider. Reading the origin from here is what keeps that one value.
    #[must_use]
    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Construct against an explicit base URL, reading no process env. Used by
    /// `providers::smoke_tests` so the parallel suite never mutates env.
    #[cfg(test)]
    pub(crate) fn for_base_url(base_url: impl Into<String>) -> anyhow::Result<Self> {
        Ok(Self {
            client: crate::ssrf_guard::safe_client_builder()
                .timeout(std::time::Duration::from_secs(300))
                .build()
                .context("build Anthropic reqwest client")?,
            base_url: base_url.into(),
        })
    }

    /// Send a streaming chat request to the Anthropic Messages API.
    ///
    /// `api_key` is the customer's BYOK key — never logged, never in spans.
    #[instrument(skip(self, request, api_key), fields(
        tenant_id = %tenant_id,
        model = %request.model,
        provider = "anthropic",
    ))]
    pub async fn chat(
        &self,
        request: ChatRequest,
        api_key: &str,
        tenant_id: &TenantId,
    ) -> Result<ProviderStream> {
        let anthropic_request =
            AnthropicRequest::from_universal(request).context("failed to translate request")?;
        let url = format!("{}/v1/messages", self.base_url);

        // SSRF: validate before the POST (reviewer).
        crate::ssrf_guard::validate_url(&url)
            .await
            .context("SSRF guard rejected Anthropic base URL")?;

        let response = crate::routing::deadlines::send(
            self.client
                .post(&url)
                .header("x-api-key", api_key)
                .header("anthropic-version", "2023-06-01")
                .header("anthropic-beta", "interleaved-thinking-2025-05-14")
                .header("content-type", "application/json")
                .json(&anthropic_request),
        )
        .await
        .context("failed to send request to Anthropic API")?;

        let status = response.status();
        if !status.is_success() {
            // SECURITY: drop the response body — Anthropic
            // 401/403 bodies can echo the x-api-key header value, leaking
            // the customer's BYOK key to logs.
            let retry_after = crate::providers::retry_after_from(response.headers());
            let body = crate::routing::deadlines::error_text(response).await?;
            tracing::warn!(status = %status, "Anthropic API error");
            // Typed so the gateway distinguishes an auth rejection (401/403) from
            // an outage (5xx). Status only, never the body (credential echo).
            // OG-03 §3.4: a relayable 4xx carries the scrubbed upstream message.
            return Err(crate::providers::ProviderHttpError::from_response(
                "anthropic",
                status.as_u16(),
                None,
                &body,
                api_key,
            )
            .with_retry_after(retry_after)
            .into());
        }

        let stream = build_event_stream(response);
        Ok(Box::pin(stream))
    }
}

// A14: `Default` removed — `new()` is now fallible (see ProviderRegistry).

// `ExtendedThinkingConfig` (a typed `{type, budget_tokens}` request-body
// struct) was deleted 2026-09-12 (B-390) — never constructed anywhere.
// Extended thinking is enabled entirely via the `anthropic-beta:
// interleaved-thinking-2025-05-14` header above; the SSE response parser
// below already handles `thinking_delta` events without this struct.

/// Build a ProviderEvent stream from an Anthropic SSE response.
fn build_event_stream(
    response: reqwest::Response,
) -> impl Stream<Item = Result<ProviderEvent>> + Send {
    try_stream! {
        let mut byte_stream = response.bytes_stream();
        // Bytes, not text: a chunk boundary can fall inside a character.
        let mut lines = super::sse_lines::LineBuffer::default();

        use futures::StreamExt as _;
        while let Some(chunk) = byte_stream.next().await {
            let chunk: Bytes = chunk.map_err(reqwest::Error::without_url).context("error reading response chunk")?;
            lines.push(&chunk);

            // Process complete SSE lines
            while let Some(line) = lines.next_line() {
                let line = line.context("non-UTF8 SSE line")?;

                if line.is_empty() || line.starts_with(':') {
                    continue;
                }

                if let Some(data) = line.strip_prefix("data: ") {
                    if data == "[DONE]" {
                        return;
                    }
                    if let Ok(provider_events) = parse_anthropic_sse_event(data) {
                        for provider_event in provider_events {
                            yield provider_event;
                        }
                    }
                }
            }
        }
    }
}

/// Parse a single Anthropic SSE data payload into zero or more `ProviderEvent`s.
///
/// **Returns a `Vec`, not an `Option`, because ONE Anthropic frame can carry TWO
/// facts.** `message_delta` holds both the output-token count and the
/// `stop_reason`, and collapsing it to a single event is how the stop reason
/// went unread for the life of the adapter (B-354).
fn parse_anthropic_sse_event(data: &str) -> Result<Vec<ProviderEvent>> {
    let v: Value = serde_json::from_str(data).context("invalid SSE JSON")?;
    let event_type = v["type"].as_str().unwrap_or("");

    let mut events: Vec<ProviderEvent> = Vec::new();
    let event = match event_type {
        "content_block_delta" => {
            let delta_type = v["delta"]["type"].as_str().unwrap_or("");
            match delta_type {
                "text_delta" => {
                    let text = v["delta"]["text"].as_str().unwrap_or("").to_owned();
                    Some(ProviderEvent::StreamChunk { delta: text })
                }
                "thinking_delta" => {
                    let thinking = v["delta"]["thinking"].as_str().unwrap_or("").to_owned();
                    Some(ProviderEvent::ThinkingDelta { delta: thinking })
                }
                "input_json_delta" => {
                    let index = v["index"].as_u64().unwrap_or(0) as usize;
                    let partial = v["delta"]["partial_json"].as_str().unwrap_or("").to_owned();
                    Some(ProviderEvent::ToolCallDelta {
                        index,
                        id: None,
                        name: None,
                        input_delta: partial,
                    })
                }
                _ => None,
            }
        }
        "content_block_start" => {
            // Capture tool_use block start to get id + name
            if v["content_block"]["type"].as_str() == Some("tool_use") {
                let index = v["index"].as_u64().unwrap_or(0) as usize;
                let id = v["content_block"]["id"].as_str().map(str::to_owned);
                let name = v["content_block"]["name"].as_str().map(str::to_owned);
                Some(ProviderEvent::ToolCallDelta {
                    index,
                    id,
                    name,
                    input_delta: String::new(),
                })
            } else {
                None
            }
        }
        "message_delta" => {
            // B-354: the stop reason rides on the SAME frame as the usage
            // update. `Vec` return exists for this one case.
            if let Some(reason) = v["delta"]["stop_reason"]
                .as_str()
                .and_then(FinishReason::from_anthropic_stop_reason)
            {
                events.push(ProviderEvent::Finish { reason });
            }
            // Usage update in streaming mode
            if let Some(usage) = v["usage"].as_object() {
                let output_tokens = usage
                    .get("output_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;
                Some(ProviderEvent::UsageUpdate {
                    input_tokens: 0,
                    output_tokens,
                    cache_read: None,
                    cache_creation: None,
                    cost_usd: None,
                    // RI-05 / M11: Anthropic has no reasoning-token field on the wire.
                    reasoning: None,
                })
            } else {
                None
            }
        }
        "message_start" => {
            // RI-05 / B-444: the served model and the message id live on this frame.
            let id = v["message"]["id"].as_str().map(str::to_owned);
            let model = v["message"]["model"].as_str().map(str::to_owned);
            if id.is_some() || model.is_some() {
                events.push(ProviderEvent::ResponseMeta {
                    id,
                    model,
                    system_fingerprint: None,
                });
            }
            if let Some(usage) = v["message"]["usage"].as_object() {
                let input_tokens = usage
                    .get("input_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;
                let cache_read = usage
                    .get("cache_read_input_tokens")
                    .and_then(|v| v.as_u64())
                    .map(|n| n as u32);
                let cache_creation = usage
                    .get("cache_creation_input_tokens")
                    .and_then(|v| v.as_u64())
                    .map(|n| n as u32);
                Some(ProviderEvent::UsageUpdate {
                    input_tokens,
                    output_tokens: 0,
                    cache_read,
                    cache_creation,
                    cost_usd: None,
                    // RI-05 / M11: Anthropic has no reasoning-token field on the wire.
                    reasoning: None,
                })
            } else {
                None
            }
        }
        "message_stop" => None,
        "ping" => None,
        _ => None,
    };

    events.extend(event);
    Ok(events)
}

// ── Anthropic-native request/response types ──────────────────────────────────

#[derive(Debug, Serialize)]
struct AnthropicRequest {
    model: String,
    messages: Vec<AnthropicMessage>,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<AnthropicTool>>,
    /// B-355, translated: Anthropic spells the modes `auto` / `any` / `tool`.
    /// There is no `none` — that is expressed by omitting `tools` entirely.
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<Value>,
    /// GWY-48. Forwarded so a parameter the span RECORDS is a parameter the
    /// provider actually RECEIVED. `skip_serializing_if`, so a request that did
    /// not send it serialises byte-identically to before this field existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f32>,
    /// **B-363 — the field this adapter simply did not have.** A caller who set
    /// `temperature` on a Claude model got the provider's default and no signal
    /// that their instruction had been discarded: `AnthropicRequest` carried no
    /// such field and `from_universal` never read `req.temperature`. Same shape as
    /// B-355 (`tool_choice` dropped) and B-353 (`tool_calls` dropped), and this one
    /// reached ~94% of prod traffic.
    ///
    /// **This is a BEHAVIOUR CHANGE, deliberately taken (founder, 2026-09-08).** An
    /// existing caller who has been sending `temperature` to Claude through this
    /// gateway will now get different sampling — because they will finally get the
    /// sampling they asked for. Honouring an explicit parameter is the correct
    /// direction; silently discarding it was the defect.
    ///
    /// `skip_serializing_if`, so a request that sent none is byte-identical on the
    /// wire to before this field existed — the change is scoped exactly to callers
    /// who were being ignored.
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    /// OG-03. OpenAI `stop` → Anthropic `stop_sequences`.
    #[serde(skip_serializing_if = "Option::is_none")]
    stop_sequences: Option<Vec<String>>,
    /// OG-03. `reasoning_effort` → `thinking`, per the reference table
    /// (`translation_policy`); never a literal budget here.
    #[serde(skip_serializing_if = "Option::is_none")]
    thinking: Option<Value>,
    /// OG-03. `{effort}` (adaptive-thinking models) and/or `{format}` (a `json_schema`
    /// `response_format`) — Anthropic keeps both under one `output_config`.
    #[serde(skip_serializing_if = "Option::is_none")]
    output_config: Option<Value>,
    /// OG-03. OpenAI `user` → `metadata.user_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<Value>,
    stream: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct AnthropicMessage {
    role: AnthropicRole,
    content: AnthropicContent,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum AnthropicRole {
    User,
    Assistant,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum AnthropicContent {
    Text(String),
    Blocks(Vec<Value>),
}

#[derive(Debug, Serialize)]
struct AnthropicTool {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    input_schema: Value,
}

impl AnthropicRequest {
    fn from_universal(req: ChatRequest) -> Result<Self> {
        // OG-03: resolved FIRST, while `req` is still whole. `check_supported` has already
        // refused anything unmappable; this re-derives the same value from the same
        // function, so the two cannot disagree.
        let thinking_cfg = crate::request_support::anthropic_thinking_for(&req)
            .map_err(|u| anyhow::anyhow!("{}", u.message))?;
        let mut output_config = serde_json::Map::new();
        let thinking = match thinking_cfg {
            None | Some(AnthropicThinking::Omit) => None,
            Some(AnthropicThinking::Disabled) => Some(serde_json::json!({ "type": "disabled" })),
            Some(AnthropicThinking::BetweenTools) => {
                Some(serde_json::json!({ "type": "between_tools" }))
            }
            Some(AnthropicThinking::Adaptive { effort }) => {
                output_config.insert("effort".into(), Value::String(effort));
                Some(serde_json::json!({ "type": "adaptive" }))
            }
            Some(AnthropicThinking::Budget(n)) => {
                Some(serde_json::json!({ "type": "enabled", "budget_tokens": n }))
            }
        };
        if let Some(schema) = req
            .response_format
            .as_ref()
            .filter(|rf| rf.get("type").and_then(Value::as_str) == Some("json_schema"))
            .and_then(|rf| rf.get("json_schema"))
            .and_then(|js| js.get("schema"))
        {
            output_config.insert(
                "format".into(),
                serde_json::json!({ "type": "json_schema", "schema": schema }),
            );
        }
        let output_config = (!output_config.is_empty()).then_some(Value::Object(output_config));
        let stop_sequences = req.stop.as_ref().map(|s| {
            s.sequences()
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        });
        let metadata = req
            .user
            .as_ref()
            .map(|u| serde_json::json!({ "user_id": u }));
        let max_tokens = req
            .max_completion_tokens
            .or(req.max_tokens)
            .unwrap_or(DEFAULT_MAX_TOKENS);
        let no_parallel_tools = req.parallel_tool_calls == Some(false);
        let mut system: Option<String> = req.system.clone();
        let mut messages: Vec<AnthropicMessage> = Vec::with_capacity(req.messages.len());

        for msg in req.messages {
            match msg.role {
                Role::System => {
                    // Merge system messages into the system field
                    let text = match msg.content {
                        MessageContent::Text(t) => t,
                        MessageContent::Parts(_) => bail!("system message must be text"),
                    };
                    system = Some(match system {
                        Some(existing) => format!("{existing}\n{text}"),
                        None => text,
                    });
                }
                Role::User => messages.push(AnthropicMessage {
                    role: AnthropicRole::User,
                    content: translate_content(msg.content)?,
                }),
                Role::Assistant => messages.push(AnthropicMessage {
                    role: AnthropicRole::Assistant,
                    // B-356 (the outbound half): an assistant turn replayed from
                    // history carries its `tool_calls` in the OpenAI-shaped
                    // sibling field, and Anthropic requires them as `tool_use`
                    // CONTENT BLOCKS immediately before the matching
                    // `tool_result`. Dropping them — which is what happened
                    // until this line — makes Anthropic reject the very next
                    // message with "tool_result without tool_use", so accepting
                    // the OpenAI history shape on the way IN would have bought
                    // the caller a provider 400 instead of a gateway 400.
                    content: append_tool_use_blocks(
                        translate_content(msg.content)?,
                        msg.tool_calls.as_deref(),
                    ),
                }),
                Role::Tool => {
                    // Tool results go as user messages with tool_result content blocks
                    let tool_use_id = msg.tool_call_id.unwrap_or_default();
                    let result_text = match msg.content {
                        MessageContent::Text(t) => t,
                        MessageContent::Parts(_) => bail!("tool result must be text"),
                    };
                    messages.push(AnthropicMessage {
                        role: AnthropicRole::User,
                        content: AnthropicContent::Blocks(vec![serde_json::json!({
                            "type": "tool_result",
                            "tool_use_id": tool_use_id,
                            "content": result_text,
                        })]),
                    });
                }
            }
        }

        // B-355. Anthropic has no `none`, and the documented way to say it is to
        // send no tools at all — so `none` DROPS the tool definitions rather
        // than being silently ignored (which is the defect being fixed) or
        // downgraded to `auto` (which would be worse: the model could then call
        // a tool the caller explicitly forbade).
        let forbid_tools = matches!(req.tool_choice, Some(ToolChoice::None));
        let tool_choice = match &req.tool_choice {
            None | Some(ToolChoice::None) => None,
            Some(ToolChoice::Auto) => Some(serde_json::json!({ "type": "auto" })),
            Some(ToolChoice::Required) => Some(serde_json::json!({ "type": "any" })),
            Some(ToolChoice::Function { name }) => {
                Some(serde_json::json!({ "type": "tool", "name": name }))
            }
        };

        // OG-03: `parallel_tool_calls: false` is `disable_parallel_tool_use: true` INSIDE the
        // tool_choice object. With tools offered and no explicit choice, the choice is
        // `auto` — Anthropic's own default — so the flag has somewhere to live.
        let has_tools = req.tools.as_ref().is_some_and(|t| !t.is_empty());
        let tool_choice = match tool_choice {
            Some(mut tc) if no_parallel_tools => {
                if let Some(obj) = tc.as_object_mut() {
                    obj.insert("disable_parallel_tool_use".into(), Value::Bool(true));
                }
                Some(tc)
            }
            None if no_parallel_tools && has_tools && !forbid_tools => {
                Some(serde_json::json!({ "type": "auto", "disable_parallel_tool_use": true }))
            }
            other => other,
        };

        let tools = if forbid_tools {
            None
        } else {
            req.tools.map(|tools| {
                tools
                    .into_iter()
                    .map(|t| AnthropicTool {
                        name: t.name,
                        description: t.description,
                        input_schema: t.input_schema,
                    })
                    .collect()
            })
        };

        Ok(Self {
            model: req.model,
            messages,
            max_tokens,
            system,
            tools,
            tool_choice,
            // ALWAYS TRUE, REGARDLESS OF WHAT THE CALLER ASKED FOR.
            //
            // This adapter has exactly one response reader — `build_event_stream`
            // — and it is an SSE parser: it reads `data:` lines off
            // `response.bytes_stream()`. Anthropic honours `stream: false` by
            // returning a SINGLE JSON OBJECT, which that parser cannot see, so it
            // yields no events and the caller gets an empty completion.
            //
            // THE BUG THIS FIXES, observed on prod 2026-08-22 with unique prompts
            // so no cache was involved:
            //     explicit "stream": false  -> content "", usage {0,0,0}, HTTP 200
            //     "stream" omitted          -> correct content and usage
            //     "stream": true            -> correct
            //     vertex, explicit false    -> correct (different adapter)
            // Omitting the field worked only because `unwrap_or(true)` defaulted
            // it, which is why this went unnoticed: our own dogfood driver and
            // canary both stream, and a 200 carrying an empty completion is the
            // quietest failure this system can produce. Prod is 94% Anthropic.
            //
            // The caller's `stream` choice is honoured ONE LAYER UP: the handler
            // buffers this event stream into a `chat.completion` for a
            // non-streaming client, which is how the vertex path already behaves.
            // `:410` (the health-probe request) already hardcodes `Some(true)` for
            // the same reason. Streaming upstream is not an optimisation here, it
            // is the adapter's only supported wire format.
            top_p: req.top_p,
            // B-363. Forwarded VERBATIM — Anthropic's `temperature` is the same
            // 0.0–1.0-and-above scalar the OpenAI-shaped request carries, so there
            // is no translation to get wrong. `None` stays absent.
            temperature: req.temperature,
            stop_sequences,
            thinking,
            output_config,
            metadata,
            stream: true,
        })
    }
}

/// Append `tool_use` blocks for an assistant turn's `tool_calls`.
///
/// Anthropic carries a model's tool calls as content BLOCKS; OpenAI carries
/// them as a sibling `tool_calls` array. A history replayed from an
/// OpenAI-shaped client therefore arrives with the calls in the sibling field
/// and nothing in `content`, and Anthropic rejects the following `tool_result`
/// unless the `tool_use` precedes it. Text content, when present, is preserved
/// and the blocks are appended after it — the order Anthropic documents.
fn append_tool_use_blocks(
    content: AnthropicContent,
    tool_calls: Option<&[tracelane_shared::ToolCall]>,
) -> AnthropicContent {
    let Some(calls) = tool_calls.filter(|c| !c.is_empty()) else {
        // No tool calls: byte-identical to the pre-B-356 translation.
        return content;
    };
    let mut blocks = match content {
        AnthropicContent::Blocks(b) => b,
        AnthropicContent::Text(t) if t.is_empty() => Vec::new(),
        AnthropicContent::Text(t) => vec![serde_json::json!({ "type": "text", "text": t })],
    };
    blocks.extend(calls.iter().map(|c| {
        serde_json::json!({
            "type": "tool_use",
            "id": c.id,
            "name": c.name,
            "input": c.input,
        })
    }));
    AnthropicContent::Blocks(blocks)
}

fn translate_content(content: MessageContent) -> Result<AnthropicContent> {
    match content {
        MessageContent::Text(t) => Ok(AnthropicContent::Text(t)),
        MessageContent::Parts(parts) => {
            let blocks = parts
                .into_iter()
                .map(translate_part)
                .collect::<Result<Vec<Value>>>()?;
            Ok(AnthropicContent::Blocks(blocks))
        }
    }
}

/// OG-03 (D2). OpenAI-shaped parts are TRANSLATED, not serialised verbatim: an `image_url`
/// part went out as `{"type":"image_url",…}`, which Anthropic does not accept. Text and
/// tool blocks already carry Anthropic's own names and pass through as before.
///
/// `check_supported` has refused every part this cannot map before dispatch; the `bail!`s
/// are defence in depth, never the user-facing refusal.
fn translate_part(part: ContentPart) -> Result<Value> {
    match part {
        ContentPart::ImageUrl { image_url } => {
            if let Some((media_type, data)) = crate::request_support::split_data_uri(&image_url.url)
            {
                Ok(serde_json::json!({
                    "type": "image",
                    "source": { "type": "base64", "media_type": media_type, "data": data },
                }))
            } else if image_url.url.starts_with("https://") {
                // Anthropic fetches it; the gateway never does.
                Ok(serde_json::json!({
                    "type": "image",
                    "source": { "type": "url", "url": image_url.url },
                }))
            } else {
                bail!("image_url must be a data: URI or an https:// URL")
            }
        }
        ContentPart::File { file } => {
            let Some(data_uri) = file.file_data.as_deref() else {
                bail!("a file part needs file_data for Anthropic");
            };
            let Some((media_type, data)) = crate::request_support::split_data_uri(data_uri) else {
                bail!("file_data must be a data: URI");
            };
            Ok(serde_json::json!({
                "type": "document",
                "source": { "type": "base64", "media_type": media_type, "data": data },
            }))
        }
        ContentPart::InputAudio { .. } => bail!("audio input is not supported by Anthropic"),
        other => Ok(serde_json::to_value(other).unwrap_or(Value::Null)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RI-05 / B-444: `message_start` carries the served model and the message id.
    #[test]
    fn message_start_emits_response_meta_before_its_usage() {
        let frame = r#"{"type":"message_start","message":{"id":"msg_01XFDUDYJgAACzvnptvVoYEL","type":"message","role":"assistant","model":"claude-sonnet-4-6-20260301","usage":{"input_tokens":25,"output_tokens":1}}}"#;
        let events = parse_anthropic_sse_event(frame).unwrap();
        match &events[0] {
            ProviderEvent::ResponseMeta {
                id,
                model,
                system_fingerprint,
            } => {
                assert_eq!(id.as_deref(), Some("msg_01XFDUDYJgAACzvnptvVoYEL"));
                assert_eq!(model.as_deref(), Some("claude-sonnet-4-6-20260301"));
                assert!(system_fingerprint.is_none(), "Anthropic has no such field");
            }
            other => panic!("ResponseMeta must come first, got {other:?}"),
        }
        assert!(matches!(
            events[1],
            ProviderEvent::UsageUpdate {
                input_tokens: 25,
                ..
            }
        ));
    }
    use tracelane_shared::{ChatRequest, Message, MessageContent, Role};

    /// **The upstream request is ALWAYS `stream: true`, whatever the caller asked.**
    ///
    /// This is the regression test for the 2026-08-22 prod defect: an explicit
    /// `"stream": false` made `to_anthropic_request` forward `false`, Anthropic
    /// returned a single JSON object, and `build_event_stream` — an SSE parser —
    /// saw no `data:` lines and produced an EMPTY completion with a 200.
    ///
    /// It is written against the THREE inputs that must all agree, because the
    /// defect was invisible on two of them: omitting the field already defaulted
    /// to `true` via `unwrap_or(true)`, and `Some(true)` was obviously fine. Only
    /// `Some(false)` was broken, so a test that exercised the common case would
    /// have stayed green — which is exactly what happened for the feature's whole
    /// life. Asserting all three is what makes this a control rather than a
    /// coincidence.
    #[test]
    fn upstream_is_always_streaming_whatever_the_caller_asked() {
        for asked in [Some(false), Some(true), None] {
            let mut req = make_simple_request();
            req.stream = asked;
            let built = AnthropicRequest::from_universal(req).expect("request must build");
            assert!(
                built.stream,
                "caller stream={asked:?} must still be streamed upstream — this \
                 adapter's only response reader is an SSE parser, so a \
                 non-streaming upstream body yields an empty completion"
            );
        }
    }

    // ── B-355: tool_choice, translated rather than dropped ──────────────────

    /// OpenAI's vocabulary → Anthropic's. `required` is Anthropic's `any`, a
    /// named function is `{"type":"tool","name":…}`, and `auto` is explicit
    /// rather than omitted so the wire says what the caller asked for.
    #[test]
    fn tool_choice_translates_to_anthropics_vocabulary() {
        use tracelane_shared::ToolChoice;
        for (asked, want) in [
            (ToolChoice::Auto, serde_json::json!({ "type": "auto" })),
            (ToolChoice::Required, serde_json::json!({ "type": "any" })),
            (
                ToolChoice::Function {
                    name: "get_weather".into(),
                },
                serde_json::json!({ "type": "tool", "name": "get_weather" }),
            ),
        ] {
            let mut req = make_request_with_tools();
            req.tool_choice = Some(asked.clone());
            let built = AnthropicRequest::from_universal(req).expect("request must build");
            assert_eq!(built.tool_choice.as_ref(), Some(&want), "for {asked:?}");
            assert!(
                built.tools.is_some(),
                "tools must still be sent for {asked:?}"
            );
        }
    }

    /// **Anthropic has no `none`.** The documented way to say it is to send no
    /// tools at all — so `none` DROPS the definitions rather than being ignored
    /// (the B-355 defect) or downgraded to `auto` (worse: the model could then
    /// call a tool the caller explicitly forbade).
    #[test]
    fn tool_choice_none_omits_the_tools_entirely() {
        use tracelane_shared::ToolChoice;
        let mut req = make_request_with_tools();
        req.tool_choice = Some(ToolChoice::None);
        let built = AnthropicRequest::from_universal(req).expect("request must build");
        assert!(built.tool_choice.is_none(), "Anthropic has no `none` mode");
        assert!(
            built.tools.is_none(),
            "`none` must remove the tools, or the model may still call one"
        );
    }

    /// The control: a request that never mentioned `tool_choice` must reach the
    /// wire exactly as it did before B-355 — no key at all.
    #[test]
    fn a_request_without_tool_choice_is_unchanged() {
        let built =
            AnthropicRequest::from_universal(make_request_with_tools()).expect("request builds");
        assert!(built.tool_choice.is_none());
        assert!(built.tools.is_some());
        let wire = serde_json::to_value(&built).expect("serialize");
        assert!(
            wire.get("tool_choice").is_none(),
            "an absent tool_choice must not reach the wire: {wire}"
        );
    }

    // ── B-356 (outbound half): an assistant turn's tool_calls ────────────────

    /// **Accepting the OpenAI history shape on the way IN is only half the
    /// round trip.** Anthropic carries a model's tool calls as `tool_use`
    /// CONTENT BLOCKS and rejects the following `tool_result` unless one
    /// precedes it — so an assistant turn whose calls live in the sibling
    /// `tool_calls` field must be rebuilt into blocks, or fixing the 400 in the
    /// gateway just buys the caller a 400 from Anthropic.
    #[test]
    fn an_assistant_turns_tool_calls_become_tool_use_blocks() {
        use tracelane_shared::ToolCall;
        let mut req = make_request_with_tools();
        req.messages.push(Message {
            role: Role::Assistant,
            content: MessageContent::Text(String::new()),
            tool_call_id: None,
            tool_calls: Some(vec![ToolCall {
                id: "toolu_1".into(),
                name: "get_weather".into(),
                input: serde_json::json!({ "city": "Paris" }),
            }]),
        });
        req.messages.push(Message {
            role: Role::Tool,
            content: MessageContent::Text("18C".into()),
            tool_call_id: Some("toolu_1".into()),
            tool_calls: None,
        });
        let built = AnthropicRequest::from_universal(req).expect("request builds");

        let assistant = serde_json::to_value(&built.messages[1]).expect("serialize");
        assert_eq!(assistant["role"], "assistant");
        assert_eq!(
            assistant["content"],
            serde_json::json!([{
                "type": "tool_use",
                "id": "toolu_1",
                "name": "get_weather",
                "input": { "city": "Paris" }
            }]),
            "an empty text turn becomes tool_use blocks only"
        );

        // And the tool RESULT — already correct before this change, asserted
        // here because the two must line up for the loop to work at all.
        let result = serde_json::to_value(&built.messages[2]).expect("serialize");
        assert_eq!(result["role"], "user");
        assert_eq!(
            result["content"],
            serde_json::json!([{
                "type": "tool_result",
                "tool_use_id": "toolu_1",
                "content": "18C"
            }])
        );
    }

    /// Text and a tool call in the same turn: the text block comes FIRST, which
    /// is the order Anthropic documents.
    #[test]
    fn text_is_preserved_before_the_tool_use_blocks() {
        use tracelane_shared::ToolCall;
        let mut req = make_request_with_tools();
        req.messages.push(Message {
            role: Role::Assistant,
            content: MessageContent::Text("Let me check.".into()),
            tool_call_id: None,
            tool_calls: Some(vec![ToolCall {
                id: "toolu_2".into(),
                name: "get_weather".into(),
                input: serde_json::json!({}),
            }]),
        });
        let built = AnthropicRequest::from_universal(req).expect("request builds");
        let assistant = serde_json::to_value(&built.messages[1]).expect("serialize");
        assert_eq!(assistant["content"][0]["type"], "text");
        assert_eq!(assistant["content"][0]["text"], "Let me check.");
        assert_eq!(assistant["content"][1]["type"], "tool_use");
    }

    /// The control: an assistant turn with NO tool calls translates exactly as
    /// it did before — a plain string, not a one-element block array.
    #[test]
    fn an_assistant_turn_without_tool_calls_is_unchanged() {
        let mut req = make_request_with_tools();
        req.messages.push(Message {
            role: Role::Assistant,
            content: MessageContent::Text("Sunny.".into()),
            tool_call_id: None,
            tool_calls: None,
        });
        let built = AnthropicRequest::from_universal(req).expect("request builds");
        let assistant = serde_json::to_value(&built.messages[1]).expect("serialize");
        assert_eq!(assistant["content"], serde_json::json!("Sunny."));
    }

    fn make_request_with_tools() -> ChatRequest {
        let mut req = make_simple_request();
        req.tools = Some(vec![tracelane_shared::Tool {
            name: "get_weather".into(),
            description: None,
            input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        }]);
        req
    }

    fn make_simple_request() -> ChatRequest {
        ChatRequest {
            top_p: None,
            seed: None,
            logprobs: None,
            top_logprobs: None,
            model: "claude-sonnet-4-6".into(),
            messages: vec![Message {
                role: Role::User,
                content: MessageContent::Text("hello".into()),
                tool_call_id: None,
                tool_calls: None,
            }],
            tools: None,
            tool_choice: None,
            max_tokens: Some(100),
            temperature: None,
            stream: Some(true),
            system: None,
            metadata: None,
            ..Default::default()
        }
    }

    // ── OG-03 D2: an OpenAI-shaped image part must be translated for Anthropic ─

    #[test]
    fn og03_d2_anthropic_receives_an_image_block_not_an_openai_image_url_part() {
        use tracelane_shared::{ContentPart, ImageUrl};
        let mut req = make_simple_request();
        req.messages = vec![Message {
            role: Role::User,
            content: MessageContent::Parts(vec![ContentPart::ImageUrl {
                image_url: ImageUrl {
                    url: "data:image/png;base64,AAAA".into(),
                    detail: None,
                },
            }]),
            tool_call_id: None,
            tool_calls: None,
        }];
        let wire = serde_json::to_value(AnthropicRequest::from_universal(req).unwrap()).unwrap();
        let block = &wire["messages"][0]["content"][0];
        assert_ne!(
            block["type"], "image_url",
            "Anthropic does not accept image_url blocks: {wire}"
        );
        assert_eq!(block["type"], "image", "{wire}");
        assert_eq!(block["source"]["type"], "base64");
        assert_eq!(block["source"]["media_type"], "image/png");
        assert_eq!(block["source"]["data"], "AAAA");
    }

    // ── OG-03: every translated field, asserted on the exact upstream JSON ────

    fn og03_wire(req: ChatRequest) -> serde_json::Value {
        serde_json::to_value(AnthropicRequest::from_universal(req).expect("builds")).expect("ser")
    }

    #[test]
    fn og03_stop_cap_user_and_json_schema_reach_the_anthropic_wire() {
        let mut req = make_simple_request();
        req.stop = Some(tracelane_shared::Stop::Many(vec![
            "END".into(),
            "STOP".into(),
        ]));
        req.max_tokens = Some(100);
        req.max_completion_tokens = Some(300);
        req.user = Some("end-user-1".into());
        req.response_format = Some(serde_json::json!({
            "type": "json_schema",
            "json_schema": {"name": "x", "schema": {"type": "object", "properties": {}}}
        }));
        let wire = og03_wire(req);
        assert_eq!(wire["stop_sequences"], serde_json::json!(["END", "STOP"]));
        assert_eq!(wire["max_tokens"], 300, "max_completion_tokens wins");
        assert_eq!(
            wire["metadata"],
            serde_json::json!({"user_id": "end-user-1"})
        );
        assert_eq!(
            wire["output_config"]["format"],
            serde_json::json!({"type": "json_schema", "schema": {"type": "object", "properties": {}}})
        );
        // The control: a plain request carries none of the new keys.
        let plain = og03_wire(make_simple_request());
        for k in ["stop_sequences", "thinking", "output_config", "metadata"] {
            assert!(
                plain.get(k).is_none(),
                "{k} leaked into a plain request: {plain}"
            );
        }
    }

    #[test]
    fn og03_reasoning_effort_becomes_adaptive_effort_or_a_clamped_budget_per_model() {
        // An adaptive-only model: thinking:{adaptive} + output_config.effort, NO budget.
        let mut req = make_simple_request();
        req.model = "claude-opus-5-5".into();
        req.reasoning_effort = Some("xhigh".into());
        let wire = og03_wire(req);
        assert_eq!(wire["thinking"], serde_json::json!({"type": "adaptive"}));
        assert_eq!(wire["output_config"]["effort"], "xhigh");
        assert!(wire["thinking"].get("budget_tokens").is_none());
        // An extended-only model: a budget from the table, clamped below max_tokens.
        let mut req = make_simple_request();
        req.model = "claude-haiku-4-5".into();
        req.reasoning_effort = Some("medium".into());
        req.max_tokens = Some(4000);
        let wire = og03_wire(req);
        assert_eq!(
            wire["thinking"],
            serde_json::json!({"type": "enabled", "budget_tokens": 3999})
        );
        assert!(wire.get("output_config").is_none());
        // effort `none` where the model can switch thinking off.
        let mut req = make_simple_request();
        req.model = "claude-opus-4-8".into();
        req.reasoning_effort = Some("none".into());
        assert_eq!(
            og03_wire(req)["thinking"],
            serde_json::json!({"type": "disabled"})
        );
    }

    #[test]
    fn og03_parallel_tool_calls_false_becomes_disable_parallel_tool_use() {
        let mut req = make_request_with_tools();
        req.parallel_tool_calls = Some(false);
        let wire = og03_wire(req);
        assert_eq!(
            wire["tool_choice"],
            serde_json::json!({"type": "auto", "disable_parallel_tool_use": true})
        );
        let mut req = make_request_with_tools();
        req.parallel_tool_calls = Some(false);
        req.tool_choice = Some(ToolChoice::Required);
        assert_eq!(
            og03_wire(req)["tool_choice"],
            serde_json::json!({"type": "any", "disable_parallel_tool_use": true})
        );
        // `true` is Anthropic's default: nothing is sent.
        let mut req = make_request_with_tools();
        req.parallel_tool_calls = Some(true);
        assert!(og03_wire(req).get("tool_choice").is_none());
    }

    #[test]
    fn og03_https_image_and_pdf_parts_are_translated() {
        use tracelane_shared::{ContentPart, FilePart, ImageUrl};
        let mut req = make_simple_request();
        req.messages = vec![Message {
            role: Role::User,
            content: MessageContent::Parts(vec![
                ContentPart::ImageUrl {
                    image_url: ImageUrl {
                        url: "https://example.com/a.png".into(),
                        detail: None,
                    },
                },
                ContentPart::File {
                    file: FilePart {
                        file_data: Some("data:application/pdf;base64,AAAA".into()),
                        ..Default::default()
                    },
                },
            ]),
            tool_call_id: None,
            tool_calls: None,
        }];
        let wire = og03_wire(req);
        let blocks = &wire["messages"][0]["content"];
        // The gateway does not fetch: Anthropic is handed the URL.
        assert_eq!(
            blocks[0],
            serde_json::json!({"type": "image", "source": {"type": "url", "url": "https://example.com/a.png"}})
        );
        assert_eq!(
            blocks[1],
            serde_json::json!({"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": "AAAA"}})
        );
    }

    #[test]
    fn translates_simple_user_message() {
        let req = make_simple_request();
        let translated = AnthropicRequest::from_universal(req).unwrap();
        assert_eq!(translated.messages.len(), 1);
        assert!(matches!(translated.messages[0].role, AnthropicRole::User));
        assert_eq!(translated.max_tokens, 100);
        assert!(translated.stream);
    }

    #[test]
    fn cache_control_is_preserved_on_content_blocks() {
        //  PP-G8: prompt-caching markers on content blocks must survive
        // translation into the Anthropic block (the gateway used to drop them,
        // silently breaking customers' prompt caching — they'd pay full price).
        use serde_json::json;
        use tracelane_shared::ContentPart;
        let mut req = make_simple_request();
        req.messages = vec![Message {
            role: Role::User,
            content: MessageContent::Parts(vec![ContentPart::Text {
                text: "large cached context".into(),
                cache_control: Some(json!({ "type": "ephemeral" })),
            }]),
            tool_call_id: None,
            tool_calls: None,
        }];
        let translated = AnthropicRequest::from_universal(req).unwrap();
        let block = match &translated.messages[0].content {
            AnthropicContent::Blocks(blocks) => &blocks[0],
            other => panic!("expected content blocks, got {other:?}"),
        };
        assert_eq!(
            block.get("cache_control"),
            Some(&json!({ "type": "ephemeral" })),
            "cache_control must survive into the Anthropic block"
        );
        assert_eq!(block.get("type"), Some(&json!("text")));
    }

    #[test]
    fn extracts_system_message() {
        let mut req = make_simple_request();
        req.messages.insert(
            0,
            Message {
                role: Role::System,
                content: MessageContent::Text("you are helpful".into()),
                tool_call_id: None,
                tool_calls: None,
            },
        );
        let translated = AnthropicRequest::from_universal(req).unwrap();
        assert_eq!(translated.system.as_deref(), Some("you are helpful"));
        assert_eq!(translated.messages.len(), 1);
    }

    /// **B-363.** A `temperature` the caller sent must reach the Anthropic wire.
    /// Before this fix the field did not exist on `AnthropicRequest` at all, so the
    /// value was discarded with a 200 and no signal — on the adapter carrying ~94%
    /// of prod traffic. Asserted on the SERIALIZED body, not the struct: the wire
    /// is what the provider sees.
    #[test]
    fn a_temperature_the_caller_sent_reaches_the_anthropic_wire() {
        let mut req = make_simple_request();
        req.temperature = Some(0.2);
        let translated = AnthropicRequest::from_universal(req).unwrap();
        assert_eq!(translated.temperature, Some(0.2));
        let wire = serde_json::to_string(&translated).expect("serialises");
        assert!(wire.contains(r#""temperature":0.2"#), "got {wire}");
    }

    /// The other half, and the one that bounds the blast radius: a request that
    /// sent NO temperature must serialise byte-identically to before this field
    /// existed. So the behaviour change reaches exactly the callers who were being
    /// ignored, and nobody else.
    #[test]
    fn a_request_without_a_temperature_is_byte_identical_on_the_wire() {
        let req = make_simple_request();
        assert_eq!(req.temperature, None, "fixture precondition");
        let wire = serde_json::to_string(&AnthropicRequest::from_universal(req).unwrap())
            .expect("serialises");
        assert!(
            !wire.contains("temperature"),
            "an unsent temperature must not appear on the wire at all: {wire}"
        );
    }

    #[test]
    fn defaults_max_tokens_to_4096() {
        let mut req = make_simple_request();
        req.max_tokens = None;
        let translated = AnthropicRequest::from_universal(req).unwrap();
        assert_eq!(translated.max_tokens, 4096);
    }

    /// A `€` cut across two network chunks must reach the client whole.
    #[tokio::test]
    async fn a_character_split_across_network_chunks_survives() {
        use futures::StreamExt as _;
        let resp = crate::providers::sse_lines::response_from_chunks(vec![
            b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"price \xE2\x82",
            b"\xAC5\"}}\n\n",
        ]);
        let events: Vec<_> = build_event_stream(resp).collect().await;
        let text: String = events
            .into_iter()
            .map(|e| e.expect("stream must not error on a split character"))
            .filter_map(|e| match e {
                ProviderEvent::StreamChunk { delta } => Some(delta),
                _ => None,
            })
            .collect();
        assert_eq!(text, "price €5");
    }
}

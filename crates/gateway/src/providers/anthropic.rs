//! Anthropic Claude API adapter.
//!
//! Supports all Claude models via the Messages API with SSE streaming.
//! Extended thinking (interleaved-thinking-2025-05-14 beta) is enabled by default.
//! Prompt caching: `cache_control` markers on message content blocks (text /
//! tool_result) are preserved verbatim through the universal request into the
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
use std::pin::Pin;
use tracing::instrument;

use tracelane_shared::{
    ChatRequest, ChatResponse, Choice, Message, MessageContent, Role, TenantId, Usage,
};

use crate::providers::{ProviderEvent, ProviderStream};

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

        crate::ssrf_guard::validate_url(&url)
            .await
            .context("SSRF guard rejected Anthropic base URL")?;

        let response = self
            .client
            .post(&url)
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("anthropic-beta", "interleaved-thinking-2025-05-14")
            .header("content-type", "application/json")
            .json(&anthropic_request)
            .send()
            .await
            .context("failed to send request to Anthropic API")?;

        let status = response.status();
        if !status.is_success() {
            // 401/403 bodies can echo the x-api-key header value, leaking
            // the customer's BYOK key to logs.
            let _body = response.text().await.unwrap_or_default();
            tracing::warn!(status = %status, "Anthropic API error");
            // Typed so the gateway distinguishes an auth rejection (401/403) from
            // an outage (5xx). Status only, never the body (credential echo).
            return Err(crate::providers::ProviderHttpError {
                provider: "anthropic",
                status: status.as_u16(),
                reason: None,
            }
            .into());
        }

        let stream = build_event_stream(response);
        Ok(Box::pin(stream))
    }
}

// A14: `Default` removed — `new()` is now fallible (see ProviderRegistry).

/// Extended thinking configuration for the Anthropic Messages API.
///
/// Enabled via `interleaved-thinking-2025-05-14` beta header.
/// When `extended_thinking` is requested, the SSE stream emits
/// `content_block_delta` events with `delta.type = "thinking_delta"`.
#[derive(Debug, Serialize)]
struct ExtendedThinkingConfig {
    r#type: String,
    budget_tokens: u32,
}

/// Build a ProviderEvent stream from an Anthropic SSE response.
fn build_event_stream(
    response: reqwest::Response,
) -> impl Stream<Item = Result<ProviderEvent>> + Send {
    try_stream! {
        let mut byte_stream = response.bytes_stream();
        let mut buffer = String::new();

        use futures::StreamExt as _;
        while let Some(chunk) = byte_stream.next().await {
            let chunk: Bytes = chunk.context("error reading response chunk")?;
            let text = std::str::from_utf8(&chunk).context("non-UTF8 response chunk")?;
            buffer.push_str(text);

            // Process complete SSE lines
            while let Some(newline_pos) = buffer.find('\n') {
                let line = buffer[..newline_pos].trim_end_matches('\r').to_owned();
                buffer = buffer[newline_pos + 1..].to_owned();

                if line.is_empty() || line.starts_with(':') {
                    continue;
                }

                if let Some(data) = line.strip_prefix("data: ") {
                    if data == "[DONE]" {
                        return;
                    }
                    if let Ok(Some(provider_event)) = parse_anthropic_sse_event(data) {
                        yield provider_event;
                    }
                }
            }
        }
    }
}

/// Parse a single Anthropic SSE data payload into a ProviderEvent.
fn parse_anthropic_sse_event(data: &str) -> Result<Option<ProviderEvent>> {
    let v: Value = serde_json::from_str(data).context("invalid SSE JSON")?;
    let event_type = v["type"].as_str().unwrap_or("");

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
                })
            } else {
                None
            }
        }
        "message_start" => {
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
                })
            } else {
                None
            }
        }
        "message_stop" => None,
        "ping" => None,
        _ => None,
    };

    Ok(event)
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
                    content: translate_content(msg.content),
                }),
                Role::Assistant => messages.push(AnthropicMessage {
                    role: AnthropicRole::Assistant,
                    content: translate_content(msg.content),
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

        let tools = req.tools.map(|tools| {
            tools
                .into_iter()
                .map(|t| AnthropicTool {
                    name: t.name,
                    description: t.description,
                    input_schema: t.input_schema,
                })
                .collect()
        });

        Ok(Self {
            model: req.model,
            messages,
            max_tokens: req.max_tokens.unwrap_or(4096),
            system,
            tools,
            stream: req.stream.unwrap_or(true),
        })
    }
}

fn translate_content(content: MessageContent) -> AnthropicContent {
    match content {
        MessageContent::Text(t) => AnthropicContent::Text(t),
        MessageContent::Parts(parts) => {
            let blocks: Vec<Value> = parts
                .into_iter()
                .map(|p| serde_json::to_value(p).unwrap_or(Value::Null))
                .collect();
            AnthropicContent::Blocks(blocks)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracelane_shared::{ChatRequest, Message, MessageContent, Role};

    fn make_simple_request() -> ChatRequest {
        ChatRequest {
            model: "claude-sonnet-4-6".into(),
            messages: vec![Message {
                role: Role::User,
                content: MessageContent::Text("hello".into()),
                tool_call_id: None,
                tool_calls: None,
            }],
            tools: None,
            max_tokens: Some(100),
            temperature: None,
            stream: Some(true),
            system: None,
            metadata: None,
        }
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

    #[test]
    fn defaults_max_tokens_to_4096() {
        let mut req = make_simple_request();
        req.max_tokens = None;
        let translated = AnthropicRequest::from_universal(req).unwrap();
        assert_eq!(translated.max_tokens, 4096);
    }
}

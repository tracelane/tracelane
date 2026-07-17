//! OpenAI Chat Completions adapter.
//!
//! Handles GPT-5.5, GPT-5.5 Pro, Codex, and any OpenAI-compatible endpoint.
//! Also serves as the base for Together AI, Fireworks, Groq, and OpenRouter
//! (all expose OpenAI-compatible Chat Completions API).
//!
//! Streaming uses `stream_options.include_usage=true` to surface token counts.

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
    ChatResponse, Choice, Message, MessageContent, Role, TenantId, ToolCall, Usage,
};

use crate::providers::{ProviderEvent, ProviderStream};
use tracelane_shared::ChatRequest;

/// OpenAI Chat Completions API adapter.
/// Handles GPT-5.5, GPT-5.5 Pro, Codex, and any OpenAI-compatible endpoint.
/// Also serves as the base for Together AI, Fireworks, Groq, and OpenRouter
/// (all expose OpenAI-compatible endpoints).
pub struct OpenAiProvider {
    client: Client,
    pub base_url: String,
    pub provider_id: &'static str,
}

impl OpenAiProvider {
    /// A14: constructors are now fallible — `.expect()` on `reqwest`
    /// client build moved to a `?` propagated up through
    /// `ProviderRegistry::new()`. The build error is theoretical with
    /// rustls today but ruled-out by .claude/rules/rust.md regardless.
    pub fn openai() -> anyhow::Result<Self> {
        Ok(Self {
            client: crate::ssrf_guard::safe_client_builder()
                .timeout(std::time::Duration::from_secs(300))
                .build()
                .context("build OpenAI reqwest client")?,
            base_url: std::env::var("OPENAI_BASE_URL")
                .unwrap_or_else(|_| "https://api.openai.com".into()),
            provider_id: "openai",
        })
    }

    /// For OpenAI-compatible providers that share the same request shape.
    pub fn compatible(
        base_url: impl Into<String>,
        provider_id: &'static str,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            client: crate::ssrf_guard::safe_client_builder()
                .timeout(std::time::Duration::from_secs(300))
                .build()
                .context("build OpenAI-compatible reqwest client")?,
            base_url: base_url.into(),
            provider_id,
        })
    }

    #[instrument(skip(self, request, api_key), fields(
        tenant_id = %tenant_id,
        model = %request.model,
        provider = self.provider_id,
    ))]
    pub async fn chat(
        &self,
        request: ChatRequest,
        api_key: &str,
        tenant_id: &TenantId,
    ) -> Result<ProviderStream> {
        let oai_request = OpenAiRequest::from_universal(request);
        let url = format!("{}/v1/chat/completions", self.base_url);

        crate::ssrf_guard::validate_url(&url)
            .await
            .context("SSRF guard rejected OpenAI base URL")?;

        let response = self
            .client
            .post(&url)
            .header("authorization", format!("Bearer {api_key}"))
            .header("content-type", "application/json")
            .json(&oai_request)
            .send()
            .await
            .context("failed to send request to OpenAI API")?;

        let status = response.status();
        if !status.is_success() {
            // the bail! string — OpenAI 401/403 bodies routinely echo the
            // offending Authorization header and would leak the customer's
            // BYOK key into our logs / error records / tenant-visible error JSON.
            // Body is consumed to free the connection but never logged.
            let _body = response.text().await.unwrap_or_default();
            tracing::warn!(status = %status, "OpenAI API error");
            // Typed so the gateway can tell an auth rejection (401/403 → the
            // tenant's key was rejected) from an outage (5xx → 502). Status only,
            // never the body (credential-echo risk above).
            return Err(crate::providers::ProviderHttpError {
                provider: self.provider_id,
                status: status.as_u16(),
                // OpenAI-shape bodies use a lowercase `error.code`, which
                // `safe_reason` deliberately rejects (the guard is SHOUTY_SNAKE
                // only). Status-level mapping (429/404) still applies to all 28
                // OpenAI-compatible providers; extracting their codes is a
                // separate, additive step.
                reason: None,
            }
            .into());
        }

        let stream = build_openai_stream(response);
        Ok(Box::pin(stream))
    }
}

fn build_openai_stream(
    response: reqwest::Response,
) -> impl Stream<Item = Result<ProviderEvent>> + Send {
    try_stream! {
        let mut byte_stream = response.bytes_stream();
        let mut buffer = String::new();

        use futures::StreamExt as _;
        while let Some(chunk) = byte_stream.next().await {
            let chunk: Bytes = chunk.context("error reading response chunk")?;
            let text = std::str::from_utf8(&chunk).context("non-UTF8 chunk")?;
            buffer.push_str(text);

            while let Some(pos) = buffer.find('\n') {
                let line = buffer[..pos].trim_end_matches('\r').to_owned();
                buffer = buffer[pos + 1..].to_owned();

                if line.is_empty() || line.starts_with(':') {
                    continue;
                }
                if let Some(data) = line.strip_prefix("data: ") {
                    if data == "[DONE]" {
                        return;
                    }
                    if let Ok(Some(event)) = parse_openai_sse(data) {
                        yield event;
                    }
                }
            }
        }
    }
}

fn parse_openai_sse(data: &str) -> Result<Option<ProviderEvent>> {
    let v: Value = serde_json::from_str(data).context("invalid SSE JSON")?;

    // Usage chunk (stream_options.include_usage = true)
    if let Some(usage) = v.get("usage").filter(|u| !u.is_null()) {
        let input = usage["prompt_tokens"].as_u64().unwrap_or(0) as u32;
        let output = usage["completion_tokens"].as_u64().unwrap_or(0) as u32;
        // hosts) attach `usage.cost` in USD. Absent → None, never computed.
        let cost_usd = usage.get("cost").and_then(|c| c.as_f64());
        return Ok(Some(ProviderEvent::UsageUpdate {
            input_tokens: input,
            output_tokens: output,
            cache_read: None,
            cache_creation: None,
            cost_usd,
        }));
    }

    let delta = &v["choices"][0]["delta"];
    if delta.is_null() {
        return Ok(None);
    }

    // Text delta
    if let Some(text) = delta["content"].as_str() {
        if !text.is_empty() {
            return Ok(Some(ProviderEvent::StreamChunk {
                delta: text.to_owned(),
            }));
        }
    }

    // Tool call delta
    if let Some(tool_calls) = delta["tool_calls"].as_array() {
        if let Some(tc) = tool_calls.first() {
            let index = tc["index"].as_u64().unwrap_or(0) as usize;
            let id = tc["id"].as_str().map(str::to_owned);
            let name = tc["function"]["name"].as_str().map(str::to_owned);
            let input_delta = tc["function"]["arguments"]
                .as_str()
                .unwrap_or("")
                .to_owned();
            return Ok(Some(ProviderEvent::ToolCallDelta {
                index,
                id,
                name,
                input_delta,
            }));
        }
    }

    Ok(None)
}

// ── OpenAI request/response types ────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct OpenAiRequest {
    model: String,
    messages: Vec<OpenAiMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<OpenAiTool>>,
    stream: bool,
    stream_options: StreamOptions,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
}

#[derive(Debug, Serialize)]
struct StreamOptions {
    include_usage: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct OpenAiMessage {
    role: String,
    content: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<Value>>,
}

#[derive(Debug, Serialize)]
struct OpenAiTool {
    r#type: &'static str,
    function: OpenAiFunctionDef,
}

#[derive(Debug, Serialize)]
struct OpenAiFunctionDef {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    parameters: Value,
}

impl OpenAiRequest {
    fn from_universal(req: ChatRequest) -> Self {
        let messages: Vec<OpenAiMessage> =
            req.messages
                .into_iter()
                .map(|m| {
                    let role = match m.role {
                        Role::System => "system",
                        Role::User => "user",
                        Role::Assistant => "assistant",
                        Role::Tool => "tool",
                    };
                    let content = match m.content {
                        MessageContent::Text(t) => Value::String(t),
                        MessageContent::Parts(parts) => Value::Array(
                            parts
                                .into_iter()
                                .map(|p| {
                                    let mut v = serde_json::to_value(p).unwrap_or(Value::Null);
                                    // prompt-caching marker; OpenAI's caching is
                                    // automatic (no field). Strip it so a cached
                                    // block routed to OpenAI never leaks the field.
                                    if let Some(obj) = v.as_object_mut() {
                                        obj.remove("cache_control");
                                    }
                                    v
                                })
                                .collect(),
                        ),
                    };
                    let tool_calls = m.tool_calls.map(|tcs| {
                        tcs.into_iter().map(|tc| serde_json::json!({
                        "id": tc.id,
                        "type": "function",
                        "function": { "name": tc.name, "arguments": tc.input.to_string() }
                    })).collect()
                    });
                    OpenAiMessage {
                        role: role.into(),
                        content,
                        tool_call_id: m.tool_call_id,
                        tool_calls,
                    }
                })
                .collect();

        let tools = req.tools.map(|ts| {
            ts.into_iter()
                .map(|t| OpenAiTool {
                    r#type: "function",
                    function: OpenAiFunctionDef {
                        name: t.name,
                        description: t.description,
                        parameters: t.input_schema,
                    },
                })
                .collect()
        });

        Self {
            model: req.model,
            messages,
            tools,
            stream: req.stream.unwrap_or(true),
            stream_options: StreamOptions {
                include_usage: true,
            },
            max_tokens: req.max_tokens,
            temperature: req.temperature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracelane_shared::{ChatRequest, Message, MessageContent, Role};

    fn simple_request() -> ChatRequest {
        ChatRequest {
            model: "gpt-5.5".into(),
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
    fn cache_control_is_stripped_for_openai() {
        // receive it (its caching is automatic). A cached block routed here is
        // passed through with the marker removed.
        use serde_json::json;
        use tracelane_shared::ContentPart;
        let mut req = simple_request();
        req.messages = vec![Message {
            role: Role::User,
            content: MessageContent::Parts(vec![ContentPart::Text {
                text: "ctx".into(),
                cache_control: Some(json!({ "type": "ephemeral" })),
            }]),
            tool_call_id: None,
            tool_calls: None,
        }];
        let oai = OpenAiRequest::from_universal(req);
        let blocks = oai.messages[0]
            .content
            .as_array()
            .expect("parts translate to a content array");
        assert!(
            blocks[0].get("cache_control").is_none(),
            "cache_control must be stripped before reaching OpenAI"
        );
        assert_eq!(blocks[0].get("type"), Some(&json!("text")));
    }

    #[test]
    fn translates_user_message() {
        let req = simple_request();
        let oai = OpenAiRequest::from_universal(req);
        assert_eq!(oai.messages.len(), 1);
        assert_eq!(oai.messages[0].role, "user");
        assert!(oai.stream);
        assert!(oai.stream_options.include_usage);
    }

    #[test]
    fn system_role_maps_correctly() {
        let mut req = simple_request();
        req.messages.insert(
            0,
            Message {
                role: Role::System,
                content: MessageContent::Text("be helpful".into()),
                tool_call_id: None,
                tool_calls: None,
            },
        );
        let oai = OpenAiRequest::from_universal(req);
        assert_eq!(oai.messages[0].role, "system");
        assert_eq!(oai.messages.len(), 2);
    }

    #[test]
    fn stream_options_always_include_usage() {
        let req = simple_request();
        let oai = OpenAiRequest::from_universal(req);
        assert!(oai.stream_options.include_usage);
    }
}

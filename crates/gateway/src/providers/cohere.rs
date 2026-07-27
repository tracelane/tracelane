//! Cohere Chat adapter.
//!
//! Cohere's `/chat` endpoint uses a different request shape from OpenAI:
//!   - `message` (string) instead of `messages` array for the latest turn
//!   - `chat_history` array for prior turns
//!   - `connectors` for retrieval-augmented search
//!   - Streaming via `stream: true` returns newline-delimited JSON events
//!
//! This adapter translates from the universal ChatRequest to Cohere's wire format.
//!
//! Configuration env vars:
//!   COHERE_API_KEY   — Cohere API key
//!   COHERE_BASE_URL  — defaults to https://api.cohere.com/v2

use anyhow::{Context as _, Result};
use async_stream::try_stream;
use futures::Stream;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::instrument;

use crate::providers::{ProviderEvent, ProviderStream};
use tracelane_shared::{ChatRequest, Message, Role, TenantId};

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

    /// Map universal `Message` to Cohere `chat_history` + `message` split.
    /// Cohere v2 uses `messages` array like OpenAI, so translation is straightforward.
    fn translate_messages(messages: &[Message]) -> (Option<String>, Vec<Value>) {
        let history: Vec<Value> = messages
            .iter()
            .map(|m| {
                let role = match m.role {
                    Role::System => "system",
                    Role::User => "user",
                    Role::Assistant => "assistant",
                    Role::Tool => "tool",
                };
                let text = match &m.content {
                    tracelane_shared::MessageContent::Text(t) => t.clone(),
                    tracelane_shared::MessageContent::Parts(parts) => parts
                        .iter()
                        .filter_map(|p| {
                            if let tracelane_shared::ContentPart::Text { text, .. } = p {
                                Some(text.as_str())
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\n"),
                };
                serde_json::json!({ "role": role, "content": text })
            })
            .collect();

        // Last user message is `message`; rest is `chat_history`
        if let Some(last) = history.last() {
            let msg = last["content"].as_str().unwrap_or("").to_owned();
            (
                Some(msg),
                history[..history.len().saturating_sub(1)].to_vec(),
            )
        } else {
            (None, vec![])
        }
    }

    #[instrument(skip(self, request, api_key), fields(tenant_id = %tenant_id, provider = "cohere"))]
    pub async fn chat(
        &self,
        request: ChatRequest,
        api_key: &str,
        tenant_id: &TenantId,
    ) -> Result<ProviderStream> {
        let model = request
            .model
            .strip_prefix("cohere/")
            .unwrap_or(&request.model)
            .to_owned();
        let (message, chat_history) = Self::translate_messages(&request.messages);

        let mut body = serde_json::json!({
            "model": model,
            "message": message,
            "chat_history": chat_history,
            "stream": true,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
        });
        // (`parameter_definitions` keyed off the JSON-schema properties).
        // Previously the adapter dropped tools entirely — a tool-bearing
        // request silently degraded to plain chat.
        if let Some(tools) = request.tools.as_ref().filter(|t| !t.is_empty()) {
            let defs: Vec<Value> = tools.iter().map(translate_tool).collect();
            body["tools"] = Value::Array(defs);
        }

        let url = format!("{}/chat", self.base_url);

        crate::ssrf_guard::validate_url(&url)
            .await
            .context("SSRF guard rejected Cohere base URL")?;

        let response = self
            .client
            .post(&url)
            .bearer_auth(api_key)
            .json(&body)
            .send()
            .await
            .context("cohere request")?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            // 401/403 bodies can echo the Bearer token.
            let _body = response.text().await.unwrap_or_default();
            tracing::warn!(status, "Cohere API error");
            anyhow::bail!("cohere error: status {status}");
        }

        let mut byte_stream = response.bytes_stream();
        let stream = try_stream! {
            use futures::StreamExt as _;
            let mut buf = String::new();
            while let Some(chunk) = byte_stream.next().await {
                use bytes::Bytes;
                let chunk: Bytes = chunk.context("stream chunk")?;
                buf.push_str(&String::from_utf8_lossy(&chunk));
                // Cohere streams newline-delimited JSON
                let lines: Vec<String> = buf.split('\n').map(str::to_owned).collect();
                let last = lines.len().saturating_sub(1);
                buf = lines[last].clone();
                for line in &lines[..last] {
                    let line = line.trim();
                    if line.is_empty() { continue; }
                    if let Ok(v) = serde_json::from_str::<Value>(line) {
                        let event_type = v["event_type"].as_str().unwrap_or("");
                        match event_type {
                            "text-generation" => {
                                if let Some(t) = v["text"].as_str() {
                                    yield ProviderEvent::StreamChunk { delta: t.to_owned() };
                                }
                            }
                            "tool-calls-generation" => {
                                // Cohere emits complete tool calls in one event
                                // (name + full parameters), not argument deltas.
                                if let Some(calls) = v["tool_calls"].as_array() {
                                    for (i, call) in calls.iter().enumerate() {
                                        yield ProviderEvent::ToolCallDelta {
                                            index: i,
                                            id: Some(format!("cohere-tc-{i}")),
                                            name: call["name"].as_str().map(str::to_owned),
                                            input_delta: call["parameters"].to_string(),
                                        };
                                    }
                                }
                            }
                            "stream-end" => {
                                let resp = &v["response"];
                                yield ProviderEvent::UsageUpdate {
                                    input_tokens: resp["meta"]["tokens"]["input_tokens"].as_u64().unwrap_or(0) as u32,
                                    output_tokens: resp["meta"]["tokens"]["output_tokens"].as_u64().unwrap_or(0) as u32,
                                    cache_read: None,
                                    cache_creation: None,
                                    cost_usd: None,
                                };
                                return;
                            }
                            _ => {}
                        }
                    }
                }
            }
        };
        Ok(Box::pin(stream))
    }
}

/// Universal `Tool` -> Cohere tool definition. Cohere's classic `/chat` shape
/// wants `parameter_definitions: {name: {description, type, required}}`
/// rather than raw JSON schema; we map each schema property, defaulting the
/// type to `str` when the schema does not name one Cohere understands.
fn translate_tool(tool: &tracelane_shared::Tool) -> Value {
    let required: Vec<&str> = tool.input_schema["required"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let mut param_defs = serde_json::Map::new();
    if let Some(props) = tool.input_schema["properties"].as_object() {
        for (pname, pschema) in props {
            let ptype = match pschema["type"].as_str() {
                Some("integer") => "int",
                Some("number") => "float",
                Some("boolean") => "bool",
                _ => "str",
            };
            param_defs.insert(
                pname.clone(),
                serde_json::json!({
                    "description": pschema["description"].as_str().unwrap_or(""),
                    "type": ptype,
                    "required": required.contains(&pname.as_str()),
                }),
            );
        }
    }
    serde_json::json!({
        "name": tool.name,
        "description": tool.description.as_deref().unwrap_or(""),
        "parameter_definitions": param_defs,
    })
}

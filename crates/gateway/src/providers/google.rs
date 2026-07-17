//! Google Gemini provider adapter.
//!
//! Supports Gemini 3.1 Pro, Flash, and Nano via `streamGenerateContent`.
//! API key is passed as a query parameter (`?key=…`), not a Bearer header.
//! Handles thought signatures (extended reasoning), grounding/search tool,
//! and function call (functionCall/functionResponse) parts.

use anyhow::{Context as _, Result, bail};
use async_stream::try_stream;
use bytes::Bytes;
use futures::Stream;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::instrument;

use tracelane_shared::{ChatRequest, MessageContent, Role, TenantId};

use crate::providers::{ProviderEvent, ProviderStream};

/// Google Gemini API adapter.
/// Supports Gemini 3.1 Pro, Flash, and Gemini Nano via generateContent / streamGenerateContent.
///
/// Handles Gemini-specific features:
/// - Thought signatures (reasoning trace in response)
/// - grounding / search tool
/// - Inline image parts
pub struct GoogleProvider {
    client: Client,
    base_url: String,
}

impl GoogleProvider {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            client: crate::ssrf_guard::safe_client_builder()
                .timeout(std::time::Duration::from_secs(300))
                .build()
                .context("build Google reqwest client")?,
            base_url: std::env::var("GOOGLE_AI_BASE_URL")
                .unwrap_or_else(|_| "https://generativelanguage.googleapis.com".into()),
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
                .context("build Google reqwest client")?,
            base_url: base_url.into(),
        })
    }

    /// Google uses the API key as a query parameter, not a Bearer token.
    #[instrument(skip(self, request, api_key), fields(
        tenant_id = %tenant_id,
        model = %request.model,
        provider = "google",
    ))]
    pub async fn chat(
        &self,
        request: ChatRequest,
        api_key: &str,
        tenant_id: &TenantId,
    ) -> Result<ProviderStream> {
        let model = request.model.clone();
        let gemini_request = GeminiRequest::from_universal(request)
            .context("failed to translate to Gemini format")?;
        let url = format!(
            "{}/v1beta/models/{}:streamGenerateContent?alt=sse&key={}",
            self.base_url, model, api_key
        );

        crate::ssrf_guard::validate_url(&url)
            .await
            .context("SSRF guard rejected Google AI base URL")?;

        // streamGenerateContent returns newline-delimited JSON objects
        let response = self
            .client
            .post(&url)
            .header("content-type", "application/json")
            .json(&gemini_request)
            .send()
            .await
            .context("failed to send request to Google AI API")?;

        let status = response.status();
        if !status.is_success() {
            // from the `key=` query parameter, so the body is NEVER logged or
            // surfaced. We read exactly one thing out of it: a structured reason
            // token, gated by `safe_reason` (SHOUTY_SNAKE_CASE only), which an API
            // key cannot satisfy. The free-text `message` is never touched.
            //
            // B-115: this is load-bearing. Google answers an invalid/retired API
            // key with 400 INVALID_ARGUMENT / API_KEY_INVALID — not 401 — so
            // status alone cannot tell a dead key from a malformed request, and
            // Google retires ALL classic `AIza` keys in Sept 2026.
            let body = response.text().await.unwrap_or_default();
            let reason = crate::providers::reason_from_body(&body);
            drop(body);
            tracing::warn!(status = %status, reason = ?reason, "Google AI API error");
            return Err(crate::providers::ProviderHttpError {
                provider: "google",
                status: status.as_u16(),
                reason,
            }
            .into());
        }

        Ok(Box::pin(build_gemini_stream(response)))
    }
}

// A14: `Default` removed — `new()` is now fallible. No call sites used
// it, so the impl is gone rather than papered over with `.expect()`.

pub(super) fn build_gemini_stream(
    response: reqwest::Response,
) -> impl Stream<Item = Result<ProviderEvent>> + Send {
    try_stream! {
        let mut byte_stream = response.bytes_stream();
        let mut buffer = String::new();

        use futures::StreamExt as _;
        while let Some(chunk) = byte_stream.next().await {
            let chunk: Bytes = chunk.context("error reading Gemini response chunk")?;
            let text = std::str::from_utf8(&chunk).context("non-UTF8 Gemini chunk")?;
            buffer.push_str(text);

            while let Some(pos) = buffer.find('\n') {
                let line = buffer[..pos].trim_end_matches('\r').to_owned();
                buffer = buffer[pos + 1..].to_owned();

                if line.is_empty() || line.starts_with(':') {
                    continue;
                }
                if let Some(data) = line.strip_prefix("data: ") {
                    if let Ok(events) = parse_gemini_sse(data) {
                        for event in events {
                            yield event;
                        }
                    }
                }
            }
        }
    }
}

/// Parse one Gemini SSE payload into provider events.
///
/// Returns a Vec because a single Gemini chunk legitimately carries SEVERAL
/// things at once: multiple content parts (text + functionCall + thought) AND
/// `usageMetadata` on the same chunk (Gemini attaches usage to the final —
/// often only — content chunk). The previous single-event version returned
/// early on `usageMetadata`, silently DROPPING any content in that chunk
/// surfaced the first part. Content events are emitted in part order;
/// usage is emitted last.
fn parse_gemini_sse(data: &str) -> Result<Vec<ProviderEvent>> {
    let v: Value = serde_json::from_str(data).context("invalid Gemini SSE JSON")?;
    let mut events = Vec::new();

    let parts = &v["candidates"][0]["content"]["parts"];
    if let Some(arr) = parts.as_array() {
        let mut fc_index = 0usize;
        for part in arr {
            // Thought signature (Gemini reasoning trace)
            if let Some(thought) = part.get("thought").and_then(|t| t.as_str()) {
                if !thought.is_empty() {
                    events.push(ProviderEvent::ThinkingDelta {
                        delta: thought.to_owned(),
                    });
                }
            }
            // Text part
            if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                if !text.is_empty() {
                    events.push(ProviderEvent::StreamChunk {
                        delta: text.to_owned(),
                    });
                }
            }
            // Function call part
            if let Some(fc) = part.get("functionCall") {
                let name = fc["name"].as_str().unwrap_or("").to_owned();
                let args = fc["args"].to_string();
                events.push(ProviderEvent::ToolCallDelta {
                    index: fc_index,
                    id: Some(format!("gemini-fc-{}", uuid::Uuid::new_v4())),
                    name: Some(name),
                    input_delta: args,
                });
                fc_index += 1;
            }
        }
    }

    // Usage metadata — AFTER content so a chunk carrying both loses nothing.
    if let Some(meta) = v.get("usageMetadata") {
        let input = meta["promptTokenCount"].as_u64().unwrap_or(0) as u32;
        // B-104: thinking models (gemini-2.5-*) report reasoning tokens in a
        // SEPARATE `thoughtsTokenCount`, DISJOINT from `candidatesTokenCount`
        // (Gemini: totalTokenCount = prompt + thoughts + candidates) yet billed as
        // OUTPUT. Reading candidatesTokenCount alone under-counts billable output by
        // the reasoning volume (often larger than the visible answer). Fold thoughts
        // in — absent on non-thinking models → `unwrap_or(0)` → no change, no
        // double-count. Both counters are cumulative per SSE chunk, so the sum stays
        // monotonic and the max-wins usage merge (server::merge_usage_tokens)
        // resolves to the final chunk's total. `promptTokenCount` already includes
        // any cached prefix, so input is not adjusted here.
        let output = (meta["candidatesTokenCount"].as_u64().unwrap_or(0)
            + meta["thoughtsTokenCount"].as_u64().unwrap_or(0)) as u32;
        events.push(ProviderEvent::UsageUpdate {
            input_tokens: input,
            output_tokens: output,
            cache_read: None,
            cache_creation: None,
            cost_usd: None,
        });
    }

    Ok(events)
}

// ── Gemini request types ──────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub(super) struct GeminiRequest {
    contents: Vec<GeminiContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system_instruction: Option<GeminiContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<GeminiTool>>,
    #[serde(rename = "generationConfig", skip_serializing_if = "Option::is_none")]
    generation_config: Option<GeminiGenerationConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GeminiContent {
    role: String,
    parts: Vec<GeminiPart>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum GeminiPart {
    Text { text: String },
    FunctionResponse { function_response: Value },
}

#[derive(Debug, Serialize)]
struct GeminiTool {
    function_declarations: Vec<GeminiFunctionDecl>,
}

#[derive(Debug, Serialize)]
struct GeminiFunctionDecl {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    parameters: Value,
}

#[derive(Debug, Serialize)]
struct GeminiGenerationConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    max_output_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
}

impl GeminiRequest {
    pub(super) fn from_universal(req: ChatRequest) -> Result<Self> {
        let mut system_instruction: Option<GeminiContent> = None;
        let mut contents: Vec<GeminiContent> = Vec::new();

        // Prepend system from req.system field
        if let Some(sys) = &req.system {
            system_instruction = Some(GeminiContent {
                role: "user".into(),
                parts: vec![GeminiPart::Text { text: sys.clone() }],
            });
        }

        for msg in req.messages {
            match msg.role {
                Role::System => {
                    let text = match msg.content {
                        MessageContent::Text(t) => t,
                        MessageContent::Parts(_) => bail!("system must be text"),
                    };
                    system_instruction = Some(GeminiContent {
                        role: "user".into(),
                        parts: vec![GeminiPart::Text { text }],
                    });
                }
                Role::User => {
                    let text = match msg.content {
                        MessageContent::Text(t) => t,
                        MessageContent::Parts(parts) => parts
                            .into_iter()
                            .filter_map(|p| {
                                if let tracelane_shared::ContentPart::Text { text, .. } = p {
                                    Some(text)
                                } else {
                                    None
                                }
                            })
                            .collect::<Vec<_>>()
                            .join("\n"),
                    };
                    contents.push(GeminiContent {
                        role: "user".into(),
                        parts: vec![GeminiPart::Text { text }],
                    });
                }
                Role::Assistant => {
                    let text = match msg.content {
                        MessageContent::Text(t) => t,
                        MessageContent::Parts(_) => String::new(),
                    };
                    contents.push(GeminiContent {
                        role: "model".into(),
                        parts: vec![GeminiPart::Text { text }],
                    });
                }
                Role::Tool => {
                    let result = match msg.content {
                        MessageContent::Text(t) => t,
                        MessageContent::Parts(_) => String::new(),
                    };
                    contents.push(GeminiContent {
                        role: "user".into(),
                        parts: vec![GeminiPart::FunctionResponse {
                            function_response: serde_json::json!({
                                "name": msg.tool_call_id.unwrap_or_default(),
                                "response": { "result": result }
                            }),
                        }],
                    });
                }
            }
        }

        let tools = req.tools.map(|ts| {
            vec![GeminiTool {
                function_declarations: ts
                    .into_iter()
                    .map(|t| GeminiFunctionDecl {
                        name: t.name,
                        description: t.description,
                        parameters: t.input_schema,
                    })
                    .collect(),
            }]
        });

        let generation_config = if req.max_tokens.is_some() || req.temperature.is_some() {
            Some(GeminiGenerationConfig {
                max_output_tokens: req.max_tokens,
                temperature: req.temperature,
            })
        } else {
            None
        };

        Ok(Self {
            contents,
            system_instruction,
            tools,
            generation_config,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracelane_shared::{ChatRequest, Message, MessageContent, Role};

    #[test]
    fn translates_system_to_system_instruction() {
        let req = ChatRequest {
            model: "gemini-3.1-pro".into(),
            messages: vec![
                Message {
                    role: Role::System,
                    content: MessageContent::Text("be precise".into()),
                    tool_call_id: None,
                    tool_calls: None,
                },
                Message {
                    role: Role::User,
                    content: MessageContent::Text("hello".into()),
                    tool_call_id: None,
                    tool_calls: None,
                },
            ],
            tools: None,
            max_tokens: None,
            temperature: None,
            stream: None,
            system: None,
            metadata: None,
        };
        let gemini = GeminiRequest::from_universal(req).unwrap();
        assert!(gemini.system_instruction.is_some());
        assert_eq!(gemini.contents.len(), 1);
        assert_eq!(gemini.contents[0].role, "user");
    }

    #[test]
    fn assistant_maps_to_model_role() {
        let req = ChatRequest {
            model: "gemini-3.1-flash".into(),
            messages: vec![
                Message {
                    role: Role::User,
                    content: MessageContent::Text("hi".into()),
                    tool_call_id: None,
                    tool_calls: None,
                },
                Message {
                    role: Role::Assistant,
                    content: MessageContent::Text("hello".into()),
                    tool_call_id: None,
                    tool_calls: None,
                },
            ],
            tools: None,
            max_tokens: None,
            temperature: None,
            stream: None,
            system: None,
            metadata: None,
        };
        let gemini = GeminiRequest::from_universal(req).unwrap();
        assert_eq!(gemini.contents[1].role, "model");
    }

    fn usage_from(chunk: &str) -> (u32, u32) {
        parse_gemini_sse(chunk)
            .unwrap()
            .iter()
            .find_map(|e| match e {
                ProviderEvent::UsageUpdate {
                    input_tokens,
                    output_tokens,
                    ..
                } => Some((*input_tokens, *output_tokens)),
                _ => None,
            })
            .expect("a UsageUpdate event")
    }

    /// B-104: a Gemini thinking-model chunk reports reasoning tokens in a SEPARATE
    /// `thoughtsTokenCount` (disjoint from `candidatesTokenCount`) but billed as
    /// output. Extraction must FOLD thoughts into output_tokens, else 2.5 output
    /// under-counts by the reasoning volume.
    #[test]
    fn usage_folds_thoughts_into_output_for_thinking_models() {
        let (input, output) = usage_from(
            r#"{"usageMetadata":{"promptTokenCount":677,"candidatesTokenCount":175,"thoughtsTokenCount":400,"totalTokenCount":1252}}"#,
        );
        assert_eq!(input, 677, "input = promptTokenCount");
        assert_eq!(
            output, 575,
            "output = candidatesTokenCount + thoughtsTokenCount (175+400), not 175"
        );
    }

    /// Non-thinking models omit `thoughtsTokenCount`; output = candidatesTokenCount
    /// (no double-count, unchanged from prior behaviour).
    #[test]
    fn usage_without_thoughts_is_candidates_only() {
        let (input, output) = usage_from(
            r#"{"usageMetadata":{"promptTokenCount":1767,"candidatesTokenCount":1259,"totalTokenCount":3026}}"#,
        );
        assert_eq!(input, 1767);
        assert_eq!(output, 1259, "no thoughtsTokenCount → output unchanged");
    }
}

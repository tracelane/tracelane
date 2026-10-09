//! Google Gemini provider adapter.
//!
//! Supports Gemini 3.1 Pro, Flash, and Nano via `streamGenerateContent`.
//! **OG-02 D6:** the API key travels in the `x-goog-api-key` HEADER, never in the URL.
//! `reqwest::Error`'s `Display` prints the full request URL, so a `?key=` query put the
//! tenant's plaintext BYOK key into every connect/timeout/TLS error chain and every log
//! line that stringified it. Every reqwest error on this path is additionally stripped
//! with `without_url()` — defence in depth, so a future URL-borne value cannot leak the
//! same way.
//! Handles thought signatures (extended reasoning), grounding/search tool,
//! and function call (functionCall/functionResponse) parts.

use anyhow::{Context as _, Result, bail};
use async_stream::try_stream;
use bytes::Bytes;
use futures::Stream;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::instrument;

use std::collections::HashMap;

use tracelane_shared::{
    ChatRequest, ContentPart, Message, MessageContent, Role, TenantId, ToolChoice,
};

use crate::providers::translation_policy::GeminiThinking;
use crate::providers::{FinishReason, ProviderEvent, ProviderStream};

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

    /// The upstream origin — read by the Gemini-native route (`gemini_native.rs`), which
    /// builds its own paths so the two cannot resolve different hosts.
    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The SSRF-hardened client (`safe_client_builder`: redirects disabled), shared with the
    /// Gemini-native route so both reach the origin through ONE connection pool.
    pub(crate) fn client(&self) -> &Client {
        &self.client
    }

    /// The key goes in the `x-goog-api-key` header (OG-02 D6), never the URL.
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
        // The model is a URL PATH segment: validated, never interpolated raw.
        let Some(path_model) = path_model(&request.model).map(str::to_owned) else {
            return Err(invalid_model_error("google"));
        };
        let gemini_request = GeminiRequest::from_universal(request)
            .context("failed to translate to Gemini format")?;
        let url = format!(
            "{}/v1beta/models/{path_model}:streamGenerateContent?alt=sse",
            self.base_url.trim_end_matches('/')
        );

        // SSRF: validate before the POST (reviewer).
        crate::ssrf_guard::validate_url(&url)
            .await
            .context("SSRF guard rejected Google AI base URL")?;

        // streamGenerateContent returns SSE `data: {GenerateContentResponse}` frames.
        let response = crate::routing::deadlines::send(
            self.client
                .post(&url)
                .header("x-goog-api-key", api_key)
                .header("content-type", "application/json")
                .json(&gemini_request),
        )
        .await
        .context("failed to send request to Google AI API")?;

        let status = response.status();
        if !status.is_success() {
            // SECURITY: Google error bodies can echo the API key
            // (historically from the `key=` query parameter), so the body is NEVER logged or
            // surfaced. We read exactly one thing out of it: a structured reason
            // token, gated by `safe_reason` (SHOUTY_SNAKE_CASE only), which an API
            // key cannot satisfy. The free-text `message` is never touched.
            //
            // This is load-bearing. Google answers an invalid/retired API
            // key with 400 INVALID_ARGUMENT / API_KEY_INVALID — not 401 — so
            // status alone cannot tell a dead key from a malformed request, and
            // Google retires ALL classic `AIza` keys in Sept 2026.
            let retry_after = crate::providers::retry_after_from(response.headers());
            let body = crate::routing::deadlines::error_text(response).await?;
            let reason = crate::providers::reason_from_body(&body);
            tracing::warn!(status = %status, reason = ?reason, "Google AI API error");
            // OG-03 §3.4: the message is attached only for a relayable 4xx that is
            // NOT a key problem — Google's dead-key 400 names the key, and
            // `from_response` judges that on the finished error.
            return Err(crate::providers::ProviderHttpError::from_response(
                "google",
                status.as_u16(),
                reason,
                &body,
                api_key,
            )
            .with_retry_after(retry_after)
            .into());
        }

        Ok(Box::pin(build_gemini_stream(response)))
    }
}

/// The model as it appears in the Google URL path, or `None` when it is not a safe
/// path segment. OG-02 §3.1: strip the gateway's `google/` routing prefix, then
/// require `^[A-Za-z0-9._-]{1,128}$` — and additionally that it does not START with a
/// dot, so a `..` can never become a path-traversal segment on `GET /models/{model}`
/// (the spec's pattern alone admits it).
#[must_use]
pub(crate) fn path_model(model: &str) -> Option<&str> {
    safe_path_segment(model.strip_prefix("google/").unwrap_or(model))
}

/// `m` itself when it is a safe URL path segment (see [`path_model`]); shared with the
/// Vertex adapter, which builds the same kind of path.
#[must_use]
pub(crate) fn safe_path_segment(m: &str) -> Option<&str> {
    let ok = !m.is_empty()
        && m.len() <= 128
        && !m.starts_with('.')
        && m.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    ok.then_some(m)
}

/// A typed 400 raised BEFORE anything is sent upstream; `message` reaches the caller as
/// `provider_message`. `ProviderHttpError` is the one shape the chat handler turns into a
/// 4xx (a bare `bail!` would surface as a 502 that blames us).
pub(super) fn bad_request(provider: &'static str, message: String) -> anyhow::Error {
    let mut e = crate::providers::ProviderHttpError::from_response(provider, 400, None, "", "");
    e.message = Some(message);
    e.into()
}

/// The typed 400 for a model that is not a safe path segment. Never sent upstream.
pub(super) fn invalid_model_error(provider: &'static str) -> anyhow::Error {
    bad_request(
        provider,
        "the model name is not a valid Gemini model id (letters, digits, `.`, `_`, `-`; up to 128 characters)"
            .to_owned(),
    )
}

/// `OG-02` D8. Every call an assistant turn made, as `id -> function name`: the OpenAI
/// `tool_calls` AND the native `ToolUse` parts.
fn record_call_names(msg: &Message, names: &mut HashMap<String, String>) {
    for c in msg.tool_calls.iter().flatten() {
        names.insert(c.id.clone(), c.name.clone());
    }
    if let MessageContent::Parts(parts) = &msg.content {
        for p in parts {
            if let ContentPart::ToolUse { id, name, .. } = p {
                names.insert(id.clone(), name.clone());
            }
        }
    }
}

/// `OG-02` D8. The index of the first `tool` message whose `tool_call_id` answers no call an
/// EARLIER assistant turn made, or `None` when every result can be named. Gemini's
/// `functionResponse` is keyed by FUNCTION NAME, which only that earlier call knows — a result
/// that cannot be named is refused, never sent with the id in the name's place.
#[must_use]
pub(crate) fn first_unresolvable_tool_result(messages: &[Message]) -> Option<usize> {
    let mut names = HashMap::new();
    for (i, m) in messages.iter().enumerate() {
        match m.role {
            Role::Assistant => record_call_names(m, &mut names),
            Role::Tool => {
                let known = m
                    .tool_call_id
                    .as_deref()
                    .is_some_and(|id| names.contains_key(id));
                if !known {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Text of a message's content, parts joined — what an assistant or tool turn says.
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

// A14: `Default` removed — `new()` is now fallible. No call sites used
// it, so the impl is gone rather than papered over with `.expect()`.

pub(super) fn build_gemini_stream(
    response: reqwest::Response,
) -> impl Stream<Item = Result<ProviderEvent>> + Send {
    try_stream! {
        let mut byte_stream = response.bytes_stream();
        // Bytes, not text: a chunk boundary can fall inside a character.
        let mut lines = super::sse_lines::LineBuffer::default();

        use futures::StreamExt as _;
        while let Some(chunk) = byte_stream.next().await {
            let chunk: Bytes = chunk
                .map_err(reqwest::Error::without_url)
                .context("error reading Gemini response chunk")?;
            lines.push(&chunk);

            while let Some(line) = lines.next_line() {
                let line = line.context("non-UTF8 Gemini SSE line")?;

                if line.is_empty() || line.starts_with(':') {
                    continue;
                }
                if let Some(data) = line.strip_prefix("data: ")
                    && let Ok(events) = parse_gemini_sse(data)
                {
                    for event in events {
                        yield event;
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
/// (: for short responses the entire text vanished), and only ever
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
            if let Some(thought) = part.get("thought").and_then(|t| t.as_str())
                && !thought.is_empty()
            {
                events.push(ProviderEvent::ThinkingDelta {
                    delta: thought.to_owned(),
                });
            }
            // Text part
            if let Some(text) = part.get("text").and_then(|t| t.as_str())
                && !text.is_empty()
            {
                events.push(ProviderEvent::StreamChunk {
                    delta: text.to_owned(),
                });
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
        // Thinking models (gemini-2.5-*) report reasoning tokens in a
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
        // RI-05 / M11: the SAME `thoughtsTokenCount`, broken out on its own
        // attribute rather than folded into `output`. `.as_u64()` on an absent
        // key (non-thinking models omit it) is `None` — never a fabricated `0`
        // for a model that has no reasoning concept at all.
        let reasoning = meta["thoughtsTokenCount"].as_u64().map(|n| n as u32);
        events.push(ProviderEvent::UsageUpdate {
            input_tokens: input,
            output_tokens: output,
            cache_read: None,
            cache_creation: None,
            cost_usd: None,
            reasoning,
        });
    }

    if let Some(reason) = v["candidates"][0]["finishReason"]
        .as_str()
        .and_then(FinishReason::from_gemini_finish_reason)
    {
        events.push(ProviderEvent::Finish { reason });
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
    /// OG-90. `tool_choice` → `toolConfig.functionCallingConfig` (it used to be dropped, so a
    /// caller forcing — or forbidding — a tool call got the model's own choice and no signal).
    #[serde(rename = "toolConfig", skip_serializing_if = "Option::is_none")]
    tool_config: Option<Value>,
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
    Text {
        text: String,
    },
    /// OG-02 D8. An assistant turn's tool call, replayed: `{"functionCall": {name, args}}`,
    /// plus Gemini 3's `thoughtSignature` (a sibling field in the same part) when required.
    FunctionCall {
        #[serde(rename = "functionCall")]
        function_call: Value,
        #[serde(
            rename = "thoughtSignature",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        thought_signature: Option<String>,
    },
    FunctionResponse {
        #[serde(rename = "functionResponse")]
        function_response: Value,
    },
    /// OG-03 (D1). Image, audio and PDF bytes ride as `inlineData {mimeType, data}`; the
    /// gateway never sends a `fileData` URI (it would have to fetch or host the file).
    InlineData {
        #[serde(rename = "inlineData")]
        inline_data: Value,
    },
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
    /// Live finding F2 (2026-10-03, real Codex run through the gateway): Gemini's legacy
    /// `parameters` field is an OpenAPI SUBSET and 400s on standard JSON-Schema keys
    /// clients send by default (`additionalProperties`, strict schemas) — every Codex tool
    /// call and many OpenAI-SDK tool calls failed on Gemini. `parametersJsonSchema` takes
    /// full JSON Schema (probed live: `parameters` → 400, `parametersJsonSchema` → 200
    /// with a functionCall, gemini-3.5-flash). Vertex shares this struct.
    #[serde(rename = "parametersJsonSchema")]
    parameters: Value,
}

#[derive(Debug, Serialize)]
struct GeminiGenerationConfig {
    #[serde(rename = "maxOutputTokens", skip_serializing_if = "Option::is_none")]
    max_output_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    /// GWY-48. Forwarded so a parameter the span RECORDS is a parameter the
    /// provider actually RECEIVED. `skip_serializing_if`, so a request that did
    /// not send it serialises byte-identically to before this field existed.
    #[serde(rename = "topP", skip_serializing_if = "Option::is_none")]
    top_p: Option<f32>,
    /// OG-03. OpenAI `stop` → `stopSequences` (Google allows up to 5; the gateway caps at 4).
    #[serde(rename = "stopSequences", skip_serializing_if = "Option::is_none")]
    stop_sequences: Option<Vec<String>>,
    /// OG-03. `response_format` `json_object` / `json_schema` → `application/json`.
    #[serde(rename = "responseMimeType", skip_serializing_if = "Option::is_none")]
    response_mime_type: Option<&'static str>,
    /// OG-03. The `json_schema` body — standard JSON Schema, which is what
    /// `responseJsonSchema` takes (`responseSchema` is the OpenAPI subset).
    #[serde(rename = "responseJsonSchema", skip_serializing_if = "Option::is_none")]
    response_json_schema: Option<Value>,
    #[serde(rename = "presencePenalty", skip_serializing_if = "Option::is_none")]
    presence_penalty: Option<f32>,
    #[serde(rename = "frequencyPenalty", skip_serializing_if = "Option::is_none")]
    frequency_penalty: Option<f32>,
    /// OG-90. OpenAI `seed` → Gemini's `generationConfig.seed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<u64>,
    /// OG-03. `reasoning_effort` → `{thinkingLevel}` (Gemini 3.x) or `{thinkingBudget}`,
    /// from the reference table.
    #[serde(rename = "thinkingConfig", skip_serializing_if = "Option::is_none")]
    thinking_config: Option<Value>,
}

impl GeminiGenerationConfig {
    fn is_empty(&self) -> bool {
        self.max_output_tokens.is_none()
            && self.temperature.is_none()
            && self.top_p.is_none()
            && self.stop_sequences.is_none()
            && self.response_mime_type.is_none()
            && self.response_json_schema.is_none()
            && self.presence_penalty.is_none()
            && self.frequency_penalty.is_none()
            && self.seed.is_none()
            && self.thinking_config.is_none()
    }
}

/// OG-03. A `data:` URI → `inlineData`. The media type was allowlisted and the payload
/// proven base64 at admission; anything else here is a defect upstream of this call.
fn inline_data_part(uri: &str, what: &str) -> Result<GeminiPart> {
    let Some((mime, data)) = crate::request_support::split_data_uri(uri) else {
        bail!("{what} must be a data: URI — the gateway never fetches URLs");
    };
    Ok(GeminiPart::InlineData {
        inline_data: serde_json::json!({ "mimeType": mime, "data": data }),
    })
}

impl GeminiRequest {
    pub(super) fn from_universal(req: ChatRequest) -> Result<Self> {
        // OG-03: resolved while `req` is whole. `check_supported` already refused anything
        // unmappable; the same function is re-run here so the two cannot disagree.
        let thinking_config = match crate::request_support::gemini_thinking_for("google", &req)
            .map_err(|u| anyhow::anyhow!("{}", u.message))?
        {
            None => None,
            Some(GeminiThinking::Level(l)) => Some(serde_json::json!({ "thinkingLevel": l })),
            Some(GeminiThinking::Budget(n)) => Some(serde_json::json!({ "thinkingBudget": n })),
        };
        let rf_type = req
            .response_format
            .as_ref()
            .and_then(|rf| rf.get("type"))
            .and_then(Value::as_str);
        let response_mime_type =
            matches!(rf_type, Some("json_object" | "json_schema")).then_some("application/json");
        let response_json_schema = (rf_type == Some("json_schema"))
            .then(|| {
                req.response_format
                    .as_ref()
                    .and_then(|rf| rf.get("json_schema"))
                    .and_then(|js| js.get("schema"))
                    .cloned()
            })
            .flatten();
        let stop_sequences = req.stop.as_ref().map(|s| {
            s.sequences()
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        });
        let max_output_tokens = req.max_completion_tokens.or(req.max_tokens);
        let mut system_instruction: Option<GeminiContent> = None;
        let mut contents: Vec<GeminiContent> = Vec::new();

        // Prepend system from req.system field
        if let Some(sys) = &req.system {
            system_instruction = Some(GeminiContent {
                role: "user".into(),
                parts: vec![GeminiPart::Text { text: sys.clone() }],
            });
        }

        // OG-02 D8: `functionResponse.name` must be the FUNCTION name, which only the earlier
        // assistant call knows. Filled as the history is walked, so a result can only be
        // named by a call that came before it.
        let signature_placeholder =
            crate::providers::translation_policy::gemini_signature_placeholder(&req.model);
        let mut call_names: HashMap<String, String> = HashMap::new();
        // True while the last content pushed is a user turn made of tool results, so
        // consecutive `tool` messages (one parallel batch) share ONE turn.
        let mut last_is_tool_batch = false;

        for (msg_index, msg) in req.messages.into_iter().enumerate() {
            let is_tool = msg.role == Role::Tool;
            if !is_tool {
                last_is_tool_batch = false;
            }
            match msg.role {
                Role::System => {
                    let text = match msg.content {
                        MessageContent::Text(t) => t,
                        MessageContent::Parts(_) => bail!("system must be text"),
                    };
                    // OG-90: ACCUMULATE. This used to REPLACE the instruction, so a second
                    // system message (or a system message after `ChatRequest.system`) silently
                    // erased the first — Anthropic and Converse merge them, so must this.
                    match system_instruction.as_mut() {
                        Some(existing) => existing.parts.push(GeminiPart::Text { text }),
                        None => {
                            system_instruction = Some(GeminiContent {
                                role: "user".into(),
                                parts: vec![GeminiPart::Text { text }],
                            });
                        }
                    }
                }
                Role::User => {
                    let parts = match msg.content {
                        MessageContent::Text(text) => vec![GeminiPart::Text { text }],
                        // Text-only parts keep the historical shape: one joined text part.
                        MessageContent::Parts(parts)
                            if !parts.iter().any(|p| {
                                matches!(
                                    p,
                                    ContentPart::ImageUrl { .. }
                                        | ContentPart::InputAudio { .. }
                                        | ContentPart::File { .. }
                                )
                            }) =>
                        {
                            let text = parts
                                .into_iter()
                                .filter_map(|p| {
                                    if let ContentPart::Text { text, .. } = p {
                                        Some(text)
                                    } else {
                                        None
                                    }
                                })
                                .collect::<Vec<_>>()
                                .join("\n");
                            vec![GeminiPart::Text { text }]
                        }
                        // OG-03 (D1): an image / audio / PDF part is TRANSLATED, in order —
                        // it used to be filtered out here with no error.
                        MessageContent::Parts(parts) => {
                            let mut out = Vec::with_capacity(parts.len());
                            for p in parts {
                                match p {
                                    ContentPart::Text { text, .. } => {
                                        out.push(GeminiPart::Text { text });
                                    }
                                    ContentPart::ImageUrl { image_url } => {
                                        out.push(inline_data_part(&image_url.url, "image_url")?);
                                    }
                                    ContentPart::File { file } => {
                                        let Some(data) = file.file_data.as_deref() else {
                                            bail!("a file part needs file_data for Gemini");
                                        };
                                        out.push(inline_data_part(data, "file")?);
                                    }
                                    ContentPart::InputAudio { input_audio } => {
                                        let Some(mime) = crate::request_support::audio_media_type(
                                            &input_audio.format,
                                        ) else {
                                            bail!("unsupported input_audio format");
                                        };
                                        out.push(GeminiPart::InlineData {
                                            inline_data: serde_json::json!({
                                                "mimeType": mime,
                                                "data": input_audio.data,
                                            }),
                                        });
                                    }
                                    ContentPart::ToolUse { .. }
                                    | ContentPart::ToolResult { .. } => {}
                                }
                            }
                            out
                        }
                    };
                    contents.push(GeminiContent {
                        role: "user".into(),
                        parts,
                    });
                }
                Role::Assistant => {
                    record_call_names(&msg, &mut call_names);
                    let mut parts: Vec<GeminiPart> = Vec::new();
                    let text = text_of(&msg.content);
                    if !text.is_empty() {
                        parts.push(GeminiPart::Text { text });
                    }
                    // Calls in order: the OpenAI `tool_calls`, then native `ToolUse` parts.
                    let native = match &msg.content {
                        MessageContent::Parts(ps) => ps
                            .iter()
                            .filter_map(|p| match p {
                                ContentPart::ToolUse { name, input, .. } => {
                                    Some((name.as_str(), input))
                                }
                                _ => None,
                            })
                            .collect::<Vec<_>>(),
                        MessageContent::Text(_) => Vec::new(),
                    };
                    let openai = msg
                        .tool_calls
                        .iter()
                        .flatten()
                        .map(|c| (c.name.as_str(), &c.input));
                    let mut first_call = true;
                    for (name, input) in openai.chain(native) {
                        if !input.is_object() {
                            return Err(bad_request(
                                "google",
                                format!(
                                    "messages[{msg_index}]: tool call `{name}` arguments must be a JSON object"
                                ),
                            ));
                        }
                        parts.push(GeminiPart::FunctionCall {
                            function_call: serde_json::json!({ "name": name, "args": input }),
                            // Only the FIRST call of a turn carries the signature, as Google's
                            // own responses do for parallel calls.
                            thought_signature: if first_call {
                                signature_placeholder.map(str::to_owned)
                            } else {
                                None
                            },
                        });
                        first_call = false;
                    }
                    if parts.is_empty() {
                        // Unchanged historical behaviour for an empty assistant turn.
                        parts.push(GeminiPart::Text {
                            text: String::new(),
                        });
                    }
                    contents.push(GeminiContent {
                        role: "model".into(),
                        parts,
                    });
                }
                Role::Tool => {
                    let id = msg.tool_call_id.as_deref().unwrap_or_default();
                    let Some(name) = call_names.get(id) else {
                        return Err(bad_request(
                            "google",
                            format!(
                                "messages[{msg_index}].tool_call_id `{}` does not answer a tool call made earlier in this conversation, so the function name Gemini needs cannot be resolved",
                                id.chars().take(64).collect::<String>()
                            ),
                        ));
                    };
                    let part = GeminiPart::FunctionResponse {
                        function_response: serde_json::json!({
                            "name": name,
                            "response": { "result": text_of(&msg.content) }
                        }),
                    };
                    match contents.last_mut() {
                        // One parallel batch is ONE user turn with several functionResponses.
                        Some(last) if last_is_tool_batch => last.parts.push(part),
                        _ => contents.push(GeminiContent {
                            role: "user".into(),
                            parts: vec![part],
                        }),
                    }
                    last_is_tool_batch = true;
                }
            }
        }

        // OG-90: `tool_choice`, mapped (OpenAI vocabulary → Gemini's `functionCallingConfig`).
        // Only meaningful when tools are declared; with none there is nothing to choose among, and
        // Gemini refuses a `toolConfig` that has no tools to apply it to.
        let has_tools = req.tools.as_ref().is_some_and(|t| !t.is_empty());
        let tool_config = req
            .tool_choice
            .as_ref()
            .filter(|_| has_tools)
            .map(|choice| {
                let cfg = match choice {
                    ToolChoice::Auto => json!({ "mode": "AUTO" }),
                    ToolChoice::None => json!({ "mode": "NONE" }),
                    ToolChoice::Required => json!({ "mode": "ANY" }),
                    ToolChoice::Function { name } => {
                        json!({ "mode": "ANY", "allowedFunctionNames": [name] })
                    }
                };
                json!({ "functionCallingConfig": cfg })
            });

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

        // GWY-48: `|| req.top_p.is_some()` is NOT optional. Adding the struct
        // field without widening this condition means a request carrying only
        // `top_p` builds no `generationConfig` at all and the value is dropped —
        // with the field visibly present and the type-check passing.
        let generation_config = {
            let cfg = GeminiGenerationConfig {
                max_output_tokens,
                temperature: req.temperature,
                top_p: req.top_p,
                stop_sequences,
                response_mime_type,
                response_json_schema,
                presence_penalty: req.presence_penalty,
                frequency_penalty: req.frequency_penalty,
                seed: req.seed,
                thinking_config,
            };
            // OG-03: every field above must widen this condition (see GWY-48's warning) —
            // `generation_config_is_empty` lists them all in ONE place so a new field
            // cannot be added to the struct and forgotten here.
            (!cfg.is_empty()).then_some(cfg)
        };

        Ok(Self {
            contents,
            system_instruction,
            tools,
            tool_config,
            generation_config,
        })
    }
}

#[cfg(test)]
mod tests {

    /// F2: a strict JSON-Schema tool (`additionalProperties: false`) rides in
    /// `parametersJsonSchema`, never in the legacy OpenAPI-subset `parameters` field.
    #[test]
    fn f2_tool_schemas_go_in_parameters_json_schema() {
        let decl = GeminiFunctionDecl {
            name: "get_weather".into(),
            description: None,
            parameters: serde_json::json!({
                "type": "object",
                "properties": {"city": {"type": "string"}},
                "additionalProperties": false
            }),
        };
        let v = serde_json::to_value(&decl).expect("serialize");
        assert_eq!(
            v["parametersJsonSchema"]["additionalProperties"],
            serde_json::json!(false)
        );
        assert!(v.get("parameters").is_none(), "{v}");
    }
    use super::*;
    use tracelane_shared::{ChatRequest, Message, MessageContent, Role};

    #[test]
    fn translates_system_to_system_instruction() {
        let req = ChatRequest {
            top_p: None,
            seed: None,
            logprobs: None,
            top_logprobs: None,
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
            tool_choice: None,
            max_tokens: None,
            temperature: None,
            stream: None,
            system: None,
            metadata: None,
            ..Default::default()
        };
        let gemini = GeminiRequest::from_universal(req).unwrap();
        assert!(gemini.system_instruction.is_some());
        assert_eq!(gemini.contents.len(), 1);
        assert_eq!(gemini.contents[0].role, "user");
    }

    #[test]
    fn assistant_maps_to_model_role() {
        let req = ChatRequest {
            top_p: None,
            seed: None,
            logprobs: None,
            top_logprobs: None,
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
            tool_choice: None,
            max_tokens: None,
            temperature: None,
            stream: None,
            system: None,
            metadata: None,
            ..Default::default()
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

    /// A Gemini thinking-model chunk reports reasoning tokens in a SEPARATE
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

    #[test]
    fn gemini_max_tokens_finish_reason_is_emitted_and_unknown_is_not_guessed() {
        let events = parse_gemini_sse(r#"{"candidates":[{"finishReason":"MAX_TOKENS"}]}"#).unwrap();
        assert!(
            events.iter().any(|event| matches!(
                event,
                ProviderEvent::Finish {
                    reason: crate::providers::FinishReason::Length
                }
            )),
            "MAX_TOKENS must emit the normalized length reason"
        );

        let unknown =
            parse_gemini_sse(r#"{"candidates":[{"finishReason":"FUTURE_REASON"}]}"#).unwrap();
        assert!(
            unknown
                .iter()
                .all(|event| !matches!(event, ProviderEvent::Finish { .. })),
            "unknown Gemini reasons must not be guessed"
        );
    }

    #[test]
    fn gemini_finish_reason_mapper_covers_documented_values_only() {
        for value in [
            "SAFETY",
            "RECITATION",
            "BLOCKLIST",
            "PROHIBITED_CONTENT",
            "SPII",
        ] {
            assert_eq!(
                FinishReason::from_gemini_finish_reason(value),
                Some(FinishReason::ContentFilter),
                "{value} is a content filter"
            );
        }
        assert_eq!(
            FinishReason::from_gemini_finish_reason("STOP"),
            Some(FinishReason::Stop)
        );
        assert_eq!(
            FinishReason::from_gemini_finish_reason("MAX_TOKENS"),
            Some(FinishReason::Length)
        );
        assert_eq!(FinishReason::from_gemini_finish_reason("UNKNOWN"), None);
    }

    #[test]
    fn buffered_gemini_finish_reason_survives_event_folding() {
        let events = parse_gemini_sse(r#"{"candidates":[{"finishReason":"MAX_TOKENS"}]}"#).unwrap();
        let mut state = crate::server::BufferedToolState::default();
        for event in &events {
            state.absorb(event);
        }
        assert_eq!(state.finish_reason(), "length");
    }

    #[tokio::test]
    async fn gemini_sse_stream_ends_with_length_for_max_tokens() {
        use futures::StreamExt as _;
        let response = crate::providers::sse_lines::response_from_chunks(vec![
            b"data: {\"candidates\":[{\"finishReason\":\"MAX_TOKENS\"}]}\n\n",
        ]);
        let events: Vec<_> = build_gemini_stream(response)
            .map(|event| event.expect("valid Gemini event"))
            .collect()
            .await;
        assert!(events.iter().any(|event| matches!(
            event,
            ProviderEvent::Finish {
                reason: crate::providers::FinishReason::Length
            }
        )));
    }

    /// RI-05 / M11: the SAME `thoughtsTokenCount` also lands on
    /// `UsageUpdate.reasoning`, broken out — `output_tokens` stays the folded
    /// (inclusive) total from the two tests above, unchanged by this field.
    #[test]
    fn thoughts_token_count_also_lands_on_reasoning_and_absence_stays_absent() {
        let reasoning_of = |chunk: &str| {
            parse_gemini_sse(chunk)
                .unwrap()
                .iter()
                .find_map(|e| match e {
                    ProviderEvent::UsageUpdate { reasoning, .. } => Some(*reasoning),
                    _ => None,
                })
                .expect("a UsageUpdate event")
        };
        assert_eq!(
            reasoning_of(
                r#"{"usageMetadata":{"promptTokenCount":677,"candidatesTokenCount":175,"thoughtsTokenCount":400,"totalTokenCount":1252}}"#
            ),
            Some(400)
        );
        assert_eq!(
            reasoning_of(
                r#"{"usageMetadata":{"promptTokenCount":1767,"candidatesTokenCount":1259,"totalTokenCount":3026}}"#
            ),
            None,
            "a non-thinking model omits the key entirely ⇒ absent, never a fabricated 0"
        );
    }

    /// A `€` cut across two network chunks must reach the client whole.
    #[tokio::test]
    async fn a_character_split_across_network_chunks_survives() {
        use futures::StreamExt as _;
        let resp = crate::providers::sse_lines::response_from_chunks(vec![
            b"data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"price \xE2\x82",
            b"\xAC5\"}]}}]}\r\n\r\n",
        ]);
        let events: Vec<_> = build_gemini_stream(resp).collect().await;
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

    // ── OG-03 D1: an image part must reach Gemini, never be dropped ─────────

    #[test]
    fn og03_d1_gemini_image_part_reaches_the_wire_as_inline_data() {
        use tracelane_shared::{ContentPart, ImageUrl};
        let req = ChatRequest {
            model: "gemini-2.5-pro".into(),
            messages: vec![Message {
                role: Role::User,
                content: MessageContent::Parts(vec![
                    ContentPart::Text {
                        text: "what is this?".into(),
                        cache_control: None,
                    },
                    ContentPart::ImageUrl {
                        image_url: ImageUrl {
                            url: "data:image/png;base64,AAAA".into(),
                            detail: None,
                        },
                    },
                ]),
                tool_call_id: None,
                tool_calls: None,
            }],
            stream: Some(true),
            ..Default::default()
        };
        let wire = serde_json::to_value(GeminiRequest::from_universal(req).unwrap()).unwrap();
        let parts = wire["contents"][0]["parts"].as_array().unwrap();
        let inline = parts
            .iter()
            .find_map(|p| p.get("inlineData"))
            .unwrap_or_else(|| panic!("image dropped on the way to Gemini: {wire}"));
        assert_eq!(inline["mimeType"], "image/png");
        assert_eq!(inline["data"], "AAAA");
    }

    // ── OG-03: every translated field, asserted on the exact upstream JSON ────

    fn og03_wire(req: ChatRequest) -> serde_json::Value {
        serde_json::to_value(GeminiRequest::from_universal(req).expect("builds")).expect("ser")
    }

    fn og03_base(model: &str) -> ChatRequest {
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

    #[test]
    fn og03_stop_cap_penalties_and_json_mode_reach_generation_config() {
        let mut req = og03_base("gemini-2.5-pro");
        req.stop = Some(tracelane_shared::Stop::One("END".into()));
        req.max_tokens = Some(10);
        req.max_completion_tokens = Some(50);
        req.presence_penalty = Some(0.25);
        req.frequency_penalty = Some(0.5);
        req.response_format = Some(serde_json::json!({
            "type": "json_schema",
            "json_schema": {"name": "x", "schema": {"type": "object"}}
        }));
        let cfg = og03_wire(req)["generationConfig"].clone();
        assert_eq!(cfg["stopSequences"], serde_json::json!(["END"]));
        assert_eq!(cfg["maxOutputTokens"], 50, "max_completion_tokens wins");
        assert_eq!(cfg["presencePenalty"], 0.25);
        assert_eq!(cfg["frequencyPenalty"], 0.5);
        assert_eq!(cfg["responseMimeType"], "application/json");
        assert_eq!(
            cfg["responseJsonSchema"],
            serde_json::json!({"type": "object"})
        );
        // json_object: the mime type only.
        let mut req = og03_base("gemini-2.5-pro");
        req.response_format = Some(serde_json::json!({"type": "json_object"}));
        let cfg = og03_wire(req)["generationConfig"].clone();
        assert_eq!(cfg["responseMimeType"], "application/json");
        assert!(cfg.get("responseJsonSchema").is_none());
        // The control: a plain request builds NO generationConfig at all.
        assert!(
            og03_wire(og03_base("gemini-2.5-pro"))
                .get("generationConfig")
                .is_none()
        );
    }

    #[test]
    fn og03_reasoning_effort_becomes_a_level_on_gemini_3_and_a_budget_before_it() {
        let mut req = og03_base("gemini-3.1-pro");
        req.reasoning_effort = Some("xhigh".into());
        assert_eq!(
            og03_wire(req)["generationConfig"]["thinkingConfig"],
            serde_json::json!({"thinkingLevel": "HIGH"})
        );
        let mut req = og03_base("gemini-2.5-flash");
        req.reasoning_effort = Some("medium".into());
        assert_eq!(
            og03_wire(req)["generationConfig"]["thinkingConfig"],
            serde_json::json!({"thinkingBudget": 8192})
        );
    }

    #[test]
    fn og03_audio_and_pdf_parts_ride_as_inline_data_in_order() {
        use tracelane_shared::{ContentPart, FilePart, InputAudio};
        let mut req = og03_base("gemini-2.5-pro");
        req.messages[0].content = MessageContent::Parts(vec![
            ContentPart::Text {
                text: "transcribe".into(),
                cache_control: None,
            },
            ContentPart::InputAudio {
                input_audio: InputAudio {
                    data: "AAAA".into(),
                    format: "mp3".into(),
                },
            },
            ContentPart::File {
                file: FilePart {
                    file_data: Some("data:application/pdf;base64,BBBB".into()),
                    ..Default::default()
                },
            },
        ]);
        let parts = og03_wire(req)["contents"][0]["parts"].clone();
        assert_eq!(parts[0], serde_json::json!({"text": "transcribe"}));
        assert_eq!(
            parts[1],
            serde_json::json!({"inlineData": {"mimeType": "audio/mp3", "data": "AAAA"}})
        );
        assert_eq!(
            parts[2],
            serde_json::json!({"inlineData": {"mimeType": "application/pdf", "data": "BBBB"}})
        );
    }

    #[test]
    fn og03_text_only_parts_keep_the_historical_single_joined_part() {
        use tracelane_shared::ContentPart;
        let mut req = og03_base("gemini-2.5-pro");
        req.messages[0].content = MessageContent::Parts(vec![
            ContentPart::Text {
                text: "a".into(),
                cache_control: None,
            },
            ContentPart::Text {
                text: "b".into(),
                cache_control: None,
            },
        ]);
        let parts = og03_wire(req)["contents"][0]["parts"].clone();
        assert_eq!(parts, serde_json::json!([{"text": "a\nb"}]));
    }
}

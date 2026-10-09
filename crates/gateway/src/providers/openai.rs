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
use tracing::instrument;

use tracelane_shared::{MessageContent, Role, TenantId, ToolChoice};

use crate::providers::{FinishReason, ProviderEvent, ProviderStream};
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
    // `openai()` (a dedicated constructor reading `OPENAI_BASE_URL`, defaulting
    // to `https://api.openai.com`) was deleted 2026-09-12 (B-390) — zero
    // callers anywhere; `providers/mod.rs`'s def-driven catalog constructs
    // every OpenAI-compatible provider, including plain OpenAI, through
    // `compatible()` below instead.

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
        // OG-05 §3.4: a model chat completions cannot serve goes through the
        // Responses API. Decided HERE, inside the one adapter, so breaker,
        // failover, guardrails and spans see the same `ProviderStream` as ever.
        if super::responses_bridge::applies(self.provider_id, &request) {
            return self.chat_via_responses(request, api_key).await;
        }
        let oai_request = OpenAiRequest::from_universal_for(request, self.provider_id);
        let url = format!("{}/v1/chat/completions", self.base_url);

        // SSRF: validate before the POST (reviewer).
        crate::ssrf_guard::validate_url(&url)
            .await
            .context("SSRF guard rejected OpenAI base URL")?;

        let response = crate::routing::deadlines::send(
            self.client
                .post(&url)
                .header("authorization", format!("Bearer {api_key}"))
                .header("content-type", "application/json")
                .json(&oai_request),
        )
        .await
        .context("failed to send request to OpenAI API")?;

        let status = response.status();
        if !status.is_success() {
            // SECURITY: do NOT include the upstream body in
            // the bail! string — OpenAI 401/403 bodies routinely echo the
            // offending Authorization header and would leak the customer's
            // BYOK key into our logs / error records / tenant-visible error JSON.
            // Body is consumed to free the connection but never logged.
            let retry_after = crate::providers::retry_after_from(response.headers());
            let body = crate::routing::deadlines::error_text(response).await?;
            tracing::warn!(status = %status, "OpenAI API error");
            // Typed so the gateway can tell an auth rejection (401/403 → the
            // tenant's key was rejected) from an outage (5xx → 502). Status only,
            // never the body (credential-echo risk above).
            //
            // OG-03 §3.4: a relayable 4xx also carries the upstream's own message —
            // scrubbed, truncated, key-stripped — built ONLY by `from_response`,
            // which refuses 401/403/407, every 5xx and any auth rejection.
            return Err(crate::providers::ProviderHttpError::from_response(
                self.provider_id,
                status.as_u16(),
                // OpenAI-shape bodies use a lowercase `error.code`, which
                // `safe_reason` deliberately rejects (the guard is SHOUTY_SNAKE
                // only). Status-level mapping (429/404) still applies to all 28
                // OpenAI-compatible providers; extracting their codes is a
                // separate, additive step.
                None,
                &body,
                api_key,
            )
            .with_retry_after(retry_after)
            .into());
        }

        let stream = build_openai_stream(response);
        Ok(Box::pin(stream))
    }
}

impl OpenAiProvider {
    /// `OG-05` §3.4: serve a chat request through `POST {base}/v1/responses`.
    /// The request body and the frame parser are `responses_bridge`'s; this
    /// method owns only the HTTP call, so its failure handling is the chat
    /// path's, line for line.
    ///
    /// # Errors
    /// Fail-CLOSED: SSRF refusal, transport failure, a non-2xx (typed
    /// `ProviderHttpError`, status only plus a scrubbed relayable message), or
    /// a request the Responses wire cannot carry. Upstream bodies never reach
    /// an error string.
    async fn chat_via_responses(
        &self,
        request: ChatRequest,
        api_key: &str,
    ) -> Result<ProviderStream> {
        let body = super::responses_bridge::build_body(&request)?;
        let url = format!("{}/v1/responses", self.base_url);

        crate::ssrf_guard::validate_url(&url)
            .await
            .context("SSRF guard rejected OpenAI base URL")?;

        let response = crate::routing::deadlines::send(
            self.client
                .post(&url)
                .header("authorization", format!("Bearer {api_key}"))
                .header("content-type", "application/json")
                .json(&body),
        )
        .await
        .context("failed to send request to OpenAI Responses API")?;

        let status = response.status();
        if !status.is_success() {
            // SECURITY: as in `chat` — the upstream body never enters an error string.
            let text = crate::routing::deadlines::error_text(response).await?;
            tracing::warn!(status = %status, "OpenAI Responses API error");
            return Err(crate::providers::ProviderHttpError::from_response(
                self.provider_id,
                status.as_u16(),
                None,
                &text,
                api_key,
            )
            .into());
        }

        Ok(Box::pin(build_responses_stream(response)))
    }
}

/// Responses SSE -> provider events, via `responses_bridge`'s pure parser.
fn build_responses_stream(
    response: reqwest::Response,
) -> impl Stream<Item = Result<ProviderEvent>> + Send {
    try_stream! {
        use futures::StreamExt as _;
        let mut byte_stream = response.bytes_stream();
        let mut buf: Vec<u8> = Vec::new();
        let mut st = super::responses_bridge::FrameState::default();
        while let Some(chunk) = byte_stream.next().await {
            let chunk: Bytes = chunk
                .map_err(reqwest::Error::without_url)
                .context("error reading Responses stream chunk")?;
            buf.extend_from_slice(&chunk);
            for event in super::responses_bridge::drain_frames(&mut buf, &mut st)? {
                yield event;
            }
        }
        // A stream that ends before a terminal frame is a truncated answer.
        if !st.finished {
            Err(anyhow::anyhow!(
                "the Responses stream ended before response.completed"
            ))?;
        }
    }
}

fn build_openai_stream(
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

            while let Some(line) = lines.next_line() {
                let line = line.context("non-UTF8 SSE line")?;

                if line.is_empty() || line.starts_with(':') {
                    continue;
                }
                if let Some(data) = line.strip_prefix("data: ") {
                    if data == "[DONE]" {
                        return;
                    }
                    if let Ok(events) = parse_openai_sse(data) {
                        for event in events {
                            yield event;
                        }
                    }
                }
            }
        }
    }
}

/// Parse one OpenAI SSE frame into zero or more provider events.
///
/// # OBS-53 — why this returns a `Vec` and not an `Option`
///
/// It used to return `Result<Option<ProviderEvent>>` — at most ONE event per
/// frame — and the `finish_reason` arm at the bottom survived that only because
/// *OpenAI sends `finish_reason` on its own chunk with an empty delta*, as the
/// comment there still explains.
///
/// **Logprobs have no such luck.** OpenAI puts `choices[0].logprobs` on the SAME
/// chunk as `choices[0].delta.content`. Under the old return type a logprobs
/// check placed after the content check would be unreachable for every real
/// chunk, and one placed before it would drop the token — so "add a logprobs
/// arm" produces a control that never fires, which is the CLAUDE.md §1 class.
///
/// `parse_anthropic_sse_event` already returns a `Vec` for exactly this reason
/// (one `message_delta` carries usage AND a stop reason), so this is the repo's
/// own precedent rather than a new shape.
///
/// **The precedence between content / tool-call / finish is DELIBERATELY
/// UNCHANGED.** At most one of those three is still emitted per frame, in the
/// same order, so the known limitation recorded at the `finish_reason` arm
/// (a compat host that bundles the reason onto the last content chunk loses it)
/// is neither fixed nor worsened here. Widening that is a behaviour change to
/// existing streams and does not belong in an observability block.
fn parse_openai_sse(data: &str) -> Result<Vec<ProviderEvent>> {
    let v: Value = serde_json::from_str(data).context("invalid SSE JSON")?;

    // RI-05 / B-444: the provider's identity claims ride every OpenAI-compatible
    // chunk (`id`, `model`, `system_fingerprint`). Emitted FIRST on any frame that
    // carries at least one of them; consumers keep the first and ignore the rest.
    let mut events: Vec<ProviderEvent> = response_meta(&v).into_iter().collect();

    // Usage chunk (stream_options.include_usage = true). Pushed LAST, after whatever
    // else this frame carries — F3 (2026-10-03): Mistral bundles the whole tool call,
    // `finish_reason` AND `usage` onto ONE terminal chunk, and an early return here
    // dropped the call and the reason with no error.
    let usage_event = v.get("usage").filter(|u| !u.is_null()).map(|usage| {
        let input = usage["prompt_tokens"].as_u64().unwrap_or(0) as u32;
        let output = usage["completion_tokens"].as_u64().unwrap_or(0) as u32;
        // Wire-reported cost: OpenRouter (and some OpenAI-compatible
        // hosts) attach `usage.cost` in USD. Absent → None, never computed.
        let cost_usd = usage.get("cost").and_then(|c| c.as_f64());
        // RI-05 / M11: o-series reasoning tokens ride a NESTED object,
        // disjoint from (and already counted inside) `completion_tokens` —
        // `output_tokens` above stays inclusive. `.as_u64()` on a missing key
        // is `None`, never a fabricated `0` for a non-reasoning model.
        let reasoning = usage
            .get("completion_tokens_details")
            .and_then(|d| d.get("reasoning_tokens"))
            .and_then(serde_json::Value::as_u64)
            .map(|n| n as u32);
        ProviderEvent::UsageUpdate {
            input_tokens: input,
            output_tokens: output,
            cache_read: None,
            cache_creation: None,
            cost_usd,
            reasoning,
        }
    });

    // OBS-53. Collected BEFORE the content/tool/finish decision below and
    // carried alongside whichever of those wins, because this frame can
    // legitimately be both a token and its logprob. Absent ⇒ nothing pushed, so
    // a stream from a client that did not ask for logprobs is byte-identical to
    // before this existed.
    if let Some(entries) = v["choices"][0]["logprobs"]["content"].as_array() {
        let logprobs: Vec<f64> = entries
            .iter()
            .filter_map(|e| e["logprob"].as_f64())
            // A logprob is <= 0 and finite. A provider that sends `null`, a
            // string, or -inf for a zero-probability token would otherwise
            // poison a mean; filtering here keeps `token_count` honest, because
            // the count is of tokens actually SUMMARISED, not of tokens seen.
            .filter(|l| l.is_finite())
            .collect();
        if !logprobs.is_empty() {
            events.push(ProviderEvent::LogprobsDelta { logprobs });
        }
    }

    // Every fact on the frame, in wire order: content, tool calls, stop reason, usage.
    // F3: this used to return after the FIRST of these it found, so a compatible host
    // that bundles them (Mistral's terminal chunk; a last token carrying its reason)
    // lost the rest silently.
    let delta = &v["choices"][0]["delta"];

    // Text delta
    if let Some(text) = delta["content"].as_str()
        && !text.is_empty()
    {
        events.push(ProviderEvent::StreamChunk {
            delta: text.to_owned(),
        });
    }

    // Tool call delta
    // OG-90: EVERY entry, not `.first()`. OpenAI sends one call per chunk, but several
    // OpenAI-compatible providers batch parallel calls into one delta, and the second call used
    // to vanish with no error.
    if let Some(tool_calls) = delta["tool_calls"].as_array() {
        for tc in tool_calls {
            let index = tc["index"].as_u64().unwrap_or(0) as usize;
            let id = tc["id"].as_str().map(str::to_owned);
            let name = tc["function"]["name"].as_str().map(str::to_owned);
            let input_delta = tc["function"]["arguments"]
                .as_str()
                .unwrap_or("")
                .to_owned();
            events.push(ProviderEvent::ToolCallDelta {
                index,
                id,
                name,
                input_delta,
            });
        }
    }

    // B-354: the provider's own stop reason, passed through.
    if let Some(reason) = v["choices"][0]["finish_reason"]
        .as_str()
        .and_then(FinishReason::from_openai_finish_reason)
    {
        events.push(ProviderEvent::Finish { reason });
    }

    events.extend(usage_event);
    Ok(events)
}

/// RI-05 / B-444: `id` / `model` / `system_fingerprint` from one OpenAI-compatible
/// frame, or `None` when the frame names none of them (a usage-only tail chunk from
/// some hosts). Never fabricates: an absent field stays absent.
fn response_meta(v: &Value) -> Option<ProviderEvent> {
    let id = v.get("id").and_then(Value::as_str).map(str::to_owned);
    let model = v.get("model").and_then(Value::as_str).map(str::to_owned);
    let system_fingerprint = v
        .get("system_fingerprint")
        .and_then(Value::as_str)
        .map(str::to_owned);
    (id.is_some() || model.is_some() || system_fingerprint.is_some()).then_some(
        ProviderEvent::ResponseMeta {
            id,
            model,
            system_fingerprint,
        },
    )
}

// ── OpenAI request/response types ────────────────────────────────────────────

/// `pub(super)` so `azure` can reuse this EXACT translation.
///
/// Azure speaks the OpenAI wire format but had been serialising the internal
/// `ChatRequest` straight to the wire, which sent Anthropic-shaped `tools`
/// (`name`/`input_schema`) and Anthropic-shaped `tool_calls` (`{id,name,input}`)
/// to an endpoint expecting OpenAI's nested forms. Two translations for one wire
/// format is the drift exist to prevent; there is now one.
#[derive(Debug, Serialize)]
pub(super) struct OpenAiRequest {
    model: String,
    messages: Vec<OpenAiMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<OpenAiTool>>,
    /// B-355. Forwarded VERBATIM: the internal `ToolChoice` serialises back to
    /// the exact OpenAI wire form, so there is no translation to get wrong.
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<ToolChoice>,
    stream: bool,
    stream_options: StreamOptions,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    /// GWY-48. Forwarded because a parameter we RECORD on the span and then
    /// throw away is the quiet dishonesty this repo keeps paying for. Every one
    /// is `skip_serializing_if`, so a request that did not send it serialises
    /// byte-identically to before these fields existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f32>,
    /// GWY-48. This is the ONLY wire with a seed concept, which is why only this
    /// adapter carries it.
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<u64>,
    /// OBS-53. Never injected by the gateway — present only when the CLIENT
    /// asked, because it changes the response body and this gateway is
    /// byte-compatible by contract.
    #[serde(skip_serializing_if = "Option::is_none")]
    logprobs: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_logprobs: Option<u8>,
    /// OG-03. Every field below is forwarded exactly as the caller sent it and is absent
    /// from the wire when they sent none, so an older request serialises byte-identically.
    #[serde(skip_serializing_if = "Option::is_none")]
    max_completion_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop: Option<tracelane_shared::Stop>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning_effort: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    presence_penalty: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    frequency_penalty: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parallel_tool_calls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_tier: Option<String>,
    /// OG-03. The caller's unmodelled top-level fields, forwarded to an OpenAI-compatible
    /// provider so a new provider feature works without a gateway release. Keys this
    /// struct writes itself are removed first — never emitted twice.
    #[serde(flatten, skip_serializing_if = "serde_json::Map::is_empty")]
    extra: serde_json::Map<String, Value>,
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
    /// Provider-agnostic form (Azure, and every test written before OG-03): `max_tokens`
    /// stays `max_tokens`.
    pub(super) fn from_universal(req: ChatRequest) -> Self {
        Self::from_universal_for(req, "")
    }

    /// `provider_id` is the catalog id of the adapter sending this. **For `openai` the
    /// output-token cap is sent as `max_completion_tokens` even when the caller sent
    /// `max_tokens`**: OpenAI accepts it on every chat model and its reasoning models accept
    /// ONLY it. Every other OpenAI-compatible provider gets the cap under the name the
    /// caller used — they implement the older name, and several reject the newer one.
    pub(super) fn from_universal_for(mut req: ChatRequest, provider_id: &str) -> Self {
        let (max_tokens, max_completion_tokens) = if provider_id == "openai" {
            (None, req.max_completion_tokens.or(req.max_tokens))
        } else {
            (req.max_tokens, req.max_completion_tokens)
        };
        let mut extra = std::mem::take(&mut req.extra);
        extra.retain(|k, _| !crate::request_support::ADAPTER_OWNED_KEYS.contains(&k.as_str()));
        let mut messages: Vec<OpenAiMessage> =
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
                                    // Cache_control is an Anthropic-only
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

        // OG-90: `ChatRequest.system` is how the Responses-translate and Anthropic-shaped entries
        // carry a system prompt (Codex's `instructions`, the A5 untrusted-data instruction). The
        // OpenAI wire has no top-level `system`, so it is the FIRST message — it used to be dropped
        // here without an error.
        if let Some(system) = req.system.take().filter(|s| !s.is_empty()) {
            messages.insert(
                0,
                OpenAiMessage {
                    role: "system".into(),
                    content: Value::String(system),
                    tool_call_id: None,
                    tool_calls: None,
                },
            );
        }

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
            tool_choice: req.tool_choice,
            stream: req.stream.unwrap_or(true),
            stream_options: StreamOptions {
                include_usage: true,
            },
            max_tokens,
            temperature: req.temperature,
            top_p: req.top_p,
            seed: req.seed,
            logprobs: req.logprobs,
            top_logprobs: req.top_logprobs,
            max_completion_tokens,
            stop: req.stop,
            response_format: req.response_format,
            reasoning_effort: req.reasoning_effort,
            presence_penalty: req.presence_penalty,
            frequency_penalty: req.frequency_penalty,
            parallel_tool_calls: req.parallel_tool_calls,
            user: req.user,
            service_tier: req.service_tier,
            extra,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracelane_shared::{ChatRequest, Message, MessageContent, Role};

    fn simple_request() -> ChatRequest {
        ChatRequest {
            top_p: None,
            seed: None,
            logprobs: None,
            top_logprobs: None,
            model: "gpt-5.5".into(),
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

    // ── OG-03 ───────────────────────────────────────────────────────────────

    #[test]
    fn og03_openai_gets_max_completion_tokens_even_when_the_caller_sent_max_tokens() {
        let mut req = simple_request();
        req.max_tokens = Some(100);
        let wire = serde_json::to_value(OpenAiRequest::from_universal_for(req, "openai")).unwrap();
        assert_eq!(wire["max_completion_tokens"], 100);
        assert!(
            wire.get("max_tokens").is_none(),
            "reasoning models reject max_tokens"
        );
        // max_completion_tokens from the caller wins over max_tokens.
        let mut req = simple_request();
        req.max_tokens = Some(100);
        req.max_completion_tokens = Some(7);
        let wire = serde_json::to_value(OpenAiRequest::from_universal_for(req, "openai")).unwrap();
        assert_eq!(wire["max_completion_tokens"], 7);
        // Every other compatible provider keeps the name the caller used.
        let mut req = simple_request();
        req.max_tokens = Some(100);
        let wire = serde_json::to_value(OpenAiRequest::from_universal_for(req, "groq")).unwrap();
        assert_eq!(wire["max_tokens"], 100);
        assert!(wire.get("max_completion_tokens").is_none());
    }

    #[test]
    fn og03_extra_is_forwarded_and_never_overrides_what_the_adapter_writes() {
        let mut req = simple_request();
        req.extra
            .insert("logit_bias".into(), serde_json::json!({"1": 2}));
        req.extra.insert(
            "stream_options".into(),
            serde_json::json!({"include_usage": false}),
        );
        req.extra
            .insert("model".into(), serde_json::json!("attacker-model"));
        let json = serde_json::to_string(&OpenAiRequest::from_universal(req)).unwrap();
        let wire: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(wire["logit_bias"], serde_json::json!({"1": 2}));
        assert_eq!(
            wire["stream_options"],
            serde_json::json!({"include_usage": true})
        );
        assert_eq!(wire["model"], "gpt-5.5");
        assert_eq!(json.matches("\"model\"").count(), 1, "{json}");
        assert_eq!(json.matches("stream_options").count(), 1, "{json}");
    }

    #[test]
    fn og03_a_request_with_none_of_the_new_fields_serialises_as_before() {
        let wire = serde_json::to_value(OpenAiRequest::from_universal(simple_request())).unwrap();
        for k in [
            "stop",
            "response_format",
            "reasoning_effort",
            "max_completion_tokens",
            "presence_penalty",
            "frequency_penalty",
            "parallel_tool_calls",
            "user",
            "service_tier",
        ] {
            assert!(wire.get(k).is_none(), "{k} must be absent: {wire}");
        }
    }

    #[test]
    fn cache_control_is_stripped_for_openai() {
        // Cache_control is an Anthropic-only marker; OpenAI must never
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

    // ── B-355: tool_choice, forwarded verbatim ──────────────────────────────

    /// The OpenAI-family adapters need no translation — the internal
    /// `ToolChoice` serialises back to the exact wire form the caller sent, so
    /// a round trip through the gateway is a no-op.
    #[test]
    fn tool_choice_is_forwarded_verbatim() {
        use tracelane_shared::ToolChoice;
        for (choice, want) in [
            (ToolChoice::Auto, serde_json::json!("auto")),
            (ToolChoice::None, serde_json::json!("none")),
            (ToolChoice::Required, serde_json::json!("required")),
            (
                ToolChoice::Function {
                    name: "get_weather".into(),
                },
                serde_json::json!({
                    "type": "function",
                    "function": { "name": "get_weather" }
                }),
            ),
        ] {
            let mut req = simple_request();
            req.tool_choice = Some(choice.clone());
            let wire = serde_json::to_value(OpenAiRequest::from_universal(req)).expect("serialize");
            assert_eq!(wire["tool_choice"], want, "for {choice:?}");
        }
    }

    /// The control: no `tool_choice` on the way in, no key on the way out.
    #[test]
    fn a_request_without_tool_choice_sends_no_key() {
        let wire =
            serde_json::to_value(OpenAiRequest::from_universal(simple_request())).expect("ser");
        assert!(
            wire.get("tool_choice").is_none(),
            "an absent tool_choice must not reach the wire: {wire}"
        );
    }

    // ── B-354: the provider's own finish_reason ─────────────────────────────

    /// OpenAI sends `finish_reason` on its OWN chunk with an empty delta. Before
    /// B-354 that chunk parsed to `None` and the reason was lost.
    /// RI-05 / B-444: an OpenAI-compatible chunk names the response it belongs to.
    #[test]
    fn response_meta_rides_first_on_a_chunk_that_names_the_model_and_not_on_one_that_does_not() {
        let chunk = r#"{"id":"chatcmpl-9x","object":"chat.completion.chunk","model":"gpt-4o-2024-08-06","system_fingerprint":"fp_44709d6fcb","choices":[{"index":0,"delta":{"content":"Hi"},"finish_reason":null}]}"#;
        let events = parse_openai_sse(chunk).unwrap();
        match &events[0] {
            ProviderEvent::ResponseMeta {
                id,
                model,
                system_fingerprint,
            } => {
                assert_eq!(id.as_deref(), Some("chatcmpl-9x"));
                assert_eq!(model.as_deref(), Some("gpt-4o-2024-08-06"));
                assert_eq!(system_fingerprint.as_deref(), Some("fp_44709d6fcb"));
            }
            other => panic!("ResponseMeta must come first, got {other:?}"),
        }
        assert!(
            matches!(events[1], ProviderEvent::StreamChunk { .. }),
            "the token still follows"
        );
        // A frame with none of the three emits no meta and nothing else changes.
        let bare = r#"{"choices":[{"index":0,"delta":{"content":"Hi"},"finish_reason":null}]}"#;
        let events = parse_openai_sse(bare).unwrap();
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, ProviderEvent::ResponseMeta { .. }))
        );
        assert!(matches!(events[0], ProviderEvent::StreamChunk { .. }));
    }

    /// RI-05 / M11: an o-series `usage.completion_tokens_details.reasoning_tokens`
    /// lands on `UsageUpdate.reasoning`, and `output_tokens` stays the SAME
    /// inclusive total it always was — reasoning is broken out, not subtracted.
    #[test]
    fn reasoning_tokens_are_parsed_separately_and_output_tokens_stays_inclusive() {
        let chunk = r#"{"choices":[],"usage":{"prompt_tokens":25,"completion_tokens":100,"completion_tokens_details":{"reasoning_tokens":7}}}"#;
        let events = parse_openai_sse(chunk).unwrap();
        let usage = events
            .iter()
            .find_map(|e| match e {
                ProviderEvent::UsageUpdate {
                    input_tokens,
                    output_tokens,
                    reasoning,
                    ..
                } => Some((*input_tokens, *output_tokens, *reasoning)),
                _ => None,
            })
            .expect("a UsageUpdate event");
        assert_eq!(usage, (25, 100, Some(7)));

        // A non-reasoning model's usage carries no such key ⇒ `None`, never `Some(0)`.
        let plain = r#"{"choices":[],"usage":{"prompt_tokens":25,"completion_tokens":10}}"#;
        let events = parse_openai_sse(plain).unwrap();
        let reasoning = events
            .iter()
            .find_map(|e| match e {
                ProviderEvent::UsageUpdate { reasoning, .. } => Some(*reasoning),
                _ => None,
            })
            .expect("a UsageUpdate event");
        assert_eq!(
            reasoning, None,
            "no completion_tokens_details ⇒ absent, never a fabricated 0"
        );
    }

    #[test]
    fn the_terminal_chunks_finish_reason_is_parsed() {
        for (wire, want) in [
            ("stop", FinishReason::Stop),
            ("length", FinishReason::Length),
            ("tool_calls", FinishReason::ToolCalls),
            // The pre-2023 spelling some compatible hosts still emit.
            ("function_call", FinishReason::ToolCalls),
            ("content_filter", FinishReason::ContentFilter),
        ] {
            let data =
                format!(r#"{{"choices":[{{"index":0,"delta":{{}},"finish_reason":"{wire}"}}]}}"#);
            match parse_openai_sse(&data).expect("parses").as_slice() {
                [ProviderEvent::Finish { reason }] => assert_eq!(*reason, want, "for {wire}"),
                other => panic!("expected a Finish event for {wire}, got {other:?}"),
            }
        }
    }

    /// A reason we do not recognise is DROPPED, not forwarded — an OpenAI
    /// client cannot act on a word that is not in its vocabulary, and the
    /// buffered path can still derive `tool_calls` from the response contents.
    #[test]
    fn an_unrecognised_finish_reason_yields_no_event() {
        let data = r#"{"choices":[{"index":0,"delta":{},"finish_reason":"invented"}]}"#;
        assert!(
            parse_openai_sse(data).expect("parses").is_empty(),
            "an unknown finish_reason must not reach the wire"
        );
    }

    /// **OBS-53's whole reason for changing this function's return type.** OpenAI
    /// puts `logprobs` on the SAME chunk as the content token. Under the old
    /// `Option` return, whichever check came first won and the other fact was
    /// lost; this asserts BOTH survive, and that the content event is still
    /// there — the property a naive "add an arm" would have broken.
    #[test]
    fn an_openai_chunk_with_content_and_logprobs_still_yields_the_content_event() {
        let data = r#"{"choices":[{"index":0,"delta":{"content":"hi"},
            "logprobs":{"content":[{"token":"hi","logprob":-0.25}]},
            "finish_reason":null}]}"#;
        let events = parse_openai_sse(data).expect("parses");
        assert_eq!(events.len(), 2, "got {events:?}");
        match events.as_slice() {
            [
                ProviderEvent::LogprobsDelta { logprobs },
                ProviderEvent::StreamChunk { delta },
            ] => {
                assert_eq!(delta, "hi", "the token must NOT be dropped");
                assert_eq!(logprobs, &vec![-0.25]);
            }
            other => panic!("expected logprobs + content, got {other:?}"),
        }
    }

    /// A chunk with no logprobs is byte-identical in behaviour to before OBS-53:
    /// exactly one event, and it is the content.
    #[test]
    fn a_chunk_without_logprobs_yields_exactly_one_event() {
        let data = r#"{"choices":[{"index":0,"delta":{"content":"hi"}}]}"#;
        assert_eq!(parse_openai_sse(data).expect("parses").len(), 1);
    }

    /// A non-finite logprob is dropped rather than allowed to poison a mean —
    /// and if that leaves nothing, no event is emitted at all.
    #[test]
    fn a_non_finite_logprob_is_dropped_not_summarised() {
        let data = r#"{"choices":[{"index":0,"delta":{"content":"hi"},
            "logprobs":{"content":[{"token":"hi","logprob":null}]}}]}"#;
        let events = parse_openai_sse(data).expect("parses");
        assert_eq!(events.len(), 1, "only the content event: {events:?}");
    }

    /// GWY-48: the four new wire fields reach the OpenAI body, and a request that
    /// sent none of them serialises without any of the keys.
    #[test]
    fn the_openai_body_forwards_top_p_seed_and_logprobs_only_when_sent() {
        let bare = OpenAiRequest::from_universal(simple_request());
        let json = serde_json::to_string(&bare).expect("serialises");
        for k in ["top_p", "seed", "logprobs", "top_logprobs"] {
            assert!(!json.contains(k), "`{k}` must be absent: {json}");
        }

        let mut req = simple_request();
        req.top_p = Some(0.9);
        req.seed = Some(7);
        req.logprobs = Some(true);
        req.top_logprobs = Some(3);
        let json = serde_json::to_string(&OpenAiRequest::from_universal(req)).expect("serialises");
        assert!(json.contains(r#""top_p":0.9"#), "{json}");
        assert!(json.contains(r#""seed":7"#), "{json}");
        assert!(json.contains(r#""logprobs":true"#), "{json}");
        assert!(json.contains(r#""top_logprobs":3"#), "{json}");
    }

    /// Live defect F3 (2026-10-03, founder Mistral key): Mistral sends the WHOLE tool
    /// call, `finish_reason` and `usage` on ONE terminal chunk (verbatim shape below,
    /// `id`/`model` dropped). The `usage` arm returned early, so the call and the reason
    /// vanished: the client got `finish_reason: stop` and no `tool_calls`, with no error.
    #[test]
    fn a_bundled_terminal_chunk_keeps_its_tool_call_reason_and_usage() {
        let data = r#"{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"id":"ovsMU69C5","type":"function","function":{"name":"get_weather","arguments":"{\"city\": \"Paris\"}"},"index":0}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":71,"total_tokens":83,"completion_tokens":12}}"#;
        match parse_openai_sse(data).expect("parses").as_slice() {
            [
                ProviderEvent::ToolCallDelta {
                    index: 0,
                    id,
                    name,
                    input_delta,
                },
                ProviderEvent::Finish {
                    reason: FinishReason::ToolCalls,
                },
                ProviderEvent::UsageUpdate {
                    input_tokens: 71,
                    output_tokens: 12,
                    ..
                },
            ] => {
                assert_eq!(id.as_deref(), Some("ovsMU69C5"));
                assert_eq!(name.as_deref(), Some("get_weather"));
                assert_eq!(input_delta, r#"{"city": "Paris"}"#);
            }
            other => panic!("expected tool call + finish + usage, got {other:?}"),
        }
    }

    /// Same class, content side: a host that bundles the last token with its stop
    /// reason keeps BOTH.
    #[test]
    fn a_content_chunk_carrying_its_finish_reason_keeps_both() {
        let data = r#"{"choices":[{"index":0,"delta":{"content":"5"},"finish_reason":"length"}]}"#;
        match parse_openai_sse(data).expect("parses").as_slice() {
            [
                ProviderEvent::StreamChunk { delta },
                ProviderEvent::Finish {
                    reason: FinishReason::Length,
                },
            ] => assert_eq!(delta, "5"),
            other => panic!("expected content + finish, got {other:?}"),
        }
    }

    /// The control: a content chunk still parses as content, unchanged.
    #[test]
    fn a_content_chunk_is_still_a_content_chunk() {
        let data = r#"{"choices":[{"index":0,"delta":{"content":"hi"},"finish_reason":null}]}"#;
        match parse_openai_sse(data).expect("parses").as_slice() {
            [ProviderEvent::StreamChunk { delta }] => assert_eq!(delta, "hi"),
            other => panic!("expected a content chunk, got {other:?}"),
        }
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

// ============================================================================
// GWY-26 — the OpenAI Embeddings wire shape, owned by the adapter that speaks it.
//
// Why this lives here and not in its own module: `openai.rs` IS the definition
// of the OpenAI wire format, and every OpenAI-compatible provider in
// `crates/gateway/providers.tsv` reuses this same adapter.
//
// GWY-42 retired the second reason this comment used to give — that a new
// `providers/embeddings.rs` would inflate the provider count.
// `scripts/ci/check-provider-count.py` no longer globs `providers/*.rs`; it
// derives the count from `ProviderRegistry`'s adapter fields plus the catalog
// rows, so adding a module here cannot move it. The leak that guard exists to
// stop (, a wrong count reaching published marketing copy) is still real.
//
// Why the endpoint exists at all: the flight recorder claims full-fidelity
// capture of what an agent did, but the gateway mounted exactly three top-level
// routes and none of them was `/v1/embeddings`, so every embeddings call in a
// RAG agent went straight to the provider — the retrieval step that decides
// what the model sees was invisible in the ledger and in /traces.
//
// Coverage is deliberately narrow and fails CLOSED: only providers exposing an
// OpenAI-compatible `POST {base}/v1/embeddings` are dispatched
// (`ProviderRegistry::openai_compatible`). Anthropic, Google/Vertex, Bedrock,
// Cohere and Azure each use a different embeddings wire format; a request for
// one of them is refused by name rather than forwarded on a guess, which would
// surface as an opaque upstream 400 that reads like a Tracelane outage.
// ============================================================================

/// An OpenAI-shaped embeddings request.
///
/// `input` stays a `serde_json::Value` because the OpenAI contract accepts four
/// forms (string, array of strings, array of tokens, array of token arrays) and
/// re-encoding them into a Rust enum would only add a way to mangle a caller's
/// payload. It is *validated* — see [`EmbeddingsRequest::validate`] — never
/// silently reshaped.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingsRequest {
    pub model: String,
    pub input: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dimensions: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

impl EmbeddingsRequest {
    /// Reject an `input` no provider can embed, before a credential is
    /// resolved or a byte leaves the gateway.
    ///
    /// # Errors
    ///
    /// **Fails CLOSED.** An absent, empty, or wrong-typed `input` is a caller
    /// error; forwarding it burns a provider round-trip and returns an upstream
    /// 400 that reads as a Tracelane fault.
    pub fn validate(&self) -> Result<()> {
        if self.model.trim().is_empty() {
            bail!("`model` is required");
        }
        match &self.input {
            serde_json::Value::String(s) if !s.is_empty() => Ok(()),
            serde_json::Value::String(_) => bail!("`input` must not be an empty string"),
            serde_json::Value::Array(items) if !items.is_empty() => {
                let uniform_strings = items.iter().all(|i| i.is_string());
                let uniform_tokens = items.iter().all(|i| {
                    i.is_number()
                        || i.as_array()
                            .is_some_and(|a| a.iter().all(serde_json::Value::is_number))
                });
                if uniform_strings || uniform_tokens {
                    Ok(())
                } else {
                    bail!("`input` array must be all strings, all tokens, or all token arrays")
                }
            }
            serde_json::Value::Array(_) => bail!("`input` must not be an empty array"),
            _ => bail!("`input` must be a string or an array"),
        }
    }

    /// Number of separate texts embedded. Drives nothing but telemetry — the
    /// billed unit is the provider-reported token count.
    #[must_use]
    pub fn input_count(&self) -> usize {
        match &self.input {
            serde_json::Value::Array(items) => items.len(),
            _ => 1,
        }
    }
}

/// One embedding vector in the response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingData {
    #[serde(default = "embedding_object")]
    pub object: String,
    pub index: u32,
    pub embedding: Vec<f32>,
}

fn embedding_object() -> String {
    "embedding".to_string()
}

/// Provider-reported token usage. Embeddings have no output tokens.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct EmbeddingsUsage {
    #[serde(default)]
    pub prompt_tokens: u32,
    #[serde(default)]
    pub total_tokens: u32,
}

/// An OpenAI-shaped embeddings response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingsResponse {
    #[serde(default = "list_object")]
    pub object: String,
    pub data: Vec<EmbeddingData>,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub usage: EmbeddingsUsage,
}

fn list_object() -> String {
    "list".to_string()
}

impl EmbeddingsResponse {
    /// Tokens to meter for this request. Prefers the provider's `total_tokens`
    /// and falls back to `prompt_tokens`; never fabricates a count.
    #[must_use]
    pub fn billable_tokens(&self) -> u32 {
        if self.usage.total_tokens > 0 {
            self.usage.total_tokens
        } else {
            self.usage.prompt_tokens
        }
    }
}

impl OpenAiProvider {
    /// `POST {base_url}/v1/embeddings`.
    ///
    /// # Errors
    ///
    /// **Fails CLOSED** — an error here is returned to the caller, never
    /// swallowed:
    /// - the SSRF guard rejects the configured base URL;
    /// - the request cannot be sent;
    /// - the upstream answers non-2xx, which becomes a typed
    ///   [`crate::providers::ProviderHttpError`] carrying the STATUS ONLY. The upstream body is
    ///   read to free the connection and then dropped — provider error bodies
    ///   routinely echo the `Authorization` header, i.e. the tenant's own BYOK
    ///   key (`.claude/rules/security.md`, /);
    /// - the 2xx body is not an embeddings payload.
    #[instrument(skip(self, request, api_key), fields(
        tenant_id = %tenant_id,
        model = %request.model,
        provider = self.provider_id,
        inputs = request.input_count(),
    ))]
    pub async fn embeddings(
        &self,
        request: &EmbeddingsRequest,
        api_key: &str,
        tenant_id: &TenantId,
    ) -> Result<EmbeddingsResponse> {
        let url = format!("{}/v1/embeddings", self.base_url);

        crate::ssrf_guard::validate_url(&url)
            .await
            .context("SSRF guard rejected the embeddings base URL")?;

        let response = crate::routing::deadlines::send(
            self.client
                .post(&url)
                .header("authorization", format!("Bearer {api_key}"))
                .header("content-type", "application/json")
                .json(request),
        )
        .await
        .context("failed to send embeddings request upstream")?;

        let status = response.status();
        if !status.is_success() {
            // Body consumed to free the connection, never logged or propagated
            // (credential-echo risk — see the `# Errors` note above).
            let retry_after = crate::providers::retry_after_from(response.headers());
            let _body = crate::routing::deadlines::error_text(response).await?;
            tracing::warn!(status = %status, provider = self.provider_id, "embeddings upstream error");
            return Err(crate::providers::ProviderHttpError {
                provider: self.provider_id,
                status: status.as_u16(),
                reason: None,
                message: None,
                retry_after,
            }
            .into());
        }

        response
            .json::<EmbeddingsResponse>()
            .await
            .map_err(reqwest::Error::without_url)
            .context("upstream returned a body that is not an embeddings response")
    }
}

#[cfg(all(test, debug_assertions))]
mod embeddings_tests {
    use super::*;
    use uuid::Uuid;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Wiremock binds 127.0.0.1 and the SSRF guard blocks loopback. Same
    /// thread-local RAII opt-in `providers::smoke_tests` uses — never a
    /// process-env mutation, which would race the parallel suite.
    struct LoopbackBypassGuard;

    impl LoopbackBypassGuard {
        fn new() -> Self {
            crate::ssrf_guard::set_loopback_bypass_for_tests(true);
            Self
        }
    }

    impl Drop for LoopbackBypassGuard {
        fn drop(&mut self) {
            crate::ssrf_guard::set_loopback_bypass_for_tests(false);
        }
    }

    fn tenant() -> TenantId {
        TenantId::from_jwt_claim(Uuid::from_u128(0xE11BE11B))
    }

    fn req(input: serde_json::Value) -> EmbeddingsRequest {
        EmbeddingsRequest {
            model: "text-embedding-3-small".into(),
            input,
            encoding_format: None,
            dimensions: None,
            user: None,
        }
    }

    // ── Negative first: every input shape that must be REFUSED. ──

    #[test]
    fn rejects_inputs_no_provider_can_embed() {
        for bad in [
            serde_json::json!(null),
            serde_json::json!(""),
            serde_json::json!([]),
            serde_json::json!({ "text": "hi" }),
            serde_json::json!(["ok", { "not": "a string" }]),
            serde_json::json!(true),
        ] {
            assert!(
                req(bad.clone()).validate().is_err(),
                "input {bad} must be refused before dispatch"
            );
        }
    }

    #[test]
    fn accepts_every_documented_input_shape() {
        for good in [
            serde_json::json!("one string"),
            serde_json::json!(["a", "b"]),
            serde_json::json!([1, 2, 3]),
            serde_json::json!([[1, 2], [3, 4]]),
        ] {
            req(good.clone())
                .validate()
                .unwrap_or_else(|e| panic!("input {good} must be accepted: {e}"));
        }
    }

    #[test]
    fn rejects_a_missing_model() {
        let mut r = req(serde_json::json!("hi"));
        r.model = "  ".into();
        assert!(r.validate().is_err(), "a blank model must be refused");
    }

    // ── The end state: real vectors come back over real HTTP. ──

    #[tokio::test]
    async fn returns_the_upstream_vectors_and_usage() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/embeddings"))
            .and(header("authorization", "Bearer sk-test-key"))
            // The caller's model + input must actually reach the upstream.
            .and(body_string_contains("text-embedding-3-small"))
            .and(body_string_contains("hello world"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "object": "list",
                "data": [
                    { "object": "embedding", "index": 0, "embedding": [0.25, -0.5, 0.75] },
                    { "object": "embedding", "index": 1, "embedding": [1.0, 0.0, -1.0] }
                ],
                "model": "text-embedding-3-small",
                "usage": { "prompt_tokens": 7, "total_tokens": 7 }
            })))
            .mount(&server)
            .await;

        let provider = OpenAiProvider::compatible(server.uri(), "openai")
            .expect("build OpenAI-compatible provider");
        let out = provider
            .embeddings(
                &req(serde_json::json!(["hello world", "second"])),
                "sk-test-key",
                &tenant(),
            )
            .await
            .expect("embeddings round-trip");

        // The observable end state: usable vectors, not a status code.
        assert_eq!(out.data.len(), 2);
        assert_eq!(out.data[0].embedding, vec![0.25, -0.5, 0.75]);
        assert_eq!(out.data[1].embedding, vec![1.0, 0.0, -1.0]);
        assert_eq!(out.data[1].index, 1);
        assert_eq!(out.model, "text-embedding-3-small");
        assert_eq!(out.billable_tokens(), 7);
    }

    #[tokio::test]
    async fn upstream_401_is_typed_and_never_echoes_the_key() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;

        // A real OpenAI 401 body echoes the offending key back at us.
        Mock::given(method("POST"))
            .and(path("/v1/embeddings"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": { "message": "Incorrect API key provided: sk-leaky-secret-value" }
            })))
            .mount(&server)
            .await;

        let provider = OpenAiProvider::compatible(server.uri(), "openai")
            .expect("build OpenAI-compatible provider");
        let err = provider
            .embeddings(
                &req(serde_json::json!("hi")),
                "sk-leaky-secret-value",
                &tenant(),
            )
            .await
            .expect_err("a 401 must surface as an error");

        let typed = err
            .downcast_ref::<crate::providers::ProviderHttpError>()
            .expect("upstream 401 must be a typed ProviderHttpError");
        assert!(
            typed.is_auth_rejection(),
            "401 must classify as an auth rejection"
        );
        // The whole error chain, rendered — this is what reaches logs.
        let rendered = format!("{err:#}");
        assert!(
            !rendered.contains("sk-leaky-secret-value"),
            "the upstream body (which echoes the key) must never reach the error: {rendered}"
        );
    }

    #[tokio::test]
    async fn a_non_embeddings_2xx_body_is_an_error_not_an_empty_result() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/embeddings"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "hello": "world" })),
            )
            .mount(&server)
            .await;

        let provider = OpenAiProvider::compatible(server.uri(), "openai")
            .expect("build OpenAI-compatible provider");
        let err = provider
            .embeddings(&req(serde_json::json!("hi")), "k", &tenant())
            .await
            .expect_err("a 200 that is not an embeddings payload must be an error");
        assert!(
            format!("{err:#}").contains("not an embeddings response"),
            "{err:#}"
        );
    }

    /// A `€` cut across two network chunks must reach the client whole. The
    /// per-chunk `from_utf8(&chunk)?` this replaced ended the stream instead.
    #[tokio::test]
    async fn a_character_split_across_network_chunks_survives() {
        use futures::StreamExt as _;
        let resp = crate::providers::sse_lines::response_from_chunks(vec![
            b"data: {\"choices\":[{\"delta\":{\"content\":\"price \xE2\x82",
            b"\xAC5\"}}]}\n\n",
            b"data: [DONE]\n\n",
        ]);
        let events: Vec<_> = build_openai_stream(resp).collect().await;
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

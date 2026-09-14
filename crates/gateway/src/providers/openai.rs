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
        let oai_request = OpenAiRequest::from_universal(request);
        let url = format!("{}/v1/chat/completions", self.base_url);

        // SSRF: validate before the POST (reviewer).
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
            // SECURITY: do NOT include the upstream body in
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

    // Usage chunk (stream_options.include_usage = true)
    if let Some(usage) = v.get("usage").filter(|u| !u.is_null()) {
        let input = usage["prompt_tokens"].as_u64().unwrap_or(0) as u32;
        let output = usage["completion_tokens"].as_u64().unwrap_or(0) as u32;
        // Wire-reported cost: OpenRouter (and some OpenAI-compatible
        // hosts) attach `usage.cost` in USD. Absent → None, never computed.
        let cost_usd = usage.get("cost").and_then(|c| c.as_f64());
        return Ok(vec![ProviderEvent::UsageUpdate {
            input_tokens: input,
            output_tokens: output,
            cache_read: None,
            cache_creation: None,
            cost_usd,
        }]);
    }

    // OBS-53. Collected BEFORE the content/tool/finish decision below and
    // carried alongside whichever of those wins, because this frame can
    // legitimately be both a token and its logprob. Absent ⇒ nothing pushed, so
    // a stream from a client that did not ask for logprobs is byte-identical to
    // before this existed.
    let mut events: Vec<ProviderEvent> = Vec::new();
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

    let delta = &v["choices"][0]["delta"];
    if delta.is_null() {
        return Ok(events);
    }

    // Text delta
    if let Some(text) = delta["content"].as_str()
        && !text.is_empty()
    {
        events.push(ProviderEvent::StreamChunk {
            delta: text.to_owned(),
        });
        return Ok(events);
    }

    // Tool call delta
    if let Some(tool_calls) = delta["tool_calls"].as_array()
        && let Some(tc) = tool_calls.first()
    {
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
        return Ok(events);
    }

    // B-354: the provider's own stop reason, passed through.
    //
    // Checked LAST, and that is the honest limit of this parser's single-event
    // return: OpenAI itself sends `finish_reason` on its own chunk with an
    // EMPTY delta, so this is reached for every real OpenAI stream. A
    // compatible host that bundles the reason onto the last CONTENT chunk
    // loses it here — the content event wins, because dropping a token is
    // worse than dropping a reason the buffered path can still derive from the
    // presence of tool calls.
    if let Some(reason) = v["choices"][0]["finish_reason"]
        .as_str()
        .and_then(FinishReason::from_openai_finish_reason)
    {
        events.push(ProviderEvent::Finish { reason });
        return Ok(events);
    }

    Ok(events)
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
    pub(super) fn from_universal(req: ChatRequest) -> Self {
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
            max_tokens: req.max_tokens,
            temperature: req.temperature,
            top_p: req.top_p,
            seed: req.seed,
            logprobs: req.logprobs,
            top_logprobs: req.top_logprobs,
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

    /// The control: a content chunk still parses as content, unchanged. The
    /// finish_reason check is LAST for exactly this reason.
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

        let response = self
            .client
            .post(&url)
            .header("authorization", format!("Bearer {api_key}"))
            .header("content-type", "application/json")
            .json(request)
            .send()
            .await
            .context("failed to send embeddings request upstream")?;

        let status = response.status();
        if !status.is_success() {
            // Body consumed to free the connection, never logged or propagated
            // (credential-echo risk — see the `# Errors` note above).
            let _body = response.text().await.unwrap_or_default();
            tracing::warn!(status = %status, provider = self.provider_id, "embeddings upstream error");
            return Err(crate::providers::ProviderHttpError {
                provider: self.provider_id,
                status: status.as_u16(),
                reason: None,
            }
            .into());
        }

        response
            .json::<EmbeddingsResponse>()
            .await
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
}

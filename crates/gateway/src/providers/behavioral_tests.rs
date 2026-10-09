//! Provider BEHAVIORAL E2E tests via `wiremock`.
//!
//! `smoke_tests.rs` proves the wire shape (right path, right headers, mock got
//! hit) and deliberately discards stream contents. These tests close the
//! "green-is-not-proof" gap on the provider matrix: each native adapter's
//! stream is fully collected and asserted on the OBSERVABLE END-STATE —
//! assembled text, tool-call delta sequence, token usage, and wire-reported
//! cost — against provider-authentic SSE/NDJSON fixtures. Stream-level decode
//! errors FAIL the test (no silent `drain`).
//!
//! Bugs this suite caught at introduction (fixed in the same change):
//!   - Google: a chunk carrying BOTH content parts and `usageMetadata`
//!     dropped the content (early return) — short Gemini responses lost
//!     their entire text; multi-part chunks surfaced only the first part.
//!   - Azure: `delta.tool_calls` was never parsed — tool calls silently
//!     vanished from Azure OpenAI streams.
//!   - Cohere: tools were dropped from requests AND tool-call events were
//!     never parsed.
//!
//! Same cfg gate as smoke_tests (loopback SSRF bypass is debug-only —).

#![cfg(test)]

use futures::StreamExt as _;
use uuid::Uuid;
use wiremock::matchers::{body_partial_json, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::providers::{
    AnthropicProvider, AzureOpenAiProvider, CohereProvider, GoogleProvider, OpenAiProvider,
    ProviderEvent,
};
use tracelane_shared::{ChatRequest, Message, MessageContent, Role, TenantId, Tool};

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

fn test_tenant() -> TenantId {
    TenantId::from_jwt_claim(Uuid::from_u128(0xB067))
}

fn request_with_tools(model: &str) -> ChatRequest {
    ChatRequest {
        top_p: None,
        seed: None,
        logprobs: None,
        top_logprobs: None,
        model: model.into(),
        messages: vec![Message {
            role: Role::User,
            content: MessageContent::Text("what's the weather in Bangalore?".into()),
            tool_call_id: None,
            tool_calls: None,
        }],
        max_tokens: Some(128),
        temperature: Some(0.0),
        stream: Some(true),
        tools: Some(vec![Tool {
            name: "get_weather".into(),
            description: Some("Look up current weather".into()),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "city": { "type": "string", "description": "City name" }
                },
                "required": ["city"]
            }),
        }]),
        tool_choice: None,
        system: None,
        metadata: None,
        ..Default::default()
    }
}

/// Collect the FULL stream; any stream-level error fails the test (the
/// smoke-test `drain` discards errors — that is exactly the critique).
async fn collect(mut s: crate::providers::ProviderStream) -> Vec<ProviderEvent> {
    let mut out = Vec::new();
    while let Some(item) = s.next().await {
        out.push(item.expect("provider stream must not yield decode errors"));
    }
    out
}

fn assembled_text(events: &[ProviderEvent]) -> String {
    events
        .iter()
        .filter_map(|e| match e {
            ProviderEvent::StreamChunk { delta } => Some(delta.as_str()),
            _ => None,
        })
        .collect()
}

/// Assemble tool-call deltas: (first id seen, first name seen, concatenated args).
fn assembled_tool(events: &[ProviderEvent]) -> Option<(Option<String>, Option<String>, String)> {
    let mut id = None;
    let mut name = None;
    let mut args = String::new();
    let mut saw_any = false;
    for e in events {
        if let ProviderEvent::ToolCallDelta {
            id: i,
            name: n,
            input_delta,
            ..
        } = e
        {
            saw_any = true;
            if id.is_none() {
                id = i.clone();
            }
            if name.is_none() {
                name = n.clone();
            }
            args.push_str(input_delta);
        }
    }
    saw_any.then_some((id, name, args))
}

fn usage_of(events: &[ProviderEvent]) -> Option<(u32, u32, Option<f64>)> {
    // Last usage event wins (providers may send progressive updates).
    events.iter().rev().find_map(|e| match e {
        ProviderEvent::UsageUpdate {
            input_tokens,
            output_tokens,
            cost_usd,
            ..
        } => Some((*input_tokens, *output_tokens, *cost_usd)),
        _ => None,
    })
}

// ═════════════════════════════════════════════════════════════════════════
// OpenAI — native adapter + the base of the ~29-provider compatible class.
// ═════════════════════════════════════════════════════════════════════════

/// Multi-chunk content + a split tool-call (id/name first, args fragmented) +
/// final usage chunk carrying a wire cost (OpenRouter-style `usage.cost`).
const OPENAI_BEHAVIORAL_SSE: &str = concat!(
    "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"The \"},\"finish_reason\":null}]}\n\n",
    "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"weather is \"},\"finish_reason\":null}]}\n\n",
    "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"sunny.\"},\"finish_reason\":null}]}\n\n",
    "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_b067\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]},\"finish_reason\":null}]}\n\n",
    "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"city\\\":\"}}]},\"finish_reason\":null}]}\n\n",
    "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"Bangalore\\\"}\"}}]},\"finish_reason\":null}]}\n\n",
    "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}],\"usage\":{\"prompt_tokens\":42,\"completion_tokens\":17,\"total_tokens\":59,\"cost\":0.00234}}\n\n",
    "data: [DONE]\n\n",
);

async fn openai_family_assertions(events: Vec<ProviderEvent>) {
    assert_eq!(
        assembled_text(&events),
        "The weather is sunny.",
        "multi-chunk content must assemble in order"
    );
    let (id, name, args) = assembled_tool(&events).expect("tool-call deltas must surface");
    assert_eq!(id.as_deref(), Some("call_b067"));
    assert_eq!(name.as_deref(), Some("get_weather"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&args).expect("args fragments form valid JSON"),
        serde_json::json!({"city": "Bangalore"})
    );
    let (input, output, cost) = usage_of(&events).expect("usage chunk must surface");
    assert_eq!(input, 42);
    assert_eq!(output, 17);
    assert_eq!(cost, Some(0.00234), "wire-reported usage.cost must extract");
}

#[tokio::test]
async fn openai_stream_assembles_content_tools_usage_and_cost() {
    let _bypass = LoopbackBypassGuard::new();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(OPENAI_BEHAVIORAL_SSE)
                .insert_header("content-type", "text/event-stream"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let stream = OpenAiProvider::compatible(server.uri(), "openai")
        .unwrap()
        .chat(request_with_tools("gpt-5"), "sk-test", &test_tenant())
        .await
        .expect("chat returns stream");
    openai_family_assertions(collect(stream).await).await;
}

/// The OpenAI-compatible CLASS representative (29 registry instances share
/// this adapter): same behavioral contract against an alternate base URL +
/// provider id, proving the class — not just api.openai.com — extracts
/// content/tools/usage/cost.
#[tokio::test]
async fn openai_compatible_class_shares_the_behavioral_contract() {
    let _bypass = LoopbackBypassGuard::new();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(OPENAI_BEHAVIORAL_SSE)
                .insert_header("content-type", "text/event-stream"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let stream = OpenAiProvider::compatible(server.uri(), "openrouter")
        .unwrap()
        .chat(
            request_with_tools("openai/gpt-5"),
            "sk-or-test",
            &test_tenant(),
        )
        .await
        .expect("compat chat returns stream");
    openai_family_assertions(collect(stream).await).await;
}

// ═════════════════════════════════════════════════════════════════════════
// Azure OpenAI — deployment URL; tool-calls previously DROPPED (fix).
// ═════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn azure_stream_surfaces_tool_calls_content_and_usage() {
    let _bypass = LoopbackBypassGuard::new();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/openai/deployments/[^/]+/chat/completions$"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(OPENAI_BEHAVIORAL_SSE)
                .insert_header("content-type", "text/event-stream"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let stream = AzureOpenAiProvider::for_endpoint(server.uri(), "2025-01-01-preview")
        .unwrap()
        .chat(request_with_tools("azure/gpt-4o"), "az-key", &test_tenant())
        .await
        .expect("azure chat returns stream");
    let events = collect(stream).await;

    assert_eq!(assembled_text(&events), "The weather is sunny.");
    // Regression: these deltas were silently dropped before the fix.
    let (id, name, args) = assembled_tool(&events)
        .expect("azure tool-call deltas must surface (were previously dropped)");
    assert_eq!(id.as_deref(), Some("call_b067"));
    assert_eq!(name.as_deref(), Some("get_weather"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&args).unwrap(),
        serde_json::json!({"city": "Bangalore"})
    );
    let (input, output, _cost) = usage_of(&events).expect("usage surfaces");
    assert_eq!((input, output), (42, 17));
}

// ═════════════════════════════════════════════════════════════════════════
// Anthropic — event-typed SSE; tool id/name on content_block_start, args via
// input_json_delta; usage split across message_start / message_delta.
// ═════════════════════════════════════════════════════════════════════════

const ANTHROPIC_BEHAVIORAL_SSE: &str = concat!(
    "event: message_start\n",
    "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_b067\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":42,\"output_tokens\":0,\"cache_read_input_tokens\":7}}}\n\n",
    "event: content_block_start\n",
    "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
    "event: content_block_delta\n",
    "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"The weather is \"}}\n\n",
    "event: content_block_delta\n",
    "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"sunny.\"}}\n\n",
    "event: content_block_start\n",
    "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_b067\",\"name\":\"get_weather\",\"input\":{}}}\n\n",
    "event: content_block_delta\n",
    "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"city\\\":\"}}\n\n",
    "event: content_block_delta\n",
    "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"Bangalore\\\"}\"}}\n\n",
    "event: message_delta\n",
    "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":17}}\n\n",
    "event: message_stop\n",
    "data: {\"type\":\"message_stop\"}\n\n",
);

#[tokio::test]
async fn anthropic_stream_assembles_text_tools_and_split_usage() {
    let _bypass = LoopbackBypassGuard::new();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(ANTHROPIC_BEHAVIORAL_SSE)
                .insert_header("content-type", "text/event-stream"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let stream = AnthropicProvider::for_base_url(server.uri())
        .unwrap()
        .chat(
            request_with_tools("claude-sonnet-4-6"),
            "sk-ant-test",
            &test_tenant(),
        )
        .await
        .expect("anthropic chat returns stream");
    let events = collect(stream).await;

    assert_eq!(assembled_text(&events), "The weather is sunny.");
    let (id, name, args) = assembled_tool(&events).expect("anthropic tool deltas surface");
    assert_eq!(id.as_deref(), Some("toolu_b067"));
    assert_eq!(name.as_deref(), Some("get_weather"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&args).unwrap(),
        serde_json::json!({"city": "Bangalore"})
    );

    // Usage is split: input (+cache_read) on message_start, output on
    // message_delta. Both events must surface with their halves intact.
    let usages: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            ProviderEvent::UsageUpdate {
                input_tokens,
                output_tokens,
                cache_read,
                ..
            } => Some((*input_tokens, *output_tokens, *cache_read)),
            _ => None,
        })
        .collect();
    assert!(
        usages.contains(&(42, 0, Some(7))),
        "message_start usage (input + cache_read) must surface: {usages:?}"
    );
    assert!(
        usages.contains(&(0, 17, None)),
        "message_delta usage (output) must surface: {usages:?}"
    );
}

// ═════════════════════════════════════════════════════════════════════════
// Google Gemini — one chunk carrying text + functionCall + usageMetadata.
// Regression for the early return that dropped content.
// ═════════════════════════════════════════════════════════════════════════

const GEMINI_BEHAVIORAL_SSE: &str = concat!(
    "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"The weather is \"}],\"role\":\"model\"},\"index\":0}]}\n\n",
    "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"sunny.\"},{\"functionCall\":{\"name\":\"get_weather\",\"args\":{\"city\":\"Bangalore\"}}}],\"role\":\"model\"},\"finishReason\":\"STOP\",\"index\":0}],\"usageMetadata\":{\"promptTokenCount\":42,\"candidatesTokenCount\":17,\"totalTokenCount\":59}}\n\n",
);

#[tokio::test]
async fn google_chunk_with_text_tools_and_usage_loses_nothing() {
    let _bypass = LoopbackBypassGuard::new();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/v1beta/models/[^:]+:streamGenerateContent$"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(GEMINI_BEHAVIORAL_SSE)
                .insert_header("content-type", "text/event-stream"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let stream = GoogleProvider::for_base_url(server.uri())
        .unwrap()
        .chat(request_with_tools("gemini-3-pro"), "g-test", &test_tenant())
        .await
        .expect("google chat returns stream");
    let events = collect(stream).await;

    // the second chunk's text AND functionCall vanished (the
    // usageMetadata early-return), so the text stopped at "The weather is ".
    assert_eq!(
        assembled_text(&events),
        "The weather is sunny.",
        "content in a usage-bearing chunk must not be dropped"
    );
    let (_id, name, args) = assembled_tool(&events).expect("functionCall part surfaces");
    assert_eq!(name.as_deref(), Some("get_weather"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&args).unwrap(),
        serde_json::json!({"city": "Bangalore"})
    );
    let (input, output, _cost) = usage_of(&events).expect("usageMetadata surfaces");
    assert_eq!((input, output), (42, 17));
}

// ═════════════════════════════════════════════════════════════════════════
// D9 — Cohere v2 chat: a 2-turn tool conversation, asserted on the BODY.
// ═════════════════════════════════════════════════════════════════════════

fn cohere_v2_tool_conversation() -> ChatRequest {
    use tracelane_shared::ToolCall;
    let mut req = request_with_tools("command-a-03-2025");
    req.messages = vec![
        Message {
            role: Role::System,
            content: MessageContent::Text("Be brief.".into()),
            tool_call_id: None,
            tool_calls: None,
        },
        Message {
            role: Role::User,
            content: MessageContent::Text("weather in Bangalore?".into()),
            tool_call_id: None,
            tool_calls: None,
        },
        Message {
            role: Role::Assistant,
            content: MessageContent::Text(String::new()),
            tool_call_id: None,
            tool_calls: Some(vec![ToolCall {
                id: "call_77".into(),
                name: "get_weather".into(),
                input: serde_json::json!({"city": "Bangalore"}),
            }]),
        },
        // The LAST message is a tool result: v1 sent it as `message` text.
        Message {
            role: Role::Tool,
            content: MessageContent::Text("29C, sunny".into()),
            tool_call_id: Some("call_77".into()),
            tool_calls: None,
        },
    ];
    req
}

/// Cohere v2 `POST /v2/chat` stream, event names and shapes per docs.cohere.com/reference/chat-stream.
const COHERE_V2_SSE: &str = concat!(
    "event: message-start\n",
    r#"data: {"type":"message-start","id":"m1","delta":{"message":{"role":"assistant"}}}"#,
    "\n\n",
    "event: content-start\n",
    r#"data: {"type":"content-start","index":0,"delta":{"message":{"content":{"type":"text","text":""}}}}"#,
    "\n\n",
    "event: content-delta\n",
    r#"data: {"type":"content-delta","index":0,"delta":{"message":{"content":{"text":"It is "}}}}"#,
    "\n\n",
    "event: content-delta\n",
    r#"data: {"type":"content-delta","index":0,"delta":{"message":{"content":{"text":"sunny."}}}}"#,
    "\n\n",
    "event: content-end\n",
    r#"data: {"type":"content-end","index":0}"#,
    "\n\n",
    "event: tool-plan-delta\n",
    r#"data: {"type":"tool-plan-delta","delta":{"message":{"tool_plan":"I will look"}}}"#,
    "\n\n",
    "event: tool-call-start\n",
    r#"data: {"type":"tool-call-start","index":0,"delta":{"message":{"tool_calls":{"id":"call_88","type":"function","function":{"name":"get_weather","arguments":""}}}}}"#,
    "\n\n",
    "event: tool-call-delta\n",
    r#"data: {"type":"tool-call-delta","index":0,"delta":{"message":{"tool_calls":{"function":{"arguments":"{\"city\":"}}}}}"#,
    "\n\n",
    "event: tool-call-delta\n",
    r#"data: {"type":"tool-call-delta","index":0,"delta":{"message":{"tool_calls":{"function":{"arguments":"\"Pune\"}"}}}}}"#,
    "\n\n",
    "event: tool-call-end\n",
    r#"data: {"type":"tool-call-end","index":0}"#,
    "\n\n",
    "event: message-end\n",
    r#"data: {"type":"message-end","id":"m1","delta":{"finish_reason":"TOOL_CALL","usage":{"billed_units":{"input_tokens":50,"output_tokens":20},"tokens":{"input_tokens":42,"output_tokens":17}}}}"#,
    "\n\n",
);

#[tokio::test]
async fn d9_cohere_v2_body_carries_tool_history_and_the_stream_surfaces_tool_calls_and_usage() {
    let _bypass = LoopbackBypassGuard::new();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat"))
        .and(body_partial_json(serde_json::json!({
            "model": "command-a-03-2025",
            "stream": true,
            "messages": [
                {"role": "system", "content": "Be brief."},
                {"role": "user", "content": "weather in Bangalore?"},
                {"role": "assistant", "tool_calls": [{
                    "id": "call_77", "type": "function",
                    "function": {"name": "get_weather", "arguments": "{\"city\":\"Bangalore\"}"}
                }]},
                {"role": "tool", "tool_call_id": "call_77", "content": "29C, sunny"}
            ],
            "tools": [{"type": "function", "function": {
                "name": "get_weather",
                "description": "Look up current weather",
                "parameters": {"type": "object", "required": ["city"]}
            }}]
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(COHERE_V2_SSE)
                .insert_header("content-type", "text/event-stream"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let stream = CohereProvider::for_base_url(server.uri())
        .unwrap()
        .chat(cohere_v2_tool_conversation(), "co-test", &test_tenant())
        .await
        .expect("cohere v2 chat returns a stream");
    let events = collect(stream).await;

    // No v1 field survives in the body.
    let sent = server.received_requests().await.expect("log");
    let body: serde_json::Value = serde_json::from_slice(&sent[0].body).expect("json");
    for v1 in ["message", "chat_history", "connectors"] {
        assert!(body.get(v1).is_none(), "v1 field `{v1}` must not be sent");
    }
    assert!(body["tools"][0].get("parameter_definitions").is_none());

    // content-delta text, then the tool plan (visible output, replayed as `tool_plan`).
    assert_eq!(assembled_text(&events), "It is sunny.I will look");
    let (id, name, args) = assembled_tool(&events).expect("v2 tool-call-* events must surface");
    assert_eq!(id.as_deref(), Some("call_88"));
    assert_eq!(name.as_deref(), Some("get_weather"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&args).unwrap(),
        serde_json::json!({"city": "Pune"})
    );
    let (input, output, _cost) = usage_of(&events).expect("message-end usage surfaces");
    assert_eq!((input, output), (42, 17), "`tokens`, not `billed_units`");
    assert!(events.iter().any(|e| matches!(
        e,
        ProviderEvent::Finish {
            reason: crate::providers::FinishReason::ToolCalls
        }
    )));
}

// ═════════════════════════════════════════════════════════════════════════
// B-353 / B-354 — the BUFFERED (non-streaming) assembly.
//
// `buffer_provider_stream` itself needs an `AppState`, a NATS handle and a
// guardrail engine, which is exactly why this half had no coverage and why a
// 100%-dropped tool call shipped. The two facts it folds out of the stream live
// in `BufferedToolState`, and the body it builds in
// `buffered_completion_payload`, so both are driven here from the REAL
// Anthropic adapter parsing a provider-authentic fixture.
// ═════════════════════════════════════════════════════════════════════════

/// A text-only Anthropic stream: no `tool_use` block, `stop_reason: end_turn`.
/// The control for "nothing changed for the 94% of traffic that uses no tools".
const ANTHROPIC_TEXT_ONLY_SSE: &str = concat!(
    "event: message_start\n",
    "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_t1\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":11,\"output_tokens\":0}}}\n\n",
    "event: content_block_delta\n",
    "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Sunny.\"}}\n\n",
    "event: message_delta\n",
    "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":3}}\n\n",
    "event: message_stop\n",
    "data: {\"type\":\"message_stop\"}\n\n",
);

/// The same answer, cut short by the token budget: `stop_reason: max_tokens`.
const ANTHROPIC_TRUNCATED_SSE: &str = concat!(
    "event: message_start\n",
    "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_t2\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":11,\"output_tokens\":0}}}\n\n",
    "event: content_block_delta\n",
    "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Sunny and\"}}\n\n",
    "event: message_delta\n",
    "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"max_tokens\"},\"usage\":{\"output_tokens\":128}}\n\n",
    "event: message_stop\n",
    "data: {\"type\":\"message_stop\"}\n\n",
);

/// Run the real Anthropic adapter over `sse`, fold the events exactly as
/// `buffer_provider_stream` does, and return the `chat.completion` body a
/// non-streaming caller would receive.
async fn buffered_body_for(sse: &'static str) -> serde_json::Value {
    let _bypass = LoopbackBypassGuard::new();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(sse)
                .insert_header("content-type", "text/event-stream"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let stream = AnthropicProvider::for_base_url(server.uri())
        .expect("provider")
        .chat(
            request_with_tools("claude-sonnet-4-6"),
            "sk-ant-test-do-not-use-in-prod",
            &test_tenant(),
        )
        .await
        .expect("anthropic chat returns stream");

    let events = collect(stream).await;
    let mut state = crate::server::BufferedToolState::default();
    let mut text = String::new();
    let mut input_tokens = 0u32;
    let mut output_tokens = 0u32;
    for ev in &events {
        if state.absorb(ev) {
            continue;
        }
        match ev {
            ProviderEvent::StreamChunk { delta } => text.push_str(delta),
            ProviderEvent::UsageUpdate {
                input_tokens: i,
                output_tokens: o,
                ..
            } => {
                if *i > 0 {
                    input_tokens = *i;
                }
                if *o > 0 {
                    output_tokens = *o;
                }
            }
            _ => {}
        }
    }
    crate::server::buffered_completion_payload(
        "chatcmpl-fixture",
        "claude-sonnet-4-6",
        text,
        &state,
        input_tokens,
        output_tokens,
    )
}

/// **THE TEST THAT WOULD HAVE CAUGHT B-353.** A provider-authentic Anthropic
/// stream carrying a `tool_use` block, buffered the way a non-streaming caller
/// gets it. Before the fix the assembled body carried content only: the
/// `ToolCallDelta`s fell through `Ok(_) => {}` and the model's tool intent was
/// discarded with a 200.
#[tokio::test]
async fn a_buffered_tool_use_stream_carries_the_tool_call_in_openai_shape() {
    let body = buffered_body_for(ANTHROPIC_BEHAVIORAL_SSE).await;
    let calls = body["choices"][0]["message"]["tool_calls"]
        .as_array()
        .expect("a buffered response must carry the model's tool calls");
    assert_eq!(calls.len(), 1, "one tool_use block -> one tool call");
    assert_eq!(calls[0]["id"], "toolu_b067");
    assert_eq!(calls[0]["type"], "function");
    assert_eq!(calls[0]["function"]["name"], "get_weather");
    // `arguments` is a JSON *string* on the OpenAI wire — that is what every
    // SDK's `json.loads(tc.function.arguments)` expects. Asserting the parsed
    // value as well as the type is what makes this a contract rather than a
    // spelling check.
    let raw = calls[0]["function"]["arguments"]
        .as_str()
        .expect("arguments must be a STRING, not an object");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(raw).expect("arguments parse as JSON"),
        serde_json::json!({ "city": "Bangalore" })
    );
    // B-354, same response: the SDK tool loop branches on this.
    assert_eq!(body["choices"][0]["finish_reason"], "tool_calls");
    // The text half is untouched.
    assert_eq!(
        body["choices"][0]["message"]["content"],
        "The weather is sunny."
    );
}

/// **The no-behaviour-change control.** A stream with no tool calls must
/// produce the body it produced before B-353/B-354 existed — asserted against
/// the WHOLE body, not a field, so an added key fails the test.
#[tokio::test]
async fn a_text_only_buffered_response_is_unchanged() {
    let body = buffered_body_for(ANTHROPIC_TEXT_ONLY_SSE).await;
    assert_eq!(
        body,
        serde_json::json!({
            "id": "chatcmpl-fixture",
            "object": "chat.completion",
            "model": "claude-sonnet-4-6",
            "choices": [{
                "index": 0,
                "message": { "role": "assistant", "content": "Sunny." },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 11,
                "completion_tokens": 3,
                "total_tokens": 14
            }
        }),
        // B-353 regression pin: the tool-free path must not change bytes.
        "a tool-free response must be byte-identical to the body it produced before tool-call accumulation was added"
    );
}

/// B-354, the mapping that is not derivable from the response's own contents: a
/// truncated answer carries no tool calls and looks exactly like a complete one
/// unless the provider's `stop_reason` is read.
#[tokio::test]
async fn a_max_tokens_stop_becomes_finish_reason_length() {
    let body = buffered_body_for(ANTHROPIC_TRUNCATED_SSE).await;
    assert_eq!(body["choices"][0]["finish_reason"], "length");
    assert!(
        body["choices"][0]["message"].get("tool_calls").is_none(),
        "a truncated text answer must not grow a tool_calls key"
    );
}

// ═════════════════════════════════════════════════════════════════════════
// OG-05 §3.4 — the chat → Responses bridge, against a wiremock OpenAI.
//
// A chat request for a Responses-only model (`gpt-5.5-pro`), or for a "tools
// need Responses" model (`gpt-6-astra`) WITH tools, must POST `/v1/responses`
// (never `/v1/chat/completions`), and the Responses stream must come back as the
// same `ProviderEvent`s every other adapter yields — which the REAL buffered
// fold then turns into a chat.completion body.
// ═════════════════════════════════════════════════════════════════════════

const RESPONSES_TEXT_SSE: &str = concat!(
    "event: response.created\n",
    "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_og05\",\"model\":\"gpt-5.5-pro-2026-10-01\"}}\n\n",
    "event: response.output_text.delta\n",
    "data: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"delta\":\"Hello \"}\n\n",
    "event: response.output_text.delta\n",
    "data: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"delta\":\"there.\"}\n\n",
    "event: response.completed\n",
    "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":21,\"output_tokens\":4,\"input_tokens_details\":{\"cached_tokens\":8},\"output_tokens_details\":{\"reasoning_tokens\":2}}}}\n\n",
);

const RESPONSES_TOOL_SSE: &str = concat!(
    "event: response.created\n",
    "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_og05_t\",\"model\":\"gpt-6-astra\"}}\n\n",
    "event: response.output_item.added\n",
    "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"id\":\"fc_1\",\"call_id\":\"call_og05\",\"name\":\"get_weather\",\"arguments\":\"\"}}\n\n",
    "event: response.function_call_arguments.delta\n",
    "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"delta\":\"{\\\"city\\\":\"}\n\n",
    "event: response.function_call_arguments.delta\n",
    "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"delta\":\"\\\"Bangalore\\\"}\"}\n\n",
    "event: response.output_item.done\n",
    "data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"call_id\":\"call_og05\",\"name\":\"get_weather\",\"arguments\":\"{\\\"city\\\":\\\"Bangalore\\\"}\"}}\n\n",
    "event: response.completed\n",
    "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":30,\"output_tokens\":9}}}\n\n",
);

async fn mount_responses(server: &MockServer, sse: &'static str) {
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(sse)
                .insert_header("content-type", "text/event-stream"),
        )
        .expect(1)
        .mount(server)
        .await;
    // The chat route must NEVER be hit for a bridged model.
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(server)
        .await;
}

fn bridge_request(model: &str, with_tools: bool) -> ChatRequest {
    let mut r = request_with_tools(model);
    if !with_tools {
        r.tools = None;
    }
    r
}

/// Buffered, exactly as `buffer_provider_stream` folds a stream.
fn fold_buffered(events: &[ProviderEvent], model: &str) -> serde_json::Value {
    let mut state = crate::server::BufferedToolState::default();
    let mut text = String::new();
    let (mut i_tok, mut o_tok) = (0u32, 0u32);
    for ev in events {
        if state.absorb(ev) {
            continue;
        }
        match ev {
            ProviderEvent::StreamChunk { delta } => text.push_str(delta),
            ProviderEvent::UsageUpdate {
                input_tokens,
                output_tokens,
                ..
            } => {
                i_tok = *input_tokens;
                o_tok = *output_tokens;
            }
            _ => {}
        }
    }
    crate::server::buffered_completion_payload("chatcmpl-og05", model, text, &state, i_tok, o_tok)
}

#[tokio::test]
async fn og05_bridge_buffered_text_round_trip_hits_responses_not_chat() {
    let _bypass = LoopbackBypassGuard::new();
    let server = MockServer::start().await;
    mount_responses(&server, RESPONSES_TEXT_SSE).await;

    let stream = OpenAiProvider::compatible(server.uri(), "openai")
        .unwrap()
        .chat(
            bridge_request("gpt-5.5-pro", false),
            "sk-test-bridge",
            &test_tenant(),
        )
        .await
        .expect("a bridged chat returns a stream");
    let events = collect(stream).await;
    let body = fold_buffered(&events, "gpt-5.5-pro");

    assert_eq!(body["choices"][0]["message"]["content"], "Hello there.");
    assert_eq!(body["choices"][0]["finish_reason"], "stop");
    // Usage: `input_tokens` is inclusive of the cached prefix, as in the chat adapter.
    assert_eq!(body["usage"]["prompt_tokens"], 21);
    assert_eq!(body["usage"]["completion_tokens"], 4);
    assert!(
        events.iter().any(
            |e| matches!(e, ProviderEvent::ResponseMeta { id: Some(i), .. } if i == "resp_og05")
        ),
        "the upstream response id must reach the span"
    );

    // What the gateway SENT: the Responses shape, the tenant key, no retention.
    let reqs = server.received_requests().await.expect("recorded");
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].url.path(), "/v1/responses");
    assert_eq!(
        reqs[0]
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok()),
        Some("Bearer sk-test-bridge")
    );
    let sent: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
    assert_eq!(sent["model"], "gpt-5.5-pro");
    assert_eq!(sent["store"], false);
    assert_eq!(sent["stream"], true);
    assert_eq!(sent["max_output_tokens"], 128);
    assert_eq!(sent["input"][0]["role"], "user");
    assert!(sent.get("messages").is_none(), "{sent}");
}

#[tokio::test]
async fn og05_bridge_stream_yields_incremental_chunks_in_order() {
    let _bypass = LoopbackBypassGuard::new();
    let server = MockServer::start().await;
    mount_responses(&server, RESPONSES_TEXT_SSE).await;

    let stream = OpenAiProvider::compatible(server.uri(), "openai")
        .unwrap()
        .chat(
            bridge_request("gpt-5.3-codex", false),
            "sk-test",
            &test_tenant(),
        )
        .await
        .expect("stream");
    let events = collect(stream).await;
    let chunks: Vec<&str> = events
        .iter()
        .filter_map(|e| match e {
            ProviderEvent::StreamChunk { delta } => Some(delta.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(chunks, vec!["Hello ", "there."], "deltas stay incremental");
    // Finish precedes the usage tail, as on the chat wire.
    let fin = events
        .iter()
        .position(|e| matches!(e, ProviderEvent::Finish { .. }))
        .expect("finish");
    let usage = events
        .iter()
        .position(|e| matches!(e, ProviderEvent::UsageUpdate { .. }))
        .expect("usage");
    assert!(fin < usage);
    let (_, _, cost) = usage_of(&events).expect("usage");
    assert_eq!(
        cost, None,
        "the gateway prices from its own cards, never invents one"
    );
}

/// The tool-call round trip: turn 1 returns a `function_call`, which comes out as
/// an OpenAI `tool_calls` entry; turn 2 replays it with its result and the
/// request reaches the wire as `function_call` + `function_call_output` items.
#[tokio::test]
async fn og05_bridge_tool_call_round_trip() {
    let _bypass = LoopbackBypassGuard::new();
    let server = MockServer::start().await;
    mount_responses(&server, RESPONSES_TOOL_SSE).await;
    let provider = OpenAiProvider::compatible(server.uri(), "openai").unwrap();

    // Turn 1: tools present on gpt-6-astra => bridged.
    let stream = provider
        .chat(
            bridge_request("gpt-6-astra", true),
            "sk-test",
            &test_tenant(),
        )
        .await
        .expect("stream");
    let events = collect(stream).await;
    let body = fold_buffered(&events, "gpt-6-astra");
    let calls = body["choices"][0]["message"]["tool_calls"]
        .as_array()
        .expect("tool_calls");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["id"], "call_og05");
    assert_eq!(calls[0]["type"], "function");
    assert_eq!(calls[0]["function"]["name"], "get_weather");
    let args: serde_json::Value =
        serde_json::from_str(calls[0]["function"]["arguments"].as_str().unwrap()).unwrap();
    assert_eq!(args, serde_json::json!({ "city": "Bangalore" }));
    assert_eq!(body["choices"][0]["finish_reason"], "tool_calls");

    // The tool went out FLAT (Responses shape), not nested (chat shape).
    let reqs = server.received_requests().await.unwrap();
    let sent: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
    assert_eq!(sent["tools"][0]["name"], "get_weather");
    assert!(sent["tools"][0].get("function").is_none());

    // Turn 2 (a fresh mock server for a clean request log): replay + result.
    let server2 = MockServer::start().await;
    mount_responses(&server2, RESPONSES_TEXT_SSE).await;
    let provider2 = OpenAiProvider::compatible(server2.uri(), "openai").unwrap();
    let mut r2 = bridge_request("gpt-6-astra", true);
    r2.messages.push(Message {
        role: Role::Assistant,
        content: MessageContent::Text(String::new()),
        tool_call_id: None,
        tool_calls: Some(vec![tracelane_shared::ToolCall {
            id: "call_og05".into(),
            name: "get_weather".into(),
            input: serde_json::json!({ "city": "Bangalore" }),
        }]),
    });
    r2.messages.push(Message {
        role: Role::Tool,
        content: MessageContent::Text("31C and clear".into()),
        tool_call_id: Some("call_og05".into()),
        tool_calls: None,
    });
    let events2 = collect(
        provider2
            .chat(r2, "sk-test", &test_tenant())
            .await
            .expect("stream"),
    )
    .await;
    assert_eq!(assembled_text(&events2), "Hello there.");
    let sent2: serde_json::Value =
        serde_json::from_slice(&server2.received_requests().await.unwrap()[0].body).unwrap();
    let items = sent2["input"].as_array().unwrap();
    assert_eq!(items[1]["type"], "function_call");
    assert_eq!(items[1]["call_id"], "call_og05");
    assert_eq!(items[2]["type"], "function_call_output");
    assert_eq!(items[2]["output"], "31C and clear");
}

/// The control: a model NOT on the list, and a "tools need Responses" model with
/// NO tools, still use the chat route — nothing was rewritten for ordinary traffic.
#[tokio::test]
async fn og05_non_bridged_requests_still_use_chat_completions() {
    let _bypass = LoopbackBypassGuard::new();
    for (model, tools) in [("gpt-5.5", true), ("gpt-6-astra", false)] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("data: [DONE]\n\n")
                    .insert_header("content-type", "text/event-stream"),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/responses"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let stream = OpenAiProvider::compatible(server.uri(), "openai")
            .unwrap()
            .chat(bridge_request(model, tools), "sk-test", &test_tenant())
            .await
            .expect("stream");
        let _ = collect(stream).await;
    }
}

/// Failure handling is the chat path's: a typed `ProviderHttpError` carrying the
/// status — never the upstream body — and a truncated stream is an error.
#[tokio::test]
async fn og05_bridge_failures_are_typed_and_never_leak_the_upstream_body() {
    let _bypass = LoopbackBypassGuard::new();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_string("{\"error\":{\"message\":\"bad key sk-LEAK-ME-1234567890\"}}"),
        )
        .mount(&server)
        .await;
    let err = OpenAiProvider::compatible(server.uri(), "openai")
        .unwrap()
        .chat(
            bridge_request("gpt-5.5-pro", false),
            "sk-LEAK-ME-1234567890",
            &test_tenant(),
        )
        .await
        .err()
        .expect("a 401 must be an error");
    let http = err
        .downcast_ref::<crate::providers::ProviderHttpError>()
        .expect("typed ProviderHttpError");
    assert_eq!(http.status, 401);
    assert!(
        !format!("{err:#}").contains("LEAK-ME"),
        "the upstream body / key must never reach an error string"
    );

    // A stream that ends before `response.completed`.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(
                    "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"par\"}\n\n",
                )
                .insert_header("content-type", "text/event-stream"),
        )
        .mount(&server)
        .await;
    let mut s = OpenAiProvider::compatible(server.uri(), "openai")
        .unwrap()
        .chat(
            bridge_request("gpt-5.5-pro", false),
            "sk-test",
            &test_tenant(),
        )
        .await
        .expect("stream");
    let mut saw_err = false;
    while let Some(item) = s.next().await {
        if item.is_err() {
            saw_err = true;
        }
    }
    assert!(
        saw_err,
        "a truncated Responses stream must surface as an error"
    );
}

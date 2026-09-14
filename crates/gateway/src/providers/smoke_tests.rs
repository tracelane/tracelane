//! Provider integration smoke tests via `wiremock`.
//!
//! Closes A1 from `DAY1_GAP_REPORT.md` §16. Each test:
//!   1. Spins a mock HTTP server with a canned response matching that
//!      provider's API shape.
//!   2. Constructs the gateway provider pointed at the mock URL.
//!   3. Asserts the outbound request hit the mock with the right path,
//!      content-type, and auth header.
//!   4. Drains the response stream — wire-shape success is the test;
//!      provider-specific SSE parsing is exercised in evals/providers/.
//!
//! These are *smoke* tests — they prove the wire shape is right, not that
//! the full provider matrix is correct. Full per-provider coverage lives
//! in `evals/providers/` (post-V1).
//!
//! Tests live as a `mod` inside the providers module so they have access
//! to the crate-internal `gateway::providers::*` API.
//!
//! Concurrency: these tests do NOT mutate process env. The wiremock server
//! binds to loopback, which the SSRF guard blocks — each test opts into the
//! bypass via a THREAD-LOCAL flag (`ssrf_guard::set_loopback_bypass_for_tests`,
//! RAII [`LoopbackBypassGuard`]), and providers are built with explicit base
//! URLs (`*::for_base_url` / `OpenAiProvider::compatible`). This replaces the
//! old `set_var`/`remove_var` approach, which raced across the parallel suite
//! (Rust 2024 marks `set_var` `unsafe` — a data race against any reader) and
//! could flip the SSRF bypass off mid-test in a sibling, or leak the relaxed
//! policy into the guard's own loopback tests. The lone exception is the
//! Bedrock creds-absence test, which only *removes* AWS_* vars and does so
//! conditionally (a no-op when they're already unset, i.e. in CI).

#![cfg(test)]

use futures::StreamExt as _;
use uuid::Uuid;
use wiremock::matchers::{header, method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::providers::failover::{FAILOVER_CODES, execute_with_failover};
use crate::providers::{
    AnthropicProvider, AzureOpenAiProvider, BedrockProvider, CohereProvider, GoogleProvider,
    OpenAiProvider,
};
use tracelane_shared::{ChatRequest, Message, MessageContent, Role, TenantId};

/// Wiremock binds to 127.0.0.1; the SSRF guard blocks loopback. This RAII
/// guard enables the loopback bypass on the CURRENT thread via a thread-local
/// flag (no process env — see `ssrf_guard::set_loopback_bypass_for_tests`), so
/// parallel smoke tests never race each other or the guard's own loopback
/// tests. Disabled again on drop.
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

fn allow_loopback_for_this_test() -> LoopbackBypassGuard {
    LoopbackBypassGuard::new()
}

fn test_tenant() -> TenantId {
    TenantId::from_jwt_claim(Uuid::from_u128(0xA1A1A1A1))
}

fn simple_request() -> ChatRequest {
    ChatRequest {
        top_p: None,
        seed: None,
        logprobs: None,
        top_logprobs: None,
        model: "gpt-5".into(),
        messages: vec![Message {
            role: Role::User,
            content: MessageContent::Text("hello".into()),
            tool_call_id: None,
            tool_calls: None,
        }],
        max_tokens: Some(64),
        temperature: Some(0.0),
        stream: Some(true),
        tools: None,
        tool_choice: None,
        system: None,
        metadata: None,
    }
}

/// Drain a provider stream into a Vec, ignoring stream-level decode errors.
/// Wire-shape success (mock got hit) is the test; SSE parsing nuances are
/// exercised in evals/providers/ where each provider's wire format gets
/// dedicated coverage.
async fn drain<S, T, E>(mut s: S) -> Vec<T>
where
    S: futures::Stream<Item = std::result::Result<T, E>> + Unpin,
{
    let mut out = Vec::new();
    while let Some(item) = s.next().await {
        if let Ok(v) = item {
            out.push(v);
        }
    }
    out
}

// =============================================================================
// OpenAI — base case for the OpenAI-compatible adapter (~30 of the providers).
// =============================================================================

const OPENAI_SSE_BODY: &str = concat!(
    "data: {\"id\":\"x\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"hi\"},\"finish_reason\":null}]}\n\n",
    "data: {\"id\":\"x\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}\n\n",
    "data: [DONE]\n\n",
);

#[tokio::test]
async fn openai_401_surfaces_typed_auth_rejection() {
    //  GW-SPAN-002: an upstream 401 must surface as a typed
    // ProviderHttpError(401) so the gateway answers `provider_key_rejected`
    // instead of an opaque 502 — and the credential-echoing body must NOT leak.
    let _bypass = allow_loopback_for_this_test();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_string("{\"error\":\"invalid api key sk-leaked-secret\"}"),
        )
        .mount(&server)
        .await;

    // `ProviderStream` is not Debug, so `.expect_err()` won't compile — match.
    let err = match OpenAiProvider::compatible(server.uri(), "openai")
        .unwrap()
        .chat(simple_request(), "sk-wrong-key", &test_tenant())
        .await
    {
        Ok(_) => panic!("upstream 401 must surface as an error, not Ok"),
        Err(e) => e,
    };

    let http = err
        .downcast_ref::<crate::providers::ProviderHttpError>()
        .expect("dispatch error must downcast to ProviderHttpError");
    assert_eq!(http.status, 401);
    assert!(http.is_auth_rejection());
    // Redaction (security.md /): the upstream body echoed a key
    // it must never appear in the error chain.
    assert!(
        !format!("{err:#}").contains("sk-leaked-secret"),
        "upstream 401 body must not leak into the error chain"
    );
}

#[tokio::test]
async fn openai_500_is_not_an_auth_rejection() {
    // A 5xx outage is an availability failure → 502, NOT provider_key_rejected.
    // A VERBOSE 5xx body (echoing a BYOK key) + a `www-authenticate` header
    // must NOT leak into the error surfaced to the gateway — only status + a safe
    // reason token survive; the client then gets our normalized `provider
    // unavailable`, never the provider's payload.
    let _bypass = allow_loopback_for_this_test();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(500)
                .insert_header("www-authenticate", "Bearer error=\"invalid_token\"")
                // Clearly-fake key per rules/testing.md.
                .set_body_string(
                    "{\"error\":{\"message\":\"internal error: key \
sk-projFAKEleakDONOTUSE0123456789abcdef rejected upstream\",\"type\":\"server_error\"}}",
                ),
        )
        .mount(&server)
        .await;

    let err = match OpenAiProvider::compatible(server.uri(), "openai")
        .unwrap()
        .chat(simple_request(), "sk-key", &test_tenant())
        .await
    {
        Ok(_) => panic!("upstream 500 must surface as an error"),
        Err(e) => e,
    };
    let http = err
        .downcast_ref::<crate::providers::ProviderHttpError>()
        .expect("typed ProviderHttpError");
    assert_eq!(http.status, 500);
    assert!(!http.is_auth_rejection());
    // Neither the verbose body's key nor the auth header survives.
    let chain = format!("{err:#}");
    assert!(
        !chain.contains("sk-projFAKEleak"),
        "verbose 500 body leaked a key into the error chain: {chain}"
    );
    assert!(
        !chain.to_lowercase().contains("www-authenticate"),
        "upstream auth header leaked into the error chain: {chain}"
    );
}

#[tokio::test]
async fn openai_provider_request_shape() {
    let _bypass = allow_loopback_for_this_test();
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("authorization", "Bearer sk-fake-key"))
        .and(header("content-type", "application/json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(OPENAI_SSE_BODY)
                .insert_header("content-type", "text/event-stream"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let stream = OpenAiProvider::compatible(server.uri(), "openai")
        .unwrap()
        .chat(simple_request(), "sk-fake-key", &test_tenant())
        .await
        .expect("openai chat returns stream");

    let _events = drain(stream).await;
}

#[tokio::test]
async fn openai_compatible_provider_routes_to_alternate_base_url() {
    let _bypass = allow_loopback_for_this_test();
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(OPENAI_SSE_BODY)
                .insert_header("content-type", "text/event-stream"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let stream = OpenAiProvider::compatible(server.uri(), "groq-test")
        .unwrap()
        .chat(simple_request(), "gsk_fake", &test_tenant())
        .await
        .expect("compatible chat returns stream");
    let _events = drain(stream).await;
}

// =============================================================================
// Anthropic — POST /v1/messages, x-api-key header, anthropic-version + beta.
// =============================================================================

const ANTHROPIC_SSE_BODY: &str = concat!(
    "event: message_start\n",
    "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_x\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-sonnet-4-6\",\"stop_reason\":null,\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n",
    "event: content_block_start\n",
    "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
    "event: content_block_delta\n",
    "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
    "event: message_stop\n",
    "data: {\"type\":\"message_stop\"}\n\n",
);

#[tokio::test]
async fn anthropic_provider_request_shape() {
    let _bypass = allow_loopback_for_this_test();
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(header("x-api-key", "sk-ant-fake"))
        .and(header("anthropic-version", "2023-06-01"))
        .and(header("content-type", "application/json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(ANTHROPIC_SSE_BODY)
                .insert_header("content-type", "text/event-stream"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let mut req = simple_request();
    req.model = "claude-sonnet-4-6".into();
    let stream = AnthropicProvider::for_base_url(server.uri())
        .unwrap()
        .chat(req, "sk-ant-fake", &test_tenant())
        .await
        .expect("anthropic chat returns stream");
    let _events = drain(stream).await;
}

// =============================================================================
// Azure OpenAI — deployment URL + api-key header + api-version query.
// =============================================================================

#[tokio::test]
async fn azure_provider_request_shape() {
    let _bypass = allow_loopback_for_this_test();
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"^/openai/deployments/[^/]+/chat/completions$"))
        .and(query_param("api-version", "2025-01-01-preview"))
        .and(header("api-key", "az-fake-key"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(OPENAI_SSE_BODY)
                .insert_header("content-type", "text/event-stream"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let mut req = simple_request();
    req.model = "azure/gpt-4o".into(); // strips to deployment "gpt-4o"
    let stream = AzureOpenAiProvider::for_endpoint(server.uri(), "2025-01-01-preview")
        .unwrap()
        .chat(req, "az-fake-key", &test_tenant())
        .await
        .expect("azure chat returns stream");
    let _events = drain(stream).await;
}

// =============================================================================
// Bedrock — SigV4 + Converse API (ADR-011 Move #4). Without AWS creds in
// the environment the chat() call must fail with a credentials error.
// We can't drive the live signing path from the smoke test since it
// requires real AWS credentials + a real Bedrock endpoint; the unit
// tests in providers/bedrock.rs cover the SigV4 derivation + Converse
// translation logic.
// =============================================================================

#[tokio::test]
async fn bedrock_provider_fails_without_aws_credentials() {
    // Only mutate env if the creds are actually present — in CI (and any
    // normal test run) they're unset, so this is a no-op and adds zero
    // env-write churn to the parallel suite. We restore on the way out only
    // what we removed. (Concurrent set_var/var is a data race; we minimise it.)
    let saved_ak = std::env::var("AWS_ACCESS_KEY_ID").ok();
    let saved_sk = std::env::var("AWS_SECRET_ACCESS_KEY").ok();
    if saved_ak.is_some() {
        unsafe {
            std::env::remove_var("AWS_ACCESS_KEY_ID");
        }
    }
    if saved_sk.is_some() {
        unsafe {
            std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        }
    }

    let provider = BedrockProvider::new().unwrap();
    let result = provider
        .chat(simple_request(), "ignored", &test_tenant())
        .await;

    let err = match result {
        Ok(_) => panic!("bedrock chat() must fail when AWS creds are absent"),
        Err(e) => e,
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("AWS_ACCESS_KEY_ID")
            || msg.contains("AWS credentials")
            || msg.contains("AWS_SECRET_ACCESS_KEY"),
        "expected credentials error, got: {msg}"
    );

    unsafe {
        if let Some(v) = saved_ak {
            std::env::set_var("AWS_ACCESS_KEY_ID", v);
        }
        if let Some(v) = saved_sk {
            std::env::set_var("AWS_SECRET_ACCESS_KEY", v);
        }
    }
}

// =============================================================================
// B-391 (b): the typed-status contract holds for EVERY adapter, not just the
// OpenAI-shaped ones. Before this, Cohere / Azure / Bedrock returned a stringly
// `anyhow::bail!("… error: status 401")` that `classify_dispatch_error` could
// not see, so a rejected BYOK key on those three providers reached the customer
// as 502 `provider_unavailable` — "our outage" — instead of 401
// `provider_key_rejected`. One test per adapter, one status each, and the
// credential-echo assertion on every one.
// =============================================================================

#[tokio::test]
async fn cohere_401_surfaces_typed_auth_rejection() {
    let _bypass = allow_loopback_for_this_test();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_string("{\"message\":\"invalid api token co-leaked-secret\"}"),
        )
        .mount(&server)
        .await;

    let err = match CohereProvider::for_base_url(server.uri())
        .unwrap()
        .chat(simple_request(), "co-leaked-secret", &test_tenant())
        .await
    {
        Ok(_) => panic!("upstream 401 must surface as an error, not Ok"),
        Err(e) => e,
    };
    let http = err
        .downcast_ref::<crate::providers::ProviderHttpError>()
        .expect("Cohere non-2xx must be a typed ProviderHttpError");
    assert_eq!(http.status, 401);
    assert_eq!(http.provider, "cohere");
    assert!(http.is_auth_rejection());
    assert!(
        !format!("{err:#}").contains("co-leaked-secret"),
        "upstream 401 body must not leak into the error chain"
    );
}

#[tokio::test]
async fn azure_429_surfaces_typed_rate_limit() {
    let _bypass = allow_loopback_for_this_test();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/openai/deployments/.+/chat/completions$"))
        .respond_with(ResponseTemplate::new(429).set_body_string(
            "{\"error\":{\"code\":\"429\",\"message\":\"rate limited az-leaked-secret\"}}",
        ))
        .mount(&server)
        .await;

    let err = match AzureOpenAiProvider::for_endpoint(server.uri(), "2025-01-01-preview")
        .unwrap()
        .chat(simple_request(), "az-leaked-secret", &test_tenant())
        .await
    {
        Ok(_) => panic!("upstream 429 must surface as an error, not Ok"),
        Err(e) => e,
    };
    let http = err
        .downcast_ref::<crate::providers::ProviderHttpError>()
        .expect("Azure non-2xx must be a typed ProviderHttpError");
    assert_eq!(http.status, 429);
    assert_eq!(http.provider, "azure");
    assert!(http.is_rate_limited());
    assert!(
        !format!("{err:#}").contains("az-leaked-secret"),
        "upstream 429 body must not leak into the error chain"
    );
}

#[tokio::test]
async fn bedrock_403_surfaces_typed_auth_rejection() {
    let _bypass = allow_loopback_for_this_test();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/model/.+/converse$"))
        .respond_with(ResponseTemplate::new(403).set_body_string(
            "{\"message\":\"The security token included in the request is invalid: br-leaked-token\"}",
        ))
        .mount(&server)
        .await;

    // Static test credentials + an endpoint override: reads NO process env, so
    // this is safe beside the env-mutating `bedrock_*` test above.
    let err =
        match BedrockProvider::for_test_endpoint(server.uri(), "AKIATESTKEY", "br-leaked-token")
            .unwrap()
            .chat(simple_request(), "ignored", &test_tenant())
            .await
        {
            Ok(_) => panic!("upstream 403 must surface as an error, not Ok"),
            Err(e) => e,
        };
    let http = err
        .downcast_ref::<crate::providers::ProviderHttpError>()
        .expect("Bedrock non-2xx must be a typed ProviderHttpError");
    assert_eq!(http.status, 403);
    assert_eq!(http.provider, "bedrock");
    assert!(http.is_auth_rejection());
    assert!(
        !format!("{err:#}").contains("br-leaked-token"),
        "upstream 403 body must not leak into the error chain"
    );
}

/// B-391 (b), the table: EVERY mockable adapter × the four statuses the
/// handler classifies (401 key rejected · 404 model not found · 429 rate
/// limited · 503 unavailable). Each cell asserts the typed status AND that the
/// upstream body — which carries a credential-shaped string on purpose — never
/// reaches the error chain. Bedrock is covered by its own test above (it needs
/// static credentials); Vertex needs a GCP token exchange and is out of this
/// table.
#[tokio::test]
async fn every_adapter_types_its_upstream_status() {
    let _bypass = allow_loopback_for_this_test();
    type Predicate = fn(&crate::providers::ProviderHttpError) -> bool;
    let statuses: [(u16, Predicate); 4] = [
        (401, |h| h.is_auth_rejection()),
        (404, |h| h.is_model_not_found()),
        (429, |h| h.is_rate_limited()),
        (503, |h| {
            !h.is_auth_rejection()
                && !h.is_model_not_found()
                && !h.is_rate_limited()
                && !h.is_unclassified_client_error()
        }),
    ];
    // (adapter, mock path, a request whose model routes to it)
    let adapters: [(&str, &str); 5] = [
        ("openai", "/v1/chat/completions"),
        ("anthropic", "/v1/messages"),
        (
            "google",
            "/v1beta/models/gemini-2.5-flash:streamGenerateContent",
        ),
        ("azure", "/openai/deployments/gpt-4o/chat/completions"),
        ("cohere", "/chat"),
    ];
    for (adapter, mock_path) in adapters {
        for (status, predicate) in statuses {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path(mock_path))
                .respond_with(
                    ResponseTemplate::new(status)
                        .set_body_string("{\"error\":\"see key sk-table-leaked-secret\"}"),
                )
                .mount(&server)
                .await;
            let mut req = simple_request();
            let result = match adapter {
                "openai" => {
                    OpenAiProvider::compatible(server.uri(), "openai")
                        .unwrap()
                        .chat(req, "sk-table-leaked-secret", &test_tenant())
                        .await
                }
                "anthropic" => {
                    req.model = "claude-sonnet-4-6".into();
                    AnthropicProvider::for_base_url(server.uri())
                        .unwrap()
                        .chat(req, "sk-table-leaked-secret", &test_tenant())
                        .await
                }
                "google" => {
                    req.model = "gemini-2.5-flash".into();
                    GoogleProvider::for_base_url(server.uri())
                        .unwrap()
                        .chat(req, "sk-table-leaked-secret", &test_tenant())
                        .await
                }
                "azure" => {
                    req.model = "azure/gpt-4o".into();
                    AzureOpenAiProvider::for_endpoint(server.uri(), "2025-01-01-preview")
                        .unwrap()
                        .chat(req, "sk-table-leaked-secret", &test_tenant())
                        .await
                }
                "cohere" => {
                    req.model = "command-r".into();
                    CohereProvider::for_base_url(server.uri())
                        .unwrap()
                        .chat(req, "sk-table-leaked-secret", &test_tenant())
                        .await
                }
                _ => unreachable!(),
            };
            let err = match result {
                Ok(_) => panic!("{adapter}: upstream {status} must surface as an error"),
                Err(e) => e,
            };
            let http = err
                .downcast_ref::<crate::providers::ProviderHttpError>()
                .unwrap_or_else(|| {
                    panic!("{adapter}: upstream {status} must be a typed ProviderHttpError, got: {err:#}")
                });
            assert_eq!(http.status, status, "{adapter}");
            assert!(predicate(http), "{adapter}: {status} classified wrong");
            assert!(
                !format!("{err:#}").contains("sk-table-leaked-secret"),
                "{adapter}: upstream {status} body leaked into the error chain"
            );
        }
    }
}

// =============================================================================
// Cohere — POST /chat (Cohere event-stream JSONL); bearer auth.
// =============================================================================

const COHERE_BODY: &str = concat!(
    "{\"event_type\":\"text-generation\",\"text\":\"hi\"}\n",
    "{\"event_type\":\"stream-end\",\"finish_reason\":\"COMPLETE\",\"response\":{\"meta\":{\"billed_units\":{\"input_tokens\":1,\"output_tokens\":1}}}}\n",
);

#[tokio::test]
async fn cohere_provider_request_shape() {
    let _bypass = allow_loopback_for_this_test();
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat"))
        .and(header("authorization", "Bearer co-fake"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(COHERE_BODY)
                .insert_header("content-type", "application/x-ndjson"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let mut req = simple_request();
    req.model = "command-r-plus".into();
    let stream = CohereProvider::for_base_url(server.uri())
        .unwrap()
        .chat(req, "co-fake", &test_tenant())
        .await
        .expect("cohere chat returns stream");
    let _events = drain(stream).await;
}

// =============================================================================
// Google Gemini — POST /v1beta/models/{model}:streamGenerateContent
//                 query: alt=sse, key=<api_key> (in URL, not header).
// =============================================================================

const GEMINI_SSE_BODY: &str = "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hi\"}],\"role\":\"model\"},\"finishReason\":\"STOP\",\"index\":0}],\"usageMetadata\":{\"promptTokenCount\":1,\"candidatesTokenCount\":1,\"totalTokenCount\":2}}\n\n";

#[tokio::test]
async fn google_provider_request_shape() {
    let _bypass = allow_loopback_for_this_test();
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"^/v1beta/models/[^:]+:streamGenerateContent$"))
        .and(query_param("alt", "sse"))
        .and(query_param("key", "g-fake"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(GEMINI_SSE_BODY)
                .insert_header("content-type", "text/event-stream"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let mut req = simple_request();
    req.model = "gemini-3-pro".into();
    let stream = GoogleProvider::for_base_url(server.uri())
        .unwrap()
        .chat(req, "g-fake", &test_tenant())
        .await
        .expect("google chat returns stream");
    let _events = drain(stream).await;
}

// =============================================================================
// Failover meta-adapter — primary returns 503, secondary succeeds.
// Exercises `execute_with_failover` directly so we don't have to compose the
// full multi-provider call site.
// =============================================================================

#[tokio::test]
async fn failover_meta_adapter_promotes_secondary_on_503() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let attempts = AtomicUsize::new(0);
    let chain = ["primary", "secondary"];
    let tenant = test_tenant();

    let (winner, record) = execute_with_failover(&tenant, &chain, |provider_name| {
        // Convert the borrowed &str into an owned String before crossing into
        // the async block — `async move` borrows the future from outside the
        // closure, but the &str only lives as long as the closure body.
        let name_owned: String = provider_name.to_string();
        let n = attempts.fetch_add(1, Ordering::SeqCst);
        async move {
            if n == 0 {
                // First call: primary returns a failover-eligible status.
                Err::<String, u16>(503u16)
            } else {
                Ok::<String, u16>(name_owned)
            }
        }
    })
    .await
    .expect("failover should succeed on secondary");

    assert_eq!(winner, "secondary");
    assert!(record.failover_activated);
    assert_eq!(record.attempt_count, 2);
    assert_eq!(record.winning_provider_index, 1);
    assert!(FAILOVER_CODES.contains(&503u16));
}

#[tokio::test]
async fn failover_meta_adapter_skips_failover_for_caller_errors() {
    // 401 / 403 / 400 are caller errors — must NOT trigger failover.
    assert!(!crate::providers::failover::is_failover_eligible(400));
    assert!(!crate::providers::failover::is_failover_eligible(401));
    assert!(!crate::providers::failover::is_failover_eligible(403));
    assert!(!crate::providers::failover::is_failover_eligible(404));
    // 5xx that we explicitly treat as transient.
    assert!(crate::providers::failover::is_failover_eligible(500));
    assert!(crate::providers::failover::is_failover_eligible(502));
    assert!(crate::providers::failover::is_failover_eligible(503));
    assert!(crate::providers::failover::is_failover_eligible(504));
}

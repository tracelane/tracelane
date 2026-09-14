//! B-385 (2c) — the in-process handler harness.
//!
//! `test_state()` + a direct call to the REAL handler (`chat_completions_handler`,
//! `embeddings_handler`, `messages_handler`) is the pattern: no axum server, no
//! Postgres, no ClickHouse, no NATS — the OSS self-host shape, in which
//! `entitlements` is `None` and therefore the FREE tier
//! (`.claude/rules/tenancy.md`). A wiremock upstream stands in for the provider.
//!
//! Until 2026-09-12 the crate had no such harness and the ORDER of the admission
//! cascade was asserted by `include_str!`-ing `server.rs` and comparing string
//! offsets — a test that passes when the comment moves and the code does not.
//! Every test in this module drives the handler and reads a counter, a response
//! byte or a mock's request log.
//!
//! Compiled only under `cfg(all(test, debug_assertions))` (declared so in
//! `main.rs`); nothing here reaches the binary.

use std::sync::Arc;

use axum::http::HeaderMap;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::audit::AuditChain;
use crate::predictive::PredictiveLayer;
use crate::providers::ProviderRegistry;
use crate::rate_limiter::RateLimiter;
use crate::server::AppState;

/// Thread-local loopback opt-in — wiremock binds 127.0.0.1 and the SSRF guard
/// blocks it. Never a process-env mutation (that races the suite).
pub(crate) struct LoopbackBypassGuard;

impl LoopbackBypassGuard {
    pub(crate) fn new() -> Self {
        crate::ssrf_guard::set_loopback_bypass_for_tests(true);
        Self
    }
}

impl Drop for LoopbackBypassGuard {
    fn drop(&mut self) {
        crate::ssrf_guard::set_loopback_bypass_for_tests(false);
    }
}

/// An in-memory audit chain: no signing key, no ClickHouse, no Postgres. Its
/// per-tenant `seq` is readable through `AuditChain::in_memory_seq`, which is
/// how a test proves "the ledger did not move".
pub(crate) fn in_memory_chain() -> Arc<AuditChain> {
    Arc::new(AuditChain::new(100, None, None).expect("audit chain builds without a signing key"))
}

/// An `AppState` with no Postgres, no ClickHouse, no NATS and no Polar —
/// i.e. the OSS self-host shape. Entitlements are `None`, which resolves to
/// the FREE tier, never a paid one (`.claude/rules/tenancy.md`).
pub(crate) fn test_state(providers: ProviderRegistry) -> AppState {
    test_state_with_chain(providers, in_memory_chain())
}

/// [`test_state`] with a caller-supplied audit chain — the seam for a chain
/// that REFUSES (`unreachable_pg_chain` in the Anthropic tests), which is how
/// the fail-closed 503 is proven rather than described.
pub(crate) fn test_state_with_chain(
    providers: ProviderRegistry,
    audit_chain: Arc<AuditChain>,
) -> AppState {
    AppState {
        providers: Arc::new(providers),
        // The cache is OFF in the test state, which is the production
        // default too — every hot-path test therefore exercises the
        // no-cache path, and the cache's own behaviour is tested in
        // `semantic_cache`'s module tests rather than implicitly here.
        semantic_cache: None,
        audit_chain: Arc::clone(&audit_chain),
        rate_limiter: Arc::new(RateLimiter::new()),

        quota_ch_url: None,
        predictive: Arc::new(PredictiveLayer::new()),
        predictive_enforce: false,
        guardrail: Arc::new(crate::guardrail::GuardrailEngine::new(
            audit_chain,
            None,
            None,
            Arc::new(crate::guardrail::capability::CapabilityRegistry::new()),
        )),
        nats: None,
        entitlements: None,
        circuit_breaker: Arc::new(crate::circuit_breaker::CircuitBreaker::new(
            crate::circuit_breaker::BreakerConfig::default(),
        )),
        kill_switch: Arc::new(crate::kill_switch::KillSwitch::disabled()),
        prompt_router: crate::server::build_prompt_router(None),
        bench_mock_upstream: false,
        // B-386 (b): constructor arguments, not process globals — no `set_var`.
        // FREE is the hosted no-control-plane answer; a self-host test that
        // wants Enterprise sets the field, not the environment.
        no_control_plane_rate_limit_rpm: Some(60),
        rejection_metrics: Arc::new(crate::rejection_metrics::RejectionRegistry::new()),
        hotpath: crate::hotpath::Config::default(),
        failover: None,
        pg: None,
        // BILL-01: no ClickHouse in the test state, so no meter sink either —
        // the same OSS self-host shape `quota_ch_url: None` above already
        // states. `meters::global()` returning `None` here is what
        // `crate::billing::meters` documents as fail-open (a dropped-on-the-
        // floor meter counter, never a blocked request).
        meters: None,
        // No Postgres in the test state, so the rate card can never load —
        // `unavailable()` is the exact state the real boot path starts in
        // before its first successful refresh, so this is not a test-only
        // stand-in, it is a real reachable state.
        rate_card: Arc::new(arc_swap::ArcSwap::from_pointee(
            crate::billing::RateCard::unavailable(),
        )),
    }
}

/// `Authorization: Bearer test-token` — resolved by the debug-build dev stub
/// (`auth::dev_stub_claims`) to the fixed dev tenant with full scope.
pub(crate) fn authed() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        axum::http::header::AUTHORIZATION,
        axum::http::HeaderValue::from_static("Bearer test-token"),
    );
    h
}

/// The tenant every dev-stub credential resolves to.
pub(crate) fn dev_tenant() -> tracelane_shared::TenantId {
    crate::auth::dev_stub_claims(crate::auth::AuthMethod::JwtBearer).tenant_id
}

pub(crate) async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("response body is JSON")
}

/// A registry whose Ollama adapter points at `uri`. Ollama is the one
/// provider whose credential env var is empty by design, so this exercises
/// the real BYOK resolution path without a Postgres pool or an env var.
pub(crate) fn registry_pointing_ollama_at(uri: String) -> ProviderRegistry {
    let mut reg = ProviderRegistry::new().expect("provider registry");
    reg.set_compat_base_url_for_test("ollama", uri)
        .expect("ollama adapter for the mock");
    reg
}

/// A wiremock upstream that answers `POST /v1/chat/completions` with one
/// complete OpenAI-shaped completion.
pub(crate) async fn chat_ok_mock() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(chat_ok_body()))
        .mount(&server)
        .await;
    server
}

pub(crate) fn chat_ok_body() -> serde_json::Value {
    json!({
        "id": "chatcmpl-harness", "object": "chat.completion", "model": "ollama/llama3",
        "choices": [{"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": "ok"}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    })
}

/// `authed()` plus an `x-trace-id`, so the span this request produces can be
/// read back from `otlp_emit::test_sink::for_trace` without racing the suite.
pub(crate) fn authed_with_trace(trace_id: uuid::Uuid) -> HeaderMap {
    let mut h = authed();
    h.insert(
        "x-trace-id",
        axum::http::HeaderValue::from_str(&trace_id.to_string()).expect("uuid is a header value"),
    );
    h
}

/// An audit chain whose Postgres pool points at a port nothing listens on, so
/// every publish FAILS — the fail-closed 503 is provable rather than described.
pub(crate) fn unreachable_pg_chain() -> Arc<AuditChain> {
    let mut cfg = deadpool_postgres::Config::new();
    cfg.host = Some("127.0.0.1".to_owned());
    cfg.port = Some(1);
    cfg.user = Some("tracelane-unit-test-no-such-user".to_owned());
    cfg.dbname = Some("tracelane-unit-test-no-such-db".to_owned());
    cfg.connect_timeout = Some(std::time::Duration::from_millis(250));
    let pool = cfg
        .create_pool(
            Some(deadpool_postgres::Runtime::Tokio1),
            tokio_postgres::NoTls,
        )
        .expect("deadpool builds without connecting");
    Arc::new(AuditChain::with_pg_pool(100, None, None, Some(pool)).expect("audit chain"))
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    use crate::server::{chat_completions_handler, embeddings_handler};
    use axum::extract::{Json, State};
    use axum::http::StatusCode;

    // ── B-385 (2b): PARSE BEFORE CHARGE, as a behaviour, on every route ──
    //
    // The defect this pins (spec §0): the chat route charged the monthly quota
    // and published the ledger row BEFORE it parsed the body, so a request
    // without `model` was charged and ledgered on one route and refused for
    // free on another. The assertion is on the COUNTERS, not the status: a 400
    // proves nothing on its own — the pre-refactor chat handler also answered
    // 400 (`provider_not_configured`, after defaulting the model), having
    // already moved both counters.

    #[tokio::test]
    async fn chat_without_a_model_is_refused_before_quota_or_ledger() {
        let state = test_state(ProviderRegistry::new().expect("registry"));
        let tenant = dev_tenant();
        let ledger_before = state.audit_chain.in_memory_seq(&tenant);
        let publish_before = crate::audit::audit_publish_stats();

        let resp = chat_completions_handler(
            State(state.clone()),
            authed(),
            Json(json!({ "messages": [{"role": "user", "content": "no model here"}] })),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert!(
            body["error"]
                .as_str()
                .is_some_and(|e| e.starts_with("malformed request:")),
            "a body without `model` is a malformed request, not a routing or key problem: {body}"
        );
        assert_eq!(
            state.audit_chain.in_memory_seq(&tenant),
            ledger_before,
            "a malformed body must not land a ledger row (nothing was dispatched)"
        );
        assert_eq!(
            crate::audit::audit_publish_stats(),
            publish_before,
            "the async publish counters must not move either"
        );
    }

    #[tokio::test]
    async fn embeddings_without_a_model_is_refused_before_quota_or_ledger() {
        let state = test_state(ProviderRegistry::new().expect("registry"));
        let tenant = dev_tenant();
        let ledger_before = state.audit_chain.in_memory_seq(&tenant);

        let resp = embeddings_handler(
            State(state.clone()),
            authed(),
            Json(json!({ "input": "orphan input, no model" })),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(resp).await["error"], "invalid_request");
        assert_eq!(state.audit_chain.in_memory_seq(&tenant), ledger_before);
    }

    #[tokio::test]
    async fn messages_without_a_model_is_refused_before_quota_or_ledger() {
        let state = test_state(ProviderRegistry::new().expect("registry"));
        let tenant = dev_tenant();
        let ledger_before = state.audit_chain.in_memory_seq(&tenant);

        let resp = crate::anthropic_messages::messages_handler(
            State(state.clone()),
            authed(),
            axum::body::Bytes::from_static(
                br#"{"max_tokens":16,"messages":[{"role":"user","content":"no model"}]}"#,
            ),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(resp).await["error"]["code"], "invalid_request");
        assert_eq!(state.audit_chain.in_memory_seq(&tenant), ledger_before);
    }

    // ── B-385 (2c): the chaos harness, THROUGH the real handler ──
    //
    // `tests/failover_chaos.rs` and `tests/rate_limit_chaos.rs` used to drive a
    // bare reqwest client against wiremock and sleep for the backoff themselves
    // — they proved wiremock works. These drive `chat_completions_handler` and
    // read the gateway's own state: the mock's request log (how many attempts),
    // the span sink (how many spans), the breaker's window (how many feeds),
    // the response bytes (the 429 and its `Retry-After`).

    /// FT-01 / A7: an upstream 503 followed by a 200 is ONE retry — two requests
    /// reach the provider, ONE span is recorded (the successful one, not an error
    /// span per attempt), and the breaker is fed ONCE with the final outcome.
    /// Through `retry_loop` (B-391 made it closure-driven) inside the real handler.
    #[tokio::test]
    async fn a_503_then_200_is_retried_once_records_one_span_and_feeds_the_breaker_once() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(503).set_body_string("upstream broke"))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(chat_ok_body()))
            .mount(&server)
            .await;
        let mut state = test_state(registry_pointing_ollama_at(server.uri()));
        // A breaker that trips on ONE failure: if the retry loop fed the 503 as
        // its own outcome, the breaker would be Open by the time the 200 landed
        // and the second assertion below would read it.
        state.circuit_breaker = Arc::new(crate::circuit_breaker::CircuitBreaker::new(
            crate::circuit_breaker::BreakerConfig {
                consecutive_failure_threshold: 1,
                ..crate::circuit_breaker::BreakerConfig::default()
            },
        ));
        let trace_id = uuid::Uuid::new_v4();

        let resp = chat_completions_handler(
            State(state.clone()),
            authed_with_trace(trace_id),
            Json(json!({
                "model": "ollama/llama3",
                "messages": [{"role": "user", "content": "retry me"}]
            })),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK, "{:?}", body_json(resp).await);
        let received = server
            .received_requests()
            .await
            .expect("mock recorded requests");
        assert_eq!(
            received.len(),
            2,
            "exactly one retry: the 503 attempt and the 200 attempt, no third"
        );
        let spans = crate::otlp_emit::test_sink::for_trace(trace_id);
        assert_eq!(
            spans.len(),
            1,
            "one request, one span — the retry is not a second span"
        );
        assert!(
            spans[0].status.message.is_none()
                || !spans[0]
                    .status
                    .message
                    .as_deref()
                    .is_some_and(|m| m.contains("provider_unavailable")),
            "the served request's span must not carry the intermediate 503: {:?}",
            spans[0].status
        );
        assert_eq!(
            state.circuit_breaker.outcomes("ollama", "default"),
            vec![true],
            "the breaker is fed once, with the FINAL outcome — not once per attempt"
        );
        assert_eq!(
            state.circuit_breaker.state("ollama", "default"),
            crate::circuit_breaker::State::Closed
        );
    }

    /// FT-02 half: a persistent 503 exhausts the single retry, the caller gets
    /// the typed 502, ONE error span is recorded and the breaker is fed ONE
    /// failure.
    #[tokio::test]
    async fn a_persistent_503_exhausts_the_single_retry_and_records_one_error_span() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let state = test_state(registry_pointing_ollama_at(server.uri()));
        let trace_id = uuid::Uuid::new_v4();

        let resp = chat_completions_handler(
            State(state.clone()),
            authed_with_trace(trace_id),
            Json(json!({
                "model": "ollama/llama3",
                "messages": [{"role": "user", "content": "still broken"}]
            })),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(body_json(resp).await["error"], "provider unavailable");
        assert_eq!(
            server.received_requests().await.expect("requests").len(),
            2,
            "one attempt plus exactly one retry, then give up"
        );
        let spans = crate::otlp_emit::test_sink::for_trace(trace_id);
        assert_eq!(
            spans.len(),
            1,
            "one error span for the whole failed request"
        );
        assert_eq!(
            spans[0].status.message.as_deref(),
            Some("provider_unavailable")
        );
        assert_eq!(
            state.circuit_breaker.outcomes("ollama", "default"),
            vec![false]
        );
    }

    /// A tenant over its per-minute limit gets 429 + `Retry-After` from the REAL
    /// handler, on all three routes — before the quota is charged, before the
    /// ledger row, before any provider call.
    #[tokio::test]
    async fn a_tenant_over_its_per_minute_limit_gets_429_with_retry_after() {
        let _bypass = LoopbackBypassGuard::new();
        let server = chat_ok_mock().await;
        let tenant = dev_tenant();

        // Drain the FREE bucket (60 rpm) on the SAME limiter the handler consults.
        let drained = || {
            let state = test_state(registry_pointing_ollama_at(server.uri()));
            for _ in 0..60u32 {
                assert!(matches!(
                    state.rate_limiter.check(&tenant, Some(60)),
                    crate::rate_limiter::RateLimitDecision::Allow
                ));
            }
            state
        };

        // Chat.
        let state = drained();
        let resp = chat_completions_handler(
            State(state.clone()),
            authed(),
            Json(
                json!({ "model": "ollama/llama3", "messages": [{"role": "user", "content": "x"}] }),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after = resp
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok())
            .expect("a 429 from the handler carries a numeric Retry-After");
        let body = body_json(resp).await;
        assert_eq!(body["error"], "rate limit exceeded");
        assert_eq!(body["retry_after_secs"], retry_after);
        assert_eq!(state.audit_chain.in_memory_seq(&tenant), 0, "not ledgered");
        assert_eq!(state.rejection_metrics.snapshot(&tenant), (1, 0));

        // Embeddings.
        let state = drained();
        let resp = embeddings_handler(
            State(state.clone()),
            authed(),
            Json(json!({ "model": "ollama/nomic-embed-text", "input": "x" })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().contains_key(axum::http::header::RETRY_AFTER));
        assert_eq!(body_json(resp).await["error"], "rate limit exceeded");
        assert_eq!(state.rejection_metrics.snapshot(&tenant), (1, 0));

        // Anthropic Messages.
        let state = drained();
        let resp = crate::anthropic_messages::messages_handler(
            State(state.clone()),
            authed(),
            axum::body::Bytes::from_static(
                br#"{"model":"claude-sonnet-4-6","max_tokens":16,"messages":[{"role":"user","content":"x"}]}"#,
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().contains_key(axum::http::header::RETRY_AFTER));
        let body = body_json(resp).await;
        assert_eq!(body["error"]["type"], "rate_limit_error");
        assert_eq!(body["error"]["code"], "rate_limited");
        assert_eq!(state.rejection_metrics.snapshot(&tenant), (1, 0));

        assert!(
            server
                .received_requests()
                .await
                .is_some_and(|r| r.is_empty()),
            "a throttled request must never reach the provider"
        );
    }

    /// The ledger is unavailable ⇒ 503 `audit_unavailable`, NO dispatch, no
    /// charge beyond the quota increment that precedes it — on the chat route
    /// (the Anthropic route's twin lives in `anthropic_messages::tests`).
    #[tokio::test]
    async fn chat_with_an_unavailable_ledger_503s_before_any_dispatch() {
        let _bypass = LoopbackBypassGuard::new();
        let server = chat_ok_mock().await;
        let state = test_state_with_chain(
            registry_pointing_ollama_at(server.uri()),
            unreachable_pg_chain(),
        );
        let resp = chat_completions_handler(
            State(state.clone()),
            authed(),
            Json(
                json!({ "model": "ollama/llama3", "messages": [{"role": "user", "content": "x"}] }),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body_json(resp).await["error"], "audit_unavailable");
        assert!(
            server
                .received_requests()
                .await
                .is_some_and(|r| r.is_empty()),
            "an unrecorded request must never reach the provider"
        );
    }
}

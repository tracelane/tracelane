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
        zdr: Arc::new(arc_swap::ArcSwap::from_pointee(
            crate::zdr::ZdrCapabilities::unavailable(),
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

    // ── GWY-49 — zero-data-retention routing, spec §7 rows 3–4 ──────────────
    //
    // The whole feature is one decision (`zdr::ZdrCapabilities::eligible`) sitting in
    // front of dispatch. These drive the REAL handler and count what the mock provider
    // received — a refused request must reach it ZERO times.

    fn with_zdr_caps(state: &AppState, rows: &[(&str, &str)]) {
        state
            .zdr
            .store(Arc::new(crate::zdr::ZdrCapabilities::from_rows(
                rows.iter()
                    .map(|(p, z)| ((*p).to_string(), (*z).to_string())),
            )));
    }

    fn authed_with_trace_and_zdr(trace_id: uuid::Uuid, value: &str) -> HeaderMap {
        let mut h = authed_with_trace(trace_id);
        h.insert(
            "x-tracelane-zdr",
            axum::http::HeaderValue::from_str(value).expect("header value"),
        );
        h
    }

    /// Row 4: the model's provider is `none` → 400 `zdr_unsatisfiable`, the provider
    /// receives NOTHING, and the error span names the reason. Fail-closed, observed.
    #[tokio::test]
    async fn zdr_required_on_a_none_provider_is_refused_before_any_byte_leaves() {
        let _bypass = LoopbackBypassGuard::new();
        let server = chat_ok_mock().await;
        let state = test_state(registry_pointing_ollama_at(server.uri()));
        with_zdr_caps(&state, &[("ollama", "none")]);
        let trace_id = uuid::Uuid::new_v4();
        let resp = chat_completions_handler(
            State(state.clone()),
            authed_with_trace_and_zdr(trace_id, "required"),
            Json(
                json!({"model": "ollama/llama3", "messages": [{"role": "user", "content": "hi"}]}),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "zdr_unsatisfiable");
        assert_eq!(body["provider"], "ollama");
        assert_eq!(
            server.received_requests().await.expect("recorded").len(),
            0,
            "a refused ZDR request must never reach the provider"
        );
        let spans = crate::otlp_emit::test_sink::for_trace(trace_id);
        assert_eq!(spans.len(), 1, "the refusal leaves exactly one error span");
        assert_eq!(
            spans[0].status.code,
            tracelane_shared::SpanStatusCode::Error
        );
        assert_eq!(
            spans[0].status.message.as_deref(),
            Some("zdr_unsatisfiable")
        );
        // The REFUSAL span carries the constraint and the EMPTY eligible set, so an
        // auditor filtering `tracelane_zdr_required = true` sees refusals too.
        assert_eq!(spans[0].attributes.tracelane_zdr_required, Some(true));
        assert_eq!(
            spans[0]
                .attributes
                .tracelane_zdr_eligible_providers
                .as_deref(),
            Some(&[][..])
        );
        assert_eq!(
            body["eligible_provider_count"], 0,
            "no provider is `default` in this table, and the body says so"
        );
        assert!(
            body["message"]
                .as_str()
                .is_some_and(|m| m.contains("no provider in this gateway's capability table")),
            "with zero eligible providers the advice must not point at a choice that does not exist: {body}"
        );
    }

    /// Row 3 — the router PRUNES: the primary is `none`, the customer opted into
    /// cross-provider failover, and the chain's candidate is `default` → the candidate
    /// serves the request as if asked for; the primary is a `zdr_ineligible` skip in the
    /// attempt ledger; `failover_from` names it; the eligible set is the candidate alone.
    #[tokio::test]
    async fn zdr_required_prunes_a_none_primary_to_the_eligible_failover_candidate() {
        let _bypass = LoopbackBypassGuard::new();
        let server = chat_ok_mock().await;
        let mut state = test_state(registry_pointing_ollama_at(server.uri()));
        // openai → ollama chain. `gpt-4o` routes to openai (the ineligible primary);
        // the candidate `ollama/llama3` routes to the mock. Leaked: `AppState.failover`
        // is `&'static`, exactly as the boot path installs it.
        let chain: &'static crate::server::config::FailoverConfig =
            Box::leak(Box::new(crate::server::config::FailoverConfig::for_test(
                vec![
                    crate::server::config::FailoverHop {
                        provider_id: "openai".into(),
                        model: "gpt-4o".into(),
                    },
                    crate::server::config::FailoverHop {
                        provider_id: "ollama".into(),
                        model: "ollama/llama3".into(),
                    },
                ],
                0,
                0,
            )));
        state.failover = Some(chain);
        with_zdr_caps(&state, &[("openai", "none"), ("ollama", "default")]);
        let trace_id = uuid::Uuid::new_v4();
        let mut headers = authed_with_trace_and_zdr(trace_id, "required");
        headers.insert(
            "x-tracelane-failover",
            axum::http::HeaderValue::from_static("cross-provider"),
        );
        let resp = chat_completions_handler(
            State(state.clone()),
            headers,
            Json(json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]})),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "{:?}", body_json(resp).await);
        assert_eq!(
            server.received_requests().await.expect("recorded").len(),
            1,
            "exactly one dispatch, to the eligible candidate"
        );
        let spans = crate::otlp_emit::test_sink::for_trace(trace_id);
        assert_eq!(spans.len(), 1);
        let a = &spans[0].attributes;
        assert_eq!(a.tracelane_zdr_required, Some(true));
        assert_eq!(
            a.tracelane_zdr_eligible_providers.as_deref(),
            Some(&["ollama".to_string()][..]),
            "the pruned set: the primary is NOT in it"
        );
        assert_eq!(
            a.tracelane_failover_from.as_deref(),
            Some("openai"),
            "the swap is on the span, never silent"
        );
        let ledger = a
            .tracelane_dispatch_attempts
            .as_deref()
            .expect("a pruned primary makes the ledger worth recording");
        assert_eq!(ledger.len(), 2, "one skip, one dispatch: {ledger:?}");
        assert_eq!(ledger[0].outcome, "skipped");
        assert_eq!(ledger[0].provider, "openai");
        assert_eq!(ledger[0].model, "gpt-4o");
        assert_eq!(ledger[0].reason.as_deref(), Some("zdr_ineligible"));
        assert_eq!(ledger[1].outcome, "ok");
        assert_eq!(ledger[1].provider, "ollama");
    }

    /// The prune needs BOTH headers: without the failover opt-in an ineligible primary
    /// is refused even when an eligible candidate exists — Tracelane never sends to a
    /// provider the customer did not name.
    #[tokio::test]
    async fn zdr_required_without_failover_opt_in_never_swaps_the_provider() {
        let _bypass = LoopbackBypassGuard::new();
        let server = chat_ok_mock().await;
        let mut state = test_state(registry_pointing_ollama_at(server.uri()));
        let chain: &'static crate::server::config::FailoverConfig =
            Box::leak(Box::new(crate::server::config::FailoverConfig::for_test(
                vec![crate::server::config::FailoverHop {
                    provider_id: "ollama".into(),
                    model: "ollama/llama3".into(),
                }],
                0,
                0,
            )));
        state.failover = Some(chain);
        with_zdr_caps(&state, &[("openai", "none"), ("ollama", "default")]);
        let resp = chat_completions_handler(
            State(state.clone()),
            authed_with_trace_and_zdr(uuid::Uuid::new_v4(), "required"),
            Json(json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]})),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "zdr_unsatisfiable");
        assert_eq!(
            body["eligible_provider_count"], 1,
            "ollama IS default — but not named"
        );
        assert_eq!(server.received_requests().await.expect("recorded").len(), 0);
    }

    /// `/v1/embeddings` — the same refusal, its own span (this route does not use
    /// `RequestConfig`), the mock untouched.
    #[tokio::test]
    async fn zdr_required_on_embeddings_refuses_a_none_provider_with_the_constraint_on_the_span() {
        let _bypass = LoopbackBypassGuard::new();
        let server = chat_ok_mock().await;
        let state = test_state(registry_pointing_ollama_at(server.uri()));
        with_zdr_caps(&state, &[("ollama", "none")]);
        let trace_id = uuid::Uuid::new_v4();
        let resp = embeddings_handler(
            State(state.clone()),
            authed_with_trace_and_zdr(trace_id, "required"),
            Json(json!({ "model": "ollama/nomic-embed-text", "input": "x" })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(resp).await["error"], "zdr_unsatisfiable");
        assert_eq!(server.received_requests().await.expect("recorded").len(), 0);
        let spans = crate::otlp_emit::test_sink::for_trace(trace_id);
        assert_eq!(spans.len(), 1);
        assert_eq!(
            spans[0].status.message.as_deref(),
            Some("zdr_unsatisfiable")
        );
        assert_eq!(spans[0].attributes.tracelane_zdr_required, Some(true));
        assert_eq!(
            spans[0]
                .attributes
                .tracelane_zdr_eligible_providers
                .as_deref(),
            Some(&[][..])
        );
    }

    /// `/v1/messages` — the refusal in the ANTHROPIC error shape (a Claude SDK cannot
    /// read an OpenAI body), before BYOK, with the constraint on the error span.
    #[tokio::test]
    async fn zdr_required_on_v1_messages_refuses_in_the_anthropic_error_shape() {
        let _bypass = LoopbackBypassGuard::new();
        let state = test_state(ProviderRegistry::new().expect("registry"));
        with_zdr_caps(&state, &[("anthropic", "none")]);
        let trace_id = uuid::Uuid::new_v4();
        let resp = crate::anthropic_messages::messages_handler(
            State(state.clone()),
            authed_with_trace_and_zdr(trace_id, "required"),
            axum::body::Bytes::from_static(
                br#"{"model":"claude-sonnet-4-6","max_tokens":16,"messages":[{"role":"user","content":"x"}]}"#,
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(body["type"], "error");
        assert_eq!(body["error"]["type"], "invalid_request_error");
        assert_eq!(body["error"]["code"], "zdr_unsatisfiable");
        assert_eq!(body["error"]["provider"], "anthropic");
        let spans = crate::otlp_emit::test_sink::for_trace(trace_id);
        assert_eq!(spans.len(), 1);
        assert_eq!(
            spans[0].status.message.as_deref(),
            Some("zdr_unsatisfiable")
        );
        assert_eq!(spans[0].attributes.tracelane_zdr_required, Some(true));
        assert_eq!(
            spans[0]
                .attributes
                .tracelane_zdr_eligible_providers
                .as_deref(),
            Some(&[][..])
        );
    }

    /// Row 3 (the half a single provider can show): the provider is `default` → the
    /// request dispatches, and the span records the constraint and the eligible set.
    #[tokio::test]
    async fn zdr_required_on_a_default_provider_dispatches_and_marks_the_span() {
        let _bypass = LoopbackBypassGuard::new();
        let server = chat_ok_mock().await;
        let state = test_state(registry_pointing_ollama_at(server.uri()));
        with_zdr_caps(&state, &[("ollama", "default")]);
        let trace_id = uuid::Uuid::new_v4();
        let resp = chat_completions_handler(
            State(state.clone()),
            authed_with_trace_and_zdr(trace_id, "required"),
            Json(
                json!({"model": "ollama/llama3", "messages": [{"role": "user", "content": "hi"}]}),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "{:?}", body_json(resp).await);
        assert_eq!(server.received_requests().await.expect("recorded").len(), 1);
        let spans = crate::otlp_emit::test_sink::for_trace(trace_id);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].attributes.tracelane_zdr_required, Some(true));
        assert_eq!(
            spans[0]
                .attributes
                .tracelane_zdr_eligible_providers
                .as_deref(),
            Some(&["ollama".to_string()][..])
        );
    }

    /// An unreadable constraint is refused BEFORE routing — never guessed at.
    #[tokio::test]
    async fn a_garbage_zdr_header_is_refused_with_its_own_code() {
        let _bypass = LoopbackBypassGuard::new();
        let server = chat_ok_mock().await;
        let state = test_state(registry_pointing_ollama_at(server.uri()));
        with_zdr_caps(&state, &[("ollama", "default")]);
        let resp = chat_completions_handler(
            State(state.clone()),
            authed_with_trace_and_zdr(uuid::Uuid::new_v4(), "please"),
            Json(
                json!({"model": "ollama/llama3", "messages": [{"role": "user", "content": "hi"}]}),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(resp).await["error"], "invalid_zdr_constraint");
        assert_eq!(server.received_requests().await.expect("recorded").len(), 0);
    }

    /// No header → today's behaviour exactly, even with an empty (fail-closed) table.
    #[tokio::test]
    async fn without_the_header_zdr_changes_nothing() {
        let _bypass = LoopbackBypassGuard::new();
        let server = chat_ok_mock().await;
        let state = test_state(registry_pointing_ollama_at(server.uri()));
        let trace_id = uuid::Uuid::new_v4();
        let resp = chat_completions_handler(
            State(state.clone()),
            authed_with_trace(trace_id),
            Json(
                json!({"model": "ollama/llama3", "messages": [{"role": "user", "content": "hi"}]}),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "{:?}", body_json(resp).await);
        let spans = crate::otlp_emit::test_sink::for_trace(trace_id);
        assert_eq!(spans[0].attributes.tracelane_zdr_required, None);
        assert_eq!(spans[0].attributes.tracelane_zdr_eligible_providers, None);
    }

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

    /// RI-05 slice 2 (M1) — the spec's own proof (§7 row 2): a provider
    /// forced to 429 once then succeed leaves a TWO-element dispatch ledger
    /// on the served request's span, `[0]` carrying the 429's status and a
    /// classified reason, `[1]` the clean success — and no element anywhere
    /// leaks the upstream body, even when that body is planted with a
    /// credential-shaped string.
    #[tokio::test]
    async fn a_429_then_200_leaves_a_two_element_dispatch_ledger_with_no_body_leak() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        // A body shaped like a leaked credential — proves the ledger never
        // reads it, not merely that this test forgot to check.
        const PLANTED: &str = "sk-live-PLANTED-CREDENTIAL-9911-do-not-leak";
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(429)
                    .set_body_string(format!(r#"{{"error":{{"message":"{PLANTED}"}}}}"#)),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(chat_ok_body()))
            .mount(&server)
            .await;
        let state = test_state(registry_pointing_ollama_at(server.uri()));
        let trace_id = uuid::Uuid::new_v4();

        let resp = chat_completions_handler(
            State(state.clone()),
            authed_with_trace(trace_id),
            Json(json!({
                "model": "ollama/llama3",
                "messages": [{"role": "user", "content": "rate limit me then succeed"}]
            })),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK, "{:?}", body_json(resp).await);
        assert_eq!(
            server
                .received_requests()
                .await
                .expect("mock recorded requests")
                .len(),
            2,
            "exactly one retry: the 429 attempt and the 200 attempt"
        );

        let spans = crate::otlp_emit::test_sink::for_trace(trace_id);
        assert_eq!(spans.len(), 1, "one request, one span");
        let attempts = spans[0]
            .attributes
            .tracelane_dispatch_attempts
            .as_ref()
            .expect("a retried request must carry the dispatch ledger");
        assert_eq!(attempts.len(), 2, "one element per attempt made");
        assert_eq!(attempts[0].status, Some(429));
        assert!(
            attempts[0]
                .reason
                .as_deref()
                .is_some_and(|r| r == "provider_rate_limited"
                    || r.bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')),
            "reason must be the five-class label or an `[A-Z0-9_]` upstream token, got {:?}",
            attempts[0].reason
        );
        assert_eq!(attempts[1].outcome, "ok");
        assert_eq!(attempts[1].status, None);

        // THE PROOF: the planted credential-shaped body text must not reach
        // the span by ANY path — serialize the whole span, not just the
        // ledger field, so a leak into some OTHER attribute would also fail.
        let span_json = serde_json::to_string(&spans[0]).expect("span serializes");
        assert!(
            !span_json.contains(PLANTED),
            "the upstream error body leaked into the span: {span_json}"
        );
    }

    /// RI-05 slice 2 (M1) — the other half of the write rule: a clean single
    /// attempt (no retry, no failover) leaves the ledger field ABSENT, not an
    /// empty array. This is what lets a read path tell "verified clean" apart
    /// from "built before RI-05 existed".
    #[tokio::test]
    async fn a_clean_single_attempt_leaves_the_dispatch_ledger_absent() {
        let _bypass = LoopbackBypassGuard::new();
        let server = chat_ok_mock().await;
        let state = test_state(registry_pointing_ollama_at(server.uri()));
        let trace_id = uuid::Uuid::new_v4();

        let resp = chat_completions_handler(
            State(state.clone()),
            authed_with_trace(trace_id),
            Json(json!({
                "model": "ollama/llama3",
                "messages": [{"role": "user", "content": "just answer"}]
            })),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK, "{:?}", body_json(resp).await);
        let spans = crate::otlp_emit::test_sink::for_trace(trace_id);
        assert_eq!(spans.len(), 1);
        assert!(
            spans[0].attributes.tracelane_dispatch_attempts.is_none(),
            "a clean single attempt must leave the field ABSENT, not Some(vec![one ok])"
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
    #[tokio::test]
    async fn kya_chat_and_embeddings_record_bounded_names_and_classified_clients() {
        let _bypass = LoopbackBypassGuard::new();
        let server = chat_ok_mock().await;
        Mock::given(method("POST"))
            .and(path("/v1/embeddings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "object":"list", "model":"ollama/nomic-embed-text",
                "data":[{"object":"embedding","index":0,"embedding":[0.1,0.2]}],
                "usage":{"prompt_tokens":2,"total_tokens":2}
            })))
            .mount(&server)
            .await;
        for embeddings in [false, true] {
            let trace = uuid::Uuid::new_v4();
            let state = test_state(registry_pointing_ollama_at(server.uri()));
            let mut headers = authed_with_trace(trace);
            headers.insert("x-tracelane-agent-name", "KYA-Proof".parse().unwrap());
            headers.insert(
                "user-agent",
                "codex_exec/0.155.1 private-machine-metadata"
                    .parse()
                    .unwrap(),
            );
            let response = if embeddings {
                embeddings_handler(
                    State(state),
                    headers,
                    Json(json!({"model":"ollama/nomic-embed-text","input":"hello"})),
                )
                .await
            } else {
                chat_completions_handler(State(state),headers,Json(json!({"model":"ollama/llama3","messages":[{"role":"user","content":"hello"}]}))).await
            };
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "{:?}",
                body_json(response).await
            );
            let spans = crate::otlp_emit::test_sink::for_trace(trace);
            assert_eq!(spans.len(), 1);
            assert_eq!(
                spans[0].attributes.gen_ai_agent_name.as_deref(),
                Some("kya-proof")
            );
            assert_eq!(
                spans[0].attributes.tracelane_client_name.as_deref(),
                Some("codex")
            );
            assert_eq!(
                spans[0].attributes.tracelane_agent_name_source.as_deref(),
                Some("header")
            );
            let wire = serde_json::to_string(&spans[0]).unwrap();
            assert!(!wire.contains("private-machine-metadata"));
            assert!(!wire.contains("codex_exec/"));
        }
    }

    // ── GWY-27 — per-workspace model aliases, spec §7 rows 1–2 ──────────────────
    //
    // Drive the REAL handlers with an entitlement cache whose resolved set carries the
    // workspace's aliases — the only way the hot path ever sees them.

    fn entitlements_with_aliases(
        pairs: &[(&str, &str)],
    ) -> Arc<crate::entitlement_cache::EntitlementCache> {
        let aliases: std::collections::BTreeMap<String, String> = pairs
            .iter()
            .map(|(a, t)| ((*a).to_string(), (*t).to_string()))
            .collect();
        let aliases = Arc::new(aliases);
        Arc::new(crate::entitlement_cache::EntitlementCache::new(Arc::new(
            move |_tenant: uuid::Uuid| {
                let aliases = Arc::clone(&aliases);
                Box::pin(async move {
                    Ok(crate::entitlement_cache::ResolvedEntitlements {
                        model_aliases: aliases,
                        ..crate::entitlement_cache::ResolvedEntitlements::deny_all()
                    })
                })
                    as std::pin::Pin<
                        Box<
                            dyn std::future::Future<
                                    Output = anyhow::Result<
                                        crate::entitlement_cache::ResolvedEntitlements,
                                    >,
                                > + Send,
                        >,
                    >
            },
        )))
    }

    async fn last_upstream_model(server: &MockServer) -> serde_json::Value {
        let received = server.received_requests().await.expect("recorded");
        let sent: serde_json::Value =
            serde_json::from_slice(&received.last().expect("one request").body)
                .expect("upstream body is JSON");
        sent["model"].clone()
    }

    /// Row 1: `model: "fast"` reaches the provider as the TARGET (byte-identical to a
    /// direct call for it), and the span records the caller's alias with the
    /// substitution named — so a trace shows both names and why they differ.
    /// An upstream that answers the way the OpenAI-compatible adapter actually talks
    /// to providers — SSE (it always streams upstream, `providers/openai.rs`) — with
    /// the `model` claim in the frame. A plain JSON body carries no frame, so the
    /// span's served model (and therefore any substitution) would be unobservable.
    async fn chat_sse_mock(served_model: &str) -> MockServer {
        let server = MockServer::start().await;
        let frame = json!({
            "id": "chatcmpl-harness", "object": "chat.completion.chunk", "model": served_model,
            "choices": [{"index": 0, "delta": {"content": "ok"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        });
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(format!("data: {frame}\n\ndata: [DONE]\n\n")),
            )
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn gwy27_a_tenant_alias_routes_to_its_target_and_the_span_says_so() {
        let _bypass = LoopbackBypassGuard::new();
        let server = chat_sse_mock("llama3").await;
        let mut state = test_state(registry_pointing_ollama_at(server.uri()));
        state.entitlements = Some(entitlements_with_aliases(&[("fast", "ollama/llama3")]));

        // The control: what a direct call for the target sends upstream.
        let direct = chat_completions_handler(
            State(state.clone()),
            authed(),
            Json(
                json!({"model": "ollama/llama3", "messages": [{"role": "user", "content": "hi"}]}),
            ),
        )
        .await;
        assert_eq!(direct.status(), StatusCode::OK);
        let want = last_upstream_model(&server).await;

        let trace_id = uuid::Uuid::new_v4();
        let resp = chat_completions_handler(
            State(state.clone()),
            authed_with_trace(trace_id),
            Json(json!({"model": "fast", "messages": [{"role": "user", "content": "hi"}]})),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a workspace alias must make its name routable"
        );
        let got = last_upstream_model(&server).await;
        assert_eq!(
            got, want,
            "the provider must be asked for the TARGET, exactly as a direct call"
        );
        assert_ne!(
            got,
            json!("fast"),
            "the alias itself must never leave the gateway"
        );

        let spans = crate::otlp_emit::test_sink::for_trace(trace_id);
        let span = spans.first().expect("the aliased request emits a span");
        assert_eq!(
            span.attributes.gen_ai_request_model.as_deref(),
            Some("fast"),
            "the span records what the CALLER sent"
        );
        assert_eq!(
            span.attributes.gen_ai_response_model.as_deref(),
            Some("llama3"),
            "the provider's own claim — the resolved model, observed"
        );
        assert_eq!(
            span.attributes.tracelane_model_substitution.as_deref(),
            Some("alias"),
            "and names why the served model differs"
        );
    }

    /// Row 2: an alias whose target no longer routes fails CLOSED — `400
    /// unroutable_model`, zero bytes to any provider, no default target.
    #[tokio::test]
    async fn gwy27_an_alias_to_an_unroutable_target_fails_closed() {
        let _bypass = LoopbackBypassGuard::new();
        let server = chat_ok_mock().await;
        let mut state = test_state(registry_pointing_ollama_at(server.uri()));
        state.entitlements = Some(entitlements_with_aliases(&[(
            "fast",
            "no-such-provider-model-xyz",
        )]));
        let resp = chat_completions_handler(
            State(state),
            authed(),
            Json(json!({"model": "fast", "messages": [{"role": "user", "content": "hi"}]})),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(resp).await["error"], "unroutable_model");
        assert_eq!(server.received_requests().await.expect("recorded").len(), 0);
    }

    /// The embeddings route honours the same alias map (spec §2).
    #[tokio::test]
    async fn gwy27_embeddings_resolve_a_tenant_alias() {
        let _bypass = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/embeddings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "object": "list",
                "data": [{ "object": "embedding", "index": 0, "embedding": [0.1, 0.2] }],
                "model": "nomic-embed-text",
                "usage": { "prompt_tokens": 1, "total_tokens": 1 }
            })))
            .mount(&server)
            .await;
        let mut state = test_state(registry_pointing_ollama_at(server.uri()));
        state.entitlements = Some(entitlements_with_aliases(&[(
            "embed",
            "ollama/nomic-embed-text",
        )]));
        let direct = embeddings_handler(
            State(state.clone()),
            authed(),
            Json(json!({"model": "ollama/nomic-embed-text", "input": "x"})),
        )
        .await;
        assert_eq!(direct.status(), StatusCode::OK);
        let want = last_upstream_model(&server).await;
        let resp = embeddings_handler(
            State(state),
            authed(),
            Json(json!({"model": "embed", "input": "x"})),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(last_upstream_model(&server).await, want);
    }

    // ── GWY-52 — workspace failover, spec §7 rows 1–3 ───────────────────────────

    fn entitlements_with_failover(
        enabled: bool,
        models: &[&str],
    ) -> Arc<crate::entitlement_cache::EntitlementCache> {
        let models: Arc<Vec<String>> = Arc::new(models.iter().map(|m| (*m).to_string()).collect());
        Arc::new(crate::entitlement_cache::EntitlementCache::new(Arc::new(
            move |_tenant: uuid::Uuid| {
                let models = Arc::clone(&models);
                Box::pin(async move {
                    Ok(crate::entitlement_cache::ResolvedEntitlements {
                        failover_enabled: enabled,
                        failover_models: models,
                        ..crate::entitlement_cache::ResolvedEntitlements::deny_all()
                    })
                })
                    as std::pin::Pin<
                        Box<
                            dyn std::future::Future<
                                    Output = anyhow::Result<
                                        crate::entitlement_cache::ResolvedEntitlements,
                                    >,
                                > + Send,
                        >,
                    >
            },
        )))
    }

    /// Primary `groq/…` answers 500; the workspace's chain names ONLY
    /// `nebius/…` — absent from the operator chain, so a hop there proves the
    /// workspace chain was used.
    async fn failing_openai_and_ok_ollama() -> (MockServer, MockServer, AppState) {
        let bad = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(500).set_body_string("upstream down"))
            .mount(&bad)
            .await;
        let good = chat_ok_mock().await;
        let mut reg = ProviderRegistry::new().expect("provider registry");
        reg.set_compat_base_url_for_test("nebius", good.uri())
            .expect("nebius adapter for the serving mock");
        reg.set_compat_base_url_for_test("groq", bad.uri())
            .expect("groq adapter for the failing mock");
        // The primary must actually DISPATCH (a missing key is refused before any hop,
        // which is not a provider error), and a hop needs the tenant's own key too (the
        // loop skips a keyless candidate as `no_byok_key`, by design). Seed the decrypted
        // key cache — the first thing `resolve_provider_key` reads — for two providers
        // no other handler test uses, so no test sees them through the shared dev tenant.
        for provider in ["groq", "nebius"] {
            crate::db::provider_keys::cache_decrypted(
                &dev_tenant(),
                provider,
                Arc::new(secrecy::SecretString::from(format!(
                    "unit-test-{provider}-key-not-real"
                ))),
            );
        }
        (bad, good, test_state(reg))
    }

    fn gpt4o() -> Json<serde_json::Value> {
        Json(
            json!({"model": "llama-3.3-70b-versatile", "messages": [{"role": "user", "content": "hi"}]}),
        )
    }

    /// Row 1: workspace ON + its own chain, NO header → the fallback serves; the span
    /// names the primary it left.
    #[tokio::test]
    async fn gwy52_workspace_failover_serves_from_its_own_chain_without_a_header() {
        let _bypass = LoopbackBypassGuard::new();
        let (_bad, good, mut state) = failing_openai_and_ok_ollama().await;
        state.entitlements = Some(entitlements_with_failover(
            true,
            &["nebius/meta-llama-3.1-8b"],
        ));
        let trace_id = uuid::Uuid::new_v4();
        let resp =
            chat_completions_handler(State(state), authed_with_trace(trace_id), gpt4o()).await;
        let status = resp.status();
        assert_eq!(status, StatusCode::OK, "{:?}", body_json(resp).await);
        assert_eq!(good.received_requests().await.expect("recorded").len(), 1);
        let spans = crate::otlp_emit::test_sink::for_trace(trace_id);
        assert_eq!(
            spans
                .first()
                .and_then(|s| s.attributes.tracelane_failover_from.as_deref()),
            Some("groq")
        );
    }

    /// Row 2: a per-request `off` beats the workspace default — no hop.
    #[tokio::test]
    async fn gwy52_header_off_beats_the_workspace_default() {
        let _bypass = LoopbackBypassGuard::new();
        let (bad, good, mut state) = failing_openai_and_ok_ollama().await;
        state.entitlements = Some(entitlements_with_failover(
            true,
            &["nebius/meta-llama-3.1-8b"],
        ));
        let mut headers = authed();
        headers.insert(
            "x-tracelane-failover",
            axum::http::HeaderValue::from_static("off"),
        );
        let resp = chat_completions_handler(State(state), headers, gpt4o()).await;
        assert_ne!(resp.status(), StatusCode::OK);
        assert!(
            !bad.received_requests().await.expect("recorded").is_empty(),
            "the primary must have been TRIED — otherwise 'no hop' proves nothing"
        );
        assert_eq!(good.received_requests().await.expect("recorded").len(), 0);
    }

    /// Control: the workspace default OFF (today's behaviour) — no header, no hop, even
    /// with a chain stored.
    #[tokio::test]
    async fn gwy52_workspace_off_keeps_failover_opt_in() {
        let _bypass = LoopbackBypassGuard::new();
        let (bad, good, mut state) = failing_openai_and_ok_ollama().await;
        state.entitlements = Some(entitlements_with_failover(
            false,
            &["nebius/meta-llama-3.1-8b"],
        ));
        let resp = chat_completions_handler(State(state), authed(), gpt4o()).await;
        assert_ne!(resp.status(), StatusCode::OK);
        assert!(
            !bad.received_requests().await.expect("recorded").is_empty(),
            "the primary must have been TRIED — otherwise 'no hop' proves nothing"
        );
        assert_eq!(good.received_requests().await.expect("recorded").len(), 0);
    }

    /// Row 3, with the header: the WORKSPACE chain replaces the operator chain.
    #[tokio::test]
    async fn gwy52_the_workspace_chain_replaces_the_operator_chain() {
        let _bypass = LoopbackBypassGuard::new();
        let (_bad, good, mut state) = failing_openai_and_ok_ollama().await;
        state.entitlements = Some(entitlements_with_failover(
            false,
            &["nebius/meta-llama-3.1-8b"],
        ));
        let mut headers = authed();
        headers.insert(
            "x-tracelane-failover",
            axum::http::HeaderValue::from_static("cross-provider"),
        );
        let resp = chat_completions_handler(State(state), headers, gpt4o()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(good.received_requests().await.expect("recorded").len(), 1);
    }

    // ── GWY-53 — self-serve content capture, spec §7 rows 1–3 and 5 ─────────────
    //
    // Every test drives the REAL chat handler against a wiremock upstream and reads the
    // span the gateway emitted (`otlp_emit::test_sink`), never a builder in isolation.
    // No `trace_content:` block is installed in this test binary, so ONLY the workspace
    // half can turn capture on here — which is exactly the half GWY-53 adds.

    const GWY53_PROMPT: &str = "gwy53: what did my app send?";
    const GWY53_ANSWER: &str = "gwy53: the model's own answer";

    /// A cache whose every tenant resolves with this capture choice; `r2` also grants
    /// the R2 secrets rail (paid), for the redaction proof.
    fn entitlements_with_capture(
        input: bool,
        output: bool,
        r2: bool,
    ) -> Arc<crate::entitlement_cache::EntitlementCache> {
        Arc::new(crate::entitlement_cache::EntitlementCache::new(Arc::new(
            move |_tenant| {
                Box::pin(async move {
                    Ok(crate::entitlement_cache::ResolvedEntitlements {
                        content_capture: crate::db::workspace_capture::WorkspaceCapture {
                            input,
                            output,
                        },
                        f_guardrail_r2: r2,
                        ..crate::entitlement_cache::ResolvedEntitlements::deny_all()
                    })
                })
                    as std::pin::Pin<
                        Box<
                            dyn std::future::Future<
                                    Output = anyhow::Result<
                                        crate::entitlement_cache::ResolvedEntitlements,
                                    >,
                                > + Send,
                        >,
                    >
            },
        )))
    }

    /// The upstream answers in SSE whatever the CALLER asked for: the OpenAI-compatible
    /// adapter always requests a stream upstream (`providers/openai.rs`,
    /// `build_openai_stream`) and the buffered path assembles it. A JSON body here
    /// would parse as an EMPTY answer — which is how the first draft of these tests
    /// "failed" for the wrong reason.
    async fn chat_answering(content: &str) -> MockServer {
        let server = MockServer::start().await;
        // Content and usage in SEPARATE frames, as OpenAI sends them: a frame carrying
        // `usage` is read as the usage chunk (`providers/openai.rs`), so a combined
        // frame would deliver an empty answer.
        let content_frame = json!({
            "id": "chatcmpl-gwy53", "object": "chat.completion.chunk", "model": "llama3",
            "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": null}]
        });
        let final_frame = json!({
            "id": "chatcmpl-gwy53", "object": "chat.completion.chunk", "model": "llama3",
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 5, "total_tokens": 8}
        });
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(format!(
                        "data: {content_frame}\n\ndata: {final_frame}\n\ndata: [DONE]\n\n"
                    )),
            )
            .mount(&server)
            .await;
        server
    }

    /// Drive one chat call and return the span it emitted (the SSE body is drained
    /// first, so the finalizer has run).
    async fn gwy53_span(state: AppState, stream: bool) -> tracelane_shared::TracelaneSpan {
        let trace_id = uuid::Uuid::new_v4();
        let resp = chat_completions_handler(
            State(state),
            authed_with_trace(trace_id),
            Json(json!({
                "model": "ollama/llama3",
                "stream": stream,
                "messages": [{"role": "user", "content": GWY53_PROMPT}]
            })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("drain body");
        let mut spans = Vec::new();
        for _ in 0..50 {
            spans = crate::otlp_emit::test_sink::for_trace(trace_id);
            if !spans.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        spans
            .into_iter()
            .next()
            .expect("the request emitted a span")
    }

    fn text_of(v: Option<&serde_json::Value>) -> String {
        v.map(serde_json::Value::to_string).unwrap_or_default()
    }

    /// Row 1 — the default: a workspace that did not opt in stores no text, and a
    /// deployment with no control plane stores none either (tenancy rule).
    #[tokio::test]
    async fn gwy53_capture_off_leaves_no_text_on_the_span() {
        let _bypass = LoopbackBypassGuard::new();
        let server = chat_answering(GWY53_ANSWER).await;
        let mut state = test_state(registry_pointing_ollama_at(server.uri()));
        state.entitlements = Some(entitlements_with_capture(false, false, false));
        let span = gwy53_span(state, false).await;
        assert!(span.attributes.gen_ai_input_messages.is_none());
        assert!(span.attributes.gen_ai_output_messages.is_none());

        let no_control_plane = test_state(registry_pointing_ollama_at(server.uri()));
        assert!(no_control_plane.entitlements.is_none());
        let span = gwy53_span(no_control_plane, false).await;
        assert!(
            span.attributes.gen_ai_input_messages.is_none()
                && span.attributes.gen_ai_output_messages.is_none(),
            "no control plane = the unprivileged state = no capture"
        );
    }

    /// Row 2 — opted in: the span carries the request messages AND the response text,
    /// on the buffered path and the streamed one.
    #[tokio::test]
    async fn gwy53_capture_on_records_request_and_response_buffered_and_streamed() {
        let _bypass = LoopbackBypassGuard::new();
        for stream in [false, true] {
            let server = chat_answering(GWY53_ANSWER).await;
            let mut state = test_state(registry_pointing_ollama_at(server.uri()));
            state.entitlements = Some(entitlements_with_capture(true, true, false));
            let span = gwy53_span(state, stream).await;
            let input = text_of(span.attributes.gen_ai_input_messages.as_ref());
            let output = text_of(span.attributes.gen_ai_output_messages.as_ref());
            assert!(
                input.contains(GWY53_PROMPT),
                "stream={stream}: the request text must be on the span, got {input:?}"
            );
            assert!(
                output.contains(GWY53_ANSWER),
                "stream={stream}: the response text must be on the span, got {output:?}"
            );
        }
    }

    /// Each half is independent: input-only records no answer.
    #[tokio::test]
    async fn gwy53_input_only_records_no_response() {
        let _bypass = LoopbackBypassGuard::new();
        let server = chat_answering(GWY53_ANSWER).await;
        let mut state = test_state(registry_pointing_ollama_at(server.uri()));
        state.entitlements = Some(entitlements_with_capture(true, false, false));
        let span = gwy53_span(state, false).await;
        assert!(text_of(span.attributes.gen_ai_input_messages.as_ref()).contains(GWY53_PROMPT));
        assert!(span.attributes.gen_ai_output_messages.is_none());
    }

    /// Row 3 — a secret is NEVER what the span stores: under R2 because the caller
    /// received the redacted text, and without R2 because the stored copy is redacted on
    /// every plan (security review 2026-09-28, H-2).
    #[tokio::test]
    async fn gwy53_a_guardrail_redacted_value_is_never_persisted() {
        const SECRET: &str = "AKIAIOSFODNN7EXAMPLE";
        let _bypass = LoopbackBypassGuard::new();
        for stream in [false, true] {
            let answer = format!("here is a fresh key {SECRET} keep it safe");
            for r2 in [false, true] {
                let server = chat_answering(&answer).await;
                let mut state = test_state(registry_pointing_ollama_at(server.uri()));
                let cache = entitlements_with_capture(true, true, r2);
                state.guardrail = Arc::new(crate::guardrail::GuardrailEngine::new(
                    Arc::clone(&state.audit_chain),
                    None,
                    Some(Arc::clone(&cache)),
                    Arc::new(crate::guardrail::capability::CapabilityRegistry::new()),
                ));
                state.entitlements = Some(cache);
                let span = gwy53_span(state, stream).await;
                let output = text_of(span.attributes.gen_ai_output_messages.as_ref());
                // Security review 2026-09-28 (H-2): the STORED copy is redacted on every
                // plan, so the pre-fix control ("without R2 the raw value is stored") is now
                // the defect this asserts against. The leak-visibility this test used the
                // control for is held by `server::spans::tests::gwy53_stored_*`, which were
                // red on the pre-fix code.
                assert!(
                    !output.contains(SECRET),
                    "stream={stream} r2={r2}: a secret reached the span: {output:?}"
                );
                assert!(
                    output.contains("[REDACTED:aws_key]"),
                    "stream={stream} r2={r2}: the stored copy carries the redaction marker: {output:?}"
                );
            }
        }
    }
}

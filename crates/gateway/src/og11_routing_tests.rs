//! `OG-11` — the routing document through the REAL handlers (`specs/OG-11` §7).
//!
//! Wiremock upstreams stand in for two catalog providers no other handler test uses
//! (`ai21`, `cerebras`), and the decrypted-key cache is seeded per `(tenant, provider,
//! label)` — the first thing key resolution reads — so pool keys resolve without a
//! control plane. Every assertion reads the RECORDED span or the upstream's received
//! requests, never only a status code.

use std::sync::Arc;

use axum::extract::{Json, State};
use axum::http::StatusCode;
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::handler_harness::{
    LoopbackBypassGuard, authed_with_trace, body_json, chat_ok_body, dev_tenant, test_state,
};
use crate::providers::ProviderRegistry;
use crate::routing::{RoutingDoc, RoutingState};
use crate::server::chat_completions_handler;

pub(crate) fn entitlements_with(
    routing: RoutingState,
    controls: crate::controls::WorkspaceControls,
) -> Arc<crate::entitlement_cache::EntitlementCache> {
    let routing = Arc::new(routing);
    let controls = Arc::new(controls);
    Arc::new(crate::entitlement_cache::EntitlementCache::new(Arc::new(
        move |_tenant: uuid::Uuid| {
            let routing = Arc::clone(&routing);
            let controls = Arc::clone(&controls);
            Box::pin(async move {
                Ok(crate::entitlement_cache::ResolvedEntitlements {
                    routing,
                    controls,
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

pub(crate) fn doc(v: serde_json::Value) -> RoutingState {
    RoutingState::Valid(Arc::new(
        serde_json::from_value::<RoutingDoc>(v).expect("test doc"),
    ))
}

fn key(provider: &'static str, label: &str, secret: &str) {
    crate::db::provider_keys::cache_decrypted_labeled(
        &dev_tenant(),
        provider,
        label,
        Arc::new(secrecy::SecretString::from(secret.to_owned())),
    );
}

/// `ai21` answers 503; `cerebras` answers 429 to key `team-a` and 200 to `team-b`.
async fn upstreams() -> (MockServer, MockServer, ProviderRegistry) {
    let ai21 = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(503).set_body_string("down"))
        .mount(&ai21)
        .await;
    let cerebras = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("authorization", "Bearer og11-test-cerebras-team-a"))
        .respond_with(ResponseTemplate::new(429).set_body_string("slow down"))
        .mount(&cerebras)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("authorization", "Bearer og11-test-cerebras-team-b"))
        .respond_with(ResponseTemplate::new(200).set_body_json(chat_ok_body()))
        .mount(&cerebras)
        .await;
    let mut reg = ProviderRegistry::new().expect("registry");
    reg.set_compat_base_url_for_test("ai21", ai21.uri())
        .expect("ai21 adapter");
    reg.set_compat_base_url_for_test("cerebras", cerebras.uri())
        .expect("cerebras adapter");
    key("ai21", "default", "og11-test-ai21-default");
    key("cerebras", "team-a", "og11-test-cerebras-team-a");
    key("cerebras", "team-b", "og11-test-cerebras-team-b");
    (ai21, cerebras, reg)
}

fn routing_doc() -> RoutingState {
    doc(json!({
        "virtual_models": {"og11-fast": {"strategy": "priority", "targets": [
            {"model": "jamba-1.5-mini"}, {"model": "cerebras/llama3.1-8b"}
        ]}},
        "key_pools": [{"provider": "cerebras", "keys": [{"label": "team-a"}, {"label": "team-b"}]}]
    }))
}

fn ask(model: &str) -> Json<serde_json::Value> {
    Json(json!({"model": model, "messages": [{"role": "user", "content": "hi"}]}))
}

/// Proofs 2 + 3: the primary target answers 503 → the second target serves; on the
/// second, pool key `team-a` answers 429 → key `team-b` serves IN THE SAME REQUEST.
/// Every attempt and its key label is on the recorded span, and the span says the
/// virtual model, the strategy, the target and the key that served.
#[tokio::test]
async fn og11_priority_fallthrough_and_pool_key_failover_land_in_the_ledger() {
    let _bypass = LoopbackBypassGuard::new();
    let (ai21, cerebras, reg) = upstreams().await;
    let mut state = test_state(reg);
    state.entitlements = Some(entitlements_with(routing_doc(), Default::default()));
    let trace_id = uuid::Uuid::new_v4();
    let resp =
        chat_completions_handler(State(state), authed_with_trace(trace_id), ask("og11-fast")).await;
    let status = resp.status();
    assert_eq!(status, StatusCode::OK, "{:?}", body_json(resp).await);
    assert!(
        !ai21.received_requests().await.unwrap().is_empty(),
        "primary tried"
    );
    // team-a answers 429 (OG-10 may retry it once inside ONE attempt), then team-b 200.
    let by_key = |k: &str| {
        let k = k.to_owned();
        move |r: &wiremock::Request| {
            r.headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.ends_with(&k))
        }
    };
    let got = cerebras.received_requests().await.unwrap();
    assert!(got.iter().any(by_key("team-a")), "team-a tried first");
    assert_eq!(
        got.iter().filter(|r| by_key("team-b")(r)).count(),
        1,
        "then team-b once"
    );
    let spans = crate::otlp_emit::test_sink::for_trace(trace_id);
    let a = &spans.first().expect("one span").attributes;
    let ledger = a.tracelane_dispatch_attempts.clone().expect("a ledger");
    let shape: Vec<(String, String, Option<u16>, Option<String>)> = ledger
        .iter()
        .map(|d| {
            (
                d.provider.clone(),
                d.outcome.clone(),
                d.status,
                d.key_label.clone(),
            )
        })
        .collect();
    assert!(
        shape
            .iter()
            .any(|(p, o, s, _)| p == "ai21" && o == "error" && *s == Some(503)),
        "{shape:?}"
    );
    assert!(
        shape.iter().any(|(p, o, s, l)| p == "cerebras"
            && o == "error"
            && *s == Some(429)
            && l.as_deref() == Some("team-a")),
        "{shape:?}"
    );
    assert!(
        shape
            .iter()
            .any(|(p, o, _, l)| p == "cerebras" && o == "ok" && l.as_deref() == Some("team-b")),
        "{shape:?}"
    );
    assert_eq!(
        a.extra.get("tracelane_route_virtual_model"),
        Some(&json!("og11-fast"))
    );
    assert_eq!(
        a.extra.get("tracelane_route_strategy"),
        Some(&json!("priority"))
    );
    assert_eq!(a.extra.get("tracelane_route_target_index"), Some(&json!(1)));
    assert_eq!(a.extra.get("tracelane_key_label"), Some(&json!("team-b")));
}

/// Proof 5: a workspace block on ANY target refuses the virtual name — even though the
/// first target is allowed — and nothing is dispatched (no prune-around).
#[tokio::test]
async fn og11_a_block_on_any_target_refuses_the_virtual_model_and_sends_nothing() {
    let _bypass = LoopbackBypassGuard::new();
    let (ai21, cerebras, reg) = upstreams().await;
    let mut state = test_state(reg);
    let controls = crate::controls::WorkspaceControls {
        blocked_models: vec!["cerebras/*".to_owned()],
        ..Default::default()
    };
    state.entitlements = Some(entitlements_with(routing_doc(), controls));
    let resp = chat_completions_handler(
        State(state),
        authed_with_trace(uuid::Uuid::new_v4()),
        ask("og11-fast"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp).await;
    assert!(body.to_string().contains("model_blocked"), "{body}");
    assert!(ai21.received_requests().await.unwrap().is_empty());
    assert!(cerebras.received_requests().await.unwrap().is_empty());
}

/// A stored document this gateway cannot parse refuses routed requests (fail-CLOSED).
#[tokio::test]
async fn og11_blocked_virtual_name_is_not_erased_by_expansion() {
    let _bypass = LoopbackBypassGuard::new();
    let (ai21, cerebras, reg) = upstreams().await;
    let mut state = test_state(reg);
    let controls = crate::controls::WorkspaceControls {
        blocked_models: vec!["og11-fast".to_owned()],
        ..Default::default()
    };
    state.entitlements = Some(entitlements_with(routing_doc(), controls));
    let resp = chat_completions_handler(
        State(state),
        authed_with_trace(uuid::Uuid::new_v4()),
        ask("og11-fast"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a virtual name remains a policy subject"
    );
    assert!(ai21.received_requests().await.unwrap().is_empty());
    assert!(cerebras.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn og11_an_unparseable_document_refuses_with_503_routing_invalid() {
    let _bypass = LoopbackBypassGuard::new();
    let (ai21, _c, reg) = upstreams().await;
    let mut state = test_state(reg);
    state.entitlements = Some(entitlements_with(RoutingState::Invalid, Default::default()));
    let resp = chat_completions_handler(
        State(state),
        authed_with_trace(uuid::Uuid::new_v4()),
        ask("jamba-1.5-mini"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        body_json(resp)
            .await
            .to_string()
            .contains("routing_invalid")
    );
    assert!(ai21.received_requests().await.unwrap().is_empty());
}

/// Proof 5 (ZDR half): under `x-tracelane-zdr: required` an ineligible target is pruned;
/// with none eligible (the test state's empty capability table) the request is refused
/// `zdr_unsatisfiable` and nothing is sent.
#[tokio::test]
async fn og11_zdr_required_prunes_every_ineligible_target() {
    let _bypass = LoopbackBypassGuard::new();
    let (ai21, cerebras, reg) = upstreams().await;
    let mut state = test_state(reg);
    state.entitlements = Some(entitlements_with(routing_doc(), Default::default()));
    let mut headers = authed_with_trace(uuid::Uuid::new_v4());
    headers.insert("x-tracelane-zdr", "required".parse().unwrap());
    let resp = chat_completions_handler(State(state), headers, ask("og11-fast")).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        body_json(resp)
            .await
            .to_string()
            .contains("zdr_unsatisfiable")
    );
    assert!(ai21.received_requests().await.unwrap().is_empty());
    assert!(cerebras.received_requests().await.unwrap().is_empty());
}

/// Proof 4: `/v1/messages` with a virtual model whose targets are not all Anthropic is
/// refused `virtual_model_unroutable_on_wire` before anything is charged or sent.
#[tokio::test]
async fn og11_messages_refuses_a_virtual_model_with_a_foreign_target() {
    let _bypass = LoopbackBypassGuard::new();
    let (_a, _c, reg) = upstreams().await;
    let mut state = test_state(reg);
    state.entitlements = Some(entitlements_with(routing_doc(), Default::default()));
    let resp = crate::anthropic_messages::messages_handler(
        State(state),
        authed_with_trace(uuid::Uuid::new_v4()),
        axum::body::Bytes::from(
            json!({"model": "og11-fast", "max_tokens": 16,
                   "messages": [{"role": "user", "content": "hi"}]})
            .to_string(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        body_json(resp)
            .await
            .to_string()
            .contains("virtual_model_unroutable_on_wire")
    );
}

/// No document: a plain request is untouched — no route attributes, no key label.
#[tokio::test]
async fn og11_no_document_changes_nothing() {
    let _bypass = LoopbackBypassGuard::new();
    let (_a, cerebras, reg) = upstreams().await;
    key("cerebras", "default", "og11-test-cerebras-team-b");
    let state = test_state(reg);
    let trace_id = uuid::Uuid::new_v4();
    let resp = chat_completions_handler(
        State(state),
        authed_with_trace(trace_id),
        ask("cerebras/llama3.1-8b"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(cerebras.received_requests().await.unwrap().len(), 1);
    let spans = crate::otlp_emit::test_sink::for_trace(trace_id);
    let a = &spans[0].attributes;
    assert!(!a.extra.contains_key("tracelane_route_virtual_model"));
    assert!(!a.extra.contains_key("tracelane_key_label"));
}

/// The upstream received exactly one request, but its delayed head exceeded the
/// workspace rule. This is not eligible for an identical retry.
#[tokio::test]
async fn og13_chat_headers_timeout_is_504_with_phase_ledger_and_no_retry() {
    let _bypass = LoopbackBypassGuard::new();
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(200))
                .set_body_json(chat_ok_body()),
        )
        .mount(&upstream)
        .await;
    let mut reg = ProviderRegistry::new().unwrap();
    reg.set_compat_base_url_for_test("ai21", upstream.uri())
        .unwrap();
    key("ai21", "default", "og11-test-ai21-default");
    let mut state = test_state(reg);
    state.entitlements = Some(entitlements_with(
        doc(json!({"timeouts":[{"match":{"provider":"ai21"},"headers_ms":20}]})),
        Default::default(),
    ));
    let trace = uuid::Uuid::new_v4();
    let resp = chat_completions_handler(
        State(state),
        authed_with_trace(trace),
        ask("jamba-1.5-mini"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
    let body = body_json(resp).await;
    assert_eq!(body["phase"], "headers");
    assert_eq!(body["limit_ms"], 20);
    assert_eq!(upstream.received_requests().await.unwrap().len(), 1);
    let spans = crate::otlp_emit::test_sink::for_trace(trace);
    let span = spans.first().expect("timeout span");
    assert_eq!(span.status.message.as_deref(), Some("upstream_timeout"));
    assert_eq!(
        span.attributes
            .tracelane_dispatch_attempts
            .as_ref()
            .unwrap()[0]
            .reason
            .as_deref(),
        Some("upstream_timeout:headers")
    );
}

#[tokio::test]
async fn og13_headers_deadline_on_native_embeddings_media_and_companions() {
    use crate::media_common::test_support::{as_claims, claims_for, install_byok, tenant, traced};
    use axum::{
        body::{Body, Bytes},
        extract::{Path, RawQuery},
    };
    let _bypass = LoopbackBypassGuard::new();
    let upstream = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(200))
                .set_body_json(json!({})),
        )
        .mount(&upstream)
        .await;
    let t = tenant();
    for provider in ["openai", "anthropic", "google"] {
        install_byok(&t, provider);
    }
    let _claims = as_claims(claims_for(&t));
    let mut reg = ProviderRegistry::new().unwrap();
    reg.set_compat_base_url_for_test("openai", upstream.uri())
        .unwrap();
    reg.anthropic = crate::providers::AnthropicProvider::for_base_url(upstream.uri()).unwrap();
    reg.google = crate::providers::GoogleProvider::for_base_url(upstream.uri()).unwrap();
    let mut state = test_state(reg);
    state.entitlements = Some(entitlements_with(
        doc(json!({"timeouts":[{"match":{},"headers_ms":20}]})),
        Default::default(),
    ));
    for wire in [
        "embeddings",
        "messages",
        "responses",
        "gemini",
        "media",
        "files",
        "batches",
        "count_tokens",
        "models",
        "upload",
        "passthrough",
    ] {
        let trace = uuid::Uuid::new_v4();
        let h = traced(trace);
        let st = State(state.clone());
        let resp = match wire {
            "embeddings" => crate::server::embeddings_handler(st, h, Json(json!({"model":"text-embedding-3-small","input":"hi"}))).await,
            "messages" => crate::anthropic_messages::messages_handler(st, h, Bytes::from(json!({"model":"claude-sonnet-4-5","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}).to_string())).await,
            "responses" => crate::openai_responses::responses_handler(st, h, Bytes::from(json!({"model":"gpt-4o-mini","input":"hi"}).to_string())).await,
            "gemini" => crate::gemini_native::model_action_handler(st, Path("gemini-2.5-flash:generateContent".to_owned()), RawQuery(None), h, Bytes::from(json!({"contents":[{"parts":[{"text":"hi"}]}]}).to_string())).await,
            "media" => crate::media_routes::audio_speech_handler(st, h, Body::from(json!({"model":"tts-1","input":"hi","voice":"alloy"}).to_string())).await,
            "files" => crate::files_batches::files_list_handler(st, RawQuery(None), h).await,
            "batches" => crate::files_batches::batches_list_handler(st, RawQuery(None), h).await,
            "count_tokens" => crate::anthropic_messages::count_tokens_handler(st, h, Bytes::from(json!({"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"hi"}]}).to_string())).await,
            "models" => crate::gemini_native::models_list_handler(st, RawQuery(None), h).await,
            "upload" => {
                let (ct, bytes) = crate::media_common::test_support::multipart(&[("purpose", None, b"fine-tune"), ("file", Some("data.jsonl"), b"{}\n")]);
                let mut h = h;
                h.insert("content-type", ct.parse().unwrap());
                crate::files_batches::files_upload_handler(st, h, Body::from(bytes)).await
            }
            "passthrough" => {
                let _scope = as_claims(crate::media_common::test_support::scoped_claims(&t, &[crate::auth::scope::Scope::Passthrough]));
                let mut request = axum::http::Request::builder().method("POST").uri("/v1/passthrough/openai/probe").body(Body::from("{}")).unwrap();
                *request.headers_mut() = h;
                crate::passthrough::passthrough_handler(st, request).await
            }
            _ => unreachable!(),
        };
        let status = resp.status();
        let body = body_json(resp).await;
        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "{wire}: {body}");
        assert_eq!(body["phase"], "headers", "{wire}: {body}");
        if ["embeddings", "messages", "responses", "gemini", "media"].contains(&wire) {
            let spans = crate::otlp_emit::test_sink::for_trace(trace);
            let span = spans.first().unwrap_or_else(|| panic!("{wire}: no span"));
            assert_eq!(
                span.status.message.as_deref(),
                Some("upstream_timeout"),
                "{wire}"
            );
            assert_eq!(
                span.attributes
                    .tracelane_dispatch_attempts
                    .as_ref()
                    .unwrap_or_else(|| panic!("{wire}: no ledger"))[0]
                    .reason
                    .as_deref(),
                Some("upstream_timeout:headers"),
                "{wire}"
            );
        }
    }
    assert_eq!(upstream.received_requests().await.unwrap().len(), 11);
}

/// Real HTTP heads arrive immediately and each body stalls. The adapters must keep
/// the typed deadline through reqwest and their own parsing/stream wrappers.
#[tokio::test]
async fn og13_first_chunk_timeout_survives_the_native_and_translated_wires() {
    first_chunk_timeout_wires(false).await;
    first_chunk_timeout_wires(true).await;
}

async fn first_chunk_timeout_wires(streaming: bool) {
    use crate::media_common::test_support::{as_claims, claims_for, install_byok, tenant, traced};
    use axum::{
        body::{Body, Bytes},
        extract::{Path, RawQuery},
        response::IntoResponse,
    };
    let _bypass = LoopbackBypassGuard::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let app = axum::Router::new().fallback(|| async {
            let stream = async_stream::stream! {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                yield Ok::<_, std::convert::Infallible>(Bytes::from_static(b"{}"));
            };
            Body::from_stream(stream).into_response()
        });
        axum::serve(listener, app).await.unwrap();
    });
    let t = tenant();
    for provider in ["openai", "anthropic", "google"] {
        install_byok(&t, provider);
    }
    let _claims = as_claims(claims_for(&t));
    let mut reg = ProviderRegistry::new().unwrap();
    reg.set_compat_base_url_for_test("openai", base.clone())
        .unwrap();
    reg.anthropic = crate::providers::AnthropicProvider::for_base_url(&base).unwrap();
    reg.google = crate::providers::GoogleProvider::for_base_url(&base).unwrap();
    let mut state = test_state(reg);
    state.entitlements = Some(entitlements_with(
        doc(json!({"timeouts":[{"match":{},"first_chunk_ms":20}]})),
        Default::default(),
    ));
    for wire in [
        "chat",
        "embeddings",
        "messages",
        "responses",
        "gemini",
        "media",
    ] {
        if streaming && matches!(wire, "embeddings" | "media") {
            continue;
        }
        let trace = uuid::Uuid::new_v4();
        let st = State(state.clone());
        let h = traced(trace);
        let resp = match wire {
            "chat" => chat_completions_handler(st, h, Json(json!({"model":"gpt-4o-mini","stream":streaming,"messages":[{"role":"user","content":"hi"}]}))).await,
            "embeddings" => crate::server::embeddings_handler(st, h, Json(json!({"model":"text-embedding-3-small","input":"hi"}))).await,
            "messages" => crate::anthropic_messages::messages_handler(st, h, Bytes::from(json!({"model":"claude-sonnet-4-5","max_tokens":10,"stream":streaming,"messages":[{"role":"user","content":"hi"}]}).to_string())).await,
            "responses" => crate::openai_responses::responses_handler(st, h, Bytes::from(json!({"model":"gpt-4o-mini","stream":streaming,"input":"hi"}).to_string())).await,
            "gemini" => crate::gemini_native::model_action_handler(st, Path(format!("gemini-2.5-flash:{}", if streaming { "streamGenerateContent" } else { "generateContent" })), RawQuery(streaming.then(|| "alt=sse".to_owned())), h, Bytes::from(json!({"contents":[{"parts":[{"text":"hi"}]}]}).to_string())).await,
            "media" => crate::media_routes::audio_speech_handler(st, h, Body::from(json!({"model":"tts-1","input":"hi","voice":"alloy"}).to_string())).await,
            _ => unreachable!(),
        };
        if streaming {
            assert_eq!(resp.status(), StatusCode::OK, "{wire}: SSE head");
            let bytes = axum::body::to_bytes(resp.into_body(), 16384).await.unwrap();
            let sse = std::str::from_utf8(&bytes).unwrap();
            assert!(
                sse.contains("upstream_timeout") && sse.contains("first_chunk"),
                "{wire}: {sse}"
            );
            assert!(
                !sse.contains("response.completed"),
                "{wire}: no success after a deadline"
            );
        } else if wire == "media" {
            assert_eq!(resp.status(), StatusCode::OK, "speech streams its head");
            assert!(axum::body::to_bytes(resp.into_body(), 4096).await.is_err());
        } else {
            let status = resp.status();
            let body = body_json(resp).await;
            assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "{wire}: {body}");
            assert_eq!(body["phase"], "first_chunk", "{wire}: {body}");
        }
        let spans = crate::otlp_emit::test_sink::for_trace(trace);
        let span = spans.first().unwrap_or_else(|| panic!("{wire}: no span"));
        assert_eq!(
            span.status.message.as_deref(),
            Some("upstream_timeout"),
            "{wire}"
        );
        assert_eq!(
            span.attributes
                .tracelane_dispatch_attempts
                .as_ref()
                .unwrap_or_else(|| panic!("{wire}: no ledger"))[0]
                .reason
                .as_deref(),
            Some("upstream_timeout:first_chunk"),
            "{wire}"
        );
    }
    task.abort();
}

#[tokio::test]
async fn og11_responses_falls_back_from_native_to_translated_provider() {
    use crate::media_common::test_support::{as_claims, claims_for, install_byok, tenant, traced};
    use axum::body::Bytes;
    let _bypass = LoopbackBypassGuard::new();
    let native = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({"error":{"message":"down"}})))
        .mount(&native)
        .await;
    let translated = MockServer::start().await;
    let events = [
        ("message_start", json!({"type":"message_start","message":{"id":"msg-test","type":"message","role":"assistant","model":"claude-sonnet-4-5","content":[],"usage":{"input_tokens":3,"output_tokens":0}}})),
        ("content_block_start", json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}})),
        ("content_block_delta", json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"fallback works"}})),
        ("content_block_stop", json!({"type":"content_block_stop","index":0})),
        ("message_delta", json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}})),
        ("message_stop", json!({"type":"message_stop"})),
    ].iter().map(|(name, data)| format!("event: {name}\ndata: {data}\n\n")).collect::<String>();
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(events),
        )
        .mount(&translated)
        .await;
    let t = tenant();
    for provider in ["openai", "anthropic"] {
        install_byok(&t, provider);
    }
    let _claims = as_claims(claims_for(&t));
    let mut reg = ProviderRegistry::new().unwrap();
    reg.set_compat_base_url_for_test("openai", native.uri())
        .unwrap();
    reg.anthropic = crate::providers::AnthropicProvider::for_base_url(translated.uri()).unwrap();
    let mut state = test_state(reg);
    state.entitlements = Some(entitlements_with(
        doc(
            json!({"virtual_models":{"mixed":{"strategy":"priority","targets":[{"model":"gpt-4o-mini"},{"model":"claude-sonnet-4-5"}]}}}),
        ),
        Default::default(),
    ));
    let trace = uuid::Uuid::new_v4();
    let resp = crate::openai_responses::responses_handler(
        State(state.clone()),
        traced(trace),
        Bytes::from(json!({"model":"mixed","input":"hi"}).to_string()),
    )
    .await;
    let status = resp.status();
    let body = body_json(resp).await;
    assert_eq!(status, StatusCode::OK, "cross-mode fallback: {body}");
    assert!(body.to_string().contains("fallback works"), "{body}");
    assert_eq!(native.received_requests().await.unwrap().len(), 1);
    assert_eq!(translated.received_requests().await.unwrap().len(), 1);
    let spans = crate::otlp_emit::test_sink::for_trace(trace);
    let ledger = spans[0]
        .attributes
        .tracelane_dispatch_attempts
        .as_ref()
        .unwrap();
    assert_eq!(ledger.len(), 2);
    assert_eq!(ledger[1].provider, "anthropic");
    assert_eq!(ledger[1].outcome, "ok");
    state
        .zdr
        .store(Arc::new(crate::zdr::ZdrCapabilities::from_rows([(
            "anthropic".to_owned(),
            "default".to_owned(),
        )])));
    let mut headers = traced(uuid::Uuid::new_v4());
    headers.insert("x-tracelane-zdr", "required".parse().unwrap());
    let response = crate::openai_responses::responses_handler(
        State(state),
        headers,
        Bytes::from(json!({"model":"mixed","input":"hi"}).to_string()),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "ZDR prunes the ineligible primary"
    );
    let body = body_json(response).await;
    assert!(body.to_string().contains("fallback works"));
    assert_eq!(
        native.received_requests().await.unwrap().len(),
        1,
        "ineligible primary receives no second request"
    );
    assert_eq!(translated.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn og11_control_change_during_first_response_stops_retry_and_fallback() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let _bypass = LoopbackBypassGuard::new();
    let blocked = Arc::new(AtomicBool::new(false));
    let cache = Arc::new(crate::entitlement_cache::EntitlementCache::new({
        let blocked = blocked.clone();
        Arc::new(move |_| {
            let blocked = blocked.clone();
            Box::pin(async move {
                let controls = crate::controls::WorkspaceControls {
                    blocked_models: if blocked.load(Ordering::SeqCst) {
                        vec!["og11-fast".to_owned()]
                    } else {
                        vec![]
                    },
                    ..Default::default()
                };
                Ok(crate::entitlement_cache::ResolvedEntitlements {
                    controls: Arc::new(controls),
                    routing: Arc::new(routing_doc()),
                    ..crate::entitlement_cache::ResolvedEntitlements::deny_all()
                })
            })
        })
    }));
    let sends = Arc::new(AtomicUsize::new(0));
    let app = axum::Router::new().route(
        "/v1/chat/completions",
        axum::routing::post({
            let sends = sends.clone();
            let blocked = blocked.clone();
            let cache = cache.clone();
            move || {
                let sends = sends.clone();
                let blocked = blocked.clone();
                let cache = cache.clone();
                async move {
                    sends.fetch_add(1, Ordering::SeqCst);
                    blocked.store(true, Ordering::SeqCst);
                    cache.invalidate(*dev_tenant().as_uuid()).await;
                    (StatusCode::SERVICE_UNAVAILABLE, "down")
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut reg = ProviderRegistry::new().unwrap();
    for provider in ["ai21", "cerebras"] {
        reg.set_compat_base_url_for_test(provider, url.clone())
            .unwrap();
    }
    key("ai21", "default", "og11-test-ai21-default");
    key("cerebras", "team-a", "og11-test-cerebras-team-a");
    key("cerebras", "team-b", "og11-test-cerebras-team-b");
    let mut state = test_state(reg);
    state.entitlements = Some(cache);
    let trace = uuid::Uuid::new_v4();
    let response =
        chat_completions_handler(State(state), authed_with_trace(trace), ask("og11-fast")).await;
    let status = response.status();
    let body = body_json(response).await;
    server.abort();
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        sends.load(Ordering::SeqCst),
        1,
        "no retry or fallback after the control change"
    );
    let spans = crate::otlp_emit::test_sink::for_trace(trace);
    let ledger = spans[0]
        .attributes
        .tracelane_dispatch_attempts
        .as_ref()
        .unwrap();
    assert!(
        ledger
            .iter()
            .any(|a| a.outcome == "skipped" && a.reason.as_deref() == Some("model_blocked")),
        "{ledger:?}"
    );
}

#[tokio::test]
async fn og12_header_rule_changes_the_real_dispatch_and_records_the_rule() {
    let _bypass = LoopbackBypassGuard::new();
    let (primary, target, reg) = upstreams().await;
    key("cerebras", "default", "og11-test-cerebras-team-b");
    let raw = json!({"rules":[{"id":"header-route","wires":["chat"],
        "match":{"model":"jamba-*","header":{"name":"x-route-class","equals":"canary"}},
        "action":{"route_to":"cerebras/llama3.1-8b"}}]});
    let parsed = serde_json::from_value::<RoutingDoc>(raw);
    assert!(
        parsed.is_ok(),
        "conditional routing document must be accepted: {parsed:?}"
    );
    let mut state = test_state(reg);
    state.entitlements = Some(entitlements_with(
        RoutingState::Valid(Arc::new(parsed.unwrap())),
        Default::default(),
    ));
    let trace = uuid::Uuid::new_v4();
    let mut headers = authed_with_trace(trace);
    headers.insert("x-route-class", "canary".parse().unwrap());
    let response = chat_completions_handler(State(state), headers, ask("jamba-1.5-mini")).await;
    let status = response.status();
    let body = body_json(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(primary.received_requests().await.unwrap().is_empty());
    assert_eq!(target.received_requests().await.unwrap().len(), 1);
    let spans = crate::otlp_emit::test_sink::for_trace(trace);
    assert_eq!(
        spans[0].attributes.extra.get("tracelane_route_rule"),
        Some(&json!("header-route"))
    );
}

#[tokio::test]
async fn og12_missing_sticky_identity_uses_stable_arm_without_recording_identity() {
    let _bypass = LoopbackBypassGuard::new();
    let (primary, target, reg) = upstreams().await;
    key("cerebras", "default", "og11-test-cerebras-team-b");
    let raw = json!({"rules":[{"id":"split-rule","salt":"test-server-salt",
    "match":{"model":"jamba-*"},"action":{"split":{
    "sticky_by":["header:x-tracelane-sticky"],"arms":[
        {"name":"canary","route_to":"jamba-1.5-mini","bp":1000},
        {"name":"stable","route_to":"cerebras/llama3.1-8b"}
    ]}}}]});
    let parsed = serde_json::from_value::<RoutingDoc>(raw);
    assert!(
        parsed.is_ok(),
        "sticky split document must be accepted: {parsed:?}"
    );
    let mut state = test_state(reg);
    state.entitlements = Some(entitlements_with(
        RoutingState::Valid(Arc::new(parsed.unwrap())),
        Default::default(),
    ));
    let trace = uuid::Uuid::new_v4();
    let response = chat_completions_handler(
        State(state),
        authed_with_trace(trace),
        ask("jamba-1.5-mini"),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "{:?}",
        body_json(response).await
    );
    assert!(primary.received_requests().await.unwrap().is_empty());
    assert_eq!(target.received_requests().await.unwrap().len(), 1);
    let spans = crate::otlp_emit::test_sink::for_trace(trace);
    let attrs = &spans[0].attributes.extra;
    assert_eq!(attrs.get("tracelane_route_arm"), Some(&json!("stable")));
    assert_eq!(
        attrs.get("tracelane_route_sticky_source"),
        Some(&json!("none"))
    );
    assert!(attrs.get("tracelane_route_bucket").is_none());
}

#[tokio::test]
async fn og12_blocked_canary_refuses_stable_and_metadata_cannot_escape_controls() {
    let _bypass = LoopbackBypassGuard::new();
    let (primary, target, reg) = upstreams().await;
    let base = test_state(reg);
    for metadata in ["{}", "{\"tier\":\"canary\"}"] {
        let mut state = base.clone();
        state.entitlements = Some(entitlements_with(
            doc(json!({"rules":[{
                "id":"hints","salt":"server-salt","match":{"model":"jamba-*","metadata":{"key":"tier","equals":"canary"}},
                "action":{"split":{"sticky_by":[],"arms":[{"name":"canary","route_to":"cerebras/llama3.1-8b","bp":1000},{"name":"stable","route_to":"jamba-1.5-mini"}]}}
            }]})),
            crate::controls::WorkspaceControls {
                blocked_models: vec!["cerebras/*".into()],
                ..Default::default()
            },
        ));
        let mut headers = authed_with_trace(uuid::Uuid::new_v4());
        headers.insert("x-tracelane-metadata", metadata.parse().unwrap());
        let response = chat_completions_handler(State(state), headers, ask("jamba-1.5-mini")).await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{:?}",
            body_json(response).await
        );
    }
    assert!(primary.received_requests().await.unwrap().is_empty());
    assert!(target.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn og12_rules_rewrite_responses_messages_and_streaming_gemini_at_egress() {
    use crate::media_common::test_support::{as_claims, claims_for, install_byok, tenant, traced};
    use axum::{
        body::Bytes,
        extract::{Path, RawQuery},
    };
    let _bypass = LoopbackBypassGuard::new();
    let upstream = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(
            ResponseTemplate::new(503).set_body_json(json!({"error":{"message":"test upstream"}})),
        )
        .mount(&upstream)
        .await;
    let t = tenant();
    for p in ["openai", "anthropic", "google"] {
        install_byok(&t, p);
    }
    let _claims = as_claims(claims_for(&t));
    let mut reg = ProviderRegistry::new().unwrap();
    reg.set_compat_base_url_for_test("openai", upstream.uri())
        .unwrap();
    reg.anthropic = crate::providers::AnthropicProvider::for_base_url(upstream.uri()).unwrap();
    reg.google = crate::providers::GoogleProvider::for_base_url(upstream.uri()).unwrap();
    let mut state = test_state(reg);
    state.entitlements = Some(entitlements_with(
        doc(json!({"rules":[
            {"id":"responses-rule","wires":["responses"],"match":{"model":"gpt-4o-mini","stream":true},"action":{"route_to":"gpt-4.1"}},
            {"id":"messages-rule","wires":["messages"],"match":{"model":"claude-sonnet-4-5","stream":true},"action":{"route_to":"claude-haiku-4-5"}},
            {"id":"gemini-rule","wires":["gemini"],"match":{"model":"gemini-2.5-flash","stream":true},"action":{"route_to":"gemini-2.5-pro"}}
        ]})),
        Default::default(),
    ));
    for wire in ["responses", "messages", "gemini"] {
        let trace = uuid::Uuid::new_v4();
        let h = traced(trace);
        let st = State(state.clone());
        let response = match wire {
            "responses" => crate::openai_responses::responses_handler(st, h, Bytes::from(json!({"model":"gpt-4o-mini","stream":true,"input":"hi"}).to_string())).await,
            "messages" => crate::anthropic_messages::messages_handler(st, h, Bytes::from(json!({"model":"claude-sonnet-4-5","stream":true,"max_tokens":10,"messages":[{"role":"user","content":"hi"}]}).to_string())).await,
            _ => crate::gemini_native::model_action_handler(st, Path("gemini-2.5-flash:streamGenerateContent".into()), RawQuery(Some("alt=sse".into())), h, Bytes::from(json!({"contents":[{"parts":[{"text":"hi"}]}]}).to_string())).await,
        };
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{wire}: {:?}",
            body_json(response).await
        );
        let spans = crate::otlp_emit::test_sink::for_trace(trace);
        assert_eq!(
            spans[0].attributes.extra.get("tracelane_route_rule"),
            Some(&json!(format!("{wire}-rule")))
        );
    }
    let requests = upstream.received_requests().await.unwrap();
    assert_eq!(requests.len(), 3, "one attempt per routed request");
    assert_eq!(
        requests[0].body_json::<serde_json::Value>().unwrap()["model"],
        "gpt-4.1"
    );
    assert_eq!(
        requests[1].body_json::<serde_json::Value>().unwrap()["model"],
        "claude-haiku-4-5"
    );
    assert!(
        requests[2]
            .url
            .path()
            .contains("gemini-2.5-pro:streamGenerateContent")
    );
}

#[tokio::test]
async fn og12_caller_metadata_cannot_bypass_key_denies_on_concrete_or_virtual_arms() {
    let mut state = test_state(ProviderRegistry::new().unwrap());
    state.entitlements = Some(entitlements_with(
        doc(json!({
            "virtual_models":{"canary-target":{"targets":[{"model":"gpt-4.1"}]}},
            "rules":[{"id":"hints","salt":"server-salt","match":{"model":"gpt-4o","metadata":{"key":"tier","equals":"canary"}},
            "action":{"split":{"sticky_by":[],"arms":[{"name":"canary","route_to":"canary-target","bp":1000},{"name":"stable","route_to":"gpt-4o"}]}}}]
        })),
        Default::default(),
    ));
    for denied in ["gpt-4.1", "canary-target"] {
        for metadata in ["{}", "{\"tier\":\"canary\"}"] {
            let mut claims = crate::auth::dev_stub_claims(crate::auth::AuthMethod::ApiKey);
            claims.governance = tracelane_shared::key_policy::Governance::from_columns(
                None,
                None,
                None,
                Some(&json!({"models":{"deny":[denied]}})),
            )
            .map(Arc::new);
            let mut headers = authed_with_trace(uuid::Uuid::new_v4());
            headers.insert("x-tracelane-metadata", metadata.parse().unwrap());
            let result = crate::key_policy_route_tests::run_with::<crate::admission::Chat>(
                &state,
                &headers,
                ask("gpt-4o").0,
                claims,
            )
            .await;
            assert!(
                matches!(result, Err(crate::admission::Refusal::Policy(_))),
                "deny={denied} metadata={metadata}: {result:?}"
            );
        }
    }
}

/// LOW round 2 (security re-review, 2026-10-05): chat/embeddings resolve the deadline
/// budget with the provider ID (`vertex`) but fed `record_legacy` the breaker name
/// (`gcp_vertex_ai`). A rule matched on `vertex` then made BOTH the deadline observer and
/// `record_legacy` record the same timeout (double-counted). The legacy record must
/// resolve with the same provider id the budget used.
#[tokio::test]
async fn r2_record_legacy_resolves_deadlines_with_the_budgets_provider_id() {
    use crate::circuit_breaker::{CircuitBreaker, Cred, Outcome};
    let cache = entitlements_with(
        doc(json!({"timeouts":[{"match":{"provider":"vertex"},"headers_ms":5000}]})),
        Default::default(),
    );
    let resolved = cache.resolved(uuid::Uuid::new_v4()).await;
    let cb = CircuitBreaker::default();
    let cred = Cred::byok(&uuid::Uuid::new_v4(), "vertex", "default");
    for (breaker_name, model) in [
        ("gcp_vertex_ai", "vertex/gemini-2.5-pro"),
        ("aws_bedrock", "anthropic.claude-3-haiku"),
    ] {
        crate::routing::deadlines::record_legacy(
            &cb,
            breaker_name,
            "default",
            &cred,
            Outcome::UpstreamFault,
            Some(&resolved),
            model,
        );
    }
    assert!(
        cb.outcomes("gcp_vertex_ai", "default", &cred.id).is_empty(),
        "a vertex deadline rule is in force: the observer records, record_legacy must not"
    );
    assert_eq!(
        cb.outcomes("aws_bedrock", "default", &cred.id).len(),
        1,
        "no rule for bedrock: the legacy record still happens"
    );
}

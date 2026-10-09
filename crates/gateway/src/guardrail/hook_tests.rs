//! Custom-hook contract and enforcing wire probes.
use super::hooks::*;
use super::outcome::Outcome;
use serde_json::json;
use uuid::Uuid;

#[test]
fn og31_reply_schema_fails_closed_on_ambiguous_or_unbounded_answers() {
    assert_eq!(parse_reply(br#"{"decision":"deny"}"#), Some(Reply::Deny {}));
    for bytes in [
        br#"{}"#.as_slice(),
        br#"{"decision":"allow","decision":"deny"}"#,
        br#"{"decision":"allow","extra":true}"#,
        br#"{"decision":"deny","matches":null}"#,
        br#"{"decision":"redact","matches":[]}"#,
        br#"{"decision":"redact","matches":[""]}"#,
        br#"{"decision":"allow"} trailing"#,
    ] {
        assert!(
            parse_reply(bytes).is_none(),
            "must refuse malformed decision: {:?}",
            String::from_utf8_lossy(bytes)
        );
    }
    assert!(
        parse_reply(
            &serde_json::to_vec(&json!({"decision":"redact","matches":["x".repeat(257)]})).unwrap()
        )
        .is_none()
    );
}

#[test]
fn og31_signature_authenticates_exact_json_without_transport_credentials() {
    use secrecy::ExposeSecret;
    let hook = fixture();
    let (body, signature) = signed_body(&hook, Phase::Pre, "hello");
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["text"], "hello");
    assert_eq!(value["phase"], "pre");
    assert!(value["timestamp"].is_i64());
    assert!(
        value["request_id"]
            .as_str()
            .is_some_and(|s| Uuid::parse_str(s).is_ok())
    );
    assert!(
        !String::from_utf8(body.clone())
            .unwrap()
            .contains(hook.secret.expose_secret())
    );
    let key = ring::hmac::Key::new(
        ring::hmac::HMAC_SHA256,
        hook.secret.expose_secret().as_bytes(),
    );
    let decoded = hex::decode(signature).unwrap();
    ring::hmac::verify(&key, &body, &decoded).unwrap();
    let mut changed = body;
    changed.push(b' ');
    assert!(ring::hmac::verify(&key, &changed, &decoded).is_err());
}

#[test]
fn og31_https_config_refuses_credentials_fragments_and_invalid_phases() {
    let mut config = fixture().config;
    assert!(config.valid());
    for url in [
        "http://example.com",
        "https://u:p@example.com",
        "https://example.com/?key=secret",
        "https://example.com/#secret",
        "file:///tmp/a",
    ] {
        config.endpoint = url.into();
        assert!(!config.valid(), "{url}");
    }
    config = fixture().config;
    config.pre = false;
    config.post = false;
    assert!(!config.valid());
    config = fixture().config;
    config.timeout_ms = 0;
    assert!(!config.valid());
    config.timeout_ms = 5001;
    assert!(!config.valid());
}

#[test]
fn og31_concurrency_is_bounded_per_tenant_and_released_on_drop() {
    let tenant = Uuid::new_v4();
    let permits: Vec<_> = (0..4).map(|_| acquire(tenant).unwrap()).collect();
    assert!(acquire(tenant).is_none());
    assert!(acquire(Uuid::new_v4()).is_some());
    drop(permits);
    assert!(acquire(tenant).is_some());
}

#[tokio::test]
async fn og31_timeout_has_explicit_open_and_closed_span_outcomes() {
    let mut hook = fixture();
    hook.config.timeout_ms = 1;
    hook.answer.as_mut().unwrap().delay_ms = 1000;
    let closed = evaluate(Uuid::new_v4(), &hook, Phase::Pre, "hello").await;
    assert_eq!(closed.outcome.outcome, Outcome::Block);
    assert_eq!(closed.event.reason, "HOOK_TIMEOUT");
    hook.config.fail_mode = FailMode::Open;
    let open = evaluate(Uuid::new_v4(), &hook, Phase::Pre, "hello").await;
    assert_eq!(open.outcome.outcome, Outcome::FailOpen);
    assert_eq!(open.event.reason, "HOOK_TIMEOUT");
}

#[tokio::test]
async fn og31_malformed_answer_never_uses_fail_open() {
    let mut hook = fixture();
    hook.config.fail_mode = FailMode::Open;
    hook.answer.as_mut().unwrap().bytes = b"{broken".to_vec();
    let got = evaluate(Uuid::new_v4(), &hook, Phase::Pre, "hello").await;
    assert_eq!(got.outcome.outcome, Outcome::Block);
    assert_eq!(got.event.reason, "HOOK_MALFORMED");
}

#[tokio::test]
async fn og31_deny_and_redact_are_distinct_enforcing_decisions() {
    let mut hook = fixture();
    let denied = evaluate(Uuid::new_v4(), &hook, Phase::Pre, "private phrase").await;
    assert_eq!(denied.outcome.outcome, Outcome::Block);
    hook.answer.as_mut().unwrap().bytes =
        br#"{"decision":"redact","matches":["private"]}"#.to_vec();
    let redacted = evaluate(Uuid::new_v4(), &hook, Phase::Post, "private phrase").await;
    assert_eq!(redacted.outcome.outcome, Outcome::Redact);
    assert_eq!(redacted.redactions, vec!["private"]);
    assert!(
        !serde_json::to_string(&redacted.event)
            .unwrap()
            .contains("private")
    );
}

pub(crate) fn state(
    state: crate::server::AppState,
    _config: serde_json::Value,
) -> crate::server::AppState {
    state_with_hook(state, fixture())
}
pub(crate) fn state_with_hook(
    state: crate::server::AppState,
    hook: Hook,
) -> crate::server::AppState {
    state_with_hooks(state, vec![hook])
}
fn state_with_hooks(
    mut state: crate::server::AppState,
    hooks: Vec<Hook>,
) -> crate::server::AppState {
    use crate::entitlement_cache::{EntitlementCache, ResolvedEntitlements};
    use std::sync::Arc;
    let cache = Arc::new(EntitlementCache::new(Arc::new(move |_| {
        let hooks = hooks.clone();
        Box::pin(async move {
            Ok(ResolvedEntitlements {
                guardrail_policies: Arc::new(super::policy::Policies {
                    hooks,
                    ..Default::default()
                }),
                ..ResolvedEntitlements::deny_all()
            })
        })
    })));
    state.guardrail = Arc::new(super::GuardrailEngine::new(
        state.audit_chain.clone(),
        None,
        Some(cache),
        Arc::new(super::CapabilityRegistry::new()),
    ));
    state
}

#[test]
fn og31_ciphertext_cannot_move_between_tenants_hooks_or_endpoints() {
    use base64::Engine as _;
    use secrecy::SecretString;
    let encoded = base64::engine::general_purpose::STANDARD.encode([7_u8; 32]);
    let key = crate::byok::ByokMasterKey::from_values(Some(&encoded), None, None)
        .unwrap()
        .unwrap();
    let tenant = Uuid::new_v4();
    let id = Uuid::new_v4();
    let endpoint = "https://hooks.example.com/check";
    let context = credential_aad(&tenant, &credential_key(id, endpoint));
    let sealed = key
        .encrypt_with_context(
            &SecretString::from("0123456789abcdef0123456789abcdef"),
            &context,
        )
        .unwrap();
    assert!(key.decrypt_with_context(&sealed, &context).is_ok());
    for other in [
        credential_aad(&Uuid::new_v4(), &credential_key(id, endpoint)),
        credential_aad(&tenant, &credential_key(Uuid::new_v4(), endpoint)),
        credential_aad(
            &tenant,
            &credential_key(id, "https://other.example.com/check"),
        ),
    ] {
        assert!(key.decrypt_with_context(&sealed, &other).is_err());
    }
}

#[test]
fn og31_literal_redaction_preserves_structure_and_opaque_credentials() {
    let mut body = json!({"model":"gpt-4o","messages":[{"role":"user","content":"private phrase"}],"tools":[{"type":"mcp","server_label":"service","server_url":"https://service.example.com","authorization":"private phrase"}]});
    super::egress::redact_hook_json(&mut body, &[vec!["private".into()]]).unwrap();
    assert_eq!(body["messages"][0]["content"], "[REDACTED:custom] phrase");
    assert_eq!(body["tools"][0]["authorization"], "private phrase");
    let mut selector = json!({"model":"private-model","messages":[]});
    assert!(super::egress::redact_hook_json(&mut selector, &[vec!["private".into()]]).is_err());
    let mut key = json!({"metadata":{"private":"value"}});
    assert!(super::egress::redact_hook_json(&mut key, &[vec!["private".into()]]).is_err());
}

#[tokio::test]
async fn og31_post_hooks_hold_the_whole_response_and_apply_once() {
    use super::{GuardStep, ResponseGuard, ResponseInputs, SessionState};
    let base =
        crate::handler_harness::test_state(crate::providers::ProviderRegistry::new().unwrap());
    let events = Events::default();
    let mut hook = fixture();
    hook.config.pre = false;
    hook.config.post = true;
    let inputs = ResponseInputs {
        hooks: Some(vec![hook.clone()]),
        hook_events: events.clone(),
        tenant_id: crate::handler_harness::dev_tenant(),
        api_key_id: None,
        project_id: None,
        correlation_id: ulid::Ulid::new(),
        system_prompt: None,
        model: "gpt-4o".into(),
        session: SessionState::fresh(None),
        actor: "unit-test".into(),
        expected_format: None,
    };
    let text = format!("{} private phrase", "hello ".repeat(100));
    let mut deny =
        ResponseGuard::with_holdback(base.guardrail.clone(), inputs.clone(), Vec::new(), 1);
    assert_eq!(
        deny.on_delta(&text, None).await,
        GuardStep::Emit(String::new())
    );
    assert_eq!(
        deny.on_end(None).await,
        GuardStep::Block {
            reason_code: "HOOK_DENY"
        }
    );
    hook.answer.as_mut().unwrap().bytes =
        br#"{"decision":"redact","matches":["private"]}"#.to_vec();
    let mut inputs = inputs;
    inputs.hooks = Some(vec![hook]);
    inputs.hook_events = Events::default();
    let once = inputs.hook_events.clone();
    let mut redact = ResponseGuard::with_holdback(base.guardrail, inputs, Vec::new(), 1);
    assert_eq!(
        redact.on_delta(&text, None).await,
        GuardStep::Emit(String::new())
    );
    let GuardStep::Emit(safe) = redact.on_end(None).await else {
        panic!("redact must emit")
    };
    assert!(!safe.contains("private"));
    assert!(safe.contains("[REDACTED:custom]"));
    assert_eq!(redact.on_end(None).await, GuardStep::Emit(String::new()));
    assert_eq!(once.value().unwrap().as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn og31_private_destination_is_closed_even_with_fail_open() {
    let mut hook = fixture();
    hook.config.endpoint = "https://169.254.169.254/latest/meta-data".into();
    hook.config.fail_mode = FailMode::Open;
    hook.answer = None;
    let result = evaluate(Uuid::new_v4(), &hook, Phase::Pre, "hello").await;
    assert_eq!(result.outcome.outcome, Outcome::Block);
    assert_eq!(result.event.reason, "HOOK_DESTINATION_INVALID");
}

#[tokio::test]
async fn og31_chat_pre_redaction_reaches_upstream_without_invoking_unentitled_r2() {
    use axum::{Json, extract::State};
    let _b = crate::handler_harness::LoopbackBypassGuard::new();
    let upstream = crate::handler_harness::chat_ok_mock().await;
    let mut hook = fixture();
    hook.answer.as_mut().unwrap().bytes =
        br#"{"decision":"redact","matches":["private"]}"#.to_vec();
    let state = state_with_hook(
        crate::handler_harness::test_state(crate::handler_harness::registry_pointing_ollama_at(
            upstream.uri(),
        )),
        hook,
    );
    let response=crate::server::chat_completions_handler(State(state),crate::handler_harness::authed(),Json(json!({"model":"ollama/llama3","messages":[{"role":"user","content":"private phrase person@example.com"}]}))).await;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let requests = upstream.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let value: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(
        value["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["role"] == "user")
            .unwrap()["content"],
        "[REDACTED:custom] phrase person@example.com"
    );
}

#[tokio::test]
async fn og31_post_stream_refuses_before_upstream_and_hooks_suspend_cache() {
    use axum::{Json, extract::State};
    let _b = crate::handler_harness::LoopbackBypassGuard::new();
    let upstream = crate::handler_harness::chat_ok_mock().await;
    let mut hook = fixture();
    hook.config.pre = false;
    hook.config.post = true;
    let state = state_with_hook(
        crate::handler_harness::test_state(crate::handler_harness::registry_pointing_ollama_at(
            upstream.uri(),
        )),
        hook,
    );
    assert!(
        state
            .guardrail
            .policy_for(*crate::handler_harness::dev_tenant().as_uuid(), None, None)
            .await
            .has_controls()
    );
    let response=crate::server::chat_completions_handler(State(state),crate::handler_harness::authed(),Json(json!({"model":"ollama/llama3","stream":true,"messages":[{"role":"user","content":"hello"}]}))).await;
    assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    let value = crate::handler_harness::body_json(response).await;
    assert_eq!(value["reason_code"], "HOOK_POST_STREAM_UNSUPPORTED");
    assert!(upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn og31_cold_snapshot_cannot_silently_drop_hooks() {
    use std::sync::Arc;
    let cache = Arc::new(crate::entitlement_cache::EntitlementCache::new(Arc::new(
        |_| Box::pin(async { Err(anyhow::anyhow!("unavailable")) }),
    )));
    let engine = super::GuardrailEngine::new(
        crate::handler_harness::in_memory_chain(),
        None,
        Some(cache),
        Arc::new(super::CapabilityRegistry::new()),
    );
    let tenant = crate::handler_harness::dev_tenant();
    let policy = engine.policy_for(*tenant.as_uuid(), None, None).await;
    assert!(policy.unavailable);
    assert!(policy.has_controls());
    assert!(
        !engine
            .realtime_policy_supported(*tenant.as_uuid(), None, None)
            .await
    );
    assert!(!engine.batch_policy(*tenant.as_uuid(), None, None).await.1);
    let request = crate::media_common::text_view("gpt-4o", &["hello"]);
    let result = engine
        .evaluate_request(super::RequestInputs {
            tenant_id: &tenant,
            api_key_id: None,
            project_id: None,
            correlation_id: ulid::Ulid::new(),
            request: &request,
            rag_context: Vec::new(),
            session: super::SessionState::fresh(None),
            actor: "unit-test",
            egress_json: None,
        })
        .await;
    assert!(result.is_block());
    assert!(
        result
            .outcome
            .records
            .iter()
            .any(|r| r.outcome.reason_code == Some("HOOK_POLICY_UNAVAILABLE"))
    );
}

#[test]
fn og31_hook_body_excludes_wire_credentials_and_refuses_url_userinfo() {
    let request = crate::media_common::text_view("gpt-4o", &["hello"]);
    let body = json!({"messages":[{"role":"user","content":"hello"}],"tools":[{"type":"mcp","server_label":"tool","server_url":"https://example.com","authorization":"transport-secret"}]});
    let text = request_text(&request, Some(&body)).unwrap();
    assert!(!text.contains("transport-secret"));
    assert!(text.contains("hello"));
    let body = json!({"tools":[{"type":"mcp","server_label":"tool","server_url":"https://user:secret@example.com"}]});
    assert!(request_text(&request, Some(&body)).is_err());
}

#[tokio::test]
async fn og31_transport_client_never_follows_redirects() {
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let source = MockServer::start().await;
    let destination = MockServer::start().await;
    Mock::given(wiremock::matchers::method("POST"))
        .respond_with(ResponseTemplate::new(307).insert_header("location", destination.uri()))
        .mount(&source)
        .await;
    let client = crate::ssrf_guard::safe_client_builder()
        .no_proxy()
        .build()
        .unwrap();
    let response = client
        .post(source.uri())
        .body("screened text")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::TEMPORARY_REDIRECT);
    assert!(destination.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn og31_sequential_pre_redactions_apply_the_same_text_each_hook_screened() {
    use axum::{Json, extract::State};
    let _b = crate::handler_harness::LoopbackBypassGuard::new();
    let upstream = crate::handler_harness::chat_ok_mock().await;
    let mut first = fixture();
    first.answer.as_mut().unwrap().bytes =
        br#"{"decision":"redact","matches":["private"]}"#.to_vec();
    let mut second = fixture();
    second.answer.as_mut().unwrap().bytes =
        br#"{"decision":"redact","matches":["[REDACTED:custom] phrase"]}"#.to_vec();
    let state = state_with_hooks(
        crate::handler_harness::test_state(crate::handler_harness::registry_pointing_ollama_at(
            upstream.uri(),
        )),
        vec![first, second],
    );
    let response=crate::server::chat_completions_handler(State(state),crate::handler_harness::authed(),Json(json!({"model":"ollama/llama3","messages":[{"role":"user","content":"private phrase"}]}))).await;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let requests = upstream.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(
        body["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["role"] == "user")
            .unwrap()["content"],
        "[REDACTED:custom]"
    );
}

#[test]
fn og31_redaction_across_json_field_boundaries_is_refused() {
    let mut body = json!({"first":"private","second":"phrase"});
    assert!(
        super::egress::redact_hook_json(&mut body, &[vec!["private\nsecond\nphrase".into()]])
            .is_err()
    );
}

//! Documented vendor examples and enforcing wire fixtures, without remote calls.
use super::{
    adapters::{Adapter, Thresholds, parse_reply, request},
    hooks::{FailMode, Hook, Phase, Reply, credential_key, evaluate, fixture},
};
use serde_json::{Value, json};

pub(crate) fn fixtures() -> Vec<Hook> {
    let mut lakera = fixture();
    lakera.config.endpoint = "https://api.lakera.ai/v2/guard".into();
    lakera.config.adapter = Some(Adapter::Lakera {});
    lakera.answer.as_mut().unwrap().bytes = br#"{"flagged":true,"action":"enforce"}"#.to_vec();
    let mut azure = fixture();
    azure.config.endpoint = "https://unit.cognitiveservices.azure.com".into();
    azure.config.adapter = Some(Adapter::AzureContentSafety {
        thresholds: Thresholds {
            hate: 4,
            self_harm: 4,
            sexual: 4,
            violence: 4,
        },
    });
    azure.answer.as_mut().unwrap().bytes = serde_json::to_vec(&azure_reply([4, 0, 0, 0])).unwrap();
    vec![lakera, azure]
}
fn azure_reply(severities: [u8; 4]) -> Value {
    json!({"blocklistsMatch":[],"categoriesAnalysis":[
        {"category":"Hate","severity":severities[0]},
        {"category":"SelfHarm","severity":severities[1]},
        {"category":"Sexual","severity":severities[2]},
        {"category":"Violence","severity":severities[3]}]})
}
#[test]
fn og32_only_fixed_vendor_destinations_and_explicit_thresholds_are_valid() {
    for hook in fixtures() {
        assert!(hook.config.valid());
        for endpoint in [
            "https://evil.example.com",
            "https://api.lakera.ai.evil.example/v2/guard",
            "https://unit.cognitiveservices.azure.com.evil.example",
            "https://u:p@unit.cognitiveservices.azure.com",
            "https://unit.cognitiveservices.azure.com:8443",
            "https://unit.cognitiveservices.azure.com/other",
        ] {
            let mut config = hook.config.clone();
            config.endpoint = endpoint.into();
            assert!(!config.valid(), "{endpoint}");
        }
    }
    let mut bad = fixtures().remove(1).config;
    bad.adapter = Some(Adapter::AzureContentSafety {
        thresholds: Thresholds {
            hate: 8,
            self_harm: 4,
            sexual: 4,
            violence: 4,
        },
    });
    assert!(!bad.valid());
    assert!(serde_json::from_value::<Adapter>(json!({"kind":"lakera","extra":true})).is_err());
    assert!(
        serde_json::from_value::<Adapter>(
            json!({"kind":"azure_content_safety","thresholds":{"Hate":4}})
        )
        .is_err()
    );
}
#[test]
fn og32_lakera_request_uses_documented_roles_and_sensitive_bearer_header() {
    use secrecy::ExposeSecret;
    let hook = fixtures().remove(0);
    for (phase, role) in [(Phase::Pre, "user"), (Phase::Post, "assistant")] {
        let request = request(&hook, phase, "screen me").unwrap();
        assert_eq!(request.url, "https://api.lakera.ai/v2/guard");
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(
            body,
            json!({"messages":[{"role":role,"content":"screen me"}]})
        );
        assert!(!String::from_utf8_lossy(&request.body).contains(hook.secret.expose_secret()));
        let built = request
            .into_request(&reqwest::Client::new(), &hook)
            .build()
            .unwrap();
        let header = &built.headers()["authorization"];
        assert_eq!(
            header.to_str().unwrap().strip_prefix("Bearer "),
            Some(hook.secret.expose_secret())
        );
        assert!(header.is_sensitive());
    }
}
#[test]
fn og32_lakera_detect_missing_duplicate_and_wrong_type_never_allow() {
    let adapter = Adapter::Lakera {};
    assert_eq!(
        parse_reply(&adapter, br#"{"flagged":false,"action":"enforce"}"#),
        Some(Reply::Allow {})
    );
    assert_eq!(
        parse_reply(
            &adapter,
            br#"{"flagged":true,"action":"enforce","metadata":{"request_uuid":"example"}}"#
        ),
        Some(Reply::Deny {})
    );
    for bytes in [
        br#"{"flagged":false,"action":"detect"}"#.as_slice(),
        br#"{"flagged":false}"#,
        br#"{"flagged":false,"flagged":true,"action":"enforce"}"#,
        br#"{"flagged":"false","action":"enforce"}"#,
        br#"{"flagged":false,"action":"enforce","unexpected":true}"#,
    ] {
        assert!(parse_reply(&adapter, bytes).is_none());
    }
}
#[test]
fn og32_azure_request_uses_versioned_path_key_header_and_unicode_limit() {
    use secrecy::ExposeSecret;
    let hook = fixtures().remove(1);
    let wire = request(&hook, Phase::Pre, &"🦀".repeat(10_000)).unwrap();
    assert_eq!(
        wire.url,
        "https://unit.cognitiveservices.azure.com/contentsafety/text:analyze?api-version=2024-09-01"
    );
    let body: Value = serde_json::from_slice(&wire.body).unwrap();
    assert_eq!(body["text"].as_str().unwrap().chars().count(), 10_000);
    assert_eq!(body["outputType"], "EightSeverityLevels");
    assert_eq!(
        body["categories"],
        json!(["Hate", "SelfHarm", "Sexual", "Violence"])
    );
    let header = &wire.headers["ocp-apim-subscription-key"];
    assert_eq!(header.to_str().unwrap(), hook.secret.expose_secret());
    assert!(header.is_sensitive());
    assert!(
        !String::from_utf8(wire.body)
            .unwrap()
            .contains(hook.secret.expose_secret())
    );
    assert!(request(&hook, Phase::Pre, &"🦀".repeat(10_001)).is_none());
}
#[test]
fn og32_azure_each_threshold_and_blocklist_match_enforce() {
    let hook = fixtures().remove(1);
    let adapter = hook.config.adapter.as_ref().unwrap();
    assert_eq!(
        parse_reply(
            adapter,
            &serde_json::to_vec(&azure_reply([3, 3, 3, 3])).unwrap()
        ),
        Some(Reply::Allow {})
    );
    for i in 0..4 {
        let mut severity = [0; 4];
        severity[i] = 4;
        assert_eq!(
            parse_reply(
                adapter,
                &serde_json::to_vec(&azure_reply(severity)).unwrap()
            ),
            Some(Reply::Deny {})
        );
    }
    let mut reply = azure_reply([0; 4]);
    reply["blocklistsMatch"] =
        json!([{"blocklistName":"test","blocklistItemId":"item","blocklistItemText":"phrase"}]);
    assert_eq!(
        parse_reply(adapter, &serde_json::to_vec(&reply).unwrap()),
        Some(Reply::Deny {})
    );
}
#[test]
fn og32_azure_missing_duplicate_or_invalid_categories_fail_closed() {
    let hook = fixtures().remove(1);
    let adapter = hook.config.adapter.as_ref().unwrap();
    for severity in [json!(8), json!(-1), json!(true), json!(1.0)] {
        let mut reply = azure_reply([0; 4]);
        reply["categoriesAnalysis"][0]["severity"] = severity;
        assert!(parse_reply(adapter, &serde_json::to_vec(&reply).unwrap()).is_none());
    }
    let mut duplicate = azure_reply([0; 4]);
    duplicate["categoriesAnalysis"][1]["category"] = json!("Hate");
    assert!(parse_reply(adapter, &serde_json::to_vec(&duplicate).unwrap()).is_none());
    let mut missing = azure_reply([0; 4]);
    missing["categoriesAnalysis"].as_array_mut().unwrap().pop();
    assert!(parse_reply(adapter, &serde_json::to_vec(&missing).unwrap()).is_none());
    assert!(
        parse_reply(
            adapter,
            br#"{"categoriesAnalysis":[],"categoriesAnalysis":[],"blocklistsMatch":[]}"#
        )
        .is_none()
    );
}
#[test]
fn og32_credentials_are_bound_to_adapter_kind_and_legacy_context_stays_stable() {
    let hook = fixture();
    let legacy = credential_key(hook.id, &hook.config.endpoint);
    assert_eq!(hook.config.credential_key(hook.id), legacy);
    let mut lakera = hook.config.clone();
    lakera.adapter = Some(Adapter::Lakera {});
    assert_ne!(lakera.credential_key(hook.id), legacy);
    let mut azure = lakera.clone();
    azure.adapter = fixtures().remove(1).config.adapter;
    assert_ne!(
        lakera.credential_key(hook.id),
        azure.credential_key(hook.id)
    );
}
#[tokio::test]
async fn og32_vendor_failures_obey_hook_failure_mode_but_bad_answers_are_closed() {
    for mut hook in fixtures() {
        hook.config.fail_mode = FailMode::Open;
        hook.answer.as_mut().unwrap().bytes = b"{}".to_vec();
        let malformed = evaluate(uuid::Uuid::new_v4(), &hook, Phase::Pre, "hello").await;
        assert_eq!(malformed.event.reason, "HOOK_MALFORMED");
        assert_eq!(malformed.outcome.outcome, super::outcome::Outcome::Block);
        hook.answer.as_mut().unwrap().transport_error = true;
        let unavailable = evaluate(uuid::Uuid::new_v4(), &hook, Phase::Pre, "hello").await;
        assert_eq!(
            unavailable.outcome.outcome,
            super::outcome::Outcome::FailOpen
        );
    }
}

#[tokio::test]
async fn og32_both_adapters_hold_post_output_and_refuse_streamed_post_before_dispatch() {
    use super::{GuardStep, ResponseGuard, ResponseInputs, SessionState};
    use axum::{Json, extract::State};
    let _b = crate::handler_harness::LoopbackBypassGuard::new();
    for mut hook in fixtures() {
        hook.config.pre = false;
        hook.config.post = true;
        let state =
            crate::handler_harness::test_state(crate::providers::ProviderRegistry::new().unwrap());
        let mut guard = ResponseGuard::new(
            state.guardrail,
            ResponseInputs {
                hooks: Some(vec![hook.clone()]),
                hook_events: super::hooks::Events::default(),
                tenant_id: crate::handler_harness::dev_tenant(),
                api_key_id: None,
                project_id: None,
                correlation_id: ulid::Ulid::new(),
                system_prompt: None,
                model: "gpt-4o".into(),
                session: SessionState::fresh(None),
                actor: "test".into(),
                expected_format: None,
            },
            Vec::new(),
        );
        assert_eq!(
            guard.on_delta("screen the whole response", None).await,
            GuardStep::Emit(String::new())
        );
        assert_eq!(
            guard.on_end(None).await,
            GuardStep::Block {
                reason_code: "HOOK_DENY"
            }
        );
        let upstream = crate::handler_harness::chat_ok_mock().await;
        let state = super::hook_tests::state_with_hook(
            crate::handler_harness::test_state(
                crate::handler_harness::registry_pointing_ollama_at(upstream.uri()),
            ),
            hook,
        );
        let response=crate::server::chat_completions_handler(State(state),crate::handler_harness::authed(),Json(json!({"model":"ollama/llama3","stream":true,"messages":[{"role":"user","content":"hello"}]}))).await;
        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
        assert_eq!(
            crate::handler_harness::body_json(response).await["reason_code"],
            "HOOK_POST_STREAM_UNSUPPORTED"
        );
        assert!(upstream.received_requests().await.unwrap().is_empty());
    }
}
#[tokio::test]
async fn og32_adapter_input_limits_and_bad_headers_never_fail_open() {
    let mut azure = fixtures().remove(1);
    azure.config.fail_mode = FailMode::Open;
    let outcome = evaluate(
        uuid::Uuid::new_v4(),
        &azure,
        Phase::Pre,
        &"x".repeat(10_001),
    )
    .await;
    assert_eq!(outcome.event.reason, "HOOK_ADAPTER_INPUT_INVALID");
    assert_eq!(outcome.outcome.outcome, super::outcome::Outcome::Block);
    for mut hook in fixtures() {
        hook.config.fail_mode = FailMode::Open;
        hook.secret = std::sync::Arc::new(secrecy::SecretString::from("bad\r\nheader"));
        assert!(!hook.config.credential_valid(&hook.secret));
        assert_eq!(
            evaluate(uuid::Uuid::new_v4(), &hook, Phase::Pre, "hello")
                .await
                .outcome
                .outcome,
            super::outcome::Outcome::Block
        );
    }
}
#[test]
fn og32_adapter_reply_caps_and_tenant_provider_aad_are_enforced() {
    use base64::Engine as _;
    use secrecy::SecretString;
    let encoded = base64::engine::general_purpose::STANDARD.encode([9; 32]);
    let master = crate::byok::ByokMasterKey::from_values(Some(&encoded), None, None)
        .unwrap()
        .unwrap();
    let tenant = uuid::Uuid::new_v4();
    for hook in fixtures() {
        let key = hook.config.credential_key(hook.id);
        let adapter = hook.config.adapter.as_ref().unwrap();
        assert_eq!(
            key,
            format!("{}:{}:{}", adapter.kind(), hook.id, hook.config.endpoint)
        );
        let aad = super::hooks::credential_aad(&tenant, &key);
        let sealed = master
            .encrypt_with_context(&SecretString::from("synthetic-key"), &aad)
            .unwrap();
        assert!(master.decrypt_with_context(&sealed, &aad).is_ok());
        assert!(
            master
                .decrypt_with_context(
                    &sealed,
                    &super::hooks::credential_aad(&uuid::Uuid::new_v4(), &key)
                )
                .is_err()
        );
        assert!(
            master
                .decrypt_with_context(
                    &sealed,
                    &super::hooks::credential_aad(
                        &tenant,
                        &credential_key(hook.id, &hook.config.endpoint)
                    )
                )
                .is_err()
        );
        assert!(
            parse_reply(
                adapter,
                &vec![b' '; super::hooks::limits().unwrap().response_bytes + 1]
            )
            .is_none()
        );
    }
}

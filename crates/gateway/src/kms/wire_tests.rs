//! Real handlers with a typed failure at the shared resolver's KMS boundary.
//! Cache/unwrap behavior is proved separately in vault::tests; this matrix proves
//! no wire converts the failure to a missing credential or dispatches upstream.
use super::KmsError;
tokio::task_local! { pub(crate) static FAILURE: KmsError; }

#[cfg(debug_assertions)]
mod tests {
    use super::*;
    use crate::handler_harness::{authed, body_json, test_state};
    use axum::{
        Router,
        body::{Body, Bytes},
        extract::{Path, RawQuery, State},
        http::{Method, Request, StatusCode},
        routing::{any, get, post},
    };
    use serde_json::json;
    use tower::ServiceExt as _;

    #[tokio::test]
    async fn typed_kms_failure_is_terminal_even_when_an_env_fallback_exists() {
        // PATH is already present and harmless; no process-global env mutation,
        // and no credential value is read into a test assertion or log.
        assert!(std::env::var_os("PATH").is_some());
        let tenant = tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        for error in [KmsError::Unavailable, KmsError::Denied] {
            let key = FAILURE
                .scope(
                    error,
                    crate::server::resolve_provider_key(&tenant, "openai", "PATH"),
                )
                .await;
            assert!(matches!(
                (error, key),
                (
                    KmsError::Unavailable,
                    crate::server::ProviderKey::KmsUnavailable
                ) | (KmsError::Denied, crate::server::ProviderKey::KmsDenied)
            ));
        }
    }

    #[tokio::test]
    async fn kms_refusals_reach_real_inference_media_and_companion_handlers() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock)
            .await;
        let mut registry = crate::providers::ProviderRegistry::new().unwrap();
        registry
            .set_compat_base_url_for_test("openai", mock.uri())
            .unwrap();
        registry.anthropic = crate::providers::AnthropicProvider::for_base_url(mock.uri()).unwrap();
        registry.google = crate::providers::GoogleProvider::for_base_url(mock.uri()).unwrap();
        let state = test_state(registry);
        let claims = crate::auth::Claims {
            tenant_id: tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::new_v4()),
            key_scope: crate::auth::scope::KeyScope::Scoped(
                [
                    crate::auth::scope::Scope::Chat,
                    crate::auth::scope::Scope::Read,
                    crate::auth::scope::Scope::Passthrough,
                ]
                .into_iter()
                .collect(),
            ),
            ..crate::auth::dev_stub_claims(crate::auth::AuthMethod::JwtBearer)
        };
        crate::files_batches::mark_batch_validated(
            *claims.tenant_id.as_uuid(),
            "file-fixture",
            None,
            None,
        );
        let _claims = crate::auth::test_claims::Guard::set(claims);
        for (failure, status, code) in [
            (
                KmsError::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "kms_unavailable",
            ),
            (KmsError::Denied, StatusCode::FORBIDDEN, "kms_access_denied"),
        ] {
            FAILURE.scope(failure,async {
                let app=Router::new()
                    .route("/v1/chat/completions",post(crate::server::chat_completions_handler))
                    .route("/v1/embeddings",post(crate::server::embeddings_handler))
                    .route("/v1/messages",post(crate::anthropic_messages::messages_handler))
                    .route("/v1/messages/count_tokens",post(crate::anthropic_messages::count_tokens_handler))
                    .route("/v1/responses",post(crate::openai_responses::responses_handler))
                    .route("/v1/responses/input_tokens",post(crate::openai_responses::input_tokens_handler))
                    .route("/v1/images/generations",post(crate::media_routes::images_generations_handler))
                    .route("/v1/audio/speech",post(crate::media_routes::audio_speech_handler))
                    .route("/v1/moderations",post(crate::media_routes::moderations_handler))
                    .route("/v1/files",get(crate::files_batches::files_list_handler))
                    .route("/v1/batches",get(crate::files_batches::batches_list_handler).post(crate::files_batches::batches_create_handler))
                    .route("/v1/passthrough/{provider}/{*path}",any(crate::passthrough::passthrough_handler))
                    .with_state(state.clone());
                for (method,path,doc) in [
                    (Method::POST,"/v1/chat/completions",json!({"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"max_tokens":5})),
                    (Method::POST,"/v1/embeddings",json!({"model":"text-embedding-3-small","input":"hi"})),
                    (Method::POST,"/v1/messages",json!({"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}],"max_tokens":5})),
                    (Method::POST,"/v1/messages/count_tokens",json!({"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}]})),
                    (Method::POST,"/v1/responses",json!({"model":"gpt-4o","input":"hi","max_output_tokens":5})),
                    (Method::POST,"/v1/responses/input_tokens",json!({"model":"gpt-4o","input":"hi"})),
                    (Method::POST,"/v1/images/generations",json!({"model":"gpt-image-1","prompt":"hi"})),
                    (Method::POST,"/v1/audio/speech",json!({"model":"tts-1","input":"hi","voice":"alloy"})),
                    (Method::POST,"/v1/moderations",json!({"model":"omni-moderation-latest","input":"hi"})),
                    (Method::GET,"/v1/files",json!({})),
                    (Method::GET,"/v1/batches",json!({})),
                    (Method::POST,"/v1/batches",json!({"input_file_id":"file-fixture","endpoint":"/v1/chat/completions","completion_window":"24h"})),
                    (Method::POST,"/v1/passthrough/openai/v1/responses",json!({"model":"gpt-4o","input":"hi"})),
                ] {
                    let req=Request::builder().method(method).uri(path).header("authorization","Bearer unit-test").header("content-type","application/json").body(Body::from(doc.to_string())).unwrap();
                    let response=app.clone().oneshot(req).await.unwrap();
                    assert_eq!(response.status(),status,"{path}: {}",body_json(response).await);
                    if failure==KmsError::Unavailable{assert_eq!(response.headers()["retry-after"],"5","{path}");}
                    assert!(body_json(response).await.to_string().contains(code),"{path}");
                }
                let (content_type, bytes) = crate::media_common::test_support::multipart(&[("purpose",None,b"assistants"),("file",Some("fixture.txt"),b"hi")]);
                let mut headers=authed();headers.insert("content-type",content_type.parse().unwrap());
                let response=crate::files_batches::files_upload_handler(State(state.clone()),headers,Body::from(bytes)).await;
                assert_eq!(response.status(),status,"files upload: {}",body_json(response).await);
                assert!(body_json(response).await.to_string().contains(code));
                for action in ["generateContent","countTokens"] {
                    let response=crate::gemini_native::model_action_handler(State(state.clone()),Path(format!("gemini-2.5-flash:{action}")),RawQuery(None),authed(),Bytes::from(json!({"contents":[{"role":"user","parts":[{"text":"hi"}]}]}).to_string())).await;
                    assert_eq!(response.status(),status,"{action}: {}",body_json(response).await);
                    if failure==KmsError::Unavailable{assert_eq!(response.headers()["retry-after"],"5");}
                    assert!(body_json(response).await.to_string().contains(code));
                }
            }).await;
        }
        let providers = std::sync::Arc::clone(&state.providers);
        let engine = crate::prompt_eval::PromptEvalEngine::new(
            clickhouse::Client::default(),
            providers,
            std::sync::Arc::new(crate::prompt_router::PromptRouter::new()),
            None,
        );
        let caller = crate::auth::dev_stub_claims(crate::auth::AuthMethod::JwtBearer);
        let case = serde_json::from_value(
            json!({"name":"fixture","messages":[{"role":"user","content":"hi"}]}),
        )
        .unwrap();
        for (failure, code) in [
            (KmsError::Unavailable, "kms_unavailable"),
            (KmsError::Denied, "kms_access_denied"),
        ] {
            let result = FAILURE
                .scope(
                    failure,
                    engine.execute_case(
                        &caller,
                        "gpt-4o",
                        "",
                        &case,
                        uuid::Uuid::new_v4(),
                        None,
                        crate::prompt_eval::EvalSpanRole::Judge,
                    ),
                )
                .await;
            assert_eq!(result.expect_err("KMS refusal").to_string(), code);
        }
        assert!(mock.received_requests().await.unwrap().is_empty());
    }
}

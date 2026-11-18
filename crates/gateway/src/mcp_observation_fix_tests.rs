use super::*;
use crate::{
    auth::{AuthMethod, Claims},
    entitlement_cache::{EntitlementCache, ResolvedEntitlements},
    handler_harness::{LoopbackBypassGuard, test_state},
    providers::ProviderRegistry,
};
use std::sync::Arc;
use tower::ServiceExt;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

fn fixture(url: &str) -> (AppState, Claims) {
    crate::tool_fingerprint::init_from_existing_pepper(&"07".repeat(32)).unwrap();
    let claims = Claims {
        tenant_id: tracelane_shared::TenantId::from_jwt_claim(Uuid::new_v4()),
        sub: format!("apikey:{}", Uuid::new_v4()),
        key_scope: crate::auth::scope::KeyScope::Scoped([crate::auth::scope::Scope::Mcp].into()),
        ..crate::auth::dev_stub_claims(AuthMethod::ApiKey)
    };
    let server = serde_json::from_value(json!({
        "id":Uuid::new_v4(), "slug":"fixture", "name":"Fixture", "url":url,
        "transport":"streamable_http", "auth_mode":"none", "credential_kind":"bearer",
        "credential_header":null, "credential_ct":null, "credential_last4":null, "enabled":true
    }))
    .unwrap();
    let snapshot = Snapshot {
        kms: None,
        kms_revision: 0,
        servers: vec![server],
        policy: Default::default(),
        rules: vec![],
        model_rules: vec![],
        approval_settings: crate::mcp_store::ApprovalSettings {
            require_second_approver: false,
            default_ttl_secs: mcp_policy::settings().unwrap().approvals.default_ttl_secs,
        },
        approved: Default::default(),
    };
    let mut ent = ResolvedEntitlements::deny_all();
    ent.mcp = Some(Arc::new(snapshot));
    let mut state = test_state(ProviderRegistry::new().unwrap());
    state.entitlements = Some(Arc::new(EntitlementCache::new(Arc::new(move |_| {
        let ent = ent.clone();
        Box::pin(async move { Ok(ent) })
    }))));
    (state, claims)
}

#[tokio::test]
async fn mcp_protocol_version_cannot_capture_query_credentials() {
    let _ssrf = LoopbackBypassGuard::new();
    let upstream = MockServer::start().await;
    let expected = json!({"jsonrpc":"2.0","id":1,"result":{}});
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&expected))
        .mount(&upstream)
        .await;
    for version in [
        "https://example.test/?access_token=PROTOCOL_SECRET_CANARY",
        "Bearer PROTOCOL_SECRET_CANARY",
        "2025-03-26?token=PROTOCOL_SECRET_CANARY",
        "2025-03-26",
    ] {
        let (state, claims) = fixture(&upstream.uri());
        let tenant = claims.tenant_id.clone();
        let _auth = crate::auth::test_claims::Guard::set(claims);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/mcp/fixture")
            .header("authorization", "Bearer fixture")
            .header("mcp-protocol-version", version)
            .body(Body::from(
                json!({"jsonrpc":"2.0","id":1,"method":"ping"}).to_string(),
            ))
            .unwrap();
        let response = router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), expected);
        let spans = crate::otlp_emit::test_sink::for_tenant(&tenant);
        assert_eq!(
            spans.len(),
            1,
            "successful identified request emits one span"
        );
        let bytes = serde_json::to_string(&spans[0]).unwrap();
        assert!(
            !bytes.contains("PROTOCOL_SECRET_CANARY"),
            "protocol metadata leaked: {version}"
        );
        if version == "2025-03-26" {
            assert_eq!(spans[0].attributes.extra["mcp.protocol.version"], version);
        } else {
            assert!(
                !spans[0]
                    .attributes
                    .extra
                    .contains_key("mcp.protocol.version")
            );
        }
    }
}

#[test]
fn mcp_escaped_input_and_output_fit_nats_payload() {
    let (state, claims) = fixture("https://example.test");
    let tenant = claims.tenant_id.clone();
    let span = crate::server::build_gateway_span(
        &tenant,
        Uuid::new_v4(),
        None,
        "",
        &crate::server::CallerIdentity::default(),
        chrono::Utc::now(),
        0,
        0,
        None,
        crate::server::SpanUsageMeta::default(),
        None,
        None,
        None,
        claims.api_key_id(),
    );
    let cap = mcp_policy::settings().unwrap().spans.max_content_bytes;
    let mut mcp = McpSpan {
        state,
        span: Some(span),
        publish: true,
        capture: crate::server::config::ContentCapture {
            input: true,
            output: true,
            max_field_bytes: cap,
        },
        completed: false,
    };
    // Both content fields are stored as JSON strings, then escaped a second time
    // in the span envelope. Plain repeated ASCII cannot reveal this boundary.
    let mut args = json!({"text":"\\".repeat(cap)}).to_string();
    crate::server::store_safe(&mut args, mcp_capture_cap(mcp.capture).unwrap());
    mcp.span
        .as_mut()
        .unwrap()
        .attributes
        .gen_ai_tool_call_arguments = Some(args);
    mcp.capture_result(&json!({"result":{"text":"\\".repeat(cap)}}));
    mcp.finish(None);
    drop(mcp);
    let spans = crate::otlp_emit::test_sink::for_tenant(&tenant);
    assert_eq!(
        spans.len(),
        1,
        "oversize capture must not lose the whole span"
    );
    let bytes = serde_json::to_vec(&spans[0]).unwrap();
    assert!(
        bytes.len() < 1_048_576,
        "{} serialized bytes exceed NATS max_payload",
        bytes.len()
    );
    assert!(spans[0].attributes.gen_ai_tool_call_arguments.is_some());
    assert!(spans[0].attributes.gen_ai_tool_call_result.is_some());
    assert_eq!(
        spans[0].attributes.extra["tracelane.mcp.result_truncated"],
        true
    );
}

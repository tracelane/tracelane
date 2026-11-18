//! Fresh-review reproductions through real admission, MCP handlers and disposable Postgres.
use super::*;

async fn initialize(f: &Fixture) -> Response {
    crate::mcp_proxy::router(f.state.clone())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/mcp/review")
                .header("authorization", "Bearer test-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn require_model(f: &Fixture, pattern: &str) {
    f.pool
        .get()
        .await
        .unwrap()
        .execute(
            "INSERT INTO approval_rules(tenant_id,model_glob,created_by) VALUES($1,$2,'fix-test')",
            &[f.tenant.as_uuid(), &pattern],
        )
        .await
        .unwrap();
    f.state
        .entitlements
        .as_ref()
        .unwrap()
        .invalidate(*f.tenant.as_uuid())
        .await;
}

fn require_pending<R: crate::admission::Route>(
    result: Result<crate::admission::Admitted<R>, crate::admission::Refusal>,
) {
    match result {
        Err(crate::admission::Refusal::Control(d)) => assert_eq!(d.code, "approval_required"),
        Err(other) => panic!("request did not reach the approval boundary: {other:?}"),
        Ok(mut admitted) => {
            admitted.dispatch_guard.disarm();
            panic!("request admitted without its required approval")
        }
    }
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn mcp_scope_removed_during_hold_never_consumes_or_dispatches() {
    let _loopback = LoopbackBypassGuard::new();
    let f = Fixture::new("none").await;
    let caller = f.key_principal("creator").await;
    let key = Uuid::parse_str(caller.api_key_id().unwrap()).unwrap();
    let _initial_auth = crate::auth::test_claims::Guard::set(caller.clone());
    f.prove_allowed_path().await;
    let request = f.call("delete_current", "session-a", "Bearer account-a", None);
    let change = async {
        let approval = f.pending().await;
        f.pool
            .get()
            .await
            .unwrap()
            .execute(
                "UPDATE api_keys SET scope=ARRAY['chat'] WHERE tenant_id=$1 AND id=$2",
                &[f.tenant.as_uuid(), &key],
            )
            .await
            .unwrap();
        let mut current = caller.clone();
        current.key_scope = crate::auth::scope::KeyScope::from_column(Some(&["chat".into()]));
        // This existing authentication seam now returns the persisted, reduced grant.
        // Keep the guard alive in join!'s output until the held request finishes.
        let current_auth = crate::auth::test_claims::Guard::set(current);
        f.approve(approval).await;
        (approval, current_auth)
    };
    let (response, (approval, _current_auth)) =
        tokio::time::timeout(Duration::from_secs(15), async {
            tokio::join!(request, change)
        })
        .await
        .expect("approval decision wakes held request");
    let status = response.status();
    assert_eq!(
        f.destructive_calls().await,
        0,
        "scope-removed key dispatched: {status}"
    );
    assert_eq!(
        f.status(approval).await,
        "approved",
        "invalid caller must not spend the grant"
    );
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn model_approval_cannot_follow_retargeted_workspace_alias() {
    let mut f = Fixture::new("none").await;
    require_model(&f, "gpt-*").await;
    let target = Arc::new(parking_lot::Mutex::new("gpt-4o-mini".to_owned()));
    let resolver_target = target.clone();
    let pool = f.pool.clone();
    f.state.entitlements = Some(Arc::new(EntitlementCache::new(Arc::new(move |tenant| {
        let target = resolver_target.lock().clone();
        let pool = pool.clone();
        Box::pin(async move {
            let client = pool.get().await?;
            let mut ent = ResolvedEntitlements::deny_all();
            ent.mcp = Some(crate::mcp_store::load(&client, &tenant).await?);
            ent.model_aliases = Arc::new([("friendly".to_owned(), target)].into());
            Ok(ent)
        })
    }))));
    let caller = principal(&f.tenant);
    let body = json!({"model":"friendly","messages":[{"role":"user","content":"same request"}]});
    require_pending(
        crate::admission::admit_with_claims::<crate::admission::Chat>(
            &f.state,
            &HeaderMap::new(),
            body.clone(),
            caller.clone(),
        )
        .await,
    );
    let approval = f.pending().await;
    f.approve(approval).await;
    *target.lock() = "gpt-4o".to_owned();
    f.state
        .entitlements
        .as_ref()
        .unwrap()
        .invalidate(*f.tenant.as_uuid())
        .await;
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-tracelane-approval-id",
        approval.to_string().parse().unwrap(),
    );
    let result = crate::admission::admit_with_claims::<crate::admission::Chat>(
        &f.state, &headers, body, caller,
    )
    .await;
    if let Ok(mut admitted) = result {
        admitted.dispatch_guard.disarm();
    }
    assert_eq!(
        f.status(approval).await,
        "approved",
        "retargeted alias consumed another model's grant"
    );
    assert!(f.upstream.received_requests().await.unwrap().is_empty());
}

fn audio_intake(file: &[u8]) -> crate::media_routes::Intake {
    let (content_type, raw) = crate::media_common::test_support::multipart(&[
        ("model", None, b"whisper-1"),
        ("file", Some("recording.wav"), file),
    ]);
    let form = crate::media_common::scan_form(
        &raw,
        &content_type,
        crate::media_common::scan_caps(&crate::providers::translation_policy::media_limits()),
    )
    .unwrap();
    crate::media_routes::Intake {
        raw: raw.into(),
        content_type,
        form: Some(form),
    }
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn model_approval_cannot_authorize_different_audio_bytes() {
    let f = Fixture::new("none").await;
    require_model(&f, "whisper-1").await;
    let caller = principal(&f.tenant);
    require_pending(
        crate::admission::admit_with_claims::<crate::media_routes::AudioTranscriptions>(
            &f.state,
            &HeaderMap::new(),
            audio_intake(b"approved recording"),
            caller.clone(),
        )
        .await,
    );
    let approval = f.pending().await;
    f.approve(approval).await;
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-tracelane-approval-id",
        approval.to_string().parse().unwrap(),
    );
    let result = crate::admission::admit_with_claims::<crate::media_routes::AudioTranscriptions>(
        &f.state,
        &headers,
        audio_intake(b"different recording"),
        caller,
    )
    .await;
    if let Ok(mut admitted) = result {
        admitted.dispatch_guard.disarm();
    }
    assert_eq!(
        f.status(approval).await,
        "approved",
        "changed file bytes consumed the original grant"
    );
    assert!(f.upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn model_approval_accepts_identical_audio_with_new_multipart_boundary() {
    let f = Fixture::new("none").await;
    require_model(&f, "whisper-1").await;
    let caller = principal(&f.tenant);
    require_pending(
        crate::admission::admit_with_claims::<crate::media_routes::AudioTranscriptions>(
            &f.state,
            &HeaderMap::new(),
            audio_intake(b"same recording"),
            caller.clone(),
        )
        .await,
    );
    let id = f.pending().await;
    f.approve(id).await;
    let mut retry = audio_intake(b"same recording");
    retry.content_type = retry.content_type.replace("TLBOUNDARY7", "RETRY_BOUNDARY8");
    retry.raw = bytes::Bytes::from(
        String::from_utf8(retry.raw.to_vec())
            .unwrap()
            .replace("TLBOUNDARY7", "RETRY_BOUNDARY8"),
    );
    retry.form = Some(
        crate::media_common::scan_form(
            &retry.raw,
            &retry.content_type,
            crate::media_common::scan_caps(&crate::providers::translation_policy::media_limits()),
        )
        .unwrap(),
    );
    let mut headers = HeaderMap::new();
    headers.insert("x-tracelane-approval-id", id.to_string().parse().unwrap());
    let mut admitted = crate::admission::admit_with_claims::<
        crate::media_routes::AudioTranscriptions,
    >(&f.state, &headers, retry, caller)
    .await
    .unwrap_or_else(|err| panic!("identical audio retry refused: {err:?}"));
    admitted.dispatch_guard.disarm();
    assert_eq!(f.status(id).await, "consumed");
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn model_approval_preserves_boundary_like_binary_content() {
    let first = audio_intake(b"prefix\n--TLBOUNDARY7\r\nsuffix");
    let mut changed = audio_intake(b"prefix\n--TLBOUNDARY7\r\nsuffix");
    changed.content_type = changed
        .content_type
        .replace("TLBOUNDARY7", "RETRY_BOUNDARY8");
    changed.raw = bytes::Bytes::from(
        String::from_utf8(changed.raw.to_vec())
            .unwrap()
            .replace("TLBOUNDARY7", "RETRY_BOUNDARY8"),
    );
    changed.form = Some(
        crate::media_common::scan_form(
            &changed.raw,
            &changed.content_type,
            crate::media_common::scan_caps(&crate::providers::translation_policy::media_limits()),
        )
        .unwrap(),
    );
    rejects_changed_model_payload::<crate::media_routes::AudioTranscriptions>(
        "whisper-1",
        first,
        changed,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn model_approval_cannot_be_bypassed_by_unknown_batch_file() {
    let f = Fixture::new("none").await;
    require_model(&f, "gpt-*").await;
    let body=crate::files_batches::BatchIntake {raw:bytes::Bytes::from(json!({"input_file_id":"file-before-rule","endpoint":"/v1/chat/completions","completion_window":"24h"}).to_string()),provider_id:"openai"};
    let outcome = crate::admission::admit_with_claims::<crate::files_batches::BatchesCreate>(
        &f.state,
        &HeaderMap::new(),
        body,
        principal(&f.tenant),
    )
    .await;
    match outcome {
        Err(crate::admission::Refusal::Control(d)) => assert_eq!(d.code, "approval_unenforceable"),
        Err(other) => panic!("request did not reach approval boundary: {other:?}"),
        Ok(mut admitted) => {
            admitted.dispatch_guard.disarm();
            panic!("batch with unknown models bypassed current approval rule");
        }
    }
    assert!(f.upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn model_approval_is_required_for_each_batch_execution() {
    let f = Fixture::new("none").await;
    let caller = principal(&f.tenant);
    crate::files_batches::mark_batch_validated(
        *f.tenant.as_uuid(),
        "file-approved-upload",
        None,
        None,
    );
    crate::files_batches::note_batch_models(
        *f.tenant.as_uuid(),
        "file-approved-upload",
        &["gpt-4o-mini".into()],
    );
    require_model(&f, "gpt-*").await;
    let body = || {
        crate::files_batches::BatchIntake {raw:bytes::Bytes::from(json!({"input_file_id":"file-approved-upload","endpoint":"/v1/chat/completions","completion_window":"24h"}).to_string()),provider_id:"openai"}
    };
    require_pending(
        crate::admission::admit_with_claims::<crate::files_batches::BatchesCreate>(
            &f.state,
            &HeaderMap::new(),
            body(),
            caller.clone(),
        )
        .await,
    );
    let id = f.pending().await;
    f.approve(id).await;
    let mut headers = HeaderMap::new();
    headers.insert("x-tracelane-approval-id", id.to_string().parse().unwrap());
    let mut admitted = crate::admission::admit_with_claims::<crate::files_batches::BatchesCreate>(
        &f.state,
        &headers,
        body(),
        caller.clone(),
    )
    .await
    .unwrap_or_else(|err| panic!("approved batch refused: {err:?}"));
    admitted.dispatch_guard.disarm();
    assert_eq!(f.status(id).await, "consumed");
    require_pending(
        crate::admission::admit_with_claims::<crate::files_batches::BatchesCreate>(
            &f.state,
            &HeaderMap::new(),
            body(),
            caller,
        )
        .await,
    );
    assert_ne!(f.pending().await, id);
    assert!(f.upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn mcp_registration_rejects_url_query_credentials_without_storing_them() {
    let _loopback = LoopbackBypassGuard::new();
    let f = Fixture::new("none").await;
    let caller = principal(&f.tenant);
    for key in [
        "access_token",
        "api_key",
        "key",
        "token",
        "secret",
        "sig",
        "password",
        "ACCESS_TOKEN",
    ] {
        let (status, body) = control_as(
            &f.state, &caller, Method::POST, "/v1/mcp-servers",
            json!({"slug":"query-credential","name":"Query credential","url":format!("{}?{key}=unit-sensitive-query-token", f.upstream.uri()),"auth_mode":"none"}),
        ).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "credential-bearing URL accepted: {body}"
        );
        assert!(!body.to_string().contains("unit-sensitive-query-token"));
    }
    let count: i64 = f
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT count(*) FROM mcp_servers WHERE tenant_id=$1 AND slug='query-credential'",
            &[f.tenant.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0, "credential-bearing URL persisted");
    assert!(f.upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
#[ignore = "requires disposable local Postgres; installs the shared test BYOK master"]
async fn mcp_invalid_session_cannot_trigger_credentialed_pin_discovery() {
    invalid_session_discovery(false).await;
}

#[tokio::test]
#[ignore = "requires disposable local Postgres; installs the shared test BYOK master"]
async fn mcp_missing_legacy_session_cannot_trigger_credentialed_pin_discovery() {
    invalid_session_discovery(true).await;
}

async fn invalid_session_discovery(legacy_missing: bool) {
    let _loopback = LoopbackBypassGuard::new();
    init_master_for_security_tests();
    let f = Fixture::new("none").await;
    let caller = principal(&f.tenant);
    let patched = control_as(
        &f.state,
        &caller,
        Method::PATCH,
        &format!("/v1/mcp-servers/{}", f.server),
        json!({"auth_mode":"gateway_held","credential":"unit-secret-pin-discovery"}),
    )
    .await;
    assert_eq!(
        patched.0,
        StatusCode::OK,
        "fixture credential setup: {}",
        patched.1
    );
    let hash = crate::guardrail::capability::def_hash("read", &json!({"type":"object"}), "Read")
        .to_hex()
        .to_string();
    let client = f.pool.get().await.unwrap();
    if legacy_missing {
        client
            .execute(
                "UPDATE mcp_servers SET transport='legacy_sse' WHERE tenant_id=$1 AND id=$2",
                &[f.tenant.as_uuid(), &f.server],
            )
            .await
            .unwrap();
    }
    client
        .execute(
            "UPDATE mcp_policy SET pins_mode='enforce' WHERE tenant_id=$1",
            &[f.tenant.as_uuid()],
        )
        .await
        .unwrap();
    client.execute("INSERT INTO mcp_tool_defs(tenant_id,server_id,tool_name,def_hash,status) VALUES($1,$2,'read',$3,'approved')", &[f.tenant.as_uuid(), &f.server, &hash]).await.unwrap();
    drop(client);
    f.state
        .entitlements
        .as_ref()
        .unwrap()
        .invalidate(*f.tenant.as_uuid())
        .await;
    let _auth = crate::auth::test_claims::Guard::set(caller);
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/v1/mcp/review")
        .header("authorization", "Bearer test-token")
        .header("content-type", "application/json");
    if !legacy_missing {
        request = request.header("mcp-session-id", Uuid::new_v4().to_string());
    }
    let response = crate::mcp_proxy::router(f.state.clone()).oneshot(
        request
            .body(Body::from(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read","arguments":{}}}).to_string())).unwrap(),
    ).await.unwrap();
    assert!(
        f.upstream.received_requests().await.unwrap().is_empty(),
        "unowned session triggered an outbound request with the stored secret"
    );
    if legacy_missing {
        assert!(!response.status().is_success());
        let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
        assert!(String::from_utf8_lossy(&bytes).contains("mcp_session_required"));
    } else {
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
#[ignore = "requires disposable local Postgres; installs the shared test BYOK master"]
async fn mcp_credential_rotation_reclaims_unusable_session_capacity() {
    let _loopback = LoopbackBypassGuard::new();
    init_master_for_security_tests();
    let f = Fixture::new("none").await;
    let caller = principal(&f.tenant);
    let path = format!("/v1/mcp-servers/{}", f.server);
    let created = control_as(
        &f.state,
        &caller,
        Method::PATCH,
        &path,
        json!({"auth_mode":"gateway_held","credential":"old-session-credential"}),
    )
    .await;
    assert_eq!(created.0, StatusCode::OK, "{}", created.1);
    let _auth = crate::auth::test_claims::Guard::set(caller.clone());
    let maximum = crate::mcp_policy::settings()
        .unwrap()
        .limits
        .max_legacy_sessions_per_workspace;
    let mut old_sessions = Vec::new();
    for _ in 0..maximum {
        let response = initialize(&f).await;
        assert_eq!(response.status(), StatusCode::OK);
        old_sessions.push(
            response.headers()["mcp-session-id"]
                .to_str()
                .unwrap()
                .to_owned(),
        );
        to_bytes(response.into_body(), 65536).await.unwrap();
    }
    let rotated = control_as(
        &f.state,
        &caller,
        Method::PATCH,
        &path,
        json!({"credential":"new-session-credential"}),
    )
    .await;
    assert_eq!(rotated.0, StatusCode::OK, "{}", rotated.1);
    let _current_auth = crate::auth::test_claims::Guard::set(caller);
    let response = initialize(&f).await;
    let status = response.status();
    if let Some(id) = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
    {
        crate::mcp_transport::close(id);
    }
    for id in old_sessions {
        crate::mcp_transport::close(&id);
    }
    let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "rotated credential could not establish a replacement session: {}",
        String::from_utf8_lossy(&bytes)
    );
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn approval_requester_poll_is_private_and_per_key_rate_limited() {
    let f = Fixture::new("none").await;
    let mut caller = f.key_principal("poll-owner").await;
    caller.rate_limit_rpm = Some(1);
    let other = f.key_principal("poll-other").await;
    let id = Uuid::new_v4();
    f.pool.get().await.unwrap().execute(
        "INSERT INTO approvals(id,tenant_id,subject_kind,subject,requester_sub,args_fp,args_bytes,args_preview,expires_at) VALUES($1,$2,'model','test',$3,'poll-fingerprint',1,'PREVIEW_SECRET',clock_timestamp()+interval '1 hour')",
        &[&id, f.tenant.as_uuid(), &caller.sub],
    ).await.unwrap();
    let _access = crate::control_plane::test_overrides::Guard::new(
        Some(Ok(crate::db::admin_security::AdminAccess {
            admin_ip_allowlist: vec!["192.0.2.0/24".into()],
            ..Default::default()
        })),
        None,
        None,
    );
    let path = format!("/v1/approvals/{id}");
    let (status, body) = control_as(&f.state, &caller, Method::GET, &path, json!({})).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "requester polling is data-plane: {body}"
    );
    assert_eq!(body["status"], "pending");
    assert_eq!(body["id"], id.to_string());
    assert_eq!(body.as_object().unwrap().len(), 4);
    assert!(!body.to_string().contains("PREVIEW_SECRET"));
    let (status, body) = control_as(&f.state, &other, Method::GET, &path, json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "approval_not_found");
    let _auth = crate::auth::test_claims::Guard::set(caller);
    let response = crate::mcp_routes::router(f.state.clone())
        .oneshot(
            Request::builder()
                .uri(&path)
                .header("authorization", "Bearer fixture")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers().contains_key("retry-after"));
    let value: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    assert!(value.to_string().contains("rate"));
    assert_eq!(f.status(id).await, "pending");
}

async fn rejects_changed_model_payload<R: crate::admission::Route>(
    pattern: &str,
    first: R::Body,
    changed: R::Body,
) {
    let f = Fixture::new("none").await;
    require_model(&f, pattern).await;
    let caller = principal(&f.tenant);
    require_pending(
        crate::admission::admit_with_claims::<R>(
            &f.state,
            &HeaderMap::new(),
            first,
            caller.clone(),
        )
        .await,
    );
    let id = f.pending().await;
    f.approve(id).await;
    let mut headers = HeaderMap::new();
    headers.insert("x-tracelane-approval-id", id.to_string().parse().unwrap());
    let outcome =
        crate::admission::admit_with_claims::<R>(&f.state, &headers, changed, caller).await;
    let denied = outcome.is_err();
    if let Ok(mut admitted) = outcome {
        admitted.dispatch_guard.disarm();
    }
    assert!(denied, "changed execution payload reused an existing grant");
    assert_eq!(f.status(id).await, "approved");
    assert!(f.upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn model_approval_binds_responses_tool_definitions() {
    let body = |description| {
        bytes::Bytes::from(json!({"model":"gpt-4o-mini","input":"same question","tools":[{"type":"function","name":"send","parameters":{"type":"object"},"description":description}]}).to_string())
    };
    rejects_changed_model_payload::<crate::openai_responses::Responses>(
        "gpt-*",
        body("approved operation"),
        body("different operation"),
    )
    .await;
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn model_approval_binds_gemini_binary_content() {
    let body = |data| {
        crate::gemini_native::GeminiBody {
        model:"gemini-2.0-flash".into(), stream:false, alt_sse:false,
        raw: bytes::Bytes::from(json!({"contents":[{"role":"user","parts":[{"inlineData":{"mimeType":"image/png","data":data}}]}]}).to_string()),
    }
    };
    rejects_changed_model_payload::<crate::gemini_native::Gemini>(
        "gemini-*",
        body("YXBwcm92ZWQ="),
        body("ZGlmZmVyZW50"),
    )
    .await;
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn model_approval_binds_batch_upload_content() {
    let body = |text| {
        let raw = bytes::Bytes::from(json!({"custom_id":"item","method":"POST","url":"/v1/chat/completions","body":{"model":"gpt-4o-mini","messages":[{"role":"user","content":text}]}}).to_string());
        crate::files_batches::FileIntake::Batch {
            data: 0..raw.len(),
            raw,
            content_type: "multipart/form-data; boundary=fixture".into(),
            provider_id: "openai",
            limits: crate::providers::translation_policy::media_limits(),
        }
    };
    rejects_changed_model_payload::<crate::files_batches::FilesUpload>(
        "gpt-*",
        body("approved prompt"),
        body("different prompt"),
    )
    .await;
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn approval_expiring_while_decision_waits_cannot_be_granted() {
    let f = Fixture::new("none").await;
    let id = Uuid::new_v4();
    let owner = principal(&f.tenant);
    let observer = f.pool.get().await.unwrap();
    observer.execute("INSERT INTO approvals(id,tenant_id,subject_kind,subject,requester_sub,args_fp,args_bytes,expires_at) VALUES($1,$2,'model','test','requester','decision-expiry',1,clock_timestamp()+interval '3 seconds')", &[&id,f.tenant.as_uuid()]).await.unwrap();
    let mut locker = f.pool.get().await.unwrap();
    let tx = locker.transaction().await.unwrap();
    tx.batch_execute("LOCK TABLE approval_settings IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let deciding = f.decision(&owner, id, "approve");
    let release = async {
        tokio::time::timeout(Duration::from_secs(2),async {
            loop {
                let waiting:bool=observer.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT require_second_approver%' AND cardinality(pg_blocking_pids(pid))>0)",&[]).await.unwrap().get(0);
                if waiting {break;}
                tokio::task::yield_now().await;
            }
        }).await.expect("decision must wait after reading the unexpired approval");
        tokio::time::timeout(Duration::from_secs(5),async {
            loop {
                let expired:bool=observer.query_one("SELECT expires_at<=clock_timestamp() FROM approvals WHERE tenant_id=$1 AND id=$2",&[f.tenant.as_uuid(),&id]).await.unwrap().get(0);
                if expired {break;}
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.unwrap();
        tx.commit().await.unwrap();
    };
    let ((status, body), ()) = tokio::join!(deciding, release);
    assert_eq!(status, StatusCode::CONFLICT, "expired decision: {body}");
    assert_eq!(f.status(id).await, "pending");
    assert_eq!(f.audit_count(id, "approval.approve").await, 0);
}

#[tokio::test]
#[ignore = "requires disposable local Postgres; installs the shared test BYOK master"]
async fn mcp_stored_credential_is_never_returned_in_upstream_errors() {
    let _loopback = LoopbackBypassGuard::new();
    init_master_for_security_tests();
    let f = Fixture::new("none").await;
    let caller = principal(&f.tenant);
    let secret = "unit-held-error-secret";
    let created = control_as(
        &f.state,
        &caller,
        Method::PATCH,
        &format!("/v1/mcp-servers/{}", f.server),
        json!({"auth_mode":"gateway_held","credential":secret}),
    )
    .await;
    assert_eq!(created.0, StatusCode::OK);
    for (status, rpc) in [(400, false), (500, false), (200, true), (400, true)] {
        f.upstream.reset().await;
        let template = if rpc {
            ResponseTemplate::new(status).set_body_json(json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":secret,"data":{"echo":secret}}}))
        } else {
            ResponseTemplate::new(status).set_body_string(format!("upstream diagnostic {secret}"))
        };
        Mock::given(method("POST"))
            .respond_with(template)
            .mount(&f.upstream)
            .await;
        let response = registered_call(&f.state, &caller, "review").await;
        let actual = response.status();
        let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(!body.contains(secret), "{body}");
        assert!(!body.contains("upstream diagnostic"), "{body}");
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        if rpc {
            assert_eq!(actual.as_u16(), status);
            assert_eq!(value["error"]["message"], "[REDACTED]");
        } else {
            assert_eq!(actual, StatusCode::BAD_GATEWAY);
            assert!(value.get("error").is_some());
        }
        let requests = f.upstream.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0]
                .headers
                .get("authorization")
                .unwrap()
                .to_str()
                .unwrap(),
            format!("Bearer {secret}")
        );
    }
}

#[tokio::test]
#[ignore = "requires disposable local Postgres; installs the shared test BYOK master"]
async fn mcp_sse_event_id_never_echoes_gateway_credential() {
    let _loopback = LoopbackBypassGuard::new();
    init_master_for_security_tests();
    let f = Fixture::new("none").await;
    let caller = principal(&f.tenant);
    let secret = "unit-sse-metadata-canary";
    assert_eq!(
        control_as(
            &f.state,
            &caller,
            Method::PATCH,
            &format!("/v1/mcp-servers/{}", f.server),
            json!({"auth_mode":"gateway_held","credential":secret})
        )
        .await
        .0,
        StatusCode::OK
    );
    f.upstream.reset().await;
    let frames = format!(
        "id: {secret}\nevent: {secret}\ndata: {{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{}}}}\n\nid: clean-id\nevent: message\ndata: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}}\n\n"
    );
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(frames, "text/event-stream"))
        .mount(&f.upstream)
        .await;
    let response = registered_call(&f.state, &caller, "review").await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = String::from_utf8(
        to_bytes(response.into_body(), 65536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(
        !body.contains(secret),
        "SSE metadata echoed held credential: {body}"
    );
    assert!(body.contains("id: clean-id"), "{body}");
    assert!(body.contains("event: message"), "{body}");
    let requests = f.upstream.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].headers["authorization"],
        format!("Bearer {secret}")
    );
}

#[tokio::test]
#[ignore = "requires disposable local Postgres; installs the shared test BYOK master"]
async fn mcp_response_headers_never_echo_gateway_credential() {
    let _loopback = LoopbackBypassGuard::new();
    init_master_for_security_tests();
    let f = Fixture::new("none").await;
    let caller = principal(&f.tenant);
    let secret = "unit-header-canary";
    assert_eq!(
        control_as(
            &f.state,
            &caller,
            Method::PATCH,
            &format!("/v1/mcp-servers/{}", f.server),
            json!({"auth_mode":"gateway_held","credential":secret})
        )
        .await
        .0,
        StatusCode::OK
    );
    for (name, sse) in [
        ("cache-control", false),
        ("content-type", false),
        ("mcp-session-id", false),
        ("content-type", true),
    ] {
        f.upstream.reset().await;
        let mime = if sse {
            "text/event-stream"
        } else {
            "application/json"
        };
        let mime = if name == "content-type" {
            format!("{mime}; echo={secret}")
        } else {
            mime.to_owned()
        };
        let body = if sse {
            format!(
                "data: {}\n\n",
                json!({"jsonrpc":"2.0","id":1,"result":{"text":secret}})
            )
        } else {
            json!({"jsonrpc":"2.0","id":1,"result":{}}).to_string()
        };
        // Wiremock's body MIME overwrites an inserted content-type at response time.
        let mut template = ResponseTemplate::new(200)
            .set_body_raw(body, &mime)
            .insert_header("cache-control", "no-store");
        if name != "content-type" {
            template = template.insert_header(name, secret);
        }
        Mock::given(method("POST"))
            .respond_with(template)
            .mount(&f.upstream)
            .await;
        let _auth = crate::auth::test_claims::Guard::set(caller.clone());
        let response = if name == "mcp-session-id" {
            initialize(&f).await
        } else {
            registered_call(&f.state, &caller, "review").await
        };
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().values().all(|v| !v
                .as_bytes()
                .windows(secret.len())
                .any(|w| w == secret.as_bytes())),
            "{name} echoed held credential: {:?}",
            response.headers()
        );
        if name != "mcp-session-id" {
            assert!(
                response.headers().get(name).is_none(),
                "contaminated {name} must be dropped"
            );
        } // Session IDs are replaced with an opaque gateway handle before forwarding.
        if name != "cache-control" {
            assert_eq!(response.headers()["cache-control"], "no-store");
        }
        let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
        let body: Value = if sse {
            let text = String::from_utf8(bytes.to_vec()).unwrap();
            assert!(!text.contains(secret));
            let event = crate::mcp_proxy::parse_event(text.trim().as_bytes()).unwrap();
            let value: Value = serde_json::from_str(&event.data).unwrap();
            assert_eq!(value["result"]["text"], "[REDACTED]");
            value
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        assert_eq!(body["id"], 1);
        let requests = f.upstream.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].headers["authorization"],
            format!("Bearer {secret}")
        );
    }
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn stale_approval_selector_has_no_side_effects() {
    let f = Fixture::new("none").await;
    let caller = principal(&f.tenant);
    // A real queued event makes the notification assertion discriminating.
    let pg = f.pool.get().await.unwrap();
    pg.execute("INSERT INTO spend_alert_channels (id,tenant_id,kind,name,target,created_by) VALUES (gen_random_uuid(),$1,'email','Test','test@example.invalid','fixture')", &[f.tenant.as_uuid()]).await.unwrap();
    async fn counts(f: &Fixture) -> (i64, i64, i64) {
        let row = f.pool.get().await.unwrap().query_one(
            "SELECT (SELECT count(*) FROM approvals WHERE tenant_id=$1), (SELECT count(*) FROM admin_audit_log WHERE actor_workspace_id=$1), (SELECT count(*) FROM spend_alert_events WHERE tenant_id=$1)", &[f.tenant.as_uuid()]).await.unwrap();
        (row.get(0), row.get(1), row.get(2))
    }
    for status in ["consumed", "denied", "expired", "pending", "approved"] {
        let body = json!({"model":"protected-model","case":status});
        let request = || crate::approvals::Request {
            kind: "model",
            server: None,
            subject: "protected-model",
            rule: None,
            ttl_secs: 900,
            body: &body,
            trace_id: Uuid::new_v4(),
        };
        let create =
            crate::approvals::gate(&f.state, &caller, request(), None, &HeaderMap::new(), None)
                .await
                .unwrap_err();
        assert_eq!(create.code, "approval_required");
        let id: Uuid = pg.query_one("SELECT id FROM approvals WHERE tenant_id=$1 AND status='pending' ORDER BY created_at DESC LIMIT 1", &[f.tenant.as_uuid()]).await.unwrap().get(0);
        pg.execute("UPDATE approvals SET status=$2, expires_at=clock_timestamp()-interval '1 second', grant_expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND id=$3", &[f.tenant.as_uuid(),&status,&id]).await.unwrap();
        let before = counts(&f).await;
        assert!(before.2 > 0, "fixture must enqueue approval notifications");
        let refusal = crate::approvals::gate(
            &f.state,
            &caller,
            request(),
            Some(&id.to_string()),
            &HeaderMap::new(),
            None,
        )
        .await
        .unwrap_err();
        let expected = match status {
            "consumed" => "approval_consumed",
            "denied" => "approval_denied",
            _ => "approval_expired",
        };
        assert_eq!(refusal.code, expected);
        assert_eq!(
            counts(&f).await,
            before,
            "stale {status} selector created lifecycle side effects"
        );
        let persisted: String = pg
            .query_one(
                "SELECT status FROM approvals WHERE tenant_id=$1 AND id=$2",
                &[f.tenant.as_uuid(), &id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(
            persisted, status,
            "selector lookup must not expire or alter its row"
        );
        // Selector-free retry still creates a fresh pending approval.
        let create =
            crate::approvals::gate(&f.state, &caller, request(), None, &HeaderMap::new(), None)
                .await
                .unwrap_err();
        assert_eq!(create.code, "approval_required");
        let before = counts(&f).await;
        let refusal = crate::approvals::gate(
            &f.state,
            &caller,
            request(),
            Some(&id.to_string()),
            &HeaderMap::new(),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(refusal.code, expected);
        assert_eq!(
            counts(&f).await,
            before,
            "old selector must not change replacement"
        );
    }
}

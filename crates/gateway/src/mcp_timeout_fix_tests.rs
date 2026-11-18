// Included inside mcp_proxy::tests::timeout_fix_tests to share handler fixtures.

async fn advance_after_upstream_receives(upstream: &MockServer, duration: Duration) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while upstream.received_requests().await.unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the request must actually reach the hanging upstream");
    tokio::time::pause();
    tokio::time::advance(duration).await;
}

async fn bounded_call<F: std::future::Future>(
    upstream: &MockServer,
    limit: Duration,
    call: F,
) -> F::Output {
    let start = tokio::time::Instant::now();
    let bound = limit + Duration::from_secs(1);
    let (result, ()) = tokio::join!(
        tokio::time::timeout(bound, call),
        advance_after_upstream_receives(upstream, limit),
    );
    let elapsed = start.elapsed();
    tokio::time::resume();
    assert!(
        elapsed <= bound,
        "timeout took {elapsed:?}, bound {bound:?}"
    );
    result.expect("outbound request exceeded the reference timeout plus one second")
}

async fn hanging_upstream(limit: Duration) -> MockServer {
    let upstream = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(limit * 4)
                .set_body_json(json!({"jsonrpc":"2.0","id":1,"result":{}})),
        )
        .mount(&upstream)
        .await;
    upstream
}

#[tokio::test]
async fn mcp_dispatch_hanging_upstream_obeys_reference_timeout() {
    let _ssrf = LoopbackBypassGuard::new();
    let limit = Duration::from_secs(mcp_policy::settings().unwrap().limits.call_timeout_secs);
    let upstream = hanging_upstream(limit).await;
    let (state, claims) = fixture(&upstream.uri());
    let tenant = claims.tenant_id.clone();
    let _auth = crate::auth::test_claims::Guard::set(claims);
    let (status, _, body) =
        bounded_call(&upstream, limit, send(&state, call(), HeaderMap::new())).await;
    assert_eq!(
        status,
        StatusCode::GATEWAY_TIMEOUT,
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert!(String::from_utf8_lossy(&body).contains("upstream_timeout"));
    assert_eq!(upstream.received_requests().await.unwrap().len(), 1);
    let spans = crate::otlp_emit::test_sink::for_tenant(&tenant);
    assert_eq!(spans.len(), 1);
    assert_eq!(
        spans[0].attributes.error_type.as_deref(),
        Some("upstream_timeout")
    );
}

#[tokio::test]
async fn mcp_discover_hanging_upstream_obeys_reference_timeout() {
    let _ssrf = LoopbackBypassGuard::new();
    let limit = Duration::from_millis(mcp_policy::settings().unwrap().policy.verify_timeout_ms);
    let upstream = hanging_upstream(limit).await;
    let (state, claims) = fixture(&upstream.uri());
    let ent = state
        .entitlements
        .as_ref()
        .unwrap()
        .resolved(*claims.tenant_id.as_uuid())
        .await;
    let server = &ent.mcp.as_ref().unwrap().servers[0];
    let result = bounded_call(&upstream, limit, discover(server, None)).await;
    assert_eq!(result, Err("mcp_tool_unverifiable"));
    assert_eq!(upstream.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn mcp_legacy_initial_connection_obeys_call_timeout() {
    let _ssrf = LoopbackBypassGuard::new();
    let limit = Duration::from_secs(mcp_policy::settings().unwrap().limits.call_timeout_secs);
    let upstream = hanging_upstream(limit).await;
    let (state, claims) = fixture_with(&upstream.uri(), |e| {
        Arc::make_mut(e.mcp.as_mut().unwrap()).servers[0].transport = "legacy_sse".into();
    });
    let _auth = crate::auth::test_claims::Guard::set(claims);
    let (status, _, body) = bounded_call(
        &upstream,
        limit,
        send(
            &state,
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
            HeaderMap::new(),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::GATEWAY_TIMEOUT,
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert!(String::from_utf8_lossy(&body).contains("upstream_timeout"));
    let requests = upstream.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method.as_str(), "GET");
}

#[tokio::test]
async fn otel_export_hanging_collector_obeys_reference_timeout() {
    let _ssrf = LoopbackBypassGuard::new();
    let limit = Duration::from_secs(crate::otel_export::config().timeout_secs);
    let upstream = hanging_upstream(limit).await;
    let url = format!("{}/v1/traces", upstream.uri());
    let result = bounded_call(
        &upstream,
        limit,
        crate::otel_export::send_once(&url, &vec![], vec![0], limit),
    )
    .await;
    let failure = result.expect_err("a hanging collector cannot acknowledge the span");
    assert_eq!(failure.class, "timeout");
    assert!(failure.retryable);
    assert_eq!(upstream.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn mcp_unknown_oversize_slug_is_never_stored_verbatim() {
    let _ssrf = LoopbackBypassGuard::new();
    let upstream = MockServer::start().await;
    let (state, claims) = fixture(&upstream.uri());
    let tenant = claims.tenant_id.clone();
    let _auth = crate::auth::test_claims::Guard::set(claims);
    let slug = format!("secret-canary-{}", "x".repeat(10 * 1024));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/v1/mcp/{slug}"))
        .header("authorization", "Bearer fixture")
        .body(Body::from(call().to_string()))
        .unwrap();
    let response = router(state).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("invalid_mcp_server"));
    assert!(upstream.received_requests().await.unwrap().is_empty());
    let spans = crate::otlp_emit::test_sink::for_tenant(&tenant);
    for span in spans {
        assert!(
            !serde_json::to_string(&span)
                .unwrap()
                .contains("secret-canary")
        );
        if let Some(value) = span.attributes.extra.get("tracelane.mcp.server") {
            assert!(
                value.as_str().unwrap().len()
                    <= mcp_policy::settings().unwrap().limits.max_slug_chars
            );
        }
    }
}

#[tokio::test]
async fn mcp_invalid_credential_emits_no_span_for_supplied_trace() {
    let upstream = MockServer::start().await;
    let (state, _) = fixture(&upstream.uri());
    let trace = Uuid::new_v4();
    let traceparent = format!("00-{}-00f067aa0ba902b7-01", trace.simple());
    let expected = crate::trace_context::parse_traceparent(&traceparent).unwrap();
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/mcp/fixture")
        .header("authorization", "Basic invalid-credential")
        .header("traceparent", &traceparent)
        .body(Body::from(call().to_string()))
        .unwrap();
    let response = router(state).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(upstream.received_requests().await.unwrap().is_empty());
    assert!(crate::otlp_emit::test_sink::for_trace(expected.trace_id).is_empty());
}

#[tokio::test]
async fn mcp_authenticated_refusals_emit_one_tenant_span_with_inbound_trace() {
    let upstream = MockServer::start().await;
    let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let expected = crate::trace_context::parse_traceparent(traceparent).unwrap();
    for paused in [true, false] {
        let (state, claims) = fixture_with(&upstream.uri(), |e| {
            if paused {
                Arc::make_mut(&mut e.controls).paused = Some(crate::controls::Pause {
                    at: chrono::Utc::now(),
                    by: None,
                    reason: None,
                });
            } else {
                Arc::make_mut(e.mcp.as_mut().unwrap()).servers[0].enabled = false;
            }
        });
        let tenant = claims.tenant_id.clone();
        let _auth = crate::auth::test_claims::Guard::set(claims);
        let mut headers = HeaderMap::new();
        headers.insert("traceparent", HeaderValue::from_static(traceparent));
        let (status, _, body) = send(&state, call(), headers).await;
        let (expected_status, expected_reason) = if paused {
            (StatusCode::LOCKED, "workspace_paused")
        } else {
            (StatusCode::FORBIDDEN, "mcp_server_disabled")
        };
        assert_eq!(status, expected_status);
        assert!(String::from_utf8_lossy(&body).contains(expected_reason));
        assert!(upstream.received_requests().await.unwrap().is_empty());
        let spans = crate::otlp_emit::test_sink::for_tenant(&tenant);
        assert_eq!(
            spans.len(),
            1,
            "authenticated {expected_reason} refusal must be observable"
        );
        assert_eq!(spans[0].trace_id, expected.trace_id);
        assert_eq!(spans[0].parent_span_id, Some(expected.parent_span_id));
        assert_eq!(
            spans[0].attributes.gen_ai_operation_name.as_deref(),
            Some("execute_tool")
        );
        assert_eq!(
            spans[0].attributes.error_type.as_deref(),
            Some(expected_reason)
        );
    }
}

async fn persisted_timeout_fixture(upstream: &MockServer) -> (AppState, Claims, Uuid) {
    let pool = crate::entitlement_cache::b409_fixture::fresh_migrated_pool().await;
    let (mut state, mut claims) = fixture(&upstream.uri());
    claims.auth_method = AuthMethod::JwtBearer;
    claims.sub = format!("user:{}", Uuid::new_v4());
    claims.key_scope = crate::auth::scope::KeyScope::Scoped([crate::auth::scope::Scope::Mcp].into());
    let id = Uuid::new_v4();
    {
        let pg = pool.get().await.unwrap();
        pg.execute(
            "INSERT INTO tenants(id,workos_org_id,name) VALUES($1,$2,'Timeout fixture')",
            &[
                claims.tenant_id.as_uuid(),
                &format!("org_{}", claims.tenant_id),
            ],
        )
        .await
        .unwrap();
        pg.execute("INSERT INTO mcp_servers(id,tenant_id,slug,name,url,transport,auth_mode) VALUES($1,$2,'fixture','Fixture',$3,'streamable_http','none')", &[&id, claims.tenant_id.as_uuid(), &upstream.uri()]).await.unwrap();
    }
    state.pg = Some(pool.clone());
    state.entitlements = Some(Arc::new(EntitlementCache::new(Arc::new(move |tenant| {
        let pool = pool.clone();
        Box::pin(async move {
            let pg = pool.get().await?;
            let mut ent = ResolvedEntitlements::deny_all();
            ent.mcp = Some(crate::mcp_store::load(&pg, &tenant).await?);
            Ok(ent)
        })
    }))));
    (state, claims, id)
}

#[tokio::test]
#[ignore = "requires disposable POSTGRES_TEST_URL"]
async fn mcp_control_test_hanging_upstream_obeys_reference_timeout() {
    let _ssrf = LoopbackBypassGuard::new();
    let limit = Duration::from_millis(mcp_policy::settings().unwrap().policy.verify_timeout_ms);
    let upstream = hanging_upstream(limit).await;
    let (state, claims, server) = persisted_timeout_fixture(&upstream).await;
    let _auth = crate::auth::test_claims::Guard::set(claims);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/v1/mcp-servers/{server}/test"))
        .header("authorization", "Bearer fixture")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let response = bounded_call(
        &upstream,
        limit,
        crate::mcp_routes::router(state).oneshot(request),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("mcp_tool_unverifiable"));
    assert_eq!(upstream.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
#[ignore = "requires disposable POSTGRES_TEST_URL"]
async fn mcp_approval_refusal_preserves_admission_trace() {
    let _ssrf = LoopbackBypassGuard::new();
    let upstream = MockServer::start().await;
    let (state, claims, server) = persisted_timeout_fixture(&upstream).await;
    let tenant = claims.tenant_id.clone();
    let pool = state.pg.as_ref().unwrap();
    {
        let pg = pool.get().await.unwrap();
        pg.execute("INSERT INTO mcp_policy(tenant_id,rules_mode,updated_by) VALUES($1,'enforce','trace-test')", &[tenant.as_uuid()]).await.unwrap();
        pg.execute("INSERT INTO mcp_tool_rules(tenant_id,server_id,tool_glob,action,created_by) VALUES($1,$2,'read','require_approval','trace-test')", &[tenant.as_uuid(), &server]).await.unwrap();
    }
    let _auth = crate::auth::test_claims::Guard::set(claims);
    let request = send(&state, call(), HeaderMap::new());
    let deny = async {
        let row = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(row) = pool
                    .get()
                    .await
                    .unwrap()
                    .query_opt(
                        "SELECT id,trace_id FROM approvals WHERE tenant_id=$1 AND status='pending'",
                        &[tenant.as_uuid()],
                    )
                    .await
                    .unwrap()
                {
                    break row;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("request reached durable approval gate");
        let id: Uuid = row.get("id");
        let trace: Uuid = row.get("trace_id");
        pool.get().await.unwrap().execute("UPDATE approvals SET status='denied',decided_by='independent-reviewer',decided_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2", &[tenant.as_uuid(), &id]).await.unwrap();
        crate::approvals::wake(id);
        trace
    };
    let ((status, _, body), trace) = tokio::join!(request, deny);
    assert_eq!(status, StatusCode::OK);
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["result"]["isError"], true);
    assert!(upstream.received_requests().await.unwrap().is_empty());
    let spans = crate::otlp_emit::test_sink::for_tenant(&tenant);
    assert_eq!(spans.len(), 1);
    assert_eq!(
        spans[0].attributes.error_type.as_deref(),
        Some("approval_denied")
    );
    assert_eq!(
        spans[0].trace_id, trace,
        "approval row and refusal span must share admission's trace"
    );
}

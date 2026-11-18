//! Quality proofs through real authentication, Postgres protocol traffic, and handlers.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Startup globals and bounded process-wide stores need a fresh process, not a
/// test-only replacement that skips the production paths being measured.
fn isolated(name: &str) -> bool {
    const MARKER: &str = "TRACELANE_FIX_QUALITY_CHILD";
    if std::env::var(MARKER).as_deref() == Ok(name) {
        return false;
    }
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([name, "--ignored", "--nocapture", "--test-threads=1"])
        .env(MARKER, name)
        .output()
        .unwrap();
    let output = String::from_utf8_lossy(&result.stdout);
    let errors = String::from_utf8_lossy(&result.stderr);
    println!("{output}");
    assert!(
        result.status.success(),
        "isolated proof failed: {errors}\n{output}"
    );
    true
}

/// Count actual simple-query and extended-query Execute frames, including pool
/// maintenance SQL. The proxy never records query bodies or authentication bytes.
async fn count_postgres_connection(
    incoming: tokio::net::TcpStream,
    upstream: (String, u16),
    counter: Arc<AtomicUsize>,
) -> std::io::Result<()> {
    let outgoing = tokio::net::TcpStream::connect(upstream).await?;
    let (mut read_client, mut write_client) = incoming.into_split();
    let (mut read_server, mut write_server) = outgoing.into_split();
    let client_to_server = async {
        let startup_len = read_client.read_u32().await?;
        assert!(
            (8..=65536).contains(&startup_len),
            "valid local Postgres startup packet"
        );
        let mut startup = vec![0; startup_len as usize - 4];
        read_client.read_exact(&mut startup).await?;
        write_server.write_u32(startup_len).await?;
        write_server.write_all(&startup).await?;
        loop {
            let tag = read_client.read_u8().await?;
            let len = read_client.read_u32().await?;
            assert!((4..=16777216).contains(&len), "bounded local test packet");
            if matches!(tag, b'Q' | b'E') {
                counter.fetch_add(1, Ordering::SeqCst);
            }
            write_server.write_u8(tag).await?;
            write_server.write_u32(len).await?;
            let mut payload = read_client.take(u64::from(len - 4));
            tokio::io::copy(&mut payload, &mut write_server).await?;
            read_client = payload.into_inner();
        }
        #[allow(unreachable_code)]
        Ok::<(), std::io::Error>(())
    };
    let server_to_client = async {
        tokio::io::copy(&mut read_server, &mut write_client).await?;
        Ok::<(), std::io::Error>(())
    };
    tokio::try_join!(client_to_server, server_to_client)?;
    Ok(())
}

async fn counted_pool(
    pool: &crate::db::DbPool,
) -> (
    crate::db::DbPool,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let original: tokio_postgres::Config =
        std::env::var("POSTGRES_TEST_URL").unwrap().parse().unwrap();
    let host = match original.get_hosts().first().unwrap() {
        tokio_postgres::config::Host::Tcp(host) => host.clone(),
        #[cfg(unix)]
        tokio_postgres::config::Host::Unix(_) => {
            panic!("wire counter requires disposable Postgres TCP URL")
        }
    };
    let port = original.get_ports().first().copied().unwrap_or(5432);
    let db: String = pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT current_database()", &[])
        .await
        .unwrap()
        .get(0);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let counter = Arc::new(AtomicUsize::new(0));
    let mut config = deadpool_postgres::Config::new();
    config.host = Some("127.0.0.1".into());
    config.port = Some(listener.local_addr().unwrap().port());
    config.user = original.get_user().map(str::to_owned);
    config.password = original
        .get_password()
        .map(|p| String::from_utf8(p.to_vec()).unwrap());
    config.dbname = Some(db);
    let counted = config
        .create_pool(
            Some(deadpool_postgres::Runtime::Tokio1),
            tokio_postgres::NoTls,
        )
        .unwrap();
    let observed = counter.clone();
    let task = tokio::spawn(async move {
        while let Ok((incoming, _)) = listener.accept().await {
            let counter = observed.clone();
            let upstream = (host.clone(), port);
            tokio::spawn(async move {
                let _ = count_postgres_connection(incoming, upstream, counter).await;
            });
        }
    });
    (counted, counter, task)
}

async fn authenticated_mcp(
    state: &AppState,
    bearer: &str,
    body: Value,
    session: Option<&axum::http::HeaderValue>,
) -> Response {
    let mut request = Request::builder()
        .method("POST")
        .uri("/v1/mcp/review")
        .header("authorization", bearer)
        .header("content-type", "application/json");
    if let Some(session) = session {
        request = request.header("mcp-session-id", session);
    }
    crate::mcp_proxy::router(state.clone())
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires disposable local Postgres; isolates process-wide startup globals"]
async fn mcp_warm_allow_and_chat_have_zero_postgres_queries() {
    if isolated("mcp_warm_allow_and_chat_have_zero_postgres_queries") {
        return;
    }
    let _loopback = LoopbackBypassGuard::new();
    let mut fixture = Fixture::new("none").await;
    let (pool, counter, proxy) = counted_pool(&fixture.pool).await;
    crate::db::api_keys::init_pepper(&"07".repeat(32)).unwrap();
    let minted = crate::db::api_keys::mint(
        &pool,
        &fixture.tenant,
        "Query counter",
        Some("fixture-owner"),
        crate::db::api_keys::MintOptions {
            scope: Some(vec!["mcp".into(), "chat".into()]),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    crate::db::set_global_pool(pool.clone());
    fixture.state.pg = Some(pool.clone());
    let source = pool.clone();
    fixture.state.entitlements = Some(Arc::new(EntitlementCache::new(Arc::new(move |tenant| {
        let source = source.clone();
        Box::pin(async move {
            let client = source.get().await?;
            let mut ent = ResolvedEntitlements::deny_all();
            ent.mcp = Some(crate::mcp_store::load(&client, &tenant).await?);
            Ok(ent)
        })
    }))));
    let bearer = format!("Bearer {}", minted.raw_key);
    let initialized = authenticated_mcp(
        &fixture.state,
        &bearer,
        json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}),
        None,
    )
    .await;
    assert_eq!(initialized.status(), StatusCode::OK);
    let session = initialized.headers()["mcp-session-id"].clone();
    let init = response_json(initialized).await.1;
    assert_eq!(init["result"], json!({}));
    let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read","arguments":{}}});
    let warmup = response_json(
        authenticated_mcp(&fixture.state, &bearer, body.clone(), Some(&session)).await,
    )
    .await;
    assert_eq!(warmup.0, StatusCode::OK);
    assert_eq!(warmup.1["result"]["content"][0]["text"], "executed");
    assert!(
        counter.load(Ordering::SeqCst) > 0,
        "the counter must observe real setup/auth SQL"
    );
    let before = counter.load(Ordering::SeqCst);
    let auth_before = crate::db::api_keys::auth_cache_counters();
    let allowed =
        response_json(authenticated_mcp(&fixture.state, &bearer, body, Some(&session)).await).await;
    assert_eq!(allowed.0, StatusCode::OK);
    assert_eq!(allowed.1["result"]["content"][0]["text"], "executed");
    let mcp_queries = counter.load(Ordering::SeqCst) - before;
    let auth_after = crate::db::api_keys::auth_cache_counters();
    assert!(
        auth_after.0 >= auth_before.0 + 2,
        "both admission and ensure_fresh must use real cached key lookups"
    );
    assert_eq!(
        mcp_queries, 0,
        "warm MCP tools/call must not query Postgres"
    );

    // The compatibility adapter always requests SSE upstream, even for a
    // buffered caller. A plain completion JSON would yield an empty answer.
    let upstream = MockServer::start().await;
    let frame = json!({
        "id":"chatcmpl-query-counter", "object":"chat.completion.chunk",
        "model":"ollama/llama3", "choices":[{
            "index":0, "delta":{"content":"ok"}, "finish_reason":"stop"
        }],
        "usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}
    });
    Mock::given(method("POST"))
        .and(wiremock::matchers::path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(format!("data: {frame}\n\ndata: [DONE]\n\n")),
        )
        .mount(&upstream)
        .await;
    let mut chat_state = fixture.state.clone();
    chat_state.providers = Arc::new(crate::handler_harness::registry_pointing_ollama_at(
        upstream.uri(),
    ));
    let mut headers = HeaderMap::new();
    headers.insert("authorization", bearer.parse().unwrap());
    let chat_body =
        json!({"model":"ollama/llama3","messages":[{"role":"user","content":"query counter"}]});
    let chat = |headers, body| {
        crate::server::chat_completions_handler(
            axum::extract::State(chat_state.clone()),
            headers,
            axum::Json(body),
        )
    };
    let warmup = response_json(chat(headers.clone(), chat_body.clone()).await).await;
    assert_eq!(warmup.0, StatusCode::OK);
    assert_eq!(
        warmup.1["choices"][0]["message"]["content"], "ok",
        "{}",
        warmup.1
    );
    let before = counter.load(Ordering::SeqCst);
    let allowed = response_json(chat(headers, chat_body).await).await;
    assert_eq!(allowed.0, StatusCode::OK);
    assert_eq!(
        allowed.1["choices"][0]["message"]["content"], "ok",
        "{}",
        allowed.1
    );
    let chat_queries = counter.load(Ordering::SeqCst) - before;
    assert_eq!(chat_queries, 0, "warm chat must not query Postgres");
    assert_eq!(upstream.received_requests().await.unwrap().len(), 2);
    let before = counter.load(Ordering::SeqCst);
    let protected = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_current","arguments":{}}});
    let (approved, ()) = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(
            authenticated_mcp(&fixture.state, &bearer, protected, Some(&session)),
            async {
                let id = fixture.pending().await;
                fixture.approve(id).await;
            }
        )
    })
    .await
    .expect("approved held call completes");
    let approved = response_json(approved).await;
    assert_eq!(approved.0, StatusCode::OK);
    assert_eq!(approved.1["result"]["content"][0]["text"], "executed");
    assert_eq!(fixture.destructive_calls().await, 1);
    let approval_queries = counter.load(Ordering::SeqCst) - before;
    assert!(
        approval_queries > 0,
        "the durable approval path must reach real SQL"
    );
    println!(
        "Q1 real Postgres Execute/simple-query count: warm MCP={mcp_queries}; warm chat={chat_queries}; require_approval={approval_queries} (approver SQL excluded)"
    );
    proxy.abort();
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn approval_viewer_cannot_decide_and_leaves_row_and_audit_unchanged() {
    let _loopback = LoopbackBypassGuard::new();
    let fixture = Fixture::new("none").await;
    let owner = principal(&fixture.tenant);
    let id = fixture.create_pending_for(&owner).await;
    let viewer = Claims {
        role: Some(crate::auth::Role::Viewer),
        sub: "viewer".into(),
        ..owner
    };
    for action in ["approve", "deny"] {
        let response = fixture.decision(&viewer, id, action).await;
        assert_eq!(response.0, StatusCode::FORBIDDEN);
        assert!(response.1.get("error").is_some());
        assert_eq!(fixture.status(id).await, "pending");
        assert_eq!(
            fixture.audit_count(id, &format!("approval.{action}")).await,
            0
        );
    }
    assert_eq!(fixture.destructive_calls().await, 0);
}

#[tokio::test]
#[ignore = "requires disposable local Postgres; isolates process-wide observation store"]
async fn mcp_observation_buffer_never_persists_more_than_reference_cap() {
    if isolated("mcp_observation_buffer_never_persists_more_than_reference_cap") {
        return;
    }
    let fixture = Fixture::new("none").await;
    let claims = principal(&fixture.tenant);
    let snapshot =
        crate::mcp_store::load(&fixture.pool.get().await.unwrap(), fixture.tenant.as_uuid())
            .await
            .unwrap();
    let server = snapshot
        .servers
        .iter()
        .find(|s| s.id == fixture.server)
        .unwrap();
    let cap = crate::mcp_policy::settings()
        .unwrap()
        .policy
        .observer_max_tracked;
    let tools: Vec<_> = (0..=cap).map(|i| json!({"name":format!("bounded_tool_{i}"),"description":"Read data","inputSchema":{"type":"object"}})).collect();
    let mut response = json!({"jsonrpc":"2.0","id":1,"result":{"tools":tools}});
    crate::mcp_inspection::inspect(
        &fixture.state,
        &claims,
        &snapshot,
        server,
        "tools/list",
        &mut response,
    );
    let persisted = crate::mcp_inspection::flush(&fixture.pool).await.unwrap();
    assert_eq!(
        persisted, cap,
        "new observation keys past the cap must be dropped"
    );
    let rows: i64 = fixture
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT count(*) FROM mcp_tool_defs WHERE tenant_id=$1 AND server_id=$2",
            &[fixture.tenant.as_uuid(), &fixture.server],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(rows, i64::try_from(cap).unwrap());
    assert_eq!(
        response["result"]["tools"].as_array().unwrap().len(),
        cap + 1,
        "observation pressure must not discard permitted response data"
    );
    assert_eq!(
        crate::mcp_inspection::flush(&fixture.pool).await.unwrap(),
        0
    );
    println!(
        "Q2 observation cap={cap}; submitted={}; persisted={rows}; drained=0",
        cap + 1
    );
}

#[test]
#[ignore = "isolates the process-wide streamable session store"]
fn mcp_streamable_sessions_total_cap_refuses_without_consuming_a_slot() {
    if isolated("mcp_streamable_sessions_total_cap_refuses_without_consuming_a_slot") {
        return;
    }
    crate::tool_fingerprint::init_from_existing_pepper(&"07".repeat(32)).unwrap();
    let server: crate::mcp_store::Server = serde_json::from_value(json!({
        "id":Uuid::new_v4(),"slug":"bounded","name":"Bounded","url":"https://tools.example.invalid/mcp",
        "transport":"streamable_http","auth_mode":"none","credential_kind":"bearer",
        "credential_header":null,"credential_ct":null,"credential_last4":null,"enabled":true
    })).unwrap();
    let initialize = |claims: &Claims| -> Result<axum::http::HeaderValue, &'static str> {
        let mut response = reqwest::Response::from(
            axum::http::Response::builder()
                .status(200)
                .header("mcp-session-id", "private-upstream-session")
                .body(reqwest::Body::from(""))
                .unwrap(),
        );
        crate::mcp_transport::streamable_response(
            claims,
            crate::mcp_transport::context(&claims.tenant_id, &server, None)?,
            &Method::POST,
            "initialize",
            None,
            &mut response,
        )?;
        Ok(response.headers()["mcp-session-id"].clone())
    };
    let cap = crate::mcp_policy::settings()
        .unwrap()
        .limits
        .max_legacy_sessions_total;
    let mut admitted = Vec::new();
    // Each workspace contributes one session, so only the global bound can refuse.
    for _ in 0..cap {
        let claims = principal(&TenantId::from_jwt_claim(Uuid::new_v4()));
        admitted.push(initialize(&claims).unwrap());
    }
    let overflow = principal(&TenantId::from_jwt_claim(Uuid::new_v4()));
    for _ in 0..10 {
        assert_eq!(initialize(&overflow).unwrap_err(), "mcp_session_capacity");
    }
    let released = admitted.pop().unwrap();
    crate::mcp_transport::close(released.to_str().unwrap());
    // Refused attempts must not leak hidden rows: releasing one slot admits one call.
    admitted.push(initialize(&overflow).unwrap());
    assert_eq!(initialize(&overflow).unwrap_err(), "mcp_session_capacity");
    for token in admitted {
        crate::mcp_transport::close(token.to_str().unwrap());
    }
    let after_cleanup = initialize(&overflow).unwrap();
    crate::mcp_transport::close(after_cleanup.to_str().unwrap());
    println!(
        "Q2 streamable global cap={cap}; ten overflow requests refused; released capacity reusable"
    );
}

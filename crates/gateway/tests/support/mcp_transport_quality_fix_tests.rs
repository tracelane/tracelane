//! RED proofs for legacy transport resource and elapsed-time bounds.
use super::*;
use axum::{
    Json, Router,
    body::Body,
    http::Request,
    routing::{get, post},
};
use futures::{StreamExt, stream::FuturesUnordered};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use tower::ServiceExt;

struct RunningServer(tokio::task::JoinHandle<()>);
impl Drop for RunningServer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn server(url: String) -> Server {
    serde_json::from_value(json!({"id":Uuid::new_v4(),"slug":"quality","name":"Quality","url":url,"transport":"legacy_sse","auth_mode":"none","credential_kind":"bearer","credential_header":null,"credential_ct":null,"credential_last4":null,"enabled":true})).unwrap()
}

async fn peer() -> (Server, Arc<AtomicUsize>, mpsc::Sender<Bytes>, RunningServer) {
    let (events, receive) = mpsc::channel::<Bytes>(8);
    let receive = Arc::new(tokio::sync::Mutex::new(Some(receive)));
    let posts = Arc::new(AtomicUsize::new(0));
    let count_posts = posts.clone();
    let app = Router::new()
        .route("/sse", get(move || {
            let receive = receive.clone();
            async move {
                let mut receive = receive.lock().await.take().unwrap();
                let stream = async_stream::stream! {
                    yield Ok::<_,std::io::Error>(Bytes::from_static(b"event: endpoint\ndata: /messages\n\n"));
                    while let Some(frame) = receive.recv().await { yield Ok(frame); }
                };
                ([("content-type", "text/event-stream")], Body::from_stream(stream))
            }
        }))
        .route("/messages", post(move |Json(_): Json<Value>| {
            count_posts.fetch_add(1, Ordering::SeqCst);
            async { StatusCode::ACCEPTED }
        }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = RunningServer(tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap()
    }));
    (server(format!("http://{address}/sse")), posts, events, task)
}

fn pending_limit() -> usize {
    let reference: Value = serde_json::from_str(include_str!("../../mcp_policy.v1.json")).unwrap();
    reference["limits"]["max_pending_calls_per_session"]
        .as_u64()
        .unwrap_or_else(|| {
            reference["limits"]["max_legacy_sessions_per_workspace"]
                .as_u64()
                .unwrap()
        }) as usize
}

#[tokio::test]
async fn legacy_session_commit_releases_opening_reservation_atomically() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    let (server, _posts, _events, _running) = peer().await;
    let connection = Connection::open(&server, &HeaderMap::new(), None)
        .await
        .unwrap();
    let tenant = Uuid::new_v4();
    let id = Uuid::new_v4();
    opening_sessions().lock().insert(tenant, 1);
    let session = Arc::new(Session {
        tenant,
        caller: "quality".into(),
        context: "quality".into(),
        started: Instant::now(),
        connection,
    });
    commit_opening(id, session, OpeningSession(tenant));
    assert!(opening_sessions().lock().get(&tenant).is_none());
    assert!(sessions().lock().contains_key(&id));
    sessions().lock().remove(&id);
}

#[tokio::test]
async fn legacy_pending_calls_are_bounded_before_upstream_dispatch_and_release_on_drop() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    let (server, posts, _events, _running) = peer().await;
    let headers = HeaderMap::new();
    let connection = Connection::open(&server, &headers, None).await.unwrap();
    let cap = pending_limit();
    let mut replies = Vec::new();
    for id in 0..cap {
        replies.push(connection.rpc(&server, &headers, None,
            &json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"slow","arguments":{}}}),
            async { Ok(()) }).await.unwrap());
    }
    assert_eq!(connection.pending.lock().len(), cap);
    let overflow = connection.rpc(&server, &headers, None,
        &json!({"jsonrpc":"2.0","id":cap,"method":"tools/call","params":{"name":"slow","arguments":{}}}),
        async { Ok(()) }).await;
    let rejected = overflow.is_err();
    let peak_pending = connection.pending.lock().len();
    let dispatched = posts.load(Ordering::SeqCst);
    drop(overflow);
    drop(replies);
    assert_eq!(
        connection.pending.lock().len(),
        0,
        "disconnect must release pending entries"
    );
    assert!(
        rejected,
        "the next outstanding RPC must refuse at the reference-table cap"
    );
    assert_eq!(
        peak_pending, cap,
        "overflow must not allocate another pending entry"
    );
    assert_eq!(dispatched, cap, "overflow must not reach the upstream");
    let replacement = connection
        .rpc(
            &server,
            &headers,
            None,
            &json!({"jsonrpc":"2.0","id":"replacement","method":"ping"}),
            async { Ok(()) },
        )
        .await
        .unwrap();
    assert_eq!(posts.load(Ordering::SeqCst), cap + 1);
    drop(replacement);
    assert!(connection.pending.lock().is_empty());
}

#[tokio::test]
async fn legacy_notifications_do_not_extend_the_total_rpc_deadline() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    let (server, posts, _events, _running) = peer().await;
    let headers = HeaderMap::new();
    let connection = Connection::open(&server, &headers, None).await.unwrap();
    let mut response = connection.rpc(&server, &headers, None,
        &json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"slow","arguments":{}}}),
        async { Ok(()) }).await.unwrap();
    let sender = connection.pending.lock().get("7").unwrap().sender.clone();
    let limit = Duration::from_secs(mcp_policy::settings().unwrap().limits.call_timeout_secs);
    tokio::time::pause();
    let mut first = Box::pin(response.chunk());
    assert!(futures::poll!(first.as_mut()).is_pending());
    tokio::time::advance(limit / 2).await;
    // Inject at the demultiplexer seam; no kernel/network timing runs on the paused clock.
    sender.try_send(Ok(Bytes::from_static(b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n"))).unwrap();
    assert!(first.await.unwrap().is_some());
    let mut second = Box::pin(response.chunk());
    assert!(futures::poll!(second.as_mut()).is_pending());
    tokio::time::advance(limit / 2 + Duration::from_secs(1)).await;
    let outcome = futures::poll!(second.as_mut());
    drop(second);
    drop(response);
    tokio::time::resume();
    assert_eq!(posts.load(Ordering::SeqCst), 1);
    assert!(connection.pending.lock().is_empty());
    assert!(
        matches!(outcome, Poll::Ready(Err(_)) | Poll::Ready(Ok(None))),
        "a progress event reset the call deadline: {outcome:?}"
    );
}

#[tokio::test]
async fn legacy_initialization_reserves_capacity_before_opening_connections() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    crate::tool_fingerprint::init_from_existing_pepper(&"07".repeat(32)).unwrap();
    let entered = Arc::new(AtomicUsize::new(0));
    let received = entered.clone();
    let app = Router::new().route(
        "/sse",
        get(move || {
            received.fetch_add(1, Ordering::SeqCst);
            async {
                // Never advertise an endpoint: every setup stays in Connection::open.
                std::future::pending::<StatusCode>().await
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let _running = RunningServer(tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap()
    }));
    let tenant = tracelane_shared::TenantId::from_jwt_claim(Uuid::new_v4());
    let claims = crate::auth::Claims {
        tenant_id: tenant.clone(),
        sub: format!("quality:{}", Uuid::new_v4()),
        key_scope: crate::auth::scope::KeyScope::Scoped([crate::auth::scope::Scope::Mcp].into()),
        ..crate::auth::dev_stub_claims(crate::auth::AuthMethod::JwtBearer)
    };
    let snapshot = crate::mcp_store::Snapshot {
        kms: None,
        kms_revision: 0,
        servers: vec![server(format!("http://{address}/sse"))],
        policy: Default::default(),
        rules: vec![],
        model_rules: vec![],
        approval_settings: crate::mcp_store::ApprovalSettings {
            require_second_approver: false,
            default_ttl_secs: mcp_policy::settings().unwrap().approvals.default_ttl_secs,
        },
        approved: Default::default(),
    };
    let mut ent = crate::entitlement_cache::ResolvedEntitlements::deny_all();
    ent.mcp = Some(Arc::new(snapshot));
    let mut state =
        crate::handler_harness::test_state(crate::providers::ProviderRegistry::new().unwrap());
    state.entitlements = Some(Arc::new(crate::entitlement_cache::EntitlementCache::new(
        Arc::new(move |_| {
            let ent = ent.clone();
            Box::pin(async move { Ok(ent) })
        }),
    )));
    let _auth = crate::auth::test_claims::Guard::set(claims);
    let router = mcp_proxy::router(state);
    let cap = mcp_policy::settings()
        .unwrap()
        .limits
        .max_legacy_sessions_per_workspace;
    let mut requests = FuturesUnordered::new();
    for id in 0..=cap {
        requests.push(
            router.clone().oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/mcp/quality")
                    .header("authorization", "Bearer fixture")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"jsonrpc":"2.0","id":id,"method":"initialize","params":{}})
                            .to_string(),
                    ))
                    .unwrap(),
            ),
        );
    }
    let mut refusals = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if entered.load(Ordering::SeqCst) > cap || (entered.load(Ordering::SeqCst) == cap && !refusals.is_empty()) { break; }
            tokio::select! {
                response = requests.next() => {
                    let response = response.expect("initialization must remain pending or refuse capacity").unwrap();
                    refusals.push(response.status());
                },
                _ = tokio::time::sleep(Duration::from_millis(1)) => {},
            }
        }
    }).await.expect("all concurrent calls must reach setup or refuse without waiting for upstream");
    let connected = entered.load(Ordering::SeqCst);
    drop(requests);
    assert_eq!(
        connected, cap,
        "unreserved initializations exceeded the workspace connection cap"
    );
    assert_eq!(refusals, vec![StatusCode::TOO_MANY_REQUESTS]);
    assert!(
        sessions()
            .lock()
            .values()
            .all(|s| s.tenant != *tenant.as_uuid()),
        "cancelled initialization retained a live session"
    );
}

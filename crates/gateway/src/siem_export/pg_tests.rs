//! Configuration and durable delivery proof against disposable real PostgreSQL.
use super::*;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use std::sync::Arc;
use tower::ServiceExt;
use tracelane_shared::TenantId;

async fn fixture() -> (
    crate::db::DbPool,
    crate::auth::Claims,
    crate::server::AppState,
) {
    let pool = crate::entitlement_cache::b409_fixture::fresh_migrated_pool().await;
    let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
    crate::db::tenants::create(&pool, *tenant.as_uuid(), "synthetic-siem", "free")
        .await
        .unwrap();
    if crate::byok::master_key().is_none() {
        crate::byok::set_global_master_key(
            crate::byok::ByokMasterKey::from_values(
                Some("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="),
                None,
                None,
            )
            .unwrap()
            .unwrap(),
        );
    }
    let mut claims = crate::auth::dev_stub_claims(crate::auth::AuthMethod::JwtBearer);
    claims.tenant_id = tenant;
    claims.sub = "synthetic-siem-owner".into();
    claims.role = Some(crate::auth::Role::Owner);
    let mut state =
        crate::handler_harness::test_state(crate::providers::ProviderRegistry::new().unwrap());
    state.pg = Some(pool.clone());
    let mut ent = crate::entitlement_cache::ResolvedEntitlements::deny_all();
    ent.f_otel_export = true;
    ent.max_exports = 3;
    state.entitlements = Some(Arc::new(crate::entitlement_cache::EntitlementCache::new(
        Arc::new(move |_| {
            let e = ent.clone();
            Box::pin(async move { Ok(e) })
        }),
    )));
    (pool, claims, state)
}
async fn create(
    state: crate::server::AppState,
    claims: crate::auth::Claims,
    kind: &str,
    url: &str,
) -> (StatusCode, Value) {
    let _auth = crate::auth::test_claims::Guard::set(claims);
    let body = json!({"name":"synthetic SIEM","format":kind,"url":url,"headers":{"authorization":if kind=="splunk" {"Splunk FAKEtestkeyDONOTUSE"}else{"Bearer FAKEtestkeyDONOTUSE"}}});
    let reply = crate::otel_export_routes::router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/exports/otel")
                .header("authorization", "Bearer synthetic")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = reply.status();
    let body = serde_json::from_slice(&to_bytes(reply.into_body(), 65536).await.unwrap()).unwrap();
    (status, body)
}
#[tokio::test]
#[ignore = "requires disposable local Postgres; run serially"]
async fn obs64_pg_configuration() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    let (pool, claims, state) = fixture().await;
    let server = wiremock::MockServer::start().await;
    let (status, body) = create(
        state.clone(),
        claims.clone(),
        "splunk",
        &format!("{}/services/collector/event", server.uri()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["format"], "splunk");
    assert_eq!(body["delivery"], "at_least_once_bounded_retry");
    assert_eq!(body["delivery_scope"], "retained_scanned_records");
    assert_eq!(
        body["delivery_limits"],
        json!(["source_retention", "late_visibility", "retry_exhaustion"])
    );
    assert!(!body.to_string().contains("FAKEtestkeyDONOTUSE"));
    let id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();
    let row = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT format,headers_enc FROM otel_exports WHERE tenant_id=$1 AND id=$2",
            &[claims.tenant_id.as_uuid(), &id],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "splunk");
    let enc: String = row.get(1);
    assert!(!enc.contains("FAKEtestkeyDONOTUSE"));
    let headers = crate::otel_export::open_headers(
        crate::byok::master_key(),
        *claims.tenant_id.as_uuid(),
        id,
        Some(&enc),
    )
    .unwrap();
    assert_eq!(headers.len(), 1);
    assert!(
        crate::otel_export::open_headers(crate::byok::master_key(), Uuid::new_v4(), id, Some(&enc))
            .is_err()
    );
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "configuration does not deliver records"
    );
}

async fn seed_action(pool: &crate::db::DbPool, tenant: Uuid, seq: i64) -> Uuid {
    let id = Uuid::new_v4();
    let a = json!({"schema_version":1,"tenant_id":tenant,"event_id":id,"action_id":Uuid::new_v4(),"agent_key_id":null,"occurred_at":"2023-11-14T22:13:20Z","request_digest":"synthetic-digest","body":{"event_type":"decision_made","decision":"deny","rule_id":"synthetic","reason_codes":["policy_denied"],"policy_id":Uuid::new_v4(),"policy_version":1,"policy_hash":"synthetic"}});
    pool.get().await.unwrap().execute("INSERT INTO audit_log_rows(tenant_id,seq,event_time,event_type,actor,payload,row_hash) VALUES($1,$2,now(),'decision_made','synthetic',$3,'synthetic')", &[&tenant,&seq,&a.to_string()]).await.unwrap();
    id
}
fn quick_config() -> worker::Config {
    let mut c = worker::Config::default();
    c.delivery.retry_delays = vec![Duration::ZERO];
    c
}
async fn cursor(pool: &crate::db::DbPool, tenant: Uuid, id: Uuid) -> (i64, i32, bool, i64) {
    let r=pool.get().await.unwrap().query_one("SELECT action_cursor,delivery_attempts,enabled,failed FROM otel_exports WHERE tenant_id=$1 AND id=$2", &[&tenant,&id]).await.unwrap();
    (r.get(0), r.get(1), r.get(2), r.get(3))
}
async fn destination(
    pool: &crate::db::DbPool,
    state: &crate::server::AppState,
    claims: &crate::auth::Claims,
    server: &wiremock::MockServer,
) -> Uuid {
    let (status, body) = create(
        state.clone(),
        claims.clone(),
        "splunk",
        &format!("{}/services/collector/event", server.uri()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();
    assert_eq!(cursor(pool, *claims.tenant_id.as_uuid(), id).await.0, -1);
    id
}
#[tokio::test]
#[ignore = "requires disposable local Postgres; run serially"]
async fn obs64_pg_durable_restart() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    let (pool, claims, state) = fixture().await;
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(json!({"code":0})))
        .mount(&server)
        .await;
    let dest = destination(&pool, &state, &claims, &server).await;
    let event = seed_action(&pool, *claims.tenant_id.as_uuid(), 0).await;
    let backlog = worker::tick(&pool, None, state.entitlements.as_ref(), &quick_config())
        .await
        .unwrap();
    assert!(!backlog, "caught up: sleep the full poll");
    assert_eq!(cursor(&pool, *claims.tenant_id.as_uuid(), dest).await.0, 0);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].body_json::<Value>().unwrap()["event"]["id"],
        json!(event)
    );
    worker::tick(
        &pool.clone(),
        None,
        state.entitlements.as_ref(),
        &quick_config(),
    )
    .await
    .unwrap();
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "fresh invocation resumes persisted cursor"
    );
}
#[tokio::test]
#[ignore = "requires disposable local Postgres; run serially"]
async fn obs64_pg_retry_exhausted() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    let (pool, claims, state) = fixture().await;
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let dest = destination(&pool, &state, &claims, &server).await;
    seed_action(&pool, *claims.tenant_id.as_uuid(), 0).await;
    for _ in 0..3 {
        worker::tick(&pool, None, state.entitlements.as_ref(), &quick_config())
            .await
            .unwrap();
    }
    assert_eq!(
        cursor(&pool, *claims.tenant_id.as_uuid(), dest).await,
        (-1, 2, false, 1)
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}
#[tokio::test]
#[ignore = "requires disposable local Postgres; run serially"]
async fn obs64_pg_batch_cursor() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    let (pool, claims, state) = fixture().await;
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(json!({"code":0})))
        .mount(&server)
        .await;
    let dest = destination(&pool, &state, &claims, &server).await;
    for seq in 0..2 {
        seed_action(&pool, *claims.tenant_id.as_uuid(), seq).await;
    }
    let mut c = quick_config();
    c.batch = 1;
    // A full batch is drained again inside the destination budget: one tick, both records.
    worker::tick(&pool, None, state.entitlements.as_ref(), &c)
        .await
        .unwrap();
    assert_eq!(cursor(&pool, *claims.tenant_id.as_uuid(), dest).await.0, 1);
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
    worker::tick(&pool, None, state.entitlements.as_ref(), &c)
        .await
        .unwrap();
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}
#[tokio::test]
#[ignore = "requires disposable local Postgres; run serially"]
async fn obs64_pg_destination_budget_keeps_progress() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    let (pool, claims, state) = fixture().await;
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(250))
                .set_body_json(json!({"code":0})),
        )
        .mount(&server)
        .await;
    let dest = destination(&pool, &state, &claims, &server).await;
    for seq in 0..4 {
        seed_action(&pool, *claims.tenant_id.as_uuid(), seq).await;
    }
    let mut c = quick_config();
    c.destination_budget = Duration::from_millis(400);
    let backlog = worker::tick(&pool, None, state.entitlements.as_ref(), &c)
        .await
        .unwrap();
    assert!(
        backlog,
        "a budget-cut destination asks to be revisited soon"
    );
    let (at, attempts, enabled, failed) = cursor(&pool, *claims.tenant_id.as_uuid(), dest).await;
    let sent = server.received_requests().await.unwrap().len();
    assert!(
        (1..4).contains(&sent),
        "budget must stop the destination early: {sent}"
    );
    assert_eq!(
        at,
        i64::try_from(sent).unwrap() - 1,
        "delivered records are acknowledged"
    );
    assert_eq!((attempts, enabled, failed), (0, true, 0));
}
#[tokio::test]
#[ignore = "requires disposable local Postgres; run serially"]
async fn obs64_pg_undeliverable_record_skipped() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    let (pool, claims, state) = fixture().await;
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(json!({"code":0})))
        .mount(&server)
        .await;
    let dest = destination(&pool, &state, &claims, &server).await;
    let tenant = *claims.tenant_id.as_uuid();
    pool.get().await.unwrap().execute("INSERT INTO audit_log_rows(tenant_id,seq,event_time,event_type,actor,payload,row_hash) VALUES($1,0,now(),'decision_made','synthetic','{\"not\":\"an envelope\"}','synthetic')", &[&tenant]).await.unwrap();
    let good = seed_action(&pool, tenant, 1).await;
    worker::tick(&pool, None, state.entitlements.as_ref(), &quick_config())
        .await
        .unwrap();
    assert_eq!(cursor(&pool, tenant, dest).await, (1, 0, true, 1));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].body_json::<Value>().unwrap()["event"]["id"],
        json!(good)
    );
    let class: Option<String> = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT last_error_class FROM otel_exports WHERE tenant_id=$1 AND id=$2",
            &[&tenant, &dest],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(class.as_deref(), Some("siem_record_skipped"));
}
#[tokio::test]
#[ignore = "requires disposable local Postgres; run serially"]
async fn obs64_pg_slow_destination_does_not_block_other_tenant() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    let (pool, a, state) = fixture().await;
    let mut b = a.clone();
    b.tenant_id = TenantId::from_jwt_claim(Uuid::from_u128(u128::MAX - 1));
    crate::db::tenants::create(&pool, *b.tenant_id.as_uuid(), "synthetic-fast", "free")
        .await
        .unwrap();
    let slow = wiremock::MockServer::start().await;
    let fast = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(1500))
                .set_body_json(json!({"code":0})),
        )
        .mount(&slow)
        .await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(json!({"code":0})))
        .mount(&fast)
        .await;
    destination(&pool, &state, &a, &slow).await;
    destination(&pool, &state, &b, &fast).await;
    seed_action(&pool, *a.tenant_id.as_uuid(), 0).await;
    seed_action(&pool, *b.tenant_id.as_uuid(), 0).await;
    let p = pool.clone();
    let ent = state.entitlements.clone();
    let pending =
        tokio::spawn(async move { worker::tick(&p, None, ent.as_ref(), &quick_config()).await });
    tokio::time::timeout(Duration::from_millis(1000), async {
        while fast.received_requests().await.unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("fast tenant waited behind the slow destination");
    assert!(!pending.is_finished(), "slow destination still in flight");
    pending.await.unwrap().unwrap();
}

#[tokio::test]
#[ignore = "requires disposable local Postgres; run serially"]
async fn obs64_pg_tenant_destinations() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    let (pool, a, state) = fixture().await;
    let mut b = a.clone();
    b.tenant_id = TenantId::from_jwt_claim(Uuid::new_v4());
    crate::db::tenants::create(&pool, *b.tenant_id.as_uuid(), "synthetic-other", "free")
        .await
        .unwrap();
    let sa = wiremock::MockServer::start().await;
    let sb = wiremock::MockServer::start().await;
    for server in [&sa, &sb] {
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(json!({"code":0})))
            .mount(server)
            .await;
    }
    destination(&pool, &state, &a, &sa).await;
    destination(&pool, &state, &b, &sb).await;
    let ea = seed_action(&pool, *a.tenant_id.as_uuid(), 0).await;
    let eb = seed_action(&pool, *b.tenant_id.as_uuid(), 0).await;
    worker::tick(&pool, None, state.entitlements.as_ref(), &quick_config())
        .await
        .unwrap();
    for (server, tenant, event) in [
        (&sa, *a.tenant_id.as_uuid(), ea),
        (&sb, *b.tenant_id.as_uuid(), eb),
    ] {
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let body: Value = requests[0].body_json().unwrap();
        assert_eq!(body["event"]["tenant_id"], json!(tenant));
        assert_eq!(body["event"]["id"], json!(event));
    }
}

async fn patch_destination(
    state: crate::server::AppState,
    claims: crate::auth::Claims,
    id: Uuid,
    body: Value,
) {
    let _auth = crate::auth::test_claims::Guard::set(claims);
    let response = crate::otel_export_routes::router(state)
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/v1/exports/otel/{id}"))
                .header("authorization", "Bearer synthetic")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
#[tokio::test]
#[ignore = "requires disposable local Postgres; run serially"]
async fn obs64_pg_configuration_fences_inflight_completion() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    let (pool, claims, state) = fixture().await;
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(250))
                .set_body_json(json!({"code":0})),
        )
        .mount(&server)
        .await;
    let dest = destination(&pool, &state, &claims, &server).await;
    seed_action(&pool, *claims.tenant_id.as_uuid(), 0).await;
    let p = pool.clone();
    let ent = state.entitlements.clone();
    let pending =
        tokio::spawn(async move { worker::tick(&p, None, ent.as_ref(), &quick_config()).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if !server.received_requests().await.unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("worker did not begin delivery");
    patch_destination(
        state.clone(),
        claims.clone(),
        dest,
        json!({"enabled":false}),
    )
    .await;
    patch_destination(state.clone(), claims.clone(), dest, json!({"enabled":true})).await;
    pending.await.unwrap().unwrap();
    assert_eq!(
        cursor(&pool, *claims.tenant_id.as_uuid(), dest).await.0,
        -1,
        "stale batch must not acknowledge after configuration changes"
    );
    worker::tick(&pool, None, state.entitlements.as_ref(), &quick_config())
        .await
        .unwrap();
    assert_eq!(cursor(&pool, *claims.tenant_id.as_uuid(), dest).await.0, 0);
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}
#[tokio::test]
#[ignore = "requires disposable local Postgres; run serially"]
async fn obs64_pg_lease_token_fences_inflight_completion() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    let (pool, claims, state) = fixture().await;
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(250))
                .set_body_json(json!({"code":0})),
        )
        .mount(&server)
        .await;
    let dest = destination(&pool, &state, &claims, &server).await;
    seed_action(&pool, *claims.tenant_id.as_uuid(), 0).await;
    let p = pool.clone();
    let ent = state.entitlements.clone();
    let pending =
        tokio::spawn(async move { worker::tick(&p, None, ent.as_ref(), &quick_config()).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if !server.received_requests().await.unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("worker did not begin delivery");
    pool.get()
        .await
        .unwrap()
        .execute(
            "UPDATE otel_exports SET lease_token=$3 WHERE tenant_id=$1 AND id=$2",
            &[claims.tenant_id.as_uuid(), &dest, &Uuid::new_v4()],
        )
        .await
        .unwrap();
    pending.await.unwrap().unwrap();
    assert_eq!(cursor(&pool, *claims.tenant_id.as_uuid(), dest).await.0, -1);
}

#[tokio::test]
#[ignore = "requires disposable local Postgres; run serially"]
async fn obs64_pg_request_independent_of_failed_delivery() {
    use crate::handler_harness::{
        authed, body_json, chat_ok_mock, registry_pointing_ollama_at, test_state,
    };
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    let (pool, claims, state) = fixture().await;
    let receiver = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(503).set_delay(Duration::from_secs(2)))
        .mount(&receiver)
        .await;
    let dest = destination(&pool, &state, &claims, &receiver).await;
    seed_action(&pool, *claims.tenant_id.as_uuid(), 0).await;
    let upstream = chat_ok_mock().await;
    let chat = test_state(registry_pointing_ollama_at(upstream.uri()));
    let request =
        json!({"model":"ollama/llama3","messages":[{"role":"user","content":"synthetic"}]});
    let baseline = crate::server::chat_completions_handler(
        axum::extract::State(chat.clone()),
        authed(),
        axum::Json(request.clone()),
    )
    .await;
    assert_eq!(baseline.status(), StatusCode::OK);
    let baseline = body_json(baseline).await;
    let p = pool.clone();
    let ent = state.entitlements.clone();
    let pending =
        tokio::spawn(async move { worker::tick(&p, None, ent.as_ref(), &quick_config()).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while receiver.received_requests().await.unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("worker did not start outbound delivery");
    // A bounded deadline proves the request does not wait for the stalled receiver;
    // this is a scheduling regression assertion, not a production latency benchmark.
    let reply = tokio::time::timeout(
        Duration::from_secs(1),
        crate::server::chat_completions_handler(
            axum::extract::State(chat),
            authed(),
            axum::Json(request),
        ),
    )
    .await
    .unwrap();
    assert_eq!(reply.status(), StatusCode::OK);
    assert_eq!(body_json(reply).await["choices"], baseline["choices"]);
    assert!(!pending.is_finished());
    pending.await.unwrap().unwrap();
    assert_eq!(cursor(&pool, *claims.tenant_id.as_uuid(), dest).await.0, -1);
    assert_eq!(cursor(&pool, *claims.tenant_id.as_uuid(), dest).await.1, 1);
}

#[tokio::test]
#[ignore = "requires disposable local Postgres; run serially"]
async fn obs64_pg_crashed_final_attempt_is_paused() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    let (pool, claims, state) = fixture().await;
    let server = wiremock::MockServer::start().await;
    let dest = destination(&pool, &state, &claims, &server).await;
    seed_action(&pool, *claims.tenant_id.as_uuid(), 0).await;
    pool.get().await.unwrap().execute(
        "UPDATE otel_exports SET delivery_attempts=2,lease_token=$3,lease_until='epoch' WHERE tenant_id=$1 AND id=$2",
        &[claims.tenant_id.as_uuid(), &dest, &Uuid::new_v4()]).await.unwrap();
    worker::tick(&pool, None, state.entitlements.as_ref(), &quick_config())
        .await
        .unwrap();
    let row = cursor(&pool, *claims.tenant_id.as_uuid(), dest).await;
    assert_eq!(row.0, -1);
    assert!(
        !row.2,
        "expired final lease must leave an actionable paused destination"
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
#[ignore = "requires disposable local Postgres; run serially"]
async fn obs64_pg_mixed_failure_then_recovery() {
    use tracelane_shared::degradation::{self, Degradation};
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    let (pool, claims, state) = fixture().await;
    let bad = wiremock::MockServer::start().await;
    let good = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(503))
        .mount(&bad)
        .await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(json!({"code":0})))
        .mount(&good)
        .await;
    destination(&pool, &state, &claims, &bad).await;
    destination(&pool, &state, &claims, &good).await;
    seed_action(&pool, *claims.tenant_id.as_uuid(), 0).await;
    worker::tick(&pool, None, state.entitlements.as_ref(), &quick_config())
        .await
        .unwrap();
    assert!(
        degradation::is_open(Degradation::SiemExportFailed),
        "healthy destination must not clear failed destination"
    );
    bad.reset().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(json!({"code":0})))
        .mount(&bad)
        .await;
    worker::tick(&pool, None, state.entitlements.as_ref(), &quick_config())
        .await
        .unwrap();
    assert!(
        !degradation::is_open(Degradation::SiemExportFailed),
        "all destinations recovered"
    );
}

#[tokio::test]
#[ignore = "requires disposable local Postgres; run serially"]
async fn obs64_pg_stalled_source_does_not_starve_next_tenant() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    let (pool, a, state) = fixture().await;
    let mut b = a.clone();
    b.tenant_id = TenantId::from_jwt_claim(Uuid::from_u128(u128::MAX));
    crate::db::tenants::create(&pool, *b.tenant_id.as_uuid(), "synthetic-later", "free")
        .await
        .unwrap();
    let sa = wiremock::MockServer::start().await;
    let sb = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(json!({"code":0})))
        .mount(&sb)
        .await;
    let da = destination(&pool, &state, &a, &sa).await;
    destination(&pool, &state, &b, &sb).await;
    seed_action(&pool, *a.tenant_id.as_uuid(), 0).await;
    seed_action(&pool, *b.tenant_id.as_uuid(), 0).await;
    let source = wiremock::MockServer::start().await;
    let tenant = a.tenant_id.to_string();
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .respond_with(move |r: &wiremock::Request| {
            let response = wiremock::ResponseTemplate::new(200);
            if r.url
                .query_pairs()
                .any(|(key, value)| key == "query" && value.contains(&tenant))
            {
                response.set_delay(Duration::from_secs(2))
            } else {
                response
            }
        })
        .mount(&source)
        .await;
    let ch = clickhouse::Client::default()
        .with_url(source.uri())
        .with_compression(clickhouse::Compression::None);
    let mut c = quick_config();
    c.source_timeout = Duration::from_millis(30);
    tokio::time::timeout(
        Duration::from_secs(1),
        worker::tick(&pool, Some(&ch), state.entitlements.as_ref(), &c),
    )
    .await
    .expect("source read stalled worker")
    .unwrap();
    // Our source failing is not the destination's fault: no attempt spent, never paused.
    assert_eq!(
        cursor(&pool, *a.tenant_id.as_uuid(), da).await,
        (-1, 0, true, 0)
    );
    let class: Option<String> = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT last_error_class FROM otel_exports WHERE tenant_id=$1 AND id=$2",
            &[a.tenant_id.as_uuid(), &da],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(class.as_deref(), Some("siem_source_unavailable"));
    for _ in 0..5 {
        tokio::time::timeout(
            Duration::from_secs(1),
            worker::tick(&pool, Some(&ch), state.entitlements.as_ref(), &c),
        )
        .await
        .unwrap()
        .unwrap();
    }
    assert!(
        cursor(&pool, *a.tenant_id.as_uuid(), da).await.2,
        "a repeating source outage never pauses the destination"
    );
    assert_eq!(sb.received_requests().await.unwrap().len(), 1);
}

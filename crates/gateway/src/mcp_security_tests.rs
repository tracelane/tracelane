//! Independent security regressions. Postgres cases use isolated, migrated local databases.
//! Register under `#[cfg(all(test, debug_assertions))]`; no production exports.

use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
    time::Duration,
};

use axum::{
    body::{Body, to_bytes},
    http::{HeaderMap, Method, Request, StatusCode},
    response::Response,
};
use serde_json::{Value, json};
use tower::ServiceExt as _;
use tracelane_shared::TenantId;
use uuid::Uuid;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

use crate::{
    auth::{AuthMethod, Claims},
    entitlement_cache::{EntitlementCache, ResolvedEntitlements},
    handler_harness::{LoopbackBypassGuard, test_state},
    mcp_store::{ApprovalSettings, ModelRule, Snapshot},
    providers::ProviderRegistry,
    server::AppState,
};

#[derive(Default)]
struct ReadPause {
    entered: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}

fn read_pauses() -> &'static parking_lot::Mutex<HashMap<Uuid, Arc<ReadPause>>> {
    static PAUSES: OnceLock<parking_lot::Mutex<HashMap<Uuid, Arc<ReadPause>>>> = OnceLock::new();
    PAUSES.get_or_init(Default::default)
}

/// Test-only hook called just after server_write reads its previous row.
/// Remove first so a concurrent administrative disable is never held by this barrier.
pub(crate) async fn after_server_read(server: Uuid) {
    let pause = read_pauses().lock().remove(&server);
    if let Some(pause) = pause {
        pause.entered.notify_one();
        pause.resume.notified().await;
    }
}

fn principal(tenant: &TenantId) -> Claims {
    Claims {
        tenant_id: tenant.clone(),
        sub: format!("security-review:{tenant}"),
        key_scope: crate::auth::scope::KeyScope::from_column(Some(&["mcp".into(), "chat".into()])),
        ..crate::auth::dev_stub_claims(AuthMethod::JwtBearer)
    }
}

fn empty_snapshot() -> Snapshot {
    Snapshot {
        kms: None,
        kms_revision: 0,
        servers: vec![],
        policy: Default::default(),
        rules: vec![],
        model_rules: vec![],
        approval_settings: ApprovalSettings {
            require_second_approver: false,
            default_ttl_secs: 900,
        },
        approved: HashMap::new(),
    }
}

#[tokio::test]
async fn security_model_approval_cannot_be_bypassed_with_workspace_alias() {
    let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
    let claims = principal(&tenant);
    let mut snapshot = empty_snapshot();
    snapshot.model_rules.push(ModelRule {
        id: Uuid::new_v4(),
        model_glob: "gpt-4o-mini".into(),
        key_id: None,
        ttl_secs: None,
    });
    let mut ent = ResolvedEntitlements::deny_all();
    ent.mcp = Some(Arc::new(snapshot));
    ent.model_aliases = Arc::new([("friendly".to_owned(), "gpt-4o-mini".to_owned())].into());
    let mut state = test_state(ProviderRegistry::new().unwrap());
    state.entitlements = Some(Arc::new(EntitlementCache::new(Arc::new(move |_| {
        let ent = ent.clone();
        Box::pin(async move { Ok(ent) })
    }))));
    for model in ["gpt-4o-mini", "friendly"] {
        let result = crate::admission::admit_with_claims::<crate::admission::Chat>(
            &state,
            &HeaderMap::new(),
            json!({"model":model,"messages":[{"role":"user","content":"run protected model"}]}),
            claims.clone(),
        )
        .await;
        match result {
            // The matching rule reaches the durable gate; this unit fixture deliberately
            // has no approval store, so a matched protected model MUST fail closed here.
            Err(crate::admission::Refusal::Control(d)) => assert_eq!(
                d.code, "approval_unavailable",
                "model {model} must match the approval rule"
            ),
            Err(other) => {
                panic!("model {model} failed before proving approval enforcement: {other:?}")
            }
            Ok(mut admitted) => {
                admitted.dispatch_guard.disarm();
                panic!("model {model} was admitted without its required approval");
            }
        }
    }
}

struct Fixture {
    state: AppState,
    pool: crate::db::DbPool,
    tenant: TenantId,
    server: Uuid,
    upstream: MockServer,
    sessions: parking_lot::Mutex<HashMap<(String, String, String), axum::http::HeaderValue>>,
}

impl Fixture {
    async fn new(auth_mode: &str) -> Self {
        crate::tool_fingerprint::init_from_existing_pepper(&"07".repeat(32)).unwrap();
        let pool = crate::entitlement_cache::b409_fixture::fresh_migrated_pool().await;
        let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
        let server = Uuid::new_v4();
        let upstream = MockServer::start().await;
        Mock::given(method("POST")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"executed"}]}}))).mount(&upstream).await;
        Mock::given(method("POST"))
            .and(wiremock::matchers::body_partial_json(
                json!({"method":"initialize"}),
            ))
            .respond_with(|_: &wiremock::Request| {
                ResponseTemplate::new(200)
                    .insert_header("mcp-session-id", Uuid::new_v4().to_string())
                    .set_body_json(json!({"jsonrpc":"2.0","id":0,"result":{}}))
            })
            .with_priority(1)
            .mount(&upstream)
            .await;
        let client = pool.get().await.unwrap();
        client.execute("INSERT INTO tenants(id,workos_org_id,name) VALUES($1,$2,'MCP security regression')", &[tenant.as_uuid(), &format!("org_{tenant}")]).await.unwrap();
        client.execute("INSERT INTO mcp_servers(id,tenant_id,slug,name,url,transport,auth_mode) VALUES($1,$2,'review','Review',$3,'streamable_http',$4)", &[&server, tenant.as_uuid(), &upstream.uri(), &auth_mode]).await.unwrap();
        client.execute("INSERT INTO mcp_policy(tenant_id,rules_mode,updated_by) VALUES($1,'enforce','security-test')", &[tenant.as_uuid()]).await.unwrap();
        client.execute("INSERT INTO mcp_tool_rules(tenant_id,server_id,tool_glob,action,created_by) VALUES($1,$2,'delete_current','require_approval','security-test')", &[tenant.as_uuid(), &server]).await.unwrap();
        drop(client);
        let source = pool.clone();
        let mut state = test_state(ProviderRegistry::new().unwrap());
        state.pg = Some(pool.clone());
        state.entitlements = Some(Arc::new(EntitlementCache::new(Arc::new(move |id| {
            let source = source.clone();
            Box::pin(async move {
                let client = source.get().await?;
                let mut ent = ResolvedEntitlements::deny_all();
                ent.mcp = Some(crate::mcp_store::load(&client, &id).await?);
                Ok(ent)
            })
        }))));
        Self {
            state,
            pool,
            tenant,
            server,
            upstream,
            sessions: Default::default(),
        }
    }

    async fn pending(&self) -> Uuid {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let client = self.pool.get().await.unwrap();
                if let Some(row) = client
                    .query_opt(
                        "SELECT id FROM approvals WHERE tenant_id=$1 AND status='pending'",
                        &[self.tenant.as_uuid()],
                    )
                    .await
                    .unwrap()
                {
                    return row.get(0);
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the request must reach the pending approval row")
    }

    async fn approve(&self, id: Uuid) {
        // Simulate the already-reviewed decision transaction, keeping this test focused
        // on execution-side freshness/binding rather than approver authentication.
        let client = self.pool.get().await.unwrap();
        assert_eq!(client.execute("UPDATE approvals SET status='approved',decided_by='independent-approver',decided_at=now(),grant_expires_at=now()+interval '5 minutes' WHERE tenant_id=$1 AND id=$2 AND status='pending'", &[self.tenant.as_uuid(), &id]).await.unwrap(), 1);
        crate::approvals::wake(id);
    }

    async fn destructive_calls(&self) -> usize {
        self.upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| {
                r.body_json::<Value>().is_ok_and(|v| {
                    v["method"] == "tools/call" && v["params"]["name"] == "delete_current"
                })
            })
            .count()
    }

    async fn call(
        &self,
        name: &str,
        session: &str,
        upstream_auth: &str,
        approval: Option<Uuid>,
    ) -> Response {
        let caller = crate::auth::validate_authorization("Bearer test-token")
            .await
            .unwrap();
        let key = (caller.sub, session.to_owned(), upstream_auth.to_owned());
        let cached = { self.sessions.lock().get(&key).cloned() };
        let session = if let Some(session) = cached {
            session
        } else {
            let response = crate::mcp_proxy::router(self.state.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/mcp/review")
                        .header("authorization", "Bearer test-token")
                        .header("x-tracelane-upstream-authorization", upstream_auth)
                        .body(Body::from(
                            json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{}})
                                .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "fixture session initialize"
            );
            let id = response.headers()["mcp-session-id"].clone();
            self.sessions.lock().insert(key, id.clone());
            id
        };
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/v1/mcp/review")
            .header("authorization", "Bearer test-token")
            .header("content-type", "application/json")
            .header("mcp-session-id", session)
            .header("x-tracelane-upstream-authorization", upstream_auth);
        if let Some(id) = approval {
            request = request.header("x-tracelane-approval-id", id.to_string());
        }
        crate::mcp_proxy::router(self.state.clone()).oneshot(request.body(Body::from(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":{}}}).to_string())).unwrap()).await.unwrap()
    }

    async fn prove_allowed_path(&self) {
        let response = self
            .call("read", "session-a", "Bearer account-a", None)
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
        assert_eq!(
            body["result"]["content"][0]["text"], "executed",
            "the upstream must be reachable before the negative probe"
        );
    }
}

async fn held_call_change(revoke_key: bool) {
    let _loopback = LoopbackBypassGuard::new();
    let fixture = Fixture::new("none").await;
    let mut claims = principal(&fixture.tenant);
    let key = Uuid::new_v4();
    if revoke_key {
        claims.auth_method = AuthMethod::ApiKey;
        claims.sub = format!("apikey:{key}");
        claims.key_scope = crate::auth::scope::KeyScope::from_column(Some(&["mcp".into()]));
        let client = fixture.pool.get().await.unwrap();
        client.execute("INSERT INTO api_keys(id,tenant_id,name,key_hash,key_prefix,minted_by,scope) VALUES($1,$2,'Review',$3,'test','review-creator',ARRAY['mcp'])", &[&key, fixture.tenant.as_uuid(), &format!("security-test-{key}")]).await.unwrap();
    }
    let _claims = crate::auth::test_claims::Guard::set(claims);
    fixture.prove_allowed_path().await;
    let request = fixture.call("delete_current", "session-a", "Bearer account-a", None);
    let mutate = async {
        let approval = fixture.pending().await;
        if revoke_key {
            crate::offpath::test_revoked()
                .lock()
                .insert(key.to_string());
        } else {
            let client = fixture.pool.get().await.unwrap();
            assert_eq!(
                client
                    .execute(
                        "UPDATE mcp_servers SET enabled=false WHERE tenant_id=$1 AND id=$2",
                        &[fixture.tenant.as_uuid(), &fixture.server]
                    )
                    .await
                    .unwrap(),
                1
            );
            fixture
                .state
                .entitlements
                .as_ref()
                .unwrap()
                .invalidate(*fixture.tenant.as_uuid())
                .await;
        }
        fixture.approve(approval).await;
    };
    let (response, ()) = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(request, mutate)
    })
    .await
    .expect("decision must wake held request");
    crate::offpath::test_revoked()
        .lock()
        .remove(&key.to_string());
    let status = response.status();
    let body = String::from_utf8(
        to_bytes(response.into_body(), 65536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert_eq!(
        fixture.destructive_calls().await,
        0,
        "held call executed after security state changed: revoke_key={revoke_key}, status={status}, response={body}"
    );
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn security_held_call_cannot_execute_after_key_revocation() {
    held_call_change(true).await;
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn security_held_call_cannot_execute_after_snapshot_invalidation() {
    held_call_change(false).await;
}

async fn approval_context_change(change_session: bool) {
    let _loopback = LoopbackBypassGuard::new();
    let fixture = Fixture::new("passthrough").await;
    let _claims = crate::auth::test_claims::Guard::set(principal(&fixture.tenant));
    fixture.prove_allowed_path().await;
    let approval = {
        // Cancel the original client once the durable pending row exists; do not
        // wait for the hold timer or accidentally let that client consume the grant.
        let pending_call = fixture.call("delete_current", "session-a", "Bearer account-a", None);
        tokio::pin!(pending_call);
        tokio::select! {
            response = &mut pending_call => panic!("original call unexpectedly completed before a decision: {}", response.status()),
            id = fixture.pending() => id,
        }
    };
    fixture.approve(approval).await;
    let (session, auth) = if change_session {
        ("session-b", "Bearer account-a")
    } else {
        ("session-a", "Bearer account-b")
    };
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        fixture.call("delete_current", session, auth, Some(approval)),
    )
    .await
    .expect("a mismatched supplied grant must refuse immediately");
    let status = response.status();
    let body = String::from_utf8(
        to_bytes(response.into_body(), 65536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert_eq!(
        fixture.destructive_calls().await,
        0,
        "grant crossed execution contexts: change_session={change_session}, status={status}, body={body}"
    );
    let client = fixture.pool.get().await.unwrap();
    let original_status: String = client
        .query_one(
            "SELECT status FROM approvals WHERE tenant_id=$1 AND id=$2",
            &[fixture.tenant.as_uuid(), &approval],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        original_status, "approved",
        "a mismatched request must not consume the original grant"
    );
    drop(client);
    let correct = fixture
        .call(
            "delete_current",
            "session-a",
            "Bearer account-a",
            Some(approval),
        )
        .await;
    assert_eq!(
        correct.status(),
        StatusCode::OK,
        "original approved context must remain usable"
    );
    assert_eq!(fixture.destructive_calls().await, 1);
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn security_approval_cannot_move_to_another_upstream_session() {
    approval_context_change(true).await;
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn security_approval_cannot_move_to_another_upstream_account() {
    approval_context_change(false).await;
}

async fn patch(state: &AppState, server: Uuid, body: Value) -> Response {
    crate::mcp_routes::router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/v1/mcp-servers/{server}"))
                .header("authorization", "Bearer test-token")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn security_stale_name_patch_cannot_reenable_disabled_server() {
    let _loopback = LoopbackBypassGuard::new();
    let fixture = Fixture::new("none").await;
    let _claims = crate::auth::test_claims::Guard::set(principal(&fixture.tenant));
    let _access = crate::control_plane::test_overrides::Guard::new(
        Some(Ok(Default::default())),
        Some(Ok(true)),
        None,
    );
    let baseline = patch(
        &fixture.state,
        fixture.server,
        json!({"name":"Before race"}),
    )
    .await;
    assert_eq!(
        baseline.status(),
        StatusCode::OK,
        "control path must work before the race"
    );
    let pause = Arc::new(ReadPause::default());
    read_pauses().lock().insert(fixture.server, pause.clone());
    let stale_patch = patch(
        &fixture.state,
        fixture.server,
        json!({"name":"Delayed edit"}),
    );
    let disable = async {
        pause.entered.notified().await;
        let response = patch(&fixture.state, fixture.server, json!({"enabled":false})).await;
        let status = response.status();
        pause.resume.notify_one();
        assert_eq!(
            status,
            StatusCode::OK,
            "concurrent disable must commit before stale PATCH resumes"
        );
    };
    let (response, ()) = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(stale_patch, disable)
    })
    .await
    .expect("deterministic stale-read barrier must finish");
    read_pauses().lock().remove(&fixture.server);
    assert!(
        matches!(response.status(), StatusCode::OK | StatusCode::CONFLICT),
        "stale edits may merge safely or report a conflict"
    );
    let client = fixture.pool.get().await.unwrap();
    let enabled: bool = client
        .query_one(
            "SELECT enabled FROM mcp_servers WHERE tenant_id=$1 AND id=$2",
            &[fixture.tenant.as_uuid(), &fixture.server],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        !enabled,
        "a name-only stale PATCH restored enabled=true after the disable committed"
    );
}

async fn response_json(response: Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn control_as(
    state: &AppState,
    claims: &Claims,
    method: Method,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    let _claims = crate::auth::test_claims::Guard::set(claims.clone());
    let _access = crate::control_plane::test_overrides::Guard::new(
        Some(Ok(Default::default())),
        Some(Ok(true)),
        None,
    );
    let response = crate::mcp_routes::router(state.clone())
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", "Bearer test-token")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    response_json(response).await
}

impl Fixture {
    async fn create_pending_for(&self, claims: &Claims) -> Uuid {
        let _claims = crate::auth::test_claims::Guard::set(claims.clone());
        self.prove_allowed_path().await;
        let call = self.call("delete_current", "session-a", "Bearer account-a", None);
        tokio::pin!(call);
        tokio::select! {
            response = &mut call => panic!("request must create pending approval before completing: {}", response.status()),
            id = self.pending() => id,
        }
    }

    async fn decision(&self, claims: &Claims, id: Uuid, action: &str) -> (StatusCode, Value) {
        assert!(matches!(action, "approve" | "deny"));
        control_as(
            &self.state,
            claims,
            Method::POST,
            &format!("/v1/approvals/{id}/{action}"),
            json!({"note":"security regression"}),
        )
        .await
    }

    async fn status(&self, id: Uuid) -> String {
        self.pool
            .get()
            .await
            .unwrap()
            .query_one(
                "SELECT status FROM approvals WHERE tenant_id=$1 AND id=$2",
                &[self.tenant.as_uuid(), &id],
            )
            .await
            .unwrap()
            .get(0)
    }

    async fn audit_count(&self, id: Uuid, action: &str) -> i64 {
        self.pool.get().await.unwrap().query_one("SELECT count(*) FROM admin_audit_log WHERE actor_workspace_id=$1 AND target_id=$2 AND action=$3", &[self.tenant.as_uuid(), &id.to_string(), &action]).await.unwrap().get(0)
    }

    async fn key_principal(&self, creator: &str) -> Claims {
        let key = Uuid::new_v4();
        self.pool.get().await.unwrap().execute("INSERT INTO api_keys(id,tenant_id,name,key_hash,key_prefix,minted_by,scope) VALUES($1,$2,'Approval requester',$3,'test',$4,ARRAY['mcp'])", &[&key, self.tenant.as_uuid(), &format!("security-test-{key}"), &creator]).await.unwrap();
        Claims {
            sub: format!("apikey:{key}"),
            auth_method: AuthMethod::ApiKey,
            key_scope: crate::auth::scope::KeyScope::from_column(Some(&["mcp".into()])),
            ..principal(&self.tenant)
        }
    }

    async fn audit_failure(&self, action: Option<&str>) {
        let client = self.pool.get().await.unwrap();
        client.batch_execute("ALTER TABLE admin_audit_log DROP CONSTRAINT IF EXISTS security_reject_approval_audit").await.unwrap();
        if let Some(action) = action {
            // Values are a closed test-owned set, never request data. NOT VALID leaves
            // existing evidence readable while the planted fault blocks new inserts.
            assert!(
                [
                    "approval.request",
                    "approval.approve",
                    "approval.consume",
                    "approval.expire"
                ]
                .contains(&action)
            );
            client.batch_execute(match action {"approval.request"=>"ALTER TABLE admin_audit_log ADD CONSTRAINT security_reject_approval_audit CHECK(action <> 'approval.request') NOT VALID","approval.approve"=>"ALTER TABLE admin_audit_log ADD CONSTRAINT security_reject_approval_audit CHECK(action <> 'approval.approve') NOT VALID","approval.consume"=>"ALTER TABLE admin_audit_log ADD CONSTRAINT security_reject_approval_audit CHECK(action <> 'approval.consume') NOT VALID","approval.expire"=>"ALTER TABLE admin_audit_log ADD CONSTRAINT security_reject_approval_audit CHECK(action <> 'approval.expire') NOT VALID",_=>panic!("unknown test fault")}).await.unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn security_concurrent_approval_consumers_execute_exactly_once() {
    let _loopback = LoopbackBypassGuard::new();
    let fixture = Fixture::new("none").await;
    let caller = principal(&fixture.tenant);
    let approval = fixture.create_pending_for(&caller).await;
    assert_eq!(
        fixture.decision(&caller, approval, "approve").await.0,
        StatusCode::OK
    );
    let _claims = crate::auth::test_claims::Guard::set(caller);
    let (a, b) = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(
            fixture.call(
                "delete_current",
                "session-a",
                "Bearer account-a",
                Some(approval)
            ),
            fixture.call(
                "delete_current",
                "session-a",
                "Bearer account-a",
                Some(approval)
            )
        )
    })
    .await
    .expect("both consumers must finish without waiting for another decision");
    let replies = [response_json(a).await.1, response_json(b).await.1];
    assert_eq!(
        replies
            .iter()
            .filter(|r| r["result"]["content"][0]["text"] == "executed")
            .count(),
        1
    );
    assert_eq!(
        replies
            .iter()
            .filter(|r| r["result"]["isError"] == true)
            .count(),
        1
    );
    assert_eq!(fixture.destructive_calls().await, 1);
    assert_eq!(fixture.status(approval).await, "consumed");
    for action in ["approval.request", "approval.approve", "approval.consume"] {
        assert_eq!(
            fixture.audit_count(approval, action).await,
            1,
            "exactly one durable {action}"
        );
    }
    let retry = response_json(
        fixture
            .call(
                "delete_current",
                "session-a",
                "Bearer account-a",
                Some(approval),
            )
            .await,
    )
    .await;
    assert_eq!(retry.1["result"]["isError"], true);
    assert_eq!(
        fixture.destructive_calls().await,
        1,
        "an additional retry must not execute"
    );
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn security_approval_audit_failure_rolls_back_request_decision_and_consume() {
    let _loopback = LoopbackBypassGuard::new();
    let fixture = Fixture::new("none").await;
    let caller = principal(&fixture.tenant);
    fixture.audit_failure(Some("approval.request")).await;
    {
        let _claims = crate::auth::test_claims::Guard::set(caller.clone());
        fixture.prove_allowed_path().await;
        let refused = response_json(
            fixture
                .call("delete_current", "session-a", "Bearer account-a", None)
                .await,
        )
        .await;
        assert_eq!(refused.0, StatusCode::SERVICE_UNAVAILABLE);
    }
    let count: i64 = fixture
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT count(*) FROM approvals WHERE tenant_id=$1",
            &[fixture.tenant.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0, "request and audit must roll back together");
    fixture.audit_failure(None).await;
    let approval = fixture.create_pending_for(&caller).await;
    fixture.audit_failure(Some("approval.approve")).await;
    assert_eq!(
        fixture.decision(&caller, approval, "approve").await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(fixture.status(approval).await, "pending");
    assert_eq!(fixture.audit_count(approval, "approval.approve").await, 0);
    fixture.audit_failure(None).await;
    assert_eq!(
        fixture.decision(&caller, approval, "approve").await.0,
        StatusCode::OK
    );
    fixture.audit_failure(Some("approval.consume")).await;
    let _claims = crate::auth::test_claims::Guard::set(caller);
    let refused = response_json(
        fixture
            .call(
                "delete_current",
                "session-a",
                "Bearer account-a",
                Some(approval),
            )
            .await,
    )
    .await;
    assert_eq!(refused.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(fixture.status(approval).await, "approved");
    assert_eq!(fixture.audit_count(approval, "approval.consume").await, 0);
    assert_eq!(fixture.destructive_calls().await, 0);
    fixture.audit_failure(None).await;
    let allowed = response_json(
        fixture
            .call(
                "delete_current",
                "session-a",
                "Bearer account-a",
                Some(approval),
            )
            .await,
    )
    .await;
    assert_eq!(allowed.1["result"]["content"][0]["text"], "executed");
    assert_eq!(fixture.status(approval).await, "consumed");
    assert_eq!(fixture.audit_count(approval, "approval.consume").await, 1);
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn security_expired_pending_approval_refuses_late_decision_and_audits_expiry() {
    let _loopback = LoopbackBypassGuard::new();
    let fixture = Fixture::new("none").await;
    let caller = principal(&fixture.tenant);
    let approval = fixture.create_pending_for(&caller).await;
    fixture.pool.get().await.unwrap().execute("UPDATE approvals SET expires_at=now()-interval '1 second' WHERE tenant_id=$1 AND id=$2", &[fixture.tenant.as_uuid(), &approval]).await.unwrap();
    let late = fixture.decision(&caller, approval, "approve").await;
    assert_eq!(late.0, StatusCode::CONFLICT);
    assert_eq!(late.1["error"], "approval_expired");
    fixture.audit_failure(Some("approval.expire")).await;
    assert!(crate::approvals::expire(&fixture.pool, None).await.is_err());
    assert_eq!(
        fixture.status(approval).await,
        "pending",
        "a failed expiry audit must roll back its state change"
    );
    fixture.audit_failure(None).await;
    assert_eq!(
        crate::approvals::expire(&fixture.pool, None).await.unwrap(),
        1
    );
    assert_eq!(fixture.status(approval).await, "expired");
    assert_eq!(fixture.audit_count(approval, "approval.expire").await, 1);
    let actor:String = fixture.pool.get().await.unwrap().query_one("SELECT actor_user_id FROM admin_audit_log WHERE actor_workspace_id=$1 AND target_id=$2 AND action='approval.expire'", &[fixture.tenant.as_uuid(), &approval.to_string()]).await.unwrap().get(0);
    assert_eq!(actor, "approval-expiry");
    let _claims = crate::auth::test_claims::Guard::set(caller);
    let refused = response_json(
        fixture
            .call(
                "delete_current",
                "session-a",
                "Bearer account-a",
                Some(approval),
            )
            .await,
    )
    .await;
    assert_eq!(refused.1["result"]["isError"], true);
    assert_eq!(fixture.destructive_calls().await, 0);
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn security_expired_approved_grant_cannot_execute() {
    let _loopback = LoopbackBypassGuard::new();
    let fixture = Fixture::new("none").await;
    let caller = principal(&fixture.tenant);
    let approval = fixture.create_pending_for(&caller).await;
    assert_eq!(
        fixture.decision(&caller, approval, "approve").await.0,
        StatusCode::OK
    );
    fixture.pool.get().await.unwrap().execute("UPDATE approvals SET grant_expires_at=now()-interval '1 second' WHERE tenant_id=$1 AND id=$2", &[fixture.tenant.as_uuid(), &approval]).await.unwrap();
    let _claims = crate::auth::test_claims::Guard::set(caller);
    let refused = response_json(
        fixture
            .call(
                "delete_current",
                "session-a",
                "Bearer account-a",
                Some(approval),
            )
            .await,
    )
    .await;
    assert_eq!(refused.1["result"]["isError"], true);
    assert_eq!(fixture.destructive_calls().await, 0);
    assert_eq!(fixture.audit_count(approval, "approval.consume").await, 0);
    assert_eq!(
        crate::approvals::expire(&fixture.pool, None).await.unwrap(),
        1
    );
    assert_eq!(fixture.status(approval).await, "expired");
    assert_eq!(fixture.audit_count(approval, "approval.expire").await, 1);
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn security_second_approver_rejects_key_creator_and_non_session_deciders() {
    let _loopback = LoopbackBypassGuard::new();
    let fixture = Fixture::new("none").await;
    let creator = principal(&fixture.tenant);
    let caller = fixture.key_principal(&creator.sub).await;
    fixture.pool.get().await.unwrap().execute("INSERT INTO approval_settings(tenant_id,require_second_approver,default_ttl_secs,updated_by) VALUES($1,true,900,'security-test')", &[fixture.tenant.as_uuid()]).await.unwrap();
    let approval = fixture.create_pending_for(&caller).await;
    let poll = control_as(
        &fixture.state,
        &caller,
        Method::GET,
        &format!("/v1/approvals/{approval}"),
        json!({}),
    )
    .await;
    assert_eq!(poll.0, StatusCode::OK);
    assert_eq!(poll.1["status"], "pending");
    let keys: Vec<_> = poll
        .1
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        vec!["expires_at", "grant_expires_at", "id", "status"],
        "requester polling must expose status only"
    );
    assert_eq!(
        fixture.decision(&caller, approval, "approve").await.0,
        StatusCode::FORBIDDEN
    );
    let developer = Claims {
        role: Some(crate::auth::Role::Member),
        sub: "developer".into(),
        ..creator.clone()
    };
    assert_eq!(
        fixture.decision(&developer, approval, "approve").await.0,
        StatusCode::FORBIDDEN
    );
    let self_approval = fixture.decision(&creator, approval, "approve").await;
    assert_eq!(self_approval.0, StatusCode::FORBIDDEN);
    assert_eq!(self_approval.1["error"], "self_approval_forbidden");
    assert_eq!(fixture.status(approval).await, "pending");
    let independent = Claims {
        sub: "independent-owner".into(),
        ..creator
    };
    let method = independent.auth_method_label();
    assert_eq!(
        fixture.decision(&independent, approval, "approve").await.0,
        StatusCode::OK
    );
    assert_eq!(fixture.audit_count(approval, "approval.approve").await, 1);
    // ACT-41: the legacy approve stores how the approver authenticated in the same
    // transaction. This route harness has no WorkOS (debug dev stub), so no sign-in time.
    let row = fixture
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT decided_auth_method, decided_auth_at IS NULL FROM approvals WHERE tenant_id=$1 AND id=$2",
            &[fixture.tenant.as_uuid(), &approval],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, Option<String>>(0).as_deref(), Some(method));
    assert!(row.get::<_, bool>(1));
    let _claims = crate::auth::test_claims::Guard::set(caller);
    let allowed = response_json(
        fixture
            .call(
                "delete_current",
                "session-a",
                "Bearer account-a",
                Some(approval),
            )
            .await,
    )
    .await;
    assert_eq!(allowed.1["result"]["content"][0]["text"], "executed");
    assert_eq!(fixture.destructive_calls().await, 1);
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn security_approval_list_read_and_decisions_are_tenant_scoped() {
    let _loopback = LoopbackBypassGuard::new();
    let fixture = Fixture::new("none").await;
    let owner = principal(&fixture.tenant);
    let caller = fixture.key_principal(&owner.sub).await;
    let approval = fixture.create_pending_for(&caller).await;
    let other_tenant = TenantId::from_jwt_claim(Uuid::new_v4());
    fixture
        .pool
        .get()
        .await
        .unwrap()
        .execute(
            "INSERT INTO tenants(id,workos_org_id,name) VALUES($1,$2,'Other tenant')",
            &[other_tenant.as_uuid(), &format!("org_{other_tenant}")],
        )
        .await
        .unwrap();
    let other = principal(&other_tenant);
    let own_list = control_as(
        &fixture.state,
        &owner,
        Method::GET,
        "/v1/approvals",
        json!({}),
    )
    .await;
    assert_eq!(own_list.0, StatusCode::OK);
    assert_eq!(own_list.1["approvals"][0]["id"], approval.to_string());
    let other_list = control_as(
        &fixture.state,
        &other,
        Method::GET,
        "/v1/approvals",
        json!({}),
    )
    .await;
    assert_eq!(other_list.0, StatusCode::OK);
    assert_eq!(other_list.1["approvals"], json!([]));
    assert_eq!(other_list.1["pending"], 0);
    for principal in [
        &other,
        &Claims {
            tenant_id: other_tenant.clone(),
            ..caller.clone()
        },
    ] {
        let foreign = control_as(
            &fixture.state,
            principal,
            Method::GET,
            &format!("/v1/approvals/{approval}"),
            json!({}),
        )
        .await;
        let missing = control_as(
            &fixture.state,
            principal,
            Method::GET,
            &format!("/v1/approvals/{}", Uuid::new_v4()),
            json!({}),
        )
        .await;
        assert_eq!(foreign.0, StatusCode::NOT_FOUND);
        assert_eq!(
            foreign, missing,
            "foreign and missing approval IDs must be indistinguishable"
        );
    }
    let same_tenant_other_key = fixture.key_principal(&owner.sub).await;
    assert_eq!(
        control_as(
            &fixture.state,
            &same_tenant_other_key,
            Method::GET,
            &format!("/v1/approvals/{approval}"),
            json!({})
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    for action in ["approve", "deny"] {
        let foreign = fixture.decision(&other, approval, action).await;
        let missing = fixture.decision(&other, Uuid::new_v4(), action).await;
        assert_eq!(foreign.0, StatusCode::NOT_FOUND);
        assert_eq!(foreign, missing);
    }
    assert_eq!(fixture.status(approval).await, "pending");
    assert_eq!(
        fixture.decision(&owner, approval, "deny").await.0,
        StatusCode::OK
    );
    assert_eq!(fixture.status(approval).await, "denied");
    assert_eq!(fixture.audit_count(approval, "approval.deny").await, 1);
    let _claims = crate::auth::test_claims::Guard::set(caller);
    let refused = response_json(
        fixture
            .call(
                "delete_current",
                "session-a",
                "Bearer account-a",
                Some(approval),
            )
            .await,
    )
    .await;
    assert_eq!(refused.1["result"]["isError"], true);
    assert_eq!(fixture.destructive_calls().await, 0);
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn security_platform_rotation_rewraps_mcp_secrets_with_server_and_tenant_aad() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use secrecy::{ExposeSecret as _, SecretString};
    let fixture = Fixture::new("none").await;
    let old_key = STANDARD.encode([3; 32]);
    let next_key = STANDARD.encode([4; 32]);
    let old = crate::byok::ByokMasterKey::from_values(Some(&old_key), None, None)
        .unwrap()
        .unwrap();
    let ring = crate::byok::ByokMasterKey::from_values(
        Some(&old_key),
        Some(&format!("1:{next_key}")),
        Some(1),
    )
    .unwrap()
    .unwrap();
    let next_only =
        crate::byok::ByokMasterKey::from_values(None, Some(&format!("1:{next_key}")), Some(1))
            .unwrap()
            .unwrap();
    let tenant_b = TenantId::from_jwt_claim(Uuid::new_v4());
    let server_b = Uuid::new_v4();
    let client = fixture.pool.get().await.unwrap();
    client
        .execute(
            "INSERT INTO tenants(id,workos_org_id,name) VALUES($1,$2,'Rotation other tenant')",
            &[tenant_b.as_uuid(), &format!("org_{tenant_b}")],
        )
        .await
        .unwrap();
    client.execute("INSERT INTO mcp_servers(id,tenant_id,slug,name,url,transport,auth_mode) VALUES($1,$2,'other','Other','https://example.com/mcp','streamable_http','none')", &[&server_b, tenant_b.as_uuid()]).await.unwrap();
    let targets = [(&fixture.tenant, fixture.server), (&tenant_b, server_b)];
    for (tenant, server) in targets {
        let aad = crate::byok::provider_key_aad(tenant, &format!("mcp-server-credential:{server}"));
        let blob = old
            .encrypt_with_context(&SecretString::from("rotation-test-secret"), &aad)
            .unwrap();
        client.execute("UPDATE mcp_servers SET auth_mode='gateway_held',credential_ct=$3 WHERE tenant_id=$1 AND id=$2", &[tenant.as_uuid(), &server, &blob]).await.unwrap();
    }
    let preview = crate::byok_rotate::rotate(&fixture.pool, &ring, true)
        .await
        .unwrap();
    assert_eq!(
        preview
            .tables
            .iter()
            .find(|r| r.table == "mcp_servers")
            .unwrap()
            .rewrapped,
        2
    );
    for (tenant, server) in targets {
        let blob: String = client
            .query_one(
                "SELECT credential_ct FROM mcp_servers WHERE tenant_id=$1 AND id=$2",
                &[tenant.as_uuid(), &server],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(
            crate::byok::ByokMasterKey::kek_id_of(&blob),
            Some(0),
            "dry run must leave the old envelope untouched"
        );
    }
    let report = crate::byok_rotate::rotate(&fixture.pool, &ring, false)
        .await
        .unwrap();
    let mcp = report
        .tables
        .iter()
        .find(|r| r.table == "mcp_servers")
        .unwrap();
    assert_eq!(mcp.rewrapped, 2);
    assert_eq!(mcp.unreadable, 0);
    for (tenant, server) in targets {
        let blob: String = client
            .query_one(
                "SELECT credential_ct FROM mcp_servers WHERE tenant_id=$1 AND id=$2",
                &[tenant.as_uuid(), &server],
            )
            .await
            .unwrap()
            .get(0);
        let aad = crate::byok::provider_key_aad(tenant, &format!("mcp-server-credential:{server}"));
        assert_eq!(
            next_only
                .decrypt_with_context(&blob, &aad)
                .unwrap()
                .expose_secret(),
            "rotation-test-secret"
        );
        assert!(old.decrypt_with_context(&blob, &aad).is_err());
        let wrong_server = crate::byok::provider_key_aad(
            tenant,
            &format!("mcp-server-credential:{}", Uuid::new_v4()),
        );
        let wrong_tenant = crate::byok::provider_key_aad(
            &TenantId::from_jwt_claim(Uuid::new_v4()),
            &format!("mcp-server-credential:{server}"),
        );
        assert!(
            next_only
                .decrypt_with_context(&blob, &wrong_server)
                .is_err()
        );
        assert!(
            next_only
                .decrypt_with_context(&blob, &wrong_tenant)
                .is_err()
        );
    }
    let repeated = crate::byok_rotate::rotate(&fixture.pool, &next_only, false)
        .await
        .unwrap();
    let mcp = repeated
        .tables
        .iter()
        .find(|r| r.table == "mcp_servers")
        .unwrap();
    assert_eq!((mcp.current, mcp.rewrapped, mcp.unreadable), (2, 0, 0));
}

/// Shared by ignored local integration tests needing the production BYOK entry point.
/// No environment mutation; ordinary unit runs never install this process-global key.
pub(crate) fn init_master_for_security_tests() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        if crate::byok::master_key().is_none() {
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            let key = crate::byok::ByokMasterKey::from_values(
                Some(&STANDARD.encode([23; 32])),
                None,
                None,
            )
            .unwrap()
            .unwrap();
            crate::byok::set_global_master_key(key);
        }
    });
}

async fn registered_call(state: &AppState, caller: &Claims, slug: &str) -> Response {
    let _claims = crate::auth::test_claims::Guard::set(caller.clone());
    crate::mcp_proxy::router(state.clone()).oneshot(Request::builder().method(Method::POST).uri(format!("/v1/mcp/{slug}"))
        .header("authorization", "Bearer test-token").header("x-api-key", "test-caller-key-must-not-forward")
        .header("x-tracelane-upstream-authorization", "Bearer caller-value-must-not-override")
        .header("content-type", "application/json")
        .body(Body::from(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read","arguments":{}}}).to_string())).unwrap()).await.unwrap()
}

#[tokio::test]
#[ignore = "requires disposable local Postgres; installs the shared test BYOK master"]
async fn security_registration_encrypts_audits_invalidates_and_rejects_ciphertext_swap() {
    let _loopback = LoopbackBypassGuard::new();
    init_master_for_security_tests();
    let fixture = Fixture::new("none").await;
    let owner = principal(&fixture.tenant);
    let cache = fixture.state.entitlements.as_ref().unwrap();
    let original = cache.resolved(*fixture.tenant.as_uuid()).await;
    let secret_a = "unit-mcp-secret-a-never-plaintext";
    let secret_b = "unit-mcp-secret-b-never-plaintext";
    let mut ids = Vec::new();
    for (slug, secret) in [("sealed-a", secret_a), ("sealed-b", secret_b)] {
        let created = control_as(&fixture.state, &owner, Method::POST, "/v1/mcp-servers", json!({"slug":slug,"name":slug,"url":fixture.upstream.uri(),"auth_mode":"gateway_held","credential":secret})).await;
        assert_eq!(
            created.0,
            StatusCode::OK,
            "real credential registration must succeed"
        );
        assert!(!created.1.to_string().contains(secret));
        assert!(created.1.get("credential_ct").is_none());
        let id = Uuid::parse_str(created.1["id"].as_str().unwrap()).unwrap();
        assert_eq!(fixture.audit_count(id, "mcp_server.create").await, 1);
        ids.push(id);
    }
    assert!(
        !cache.is_current(*fixture.tenant.as_uuid(), &original),
        "registration must evict already-resolved controls"
    );
    let client = fixture.pool.get().await.unwrap();
    let mut ciphertexts = Vec::new();
    for (id, secret) in ids.iter().zip([secret_a, secret_b]) {
        let row = client
            .query_one(
                "SELECT to_jsonb(s),credential_ct FROM mcp_servers s WHERE tenant_id=$1 AND id=$2",
                &[fixture.tenant.as_uuid(), id],
            )
            .await
            .unwrap();
        let stored: Value = row.get(0);
        let ciphertext: String = row.get(1);
        assert!(
            !stored.to_string().contains(secret),
            "stored row must not contain plaintext credential"
        );
        assert_ne!(ciphertext, secret);
        let fetched = control_as(
            &fixture.state,
            &owner,
            Method::GET,
            &format!("/v1/mcp-servers/{id}"),
            json!({}),
        )
        .await;
        assert_eq!(fetched.0, StatusCode::OK);
        assert!(fetched.1.get("credential_ct").is_none());
        assert!(!fetched.1.to_string().contains(secret));
        let audit:Value = client.query_one("SELECT to_jsonb(a) FROM admin_audit_log a WHERE actor_workspace_id=$1 AND target_id=$2 AND action='mcp_server.create'", &[fixture.tenant.as_uuid(), &id.to_string()]).await.unwrap().get(0);
        assert!(!audit.to_string().contains(secret));
        assert!(!audit.to_string().contains(&ciphertext));
        ciphertexts.push(ciphertext);
    }
    let reply = response_json(registered_call(&fixture.state, &owner, "sealed-a").await).await;
    assert_eq!(reply.0, StatusCode::OK);
    assert_eq!(reply.1["result"]["content"][0]["text"], "executed");
    let received = fixture.upstream.received_requests().await.unwrap();
    let outbound = received.last().unwrap();
    assert_eq!(
        outbound
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap(),
        format!("Bearer {secret_a}")
    );
    assert!(outbound.headers.get("x-api-key").is_none());
    assert!(
        outbound
            .headers
            .get("x-tracelane-upstream-authorization")
            .is_none()
    );
    let before_swap = received.len();
    client
        .execute(
            "UPDATE mcp_servers SET credential_ct=$3 WHERE tenant_id=$1 AND id=$2",
            &[fixture.tenant.as_uuid(), &ids[0], &ciphertexts[1]],
        )
        .await
        .unwrap();
    cache.invalidate(*fixture.tenant.as_uuid()).await;
    let refused = response_json(registered_call(&fixture.state, &owner, "sealed-a").await).await;
    assert_eq!(refused.0, StatusCode::BAD_GATEWAY);
    assert_eq!(refused.1["error"], "upstream_credential_unavailable");
    assert_eq!(
        fixture.upstream.received_requests().await.unwrap().len(),
        before_swap,
        "AAD mismatch must refuse before any upstream send"
    );
    client.batch_execute("ALTER TABLE admin_audit_log ADD CONSTRAINT security_reject_registration_audit CHECK(action <> 'mcp_server.create') NOT VALID").await.unwrap();
    let failed = control_as(&fixture.state, &owner, Method::POST, "/v1/mcp-servers", json!({"slug":"failed","name":"Failed","url":fixture.upstream.uri(),"auth_mode":"gateway_held","credential":"unit-failed-registration-secret"})).await;
    assert_eq!(failed.0, StatusCode::SERVICE_UNAVAILABLE);
    let count: i64 = client
        .query_one(
            "SELECT count(*) FROM mcp_servers WHERE tenant_id=$1 AND slug='failed'",
            &[fixture.tenant.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        count, 0,
        "registration and its control audit must roll back together"
    );
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn mcp_approval_notification_is_durable_deduplicated_and_delivered() {
    let _ssrf = LoopbackBypassGuard::new();
    init_master_for_security_tests();
    let fixture = Fixture::new("none").await;
    let receiver = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&receiver)
        .await;
    let channel = Uuid::new_v4();
    let secret = crate::spend_alerts::new_signing_secret().unwrap();
    let encrypted = crate::byok::master_key()
        .unwrap()
        .encrypt_with_context(
            &secret,
            &crate::spend_alerts::channel_aad(*fixture.tenant.as_uuid(), channel),
        )
        .unwrap();
    let new = crate::db::spend_alerts::NewChannel {
        id: channel,
        kind: "webhook",
        name: "Approval proof".into(),
        target: receiver.uri(),
        secret_enc: Some(encrypted),
    };
    crate::db::spend_alerts::create_channel(&fixture.pool, &fixture.tenant, &new, 20, "proof")
        .await
        .unwrap();
    let claims = principal(&fixture.tenant);
    let id = fixture.create_pending_for(&claims).await;
    let retry = fixture.create_pending_for(&claims).await;
    assert_eq!(id, retry);
    let due = crate::db::spend_alerts::claim_due(&fixture.pool, 10, 30)
        .await
        .unwrap();
    assert_eq!(
        due.len(),
        1,
        "Retries must not send duplicate notification events"
    );
    let event = &due[0];
    assert_eq!(event.channel.tenant_id, *fixture.tenant.as_uuid());
    assert_eq!(event.payload["type"], "approval.requested");
    assert_eq!(event.payload["approval_id"], id.to_string());
    assert!(event.payload.get("args_preview").is_none());
    assert!(event.payload.get("arguments").is_none());
    crate::spend_alerts::deliver(
        &crate::spend_alerts::Mail {
            api_key: None,
            from: "local@example.invalid".into(),
        },
        &event.channel,
        event.event_id,
        &event.payload,
        "https://app.tracelane.dev",
    )
    .await
    .unwrap();
    let calls = receiver.received_requests().await.unwrap();
    assert_eq!(calls.len(), 1);
    assert!(crate::spend_alerts::verify_signature(
        &secret,
        calls[0].headers["x-tracelane-signature"].to_str().unwrap(),
        &calls[0].body,
        chrono::Utc::now().timestamp(),
        300
    ));
    let delivered = calls[0].body_json::<Value>().unwrap();
    assert_eq!(delivered["approval_id"], id.to_string());
    // GWY-81: the delivered body carries the deep link and the in-transaction labels.
    assert_eq!(
        delivered["url"],
        format!("https://app.tracelane.dev/settings/gateway/approvals?id={id}")
    );
    let server_name: String = fixture
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT s.name FROM approvals a JOIN mcp_servers s ON s.tenant_id=a.tenant_id AND s.id=a.server_id WHERE a.tenant_id=$1 AND a.id=$2",
            &[fixture.tenant.as_uuid(), &id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(delivered["server_name"], server_name);
    assert!(delivered.get("args_preview").is_none());
    // The non-protected notice carries the row's real expiry (GWY-81 review M2).
    let row_expiry: chrono::DateTime<chrono::Utc> = fixture
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT expires_at FROM approvals WHERE tenant_id=$1 AND id=$2",
            &[fixture.tenant.as_uuid(), &id],
        )
        .await
        .unwrap()
        .get(0);
    let got =
        chrono::DateTime::parse_from_rfc3339(delivered["expires_at"].as_str().unwrap()).unwrap();
    assert_eq!(got, row_expiry);
    let mut keys: Vec<&str> = delivered
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .filter(|k| *k != "rule") // present only when a rule matched
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "approval_id",
            "event_id",
            "expires_at",
            "queue_path",
            "server_name",
            "subject",
            "subject_kind",
            "type",
            "url"
        ]
    );
    crate::db::spend_alerts::record_outcome(&fixture.pool, event.event_id, Ok(()), 0, false)
        .await
        .unwrap();
    assert_eq!(
        fixture
            .pool
            .get()
            .await
            .unwrap()
            .query_one(
                "SELECT status FROM spend_alert_events WHERE tenant_id=$1 AND id=$2",
                &[fixture.tenant.as_uuid(), &event.event_id]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        "delivered"
    );
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn mcp_observed_definition_is_persisted_off_request_path() {
    let _ssrf = LoopbackBypassGuard::new();
    let fixture = Fixture::new("none").await;
    let definition = json!({"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_record","description":"Read one record","inputSchema":{"type":"object"}}]}});
    Mock::given(method("POST"))
        .and(wiremock::matchers::body_partial_json(
            json!({"method":"tools/list"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(definition.clone()))
        .with_priority(1)
        .mount(&fixture.upstream)
        .await;
    let _auth = crate::auth::test_claims::Guard::set(principal(&fixture.tenant));
    let reply = crate::mcp_proxy::router(fixture.state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mcp/review")
                .header("authorization", "Bearer fixture")
                .body(Body::from(
                    json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reply.status(), StatusCode::OK);
    let value: Value =
        serde_json::from_slice(&to_bytes(reply.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(value["result"]["tools"][0]["name"], "read_record");
    assert!(crate::mcp_inspection::flush(&fixture.pool).await.unwrap() > 0);
    let row=fixture.pool.get().await.unwrap().query_one("SELECT def_hash,seen_count FROM mcp_tool_defs WHERE tenant_id=$1 AND server_id=$2 AND tool_name='read_record'",&[fixture.tenant.as_uuid(),&fixture.server]).await.unwrap();
    assert_eq!(
        row.get::<_, String>(0),
        crate::mcp_inspection::hashes(&definition)["read_record"]
    );
    assert_eq!(row.get::<_, i64>(1), 1);
}

#[tokio::test]
#[ignore = "requires disposable local Postgres and MCP_CLICKHOUSE_TEST_URL with CLICKHOUSE_DB=mcp_proof"]
async fn mcp_preview_counts_only_tenant_and_requested_window() {
    let fixture = Fixture::new("none").await;
    let url = std::env::var("MCP_CLICKHOUSE_TEST_URL").expect("local ClickHouse fixture required");
    let ch = crate::clickhouse_query::ch_client(&url);
    let other = Uuid::new_v4();
    for (tenant, age, blocked) in [
        (*fixture.tenant.as_uuid(), 0, true),
        (*fixture.tenant.as_uuid(), 0, false),
        (*fixture.tenant.as_uuid(), 172800, true),
        (other, 0, true),
    ] {
        // FINAL deduplicates by span identity. These are four distinct events,
        // including the unblocked event in the same tenant/hour as the blocked one.
        ch.query("INSERT INTO spans(tenant_id,trace_id,span_id,start_time,attributes) VALUES(?,?,?,now64(3)-toIntervalSecond(?),?)")
            .bind(tenant.to_string())
            .bind(Uuid::new_v4().to_string())
            .bind(Uuid::new_v4().to_string())
            .bind(age)
            .bind(json!({"tracelane.mcp.would_block":blocked}).to_string())
            .execute().await.unwrap();
    }
    let mut state = fixture.state.clone();
    state.quota_ch_url = Some(url);
    let claims = principal(&fixture.tenant);
    let (status, body) = control_as(
        &state,
        &claims,
        Method::GET,
        "/v1/mcp-policy/preview",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["stats_unavailable"], false,
        "real ClickHouse read must succeed: {body}"
    );
    assert_eq!(
        body["would_block"], 1,
        "exclude another tenant, old rows and non-blocked calls"
    );
    let (status, _) = control_as(
        &state,
        &claims,
        Method::GET,
        "/v1/mcp-policy/preview?since=2000-01-01T00%3A00%3A00Z",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn mcp_held_approval_wakes_and_timeout_never_executes() {
    let _ssrf = LoopbackBypassGuard::new();
    let f = Fixture::new("none").await;
    let caller = principal(&f.tenant);
    let _auth = crate::auth::test_claims::Guard::set(caller.clone());
    f.prove_allowed_path().await;
    let ledger_before = f.state.audit_chain.in_memory_seq(&f.tenant);
    let decide = async {
        let id = f.pending().await;
        assert_eq!(f.destructive_calls().await, 0);
        assert_eq!(
            f.state.audit_chain.in_memory_seq(&f.tenant),
            ledger_before,
            "held call has no invoke ledger row"
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while crate::approvals::held_now(*f.tenant.as_uuid()) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(f.decision(&caller, id, "approve").await.0, StatusCode::OK);
        id
    };
    let (response, id) = tokio::join!(
        f.call("delete_current", "session-a", "Bearer account-a", None),
        decide
    );
    assert_eq!(
        response_json(response).await.1["result"]["content"][0]["text"],
        "executed"
    );
    assert_eq!(f.status(id).await, "consumed");
    assert_eq!(
        f.state.audit_chain.in_memory_seq(&f.tenant),
        ledger_before + 1
    );
    assert_eq!(f.destructive_calls().await, 1);
    assert_eq!(crate::approvals::held_now(*f.tenant.as_uuid()), 0);
    // The control fixture installs its own thread-local caller and clears it on drop.
    let _auth = crate::auth::test_claims::Guard::set(caller);
    let start = std::time::Instant::now();
    let response = f
        .call("delete_current", "session-b", "Bearer account-a", None)
        .await;
    assert!(
        start.elapsed()
            >= Duration::from_secs(crate::mcp_policy::settings().unwrap().approvals.hold_secs)
    );
    let body = response_json(response).await.1;
    assert_eq!(body["result"]["isError"], true);
    assert_eq!(f.destructive_calls().await, 1);
    assert_eq!(f.status(f.pending().await).await, "pending");
    assert_eq!(crate::approvals::held_now(*f.tenant.as_uuid()), 0);
    let unknown = response_json(
        f.call(
            "delete_current",
            "session-b",
            "Bearer account-a",
            Some(Uuid::new_v4()),
        )
        .await,
    )
    .await;
    assert_eq!(unknown.0, StatusCode::FORBIDDEN);
    assert_eq!(unknown.1["error"], "approval_mismatch");
    assert_eq!(f.destructive_calls().await, 1);
    use futures::StreamExt;
    let cap = crate::mcp_policy::settings()
        .unwrap()
        .approvals
        .max_held_per_workspace;
    let mut calls = (0..=cap)
        .map(|_| f.call("delete_current", "session-b", "Bearer account-a", None))
        .collect::<futures::stream::FuturesUnordered<_>>();
    let refused = tokio::time::timeout(Duration::from_secs(10), calls.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(refused.headers().contains_key("retry-after"));
    assert_eq!(
        f.destructive_calls().await,
        1,
        "capacity overflow must not execute"
    );
    assert_eq!(crate::approvals::held_now(*f.tenant.as_uuid()), cap);
    drop(calls);
    assert_eq!(
        crate::approvals::held_now(*f.tenant.as_uuid()),
        0,
        "disconnect releases every held slot"
    );
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn mcp_model_approval_is_immediate_consumable_and_capture_is_constrained() {
    use tracelane_shared::key_policy::{Fact, PolicyRequest, Subject};
    let f = Fixture::new("none").await;
    let caller = principal(&f.tenant);
    let rule = Uuid::new_v4();
    f.pool.get().await.unwrap().execute("INSERT INTO approval_rules(id,tenant_id,model_glob,created_by) VALUES($1,$2,'gpt-4o-mini','test')",&[&rule,f.tenant.as_uuid()]).await.unwrap();
    let initial = f
        .state
        .entitlements
        .as_ref()
        .unwrap()
        .resolved(*f.tenant.as_uuid())
        .await;
    let request = |body: Value, unknown: bool| crate::mcp_policy::ToolsRequest {
        model: "gpt-4o-mini".into(),
        body,
        policy_request: PolicyRequest {
            subjects: vec![Subject {
                model: if unknown {
                    Fact::Unknown
                } else {
                    Fact::Known("gpt-4o-mini".into())
                },
                ..Subject::unknown()
            }],
            body_bytes: Fact::Known(100),
        },
        mcp: None,
    };
    let body = json!({"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"approval fixture"}]});
    let ledger_before = f.state.audit_chain.in_memory_seq(&f.tenant);
    let admitted = tokio::time::timeout(
        Duration::from_secs(2),
        crate::admission::admit_with_claims::<crate::admission::Chat>(
            &f.state,
            &HeaderMap::new(),
            body.clone(),
            caller.clone(),
        ),
    )
    .await
    .unwrap();
    match admitted {
        Err(crate::admission::Refusal::Control(d)) => assert_eq!(d.code, "approval_required"),
        Err(other) => panic!("chat did not reach approval: {other:?}"),
        Ok(mut allowed) => {
            allowed.dispatch_guard.disarm();
            panic!("streaming chat was admitted without approval")
        }
    }
    let mut passthrough_caller = caller.clone();
    passthrough_caller.key_scope =
        crate::auth::scope::KeyScope::from_column(Some(&["passthrough".into()]));
    let opaque_admitted = crate::admission::admit_with_claims::<crate::passthrough::Passthrough>(
        &f.state,
        &HeaderMap::new(),
        crate::passthrough::PassthroughInput {
            provider: "openai".into(),
            raw_path: "v1/chat/completions".into(),
            method: Method::POST,
        },
        passthrough_caller,
    )
    .await;
    match opaque_admitted {
        Err(crate::admission::Refusal::Control(d)) => assert_eq!(d.code, "approval_unenforceable"),
        Err(other) => panic!("passthrough did not reach approval: {other:?}"),
        Ok(mut allowed) => {
            allowed.dispatch_guard.disarm();
            panic!("opaque passthrough admitted with model rule")
        }
    }
    assert_eq!(f.state.audit_chain.in_memory_seq(&f.tenant), ledger_before);
    let denied = tokio::time::timeout(
        Duration::from_secs(2),
        crate::mcp_policy::enforce(
            &f.state,
            &HeaderMap::new(),
            &caller,
            request(body.clone(), false),
            Some(&initial),
            Uuid::new_v4(),
        ),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(
        matches!(denied,crate::admission::Refusal::Control(ref d) if d.code=="approval_required")
    );
    // Admission and this direct policy probe have different request bindings.
    // Approve the row returned by this probe, not an assumed workspace singleton.
    let id: Uuid = match &denied {
        crate::admission::Refusal::Control(d) => serde_json::from_value(
            d.detail
                .iter()
                .find(|(key, _)| *key == "approval_id")
                .unwrap()
                .1
                .clone(),
        )
        .unwrap(),
        _ => unreachable!("approval refusal asserted above"),
    };
    assert_eq!(f.decision(&caller, id, "approve").await.0, StatusCode::OK);
    assert!(
        crate::mcp_policy::enforce(
            &f.state,
            &HeaderMap::new(),
            &caller,
            request(body.clone(), false),
            Some(&initial),
            Uuid::new_v4()
        )
        .await
        .unwrap()
        .is_some()
    );
    assert_eq!(f.status(id).await, "consumed");
    let opaque = crate::mcp_policy::enforce(
        &f.state,
        &HeaderMap::new(),
        &caller,
        request(body, true),
        Some(&initial),
        Uuid::new_v4(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(opaque,crate::admission::Refusal::Control(ref d) if d.code=="approval_unenforceable")
    );
    assert!(f.upstream.received_requests().await.unwrap().is_empty());
    for (n, workspace, key_off, zdr) in [
        (0, false, false, false),
        (1, true, true, false),
        (2, true, false, true),
        (3, true, false, false),
    ] {
        let mut ent = (*initial).clone();
        ent.content_capture.input = workspace;
        let ent = Arc::new(ent);
        let mut c = caller.clone();
        if key_off {
            c.key_capture = Some(crate::db::data_controls::KeyCapture {
                input: Some(false),
                output: None,
            });
        }
        let mut headers = HeaderMap::new();
        if zdr {
            headers.insert("x-tracelane-zdr", "true".parse().unwrap());
        }
        let payload = json!({"case":n,"authorization":"Bearer sk-unit-sensitive-value","padding":"a".repeat(4096)});
        let refusal = crate::approvals::gate(
            &f.state,
            &c,
            crate::approvals::Request {
                kind: "model",
                server: None,
                subject: "privacy",
                rule: None,
                ttl_secs: 900,
                body: &payload,
                trace_id: Uuid::new_v4(),
            },
            None,
            &headers,
            Some(&ent),
        )
        .await
        .unwrap_err();
        assert_eq!(refusal.code, "approval_required");
        let id = refusal
            .detail
            .iter()
            .find(|(k, _)| *k == "approval_id")
            .unwrap()
            .1
            .as_str()
            .unwrap();
        let preview: Option<String> = f
            .pool
            .get()
            .await
            .unwrap()
            .query_one(
                "SELECT args_preview FROM approvals WHERE tenant_id=$1 AND id=$2",
                &[f.tenant.as_uuid(), &Uuid::parse_str(id).unwrap()],
            )
            .await
            .unwrap()
            .get(0);
        if n < 3 {
            assert!(preview.is_none(), "capture constraint case {n}");
        } else {
            let preview = preview.unwrap();
            assert!(
                preview.len()
                    <= crate::mcp_policy::settings()
                        .unwrap()
                        .approvals
                        .preview_max_bytes
            );
            assert!(!preview.contains("sk-unit-sensitive-value"));
        }
    }
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn mcp_pin_rule_controls_are_audited_scoped_and_bounded() {
    let f = Fixture::new("none").await;
    let owner = principal(&f.tenant);
    let client = f.pool.get().await.unwrap();
    let hash = "a".repeat(64);
    client.execute("INSERT INTO mcp_tool_defs(tenant_id,server_id,tool_name,def_hash) VALUES($1,$2,'read',$3)",&[f.tenant.as_uuid(),&f.server,&hash]).await.unwrap();
    let pin = json!({"server_id":f.server,"tool_name":"read","def_hash":hash});
    let missing = control_as(
        &f.state,
        &owner,
        Method::POST,
        "/v1/mcp-tools/approve",
        json!({"server_id":f.server,"tool_name":"read","def_hash":"b".repeat(64)}),
    )
    .await;
    assert_eq!(missing.0, StatusCode::NOT_FOUND);
    let other = principal(&TenantId::from_jwt_claim(Uuid::new_v4()));
    client
        .execute(
            "INSERT INTO tenants(id,workos_org_id,name) VALUES($1,$2,'Other tenant')",
            &[
                other.tenant_id.as_uuid(),
                &format!("org_{}", other.tenant_id),
            ],
        )
        .await
        .unwrap();
    for (method, path, body) in [
        (
            Method::PATCH,
            format!("/v1/mcp-servers/{}", f.server),
            json!({"enabled":false}),
        ),
        (Method::POST, "/v1/mcp-tools/approve".into(), pin.clone()),
        (
            Method::POST,
            "/v1/mcp-tool-rules".into(),
            json!({"server_id":f.server,"tool_glob":"*","action":"deny"}),
        ),
    ] {
        assert_eq!(
            control_as(&f.state, &other, method, &path, body).await.0,
            StatusCode::NOT_FOUND
        );
    }
    let mut viewer = owner.clone();
    viewer.role = Some(crate::auth::Role::Viewer);
    assert_eq!(
        control_as(
            &f.state,
            &viewer,
            Method::POST,
            "/v1/mcp-tools/approve",
            pin.clone()
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        control_as(&f.state, &owner, Method::POST, "/v1/mcp-tools/approve", pin)
            .await
            .0,
        StatusCode::OK
    );
    let stored:String=client.query_one("SELECT def_hash FROM mcp_tool_defs WHERE tenant_id=$1 AND server_id=$2 AND status='approved'",&[f.tenant.as_uuid(),&f.server]).await.unwrap().get(0);
    assert_eq!(stored, hash);
    assert_eq!(
        control_as(
            &f.state,
            &owner,
            Method::DELETE,
            &format!("/v1/mcp-tools/{}/read", f.server),
            json!({})
        )
        .await
        .0,
        StatusCode::OK
    );
    let audited:i64=client.query_one("SELECT count(*) FROM admin_audit_log WHERE actor_workspace_id=$1 AND action IN ('mcp_tool.approve','mcp_tool.unpin')",&[f.tenant.as_uuid()]).await.unwrap().get(0);
    assert_eq!(audited, 2);
    let invalid = control_as(
        &f.state,
        &owner,
        Method::POST,
        "/v1/mcp-tool-rules",
        json!({"tool_glob":"[bad]","action":"deny"}),
    )
    .await;
    assert_eq!(invalid.0, StatusCode::BAD_REQUEST);
    assert_eq!(
        invalid.1["field"], "tool_glob",
        "invalid pattern identifies its field"
    );
    let cap = crate::mcp_policy::settings()
        .unwrap()
        .policy
        .max_rules_per_workspace as i32;
    client.execute("INSERT INTO mcp_tool_rules(tenant_id,tool_glob,action,created_by) SELECT $1,'*','deny','test' FROM generate_series(2,$2::int)",&[f.tenant.as_uuid(),&cap]).await.unwrap();
    assert_eq!(
        control_as(
            &f.state,
            &owner,
            Method::POST,
            "/v1/mcp-tool-rules",
            json!({"tool_glob":"*","action":"deny"})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        control_as(
            &f.state,
            &owner,
            Method::PUT,
            "/v1/approvals/settings",
            json!({"require_second_approver":true,"default_ttl_secs":600})
        )
        .await
        .0,
        StatusCode::OK
    );
    let audited:i64=client.query_one("SELECT count(*) FROM admin_audit_log WHERE actor_workspace_id=$1 AND action='approval.settings.update'",&[f.tenant.as_uuid()]).await.unwrap().get(0);
    assert_eq!(audited, 1);
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn mcp_registration_and_dispatch_refuse_private_destination() {
    let f = Fixture::new("none").await;
    let owner = principal(&f.tenant);
    let body = json!({"slug":"private","name":"Private","url":"https://169.254.169.254/latest/meta-data","auth_mode":"none"});
    let response = control_as(&f.state, &owner, Method::POST, "/v1/mcp-servers", body).await;
    assert_eq!(response.0, StatusCode::BAD_REQUEST);
    assert_eq!(response.1["error"], "ssrf_blocked");
    let count: i64 = f
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT count(*) FROM mcp_servers WHERE tenant_id=$1 AND slug='private'",
            &[f.tenant.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    // A persisted server still undergoes destination checks at dispatch; registry trust
    // cannot bypass validation when its URL resolves to a private target.
    let _auth = crate::auth::test_claims::Guard::set(owner);
    let response =
        response_json(registered_call(&f.state, &principal(&f.tenant), "review").await).await;
    assert_eq!(response.0, StatusCode::BAD_GATEWAY);
    assert_eq!(response.1["error"], "ssrf_blocked");
    assert!(f.upstream.received_requests().await.unwrap().is_empty());
}

#[cfg(test)]
#[path = "mcp_security_fix_tests.rs"]
mod fix_tests;

#[cfg(test)]
#[path = "mcp_quality_fix_tests.rs"]
mod quality_fix_tests;

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn mcp_flush_drops_only_the_orphan_row_never_the_batch() {
    let fixture = Fixture::new("none").await;
    let tenant = *fixture.tenant.as_uuid();
    // A server deleted between observe and flush has no FK target.
    crate::mcp_inspection::observe_for_tests(tenant, Uuid::new_v4(), "ghost_tool", "h-ghost");
    crate::mcp_inspection::observe_for_tests(tenant, fixture.server, "kept_tool", "h-kept");
    assert_eq!(
        crate::mcp_inspection::flush(&fixture.pool).await.unwrap(),
        1
    );
    let kept: i64 = fixture.pool.get().await.unwrap().query_one(
        "SELECT count(*) FROM mcp_tool_defs WHERE tenant_id=$1 AND server_id=$2 AND tool_name='kept_tool'",
        &[&tenant, &fixture.server],
    ).await.unwrap().get(0);
    assert_eq!(
        kept, 1,
        "the valid observation must survive an orphan in the same batch"
    );
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn mcp_flush_drops_a_batch_postgres_rejects_instead_of_retrying_forever() {
    // A value Postgres rejects deterministically (NUL in text) must not poison every later
    // tick: the batch is dropped once, and the next flush is clean (review, 2026-11-15).
    let fixture = Fixture::new("none").await;
    let tenant = *fixture.tenant.as_uuid();
    crate::mcp_inspection::observe_for_tests(tenant, fixture.server, "nul\0tool", "h-nul");
    let err = crate::mcp_inspection::flush(&fixture.pool)
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("dropped"), "got {err:#}");
    assert_eq!(
        crate::mcp_inspection::flush(&fixture.pool).await.unwrap(),
        0
    );
    crate::mcp_inspection::observe_for_tests(tenant, fixture.server, "after_poison", "h-ok");
    assert_eq!(
        crate::mcp_inspection::flush(&fixture.pool).await.unwrap(),
        1
    );
}

// ---- ACT-40: default-path approvals in the signed, hash-chained ledger ----
impl Fixture {
    /// Plant (Some) or clear (None) a fault that refuses new approval ledger rows only.
    async fn ledger_failure(&self, on: bool) {
        let client = self.pool.get().await.unwrap();
        client
            .batch_execute(
                "ALTER TABLE audit_log_rows DROP CONSTRAINT IF EXISTS act40_reject_approval_row",
            )
            .await
            .unwrap();
        if on {
            client.batch_execute("ALTER TABLE audit_log_rows ADD CONSTRAINT act40_reject_approval_row CHECK(event_type NOT LIKE 'tool_approval.%') NOT VALID").await.unwrap();
        }
    }
    /// (event_type, actor, payload) of this tenant's approval rows, in ledger order.
    async fn approval_rows(&self) -> Vec<(String, String, String)> {
        self.pool.get().await.unwrap().query("SELECT event_type,actor,payload FROM audit_log_rows WHERE tenant_id=$1 AND event_type LIKE 'tool_approval.%' ORDER BY seq", &[self.tenant.as_uuid()]).await.unwrap()
            .iter().map(|r| (r.get(0), r.get(1), r.get(2))).collect()
    }
    /// Recompute this tenant's whole chain from genesis (no gap, no fork, every row hash).
    async fn chain_holds(&self) -> bool {
        let rows = self.pool.get().await.unwrap().query("SELECT seq,event_type,actor,payload,prev_hash,row_hash FROM audit_log_rows WHERE tenant_id=$1 ORDER BY seq", &[self.tenant.as_uuid()]).await.unwrap();
        let mut prev = crate::audit_format::genesis_prev_hash(&self.tenant);
        for (i, r) in rows.iter().enumerate() {
            let seq: i64 = r.get(0);
            let (et, actor, payload): (String, String, String) = (r.get(1), r.get(2), r.get(3));
            if seq != i as i64 || r.get::<_, String>(4) != hex::encode(prev) {
                return false;
            }
            prev = crate::audit_format::row_hash_v2(
                &prev,
                &self.tenant,
                seq as u64,
                &et,
                &actor,
                &payload,
            );
            if r.get::<_, String>(5) != hex::encode(prev) {
                return false;
            }
        }
        true
    }
    fn replay(
        &self,
        rows: &[(String, String, String)],
    ) -> anyhow::Result<tracelane_audit_verifier::approval::Semantics> {
        let records = rows
            .iter()
            .map(|(et, actor, payload)| {
                tracelane_audit_verifier::approval::Record::from_row(
                    *self.tenant.as_uuid(),
                    et,
                    actor,
                    payload,
                )
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        tracelane_audit_verifier::approval::semantics(&records)
    }
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn act40_lifecycle_is_chained_signed_shape_and_replays() {
    let _loopback = LoopbackBypassGuard::new();
    let fixture = Fixture::new("none").await;
    let caller = principal(&fixture.tenant);
    // A distinct human decides; the requester's own decisions are covered by the deny test.
    let approver = Claims {
        sub: format!("security-approver:{}", fixture.tenant),
        ..principal(&fixture.tenant)
    };
    let approval = fixture.create_pending_for(&caller).await;
    assert_eq!(
        fixture.decision(&approver, approval, "approve").await.0,
        StatusCode::OK
    );
    let _claims = crate::auth::test_claims::Guard::set(caller.clone());
    let allowed = response_json(
        fixture
            .call(
                "delete_current",
                "session-a",
                "Bearer account-a",
                Some(approval),
            )
            .await,
    )
    .await;
    assert_eq!(allowed.1["result"]["content"][0]["text"], "executed");
    let rows = fixture.approval_rows().await;
    let kinds: Vec<_> = rows.iter().map(|r| r.0.as_str()).collect();
    assert_eq!(
        kinds,
        [
            "tool_approval.requested",
            "tool_approval.approved",
            "tool_approval.consumed"
        ]
    );
    // Actors come from validated claims: the requester, then the session decider.
    let actors: Vec<_> = rows.iter().map(|r| r.1.as_str()).collect();
    assert_eq!(
        actors,
        [
            caller.sub.as_str(),
            approver.sub.as_str(),
            caller.sub.as_str()
        ]
    );
    for (_, _, payload) in &rows {
        // Keyed fingerprint only: no arguments, preview or upstream credential.
        for leak in ["arguments", "args_preview", "account-a", "params"] {
            assert!(!payload.contains(leak), "{leak} in {payload}");
        }
        assert!(payload.contains(&approval.to_string()));
    }
    let s = fixture.replay(&rows).unwrap();
    assert_eq!(
        (s.requested, s.approved, s.consumed, s.open, s.self_decided),
        (1, 1, 1, 0, 0)
    );
    assert!(fixture.chain_holds().await);
    // A second consume attempt is refused and adds no ledger row.
    let again = response_json(
        fixture
            .call(
                "delete_current",
                "session-a",
                "Bearer account-a",
                Some(approval),
            )
            .await,
    )
    .await;
    assert_eq!(again.1["result"]["isError"], true);
    assert_eq!(fixture.approval_rows().await.len(), 3);
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn act40_ledger_fault_blocks_request_decision_and_consume() {
    let _loopback = LoopbackBypassGuard::new();
    let fixture = Fixture::new("none").await;
    let caller = principal(&fixture.tenant);
    // Request: with the ledger refusing, no pending approval may exist.
    fixture.ledger_failure(true).await;
    {
        let _claims = crate::auth::test_claims::Guard::set(caller.clone());
        let refused = response_json(
            fixture
                .call("delete_current", "session-a", "Bearer account-a", None)
                .await,
        )
        .await;
        assert_eq!(refused.0, StatusCode::SERVICE_UNAVAILABLE, "{}", refused.1);
    }
    let count: i64 = fixture
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT count(*) FROM approvals WHERE tenant_id=$1",
            &[fixture.tenant.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0, "a request with no ledger record must roll back");
    assert_eq!(fixture.destructive_calls().await, 0);
    fixture.ledger_failure(false).await;
    let approval = fixture.create_pending_for(&caller).await;
    // Decision: refused, state unchanged.
    fixture.ledger_failure(true).await;
    assert!(
        fixture
            .decision(&caller, approval, "approve")
            .await
            .0
            .is_server_error()
    );
    assert_eq!(fixture.status(approval).await, "pending");
    assert_eq!(fixture.audit_count(approval, "approval.approve").await, 0);
    fixture.ledger_failure(false).await;
    assert_eq!(
        fixture.decision(&caller, approval, "approve").await.0,
        StatusCode::OK
    );
    // Consume: refused, grant stays approved, the tool never runs.
    fixture.ledger_failure(true).await;
    let _claims = crate::auth::test_claims::Guard::set(caller.clone());
    let refused = response_json(
        fixture
            .call(
                "delete_current",
                "session-a",
                "Bearer account-a",
                Some(approval),
            )
            .await,
    )
    .await;
    assert_eq!(refused.0, StatusCode::SERVICE_UNAVAILABLE, "{}", refused.1);
    assert_eq!(fixture.status(approval).await, "approved");
    assert_eq!(fixture.destructive_calls().await, 0);
    fixture.ledger_failure(false).await;
    assert!(fixture.chain_holds().await);
    assert_eq!(
        fixture.replay(&fixture.approval_rows().await).unwrap().open,
        1
    );
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn act40_sweep_expiry_records_and_retries_after_fault() {
    let _loopback = LoopbackBypassGuard::new();
    let fixture = Fixture::new("none").await;
    let caller = principal(&fixture.tenant);
    // A real one-second TTL, so the recorded deadline is the one that lapses.
    fixture.pool.get().await.unwrap().execute("INSERT INTO approval_settings(tenant_id,require_second_approver,default_ttl_secs,updated_by) VALUES($1,false,1,'act40-test')", &[fixture.tenant.as_uuid()]).await.unwrap();
    let approval = fixture.create_pending_for(&caller).await;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let lapsed: bool = fixture
                .pool
                .get()
                .await
                .unwrap()
                .query_one(
                    "SELECT now()>expires_at FROM approvals WHERE tenant_id=$1 AND id=$2",
                    &[fixture.tenant.as_uuid(), &approval],
                )
                .await
                .unwrap()
                .get(0);
            if lapsed {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("one-second TTL lapses");
    fixture.ledger_failure(true).await;
    assert!(crate::approvals::expire(&fixture.pool, None).await.is_err());
    assert_eq!(
        fixture.status(approval).await,
        "pending",
        "sweep rolls back, retries next tick"
    );
    fixture.ledger_failure(false).await;
    assert_eq!(
        crate::approvals::expire(&fixture.pool, None).await.unwrap(),
        1
    );
    assert_eq!(fixture.status(approval).await, "expired");
    let rows = fixture.approval_rows().await;
    assert_eq!(rows.last().unwrap().0, "tool_approval.expired");
    assert_eq!(
        rows.last().unwrap().1,
        tracelane_audit_verifier::approval::EXPIRY_ACTOR
    );
    let s = fixture.replay(&rows).unwrap();
    assert_eq!((s.requested, s.expired, s.open), (1, 1, 0));
    assert!(fixture.chain_holds().await);
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn act40_deny_is_recorded_with_decider_and_blocks_execution() {
    let _loopback = LoopbackBypassGuard::new();
    let fixture = Fixture::new("none").await;
    let caller = principal(&fixture.tenant);
    let approval = fixture.create_pending_for(&caller).await;
    assert_eq!(
        fixture.decision(&caller, approval, "deny").await.0,
        StatusCode::OK
    );
    let rows = fixture.approval_rows().await;
    assert_eq!(rows.last().unwrap().0, "tool_approval.denied");
    assert!(
        rows.last()
            .unwrap()
            .2
            .contains(&format!("\"decided_by\":\"{}\"", caller.sub))
    );
    let s = fixture.replay(&rows).unwrap();
    assert_eq!((s.denied, s.self_decided, s.open), (1, 1, 0));
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn act40_approvals_opened_off_ledger_stay_off_ledger_and_replay_passes() {
    let _loopback = LoopbackBypassGuard::new();
    let fixture = Fixture::new("none").await;
    let caller = principal(&fixture.tenant);
    // Two approvals opened before ACT-40 shipped: rows with no `requested` ledger record.
    let legacy = |pending_secs: i64| {
        let pool = fixture.pool.clone();
        let tenant = *fixture.tenant.as_uuid();
        let sub = caller.sub.clone();
        async move {
            let id = Uuid::new_v4();
            pool.get().await.unwrap().execute("INSERT INTO approvals(id,tenant_id,subject_kind,subject,requester_sub,args_fp,args_bytes,expires_at,trace_id) VALUES($1,$2,'tool','delete_current',$3,$4,0,clock_timestamp()+make_interval(secs=>$5::double precision),$1)", &[&id, &tenant, &sub, &id.simple().to_string().repeat(2), &(pending_secs as f64)]).await.unwrap();
            id
        }
    };
    let decided = legacy(3600).await;
    let lapsed = legacy(-1).await;
    let before =
        crate::approvals::ledger::LEGACY_SKIPPED.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        fixture.decision(&caller, decided, "approve").await.0,
        StatusCode::OK
    );
    assert_eq!(fixture.status(decided).await, "approved");
    assert_eq!(
        crate::approvals::expire(&fixture.pool, None).await.unwrap(),
        1
    );
    assert_eq!(fixture.status(lapsed).await, "expired");
    assert!(
        fixture.approval_rows().await.is_empty(),
        "no orphan transition rows"
    );
    assert!(
        crate::approvals::ledger::LEGACY_SKIPPED.load(std::sync::atomic::Ordering::Relaxed)
            >= before + 2
    );
    // A ledgered approval in the same tenant still records its full lifecycle.
    let approval = fixture.create_pending_for(&caller).await;
    assert_eq!(
        fixture.decision(&caller, approval, "approve").await.0,
        StatusCode::OK
    );
    let rows = fixture.approval_rows().await;
    assert_eq!(rows.len(), 2);
    let s = fixture.replay(&rows).unwrap();
    assert_eq!((s.requested, s.approved, s.open), (1, 1, 1));
    assert!(fixture.chain_holds().await);
}

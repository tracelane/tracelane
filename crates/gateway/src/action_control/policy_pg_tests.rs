use super::policy::*;
use super::policy_store::*;
use super::tests::{claims, fixture, grants};
use super::*;
use crate::mcp_policy::{Action, Mode};
pub(super) async fn setup() -> (deadpool_postgres::Pool, crate::auth::Claims, String, String) {
    let (pool, tenant) = fixture().await;
    let c = pool.get().await.unwrap();
    c.execute(
        "UPDATE tenants SET action_control=true WHERE id=$1",
        &[tenant.as_uuid()],
    )
    .await
    .unwrap();
    let server = Uuid::new_v4();
    c.execute("INSERT INTO mcp_servers(id,tenant_id,slug,name,url,transport,auth_mode) VALUES ($1,$2,'synthetic','Synthetic','https://example.invalid','streamable_http','none')",&[&server,tenant.as_uuid()]).await.unwrap();
    let mut auth = claims(&tenant);
    auth.auth_method = crate::auth::AuthMethod::JwtBearer;
    auth.role = Some(crate::auth::Role::Owner);
    auth.sub = "synthetic-publisher".into();
    let contract=json!({"tool_ref":Uuid::new_v4(),"server_id":server,"tool_name":"pay","version":1,"protected":true,"fields":{}}).to_string();
    let policy=json!({"policy_id":Uuid::new_v4(),"version":1,"agents":null,"rules":[{"id":"deny","when":[],"decision":"deny"}]}).to_string();
    (pool, auth, contract, policy)
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_fresh_workspace_activation() {
    let (pool, auth, c, p) = setup().await;
    let mut client = pool.get().await.unwrap();
    assert_eq!(
        client
            .query_one(
                "SELECT count(*) FROM workspace_controls WHERE tenant_id=$1",
                &[auth.tenant_id.as_uuid()]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0,
        "fixture must represent a workspace that never changed controls"
    );
    let tx = client.transaction().await.unwrap();
    activate_tx(&tx, &auth, Some(&grants()), &c, &p)
        .await
        .expect("first policy activation must initialize workspace controls");
    tx.commit().await.unwrap();
    let controls = crate::db::controls::get(&pool, &auth.tenant_id)
        .await
        .unwrap();
    assert!(controls.policy.is_none());
    assert!(controls.paused_at.is_none());
    assert!(controls.blocked_models.is_empty());
    assert!(controls.blocked_providers.is_empty());
    assert!(controls.blocked_end_users.is_empty());
    for sql in [
        "SELECT count(*) FROM workspace_controls WHERE tenant_id=$1",
        "SELECT count(*) FROM action_policy_active WHERE tenant_id=$1",
        "SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1 AND event_type='policy_activated'",
    ] {
        assert_eq!(
            client
                .query_one(sql, &[auth.tenant_id.as_uuid()])
                .await
                .unwrap()
                .get::<_, i64>(0),
            1
        );
    }
    client.execute("UPDATE workspace_controls SET policy='{}'::jsonb,paused_at=now(),paused_by='synthetic',blocked_models=ARRAY['synthetic-model'] WHERE tenant_id=$1", &[auth.tenant_id.as_uuid()]).await.unwrap();
    let before = crate::db::controls::get(&pool, &auth.tenant_id)
        .await
        .unwrap();
    let mut next: Value = serde_json::from_str(&p).unwrap();
    next["version"] = json!(2);
    let tx = client.transaction().await.unwrap();
    activate_tx(&tx, &auth, Some(&grants()), &c, &next.to_string())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        crate::db::controls::get(&pool, &auth.tenant_id)
            .await
            .unwrap(),
        before,
        "activation must preserve existing workspace controls"
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_concurrent_workspace_initialization() {
    let (pool, auth, c, p) = setup().await;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let mut tasks = tokio::task::JoinSet::new();
    for tool in ["pay", "refund"] {
        let (pool, auth, barrier) = (pool.clone(), auth.clone(), barrier.clone());
        let mut contract: Value = serde_json::from_str(&c).unwrap();
        contract["tool_name"] = json!(tool);
        contract["tool_ref"] = json!(Uuid::new_v4());
        let mut policy: Value = serde_json::from_str(&p).unwrap();
        policy["policy_id"] = json!(Uuid::new_v4());
        tasks.spawn(async move {
            let mut client = pool.get().await.unwrap();
            let tx = client.transaction().await.unwrap();
            barrier.wait().await;
            let appended = activate_tx(
                &tx,
                &auth,
                Some(&grants()),
                &contract.to_string(),
                &policy.to_string(),
            )
            .await
            .expect("concurrent first activation must initialize and serialize");
            tx.commit().await.unwrap();
            appended.first_seq
        });
    }
    let mut seqs = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while let Some(result) = tasks.join_next().await {
            seqs.push(result.unwrap());
        }
    })
    .await
    .expect("workspace initialization deadlocked");
    seqs.sort_unstable();
    assert_eq!(seqs, vec![0, 1]);
    let client = pool.get().await.unwrap();
    for (sql, expected) in [
        (
            "SELECT count(*) FROM workspace_controls WHERE tenant_id=$1",
            1,
        ),
        (
            "SELECT count(*) FROM action_policy_active WHERE tenant_id=$1",
            2,
        ),
        (
            "SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1 AND event_type='policy_activated'",
            2,
        ),
    ] {
        assert_eq!(
            client
                .query_one(sql, &[auth.tenant_id.as_uuid()])
                .await
                .unwrap()
                .get::<_, i64>(0),
            expected
        );
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_activation() {
    let (pool, auth, c, p) = setup().await;
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    activate_tx(&tx, &auth, Some(&grants()), &c, &p)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let row = client
        .query_one(
            "SELECT event_type FROM audit_log_rows WHERE tenant_id=$1",
            &[auth.tenant_id.as_uuid()],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "policy_activated");
    let contract = parse_contract(&c).unwrap();
    let payload: String = client
        .query_one(
            "SELECT payload::text FROM audit_log_rows WHERE tenant_id=$1",
            &[auth.tenant_id.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    for bound in [
        format!(
            "\"contract_hash\":\"{}\"",
            sha(canonical_json(&c).unwrap().as_bytes())
        ),
        format!("\"tool_ref\":\"{}\"", contract.tool_ref),
        "\"protected\":true".into(),
    ] {
        assert!(
            payload.contains(&bound),
            "activation evidence omits {bound}: {payload}"
        );
    }
    let actor = claims(&auth.tenant_id);
    let mut request = Request {
        principal: None,
        server: contract.server_id,
        tool: "pay",
        args: b"{}",
        action_id: Uuid::new_v4(),
        decision_id: Uuid::new_v4(),
        denial_id: Uuid::new_v4(),
    };
    let tx = client.transaction().await.unwrap();
    let (verdict, rows) = decide_tx(
        &tx,
        &actor,
        Some(&grants()),
        &request,
        Action::Allow,
        Mode::Observe,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(verdict.decision, Action::Deny);
    assert_eq!(
        rows.rows
            .iter()
            .map(|r| r.event_type.as_str())
            .collect::<Vec<_>>(),
        vec!["decision_made", "denied_runtime"]
    );
    tx.commit().await.unwrap();
    request.denial_id = Uuid::new_v4();
    let tx = client.transaction().await.unwrap();
    assert!(
        decide_tx(
            &tx,
            &actor,
            Some(&grants()),
            &request,
            Action::Allow,
            Mode::Observe
        )
        .await
        .is_err(),
        "partially deduplicated decision evidence accepted"
    );
    tx.rollback().await.unwrap();
    assert!(
        client
            .execute(
                "DELETE FROM action_policy_active WHERE tenant_id=$1",
                &[auth.tenant_id.as_uuid()],
            )
            .await
            .is_err(),
        "active policy pointer deletable"
    );
    // Synthetic absent pointer: only a superuser bypassing the trigger reaches this.
    let tx = client.transaction().await.unwrap();
    tx.batch_execute(
        "ALTER TABLE action_policy_active DISABLE TRIGGER action_policy_active_immutable",
    )
    .await
    .unwrap();
    tx.execute(
        "DELETE FROM action_policy_active WHERE tenant_id=$1",
        &[auth.tenant_id.as_uuid()],
    )
    .await
    .unwrap();
    tx.batch_execute(
        "ALTER TABLE action_policy_active ENABLE TRIGGER action_policy_active_immutable",
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let tx = client.transaction().await.unwrap();
    let (_, rows) = decide_tx(
        &tx,
        &actor,
        Some(&grants()),
        &request,
        Action::Allow,
        Mode::Observe,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(rows.rows[0].event_type, "denied_runtime");
    assert_eq!(rows.rows.len(), 1);
    tx.rollback().await.unwrap();
    let tx = client.transaction().await.unwrap();
    assert!(
        activate_tx(&tx, &auth, Some(&grants()), &c, &p)
            .await
            .is_err(),
        "deleted pointer reset history"
    );
    tx.rollback().await.unwrap();
    assert!(
        client
            .execute(
                "UPDATE action_policies SET publisher_sub='changed' WHERE tenant_id=$1",
                &[auth.tenant_id.as_uuid()]
            )
            .await
            .is_err()
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_rollback() {
    let (pool, auth, c, p) = setup().await;
    let mut client = pool.get().await.unwrap();
    // audit_appended is global (event_id only), so compare before/after.
    let appended = "SELECT count(*) FROM audit_appended";
    let appended_before: i64 = client.query_one(appended, &[]).await.unwrap().get(0);
    let tx = client.transaction().await.unwrap();
    tx.batch_execute("ALTER TABLE audit_log_rows ADD CONSTRAINT synthetic_no_activation CHECK (event_type <> 'policy_activated')").await.unwrap();
    assert!(
        activate_tx(&tx, &auth, Some(&grants()), &c, &p)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    for sql in [
        "SELECT count(*) FROM workspace_controls WHERE tenant_id=$1",
        "SELECT count(*) FROM action_policies WHERE tenant_id=$1",
        "SELECT count(*) FROM action_tool_contracts WHERE tenant_id=$1",
        "SELECT count(*) FROM action_policy_active WHERE tenant_id=$1",
        "SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1",
        "SELECT count(*) FROM audit_chain_state WHERE tenant_id=$1",
    ] {
        let count = client
            .query_one(sql, &[auth.tenant_id.as_uuid()])
            .await
            .unwrap()
            .get::<_, i64>(0);
        assert_eq!(count, 0, "rollback left rows: {sql}");
    }
    let appended_after: i64 = client.query_one(appended, &[]).await.unwrap().get(0);
    assert_eq!(
        appended_after, appended_before,
        "rollback left audit_appended rows"
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_tenant_crossing() {
    let (pool, a, c, p) = setup().await;
    let mut client = pool.get().await.unwrap();
    let b = TenantId::from_jwt_claim(Uuid::new_v4());
    crate::db::tenants::create(&pool, *b.as_uuid(), "synthetic-b", "free")
        .await
        .unwrap();
    client
        .execute(
            "UPDATE tenants SET action_control=true WHERE id=$1",
            &[b.as_uuid()],
        )
        .await
        .unwrap();
    let mut other = a.clone();
    other.tenant_id = b;
    let tx = client.transaction().await.unwrap();
    activate_tx(&tx, &a, Some(&grants()), &c, &p).await.unwrap();
    tx.commit().await.unwrap();
    let contract = parse_contract(&c).unwrap();
    let tx = client.transaction().await.unwrap();
    let foreign = load_tx(&tx, &other, Some(&grants()), contract.server_id, "pay")
        .await
        .unwrap();
    assert!(foreign.is_none(), "foreign contract read");
    let write = activate_tx(&tx, &other, Some(&grants()), &c, &p).await;
    assert!(write.is_err(), "foreign server accepted");
    tx.rollback().await.unwrap();
    let server = Uuid::new_v4();
    client.execute("INSERT INTO mcp_servers(id,tenant_id,slug,name,url,transport,auth_mode) VALUES ($1,$2,'synthetic','Synthetic','https://example.invalid','streamable_http','none')",&[&server,other.tenant_id.as_uuid()]).await.unwrap();
    let mut cb: Value = serde_json::from_str(&c).unwrap();
    cb["server_id"] = json!(server);
    let mut pb: Value = serde_json::from_str(&p).unwrap();
    pb["rules"][0]["decision"] = json!("allow");
    let tx = client.transaction().await.unwrap();
    activate_tx(
        &tx,
        &other,
        Some(&grants()),
        &cb.to_string(),
        &pb.to_string(),
    )
    .await
    .unwrap();
    let loaded = load_tx(&tx, &other, Some(&grants()), server, "pay")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        loaded.policy.unwrap().rules[0].decision,
        Action::Allow,
        "foreign active pointer or policy"
    );
    let loaded = load_tx(&tx, &a, Some(&grants()), contract.server_id, "pay")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.policy.unwrap().rules[0].decision, Action::Deny);
    tx.commit().await.unwrap();
    let sql = "SELECT count(*) FROM action_policies WHERE tenant_id=$1";
    let count: i64 = client
        .query_one(sql, &[a.tenant_id.as_uuid()])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_flag_off() {
    let (pool, auth, c, p) = setup().await;
    let mut client = pool.get().await.unwrap();
    let off = crate::entitlement_cache::ResolvedEntitlements::deny_all();
    for resolved in [None, Some(&off)] {
        let tx = client.transaction().await.unwrap();
        tx.batch_execute("DROP TABLE action_policy_active; DROP TABLE action_policies CASCADE; DROP TABLE action_tool_contracts CASCADE; DROP TABLE workspace_controls").await.unwrap();
        assert!(activate_tx(&tx, &auth, resolved, &c, &p).await.is_err());
        assert!(
            load_tx(&tx, &auth, resolved, Uuid::nil(), "pay")
                .await
                .unwrap()
                .is_none()
        );
        let request = Request {
            principal: None,
            server: Uuid::nil(),
            tool: "pay",
            args: b"invalid",
            action_id: Uuid::nil(),
            decision_id: Uuid::nil(),
            denial_id: Uuid::nil(),
        };
        assert!(
            decide_tx(&tx, &auth, resolved, &request, Action::Deny, Mode::Enforce)
                .await
                .unwrap()
                .is_none()
        );
        tx.query_one("SELECT 1", &[]).await.unwrap();
        tx.rollback().await.unwrap();
    }
}

// ---- ACT-12: publish and read protected-tool policies over HTTP ----------------------
pub(super) mod publish_api {
    use super::super::approval_pg_tests::{Fixture, SessionEnv, export_pg_tests};
    use super::*;
    use axum::http::StatusCode;
    use tower::ServiceExt;

    static HTTP: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    const PATH: &str = "/v1/action-policies";

    fn state(
        f: &Fixture,
        resolved: crate::entitlement_cache::ResolvedEntitlements,
    ) -> crate::server::AppState {
        f.http_state(resolved)
    }
    /// One request through the real router with a really-signed JWT (`sid` optional).
    pub(in crate::action_control) async fn call(
        f: &Fixture,
        who: &crate::auth::Claims,
        sid: Option<&str>,
        resolved: crate::entitlement_cache::ResolvedEntitlements,
        method: &str,
        uri: &str,
        body: String,
    ) -> (StatusCode, Value) {
        let _lock = HTTP.lock().await;
        let jwks = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(
                    json!({"keys":[crate::approvals::protected::session_tests::jwk()]}),
                ),
            )
            .mount(&jwks)
            .await;
        let _env = SessionEnv::new(&jwks.uri());
        let token = crate::approvals::protected::session_tests::signed_jwt(who, sid);
        let _auth = crate::auth::test_claims::Guard::set(who.clone());
        let _access = crate::control_plane::test_overrides::Guard::new(
            Some(Ok(Default::default())),
            None,
            None,
        );
        let response = crate::mcp_routes::router(state(f, resolved))
            .oneshot(
                axum::http::Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("authorization", format!("Bearer {token}"))
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 4 << 20)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
    fn body_of(contract: &str, policy: &str) -> String {
        json!({"contract":serde_json::from_str::<Value>(contract).unwrap(),"policy":serde_json::from_str::<Value>(policy).unwrap()}).to_string()
    }
    async fn publish(f: &Fixture, contract: &str, policy: &str) -> (StatusCode, Value) {
        call(
            f,
            &f.publisher,
            Some("synthetic-session"),
            grants(),
            "POST",
            PATH,
            body_of(contract, policy),
        )
        .await
    }
    async fn get(f: &Fixture, uri: &str) -> (StatusCode, Value) {
        call(
            f,
            &f.publisher,
            Some("synthetic-session"),
            grants(),
            "GET",
            uri,
            String::new(),
        )
        .await
    }
    fn version(policy: &str, v: u64) -> String {
        let mut p: Value = serde_json::from_str(policy).unwrap();
        p["version"] = json!(v);
        p.to_string()
    }
    async fn count(f: &Fixture, table: &str) -> i64 {
        // Fixed test-only table names, never request input.
        f.pool
            .get()
            .await
            .unwrap()
            .query_one(
                &format!("SELECT count(*) FROM {table} WHERE tenant_id=$1"),
                &[f.publisher.tenant_id.as_uuid()],
            )
            .await
            .unwrap()
            .get(0)
    }
    async fn no_rows(f: &Fixture) {
        for t in [
            "action_tool_contracts",
            "action_policies",
            "action_policy_active",
        ] {
            assert_eq!(count(f, t).await, 0, "{t} must stay empty");
        }
    }
    async fn active_version(f: &Fixture) -> i32 {
        f.pool
            .get()
            .await
            .unwrap()
            .query_one(
                "SELECT version FROM action_policy_active WHERE tenant_id=$1",
                &[f.publisher.tenant_id.as_uuid()],
            )
            .await
            .unwrap()
            .get(0)
    }
    async fn admin_rows(f: &Fixture) -> Vec<tokio_postgres::Row> {
        f.pool.get().await.unwrap().query("SELECT actor_user_id,actor_workspace_id,target_id,before_json,after_json FROM admin_audit_log WHERE actor_workspace_id=$1 AND action='action_policy.activate' ORDER BY id", &[f.publisher.tenant_id.as_uuid()]).await.unwrap()
    }
    fn tool_ref(f: &Fixture) -> String {
        serde_json::from_str::<Value>(&f.contract).unwrap()["tool_ref"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    #[tokio::test]
    #[ignore = "requires isolated Postgres"]
    async fn pg_publish_first_policy_creates_rows_and_event() {
        let f = Fixture::legacy().await;
        let (st, body) = publish(&f, &f.contract, &f.policy).await;
        assert_eq!(st, StatusCode::CREATED, "{body}");
        assert_eq!(body["tool_ref"], tool_ref(&f));
        assert_eq!(body["policy_version"], 1);
        for t in [
            "action_tool_contracts",
            "action_policies",
            "action_policy_active",
        ] {
            assert_eq!(count(&f, t).await, 1, "{t}");
        }
        let n: i64 = f.pool.get().await.unwrap().query_one("SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1 AND event_type='policy_activated'", &[f.publisher.tenant_id.as_uuid()]).await.unwrap().get(0);
        assert_eq!(n, 1);
        let admin = admin_rows(&f).await;
        assert_eq!(admin.len(), 1, "exactly one admin_audit_log row");
        assert_eq!(admin[0].get::<_, String>(0), f.publisher.sub);
        assert_eq!(admin[0].get::<_, Uuid>(1), *f.publisher.tenant_id.as_uuid());
        assert_eq!(admin[0].get::<_, String>(2), tool_ref(&f));
        assert!(
            admin[0].get::<_, Option<Value>>(3).is_none(),
            "first publish has no before"
        );
    }
    #[tokio::test]
    #[ignore = "requires isolated Postgres"]
    async fn pg_publish_response_hashes_match_stored_rows() {
        let f = Fixture::legacy().await;
        let (_, body) = publish(&f, &f.contract, &f.policy).await;
        let db = f.pool.get().await.unwrap();
        let t = f.publisher.tenant_id.as_uuid();
        let ph: String = db
            .query_one(
                "SELECT policy_hash FROM action_policies WHERE tenant_id=$1",
                &[t],
            )
            .await
            .unwrap()
            .get(0);
        let ch: String = db
            .query_one(
                "SELECT contract_hash FROM action_tool_contracts WHERE tenant_id=$1",
                &[t],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(body["policy_hash"], ph);
        assert_eq!(body["contract_hash"], ch);
    }
    #[tokio::test]
    #[ignore = "requires isolated Postgres"]
    async fn pg_publish_new_version_advances_active_pointer() {
        let f = Fixture::legacy().await;
        assert_eq!(
            publish(&f, &f.contract, &f.policy).await.0,
            StatusCode::CREATED
        );
        let (st, body) = publish(&f, &f.contract, &version(&f.policy, 2)).await;
        assert_eq!(st, StatusCode::CREATED, "{body}");
        assert_eq!(active_version(&f).await, 2);
        let admin = admin_rows(&f).await;
        let before = admin[1]
            .get::<_, Option<Value>>(3)
            .expect("prior pointer recorded");
        assert_eq!(before["policy_version"], 1);
    }
    #[tokio::test]
    #[ignore = "requires isolated Postgres"]
    async fn pg_publish_new_version_invalidates_pending_grants() {
        let f = Fixture::new().await;
        let id = f.pending().await;
        let (st, body) = publish(&f, &f.contract, &version(&f.policy, 2)).await;
        assert_eq!(st, StatusCode::CREATED, "{body}");
        assert_eq!(f.status(id).await, "invalidated");
    }
    #[tokio::test]
    #[ignore = "requires isolated Postgres"]
    async fn pg_publish_records_publisher_sub() {
        let f = Fixture::legacy().await;
        assert_eq!(
            publish(&f, &f.contract, &f.policy).await.0,
            StatusCode::CREATED
        );
        let sub: String = f
            .pool
            .get()
            .await
            .unwrap()
            .query_one(
                "SELECT publisher_sub FROM action_policies WHERE tenant_id=$1",
                &[f.publisher.tenant_id.as_uuid()],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(sub, f.publisher.sub);
    }
    #[tokio::test]
    #[ignore = "requires isolated Postgres"]
    async fn pg_list_returns_active_policies_sorted() {
        let f = Fixture::legacy().await;
        assert_eq!(
            publish(&f, &f.contract, &f.policy).await.0,
            StatusCode::CREATED
        );
        let mut c: Value = serde_json::from_str(&f.contract).unwrap();
        c["tool_ref"] = json!(Uuid::new_v4());
        c["tool_name"] = json!("alpha");
        c["fields"] = json!({});
        let p = json!({"policy_id":Uuid::new_v4(),"version":1,"agents":null,"rules":[{"id":"deny","when":[],"decision":"deny"}]});
        let (st, body) = publish(&f, &c.to_string(), &p.to_string()).await;
        assert_eq!(st, StatusCode::CREATED, "{body}");
        let (st, body) = get(&f, PATH).await;
        assert_eq!(st, StatusCode::OK, "{body}");
        let names: Vec<_> = body["policies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["tool_name"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(names, ["alpha", "pay"]);
        let row = &body["policies"][1];
        for k in [
            "tool_ref",
            "server_id",
            "contract_version",
            "policy_id",
            "policy_version",
            "policy_hash",
            "contract_hash",
            "publisher_sub",
        ] {
            assert!(!row[k].is_null(), "missing {k}");
        }
    }
    #[tokio::test]
    #[ignore = "requires isolated Postgres"]
    async fn pg_detail_returns_bodies_and_history() {
        let f = Fixture::legacy().await;
        assert_eq!(
            publish(&f, &f.contract, &f.policy).await.0,
            StatusCode::CREATED
        );
        assert_eq!(
            publish(&f, &f.contract, &version(&f.policy, 2)).await.0,
            StatusCode::CREATED
        );
        let (st, body) = get(&f, &format!("{PATH}/{}", tool_ref(&f))).await;
        assert_eq!(st, StatusCode::OK, "{body}");
        let stored: String = f
            .pool
            .get()
            .await
            .unwrap()
            .query_one(
                "SELECT body_jcs FROM action_policies WHERE tenant_id=$1 AND version=2",
                &[f.publisher.tenant_id.as_uuid()],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(body["policy_jcs"], stored);
        assert_eq!(body["policy_version"], 2);
        assert!(
            body["contract_jcs"]
                .as_str()
                .is_some_and(|s| s.contains("\"pay\""))
        );
        let versions: Vec<_> = body["history"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h["version"].as_i64().unwrap())
            .collect();
        assert_eq!(versions, [2, 1]);
        assert_eq!(body["history_truncated"], false);
    }
    #[tokio::test]
    #[ignore = "requires isolated Postgres"]
    async fn pg_detail_flags_truncated_history() {
        let f = Fixture::new().await;
        let page = crate::mcp_policy::settings()
            .unwrap()
            .approvals
            .list_page_size;
        let mut db = f.pool.get().await.unwrap();
        for v in 2..=(page as u64 + 1) {
            let tx = db.transaction().await.unwrap();
            policy_store::activate_tx(
                &tx,
                &f.publisher,
                Some(&grants()),
                &f.contract,
                &version(&f.policy, v),
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }
        let (st, body) = get(&f, &format!("{PATH}/{}", tool_ref(&f))).await;
        assert_eq!(st, StatusCode::OK, "{body}");
        assert_eq!(body["history"].as_array().unwrap().len(), page);
        assert_eq!(body["history_truncated"], true);
    }
    #[tokio::test]
    #[ignore = "requires isolated Postgres"]
    async fn pg_published_policy_requires_approval_end_to_end() {
        let f = Fixture::legacy().await;
        let (st, body) = publish(&f, &f.contract, &f.policy).await;
        assert_eq!(st, StatusCode::CREATED, "{body}");
        let id = f.pending().await;
        assert_eq!(f.status(id).await, "pending");
    }
    #[tokio::test]
    #[ignore = "requires isolated Postgres"]
    async fn pg_published_activation_passes_verifier() {
        use tracelane_audit_verifier::action::bundle;
        let f = Fixture::legacy().await;
        assert_eq!(
            publish(&f, &f.contract, &f.policy).await.0,
            StatusCode::CREATED
        );
        let (zip, pin) = export_pg_tests::exported(&f).await;
        let r = bundle::verify(&zip, Some(pin)).unwrap();
        assert!(r.chain && r.head && r.rows >= 1 && r.actions.unknown.is_empty());
    }
    #[tokio::test]
    #[ignore = "requires isolated Postgres"]
    async fn pg_list_empty_returns_empty_array() {
        let f = Fixture::legacy().await;
        let (st, body) = get(&f, PATH).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body, json!({"policies":[]}));
    }

    #[tokio::test]
    #[ignore = "requires isolated Postgres"]
    async fn pg_publish_with_api_key_is_forbidden() {
        let f = Fixture::legacy().await;
        let (st, _) = call(
            &f,
            &f.agent,
            Some("s"),
            grants(),
            "POST",
            PATH,
            body_of(&f.contract, &f.policy),
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN);
        no_rows(&f).await;
    }
    #[tokio::test]
    #[ignore = "requires isolated Postgres"]
    async fn pg_publish_as_viewer_is_forbidden() {
        let f = Fixture::legacy().await;
        let mut viewer = f.publisher.clone();
        viewer.role = Some(crate::auth::Role::Viewer);
        let (st, _) = call(
            &f,
            &viewer,
            Some("s"),
            grants(),
            "POST",
            PATH,
            body_of(&f.contract, &f.policy),
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN);
        no_rows(&f).await;
    }
    #[tokio::test]
    #[ignore = "requires isolated Postgres"]
    async fn pg_publish_without_verified_session_is_forbidden() {
        let f = Fixture::legacy().await;
        let (st, body) = call(
            &f,
            &f.publisher,
            None,
            grants(),
            "POST",
            PATH,
            body_of(&f.contract, &f.policy),
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "forbidden");
        no_rows(&f).await;
    }
    #[tokio::test]
    #[ignore = "requires isolated Postgres"]
    async fn pg_publish_flag_off_is_refused() {
        let f = Fixture::legacy().await;
        let off = crate::entitlement_cache::ResolvedEntitlements::deny_all();
        let (st, body) = call(
            &f,
            &f.publisher,
            Some("s"),
            off,
            "POST",
            PATH,
            body_of(&f.contract, &f.policy),
        )
        .await;
        assert_eq!(st, StatusCode::CONFLICT);
        assert_eq!(body["error"], "action_control_disabled");
        no_rows(&f).await;
    }
    #[tokio::test]
    #[ignore = "requires isolated Postgres"]
    async fn pg_publish_same_version_conflicts() {
        let f = Fixture::legacy().await;
        assert_eq!(
            publish(&f, &f.contract, &f.policy).await.0,
            StatusCode::CREATED
        );
        let (st, body) = publish(&f, &f.contract, &f.policy).await;
        assert_eq!(st, StatusCode::CONFLICT);
        assert_eq!(body["error"], "policy_version_must_increase");
        assert_eq!(active_version(&f).await, 1);
    }
    #[tokio::test]
    #[ignore = "requires isolated Postgres"]
    async fn pg_publish_lower_version_conflicts() {
        let f = Fixture::legacy().await;
        assert_eq!(
            publish(&f, &f.contract, &version(&f.policy, 2)).await.0,
            StatusCode::CREATED
        );
        let (st, body) = publish(&f, &f.contract, &f.policy).await;
        assert_eq!(st, StatusCode::CONFLICT);
        assert_eq!(body["error"], "policy_version_must_increase");
        assert_eq!(active_version(&f).await, 2);
    }
    #[tokio::test]
    #[ignore = "requires isolated Postgres"]
    async fn pg_publish_changed_contract_same_version_is_invalid() {
        let f = Fixture::legacy().await;
        assert_eq!(
            publish(&f, &f.contract, &f.policy).await.0,
            StatusCode::CREATED
        );
        let mut c: Value = serde_json::from_str(&f.contract).unwrap();
        c["protected"] = json!(false);
        let (st, body) = publish(&f, &c.to_string(), &version(&f.policy, 2)).await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["error"], "contract_invalid");
        assert_eq!(active_version(&f).await, 1);
    }
    #[tokio::test]
    #[ignore = "requires isolated Postgres"]
    async fn pg_publish_unknown_field_is_invalid() {
        let f = Fixture::legacy().await;
        let mut p: Value = serde_json::from_str(&f.policy).unwrap();
        p["bogus"] = json!(1);
        let (st, body) = publish(&f, &f.contract, &p.to_string()).await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["error"], "policy_invalid");
        no_rows(&f).await;
    }
    #[tokio::test]
    #[ignore = "requires isolated Postgres"]
    async fn pg_publish_foreign_server_is_not_found() {
        let f = Fixture::legacy().await;
        let other = TenantId::from_jwt_claim(Uuid::new_v4());
        crate::db::tenants::create(&f.pool, *other.as_uuid(), "synthetic-foreign", "free")
            .await
            .unwrap();
        let foreign = Uuid::new_v4();
        let db = f.pool.get().await.unwrap();
        db.execute("INSERT INTO mcp_servers(id,tenant_id,slug,name,url,transport,auth_mode) VALUES ($1,$2,'foreign','Foreign','https://example.invalid','streamable_http','none')", &[&foreign, other.as_uuid()]).await.unwrap();
        let mut c: Value = serde_json::from_str(&f.contract).unwrap();
        c["server_id"] = json!(foreign);
        let (st, body) = publish(&f, &c.to_string(), &f.policy).await;
        assert_eq!(st, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["error"], "mcp_server_not_found");
        no_rows(&f).await;
        let n: i64 = db
            .query_one(
                "SELECT count(*) FROM action_tool_contracts WHERE tenant_id=$1",
                &[other.as_uuid()],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(n, 0);
        // An archived own server is equally absent.
        db.execute(
            "UPDATE mcp_servers SET archived_at=now() WHERE id=$1",
            &[&f.server],
        )
        .await
        .unwrap();
        let (st, _) = publish(&f, &f.contract, &f.policy).await;
        assert_eq!(st, StatusCode::NOT_FOUND);
        no_rows(&f).await;
    }
    #[tokio::test]
    #[ignore = "requires isolated Postgres"]
    async fn pg_publish_oversized_body_is_rejected() {
        let f = Fixture::legacy().await;
        let max = crate::mcp_policy::settings()
            .unwrap()
            .limits
            .max_request_bytes;
        // A VALID two-key body that parses and would publish, padded past the cap with
        // trailing JSON whitespace: only the size check can refuse it.
        let big = format!("{}{}", body_of(&f.contract, &f.policy), " ".repeat(max));
        let (st, body) = call(&f, &f.publisher, Some("s"), grants(), "POST", PATH, big).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_policy_request");
        no_rows(&f).await;
        let (st, _) = publish(&f, &f.contract, &f.policy).await;
        assert_eq!(
            st,
            StatusCode::CREATED,
            "same body without padding publishes"
        );
    }
    #[tokio::test]
    #[ignore = "requires isolated Postgres"]
    async fn pg_detail_cross_tenant_is_not_found() {
        let f = Fixture::new().await;
        let other = TenantId::from_jwt_claim(Uuid::new_v4());
        crate::db::tenants::create(&f.pool, *other.as_uuid(), "synthetic-reader", "free")
            .await
            .unwrap();
        let mut reader = f.publisher.clone();
        reader.tenant_id = other;
        let (st, _) = call(
            &f,
            &reader,
            Some("s"),
            grants(),
            "GET",
            &format!("{PATH}/{}", tool_ref(&f)),
            String::new(),
        )
        .await;
        assert_eq!(st, StatusCode::NOT_FOUND);
        let (st, _) = get(&f, &format!("{PATH}/{}", tool_ref(&f))).await;
        assert_eq!(st, StatusCode::OK, "owner positive control");
    }
    #[tokio::test]
    #[ignore = "requires isolated Postgres"]
    async fn pg_publish_evidence_failure_commits_nothing() {
        let f = Fixture::legacy().await;
        let db = f.pool.get().await.unwrap();
        // Static fault trigger: every pg test runs on its own fresh migrated database
        // (`action_control::tests::fixture` → `fresh_migrated_pool`), so no other test can
        // see it, and no SQL is assembled from values (banned-pattern 3).
        db.batch_execute("CREATE FUNCTION act12_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic ledger fault'; END $$; CREATE TRIGGER act12_fail BEFORE INSERT ON audit_log_rows FOR EACH ROW EXECUTE FUNCTION act12_fail()").await.unwrap();
        let (st, body) = publish(&f, &f.contract, &f.policy).await;
        db.batch_execute("DROP TRIGGER act12_fail ON audit_log_rows")
            .await
            .unwrap();
        assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(body["error"], "evidence_unavailable");
        no_rows(&f).await;
        assert!(
            admin_rows(&f).await.is_empty(),
            "no admin_audit_log row on failure"
        );
        assert_eq!(
            publish(&f, &f.contract, &f.policy).await.0,
            StatusCode::CREATED,
            "positive control after fault removed"
        );
    }
    #[tokio::test]
    #[ignore = "requires isolated Postgres"]
    async fn pg_publish_reused_policy_id_conflicts() {
        let f = Fixture::legacy().await;
        assert_eq!(
            publish(&f, &f.contract, &f.policy).await.0,
            StatusCode::CREATED
        );
        let mut c: Value = serde_json::from_str(&f.contract).unwrap();
        c["tool_ref"] = json!(Uuid::new_v4());
        c["tool_name"] = json!("refund");
        let (st, body) = publish(&f, &c.to_string(), &f.policy).await;
        assert_eq!(st, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["error"], "policy_conflict");
        assert_eq!(count(&f, "action_policies").await, 1);
    }
    #[tokio::test]
    #[ignore = "requires isolated Postgres"]
    async fn pg_list_cross_tenant_isolated() {
        let f = Fixture::new().await;
        let other = TenantId::from_jwt_claim(Uuid::new_v4());
        crate::db::tenants::create(&f.pool, *other.as_uuid(), "synthetic-lister", "free")
            .await
            .unwrap();
        let mut reader = f.publisher.clone();
        reader.tenant_id = other;
        let (st, body) = call(&f, &reader, Some("s"), grants(), "GET", PATH, String::new()).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body, json!({"policies":[]}));
        let (_, own) = get(&f, PATH).await;
        assert_eq!(
            own["policies"].as_array().unwrap().len(),
            1,
            "owner positive control"
        );
    }
}

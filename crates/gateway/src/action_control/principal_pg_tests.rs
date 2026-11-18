//! Real PostgreSQL issuer custody and protected admission tests.
use super::tests::grants;
use super::*;
use principal::{Input, Issuer};
struct Fixture {
    pool: deadpool_postgres::Pool,
    human: crate::auth::Claims,
    agent: crate::auth::Claims,
    contract: policy::Contract,
    issuer: Issuer,
    registration: Uuid,
    signer: execution::AttestationSigner,
}
impl Fixture {
    async fn new(required: bool) -> Self {
        crate::mcp_security_tests::init_master_for_security_tests();
        let (pool, human, c, p) = policy_pg_tests::setup().await;
        let mut p: Value = serde_json::from_str(&p).unwrap();
        p["require_principal"] = json!(required);
        p["rules"][0]["decision"] = json!("allow");
        if required {
            p["rules"][0]["when"] =
                json!([{"field":"principal.roles","op":"in_list","value":["treasury"]}]);
        }
        let mut db = pool.get().await.unwrap();
        let tx = db.transaction().await.unwrap();
        policy_store::activate_tx(&tx, &human, Some(&grants()), &c, &p.to_string())
            .await
            .unwrap();
        let issuer = principal::test_issuer();
        let registration = principal_api::change_tx(
            &tx,
            &human,
            &crate::db::control_audit::Actor::system("synthetic"),
            &issuer.issuer,
            Some(&issuer),
        )
        .await
        .unwrap()["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        tx.commit().await.unwrap();
        let agent = super::tests::claims(&human.tenant_id);
        db.execute("INSERT INTO api_keys(id,tenant_id,name,key_prefix,minted_by) VALUES($1,$2,'synthetic','test','synthetic')", &[&Uuid::parse_str(agent.api_key_id().unwrap()).unwrap(),agent.tenant_id.as_uuid()]).await.unwrap();
        Self {
            pool: pool.clone(),
            human,
            agent,
            contract: policy::parse_contract(&c).unwrap(),
            issuer,
            registration,
            signer: execution_tests::signer(),
        }
    }
    fn input(&self, subject: &str) -> Input {
        Input::Verified(principal::test_verified(
            *self.agent.tenant_id.as_uuid(),
            self.registration,
            subject,
            Utc::now().timestamp(),
        ))
    }
    fn call<'a>(&'a self, principal: Option<&'a Input>, key: Uuid) -> execution::Call<'a> {
        execution::Call {
            server: self.contract.server_id,
            tool: "pay",
            args: "{}",
            execution_context: "synthetic",
            idempotency_key: key,
            approval_id: None,
            legacy: crate::mcp_policy::Action::Allow,
            mode: crate::mcp_policy::Mode::Observe,
            principal,
            definition_changed: false,
        }
    }
    async fn run(&self, input: Option<&Input>, id: Uuid) -> Result<Option<execution::Receipt>> {
        self.run_with_receipt(input, id, false).await
    }
    async fn run_with_receipt(
        &self,
        input: Option<&Input>,
        id: Uuid,
        countersigned: bool,
    ) -> Result<Option<execution::Receipt>> {
        execution::execute(
            &self.pool,
            &self.agent,
            Some(&grants()),
            &self.call(input, id),
            &self.signer,
            None,
            |header| async move {
                let a = execution::verify(
                    Some(&header),
                    &self.signer.public_key(),
                    *self.agent.tenant_id.as_uuid(),
                    self.contract.server_id,
                    "pay",
                    "{}",
                    Utc::now().timestamp(),
                )
                .unwrap();
                assert!(a.principal_digest.is_some());
                let receipt = Uuid::new_v4();
                if countersigned {
                    execution::Outcome::Countersigned(
                        receipt,
                        receipt_keys::tests::tool_sign_header(
                            &receipt_keys::tests::pair(7),
                            &header,
                            self.contract.server_id,
                            receipt,
                        ),
                    )
                } else {
                    execution::Outcome::Succeeded(receipt)
                }
            },
        )
        .await
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_principal_binding_and_replay() {
    principal_binding_bundle(false).await;
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_principal_countersigned_receipt_and_tree_bundle() {
    principal_binding_bundle(true).await;
}
async fn principal_binding_bundle(countersigned: bool) {
    let f = Fixture::new(true).await;
    let input = f.input("synthetic-person");
    let id = Uuid::new_v4();
    if countersigned {
        use ring::signature::KeyPair;
        let public: [u8; 32] = receipt_keys::tests::pair(7)
            .public_key()
            .as_ref()
            .try_into()
            .unwrap();
        receipt_keys::commit(
            &f.pool,
            &f.human,
            &crate::control_plane::ControlActor::for_test(f.human.tenant_id.clone()),
            &grants(),
            std::time::Duration::from_secs(30),
            f.contract.server_id,
            &public,
        )
        .await
        .unwrap();
    }
    let first = f
        .run_with_receipt(Some(&input), id, countersigned)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.state, execution::State::Succeeded);
    assert_eq!(first.countersignature.is_some(), countersigned);
    assert_eq!(
        f.run_with_receipt(Some(&input), id, countersigned)
            .await
            .unwrap()
            .unwrap(),
        first
    );
    let db = f.pool.get().await.unwrap();
    let row: String=db.query_one("SELECT payload::text FROM audit_log_rows WHERE tenant_id=$1 AND event_type='action_proposed'", &[f.agent.tenant_id.as_uuid()]).await.unwrap().get(0);
    let value: Value = serde_json::from_str(&row).unwrap();
    assert_eq!(value["schema_version"], 2);
    assert_eq!(value["body"]["principal"]["roles"], json!(["treasury"]));
    assert!(!row.contains("synthetic-person"));
    assert_eq!(value["agent_key_id"], f.agent.api_key_id().unwrap());
    use crate::audit_export::{AuditExportReader, PgExportReader};
    let master = crate::byok::ByokMasterKey::from_values(
        Some(&base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            [7; 32],
        )),
        None,
        None,
    )
    .unwrap()
    .unwrap();
    let keys = std::sync::Arc::new(crate::audit_keys::TenantAuditKeyStore::new(
        f.pool.clone(),
        std::sync::Arc::new(master),
        None,
    ));
    let pin = keys
        .get_or_create(&f.agent.tenant_id)
        .await
        .unwrap()
        .public_key_bytes()
        .try_into()
        .unwrap();
    let reader = PgExportReader::new(f.pool.clone()).with_action_keys(Some(keys));
    let zip = crate::audit_export::action::BUILD_NOW
        .scope(
            Utc::now() + chrono::Duration::seconds(120),
            reader.action_bundle(&f.agent.tenant_id, &grants()),
        )
        .await
        .unwrap();
    let report = tracelane_audit_verifier::action::bundle::verify(&zip, Some(pin)).unwrap();
    assert_eq!(report.actions.principals.len(), 1);
    assert_eq!(report.actions.replayed, 1);
    assert_eq!(report.actions.countersigned, u64::from(countersigned));
    assert_eq!(report.actions.uncountersigned, u64::from(!countersigned));
    assert!(report.tree_size.is_some());
    assert!(report.tree_root.is_some());
    assert!(
        report
            .to_string()
            .contains("gateway assertion; IdP token omitted")
    );
    assert_eq!(
        tracelane_audit_verifier::action::bundle::verify(&zip, Some([9; 32]))
            .unwrap_err()
            .code,
        5
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_principal_change_rejects_idempotency() {
    let f = Fixture::new(true).await;
    let id = Uuid::new_v4();
    f.run(Some(&f.input("person-a")), id).await.unwrap();
    assert_eq!(
        f.run(Some(&f.input("person-b")), id)
            .await
            .unwrap_err()
            .to_string(),
        "idempotency_mismatch"
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_principal_failures_are_signed() {
    let f = Fixture::new(true).await;
    for (input, code) in [
        (Input::Missing, "principal_required"),
        (Input::Invalid, "principal_invalid"),
        (Input::Unverifiable, "principal_unverifiable"),
    ] {
        let error = execution::execute(
            &f.pool,
            &f.agent,
            Some(&grants()),
            &f.call(Some(&input), Uuid::new_v4()),
            &f.signer,
            None,
            |_| async { panic!("denied principal forwarded") },
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), code);
        let db = f.pool.get().await.unwrap();
        let count:i64=db.query_one("SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1 AND event_type='denied_runtime' AND payload::jsonb->'body'->>'reason'=$2", &[f.agent.tenant_id.as_uuid(),&code]).await.unwrap().get(0);
        assert_eq!(count, 1);
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_deleted_issuer_denies_verified_token() {
    let f = Fixture::new(true).await;
    let input = f.input("person");
    let mut db = f.pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    principal_api::change_tx(
        &tx,
        &f.human,
        &crate::db::control_audit::Actor::system("synthetic"),
        &f.issuer.issuer,
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        f.run(Some(&input), Uuid::new_v4())
            .await
            .unwrap_err()
            .to_string(),
        "principal_invalid"
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_issuer_owner_only_and_duplicate() {
    let f = Fixture::new(true).await;
    let mut db = f.pool.get().await.unwrap();
    for (auth, code) in [(&f.agent, "unauthorized"), (&f.human, "principal_exists")] {
        let tx = db.transaction().await.unwrap();
        assert_eq!(
            principal_api::change_tx(
                &tx,
                auth,
                &crate::db::control_audit::Actor::system("synthetic"),
                &f.issuer.issuer,
                Some(&f.issuer)
            )
            .await
            .unwrap_err()
            .to_string(),
            code
        );
        tx.rollback().await.unwrap();
    }
    let count:i64=db.query_one("SELECT count(*) FROM admin_audit_log WHERE actor_workspace_id=$1 AND action='principal_issuer.register'", &[f.human.tenant_id.as_uuid()]).await.unwrap().get(0);
    assert_eq!(count, 1);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_foreign_tenant_principal_denied() {
    let f = Fixture::new(true).await;
    let input = Input::Verified(principal::test_verified(
        Uuid::new_v4(),
        f.registration,
        "person",
        Utc::now().timestamp(),
    ));
    assert_eq!(
        f.run(Some(&input), Uuid::new_v4())
            .await
            .unwrap_err()
            .to_string(),
        "principal_invalid"
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_optional_missing_principal_unchanged() {
    let fixture = Fixture::new(false).await;
    let f = &fixture;
    let result = execution::execute(
        &f.pool,
        &f.agent,
        Some(&grants()),
        &f.call(None, Uuid::new_v4()),
        &f.signer,
        None,
        |header| async move {
            let a = execution::verify(
                Some(&header),
                &f.signer.public_key(),
                *f.agent.tenant_id.as_uuid(),
                f.contract.server_id,
                "pay",
                "{}",
                Utc::now().timestamp(),
            )
            .unwrap();
            assert!(a.principal_digest.is_none());
            execution::Outcome::Succeeded(Uuid::new_v4())
        },
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result.state, execution::State::Succeeded);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_expired_verified_principal_denied() {
    let f = Fixture::new(true).await;
    let input = Input::Verified(principal::test_verified(
        *f.agent.tenant_id.as_uuid(),
        f.registration,
        "person",
        Utc::now().timestamp() - 301,
    ));
    assert_eq!(
        f.run(Some(&input), Uuid::new_v4())
            .await
            .unwrap_err()
            .to_string(),
        "principal_invalid"
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approval_is_bound_to_principal() {
    let f = Fixture::new(true).await;
    let mut db = f.pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    let p=json!({"policy_id":Uuid::new_v4(),"version":2,"require_principal":true,"approval_ttl_secs":300,"rules":[{"id":"review","when":[],"decision":"require_approval"}]}).to_string();
    policy_store::activate_tx(
        &tx,
        &f.human,
        Some(&grants()),
        &canonical(&f.contract).unwrap(),
        &p,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let a = f.input("person-a");
    let b = f.input("person-b");
    let error = f.run(Some(&a), Uuid::new_v4()).await.unwrap_err();
    let id = error
        .downcast_ref::<execution::ApprovalRequired>()
        .unwrap()
        .id;
    let mut decider = f.human.clone();
    decider.sub = "synthetic-separated-decider".into();
    let tx = db.transaction().await.unwrap();
    let (code, _) = crate::approvals::protected::decide_tx(
        &tx,
        &decider,
        Some(&grants()),
        id,
        true,
        "",
        Some("synthetic-session"),
    )
    .await
    .unwrap();
    assert!(code.is_none(), "{code:?}");
    tx.commit().await.unwrap();
    let mut call = f.call(Some(&b), Uuid::new_v4());
    call.approval_id = Some(id);
    let error = execution::execute(
        &f.pool,
        &f.agent,
        Some(&grants()),
        &call,
        &f.signer,
        None,
        |_| async { panic!("approval crossed principal") },
    )
    .await
    .unwrap_err();
    assert_eq!(error.to_string(), "approval_mismatch");
    let mut call = f.call(Some(&a), Uuid::new_v4());
    call.approval_id = Some(id);
    assert!(
        execution::execute(
            &f.pool,
            &f.agent,
            Some(&grants()),
            &call,
            &f.signer,
            None,
            |_| async { execution::Outcome::Succeeded(Uuid::new_v4()) }
        )
        .await
        .unwrap()
        .is_some()
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_principal_issuer_http_owner_only() {
    use axum::http::StatusCode;
    let f = approval_pg_tests::Fixture::new().await;
    let mut issuer = principal::test_issuer();
    issuer.jwks_url = "https://8.8.8.8/synthetic-jwks".into();
    let body = serde_json::to_string(&issuer).unwrap();
    let path = "/v1/principal-issuers";
    for (who, sid) in [(&f.agent, Some("synthetic-session")), (&f.publisher, None)] {
        let (status, _) =
            policy_pg_tests::publish_api::call(&f, who, sid, grants(), "POST", path, body.clone())
                .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let (status, _) = policy_pg_tests::publish_api::call(
        &f,
        &f.publisher,
        Some("synthetic-session"),
        grants(),
        "POST",
        path,
        body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = policy_pg_tests::publish_api::call(
        &f,
        &f.publisher,
        Some("synthetic-session"),
        grants(),
        "DELETE",
        path,
        json!({"issuer":issuer.issuer}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_required_policy_warns_without_issuer() {
    use axum::http::StatusCode;
    let f = approval_pg_tests::Fixture::legacy().await;
    let mut policy: Value = serde_json::from_str(&f.policy).unwrap();
    policy["require_principal"] = json!(true);
    let body =
        json!({"contract":serde_json::from_str::<Value>(&f.contract).unwrap(),"policy":policy})
            .to_string();
    let (status, out) = policy_pg_tests::publish_api::call(
        &f,
        &f.publisher,
        Some("synthetic-session"),
        grants(),
        "POST",
        "/v1/action-policies",
        body,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(out["warnings"], json!(["principal_issuer_missing"]));
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_database_clock_rechecks_principal_issuance() {
    let f = Fixture::new(true).await;
    let input = Input::Verified(principal::test_verified(
        *f.agent.tenant_id.as_uuid(),
        f.registration,
        "person",
        Utc::now().timestamp() + 60,
    ));
    assert_eq!(
        f.run(Some(&input), Uuid::new_v4())
            .await
            .unwrap_err()
            .to_string(),
        "principal_invalid"
    );
}

async fn approved_for(f: &Fixture, input: &Input) -> Uuid {
    let mut db = f.pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    let policy=json!({"policy_id":Uuid::new_v4(),"version":2,"require_principal":true,"approval_ttl_secs":300,"rules":[{"id":"review","when":[],"decision":"require_approval"}]}).to_string();
    policy_store::activate_tx(
        &tx,
        &f.human,
        Some(&grants()),
        &canonical(&f.contract).unwrap(),
        &policy,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let error = f.run(Some(input), Uuid::new_v4()).await.unwrap_err();
    let id = error
        .downcast_ref::<execution::ApprovalRequired>()
        .unwrap()
        .id;
    let mut decider = f.human.clone();
    decider.sub = "synthetic-separated-decider".into();
    let tx = db.transaction().await.unwrap();
    let (code, _) = crate::approvals::protected::decide_tx(
        &tx,
        &decider,
        Some(&grants()),
        id,
        true,
        "",
        Some("synthetic-session"),
    )
    .await
    .unwrap();
    assert!(code.is_none(), "{code:?}");
    tx.commit().await.unwrap();
    id
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_principal_expiry_during_ledger_wait_records_denial() {
    let f = std::sync::Arc::new(Fixture::new(true).await);
    let approval = approved_for(&f, &f.input("person")).await;
    let mut blocker = f.pool.get().await.unwrap();
    let tx = blocker.transaction().await.unwrap();
    tx.query_one(
        "SELECT last_seq FROM audit_chain_state WHERE tenant_id=$1 FOR UPDATE",
        &[f.agent.tenant_id.as_uuid()],
    )
    .await
    .unwrap();
    let worker = f.clone();
    let task = tokio::spawn(async move {
        let input = Input::Verified(principal::test_verified(
            *worker.agent.tenant_id.as_uuid(),
            worker.registration,
            "person",
            Utc::now().timestamp() - 298,
        ));
        let mut call = worker.call(Some(&input), Uuid::new_v4());
        call.approval_id = Some(approval);
        execution::execute(
            &worker.pool,
            &worker.agent,
            Some(&grants()),
            &call,
            &worker.signer,
            None,
            |_| async { panic!("expired principal forwarded") },
        )
        .await
    });
    let probe = f.pool.get().await.unwrap();
    let mut waiting = false;
    for _ in 0..100 {
        let row=probe.query_opt("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%audit_chain_state%' AND pid<>pg_backend_pid()", &[]).await.unwrap();
        if let Some(row) = row {
            let pid: i32 = row.get(0);
            let minimized:bool=probe.query_one("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation='action_tokenization_secrets'::regclass AND granted)", &[&pid]).await.unwrap().get(0);
            assert!(
                minimized,
                "token expired before the reservation reached its ledger wait"
            );
            waiting = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(waiting, "reservation did not reach the held ledger lock");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    tx.commit().await.unwrap();
    assert_eq!(
        task.await.unwrap().unwrap_err().to_string(),
        "principal_invalid"
    );
    let count: i64 = probe
        .query_one(
            "SELECT count(*) FROM action_executions WHERE tenant_id=$1",
            &[f.agent.tenant_id.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    let status: String = probe
        .query_one(
            "SELECT status FROM approvals WHERE tenant_id=$1 AND id=$2",
            &[f.agent.tenant_id.as_uuid(), &approval],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(status, "approved");
    let count:i64=probe.query_one("SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1 AND event_type='denied_runtime' AND payload::jsonb->'body'->>'reason'='principal_invalid'", &[f.agent.tenant_id.as_uuid()]).await.unwrap().get(0);
    assert_eq!(count, 1);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_principal_separation_requires_proposal_evidence() {
    let f = Fixture::new(false).await;
    let mut db = f.pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    assert!(
        principal::same_approver_tx(
            &tx,
            &f.human,
            Some(&grants()),
            Uuid::new_v4(),
            &"ab".repeat(32)
        )
        .await
        .is_err()
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_legacy_proposal_without_principal_can_be_compared() {
    let f = Fixture::new(false).await;
    execution::execute(
        &f.pool,
        &f.agent,
        Some(&grants()),
        &f.call(None, Uuid::new_v4()),
        &f.signer,
        None,
        |_| async { execution::Outcome::Succeeded(Uuid::new_v4()) },
    )
    .await
    .unwrap();
    let mut db = f.pool.get().await.unwrap();
    let row=db.query_one("SELECT payload::jsonb->>'action_id',payload::jsonb->>'request_digest' FROM audit_log_rows WHERE tenant_id=$1 AND event_type='action_proposed'", &[f.agent.tenant_id.as_uuid()]).await.unwrap();
    let action: Uuid = row.get::<_, String>(0).parse().unwrap();
    let digest: String = row.get(1);
    let tx = db.transaction().await.unwrap();
    assert!(
        !principal::same_approver_tx(&tx, &f.human, Some(&grants()), action, &digest)
            .await
            .unwrap()
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres; serialized environment"]
async fn pg_same_issuer_principal_cannot_approve_self() {
    let f = Fixture::new(true).await;
    let _env = approval_pg_tests::SessionEnv::new("http://127.0.0.1:1");
    unsafe {
        std::env::set_var("WORKOS_ISSUER", "https://issuer.example");
    }
    let input = f.input("synthetic-decider");
    let mut db = f.pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    let policy=json!({"policy_id":Uuid::new_v4(),"version":2,"require_principal":true,"approval_ttl_secs":300,"rules":[{"id":"review","when":[],"decision":"require_approval"}]}).to_string();
    policy_store::activate_tx(
        &tx,
        &f.human,
        Some(&grants()),
        &canonical(&f.contract).unwrap(),
        &policy,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let error = f.run(Some(&input), Uuid::new_v4()).await.unwrap_err();
    let id = error
        .downcast_ref::<execution::ApprovalRequired>()
        .unwrap()
        .id;
    let mut human = f.human.clone();
    human.sub = "synthetic-decider".into();
    let tx = db.transaction().await.unwrap();
    let (code, _) = crate::approvals::protected::decide_tx(
        &tx,
        &human,
        Some(&grants()),
        id,
        true,
        "",
        Some("synthetic-session"),
    )
    .await
    .unwrap();
    assert_eq!(code, Some("separation_required"));
    tx.commit().await.unwrap();
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_principal_registry_cap_before_constraints() {
    let f = Fixture::new(true).await;
    let mut db = f.pool.get().await.unwrap();
    db.batch_execute("ALTER TABLE tenant_principal_issuers DROP CONSTRAINT tenant_principal_issuers_tenant_issuer").await.unwrap();
    let cap = crate::mcp_policy::settings().unwrap().principal.max_issuers;
    for n in 1..cap {
        let mut issuer = f.issuer.clone();
        issuer.issuer = format!("https://issuer-{n}.example");
        let tx = db.transaction().await.unwrap();
        principal_api::change_tx(
            &tx,
            &f.human,
            &crate::db::control_audit::Actor::system("synthetic"),
            &issuer.issuer,
            Some(&issuer),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let mut issuer = f.issuer.clone();
    issuer.issuer = "https://over-limit.example".into();
    let tx = db.transaction().await.unwrap();
    assert_eq!(
        principal_api::change_tx(
            &tx,
            &f.human,
            &crate::db::control_audit::Actor::system("synthetic"),
            &issuer.issuer,
            Some(&issuer)
        )
        .await
        .unwrap_err()
        .to_string(),
        "principal_limit"
    );
    tx.rollback().await.unwrap();
    let count: i64 = db
        .query_one(
            "SELECT count(*) FROM tenant_principal_issuers WHERE tenant_id=$1",
            &[f.human.tenant_id.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, cap as i64);
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_principal_registry_concurrent_duplicate_before_constraints() {
    let f = Fixture::new(true).await;
    let db = f.pool.get().await.unwrap();
    db.batch_execute("ALTER TABLE tenant_principal_issuers DROP CONSTRAINT tenant_principal_issuers_tenant_issuer").await.unwrap();
    let mut issuer = f.issuer.clone();
    issuer.issuer = "https://concurrent.example".into();
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let mut handles = vec![];
    for _ in 0..2 {
        let (pool, human, issuer, barrier) = (
            f.pool.clone(),
            f.human.clone(),
            issuer.clone(),
            barrier.clone(),
        );
        handles.push(tokio::spawn(async move {
            let mut db = pool.get().await.unwrap();
            let tx = db.transaction().await.unwrap();
            barrier.wait().await;
            match principal_api::change_tx(
                &tx,
                &human,
                &crate::db::control_audit::Actor::system("synthetic"),
                &issuer.issuer,
                Some(&issuer),
            )
            .await
            {
                Ok(_) => {
                    tx.commit().await.unwrap();
                    Ok(())
                }
                Err(e) => {
                    tx.rollback().await.unwrap();
                    Err(e.to_string())
                }
            }
        }));
    }
    let mut results = vec![];
    for handle in handles {
        results.push(handle.await.unwrap());
    }
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(e) if e == "principal_exists"))
            .count(),
        1
    );
    let count: i64 = db
        .query_one(
            "SELECT count(*) FROM tenant_principal_issuers WHERE tenant_id=$1 AND issuer=$2",
            &[f.human.tenant_id.as_uuid(), &issuer.issuer],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_principal_header_uses_tenant_registered_issuer() {
    use axum::http::HeaderMap;
    let f = Fixture::new(true).await;
    let _env = approval_pg_tests::SessionEnv::new("http://127.0.0.1:1");
    unsafe {
        std::env::set_var("WORKOS_ISSUER", "https://control-plane.example");
    }
    // A reachable control plane signing with its own, unrelated key.
    let _control = crate::auth::jwks::seed_control_plane_kids_for_tests(&["control-plane-key"]);
    let other = TenantId::from_jwt_claim(Uuid::new_v4());
    crate::db::tenants::create(
        &f.pool,
        *other.as_uuid(),
        "synthetic-other-principal",
        "free",
    )
    .await
    .unwrap();
    let mut human = f.human.clone();
    human.tenant_id = other.clone();
    let mut config = f.issuer.clone();
    config.audience = "other-audience".into();
    let mut db = f.pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    let registration: Uuid = principal_api::change_tx(
        &tx,
        &human,
        &crate::db::control_audit::Actor::system("synthetic"),
        &config.issuer,
        Some(&config),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    tx.commit().await.unwrap();
    let a =
        principal::test_cached_token(*f.human.tenant_id.as_uuid(), f.registration, &f.issuer).await;
    let b = principal::test_cached_token(*other.as_uuid(), registration, &config).await;
    let headers = |token: &str| {
        let mut h = HeaderMap::new();
        h.insert("tracelane-principal", token.parse().unwrap());
        h
    };
    assert!(matches!(
        principal::verify_headers(&f.pool, &f.human.tenant_id, &headers(&a)).await,
        Input::Verified(_)
    ));
    assert!(matches!(
        principal::verify_headers(&f.pool, &other, &headers(&b)).await,
        Input::Verified(_)
    ));
    assert!(matches!(
        principal::verify_headers(&f.pool, &f.human.tenant_id, &headers(&b)).await,
        Input::Invalid
    ));
    assert!(matches!(
        principal::verify_headers(&f.pool, &other, &headers(&a)).await,
        Input::Invalid
    ));
    db.execute(
        "DELETE FROM tenant_principal_issuers WHERE tenant_id=$1",
        &[other.as_uuid()],
    )
    .await
    .unwrap();
    assert!(matches!(
        principal::verify_headers(&f.pool, &other, &headers(&a)).await,
        Input::Invalid
    ));
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_shared_workos_token_from_other_org_denied() {
    let f = Fixture::new(true).await;
    let _env = approval_pg_tests::SessionEnv::new("http://127.0.0.1:1");
    unsafe {
        std::env::set_var("WORKOS_ISSUER", "https://control-plane.example");
    }
    let other = Uuid::new_v4();
    crate::db::tenants::create(&f.pool, other, "synthetic-other-org", "free")
        .await
        .unwrap();
    let db = f.pool.get().await.unwrap();
    let org: String = db
        .query_one("SELECT workos_org_id FROM tenants WHERE id=$1", &[&other])
        .await
        .unwrap()
        .get(0);
    drop(db);
    let token = principal::test_cached_token_with_claims(
        *f.human.tenant_id.as_uuid(),
        f.registration,
        &f.issuer,
        json!({"org_id":org,"tenant_id":other.to_string()}),
    )
    .await;
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("tracelane-principal", token.parse().unwrap());
    // Same signature, issuer, audience and roles: this proves a usable fixture,
    // before identifying its issuer as the shared control-plane issuer.
    assert!(matches!(
        principal::verify_headers(&f.pool, &f.human.tenant_id, &headers).await,
        Input::Verified(_)
    ));
    unsafe {
        std::env::set_var("WORKOS_ISSUER", &f.issuer.issuer);
    }
    // Covers a registration that predates the registration-time prohibition.
    assert!(matches!(
        principal::verify_headers(&f.pool, &f.human.tenant_id, &headers).await,
        Input::Invalid
    ));
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_shared_workos_issuer_registration_denied() {
    let f = Fixture::new(true).await;
    let _env = approval_pg_tests::SessionEnv::new("http://127.0.0.1:1");
    let mut issuer = f.issuer.clone();
    issuer.issuer = "https://shared-workos.example".into();
    unsafe {
        std::env::set_var("WORKOS_ISSUER", &issuer.issuer);
    }
    let mut db = f.pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    let result = principal_api::change_tx(
        &tx,
        &f.human,
        &crate::db::control_audit::Actor::system("synthetic"),
        &issuer.issuer,
        Some(&issuer),
    )
    .await;
    assert!(
        result.is_err(),
        "shared control-plane issuer must not be registered"
    );
    tx.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_principal_control_plane_issuer_must_be_configured() {
    let f = Fixture::new(true).await;
    let token =
        principal::test_cached_token(*f.human.tenant_id.as_uuid(), f.registration, &f.issuer).await;
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("tracelane-principal", token.parse().unwrap());
    let _env = approval_pg_tests::SessionEnv::new("http://127.0.0.1:1");
    for value in [
        None,
        Some(""),
        Some("not-an-issuer"),
        Some("http://control.example"),
    ] {
        unsafe {
            match value {
                Some(value) => std::env::set_var("WORKOS_ISSUER", value),
                None => std::env::remove_var("WORKOS_ISSUER"),
            }
        }
        assert!(matches!(
            principal::verify_headers(&f.pool, &f.human.tenant_id, &headers).await,
            Input::Unverifiable
        ));
    }
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_principal_clock_skew_at_reservation() {
    let f = Fixture::new(true).await;
    let input = Input::Verified(principal::test_verified(
        *f.agent.tenant_id.as_uuid(),
        f.registration,
        "person",
        Utc::now().timestamp() + 20,
    ));
    assert!(f.run(Some(&input), Uuid::new_v4()).await.is_ok());
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_shared_workos_issuer_url_aliases_denied() {
    let f = Fixture::new(true).await;
    let _env = approval_pg_tests::SessionEnv::new("http://127.0.0.1:1");
    unsafe {
        std::env::set_var("WORKOS_ISSUER", "https://shared-workos.example");
    }
    for alias in [
        "https://SHARED-WORKOS.example",
        "https://shared-workos.example:443",
        "https://shared-workos.example/",
    ] {
        let mut issuer = f.issuer.clone();
        issuer.issuer = alias.into();
        let mut db = f.pool.get().await.unwrap();
        let tx = db.transaction().await.unwrap();
        let result = principal_api::change_tx(
            &tx,
            &f.human,
            &crate::db::control_audit::Actor::system("synthetic"),
            alias,
            Some(&issuer),
        )
        .await;
        assert!(
            result.is_err(),
            "URL-equivalent shared issuer must be refused"
        );
        tx.rollback().await.unwrap();
    }
}

/// Restores the named env vars on drop. Env is process-global: run these ignored PG tests with
/// `--test-threads=1` (the documented invocation for `*_pg_tests.rs`).
struct EnvRestore(Vec<(&'static str, Option<String>)>);
impl EnvRestore {
    fn save(names: &[&'static str]) -> Self {
        Self(names.iter().map(|n| (*n, std::env::var(n).ok())).collect())
    }
}
impl Drop for EnvRestore {
    fn drop(&mut self) {
        for (name, value) in &self.0 {
            unsafe {
                match value {
                    Some(v) => std::env::set_var(name, v),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}

#[cfg(test)]
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_control_plane_audience_or_jwks_under_other_issuer_denied() {
    // A different `iss` spelling must not reopen the shared-issuer hole: the control plane's own
    // audience or JWKS identify its tokens whatever issuer string WorkOS emits.
    let f = Fixture::new(true).await;
    let _env = approval_pg_tests::SessionEnv::new("http://127.0.0.1:1");
    let _restore = EnvRestore::save(&["WORKOS_ISSUER", "WORKOS_AUDIENCE", "WORKOS_JWKS_URL"]);
    unsafe {
        std::env::set_var("WORKOS_ISSUER", "https://shared-workos.example");
        std::env::set_var("WORKOS_AUDIENCE", "client_control_plane");
        std::env::set_var(
            "WORKOS_JWKS_URL",
            "https://shared-workos.example/sso/jwks/client_control_plane",
        );
    }
    let mut same_audience = f.issuer.clone();
    same_audience.issuer = "https://auth.custom-domain.example".into();
    same_audience.audience = "client_control_plane".into();
    // WorkOS ID tokens may carry the client id as `aud` under another `iss` (review M-A).
    let mut client_id_audience = f.issuer.clone();
    client_id_audience.issuer = "https://auth.custom-domain.example".into();
    client_id_audience.audience = std::env::var("WORKOS_CLIENT_ID").unwrap();
    let mut same_jwks = f.issuer.clone();
    same_jwks.issuer = "https://auth.custom-domain.example".into();
    same_jwks.jwks_url = "https://SHARED-WORKOS.example/sso/jwks/client_control_plane".into();
    for (label, issuer) in [
        ("audience", same_audience),
        ("client-id audience", client_id_audience),
        ("jwks", same_jwks),
    ] {
        let mut db = f.pool.get().await.unwrap();
        let tx = db.transaction().await.unwrap();
        let result = principal_api::change_tx(
            &tx,
            &f.human,
            &crate::db::control_audit::Actor::system("synthetic"),
            &issuer.issuer.clone(),
            Some(&issuer),
        )
        .await;
        let err = format!(
            "{:#}",
            result.expect_err("control-plane value must be refused")
        );
        assert!(
            err.contains("principal_invalid"),
            "control-plane {label} must be refused as invalid, got {err}"
        );
        tx.rollback().await.unwrap();
    }
    // A tenant's own IdP, with its own audience and JWKS, is still accepted.
    let mut own = f.issuer.clone();
    own.issuer = "https://auth.custom-domain.example".into();
    principal::validate_issuer(&own).unwrap();
    // With a control plane configured but its audience unknown, the boundary cannot be
    // established: refuse as unverifiable rather than skip the check (review M-A).
    unsafe { std::env::remove_var("WORKOS_AUDIENCE") };
    let err = format!("{:#}", principal::validate_issuer(&own).unwrap_err());
    assert!(err.contains("principal_unverifiable"), "got {err}");
    // An unparseable control-plane JWKS URL fails closed too (review Q2).
    unsafe {
        std::env::set_var("WORKOS_AUDIENCE", "client_control_plane");
        std::env::set_var("WORKOS_JWKS_URL", "not a url");
    }
    let err = format!("{:#}", principal::validate_issuer(&own).unwrap_err());
    assert!(err.contains("principal_unverifiable"), "got {err}");
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_principal_not_before_skew_at_reservation() {
    let f = Fixture::new(true).await;
    let skew = crate::mcp_policy::settings()
        .unwrap()
        .principal
        .clock_skew_secs;
    for (offset, accepted) in [(skew - 10, true), (skew + 60, false)] {
        let now = Utc::now().timestamp();
        let mut verified =
            principal::test_verified(*f.agent.tenant_id.as_uuid(), f.registration, "person", now);
        // Model a trusted verification clock ahead of the database clock; only nbf differs.
        principal::test_set_not_before(&mut verified, now + offset);
        let result = f
            .run(Some(&Input::Verified(verified)), Uuid::new_v4())
            .await;
        if accepted {
            assert!(result.is_ok());
        } else {
            assert_eq!(result.unwrap_err().to_string(), "principal_invalid");
        }
    }
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_principal_token_under_control_plane_kid_refused_at_verify() {
    // Review M-1: a tenant key set cached before the control plane published a key must not
    // verify a token carrying that key id. The test token's kid is "test".
    use axum::http::HeaderMap;
    let f = Fixture::new(true).await;
    let _env = approval_pg_tests::SessionEnv::new("http://127.0.0.1:1");
    unsafe {
        std::env::set_var("WORKOS_ISSUER", "https://control-plane.example");
    }
    let token =
        principal::test_cached_token(*f.human.tenant_id.as_uuid(), f.registration, &f.issuer).await;
    let mut headers = HeaderMap::new();
    headers.insert("tracelane-principal", token.parse().unwrap());
    let control = crate::auth::jwks::seed_control_plane_kids_for_tests(&["control-plane-key"]);
    assert!(matches!(
        principal::verify_headers(&f.pool, &f.human.tenant_id, &headers).await,
        Input::Verified(_)
    ));
    drop(control);
    let _control =
        crate::auth::jwks::seed_control_plane_kids_for_tests(&["control-plane-key", "test"]);
    assert!(matches!(
        principal::verify_headers(&f.pool, &f.human.tenant_id, &headers).await,
        Input::Invalid
    ));
}

//! Disposable-Postgres acceptance tests, discovered by the action_control:: runner filter.
use super::{
    execution::*,
    tests::{claims, grants},
    *,
};
use crate::{
    approvals::protected,
    mcp_policy::{Action, Mode},
};
pub(super) struct Fixture {
    pub(super) pool: deadpool_postgres::Pool,
    pub(super) agent: crate::auth::Claims,
    pub(super) publisher: crate::auth::Claims,
    pub(super) human: crate::auth::Claims,
    pub(super) contract: String,
    pub(super) policy: String,
    pub(super) server: Uuid,
    pub(super) signer: AttestationSigner,
}
const ARGS: &str = r#"{"amount_minor":1500000,"currency":"USD"}"#;
impl Fixture {
    pub(super) async fn new() -> Self {
        Self::with_activation(true).await
    }
    pub(super) async fn legacy() -> Self {
        Self::with_activation(false).await
    }
    async fn with_activation(activate: bool) -> Self {
        let policy = json!({"policy_id":Uuid::new_v4(),"version":1,"agents":null,"approval_ttl_secs":900,"rules":[{"id":"review","when":[{"field":"amount","op":"gt","value":500000}],"decision":"require_approval"}]}).to_string();
        Self::with_policy(activate, policy).await
    }
    async fn with_policy(activate: bool, policy: String) -> Self {
        let (pool, publisher, raw, _) = policy_pg_tests::setup().await;
        let mut c: Value = serde_json::from_str(&raw).unwrap();
        c["fields"] = json!({"amount":{"path":"/amount_minor","kind":"minor_units","required":true,"evidence":"clear"},"currency":{"path":"/currency","kind":"currency","required":true,"evidence":"clear"}});
        let server = Uuid::parse_str(c["server_id"].as_str().unwrap()).unwrap();
        let mut agent = claims(&publisher.tenant_id);
        agent.key_scope =
            crate::auth::scope::KeyScope::Scoped([crate::auth::scope::Scope::Mcp].into());
        let mut human = publisher.clone();
        human.sub = "synthetic-qualified-human".into();
        let mut db = pool.get().await.unwrap();
        db.execute("INSERT INTO api_keys(id,tenant_id,name,key_prefix,minted_by) VALUES($1,$2,'synthetic','test','synthetic-creator')", &[&Uuid::parse_str(agent.api_key_id().unwrap()).unwrap(), agent.tenant_id.as_uuid()]).await.unwrap();
        if activate {
            let tx = db.transaction().await.unwrap();
            policy_store::activate_tx(&tx, &publisher, Some(&grants()), &c.to_string(), &policy)
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }
        db.batch_execute("CREATE TABLE synthetic_approval_effects(tenant_id uuid NOT NULL,id uuid NOT NULL,PRIMARY KEY(tenant_id,id))")
            .await
            .unwrap();
        Self {
            pool: pool.clone(),
            agent,
            publisher,
            human,
            contract: c.to_string(),
            policy,
            server,
            signer: execution_tests::signer(),
        }
    }
    pub(super) async fn other(&self) -> Self {
        let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
        crate::db::tenants::create(
            &self.pool,
            *tenant.as_uuid(),
            "synthetic-other-approval",
            "free",
        )
        .await
        .unwrap();
        let mut agent = claims(&tenant);
        agent.key_scope =
            crate::auth::scope::KeyScope::Scoped([crate::auth::scope::Scope::Mcp].into());
        let mut publisher = self.publisher.clone();
        publisher.tenant_id = tenant.clone();
        let mut human = self.human.clone();
        human.tenant_id = tenant;
        let mut c: Value = serde_json::from_str(&self.contract).unwrap();
        let server = Uuid::new_v4();
        c["server_id"] = json!(server);
        c["tool_ref"] = json!(Uuid::new_v4());
        let mut p: Value = serde_json::from_str(&self.policy).unwrap();
        p["policy_id"] = json!(Uuid::new_v4());
        let mut db = self.pool.get().await.unwrap();
        db.execute("INSERT INTO mcp_servers(id,tenant_id,slug,name,url,transport,auth_mode) VALUES($1,$2,'synthetic','Synthetic','https://example.invalid','streamable_http','none')", &[&server,agent.tenant_id.as_uuid()]).await.unwrap();
        db.execute("INSERT INTO api_keys(id,tenant_id,name,key_prefix,minted_by) VALUES($1,$2,'synthetic','test','synthetic-creator')", &[&Uuid::parse_str(agent.api_key_id().unwrap()).unwrap(),agent.tenant_id.as_uuid()]).await.unwrap();
        let tx = db.transaction().await.unwrap();
        policy_store::activate_tx(
            &tx,
            &publisher,
            Some(&grants()),
            &c.to_string(),
            &p.to_string(),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        Self {
            pool: self.pool.clone(),
            agent,
            publisher,
            human,
            contract: c.to_string(),
            policy: p.to_string(),
            server,
            signer: execution_tests::signer(),
        }
    }
    fn call(&self, id: Uuid, approval: Option<Uuid>) -> Call<'_> {
        Call {
            principal: None,
            server: self.server,
            tool: "pay",
            args: ARGS,
            execution_context: "synthetic-original-context",
            idempotency_key: id,
            approval_id: approval,
            legacy: Action::Allow,
            mode: Mode::Observe,
            definition_changed: false,
        }
    }
    pub(super) async fn pending(&self) -> Uuid {
        let err = execute(
            &self.pool,
            &self.agent,
            Some(&grants()),
            &self.call(Uuid::new_v4(), None),
            &self.signer,
            None,
            |_| async { panic!("unapproved request forwarded") },
        )
        .await
        .unwrap_err();
        err.downcast_ref::<ApprovalRequired>()
            .expect("missing structured pending response")
            .id
    }
    async fn decide(
        &self,
        human: &crate::auth::Claims,
        id: Uuid,
        approve: bool,
    ) -> Option<&'static str> {
        let mut db = self.pool.get().await.unwrap();
        let tx = db.transaction().await.unwrap();
        let (code, _) = protected::decide_tx(
            &tx,
            human,
            Some(&grants()),
            id,
            approve,
            "",
            Some("synthetic-verified-session"),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        code
    }
    pub(super) async fn status(&self, id: Uuid) -> String {
        self.pool
            .get()
            .await
            .unwrap()
            .query_one(
                "SELECT status FROM approvals WHERE tenant_id=$1 AND id=$2",
                &[self.agent.tenant_id.as_uuid(), &id],
            )
            .await
            .unwrap()
            .get(0)
    }
    async fn effects(&self) -> i64 {
        self.pool
            .get()
            .await
            .unwrap()
            .query_one(
                "SELECT count(*) FROM synthetic_approval_effects WHERE tenant_id=$1",
                &[self.agent.tenant_id.as_uuid()],
            )
            .await
            .unwrap()
            .get(0)
    }
    async fn run(&self, key: Uuid, id: Uuid) -> Result<Option<Receipt>> {
        execute(&self.pool,&self.agent,Some(&grants()),&self.call(key,Some(id)),&self.signer,None, |h| async move {
            let a=verify(Some(&h),&self.signer.public_key(),*self.agent.tenant_id.as_uuid(),self.server,"pay",ARGS,Utc::now().timestamp()).unwrap();
            let db=self.pool.get().await.unwrap();
            assert_eq!(self.status(id).await,"consumed","forward before committed consume");
            let evidence:i64=db.query_one("SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1 AND payload::jsonb->>'action_id'=$2 AND event_type IN ('approval_consumed','execution_started')", &[self.agent.tenant_id.as_uuid(),&a.action_id.to_string()]).await.unwrap().get(0);
            assert_eq!(evidence,2,"forward before committed evidence");
            db.execute("INSERT INTO synthetic_approval_effects(tenant_id,id) VALUES($1,$2)", &[self.agent.tenant_id.as_uuid(),&a.action_id]).await.unwrap(); Outcome::Succeeded(a.action_id)
        }).await
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approval_request() {
    let f = Fixture::new().await;
    let id = f.pending().await;
    assert_eq!(f.pending().await, id);
    assert_eq!(f.status(id).await, "pending");
    assert_eq!(f.effects().await, 0);
    let db = f.pool.get().await.unwrap();
    let g = db
        .query_one(
            "SELECT to_jsonb(a) FROM approvals a WHERE tenant_id=$1 AND id=$2",
            &[f.agent.tenant_id.as_uuid(), &id],
        )
        .await
        .unwrap()
        .get::<_, Value>(0);
    assert_eq!(g["request_digest"].as_str().unwrap().len(), 64);
    assert_eq!(g["args_bytes"], i64::try_from(ARGS.len()).unwrap());
    assert_causal_evidence(
        &db,
        &f.agent.tenant_id,
        &g,
        "requested_ledger_seq",
        "approval_requested",
    )
    .await;
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approval_execute() {
    let f = Fixture::new().await;
    let id = f.pending().await;
    assert_eq!(f.decide(&f.human, id, true).await, None);
    let key = Uuid::new_v4();
    let r = f.run(key, id).await.unwrap().unwrap();
    assert_eq!(r.state, State::Succeeded);
    assert_eq!(f.run(key, id).await.unwrap().unwrap(), r);
    assert_eq!(f.effects().await, 1);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approval_deny() {
    let f = Fixture::new().await;
    let id = f.pending().await;
    assert_eq!(f.decide(&f.human, id, false).await, None);
    assert_eq!(f.status(id).await, "denied");
    assert!(f.run(Uuid::new_v4(), id).await.is_err());
    assert_eq!(f.effects().await, 0);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approval_humans() {
    let f = Fixture::new().await;
    let id = f.pending().await;
    let mut creator = f.human.clone();
    creator.sub = "synthetic-creator".into();
    let mut member = f.human.clone();
    member.role = Some(crate::auth::Role::Member);
    let mut master = f.human.clone();
    master.auth_method = crate::auth::AuthMethod::SelfHostMasterKey;
    for bad in [&creator, &f.publisher, &f.agent, &member, &master] {
        assert!(f.decide(bad, id, true).await.is_some());
        assert_eq!(f.status(id).await, "pending");
    }
    assert_eq!(f.decide(&f.human, id, true).await, None);
    assert!(f.decide(&f.human, id, true).await.is_some());
    assert_eq!(f.status(id).await, "approved");
    let n:i64=f.pool.get().await.unwrap().query_one("SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1 AND event_type='approval_attempt_rejected'", &[f.agent.tenant_id.as_uuid()]).await.unwrap().get(0);
    assert_eq!(n, 6);
    let n: i64 = f.pool.get().await.unwrap().query_one("SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1 AND event_type='approval_attempt_rejected' AND actor='self_host_master_key'", &[f.agent.tenant_id.as_uuid()]).await.unwrap().get(0);
    assert_eq!(n, 1);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approval_mutation() {
    let f = Fixture::new().await;
    let id = f.pending().await;
    f.decide(&f.human, id, true).await;
    for args in [
        r#"{"amount_minor":1600000,"currency":"USD"}"#,
        r#"{"amount_minor":1500000,"currency":"USD","extra":true}"#,
    ] {
        let mut c = f.call(Uuid::new_v4(), Some(id));
        c.args = args;
        assert!(
            execute(
                &f.pool,
                &f.agent,
                Some(&grants()),
                &c,
                &f.signer,
                None,
                |_| async { panic!("mutated request forwarded") }
            )
            .await
            .is_err()
        );
        assert_eq!(f.status(id).await, "approved");
    }
    assert_eq!(f.effects().await, 0);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approval_expiry() {
    for approved in [false, true] {
        let f = Fixture::new().await;
        let id = f.pending().await;
        if approved {
            assert_eq!(f.decide(&f.human, id, true).await, None);
        }
        f.pool.get().await.unwrap().execute("UPDATE approvals SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND id=$2", &[f.agent.tenant_id.as_uuid(),&id]).await.unwrap();
        assert!(f.decide(&f.human, id, true).await.is_some());
        assert!(f.run(Uuid::new_v4(), id).await.is_err());
        assert_eq!(f.effects().await, 0);
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approval_activation() {
    for approved in [false, true] {
        let f = Fixture::new().await;
        let id = f.pending().await;
        if approved {
            f.decide(&f.human, id, true).await;
        }
        let mut p: Value = serde_json::from_str(&f.policy).unwrap();
        p["version"] = json!(2);
        let mut db = f.pool.get().await.unwrap();
        let tx = db.transaction().await.unwrap();
        policy_store::activate_tx(
            &tx,
            &f.publisher,
            Some(&grants()),
            &f.contract,
            &p.to_string(),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(f.status(id).await, "invalidated");
        let rows = db.query("SELECT payload FROM audit_log_rows WHERE tenant_id=$1 AND event_type='approval_invalidated' AND payload::jsonb->'body'->>'approval_id'=$2", &[f.agent.tenant_id.as_uuid(), &id.to_string()]).await.unwrap();
        assert_eq!(
            rows.len(),
            1,
            "activation omitted per-grant action evidence"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&rows[0].get::<_, String>(0)).unwrap()["body"],
            json!({"event_type":"approval_invalidated","approval_id":id})
        );

        assert!(f.run(Uuid::new_v4(), id).await.is_err());
        assert!(f.decide(&f.human, id, true).await.is_some());
        assert_eq!(f.effects().await, 0);
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approval_concurrency() {
    let f = std::sync::Arc::new(Fixture::new().await);
    let id = f.pending().await;
    f.decide(&f.human, id, true).await;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(50));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..50 {
        let f = f.clone();
        let b = barrier.clone();
        tasks.spawn(async move {
            b.wait().await;
            f.run(Uuid::new_v4(), id).await.is_ok()
        });
    }
    let mut winners = 0;
    while let Some(r) = tasks.join_next().await {
        winners += usize::from(r.unwrap());
    }
    assert_eq!(winners, 1);
    assert_eq!(f.effects().await, 1);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approval_rollback() {
    let f = Fixture::new().await;
    let id = f.pending().await;
    f.decide(&f.human, id, true).await;
    let mut db = f.pool.get().await.unwrap();
    let before: i64 = db
        .query_one(
            "SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1",
            &[f.agent.tenant_id.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    let tx = db.transaction().await.unwrap();
    reserve_tx(
        &tx,
        &f.agent,
        Some(&grants()),
        &f.call(Uuid::new_v4(), Some(id)),
        &f.signer,
    )
    .await
    .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(f.status(id).await, "approved");
    let after: i64 = db
        .query_one(
            "SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1",
            &[f.agent.tenant_id.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(before, after);
    assert_eq!(f.effects().await, 0);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approval_tenant() {
    let f = Fixture::new().await;
    let other = f.other().await;
    let id = f.pending().await;
    let own = other.pending().await;
    assert_eq!(f.decide(&f.human, id, true).await, None);
    assert_eq!(other.decide(&other.human, own, true).await, None);
    // Populate A's next sequence without changing its approved grant, so a
    // missing consume tenant predicate cannot be masked by its ledger FK.
    assert_eq!(
        f.decide(&f.human, id, true).await,
        Some("approval_not_pending")
    );
    let mut db = f.pool.get().await.unwrap();
    let foreign: Value = db
        .query_one(
            "SELECT to_jsonb(a) FROM approvals a WHERE tenant_id=$1 AND id=$2",
            &[f.agent.tenant_id.as_uuid(), &id],
        )
        .await
        .unwrap()
        .get(0);
    let g: protected::Grant = serde_json::from_value(foreign.clone()).unwrap();
    // Populate both protected tenants, and invoke lookup directly: no contract/key
    // mismatch can mask a missing tenant predicate in either SELECT.
    let tx = db.transaction().await.unwrap();
    let active = policy_store::protected_tx(&tx, &f.agent, Some(&grants()), f.server, "pay")
        .await
        .unwrap()
        .unwrap();
    let mut lookup = other.agent.clone();
    lookup.sub = f.agent.sub.clone();
    assert!(
        protected::find_tx(&tx, &lookup, &active, &g.request_digest, None)
            .await
            .unwrap()
            .0
            .is_none(),
        "automatic lookup disclosed foreign grant"
    );
    assert!(
        protected::find_tx(&tx, &lookup, &active, &g.request_digest, Some(id))
            .await
            .is_err(),
        "selector disclosed foreign grant"
    );
    tx.rollback().await.unwrap();
    let tx = db.transaction().await.unwrap();
    assert!(
        protected::decide_tx(
            &tx,
            &other.human,
            Some(&grants()),
            id,
            true,
            "",
            Some("synthetic-verified-session")
        )
        .await
        .is_err(),
        "decision read foreign row"
    );
    tx.rollback().await.unwrap();
    let next: i64 = db
        .query_one(
            "SELECT coalesce(max(seq),-1)+1 FROM audit_log_rows WHERE tenant_id=$1",
            &[other.agent.tenant_id.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        db.query_opt(
            "SELECT 1 FROM audit_log_rows WHERE tenant_id=$1 AND seq=$2",
            &[f.agent.tenant_id.as_uuid(), &next]
        )
        .await
        .unwrap()
        .is_some(),
        "fixture must satisfy the foreign ledger FK at the consumed-event sequence"
    );
    // Directly test the consume UPDATE, with earlier validation and FK failures
    // excluded; the caller rolls back candidate evidence on a zero-row write.
    let tx = db.transaction().await.unwrap();
    let err = protected::consume_tx(&tx, &other.agent, Some(&grants()), &g)
        .await
        .expect_err("consume updated foreign row");
    assert_eq!(err.to_string(), "approval_expired");
    tx.rollback().await.unwrap();
    assert!(
        other.run(Uuid::new_v4(), id).await.is_err(),
        "foreign selector fell through admission"
    );
    assert_eq!(other.status(own).await, "approved");
    let unchanged: Value = db
        .query_one(
            "SELECT to_jsonb(a) FROM approvals a WHERE tenant_id=$1 AND id=$2",
            &[f.agent.tenant_id.as_uuid(), &id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        foreign, unchanged,
        "foreign grant state or causal reference mutated"
    );
    let key = Uuid::new_v4();
    let original = f.run(key, id).await.unwrap().unwrap();
    let tx = db.transaction().await.unwrap();
    let reserved = reserve_tx(
        &tx,
        &other.agent,
        Some(&grants()),
        &other.call(key, Some(own)),
        &other.signer,
    )
    .await
    .unwrap();
    let Some(Reservation::Started(receipt, _, _, _)) = reserved else {
        panic!("foreign execution receipt leaked")
    };
    assert_ne!(receipt.execution_id, original.execution_id);
    tx.rollback().await.unwrap();
    assert_eq!(f.effects().await, 1);
    assert_eq!(other.effects().await, 0);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approval_legacy() {
    let f = Fixture::new().await;
    let id = Uuid::new_v4();
    f.pool.get().await.unwrap().execute("INSERT INTO approvals(id,tenant_id,subject_kind,subject,requester_sub,args_fp,args_bytes,expires_at,trace_id,status,decided_by,grant_expires_at) VALUES($1,$2,'tool','pay',$3,'legacy',0,clock_timestamp()+interval '1 hour',$1,'approved','synthetic-legacy-human',clock_timestamp()+interval '1 hour')", &[&id,f.agent.tenant_id.as_uuid(),&f.agent.sub]).await.unwrap();
    assert!(f.run(Uuid::new_v4(), id).await.is_err());
    assert_eq!(f.effects().await, 0);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approval_off() {
    let f = Fixture::new().await;
    assert!(
        execute(
            &f.pool,
            &f.agent,
            None,
            &f.call(Uuid::new_v4(), None),
            &f.signer,
            None,
            |_| async { panic!("flag off entered protected forward") }
        )
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(f.effects().await, 0);
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approval_unknown() {
    let f = Fixture::new().await;
    let id = f.pending().await;
    f.decide(&f.human, id, true).await;
    // Only the deferred outcome COMMIT fails: the synthetic forward already committed.
    f.pool.get().await.unwrap().batch_execute("CREATE FUNCTION reject_outcome_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic commit failure'; END $$; CREATE CONSTRAINT TRIGGER reject_outcome_commit AFTER UPDATE ON action_executions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_outcome_commit()").await.unwrap();
    let receipt = f.run(Uuid::new_v4(), id).await.unwrap().unwrap();
    assert_eq!(
        receipt.state,
        State::Unknown,
        "post-forward failure exposed as retryable refusal"
    );
    assert!(
        f.run(Uuid::new_v4(), id).await.is_err(),
        "unknown action re-forwarded under new key"
    );
    assert_eq!(f.effects().await, 1);
    let db = f.pool.get().await.unwrap();
    let state: String = db
        .query_one(
            "SELECT state FROM action_executions WHERE tenant_id=$1 AND execution_id=$2",
            &[f.agent.tenant_id.as_uuid(), &receipt.execution_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        state, "in_flight",
        "lost outcome commit must retain reservation"
    );
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approval_finish_after_disable() {
    let f = Fixture::new().await;
    let id = f.pending().await;
    f.decide(&f.human, id, true).await;
    let mut db = f.pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    let Some(Reservation::Started(mut receipt, _, _, _)) = reserve_tx(
        &tx,
        &f.agent,
        Some(&grants()),
        &f.call(Uuid::new_v4(), Some(id)),
        &f.signer,
    )
    .await
    .unwrap() else {
        panic!("not reserved")
    };
    tx.commit().await.unwrap();
    receipt.state = State::Unknown;
    let tx = db.transaction().await.unwrap();
    finish_tx(&tx, &f.agent, None, &receipt)
        .await
        .expect("flag disabled prevented durable outcome");
    tx.commit().await.unwrap();
    let r = db
        .query_one(
            "SELECT state FROM action_executions WHERE tenant_id=$1 AND execution_id=$2",
            &[f.agent.tenant_id.as_uuid(), &receipt.execution_id],
        )
        .await
        .unwrap();
    assert_eq!(r.get::<_, String>(0), "unknown");
}

async fn assert_causal_evidence(
    db: &tokio_postgres::Client,
    tenant: &TenantId,
    g: &Value,
    seq_field: &str,
    event: &str,
) {
    let seq = g[seq_field].as_i64().unwrap();
    let row = db
        .query_one(
            "SELECT event_type,payload FROM audit_log_rows WHERE tenant_id=$1 AND seq=$2",
            &[tenant.as_uuid(), &seq],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), event);
    let payload: Value = serde_json::from_str(&row.get::<_, String>(1)).unwrap();
    assert_eq!(payload["tenant_id"], tenant.to_string());
    assert_eq!(payload["action_id"], g["action_id"]);
    assert_eq!(payload["request_digest"], g["request_digest"]);
    assert_eq!(payload["body"]["event_type"], event);
    assert_eq!(payload["body"]["approval_id"], g["id"]);
    let decision = db.query_one("SELECT seq,payload FROM audit_log_rows WHERE tenant_id=$1 AND event_type='decision_made' AND payload::jsonb->>'event_id'=$2", &[tenant.as_uuid(), &g["decision_id"].as_str().unwrap()]).await.unwrap();
    let decision_seq = decision.get::<_, i64>(0);
    assert!(
        decision_seq < seq,
        "approval evidence precedes its decision"
    );
    let decision: Value = serde_json::from_str(&decision.get::<_, String>(1)).unwrap();
    assert_eq!(decision["action_id"], g["action_id"]);
    assert_eq!(decision["request_digest"], g["request_digest"]);
    let proposed = db.query_one("SELECT seq,payload FROM audit_log_rows WHERE tenant_id=$1 AND event_type='action_proposed' AND payload::jsonb->>'event_id'=$2", &[tenant.as_uuid(), &g["action_id"].as_str().unwrap()]).await.unwrap();
    let proposal: Value = serde_json::from_str(&proposed.get::<_, String>(1)).unwrap();
    assert_eq!(proposal["action_id"], g["action_id"]);
    assert_eq!(proposal["request_digest"], g["request_digest"]);
    assert!(proposed.get::<_, i64>(0) < decision_seq);
    if seq_field == "decided_ledger_seq" {
        assert!(g["requested_ledger_seq"].as_i64().unwrap() < seq);
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approval_expiry_renews_and_preserves_consumed_fence() {
    for approved in [false, true] {
        let f = Fixture::new().await;
        let old = f.pending().await;
        if approved {
            assert_eq!(f.decide(&f.human, old, true).await, None);
        }
        f.pool.get().await.unwrap().execute("UPDATE approvals SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND id=$2", &[f.agent.tenant_id.as_uuid(),&old]).await.unwrap();
        let new = f.pending().await;
        assert_ne!(old, new);
        assert_eq!(f.status(old).await, "expired");
        let n:i64=f.pool.get().await.unwrap().query_one("SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1 AND event_type='approval_expired' AND payload::jsonb->'body'->>'approval_id'=$2", &[f.agent.tenant_id.as_uuid(), &old.to_string()]).await.unwrap().get(0);
        assert_eq!(n, 1, "lazy expiry omitted action evidence");

        assert_eq!(f.pending().await, new);
        assert_eq!(f.decide(&f.human, new, true).await, None);
        f.run(Uuid::new_v4(), new).await.unwrap();
        f.pool.get().await.unwrap().execute("UPDATE approvals SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND id=$2", &[f.agent.tenant_id.as_uuid(),&new]).await.unwrap();
        let fresh = f.pending().await;
        assert_ne!(fresh, new, "consumed digest blocked a fresh request");
        assert_eq!(f.status(fresh).await, "pending");
        assert!(
            f.run(Uuid::new_v4(), new).await.is_err(),
            "explicit consumed selector replayed"
        );
        assert_eq!(f.status(new).await, "consumed");
        assert_eq!(f.effects().await, 1);
    }
}

impl Fixture {
    pub(super) fn http_state(
        &self,
        resolved: crate::entitlement_cache::ResolvedEntitlements,
    ) -> crate::server::AppState {
        let mut state =
            crate::handler_harness::test_state(crate::providers::ProviderRegistry::new().unwrap());
        state.pg = Some(self.pool.clone());
        state.entitlements = Some(std::sync::Arc::new(
            crate::entitlement_cache::EntitlementCache::new(std::sync::Arc::new(move |_| {
                let r = resolved.clone();
                Box::pin(async move { Ok(r) })
            })),
        ));
        state
    }
    async fn http_decide(
        &self,
        human: &crate::auth::Claims,
        id: Uuid,
        approve: bool,
    ) -> (axum::http::StatusCode, Value) {
        self.http_decide_with_session(human, id, approve, Some("synthetic-verified-session"))
            .await
    }
    async fn http_decide_with_session(
        &self,
        human: &crate::auth::Claims,
        id: Uuid,
        approve: bool,
        sid: Option<&str>,
    ) -> (axum::http::StatusCode, Value) {
        self.http_decide_at(
            human,
            id,
            approve,
            sid,
            Some(chrono::Utc::now().timestamp()),
        )
        .await
    }
    /// ACT-41: decide over HTTP with a signed JWT whose `auth_time` is chosen (`None` omits it).
    pub(super) async fn http_decide_at(
        &self,
        human: &crate::auth::Claims,
        id: Uuid,
        approve: bool,
        sid: Option<&str>,
        auth_time: Option<i64>,
    ) -> (axum::http::StatusCode, Value) {
        use tower::ServiceExt;
        static SESSION_ENV: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        let _lock = SESSION_ENV.lock().await;
        let jwks = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(json!({"keys":[protected::session_tests::jwk()]})),
            )
            .mount(&jwks)
            .await;
        let _env = SessionEnv::new(&jwks.uri());
        let authorization = format!(
            "Bearer {}",
            protected::session_tests::signed_jwt_at(human, sid, auth_time)
        );
        let positive = format!(
            "Bearer {}",
            protected::session_tests::signed_jwt(human, Some("synthetic-positive-control"))
        );
        assert_eq!(
            crate::auth::verified_session(&positive)
                .await
                .unwrap()
                .map(|(s, _)| s),
            Some("synthetic-positive-control".into()),
            "JWT verifier was bypassed before no-session assertion"
        );
        assert_eq!(
            crate::auth::verified_session(&authorization)
                .await
                .unwrap()
                .map(|(s, _)| s),
            sid.map(str::to_owned),
            "fixture did not reach verified session provenance"
        );
        let _auth = crate::auth::test_claims::Guard::set(human.clone());
        let _access = crate::control_plane::test_overrides::Guard::new(
            Some(Ok(Default::default())),
            None,
            None,
        );
        let state = self.http_state(grants());
        let path = format!(
            "/v1/approvals/{id}/{}",
            if approve { "approve" } else { "deny" }
        );
        let response = crate::mcp_routes::router(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("authorization", authorization)
                    .body(axum::body::Body::from(r#"{"note":"synthetic"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap(),
        )
        .unwrap();
        (status, body)
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approval_http_decisions() {
    for approve in [true, false] {
        let f = Fixture::new().await;
        let id = f.pending().await;
        let (status, body) = f.http_decide(&f.human, id, approve).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["status"], if approve { "approved" } else { "denied" });
        assert_eq!(f.status(id).await, body["status"].as_str().unwrap());
        let db = f.pool.get().await.unwrap();
        let g: Value = db
            .query_one(
                "SELECT to_jsonb(a) FROM approvals a WHERE tenant_id=$1 AND id=$2",
                &[f.agent.tenant_id.as_uuid(), &id],
            )
            .await
            .unwrap()
            .get(0);
        assert_causal_evidence(
            &db,
            &f.agent.tenant_id,
            &g,
            "decided_ledger_seq",
            if approve {
                "approval_granted"
            } else {
                "approval_denied"
            },
        )
        .await;
        let (status, _) = f.http_decide(&f.human, id, true).await;
        assert_eq!(status, axum::http::StatusCode::CONFLICT);
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approval_http_refuses_publisher_and_foreign_selector() {
    let f = Fixture::new().await;
    let other = f.other().await;
    let id = f.pending().await;
    let (status, _) = f.http_decide(&f.publisher, id, true).await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    let (status, _) = f.http_decide(&other.human, id, true).await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    assert_eq!(f.status(id).await, "pending");
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approval_context_mutation() {
    let f = Fixture::new().await;
    let id = f.pending().await;
    assert_eq!(f.decide(&f.human, id, true).await, None);
    for context in ["changed-account", "changed-session", "changed-server"] {
        let mut call = f.call(Uuid::new_v4(), Some(id));
        call.execution_context = context;
        let err = execute(
            &f.pool,
            &f.agent,
            Some(&grants()),
            &call,
            &f.signer,
            None,
            |_| async { panic!("changed context forwarded") },
        )
        .await
        .unwrap_err();
        assert_eq!(err.to_string(), "approval_mismatch");
        assert_eq!(f.status(id).await, "approved");
    }
    f.run(Uuid::new_v4(), id).await.unwrap();
    assert_eq!(f.effects().await, 1);
}
#[tokio::test]
#[ignore = "requires isolated Postgres and local TCP listener"]
async fn pg_approval_http_pending_approve_execute_replay() {
    use axum::{
        Json, Router,
        body::{Body, to_bytes},
        http::{HeaderMap, Request, StatusCode},
        routing::post,
    };
    use std::sync::Arc;
    use tower::ServiceExt;
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    crate::tool_fingerprint::init_from_existing_pepper(&"07".repeat(32)).unwrap();
    let f = Fixture::new().await;
    let signer = Arc::new(execution_tests::signer());
    let (pool, tenant, server, pin) = (
        f.pool.clone(),
        f.agent.tenant_id.clone(),
        f.server,
        signer.public_key(),
    );
    let tool=Router::new().route("/",post(move |h:HeaderMap,Json(v):Json<Value>| {
        let (pool,tenant,pin)=(pool.clone(),tenant.clone(),pin.clone());
        async move {
            let args=v["params"]["arguments"].to_string();
            let a=verify(h.get(HEADER).and_then(|v|v.to_str().ok()),&pin,*tenant.as_uuid(),server,"pay",&args,Utc::now().timestamp()).unwrap();
            let db=pool.get().await.unwrap();
            // The real HTTP tool sees only committed consume + started evidence.
            let n:i64=db.query_one("SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1 AND payload::jsonb->>'action_id'=$2 AND event_type IN ('approval_consumed','execution_started')", &[tenant.as_uuid(),&a.action_id.to_string()]).await.unwrap().get(0);
            assert_eq!(n,2);
            db.execute("INSERT INTO synthetic_approval_effects(tenant_id,id) VALUES($1,$2)", &[tenant.as_uuid(),&a.action_id]).await.unwrap();
            Json(json!({"jsonrpc":"2.0","id":v["id"],"result":{"structuredContent":{"tool_receipt":a.action_id}}}))
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, tool).await.unwrap() });
    struct Stop(tokio::task::JoinHandle<()>);
    impl Drop for Stop {
        fn drop(&mut self) {
            self.0.abort()
        }
    }
    let _stop = Stop(task);
    let db = f.pool.get().await.unwrap();
    db.execute(
        "UPDATE mcp_servers SET url=$3 WHERE tenant_id=$1 AND id=$2",
        &[f.agent.tenant_id.as_uuid(), &f.server, &url],
    )
    .await
    .unwrap();
    let mut ent = grants();
    ent.mcp = Some(
        crate::mcp_store::load(&db, f.agent.tenant_id.as_uuid())
            .await
            .unwrap(),
    );
    let mut state = f.http_state(ent);
    state.action_signer = Some(signer);
    let router = crate::mcp_proxy::router(state);
    let key = Uuid::new_v4();
    let body=json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay","arguments":serde_json::from_str::<Value>(ARGS).unwrap()}}).to_string();
    let send = |selector: Option<Uuid>, raw: String| {
        let router = router.clone();
        let auth = f.agent.clone();
        async move {
            let _auth = crate::auth::test_claims::Guard::set(auth);
            let mut request = Request::builder()
                .method("POST")
                .uri("/v1/mcp/synthetic")
                .header("authorization", "Bearer synthetic")
                .header("Idempotency-Key", key.to_string())
                .header(HEADER, "forged inbound attestation");
            if let Some(id) = selector {
                request = request.header("x-tracelane-approval-id", id.to_string());
            }
            let response = router
                .oneshot(request.body(Body::from(raw)).unwrap())
                .await
                .unwrap();
            let status = response.status();
            let body: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap())
                    .unwrap();
            (status, body)
        }
    };
    let (status, pending) = send(None, body.clone()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{pending}");
    assert_eq!(pending["error"], "approval_required");
    let id = Uuid::parse_str(pending["approval_id"].as_str().unwrap()).unwrap();
    assert_eq!(f.effects().await, 0);
    let (_, again) = send(None, body.clone()).await;
    assert_eq!(again["approval_id"], pending["approval_id"]);
    assert_eq!(f.http_decide(&f.human, id, true).await.0, StatusCode::OK);
    let (status, receipt) = send(Some(id), body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["result"]["structuredContent"]["state"], "succeeded");
    let (_, replay) = send(Some(id), body).await;
    assert_eq!(replay, receipt);
    assert_eq!(f.effects().await, 1);
    let duplicate = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay","arguments":{"amount_minor":1,"amount_minor":1500000,"currency":"USD"}}}"#;
    let (status, _) = send(Some(id), duplicate.into()).await;
    assert!(!status.is_success());
    assert_eq!(f.effects().await, 1);
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approval_each_query_tenant_boundary() {
    let f = Fixture::new().await;
    let other = f.other().await;
    let id = f.pending().await;
    let own = other.pending().await;
    let mut db = f.pool.get().await.unwrap();
    db.execute("INSERT INTO approvals(tenant_id,subject_kind,subject,requester_sub,args_fp,args_bytes,expires_at) VALUES($1,'tool','pay','synthetic-extra','synthetic-extra',0,clock_timestamp()+interval '1 hour')", &[f.agent.tenant_id.as_uuid()]).await.unwrap();
    let seq: i64 = db
        .query_one(
            "SELECT requested_ledger_seq FROM approvals WHERE tenant_id=$1 AND id=$2",
            &[other.agent.tenant_id.as_uuid(), &own],
        )
        .await
        .unwrap()
        .get(0);
    let tx = db.transaction().await.unwrap();
    for locked in [false, true] {
        assert!(
            protected::grant_tx(&tx, &other.agent, id, locked)
                .await
                .unwrap()
                .is_none(),
            "foreign grant read (locked={locked})"
        );
        assert!(
            protected::grant_tx(&tx, &other.agent, own, locked)
                .await
                .unwrap()
                .is_some()
        );
        let key = Uuid::parse_str(f.agent.api_key_id().unwrap()).unwrap();
        assert!(
            protected::key_tx(&tx, &other.agent, key, locked)
                .await
                .unwrap()
                .is_none(),
            "foreign key provenance read (locked={locked})"
        );
        let key = Uuid::parse_str(other.agent.api_key_id().unwrap()).unwrap();
        assert!(
            protected::key_tx(&tx, &other.agent, key, locked)
                .await
                .unwrap()
                .is_some()
        );
    }
    assert_eq!(
        protected::pending_count_tx(&tx, &other.agent)
            .await
            .unwrap(),
        1
    );
    assert_eq!(protected::pending_count_tx(&tx, &f.agent).await.unwrap(), 2);
    assert_eq!(
        protected::record_request_tx(&tx, &other.agent, id, seq)
            .await
            .unwrap(),
        0,
        "foreign requested sequence changed"
    );
    assert_eq!(
        protected::record_decision_tx(&tx, &other.human, id, true, seq)
            .await
            .unwrap(),
        0,
        "foreign decision changed"
    );
    tx.rollback().await.unwrap();
    // query_one's no-row result aborts this service operation, not the transaction.
    let tx = db.transaction().await.unwrap();
    let p: Value = serde_json::from_str(&f.policy).unwrap();
    let policy = Uuid::parse_str(p["policy_id"].as_str().unwrap()).unwrap();
    assert!(
        protected::publisher_tx(&tx, &other.agent, policy, 1)
            .await
            .is_err(),
        "foreign publisher read"
    );
    tx.rollback().await.unwrap();
    db.execute("UPDATE approvals SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND id=$2", &[f.agent.tenant_id.as_uuid(),&id]).await.unwrap();
    let tx = db.transaction().await.unwrap();
    assert!(
        protected::expire_tx(&tx, &other.agent.tenant_id, id)
            .await
            .unwrap()
            .is_none(),
        "foreign grant expired"
    );
    tx.rollback().await.unwrap();
    assert_eq!(f.status(id).await, "pending");
    assert_eq!(other.status(own).await, "pending");
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approval_http_capability_denial_records_rejection() {
    let f = Fixture::new().await;
    let other = f.other().await;
    let id = f.pending().await;
    let mut member = f.human.clone();
    member.role = Some(crate::auth::Role::Member);
    for caller in [&member, &f.agent] {
        for approve in [true, false] {
            assert_eq!(
                f.http_decide(caller, id, approve).await.0,
                axum::http::StatusCode::FORBIDDEN
            );
        }
    }
    assert_eq!(f.status(id).await, "pending");
    let db = f.pool.get().await.unwrap();
    let rows = db.query("SELECT payload FROM audit_log_rows WHERE tenant_id=$1 AND event_type='approval_attempt_rejected'", &[f.agent.tenant_id.as_uuid()]).await.unwrap();
    assert_eq!(
        rows.len(),
        4,
        "capability denial lost protected rejection evidence"
    );
    for row in rows {
        let e: Value = serde_json::from_str(&row.get::<_, String>(0)).unwrap();
        assert_eq!(e["body"]["approval_id"], id.to_string());
        assert_eq!(e["tenant_id"], f.agent.tenant_id.to_string());
    }
    assert_eq!(
        f.http_decide(&other.agent, id, true).await.0,
        axum::http::StatusCode::FORBIDDEN
    );
    let n: i64 = db.query_one("SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1 AND event_type='approval_attempt_rejected'", &[f.agent.tenant_id.as_uuid()]).await.unwrap().get(0);
    assert_eq!(n, 4, "foreign attempt wrote victim tenant evidence");
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approval_http_queue_renders_bound_minimized_evidence() {
    use tower::ServiceExt;
    crate::mcp_security_tests::init_master_for_security_tests();
    let f = Fixture::new().await;
    // Add a required token-only beneficiary to the actual activated contract.
    let mut c: Value = serde_json::from_str(&f.contract).unwrap();
    c["version"] = json!(2);
    c["fields"]["beneficiary"] =
        json!({"path":"/beneficiary","kind":"string","required":true,"evidence":"tokenize"});
    let mut p: Value = serde_json::from_str(&f.policy).unwrap();
    p["version"] = json!(2);
    let mut db = f.pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    policy_store::activate_tx(
        &tx,
        &f.publisher,
        Some(&grants()),
        &c.to_string(),
        &p.to_string(),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let mut call = f.call(Uuid::new_v4(), None);
    call.args = r#"{"amount_minor":1500000,"currency":"USD","beneficiary":"synthetic-private-account-1234","memo":"never retain this raw memo"}"#;
    let err = execute(
        &f.pool,
        &f.agent,
        Some(&grants()),
        &call,
        &f.signer,
        None,
        |_| async { panic!("pending forwarded") },
    )
    .await
    .unwrap_err();
    let id = err.downcast_ref::<ApprovalRequired>().unwrap().id;
    let _auth = crate::auth::test_claims::Guard::set(f.human.clone());
    let _access =
        crate::control_plane::test_overrides::Guard::new(Some(Ok(Default::default())), None, None);
    let response = crate::mcp_routes::router(f.http_state(grants()))
        .oneshot(
            axum::http::Request::builder()
                .uri("/v1/approvals?status=pending")
                .header("authorization", "Bearer synthetic")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    let row = body["approvals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == id.to_string())
        .unwrap();
    let preview: Value = serde_json::from_str(
        row["args_preview"]
            .as_str()
            .expect("approval UI has no bound preview"),
    )
    .unwrap();
    assert_eq!(preview["policy_id"], p["policy_id"]);
    assert_eq!(preview["policy_version"], 2);
    assert_eq!(
        preview["evidence_fields"]["amount"]["value"]["MinorUnits"],
        1500000
    );
    assert_eq!(
        preview["evidence_fields"]["currency"]["value"]["Currency"],
        "USD"
    );
    assert_eq!(
        preview["evidence_fields"]["beneficiary"]["mode"],
        "tokenize"
    );
    assert_eq!(preview["evidence_fields"]["beneficiary"]["last4"], "1234");
    assert_eq!(
        preview["evidence_fields"]["beneficiary"]["hmac"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    let wire = std::str::from_utf8(&bytes).unwrap();
    assert!(!wire.contains("synthetic-private-account"));
    assert!(!wire.contains("never retain"));
    let proposed = db.query_one("SELECT payload FROM audit_log_rows WHERE tenant_id=$1 AND event_type='action_proposed' AND payload::jsonb->>'action_id'=$2", &[f.agent.tenant_id.as_uuid(), &row["action_id"].as_str().unwrap()]).await.unwrap();
    let proposed: Value = serde_json::from_str(&proposed.get::<_, String>(0)).unwrap();
    assert_eq!(
        preview["evidence_fields"], proposed["body"]["evidence_fields"],
        "preview is not the bound proposal evidence"
    );
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approval_http_activation_between_classification_and_dispatch() {
    use tower::ServiceExt;
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    let f = Fixture::legacy().await;
    crate::tool_fingerprint::init_from_existing_pepper(&"07".repeat(32)).unwrap();
    let mut db = f.pool.get().await.unwrap();
    db.execute(
        "UPDATE mcp_servers SET url='http://127.0.0.1:1/' WHERE tenant_id=$1 AND id=$2",
        &[f.agent.tenant_id.as_uuid(), &f.server],
    )
    .await
    .unwrap();
    let mut ent = grants();
    ent.mcp = Some(
        crate::mcp_store::load(&db, f.agent.tenant_id.as_uuid())
            .await
            .unwrap(),
    );
    let mut state = f.http_state(ent);
    state.action_signer = Some(std::sync::Arc::new(execution_tests::signer()));
    let router = crate::mcp_proxy::router(state);
    let classified = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let resume = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let _auth = crate::auth::test_claims::Guard::set(f.agent.clone());
    let request = crate::mcp_proxy::protected::CLASSIFICATION_PAUSE.scope((classified.clone(),resume.clone()), async {
        router.oneshot(axum::http::Request::builder().method("POST").uri("/v1/mcp/synthetic")
            .header("authorization", "Bearer synthetic").header("Idempotency-Key", Uuid::new_v4().to_string())
            .body(axum::body::Body::from(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay","arguments":serde_json::from_str::<Value>(ARGS).unwrap()}}).to_string())).unwrap()).await.unwrap()
    });
    let activation = async {
        classified.wait().await;
        let tx = db.transaction().await.unwrap();
        policy_store::activate_tx(&tx, &f.publisher, Some(&grants()), &f.contract, &f.policy)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        resume.wait().await;
    };
    let (response, ()) = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        tokio::join!(request, activation)
    })
    .await
    .expect("activation handoff deadlocked");
    assert_eq!(
        response.status(),
        axum::http::StatusCode::CONFLICT,
        "activation escaped onto legacy forwarding path"
    );
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["error"], "approval_required");
    let count: i64 = db.query_one("SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1 AND event_type='approval_requested'", &[f.agent.tenant_id.as_uuid()]).await.unwrap().get(0);
    assert_eq!(count, 1);
    assert_eq!(f.effects().await, 0);
}

// Used only by ignored PG HTTP tests; serialize process env and restore on panic.
pub(super) struct SessionEnv(Vec<(&'static str, Option<std::ffi::OsString>)>);
impl SessionEnv {
    pub(super) fn new(url: &str) -> Self {
        let values = [
            ("WORKOS_CLIENT_ID", "synthetic-c1-4"),
            ("WORKOS_JWKS_URL", url),
            ("WORKOS_ISSUER", "synthetic-c1-4"),
            ("WORKOS_AUDIENCE", "synthetic-c1-4"),
            ("TRACELANE_JWKS_TEST_ALLOW_ANY_HOST", "1"),
            ("TRACELANE_SSRF_ALLOW_LOOPBACK_FOR_TESTS", "1"),
        ];
        let saved = values
            .iter()
            .map(|(k, _)| (*k, std::env::var_os(k)))
            .collect();
        for (key, value) in values {
            unsafe {
                std::env::set_var(key, value);
            }
        }
        Self(saved)
    }
}
impl Drop for SessionEnv {
    fn drop(&mut self) {
        for (key, value) in &self.0 {
            unsafe {
                if let Some(value) = value {
                    std::env::set_var(key, value);
                } else {
                    std::env::remove_var(key);
                }
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires isolated Postgres and local JWKS fixture"]
async fn pg_approval_signed_owner_without_sid_records_rejection() {
    let f = Fixture::new().await;
    let id = f.pending().await;
    for approve in [true, false] {
        let (status, body) = f
            .http_decide_with_session(&f.human, id, approve, None)
            .await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"], "unauthorized");
        assert_eq!(f.status(id).await, "pending");
    }
    let db = f.pool.get().await.unwrap();
    let rows = db.query("SELECT payload FROM audit_log_rows WHERE tenant_id=$1 AND event_type='approval_attempt_rejected'", &[f.agent.tenant_id.as_uuid()]).await.unwrap();
    assert_eq!(rows.len(), 2);
    for row in rows {
        let event: Value = serde_json::from_str(&row.get::<_, String>(0)).unwrap();
        assert_eq!(event["body"]["approval_id"], id.to_string());
        assert_eq!(event["body"]["reason"], "unauthorized");
        assert!(!event.to_string().contains(&f.human.sub));
    }
    let decided: Option<i64> = db
        .query_one(
            "SELECT decided_ledger_seq FROM approvals WHERE tenant_id=$1 AND id=$2",
            &[f.agent.tenant_id.as_uuid(), &id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(decided, None);
    assert_eq!(f.effects().await, 0);
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_approval_sweeper_expires_protected_with_atomic_minimized_audit() {
    for approved in [false, true] {
        let f = Fixture::new().await;
        let id = f.pending().await;
        if approved {
            assert_eq!(f.decide(&f.human, id, true).await, None);
        }
        let db = f.pool.get().await.unwrap();
        db.execute("UPDATE approvals SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND id=$2", &[f.agent.tenant_id.as_uuid(), &id]).await.unwrap();
        db.batch_execute("CREATE FUNCTION synthetic_block_expiry_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='approval.expire' THEN RAISE EXCEPTION 'synthetic expiry evidence unavailable'; END IF; RETURN NEW; END $$; CREATE TRIGGER synthetic_block_expiry_audit BEFORE INSERT ON admin_audit_log FOR EACH ROW EXECUTE FUNCTION synthetic_block_expiry_audit()").await.unwrap();
        assert!(crate::approvals::expire(&f.pool, None).await.is_err());
        assert_eq!(
            f.status(id).await,
            if approved { "approved" } else { "pending" }
        );
        db.batch_execute("DROP TRIGGER synthetic_block_expiry_audit ON admin_audit_log")
            .await
            .unwrap();
        assert_eq!(crate::approvals::expire(&f.pool, None).await.unwrap(), 1);
        assert_eq!(f.status(id).await, "expired");
        assert_eq!(crate::approvals::expire(&f.pool, None).await.unwrap(), 0);
        let rows = db.query("SELECT before_json,after_json FROM admin_audit_log WHERE actor_workspace_id=$1 AND action='approval.expire' AND target_id=$2", &[f.agent.tenant_id.as_uuid(), &id.to_string()]).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].get::<_, Value>(0),
            json!({"status":if approved {"approved"} else {"pending"}})
        );
        assert_eq!(rows[0].get::<_, Value>(1), json!({"status":"expired"}));
        let rows = db.query("SELECT payload FROM audit_log_rows WHERE tenant_id=$1 AND event_type='approval_expired' AND payload::jsonb->'body'->>'approval_id'=$2", &[f.agent.tenant_id.as_uuid(), &id.to_string()]).await.unwrap();
        assert_eq!(rows.len(), 1, "sweeper omitted canonical action evidence");
        assert_eq!(
            serde_json::from_str::<Value>(&rows[0].get::<_, String>(0)).unwrap()["body"],
            json!({"event_type":"approval_expired","approval_id":id})
        );

        assert_eq!(f.effects().await, 0);
    }
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_fix_pass_refused_decisions_write_at_most_budget_rows() {
    use tower::ServiceExt;
    let f = Fixture::new().await;
    let id = f.pending().await;
    let mut member = f.human.clone();
    member.role = Some(crate::auth::Role::Member);
    let _auth = crate::auth::test_claims::Guard::set(member);
    let _rate = crate::control_plane::test_overrides::RateGuard::set(2, 100);
    let app = crate::mcp_routes::router(f.http_state(grants()));
    for _ in 0..3 {
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/v1/approvals/{id}/approve"))
                    .header("authorization", "Bearer synthetic")
                    .body(axum::body::Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }
    let n:i64 = f.pool.get().await.unwrap().query_one("SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1 AND event_type='approval_attempt_rejected'", &[f.agent.tenant_id.as_uuid()]).await.unwrap().get(0);
    assert_eq!(n, 2, "N+1 refused attempts exceeded evidence budget");
    assert_eq!(f.status(id).await, "pending");
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_fix_pass_nonhuman_creators_cannot_request_approval() {
    let f = Fixture::new().await;
    let key = Uuid::parse_str(f.agent.api_key_id().unwrap()).unwrap();
    for creator in ["apikey:synthetic", "self-host", "dev-stub"] {
        f.pool
            .get()
            .await
            .unwrap()
            .execute(
                "UPDATE api_keys SET minted_by=$3 WHERE tenant_id=$1 AND id=$2",
                &[f.agent.tenant_id.as_uuid(), &key, &creator],
            )
            .await
            .unwrap();
        let err = execute(
            &f.pool,
            &f.agent,
            Some(&grants()),
            &f.call(Uuid::new_v4(), None),
            &f.signer,
            None,
            |_| async { panic!("invalid creator forwarded") },
        )
        .await
        .unwrap_err();
        assert_eq!(err.to_string(), "separation_required");
    }
    let n: i64 = f
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT count(*) FROM approvals WHERE tenant_id=$1",
            &[f.agent.tenant_id.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(n, 0);
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_fix_pass_stalled_legacy_calls_leave_shared_pool_available() {
    use std::sync::Arc;
    use tower::ServiceExt;
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    crate::tool_fingerprint::init_from_existing_pepper(&"07".repeat(32)).unwrap();
    let f = Fixture::legacy().await;
    let other = f.other().await;
    f.pool.resize(16);
    let upstream = wiremock::MockServer::start().await;
    struct Stalled(Arc<tokio::sync::Semaphore>);
    impl wiremock::Respond for Stalled {
        fn respond(&self, _: &wiremock::Request) -> wiremock::ResponseTemplate {
            self.0.add_permits(1);
            wiremock::ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_secs(30))
                .set_body_json(json!({"jsonrpc":"2.0","id":1,"result":{"content":[]}}))
        }
    }
    let entered = Arc::new(tokio::sync::Semaphore::new(0));
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(Stalled(entered.clone()))
        .mount(&upstream)
        .await;
    let db = f.pool.get().await.unwrap();
    db.execute(
        "UPDATE mcp_servers SET url=$3 WHERE tenant_id=$1 AND id=$2",
        &[f.agent.tenant_id.as_uuid(), &f.server, &upstream.uri()],
    )
    .await
    .unwrap();
    let mut ent = grants();
    ent.mcp = Some(
        crate::mcp_store::load(&db, f.agent.tenant_id.as_uuid())
            .await
            .unwrap(),
    );
    drop(db);
    assert_eq!(
        f.pool.status().max_size,
        16,
        "test must exceed the shared production pool size"
    );
    let app = crate::mcp_proxy::router(f.http_state(ent));
    let _auth = crate::auth::test_claims::Guard::set(f.agent.clone());
    let calls = futures::future::join_all((0..20).map(|_| {
        let app = app.clone();
        async move { app.oneshot(axum::http::Request::builder().method("POST").uri("/v1/mcp/synthetic")
            .header("authorization","Bearer synthetic").body(axum::body::Body::from(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay","arguments":{}}}).to_string())).unwrap()).await.unwrap() }
    }));
    let observer = async {
        let entered16 =
            tokio::time::timeout(std::time::Duration::from_secs(5), entered.acquire_many(16))
                .await
                .expect("legacy calls never reached upstream")
                .unwrap();
        entered16.forget();
        let control = tokio::time::timeout(std::time::Duration::from_millis(500), async {
            f.pool
                .get()
                .await
                .unwrap()
                .query_one(
                    "SELECT id FROM tenants WHERE id=$1",
                    &[other.agent.tenant_id.as_uuid()],
                )
                .await
                .unwrap()
        })
        .await
        .expect("stalled upstream exhausted another tenant's control-plane pool");
        assert_eq!(control.get::<_, Uuid>(0), *other.agent.tenant_id.as_uuid());
        let remaining =
            tokio::time::timeout(std::time::Duration::from_secs(2), entered.acquire_many(4))
                .await
                .expect("more than 16 legacy sends could not proceed")
                .unwrap();
        remaining.forget();
    };
    tokio::select! { _ = calls => panic!("upstream did not stall"), () = observer => {} }
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_fix_pass_ip_sso_and_rate_refusals_write_no_action_rows() {
    use tower::ServiceExt;
    for kind in ["ip", "sso", "rate"] {
        let f = Fixture::new().await;
        let id = f.pending().await;
        let _auth = crate::auth::test_claims::Guard::set(f.human.clone());
        let access = crate::db::admin_security::AdminAccess {
            admin_ip_allowlist: if kind == "ip" {
                vec!["192.0.2.0/24".into()]
            } else {
                vec![]
            },
            sso_required: kind == "sso",
            ..Default::default()
        };
        let _access = crate::control_plane::test_overrides::Guard::new(
            Some(Ok(access)),
            Some(Ok(false)),
            None,
        );
        let _rate = crate::control_plane::test_overrides::RateGuard::set(1, 100);
        if kind == "rate" {
            crate::control_plane::require_control(
                &f.human,
                crate::auth::capability::Capability::ApproveToolCalls,
                &axum::http::HeaderMap::new(),
            )
            .await
            .unwrap();
        }
        let app = crate::mcp_routes::router(f.http_state(grants()));
        for decision in ["approve", "deny"] {
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method("POST")
                        .uri(format!("/v1/approvals/{id}/{decision}"))
                        .header("authorization", "Bearer synthetic")
                        .body(axum::body::Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                if kind == "rate" {
                    axum::http::StatusCode::TOO_MANY_REQUESTS
                } else {
                    axum::http::StatusCode::FORBIDDEN
                }
            );
        }
        let n:i64=f.pool.get().await.unwrap().query_one("SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1 AND event_type='approval_attempt_rejected'", &[f.agent.tenant_id.as_uuid()]).await.unwrap().get(0);
        assert_eq!(n, 0, "{kind} refusal wrote action evidence");
        assert_eq!(f.status(id).await, "pending");
    }
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_fix_pass_lifecycle_action_evidence_failure_rolls_back_all_three_writers() {
    for writer in ["lazy", "sweeper", "activation"] {
        let f = Fixture::new().await;
        let id = f.pending().await;
        let mut db = f.pool.get().await.unwrap();
        let before: i64 = db
            .query_one(
                "SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1",
                &[f.agent.tenant_id.as_uuid()],
            )
            .await
            .unwrap()
            .get(0);
        db.batch_execute("ALTER TABLE audit_log_rows ADD CONSTRAINT synthetic_no_lifecycle CHECK (event_type NOT IN ('approval_expired','approval_invalidated')) NOT VALID").await.unwrap();
        if writer == "activation" {
            let mut p: Value = serde_json::from_str(&f.policy).unwrap();
            p["version"] = json!(2);
            let tx = db.transaction().await.unwrap();
            assert!(
                policy_store::activate_tx(
                    &tx,
                    &f.publisher,
                    Some(&grants()),
                    &f.contract,
                    &p.to_string()
                )
                .await
                .is_err()
            );
            tx.rollback().await.unwrap();
            let version: i32 = db
                .query_one(
                    "SELECT version FROM action_policy_active WHERE tenant_id=$1",
                    &[f.agent.tenant_id.as_uuid()],
                )
                .await
                .unwrap()
                .get(0);
            assert_eq!(version, 1, "failed invalidation advanced policy pointer");
        } else {
            db.execute("UPDATE approvals SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND id=$2", &[f.agent.tenant_id.as_uuid(),&id]).await.unwrap();
            if writer == "sweeper" {
                assert!(crate::approvals::expire(&f.pool, None).await.is_err());
            } else {
                assert!(
                    execute(
                        &f.pool,
                        &f.agent,
                        Some(&grants()),
                        &f.call(Uuid::new_v4(), None),
                        &f.signer,
                        None,
                        |_| async { panic!("failed expiry forwarded") }
                    )
                    .await
                    .is_err()
                );
            }
        }
        assert_eq!(
            f.status(id).await,
            "pending",
            "{writer} changed status without action evidence"
        );
        let after: i64 = db
            .query_one(
                "SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1",
                &[f.agent.tenant_id.as_uuid()],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(before, after, "{writer} left orphan evidence");
    }
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_fix_pass_activation_during_send_records_legacy_forward_attempt() {
    use std::sync::Arc;
    use tower::ServiceExt;
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    crate::tool_fingerprint::init_from_existing_pepper(&"07".repeat(32)).unwrap();
    let f = Fixture::legacy().await;
    let entered = Arc::new(tokio::sync::Semaphore::new(0));
    let release = Arc::new(tokio::sync::Notify::new());
    let handler_entered = entered.clone();
    let handler_release = release.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |headers: axum::http::HeaderMap| {
            let entered = handler_entered.clone();
            let release = handler_release.clone();
            async move {
                assert!(
                    !headers.contains_key(HEADER),
                    "legacy send was mislabeled as protected"
                );
                entered.add_permits(1);
                release.notified().await;
                axum::Json(json!({"jsonrpc":"2.0","id":1,"result":{"content":[]}}))
            }
        }),
    );
    let upstream_task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut db = f.pool.get().await.unwrap();
    db.execute(
        "UPDATE mcp_servers SET url=$3 WHERE tenant_id=$1 AND id=$2",
        &[f.agent.tenant_id.as_uuid(), &f.server, &url],
    )
    .await
    .unwrap();
    let mut ent = grants();
    ent.mcp = Some(
        crate::mcp_store::load(&db, f.agent.tenant_id.as_uuid())
            .await
            .unwrap(),
    );
    let app = crate::mcp_proxy::router(f.http_state(ent));
    let _auth = crate::auth::test_claims::Guard::set(f.agent.clone());
    let call=app.oneshot(axum::http::Request::builder().method("POST").uri("/v1/mcp/synthetic")
        .header("authorization","Bearer synthetic").body(axum::body::Body::from(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay","arguments":serde_json::from_str::<Value>(ARGS).unwrap()}}).to_string())).unwrap());
    let activation = async {
        let permit = entered.acquire().await.unwrap();
        permit.forget();
        let tx = db.transaction().await.unwrap();
        policy_store::activate_tx(&tx, &f.publisher, Some(&grants()), &f.contract, &f.policy)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        release.notify_one();
    };
    let (response, ()) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(call, activation)
    })
    .await
    .expect("activation/send deadlock");
    let response = response.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::CONFLICT);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["error"], "effect_may_have_occurred_do_not_retry");
    let rows=db.query("SELECT payload FROM audit_log_rows WHERE tenant_id=$1 AND event_type='legacy_forward_attempted'",&[f.agent.tenant_id.as_uuid()]).await.unwrap();
    assert_eq!(
        rows.len(),
        1,
        "legacy race omitted truthful action evidence"
    );
    let body: Value =
        serde_json::from_str::<Value>(&rows[0].get::<_, String>(0)).unwrap()["body"].clone();
    assert_eq!(
        body,
        json!({"event_type":"legacy_forward_attempted","server_id":f.server,"activation_epoch":1})
    );
    let n:i64=db.query_one("SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1 AND event_type IN ('execution_started','approval_consumed')",&[f.agent.tenant_id.as_uuid()]).await.unwrap().get(0);
    assert_eq!(n, 0, "legacy race fabricated protected execution evidence");
    upstream_task.abort();
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_fix_pass_lifecycle_and_legacy_race_evidence_is_immutable() {
    let f = Fixture::new().await;
    let mut db = f.pool.get().await.unwrap();
    for tag in [
        "approval_expired",
        "approval_invalidated",
        "legacy_forward_attempted",
    ] {
        let body: ActionPayload = serde_json::from_value(if tag == "legacy_forward_attempted" {
            json!({"event_type":tag,"server_id":f.server,"activation_epoch":1})
        } else {
            json!({"event_type":tag,"approval_id":Uuid::new_v4()})
        })
        .unwrap();
        let e = ActionEvent {
            event_id: Uuid::new_v4(),
            action_id: Uuid::new_v4(),
            occurred_at: Utc::now(),
            request_digest: "a".repeat(64),
            body,
        };
        let tx = db.transaction().await.unwrap();
        let rows = append_actions_tx(&tx, &f.agent, Some(&grants()), &[e])
            .await
            .unwrap()
            .unwrap();
        tx.commit().await.unwrap();
        let seq = i64::try_from(rows.first_seq).unwrap();
        for sql in [
            "UPDATE audit_log_rows SET payload='{}' WHERE tenant_id=$1 AND seq=$2",
            "DELETE FROM audit_log_rows WHERE tenant_id=$1 AND seq=$2",
        ] {
            let err = db
                .execute(sql, &[f.agent.tenant_id.as_uuid(), &seq])
                .await
                .expect_err("new action evidence was mutable");
            assert!(err.to_string().contains("db error"), "{err}");
            assert_eq!(
                err.as_db_error().unwrap().message(),
                "protected action evidence is append only"
            );
        }
    }
}

/// N1 (2026-10-25 review): the pre-send re-check refuses when protection activated
/// after preflight. Its only input is this epoch, so activation must move it, and an
/// unchanged workspace must not.
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_legacy_epoch_moves_on_activation_so_presend_recheck_refuses() {
    let f = Fixture::legacy().await;
    let mut db = f.pool.get().await.unwrap();
    let before = legacy_epoch(&mut db, &f).await;
    assert_eq!(
        legacy_epoch(&mut db, &f).await,
        before,
        "epoch moved with no activation"
    );
    let tx = db.transaction().await.unwrap();
    policy_store::activate_tx(&tx, &f.publisher, Some(&grants()), &f.contract, &f.policy)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_ne!(
        legacy_epoch(&mut db, &f).await,
        before,
        "activation left the epoch unchanged: the pre-send re-check could not refuse"
    );
}

async fn legacy_epoch(db: &mut deadpool_postgres::Object, f: &Fixture) -> i64 {
    let tx = db.transaction().await.unwrap();
    let e = policy_store::legacy_epoch_tx(&tx, &f.agent, f.server, "pay")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    e
}

/// 2026-10-29 SRE review: in Enforce mode a LEGACY `require_approval` rule lifts a protected
/// policy's `allow` to RequireApproval (`policy::evaluate`, `protected.max(legacy)`), but a
/// policy with no approval rule of its own need not carry `approval_ttl_secs`
/// (`parse_policy` only demands it then). `request_tx` then failed `approval_policy_invalid`,
/// the transaction rolled back, and every call to the tool answered 503
/// `protected_execution_unavailable` with no evidence — permanently. RED before the fix.
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_legacy_require_approval_without_policy_ttl_pends_instead_of_bricking() {
    let policy = json!({"policy_id":Uuid::new_v4(),"version":1,"agents":null,"rules":[{"id":"ok","when":[{"field":"amount","op":"gt","value":0}],"decision":"allow"}]}).to_string();
    let f = Fixture::with_policy(true, policy).await;
    let mut call = f.call(Uuid::new_v4(), None);
    call.legacy = Action::RequireApproval;
    call.mode = Mode::Enforce;
    let err = execute(
        &f.pool,
        &f.agent,
        Some(&grants()),
        &call,
        &f.signer,
        None,
        |_| async { panic!("an unapproved legacy-gated call was forwarded") },
    )
    .await
    .unwrap_err();
    let pending = err
        .downcast_ref::<ApprovalRequired>()
        .unwrap_or_else(|| panic!("expected a pending approval, got `{err}`"));
    assert_eq!(f.status(pending.id).await, "pending");
    assert_eq!(f.effects().await, 0);
    let ttl = i64::from(
        crate::mcp_policy::settings()
            .unwrap()
            .approvals
            .default_ttl_secs,
    );
    let left = (pending.expires_at - Utc::now()).num_seconds();
    assert!(
        (ttl - 60..=ttl).contains(&left),
        "default legacy TTL applies: {left}s of {ttl}s"
    );

    // The tenant's own legacy TTL wins over the table default (as `mcp_store` resolves it).
    f.pool
        .get()
        .await
        .unwrap()
        .execute(
            "INSERT INTO approval_settings(tenant_id,default_ttl_secs,updated_by) VALUES($1,120,'synthetic')",
            &[f.agent.tenant_id.as_uuid()],
        )
        .await
        .unwrap();
    let mut call = f.call(Uuid::new_v4(), None);
    call.args = r#"{"amount_minor":1500001,"currency":"USD"}"#;
    call.legacy = Action::RequireApproval;
    call.mode = Mode::Enforce;
    let err = execute(
        &f.pool,
        &f.agent,
        Some(&grants()),
        &call,
        &f.signer,
        None,
        |_| async { panic!("an unapproved legacy-gated call was forwarded") },
    )
    .await
    .unwrap_err();
    let pending = err.downcast_ref::<ApprovalRequired>().expect("pending");
    let left = (pending.expires_at - Utc::now()).num_seconds();
    assert!(
        (60..=120).contains(&left),
        "tenant TTL applies: {left}s of 120s"
    );
}

const NOTICE_KEYS: [&str; 9] = [
    "type",
    "approval_id",
    "subject",
    "subject_kind",
    "protected",
    "expires_at",
    "queue_path",
    "rule",
    "server_name",
];
async fn add_channel(f: &Fixture, tenant: &Uuid) {
    f.pool.get().await.unwrap().execute("INSERT INTO spend_alert_channels(id,tenant_id,kind,name,target,secret_enc) VALUES($1,$2,'webhook','synthetic','https://example.invalid/hook','synthetic-sealed')", &[&Uuid::new_v4(), tenant]).await.unwrap();
}
async fn events(f: &Fixture, tenant: &Uuid) -> Vec<(String, Value)> {
    let rows = f.pool.get().await.unwrap().query("SELECT dedup_key,payload FROM spend_alert_events WHERE tenant_id=$1 ORDER BY created_at", &[tenant]).await.unwrap();
    rows.iter().map(|r| (r.get(0), r.get(1))).collect()
}
/// One channel, one pending protected approval: its single outbox row.
async fn notified() -> (Fixture, Uuid, String, Value) {
    let f = Fixture::new().await;
    add_channel(&f, f.agent.tenant_id.as_uuid()).await;
    let id = f.pending().await;
    let ev = events(&f, f.agent.tenant_id.as_uuid()).await;
    assert_eq!(ev.len(), 1, "one channel, one row");
    let (k, p) = ev.into_iter().next().unwrap();
    (f, id, k, p)
}
async fn approval_row(f: &Fixture, id: Uuid) -> Value {
    f.pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT to_jsonb(a) FROM approvals a WHERE tenant_id=$1 AND id=$2",
            &[f.agent.tenant_id.as_uuid(), &id],
        )
        .await
        .unwrap()
        .get(0)
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_protected_approval_enqueues_notification() {
    let (_f, _id, _k, p) = notified().await;
    assert_eq!(p["type"], "approval.requested");
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_protected_approval_notifies_every_channel() {
    let f = Fixture::new().await;
    add_channel(&f, f.agent.tenant_id.as_uuid()).await;
    add_channel(&f, f.agent.tenant_id.as_uuid()).await;
    f.pending().await;
    assert_eq!(events(&f, f.agent.tenant_id.as_uuid()).await.len(), 2);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_protected_notification_dedup_key_is_window_bucket() {
    let (f, _id, k, _p) = notified().await;
    let now: i64 = f
        .pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT extract(epoch from clock_timestamp())::bigint", &[])
        .await
        .unwrap()
        .get(0);
    let window = crate::mcp_policy::settings()
        .unwrap()
        .approvals
        .approval_notice_window_secs;
    let bucket: i64 = k
        .strip_prefix("approval-waiting:")
        .expect("bucket key")
        .parse()
        .unwrap();
    assert!(
        (now / window - bucket).abs() <= 1,
        "{k} vs {}",
        now / window
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_protected_notifications_coalesce_within_one_window() {
    let f = Fixture::new().await;
    add_channel(&f, f.agent.tenant_id.as_uuid()).await;
    add_channel(&f, f.agent.tenant_id.as_uuid()).await;
    let mut ids = std::collections::HashSet::new();
    for i in 0..10 {
        let mut call = f.call(Uuid::new_v4(), None);
        let args = format!(r#"{{"amount_minor":{},"currency":"USD"}}"#, 1_500_000 + i);
        call.args = &args;
        let err = execute(
            &f.pool,
            &f.agent,
            Some(&grants()),
            &call,
            &f.signer,
            None,
            |_| async { panic!("unapproved request forwarded") },
        )
        .await
        .unwrap_err();
        ids.insert(err.downcast_ref::<ApprovalRequired>().unwrap().id);
    }
    assert_eq!(ids.len(), 10, "distinct approvals");
    assert_eq!(
        events(&f, f.agent.tenant_id.as_uuid()).await.len(),
        2,
        "one row per channel"
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_protected_notification_next_window_enqueues_again() {
    let (f, _id, _k, _p) = notified().await;
    f.pool
        .get()
        .await
        .unwrap()
        .execute(
            "UPDATE spend_alert_events SET dedup_key='approval-waiting:1' WHERE tenant_id=$1",
            &[f.agent.tenant_id.as_uuid()],
        )
        .await
        .unwrap();
    let mut call = f.call(Uuid::new_v4(), None);
    call.args = r#"{"amount_minor":1500009,"currency":"USD"}"#;
    execute(
        &f.pool,
        &f.agent,
        Some(&grants()),
        &call,
        &f.signer,
        None,
        |_| async { panic!("unapproved request forwarded") },
    )
    .await
    .unwrap_err();
    assert_eq!(events(&f, f.agent.tenant_id.as_uuid()).await.len(), 2);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_protected_notification_carries_approval_id() {
    let (_f, id, _k, p) = notified().await;
    assert_eq!(p["approval_id"], json!(id));
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_protected_notification_subject_is_tool_name() {
    let (_f, _id, _k, p) = notified().await;
    assert_eq!(p["subject"], "pay");
    assert_eq!(p["subject_kind"], "tool");
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_protected_notification_expiry_matches_row() {
    let (f, id, _k, p) = notified().await;
    let row = approval_row(&f, id).await;
    let n = DateTime::parse_from_rfc3339(p["expires_at"].as_str().unwrap()).unwrap();
    let r = DateTime::parse_from_rfc3339(row["expires_at"].as_str().unwrap()).unwrap();
    assert_eq!(n, r);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_protected_notification_is_marked_protected() {
    let (_f, _id, _k, p) = notified().await;
    assert_eq!(p["protected"], true);
    assert_eq!(p["queue_path"], "/settings/gateway/approvals");
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_protected_notification_payload_has_only_declared_keys() {
    let (_f, _id, _k, p) = notified().await;
    let mut got: Vec<&str> = p.as_object().unwrap().keys().map(String::as_str).collect();
    got.sort_unstable();
    let mut want = NOTICE_KEYS.to_vec();
    want.sort_unstable();
    assert_eq!(got, want);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_protected_notification_has_no_evidence_values() {
    let (_f, _id, _k, p) = notified().await;
    let s = p.to_string();
    for v in [
        "1500000",
        "USD",
        "amount",
        "currency",
        "beneficiary",
        "last4",
        "evidence",
    ] {
        assert!(!s.contains(v), "payload leaks `{v}`: {s}");
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_protected_notification_has_no_digests() {
    let (f, id, _k, p) = notified().await;
    let row = approval_row(&f, id).await;
    let s = p.to_string();
    for k in [
        "request_digest",
        "policy_hash",
        "args_fp",
        "policy_id",
        "digest",
    ] {
        assert!(!s.contains(k), "payload names `{k}`");
    }
    for k in ["request_digest", "policy_hash", "args_fp", "policy_id"] {
        assert!(
            !s.contains(row[k].as_str().unwrap()),
            "payload carries {k} value"
        );
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_protected_notification_not_duplicated_on_retry() {
    let (f, id, _k, _p) = notified().await;
    assert_eq!(f.pending().await, id);
    assert_eq!(events(&f, f.agent.tenant_id.as_uuid()).await.len(), 1);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_protected_approval_without_channels_writes_no_event() {
    let f = Fixture::new().await;
    let id = f.pending().await;
    assert_eq!(f.status(id).await, "pending");
    assert!(events(&f, f.agent.tenant_id.as_uuid()).await.is_empty());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_flag_off_writes_no_protected_notification() {
    let f = Fixture::new().await;
    add_channel(&f, f.agent.tenant_id.as_uuid()).await;
    let r = execute(
        &f.pool,
        &f.agent,
        None,
        &f.call(Uuid::new_v4(), None),
        &f.signer,
        None,
        |_| async { panic!("flag off entered protected forward") },
    )
    .await;
    assert!(r.unwrap().is_none());
    assert!(events(&f, f.agent.tenant_id.as_uuid()).await.is_empty());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_allowed_call_writes_no_notification() {
    let policy = json!({"policy_id":Uuid::new_v4(),"version":1,"agents":null,"rules":[{"id":"ok","when":[{"field":"amount","op":"gt","value":0}],"decision":"allow"}]}).to_string();
    let f = Fixture::with_policy(true, policy).await;
    add_channel(&f, f.agent.tenant_id.as_uuid()).await;
    let (pk, tid, server) = (
        f.signer.public_key(),
        *f.agent.tenant_id.as_uuid(),
        f.server,
    );
    let _ = execute(
        &f.pool,
        &f.agent,
        Some(&grants()),
        &f.call(Uuid::new_v4(), None),
        &f.signer,
        None,
        |h| async move {
            let a = verify(
                Some(&h),
                &pk,
                tid,
                server,
                "pay",
                ARGS,
                Utc::now().timestamp(),
            )
            .unwrap();
            Outcome::Succeeded(a.action_id)
        },
    )
    .await;
    assert!(events(&f, f.agent.tenant_id.as_uuid()).await.is_empty());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_denied_call_writes_no_notification() {
    let policy = json!({"policy_id":Uuid::new_v4(),"version":1,"agents":null,"rules":[{"id":"deny","when":[],"decision":"deny"}]}).to_string();
    let f = Fixture::with_policy(true, policy).await;
    add_channel(&f, f.agent.tenant_id.as_uuid()).await;
    let r = execute(
        &f.pool,
        &f.agent,
        Some(&grants()),
        &f.call(Uuid::new_v4(), None),
        &f.signer,
        None,
        |_| async { panic!("denied call forwarded") },
    )
    .await;
    assert!(r.is_err(), "deny must refuse");
    assert!(events(&f, f.agent.tenant_id.as_uuid()).await.is_empty());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_outbox_failure_rolls_back_approval() {
    let f = Fixture::new().await;
    add_channel(&f, f.agent.tenant_id.as_uuid()).await;
    f.pool.get().await.unwrap().batch_execute("CREATE FUNCTION synthetic_block_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic outbox unavailable'; END $$; CREATE TRIGGER synthetic_block_outbox BEFORE INSERT ON spend_alert_events FOR EACH ROW EXECUTE FUNCTION synthetic_block_outbox()").await.unwrap();
    let err = execute(
        &f.pool,
        &f.agent,
        Some(&grants()),
        &f.call(Uuid::new_v4(), None),
        &f.signer,
        None,
        |_| async { panic!("unapproved request forwarded") },
    )
    .await
    .unwrap_err();
    assert!(
        err.downcast_ref::<ApprovalRequired>().is_none(),
        "no pending reply"
    );
    let n: i64 = f
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT count(*) FROM approvals WHERE tenant_id=$1",
            &[f.agent.tenant_id.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(n, 0, "approval row survived a failed outbox insert");
    // 503 class: only the named 4xx codes map elsewhere (mcp_protected::refusal).
    let msg = err.to_string();
    for known in [
        "approval_mismatch",
        "approval_expired",
        "approval_denied",
        "policy_denied",
        "idempotency_mismatch",
        "protected_transport_unsupported",
    ] {
        assert_ne!(msg, known);
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_protected_notification_never_reaches_other_tenant_channel() {
    let f = Fixture::new().await;
    let other = f.other().await;
    add_channel(&f, other.agent.tenant_id.as_uuid()).await;
    f.pending().await;
    assert!(events(&f, other.agent.tenant_id.as_uuid()).await.is_empty());
    assert!(events(&f, f.agent.tenant_id.as_uuid()).await.is_empty());
}

#[path = "evidence_tests.rs"]
mod evidence_tests;
#[path = "export_pg_tests.rs"]
pub(super) mod export_pg_tests;
#[path = "heartbeat_pg_tests.rs"]
mod heartbeat_pg_tests;
#[path = "receipt_pg_tests.rs"]
mod receipt_pg_tests;
#[path = "timeline_pg_tests.rs"]
mod timeline_pg_tests;

// ── ACT-41: approving needs a recent sign-in ─────────────────────────────────────────────
async fn act41_row(f: &Fixture, id: Uuid) -> Value {
    f.pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT jsonb_build_object('status',status,'at',extract(epoch from decided_auth_at)::bigint,'method',decided_auth_method) FROM approvals WHERE tenant_id=$1 AND id=$2",
            &[f.agent.tenant_id.as_uuid(), &id],
        )
        .await
        .unwrap()
        .get(0)
}
const ACT41_SID: Option<&str> = Some("synthetic-verified-session");

#[tokio::test]
#[ignore = "requires isolated Postgres and local JWKS fixture"]
async fn pg_act41_stale_sign_in_cannot_approve() {
    let f = Fixture::new().await;
    let id = f.pending().await;
    let stale = chrono::Utc::now().timestamp() - 901;
    let (status, body) = f
        .http_decide_at(&f.human, id, true, ACT41_SID, Some(stale))
        .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "reauth_required");
    let row = act41_row(&f, id).await;
    assert_eq!(
        row["status"], "pending",
        "a refused step-up decided the row"
    );
    assert!(row["method"].is_null());
}

#[tokio::test]
#[ignore = "requires isolated Postgres and local JWKS fixture"]
async fn pg_act41_missing_auth_time_cannot_approve() {
    let f = Fixture::new().await;
    let id = f.pending().await;
    let (status, body) = f.http_decide_at(&f.human, id, true, ACT41_SID, None).await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "reauth_required");
    assert_eq!(act41_row(&f, id).await["status"], "pending");
}

#[tokio::test]
#[ignore = "requires isolated Postgres and local JWKS fixture"]
async fn pg_act41_future_auth_time_cannot_approve() {
    let f = Fixture::new().await;
    let id = f.pending().await;
    let future = chrono::Utc::now().timestamp() + 3_600;
    let (status, body) = f
        .http_decide_at(&f.human, id, true, ACT41_SID, Some(future))
        .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{body}");
    assert_eq!(act41_row(&f, id).await["status"], "pending");
}

#[tokio::test]
#[ignore = "requires isolated Postgres and local JWKS fixture"]
async fn pg_act41_fresh_sign_in_approves_and_records_it() {
    let f = Fixture::new().await;
    let id = f.pending().await;
    let at = chrono::Utc::now().timestamp() - 60;
    let (status, body) = f
        .http_decide_at(&f.human, id, true, ACT41_SID, Some(at))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let row = act41_row(&f, id).await;
    assert_eq!(row["status"], "approved");
    assert_eq!(row["at"], at, "the signed auth_time, not the decision time");
    assert_eq!(row["method"], "workos_session");
}

#[tokio::test]
#[ignore = "requires isolated Postgres and local JWKS fixture"]
async fn pg_act41_stale_sign_in_can_still_deny() {
    let f = Fixture::new().await;
    let id = f.pending().await;
    let stale = chrono::Utc::now().timestamp() - 86_400;
    let (status, body) = f
        .http_decide_at(&f.human, id, false, ACT41_SID, Some(stale))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let row = act41_row(&f, id).await;
    assert_eq!(row["status"], "denied");
    assert!(
        row["at"].is_null() && row["method"].is_null(),
        "deny records no step-up"
    );
}

#[tokio::test]
#[ignore = "requires isolated Postgres and local JWKS fixture"]
async fn pg_act41_unrecordable_auth_rolls_the_approval_back() {
    let f = Fixture::new().await;
    let id = f.pending().await;
    // Force the auth record to miss its row: the decision lands with another decider.
    f.pool
        .get()
        .await
        .unwrap()
        .batch_execute(
            "CREATE FUNCTION act41_swap_decider() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN IF NEW.status='approved' THEN NEW.decided_by := 'synthetic-someone-else'; END IF; RETURN NEW; END $$; \
             CREATE TRIGGER act41_swap BEFORE UPDATE ON approvals FOR EACH ROW EXECUTE FUNCTION act41_swap_decider();",
        )
        .await
        .unwrap();
    let at = chrono::Utc::now().timestamp() - 60;
    let (status, body) = f
        .http_decide_at(&f.human, id, true, ACT41_SID, Some(at))
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "{body}"
    );
    let row = act41_row(&f, id).await;
    assert_eq!(
        row["status"], "pending",
        "decision survived a missing auth record"
    );
    assert!(row["at"].is_null() && row["method"].is_null());
}

#[tokio::test]
#[ignore = "requires isolated Postgres and local JWKS fixture"]
async fn pg_act41_refusal_names_the_window_and_is_audited() {
    let f = Fixture::new().await;
    let id = f.pending().await;
    let stale = chrono::Utc::now().timestamp() - 901;
    let (status, body) = f
        .http_decide_at(&f.human, id, true, ACT41_SID, Some(stale))
        .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["max_age_secs"], 900);
    let after: Value = f
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT after_json FROM admin_audit_log WHERE actor_workspace_id=$1 AND target_id=$2 AND action='approval.reauth_required'",
            &[f.agent.tenant_id.as_uuid(), &id.to_string()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(after["reason"], "auth_time_outside_window");
    assert_eq!(after["max_age_secs"], 900);
}

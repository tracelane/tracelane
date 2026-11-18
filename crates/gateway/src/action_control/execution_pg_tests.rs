//! Real disposable Postgres, selected by run-postgres-integration.sh action_control::.
use super::tests::grants;
use super::{
    execution::*,
    execution_tests::{ARGS, signer},
    *,
};
use crate::mcp_policy::Action;
struct Fixture {
    pool: deadpool_postgres::Pool,
    auth: crate::auth::Claims,
    contract: policy::Contract,
    signer: AttestationSigner,
}
impl Fixture {
    async fn new() -> Self {
        let (pool, human, c, p) = super::policy_pg_tests::setup().await;
        let mut p: Value = serde_json::from_str(&p).unwrap();
        p["rules"][0]["decision"] = json!("allow");
        let mut c: Value = serde_json::from_str(&c).unwrap();
        c["fields"] = json!({"amount":{"path":"/amount_minor","kind":"minor_units","required":true,"evidence":"clear"},"currency":{"path":"/currency","kind":"currency","required":true,"evidence":"clear"}});
        let mut db = pool.get().await.unwrap();
        let tx = db.transaction().await.unwrap();
        policy_store::activate_tx(&tx, &human, Some(&grants()), &c.to_string(), &p.to_string())
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let auth = super::tests::claims(&human.tenant_id);
        let key = Uuid::parse_str(auth.api_key_id().unwrap()).unwrap();
        db.execute("INSERT INTO api_keys(id,tenant_id,name,key_prefix,minted_by) VALUES ($1,$2,'synthetic','test','synthetic')",&[&key,auth.tenant_id.as_uuid()]).await.unwrap();
        // The committed row IS the synthetic effect and replay record, atomically.
        db.batch_execute("CREATE TABLE synthetic_payments(tenant_id uuid NOT NULL,idempotency_key uuid NOT NULL,receipt uuid NOT NULL,PRIMARY KEY(tenant_id,idempotency_key))").await.unwrap();
        Self {
            pool: pool.clone(),
            auth,
            contract: policy::parse_contract(&c.to_string()).unwrap(),
            signer: signer(),
        }
    }
    async fn other(&self) -> Self {
        let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
        crate::db::tenants::create(&self.pool, *tenant.as_uuid(), "synthetic-other", "free")
            .await
            .unwrap();
        let auth = super::tests::claims(&tenant);
        let mut contract = self.contract.clone();
        contract.server_id = Uuid::new_v4();
        contract.tool_ref = Uuid::new_v4();
        let mut db = self.pool.get().await.unwrap();
        db.execute("INSERT INTO mcp_servers(id,tenant_id,slug,name,url,transport,auth_mode) VALUES ($1,$2,'synthetic','Synthetic','https://example.invalid','streamable_http','none')",&[&contract.server_id,tenant.as_uuid()]).await.unwrap();
        let key = Uuid::parse_str(auth.api_key_id().unwrap()).unwrap();
        db.execute("INSERT INTO api_keys(id,tenant_id,name,key_prefix,minted_by) VALUES ($1,$2,'synthetic','test','synthetic')",&[&key,tenant.as_uuid()]).await.unwrap();
        let mut human = auth.clone();
        human.auth_method = crate::auth::AuthMethod::JwtBearer;
        human.role = Some(crate::auth::Role::Owner);
        human.sub = "synthetic-publisher".into();
        let policy=json!({"policy_id":Uuid::new_v4(),"version":1,"agents":null,"rules":[{"id":"allow","when":[],"decision":"allow"}]}).to_string();
        let tx = db.transaction().await.unwrap();
        policy_store::activate_tx(
            &tx,
            &human,
            Some(&grants()),
            &canonical(&contract).unwrap(),
            &policy,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        Self {
            pool: self.pool.clone(),
            auth,
            contract,
            signer: signer(),
        }
    }
    fn input(&self, id: Uuid) -> Call<'_> {
        Call {
            principal: None,
            server: self.contract.server_id,
            tool: &self.contract.tool_name,
            args: ARGS,
            execution_context: "synthetic-original-context",
            idempotency_key: id,
            approval_id: None,
            legacy: Action::Allow,
            mode: crate::mcp_policy::Mode::Observe,
            definition_changed: false,
        }
    }
    async fn tool(&self, header: Option<&str>) -> Result<Uuid> {
        let a = verify(
            header,
            &self.signer.public_key(),
            *self.auth.tenant_id.as_uuid(),
            self.contract.server_id,
            "pay",
            ARGS,
            Utc::now().timestamp(),
        )?;
        let id = Uuid::new_v4();
        let n=self.pool.get().await?.execute("INSERT INTO synthetic_payments(tenant_id,idempotency_key,receipt) VALUES ($1,$2,$3) ON CONFLICT (tenant_id,idempotency_key) DO NOTHING",&[self.auth.tenant_id.as_uuid(),&a.idempotency_key,&id]).await?;
        ensure!(n == 1, "replayed_attestation");
        Ok(id)
    }
    async fn assert_committed_causal_rows(&self, db: &tokio_postgres::Client, header: &str) {
        let a = verify(
            Some(header),
            &self.signer.public_key(),
            *self.auth.tenant_id.as_uuid(),
            self.contract.server_id,
            "pay",
            ARGS,
            Utc::now().timestamp(),
        )
        .unwrap();
        // This observer lease is held before execute begins, forcing its writer
        // onto another physical connection. Check the exact execution identity
        // and its three causal ledger rows through an independent snapshot.
        let rows = db.query(
            "SELECT l.event_type FROM action_executions e JOIN audit_log_rows l ON l.tenant_id=e.tenant_id AND l.seq BETWEEN e.ledger_seq-2 AND e.ledger_seq WHERE e.tenant_id=$1 AND e.execution_id=$2 AND e.action_id=$3 AND e.agent_key_id=$4 AND e.idempotency_key=$5 AND e.request_digest=$6 AND e.state='in_flight' ORDER BY l.seq",
            &[self.auth.tenant_id.as_uuid(), &a.execution_id, &a.action_id,
              &a.agent_key_id, &a.idempotency_key, &a.request_digest],
        ).await.unwrap();
        assert_eq!(
            rows.iter()
                .map(|r| r.get::<_, String>(0))
                .collect::<Vec<_>>(),
            ["action_proposed", "decision_made", "execution_started"],
            "forward entered before its causal rows committed"
        );
    }
    async fn run(&self, id: Uuid) -> Receipt {
        execute(
            &self.pool,
            &self.auth,
            Some(&grants()),
            &self.input(id),
            &self.signer,
            None,
            |h| async move { Outcome::Succeeded(self.tool(Some(&h)).await.unwrap()) },
        )
        .await
        .unwrap()
        .unwrap()
    }
    async fn count(&self, table: &str) -> i64 {
        let sql = match table {
            "tool" => "SELECT count(*) FROM synthetic_payments WHERE tenant_id=$1",
            "execution" => "SELECT count(*) FROM action_executions WHERE tenant_id=$1",
            _ => {
                "SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1 AND event_type!='policy_activated'"
            }
        };
        self.pool
            .get()
            .await
            .unwrap()
            .query_one(sql, &[self.auth.tenant_id.as_uuid()])
            .await
            .unwrap()
            .get(0)
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_execution() {
    let f = Fixture::new().await;
    assert!(f.tool(None).await.is_err());
    assert_eq!(f.count("tool").await, 0);
    let id = Uuid::new_v4();
    let receipt = f.run(id).await;
    assert_eq!(receipt.state, State::Succeeded);
    assert_eq!(f.count("tool").await, 1);
    let db = f.pool.get().await.unwrap();
    let t = f.auth.tenant_id.as_uuid();
    let rows=db.query("SELECT event_type FROM audit_log_rows WHERE tenant_id=$1 AND event_type!='policy_activated' ORDER BY seq",&[t]).await.unwrap();
    assert_eq!(
        rows.iter()
            .map(|r| r.get::<_, String>(0))
            .collect::<Vec<_>>(),
        vec![
            "action_proposed",
            "decision_made",
            "execution_started",
            "execution_succeeded"
        ]
    );
    let digest: String = db
        .query_one(
            "SELECT receipt_digest FROM action_executions WHERE tenant_id=$1 AND execution_id=$2",
            &[t, &receipt.execution_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(digest, sha(canonical(&receipt).unwrap().as_bytes()));
    let mut changed = f.input(id);
    changed.args = r#"{"amount_minor":15000,"currency":"USD"}"#;
    let mut client = f.pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    assert!(
        reserve_tx(&tx, &f.auth, Some(&grants()), &changed, &f.signer)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    assert_eq!(f.count("tool").await, 1);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_duplicates() {
    let f = std::sync::Arc::new(Fixture::new().await);
    let id = Uuid::new_v4();
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(20));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let (f, b) = (f.clone(), barrier.clone());
        tasks.spawn(async move {
            b.wait().await;
            f.run(id).await
        });
    }
    let mut receipts = Vec::new();
    while let Some(r) = tasks.join_next().await {
        receipts.push(r.unwrap())
    }
    assert_eq!(f.count("tool").await, 1);
    assert_eq!(f.count("execution").await, 1);
    let original = receipts
        .iter()
        .find(|r| r.state == State::Succeeded)
        .unwrap();
    for r in &receipts {
        assert_eq!(r.execution_id, original.execution_id)
    }
    for _ in 0..20 {
        assert_eq!(f.run(id).await, *original)
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_tool_replay() {
    let f = Fixture::new().await;
    let mut db = f.pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    let Some(Reservation::Started(_, h, _, _)) = reserve_tx(
        &tx,
        &f.auth,
        Some(&grants()),
        &f.input(Uuid::new_v4()),
        &f.signer,
    )
    .await
    .unwrap() else {
        panic!("no reservation")
    };
    tx.commit().await.unwrap();
    f.tool(Some(&h)).await.unwrap();
    assert!(f.tool(Some(&h)).await.is_err());
    assert_eq!(f.count("tool").await, 1);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_timeout() {
    let f = Fixture::new().await;
    let input = f.input(Uuid::new_v4());
    let borrowed = &f;
    let r = execute(
        &f.pool,
        &f.auth,
        Some(&grants()),
        &input,
        &f.signer,
        None,
        |h| async move {
            borrowed.tool(Some(&h)).await.unwrap();
            tokio::time::pause();
            struct Resume;
            impl Drop for Resume {
                fn drop(&mut self) {
                    tokio::time::resume();
                }
            }
            let _resume = Resume;
            std::future::pending().await
        },
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(r.state, State::Unknown);
    assert_eq!(f.run(input.idempotency_key).await, r);
    assert_eq!(f.count("tool").await, 1);
    let n:i64=f.pool.get().await.unwrap().query_one("SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1 AND event_type='execution_unknown'",&[f.auth.tenant_id.as_uuid()]).await.unwrap().get(0);
    assert_eq!(n, 1);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_execute_observes_committed_causal_rows() {
    let f = Fixture::new().await;
    let borrowed = &f;
    let observer = f.pool.get().await.unwrap();
    let reader: &tokio_postgres::Client = &observer;
    let receipt = execute(
        &f.pool,
        &f.auth,
        Some(&grants()),
        &f.input(Uuid::new_v4()),
        &f.signer,
        None,
        |h| async move {
            borrowed.assert_committed_causal_rows(reader, &h).await;
            Outcome::Succeeded(borrowed.tool(Some(&h)).await.unwrap())
        },
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(receipt.state, State::Succeeded);
    assert_eq!(f.count("tool").await, 1);
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_execute_commit_failure_sends_nothing() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let f = Fixture::new().await;
    let borrowed = &f;
    let db = f.pool.get().await.unwrap();
    let before = db
        .query_one(
            "SELECT last_seq,last_row_hash FROM audit_chain_state WHERE tenant_id=$1",
            &[f.auth.tenant_id.as_uuid()],
        )
        .await
        .unwrap();
    // Reservation and all its appends succeed; failure happens only at COMMIT.
    db.batch_execute("CREATE FUNCTION reject_execution_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected_execution_commit_failure'; END $$;
        CREATE CONSTRAINT TRIGGER reject_execution_commit AFTER INSERT ON action_executions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_execution_commit()")
        .await.unwrap();
    let sends = AtomicUsize::new(0);
    let id = Uuid::new_v4();
    let err = execute(
        &f.pool,
        &f.auth,
        Some(&grants()),
        &f.input(id),
        &f.signer,
        None,
        |h| {
            sends.fetch_add(1, Ordering::SeqCst);
            async move { Outcome::Succeeded(borrowed.tool(Some(&h)).await.unwrap()) }
        },
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.downcast_ref::<tokio_postgres::Error>()
            .unwrap()
            .as_db_error()
            .unwrap()
            .message(),
        "injected_execution_commit_failure"
    );
    assert_eq!(
        sends.load(Ordering::SeqCst),
        0,
        "failed commit invoked forward"
    );
    for table in ["tool", "execution", "ledger"] {
        assert_eq!(f.count(table).await, 0, "commit failure residue {table}");
    }
    let after = db
        .query_one(
            "SELECT last_seq,last_row_hash FROM audit_chain_state WHERE tenant_id=$1",
            &[f.auth.tenant_id.as_uuid()],
        )
        .await
        .unwrap();
    assert_eq!(before.get::<_, i64>(0), after.get::<_, i64>(0));
    assert_eq!(before.get::<_, Vec<u8>>(1), after.get::<_, Vec<u8>>(1));
    db.batch_execute("DROP TRIGGER reject_execution_commit ON action_executions")
        .await
        .unwrap();
    assert_eq!(f.run(id).await.state, State::Succeeded);
    assert_eq!(f.count("tool").await, 1);
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_stalled_clickhouse_dispatches_once() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;
    let f = Fixture::new().await;
    let borrowed = &f;
    let observer = f.pool.get().await.unwrap();
    let reader: &tokio_postgres::Client = &observer;
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::any())
        .respond_with(wiremock::ResponseTemplate::new(200).set_delay(Duration::from_secs(60)))
        .mount(&server)
        .await;
    let chain = Arc::new(
        crate::audit::AuditChain::with_pg_pool(0, None, Some(&server.uri()), Some(f.pool.clone()))
            .unwrap(),
    );
    let sends = AtomicUsize::new(0);
    let input = f.input(Uuid::new_v4());
    let receipt = tokio::time::timeout(
        Duration::from_secs(2),
        execute(
            &f.pool,
            &f.auth,
            Some(&grants()),
            &input,
            &f.signer,
            Some(&chain),
            |h| {
                sends.fetch_add(1, Ordering::SeqCst);
                async move {
                    borrowed.assert_committed_causal_rows(reader, &h).await;
                    Outcome::Succeeded(borrowed.tool(Some(&h)).await.unwrap())
                }
            },
        ),
    )
    .await
    .expect("stalled ClickHouse blocked protected dispatch/receipt")
    .unwrap()
    .unwrap();
    assert_eq!(receipt.state, State::Succeeded);
    // Witness actual INSERT I/O, rather than passing because copying was omitted.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let requests = server.received_requests().await.unwrap();
            if requests.iter().any(|r| {
                r.url.query_pairs().any(|(key, value)| {
                    key == "query" && value.starts_with("INSERT INTO audit_log(")
                })
            }) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("derived copy never attempted ClickHouse INSERT");
    for _ in 0..3 {
        let retry = execute(
            &f.pool,
            &f.auth,
            Some(&grants()),
            &input,
            &f.signer,
            Some(&chain),
            |_| async { panic!("duplicate forwarded during ClickHouse outage") },
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(retry, receipt);
    }
    assert_eq!(sends.load(Ordering::SeqCst), 1);
    assert_eq!(f.count("tool").await, 1);
    assert_eq!(f.count("execution").await, 1);
    assert_eq!(f.count("ledger").await, 4);
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_rollback_execution() {
    let f = Fixture::new().await;
    let mut db = f.pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    reserve_tx(
        &tx,
        &f.auth,
        Some(&grants()),
        &f.input(Uuid::new_v4()),
        &f.signer,
    )
    .await
    .unwrap()
    .unwrap();
    tx.rollback().await.unwrap();
    for table in ["tool", "execution", "ledger"] {
        assert_eq!(f.count(table).await, 0, "rollback residue {table}")
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_execution_tenant() {
    let f = Fixture::new().await;
    let id = Uuid::new_v4();
    let first = f.run(id).await;
    let second = f.other().await;
    assert_ne!(
        second.run(id).await.execution_id,
        first.execution_id,
        "foreign receipt disclosed"
    );
    assert_eq!(second.count("tool").await, 1);
    let mut foreign = second.auth.clone();
    foreign.sub = f.auth.sub.clone();
    let mut db = f.pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    for name in ["pay", "Pay", "release_payment"] {
        assert!(
            policy_store::load_tx(&tx, &foreign, Some(&grants()), f.contract.server_id, name)
                .await
                .unwrap()
                .is_none()
        );
    }
    let Some(Reservation::Started(mut r, _, _, _)) = reserve_tx(
        &tx,
        &f.auth,
        Some(&grants()),
        &f.input(Uuid::new_v4()),
        &f.signer,
    )
    .await
    .unwrap() else {
        panic!("no reservation")
    };
    r.state = State::Unknown;
    assert!(finish_tx(&tx, &foreign, Some(&grants()), &r).await.is_err());
    tx.rollback().await.unwrap();
    let mut changed = f.auth.clone();
    changed.sub = second.auth.sub;
    assert!(
        execute(
            &f.pool,
            &changed,
            Some(&grants()),
            &f.input(Uuid::new_v4()),
            &f.signer,
            None,
            |_| async { panic!("foreign key forwarded") }
        )
        .await
        .is_err()
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_execution_off() {
    let f = Fixture::new().await;
    f.pool
        .get()
        .await
        .unwrap()
        .batch_execute("DROP TABLE action_executions")
        .await
        .unwrap();
    for off in [
        None,
        Some(crate::entitlement_cache::ResolvedEntitlements::deny_all()),
    ] {
        assert!(
            execute(
                &f.pool,
                &f.auth,
                off.as_ref(),
                &f.input(Uuid::new_v4()),
                &f.signer,
                None,
                |_| async { panic!("flag off sent") }
            )
            .await
            .unwrap()
            .is_none()
        );
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_tool_variants() {
    let f = Fixture::new().await;
    let mut db = f.pool.get().await.unwrap();
    for name in ["Pay", " pay", "pay ", "release_payment"] {
        let tx = db.transaction().await.unwrap();
        let mut input = f.input(Uuid::new_v4());
        input.tool = name;
        assert!(
            reserve_tx(&tx, &f.auth, Some(&grants()), &input, &f.signer)
                .await
                .is_err(),
            "protected alias fell through: {name}"
        );
        tx.rollback().await.unwrap();
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_decision_retry() {
    let f = Fixture::new().await;
    let mut db = f.pool.get().await.unwrap();
    let mut request = policy_store::Request {
        principal: None,
        server: f.contract.server_id,
        tool: "pay",
        args: ARGS.as_bytes(),
        action_id: Uuid::new_v4(),
        decision_id: Uuid::new_v4(),
        denial_id: Uuid::new_v4(),
    };
    let other = f.other().await;
    for tenant in [&f, &other] {
        request.server = tenant.contract.server_id;
        // A retry recomputes allow, but must return the committed deny.
        for (expected, legacy) in [(2, Action::Deny), (0, Action::Allow)] {
            let tx = db.transaction().await.unwrap();
            let (v, rows) = policy_store::decide_tx(
                &tx,
                &tenant.auth,
                Some(&grants()),
                &request,
                legacy,
                crate::mcp_policy::Mode::Enforce,
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(v.decision, Action::Deny);
            assert_eq!(rows.kept.len(), expected);
            tx.commit().await.unwrap();
        }
    }
    // Reused event IDs never hand another request the committed verdict.
    request.server = f.contract.server_id;
    let changed = r#"{"amount_minor":6000,"currency":"USD"}"#;
    for (args, action_id) in [
        (changed.as_bytes(), request.action_id),
        (ARGS.as_bytes(), Uuid::new_v4()),
    ] {
        let probe = policy_store::Request {
            principal: None,
            args,
            action_id,
            ..request
        };
        let tx = db.transaction().await.unwrap();
        let Err(err) = policy_store::decide_tx(
            &tx,
            &f.auth,
            Some(&grants()),
            &probe,
            Action::Allow,
            crate::mcp_policy::Mode::Enforce,
        )
        .await
        else {
            panic!("replay bound to a different request returned a verdict");
        };
        assert!(
            format!("{err:#}").contains("evidence_unavailable"),
            "{err:#}"
        );
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_activation_race() {
    let f = std::sync::Arc::new(Fixture::new().await);
    let mut db = f.pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    let mut p: Value = serde_json::from_str(
        &tx.query_one(
            "SELECT body_jcs FROM action_policies WHERE tenant_id=$1",
            &[f.auth.tenant_id.as_uuid()],
        )
        .await
        .unwrap()
        .get::<_, String>(0),
    )
    .unwrap();
    p["version"] = json!(2);
    p["rules"][0]["decision"] = json!("deny");
    let mut human = f.auth.clone();
    human.auth_method = crate::auth::AuthMethod::JwtBearer;
    human.role = Some(crate::auth::Role::Owner);
    human.sub = "synthetic-publisher".into();
    policy_store::activate_tx(
        &tx,
        &human,
        Some(&grants()),
        &canonical(&f.contract).unwrap(),
        &p.to_string(),
    )
    .await
    .unwrap();
    let other = f.clone();
    let task = tokio::spawn(async move {
        execute(
            &other.pool,
            &other.auth,
            Some(&grants()),
            &other.input(Uuid::new_v4()),
            &other.signer,
            None,
            |_| async { panic!("stale allow forwarded") },
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: bool = tx.query_one("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database()))", &[]).await.unwrap().get(0);
            if waiting { break; }
            tokio::task::yield_now().await;
        }
    }).await.expect("execution never contended with activation");
    tx.commit().await.unwrap();
    assert_eq!(
        task.await.unwrap().unwrap_err().to_string(),
        "policy_denied"
    );
    assert_eq!(f.count("tool").await, 0);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_failed_outcome_and_rollback() {
    let f = Fixture::new().await;
    let mut db = f.pool.get().await.unwrap();
    let input = f.input(Uuid::new_v4());
    let tx = db.transaction().await.unwrap();
    let Some(Reservation::Started(mut r, _, _, _)) =
        reserve_tx(&tx, &f.auth, Some(&grants()), &input, &f.signer)
            .await
            .unwrap()
    else {
        panic!("no reservation")
    };
    tx.commit().await.unwrap();
    r.state = State::Failed;
    let tx = db.transaction().await.unwrap();
    finish_tx(&tx, &f.auth, Some(&grants()), &r).await.unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(f.count("ledger").await, 3);
    let tx = db.transaction().await.unwrap();
    finish_tx(&tx, &f.auth, Some(&grants()), &r).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(f.count("ledger").await, 4);
    assert_eq!(f.count("tool").await, 0);
    let n:i64=db.query_one("SELECT count(*) FROM audit_log_rows WHERE tenant_id=$1 AND event_type='execution_failed'",&[f.auth.tenant_id.as_uuid()]).await.unwrap().get(0);
    assert_eq!(n, 1);
    db.execute(
        "UPDATE action_executions SET receipt_jcs=NULL WHERE tenant_id=$1 AND execution_id=$2",
        &[f.auth.tenant_id.as_uuid(), &r.execution_id],
    )
    .await
    .unwrap();
    assert!(
        execute(
            &f.pool,
            &f.auth,
            Some(&grants()),
            &input,
            &f.signer,
            None,
            |_| async { panic!("NULL receipt retried") }
        )
        .await
        .is_err()
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_unprotected_does_not_lock_workspace() {
    let f = Fixture::new().await;
    let mut db = f.pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    tx.query_one(
        "SELECT tenant_id FROM workspace_controls WHERE tenant_id=$1 FOR UPDATE",
        &[f.auth.tenant_id.as_uuid()],
    )
    .await
    .unwrap();
    let mut other = f.pool.get().await.unwrap();
    let read = other.transaction().await.unwrap();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        policy_store::protected_tx(&read, &f.auth, Some(&grants()), Uuid::new_v4(), "ordinary"),
    )
    .await
    .expect("ordinary call serialized behind workspace")
    .unwrap();
    assert!(result.is_none());
    read.rollback().await.unwrap();
    tx.rollback().await.unwrap();
}

// ── ACT-06a: signed evidence for workspace-pause refusals ──
// One focused test per spec case (specs/ACT-06a-paused-refusal-evidence.md `## Test matrix`).
use super::paused_evidence::{PausedEvidence, Undrained, spawn_worker};
use std::sync::Arc;
use std::time::{Duration, Instant};

const ARGS2: &str = r#"{"amount_minor":7000,"currency":"USD"}"#;
const FORWARDED: &str = "a refused call must never reach forward";
/// Serializes every test that asserts the process-global `action_evidence_deferred` counter.
static COUNTER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
impl Fixture {
    async fn pause(&self, on: bool) -> DateTime<Utc> {
        self.pool.get().await.unwrap().query_one(
            "UPDATE workspace_controls SET paused_at=CASE WHEN $2 THEN clock_timestamp() END,paused_by='synthetic' WHERE tenant_id=$1 RETURNING COALESCE(paused_at,now())",
            &[self.auth.tenant_id.as_uuid(), &on],
        ).await.unwrap().get(0)
    }
    async fn denied(&self) -> Vec<(String, String)> {
        self.pool.get().await.unwrap().query(
            "SELECT payload,actor FROM audit_log_rows WHERE tenant_id=$1 AND event_type='denied_runtime' ORDER BY seq",
            &[self.auth.tenant_id.as_uuid()],
        ).await.unwrap().iter().map(|r| (r.get(0), r.get(1))).collect()
    }
    /// Polls (bounded, no fixed sleep) until `n` denied rows exist; returns the final count.
    async fn wait_denied(&self, n: usize) -> usize {
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            let got = self.denied().await.len();
            if got >= n || Instant::now() > end {
                return got;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
    async fn paused_call(
        &self,
        tool: &str,
        args: &str,
        at: DateTime<Utc>,
        on: bool,
    ) -> Option<usize> {
        self.paused_call_at(tool, args, at, on, Utc::now()).await
    }
    async fn paused_call_at(
        &self,
        tool: &str,
        args: &str,
        at: DateTime<Utc>,
        on: bool,
        refused: DateTime<Utc>,
    ) -> Option<usize> {
        let mut db = self.pool.get().await.unwrap();
        let tx = db.transaction().await.unwrap();
        let call = PausedCall {
            server: self.contract.server_id,
            tool,
            args,
        };
        let res = if on {
            paused_refusal_tx(&tx, &self.auth, Some(&grants()), &call, at, refused).await
        } else {
            paused_refusal_tx(&tx, &self.auth, None, &call, at, refused).await
        };
        let out = res.unwrap().map(|o| o.rows.len());
        tx.commit().await.unwrap();
        out
    }
    fn mcp(&self, method: &str, slug: &str, args: Value) -> crate::mcp_proxy::McpRequest {
        crate::mcp_proxy::McpRequest {
            raw_body: None,
            protected: Default::default(),
            slug: slug.into(),
            method: method.into(),
            envelope: json!({"jsonrpc":"2.0","id":1,"method":method,"params":{"name":"pay","arguments":args}}),
            http_method: axum::http::Method::POST,
        }
    }
    fn good(&self) -> Value {
        json!({"amount_minor":5000,"currency":"USD"})
    }
    fn ent(&self) -> crate::entitlement_cache::ResolvedEntitlements {
        let mut e = grants();
        e.mcp = Some(Arc::new(crate::mcp_store::Snapshot {
            kms: None,
            kms_revision: 0,
            servers: vec![crate::mcp_store::Server {
                id: self.contract.server_id,
                slug: "synthetic".into(),
                name: "Synthetic".into(),
                url: "https://example.invalid".into(),
                transport: "streamable_http".into(),
                auth_mode: "none".into(),
                credential_kind: "none".into(),
                credential_header: None,
                credential_ct: None,
                credential_last4: None,
                enabled: true,
            }],
            policy: Default::default(),
            rules: vec![],
            model_rules: vec![],
            approval_settings: crate::mcp_store::ApprovalSettings {
                require_second_approver: false,
                default_ttl_secs: 900,
            },
            approved: Default::default(),
        }));
        e
    }
    /// A queue with its ONE worker running against this fixture's pool.
    fn queue(&self, capacity: usize, per_key: usize) -> PausedEvidence {
        let (q, rx) = PausedEvidence::with_limits(capacity, 1024, 1024, per_key, 1024, 1 << 25);
        let chain = Arc::new(
            crate::audit::AuditChain::with_pg_pool(0, None, None, Some(self.pool.clone())).unwrap(),
        );
        spawn_worker(q.clone(), rx, self.pool.clone(), chain);
        q
    }
    /// The request-path half only (what the admission hook runs): no database.
    fn offer(&self, q: &PausedEvidence, method: &str, slug: &str, args: Value, at: DateTime<Utc>) {
        crate::mcp_proxy::protected::offer_paused(
            q,
            &self.auth,
            Some(&Arc::new(self.ent())),
            &self.mcp(method, slug, args),
            at,
        );
    }
    /// A protected call reserved while the workspace is paused (the race path).
    async fn race(&self) -> anyhow::Error {
        execute(
            &self.pool,
            &self.auth,
            Some(&grants()),
            &self.input(Uuid::new_v4()),
            &self.signer,
            None,
            |_| async { panic!("{FORWARDED}") },
        )
        .await
        .err()
        .unwrap()
    }
    /// request_digest of a real, unpaused attempt of the same call.
    async fn unpaused_digest(&self) -> String {
        assert_eq!(self.run(Uuid::new_v4()).await.state, State::Succeeded);
        self.pool
            .get()
            .await
            .unwrap()
            .query_one(
                "SELECT request_digest FROM action_executions WHERE tenant_id=$1",
                &[self.auth.tenant_id.as_uuid()],
            )
            .await
            .unwrap()
            .get(0)
    }
    /// One real `POST /v1/mcp/synthetic` through `admission::admit::<McpRoute<true>>` for a
    /// workspace paused at `at`, with `state.pg` set and `queue` as the evidence queue.
    async fn admit_paused(
        &self,
        queue: Option<PausedEvidence>,
        at: DateTime<Utc>,
        args: Value,
    ) -> (axum::http::StatusCode, axum::body::Bytes) {
        use tower::ServiceExt;
        let mut ent = self.ent();
        Arc::make_mut(&mut ent.controls).paused = Some(crate::controls::Pause {
            at,
            by: None,
            reason: None,
        });
        let mut state =
            crate::handler_harness::test_state(crate::providers::ProviderRegistry::new().unwrap());
        state.pg = Some(self.pool.clone());
        state.paused_evidence = queue;
        state.entitlements = Some(Arc::new(crate::entitlement_cache::EntitlementCache::new(
            Arc::new(move |_| {
                let ent = ent.clone();
                Box::pin(async move { Ok(ent) })
            }),
        )));
        let mut claims = self.auth.clone();
        claims.key_scope =
            crate::auth::scope::KeyScope::Scoped([crate::auth::scope::Scope::Mcp].into());
        let _auth = crate::auth::test_claims::Guard::set(claims);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/mcp/synthetic")
            .header("authorization", "Bearer fixture")
            .body(axum::body::Body::from(
                self.mcp("tools/call", "synthetic", args)
                    .envelope
                    .to_string(),
            ))
            .unwrap();
        let response = crate::mcp_proxy::router(state)
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status();
        (
            status,
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
    }
}
fn deferred() -> u64 {
    tracelane_shared::degradation::snapshot()
        .iter()
        .find(|s| s.kind == "action_evidence_deferred")
        .map_or(0, |s| s.count)
}
/// Polls (bounded) until the deferred counter moves past `before`.
async fn wait_deferred(before: u64) -> bool {
    let end = Instant::now() + Duration::from_secs(10);
    while deferred() <= before {
        if Instant::now() > end {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    true
}
/// A queue with NO worker: counts jobs offered and lets the tests inspect admission control.
fn bare(
    capacity: usize,
    per_key: usize,
) -> (
    PausedEvidence,
    tokio::sync::mpsc::Receiver<super::paused_evidence::Job>,
) {
    PausedEvidence::with_limits(capacity, 1024, 1024, per_key, 1024, 1 << 25)
}
fn key_claims(tenant: Uuid) -> crate::auth::Claims {
    let t = TenantId::from_jwt_claim(tenant);
    let mut c = super::tests::claims(&t);
    c.sub = format!("apikey:{}", Uuid::new_v4());
    c
}
fn offer_args(
    q: &PausedEvidence,
    c: &crate::auth::Claims,
    server: Uuid,
    args: &str,
    at: DateTime<Utc>,
) {
    q.offer(
        c,
        &Arc::new(grants()),
        &PausedCall {
            server,
            tool: "pay",
            args,
        },
        at,
    );
}

// ── Positive ──
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_paused_protected_call_writes_one_denied_runtime_row() {
    let f = Fixture::new().await;
    let at = f.pause(true).await;
    assert!(f.paused_call("pay", ARGS, at, true).await.is_some());
    let rows = f.denied().await;
    assert_eq!(rows.len(), 1);
    assert!(rows[0].0.contains("workspace_paused"), "{}", rows[0].0);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_paused_row_digest_equals_unpaused_attempt_digest() {
    let f = Fixture::new().await;
    let unpaused = f.unpaused_digest().await;
    let at = f.pause(true).await;
    f.paused_call("pay", ARGS, at, true).await.unwrap();
    let rows = f.denied().await;
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0].0.contains(&unpaused),
        "digest differs: {}",
        rows[0].0
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_paused_row_actor_is_the_callers_api_key() {
    let f = Fixture::new().await;
    let at = f.pause(true).await;
    f.paused_call("pay", ARGS, at, true).await.unwrap();
    let rows = f.denied().await;
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0].1.contains(f.auth.api_key_id().unwrap()),
        "{}",
        rows[0].1
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_paused_same_call_50_times_writes_exactly_one_row() {
    let f = Fixture::new().await;
    let at = f.pause(true).await;
    assert!(f.paused_call("pay", ARGS, at, true).await.is_some());
    for _ in 0..49 {
        assert!(
            f.paused_call("pay", ARGS, at, true).await.is_none(),
            "dedup is not a new row"
        );
    }
    assert_eq!(f.denied().await.len(), 1);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_paused_new_pause_epoch_writes_a_second_row() {
    let f = Fixture::new().await;
    let at = f.pause(true).await;
    f.paused_call("pay", ARGS, at, true).await.unwrap();
    assert_eq!(f.denied().await.len(), 1);
    f.pause(false).await;
    let at2 = f.pause(true).await;
    assert_ne!(at, at2);
    f.paused_call("pay", ARGS, at2, true).await.unwrap();
    assert_eq!(f.denied().await.len(), 2);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_paused_race_after_admission_refuses_and_writes_row_without_reservation() {
    let f = Fixture::new().await;
    f.pause(true).await;
    let err = f.race().await;
    assert_eq!(err.to_string(), "workspace_paused");
    assert_eq!(f.denied().await.len(), 1);
    assert_eq!((f.count("execution").await, f.count("tool").await), (0, 0));
    // The same call retried is deduped.
    assert_eq!(f.race().await.to_string(), "workspace_paused");
    assert_eq!(f.denied().await.len(), 1);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_paused_race_revoked_key_refuses_key_revoked_without_row() {
    let f = Fixture::new().await;
    f.pool
        .get()
        .await
        .unwrap()
        .execute(
            "UPDATE api_keys SET revoked_at=now()-interval '1 second' WHERE tenant_id=$1",
            &[f.auth.tenant_id.as_uuid()],
        )
        .await
        .unwrap();
    // Even while paused: a revoked key is refused as such and leaves no evidence.
    f.pause(true).await;
    assert_eq!(f.race().await.to_string(), "key_revoked");
    assert!(f.denied().await.is_empty());
    assert_eq!((f.count("execution").await, f.count("tool").await), (0, 0));
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_paused_different_arguments_write_two_rows() {
    let f = Fixture::new().await;
    let at = f.pause(true).await;
    f.paused_call("pay", ARGS, at, true).await.unwrap();
    f.paused_call("pay", ARGS2, at, true).await.unwrap();
    assert_eq!(f.denied().await.len(), 2);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_paused_exported_bundle_passes_verifier() {
    use crate::audit_export::AuditExportReader;
    use base64::Engine;
    let f = Fixture::new().await;
    let at = f.pause(true).await;
    f.paused_call("pay", ARGS, at, true).await.unwrap();
    let master = crate::byok::ByokMasterKey::from_values(
        Some(&base64::engine::general_purpose::STANDARD.encode([7; 32])),
        None,
        None,
    )
    .unwrap()
    .unwrap();
    let keys = Arc::new(crate::audit_keys::TenantAuditKeyStore::new(
        f.pool.clone(),
        Arc::new(master),
        None,
    ));
    let pin: [u8; 32] = keys
        .get_or_create(&f.auth.tenant_id)
        .await
        .unwrap()
        .public_key_bytes()
        .try_into()
        .unwrap();
    let reader =
        crate::audit_export::PgExportReader::new(f.pool.clone()).with_action_keys(Some(keys));
    let zip = crate::audit_export::action::BUILD_NOW
        .scope(
            Utc::now() + chrono::Duration::seconds(120),
            reader.action_bundle(&f.auth.tenant_id, &grants()),
        )
        .await
        .unwrap();
    // Library call (no CLI binary): the offline verifier accepts the chain holding the row.
    tracelane_audit_verifier::action::bundle::verify(&zip, Some(pin)).unwrap();
    assert!(
        String::from_utf8_lossy(
            &tracelane_audit_verifier::action::archive::unpack(&zip).unwrap()["ledger.ndjson"]
        )
        .contains("denied_runtime")
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_paused_refusals_cause_no_side_effect() {
    let f = Fixture::new().await;
    let at = f.pause(true).await;
    f.paused_call("pay", ARGS, at, true).await.unwrap();
    let q = f.queue(8, 8);
    // Different arguments from the direct call above, so the worker adds a second row.
    f.offer(
        &q,
        "tools/call",
        "synthetic",
        json!({"amount_minor":7000,"currency":"USD"}),
        at,
    );
    assert_eq!(f.wait_denied(2).await, 2);
    f.race().await;
    assert_eq!(f.denied().await.len(), 2);
    assert_eq!((f.count("tool").await, f.count("execution").await), (0, 0));
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_paused_evidence_rows_are_committed_and_pass_after_outer_commit() {
    let f = Fixture::new().await;
    let at = f.pause(true).await;
    let chain =
        crate::audit::AuditChain::with_pg_pool(0, None, None, Some(f.pool.clone())).unwrap();
    let mut db = f.pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    let call = PausedCall {
        server: f.contract.server_id,
        tool: "pay",
        args: ARGS,
    };
    let rows = paused_refusal_tx(&tx, &f.auth, Some(&grants()), &call, at, Utc::now())
        .await
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();
    // after_outer_commit refuses anything not committed (see pg_hook_refuses_before_commit_and_after_rollback),
    // so Ok here proves the worker's rows are canonical and reach the derived-copy step.
    chain
        .after_outer_commit(&f.auth.tenant_id, rows)
        .await
        .unwrap();
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_paused_admission_hook_records_row_and_keeps_423() {
    let _c = COUNTER.lock().await;
    let f = Fixture::new().await;
    let at = f.pause(true).await;
    // Baseline: the same request with no evidence queue is the unchanged 423.
    let (base_status, base_body) = f.admit_paused(None, at, f.good()).await;
    assert_eq!(base_status, axum::http::StatusCode::LOCKED);
    assert!(f.denied().await.is_empty());
    let q = f.queue(8, 8);
    let before = deferred();
    let (status, body) = f.admit_paused(Some(q), at, f.good()).await;
    assert_eq!(status, axum::http::StatusCode::LOCKED);
    assert_eq!(body, base_body, "evidence must not change the 423 body");
    assert!(String::from_utf8_lossy(&body).contains("workspace_paused"));
    assert_eq!(
        f.wait_denied(1).await,
        1,
        "admission never offered the call"
    );
    let rows = f.denied().await;
    assert!(rows[0].0.contains("workspace_paused"));
    assert!(rows[0].1.contains(f.auth.api_key_id().unwrap()));
    assert_eq!(deferred(), before);
}
#[test]
fn paused_identical_calls_cost_one_job() {
    let (q, _rx) = bare(8, 8);
    let c = key_claims(Uuid::new_v4());
    let (server, at) = (Uuid::new_v4(), Utc::now());
    for _ in 0..50 {
        offer_args(&q, &c, server, ARGS, at);
    }
    assert_eq!(q.enqueued.load(std::sync::atomic::Ordering::Relaxed), 1);
    offer_args(&q, &c, server, ARGS2, at);
    assert_eq!(q.enqueued.load(std::sync::atomic::Ordering::Relaxed), 2);
}

// ── Negative ──
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_paused_unprotected_tool_writes_no_row() {
    let f = Fixture::new().await;
    let at = f.pause(true).await;
    // A REAL registered contract for a real tool, with `protected:false` (activation succeeds).
    let mut owner = f.auth.clone();
    owner.auth_method = crate::auth::AuthMethod::JwtBearer;
    owner.role = Some(crate::auth::Role::Owner);
    owner.sub = "synthetic-publisher".into();
    let contract = json!({"tool_ref":Uuid::new_v4(),"server_id":f.contract.server_id,"tool_name":"free","version":1,"protected":false,"fields":{}}).to_string();
    let policy = json!({"policy_id":Uuid::new_v4(),"version":1,"agents":null,"rules":[{"id":"allow","when":[],"decision":"allow"}]}).to_string();
    let mut db = f.pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    policy_store::activate_tx(&tx, &owner, Some(&grants()), &contract, &policy)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    drop(db);
    assert!(f.paused_call("free", ARGS, at, true).await.is_none());
    assert!(f.denied().await.is_empty());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_paused_flag_off_writes_no_row() {
    let f = Fixture::new().await;
    let at = f.pause(true).await;
    assert!(f.paused_call("pay", ARGS, at, false).await.is_none());
    let mut db = f.pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    let off = crate::entitlement_cache::ResolvedEntitlements::deny_all();
    let call = PausedCall {
        server: f.contract.server_id,
        tool: "pay",
        args: ARGS,
    };
    assert!(
        paused_refusal_tx(&tx, &f.auth, Some(&off), &call, at, Utc::now())
            .await
            .unwrap()
            .is_none()
    );
    tx.commit().await.unwrap();
    drop(db);
    assert!(f.denied().await.is_empty());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_paused_not_paused_attempt_writes_no_denied_row() {
    let f = Fixture::new().await;
    assert_eq!(f.run(Uuid::new_v4()).await.state, State::Succeeded);
    assert!(f.denied().await.is_empty());
}
#[test]
fn paused_per_key_budget_exhausted_for_key_a_while_key_b_still_records() {
    let _c = COUNTER.blocking_lock();
    let (q, _rx) = bare(64, 2);
    let tenant = Uuid::new_v4();
    let (a, b) = (key_claims(tenant), key_claims(tenant));
    let (server, at) = (Uuid::new_v4(), Utc::now());
    let before = deferred();
    // Key A: distinct calls; the third exceeds its budget of 2.
    for n in 0..3 {
        offer_args(
            &q,
            &a,
            server,
            &format!(r#"{{"amount_minor":{n},"currency":"USD"}}"#),
            at,
        );
    }
    assert_eq!(q.enqueued.load(std::sync::atomic::Ordering::Relaxed), 2);
    assert_eq!(deferred(), before + 1, "the over-budget call is counted");
    // A's exhausted budget is free to repeat, and never suppresses key B.
    offer_args(&q, &a, server, r#"{"amount_minor":2,"currency":"USD"}"#, at);
    assert_eq!(deferred(), before + 1);
    offer_args(&q, &b, server, ARGS, at);
    assert_eq!(q.enqueued.load(std::sync::atomic::Ordering::Relaxed), 3);
    // A new pause epoch gets a fresh budget.
    offer_args(&q, &a, server, ARGS, at + chrono::Duration::seconds(1));
    assert_eq!(q.enqueued.load(std::sync::atomic::Ordering::Relaxed), 4);
}
#[test]
fn paused_full_queue_counts_and_never_blocks() {
    let _c = COUNTER.blocking_lock();
    let (q, _rx) = bare(1, 100);
    let c = key_claims(Uuid::new_v4());
    let (server, at) = (Uuid::new_v4(), Utc::now());
    let before = deferred();
    offer_args(&q, &c, server, ARGS, at);
    assert_eq!(deferred(), before);
    offer_args(&q, &c, server, ARGS2, at); // queue (capacity 1) is full
    assert_eq!(deferred(), before + 1);
    assert_eq!(q.enqueued.load(std::sync::atomic::Ordering::Relaxed), 1);
}
#[test]
fn paused_one_tenant_flood_leaves_room_for_another() {
    let _c = COUNTER.blocking_lock();
    let (q, _rx) = PausedEvidence::with_limits(64, 1024, 1024, 100, 2, 1 << 25);
    let (a, b) = (key_claims(Uuid::new_v4()), key_claims(Uuid::new_v4()));
    let (server, at) = (Uuid::new_v4(), Utc::now());
    let before = deferred();
    for i in 0..5 {
        offer_args(&q, &a, server, &format!(r#"{{"n":{i}}}"#), at);
    }
    assert_eq!(q.enqueued.load(std::sync::atomic::Ordering::Relaxed), 2);
    assert_eq!(deferred(), before + 3);
    offer_args(&q, &b, server, ARGS, at); // the queue (64) still has room for another tenant
    assert_eq!(q.enqueued.load(std::sync::atomic::Ordering::Relaxed), 3);
    assert_eq!(deferred(), before + 3);
}
#[test]
fn paused_full_queue_refunds_budget_and_dedup() {
    let _c = COUNTER.blocking_lock();
    let (q, mut rx) = bare(1, 2); // budget of 2 per key
    let c = key_claims(Uuid::new_v4());
    let (server, at) = (Uuid::new_v4(), Utc::now());
    for i in 0..3 {
        offer_args(&q, &c, server, &format!(r#"{{"n":{i}}}"#), at); // 1 queued; 2 skipped by the full queue
    }
    assert!(rx.try_recv().is_ok()); // room again
    offer_args(&q, &c, server, r#"{"n":1}"#, at); // a skipped call may retry: no budget or dedup lost
    assert_eq!(q.enqueued.load(std::sync::atomic::Ordering::Relaxed), 2);
}
#[test]
fn paused_queue_bytes_cap_counts_and_skips() {
    let _c = COUNTER.blocking_lock();
    let (q, _rx) = PausedEvidence::with_limits(64, 1024, 1024, 100, 100, 2200);
    let c = key_claims(Uuid::new_v4());
    let (server, at) = (Uuid::new_v4(), Utc::now());
    let before = deferred();
    for i in 0..3 {
        offer_args(&q, &c, server, &format!(r#"{{"n":{i}}}"#), at); // ~1.06 KiB each: two fit
    }
    assert_eq!(q.enqueued.load(std::sync::atomic::Ordering::Relaxed), 2);
    assert_eq!(deferred(), before + 1);
}
#[test]
fn paused_jwt_caller_is_skipped_without_counting() {
    let _c = COUNTER.blocking_lock();
    let (q, _rx) = bare(8, 8);
    let mut c = key_claims(Uuid::new_v4());
    c.sub = "user_jwt".into();
    let before = deferred();
    offer_args(&q, &c, Uuid::new_v4(), ARGS, Utc::now());
    assert_eq!(q.enqueued.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(deferred(), before);
}
#[test]
fn paused_undrained_jobs_are_counted_when_the_worker_stops() {
    let _c = COUNTER.blocking_lock();
    let (q, rx) = bare(8, 8);
    let c = key_claims(Uuid::new_v4());
    for i in 0..3 {
        offer_args(
            &q,
            &c,
            Uuid::new_v4(),
            &format!(r#"{{"n":{i}}}"#),
            Utc::now(),
        );
    }
    let before = deferred();
    drop(Undrained(rx));
    assert_eq!(deferred(), before + 3);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_paused_worker_job_times_out_under_lock() {
    let _c = COUNTER.lock().await;
    let f = Fixture::new().await;
    let at = f.pause(true).await;
    let q = f.queue(8, 8);
    // Every pooled connection is held: the job's pool wait would never end without the whole-job deadline.
    let mut held = Vec::new();
    for _ in 0..f.pool.status().max_size {
        held.push(f.pool.get().await.unwrap());
    }
    let (before, started) = (deferred(), Instant::now());
    f.offer(&q, "tools/call", "synthetic", f.good(), at);
    assert!(wait_deferred(before).await, "stuck job never counted");
    assert!(
        started.elapsed() < Duration::from_secs(6),
        "deadline is 2x the 2 s statement bound"
    );
    drop(held);
    f.offer(
        &q,
        "tools/call",
        "synthetic",
        json!({"amount_minor":9,"currency":"USD"}),
        at,
    );
    assert_eq!(
        f.wait_denied(1).await,
        1,
        "worker must recover after a timeout"
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_paused_admission_full_queue_still_423_and_counts() {
    let _c = COUNTER.lock().await;
    let f = Fixture::new().await;
    let at = f.pause(true).await;
    let (q, _rx) = bare(1, 100); // no worker: the first job fills the queue
    let before = deferred();
    let (s1, _) = f.admit_paused(Some(q.clone()), at, f.good()).await;
    let (s2, body) = f
        .admit_paused(Some(q), at, json!({"amount_minor":9,"currency":"USD"}))
        .await;
    assert_eq!(
        (s1, s2),
        (
            axum::http::StatusCode::LOCKED,
            axum::http::StatusCode::LOCKED
        )
    );
    assert!(String::from_utf8_lossy(&body).contains("workspace_paused"));
    assert_eq!(deferred(), before + 1);
    assert!(f.denied().await.is_empty());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_paused_closed_pool_still_423_counts_and_does_not_panic() {
    let _c = COUNTER.lock().await;
    let f = Fixture::new().await;
    let at = f.pause(true).await;
    let q = f.queue(8, 8); // the worker holds a clone of the pool...
    f.pool.close(); // ...which is now closed: every job's write fails
    let before = deferred();
    let (status, body) = f.admit_paused(Some(q.clone()), at, f.good()).await;
    assert_eq!(status, axum::http::StatusCode::LOCKED);
    assert!(String::from_utf8_lossy(&body).contains("workspace_paused"));
    assert!(
        wait_deferred(before).await,
        "closed pool must move the counter"
    );
    // The worker survives its failure and keeps counting the next one.
    let mid = deferred();
    let (status, _) = f
        .admit_paused(Some(q), at, json!({"amount_minor":9,"currency":"USD"}))
        .await;
    assert_eq!(status, axum::http::StatusCode::LOCKED);
    assert!(
        wait_deferred(mid).await,
        "worker must survive and keep counting"
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_paused_revoked_key_writes_no_row() {
    let f = Fixture::new().await;
    let at = f.pause(true).await;
    f.pool
        .get()
        .await
        .unwrap()
        .execute(
            "UPDATE api_keys SET revoked_at=now()-interval '1 second' WHERE tenant_id=$1",
            &[f.auth.tenant_id.as_uuid()],
        )
        .await
        .unwrap();
    assert!(f.paused_call("pay", ARGS, at, true).await.is_none());
    assert!(f.denied().await.is_empty());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_paused_key_revoked_after_refusal_still_records() {
    let f = Fixture::new().await;
    let at = f.pause(true).await;
    let refused = Utc::now();
    tokio::time::sleep(Duration::from_millis(50)).await;
    f.pool
        .get()
        .await
        .unwrap()
        .execute(
            "UPDATE api_keys SET revoked_at=clock_timestamp() WHERE tenant_id=$1",
            &[f.auth.tenant_id.as_uuid()],
        )
        .await
        .unwrap();
    assert!(
        f.paused_call_at("pay", ARGS, at, true, refused)
            .await
            .is_some()
    );
    let rows = f.denied().await;
    assert_eq!(rows.len(), 1);
    assert!(rows[0].0.contains("workspace_paused"));
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_paused_malformed_arguments_write_no_row_and_count() {
    let _c = COUNTER.lock().await;
    let f = Fixture::new().await;
    let at = f.pause(true).await;
    let (q, _rx) = bare(8, 8);
    let before = deferred();
    // Request path: params the protected-call shape refuses are never queued, and are counted.
    let mut bad = f.mcp("tools/call", "synthetic", f.good());
    bad.envelope["params"]["extra"] = json!(1);
    crate::mcp_proxy::protected::offer_paused(&q, &f.auth, Some(&Arc::new(f.ent())), &bad, at);
    assert_eq!(q.enqueued.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(deferred(), before + 1);
    // Worker path: arguments the contract cannot digest are refused there, counted, no row.
    assert_eq!(
        f.paused_call("pay", r#"{"amount_minor":"x"}"#, at, true)
            .await,
        None
    );
    assert!(deferred() > before + 1);
    assert!(f.denied().await.is_empty());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_paused_cross_tenant_pause_writes_only_that_tenants_row() {
    let f = Fixture::new().await;
    let g = f.other().await; // tenant B stays unpaused
    let at = f.pause(true).await;
    f.paused_call("pay", ARGS, at, true).await.unwrap();
    assert_eq!(f.denied().await.len(), 1);
    assert!(g.denied().await.is_empty());
    assert_eq!(g.run(Uuid::new_v4()).await.state, State::Succeeded);
    assert!(g.denied().await.is_empty());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_paused_non_tool_call_methods_write_no_row() {
    let f = Fixture::new().await;
    let at = f.pause(true).await;
    let (q, _rx) = bare(8, 8);
    for m in ["resources/read", "tools/list", "prompts/get"] {
        f.offer(&q, m, "synthetic", f.good(), at);
    }
    assert_eq!(q.enqueued.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert!(f.denied().await.is_empty());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_paused_unknown_server_slug_writes_no_row() {
    let f = Fixture::new().await;
    let at = f.pause(true).await;
    let (q, _rx) = bare(8, 8);
    f.offer(&q, "tools/call", "missing", f.good(), at);
    assert_eq!(q.enqueued.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert!(f.denied().await.is_empty());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_paused_race_commit_failure_refuses_without_forward() {
    let f = Fixture::new().await;
    f.pause(true).await;
    let db = f.pool.get().await.unwrap();
    // The evidence insert succeeds; only COMMIT fails.
    db.batch_execute("CREATE FUNCTION reject_denied_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected_denied_commit_failure'; END $$;
        CREATE CONSTRAINT TRIGGER reject_denied_commit AFTER INSERT ON audit_log_rows DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.event_type = 'denied_runtime') EXECUTE FUNCTION reject_denied_commit()")
        .await.unwrap();
    let err = f.race().await;
    assert_eq!(
        err.downcast_ref::<tokio_postgres::Error>()
            .unwrap()
            .as_db_error()
            .unwrap()
            .message(),
        "injected_denied_commit_failure"
    ); // fail-closed: refusal() renders any unrecognised error as 503 protected_execution_unavailable
    assert!(f.denied().await.is_empty(), "failed commit left a row");
    assert_eq!((f.count("execution").await, f.count("tool").await), (0, 0));
    // No residue: once the fault is gone the same call is refused and recorded normally.
    db.batch_execute("DROP TRIGGER reject_denied_commit ON audit_log_rows")
        .await
        .unwrap();
    assert_eq!(f.race().await.to_string(), "workspace_paused");
    assert_eq!(f.denied().await.len(), 1);
}

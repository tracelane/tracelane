use super::*;
use serde_json::json;

fn tenant() -> TenantId {
    TenantId::from_jwt_claim(Uuid::new_v4())
}
pub(super) fn event() -> ActionEvent {
    ActionEvent {
        event_id: Uuid::new_v4(),
        action_id: Uuid::new_v4(),
        occurred_at: Utc::now(),
        request_digest: "a".repeat(64),
        body: ActionPayload::DeniedRuntime {
            reason: ReasonCode::WorkspacePaused,
        },
    }
}
#[test]
fn jcs_key_order() {
    assert_eq!(
        canonical_json(r#"{"z":2,"a":1}"#).unwrap(),
        canonical_json(r#"{"a":1,"z":2}"#).unwrap()
    );
}
#[test]
fn jcs_utf16() {
    assert_eq!(
        canonical_json("{\"\u{e000}\":1,\"😀\":2}").unwrap(),
        "{\"😀\":2,\"\u{e000}\":1}"
    );
}
#[test]
fn jcs_numbers() {
    assert_eq!(
        canonical_json("[0,-0,9007199254740991,-9007199254740991]").unwrap(),
        "[0,0,9007199254740991,-9007199254740991]"
    );
}
#[test]
fn duplicate_keys() {
    assert!(canonical_json(r#"{"a":1,"a":2}"#).is_err());
}
#[test]
fn nested_duplicate_keys() {
    assert!(canonical_json(r#"{"x":[{"a":1,"\u0061":2}]}"#).is_err());
}
#[test]
fn invalid_unicode() {
    assert!(canonical_json(r#"{"x":"\ud800"}"#).is_err());
}
#[test]
fn unsafe_integer() {
    assert!(canonical_json("9007199254740993").is_err());
}
#[derive(Clone)]
struct CapturedLogs(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for CapturedLogs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[test]
fn minimized_token() {
    let logs = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = CapturedLogs(logs.clone());
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    tracing::info!("synthetic action-evidence log capture active");
    let secret = SecretString::from("synthetic-tenant-secret-do-not-use".to_owned());
    let token = minimize(&secret, EvidenceMode::Tokenize, "BEN-TEST-001").unwrap();
    let encoded = serde_json::to_string(&token).unwrap();
    assert!(!encoded.contains("BEN-TEST-001"));
    assert!(encoded.contains("last4"));
    let captured = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
    assert!(captured.contains("synthetic action-evidence log capture active"));
    assert!(!captured.contains("BEN-TEST-001"));
    assert!(!captured.contains("synthetic-tenant-secret-do-not-use"));
    assert_eq!(
        token,
        minimize(&secret, EvidenceMode::Tokenize, "BEN-TEST-001").unwrap()
    );
}
#[test]
fn digest_only() {
    let field = minimize(
        &SecretString::from("synthetic".to_owned()),
        EvidenceMode::DigestOnly,
        "synthetic memo",
    )
    .unwrap();
    assert!(
        !serde_json::to_string(&field)
            .unwrap()
            .contains("synthetic memo")
    );
}
#[test]
fn evidence_map_digest_names_are_not_protocol_fields() {
    let fields = ["memo_digest", "policy_hash", "hmac", "sha256"]
        .into_iter()
        .map(|name| {
            (
                name.to_owned(),
                EvidenceField::DigestOnly {
                    sha256: "a".repeat(64),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut e = event();
    e.body = ActionPayload::ActionProposed {
        tool_ref: Uuid::new_v4(),
        contract_version: 1,
        args_digest: "b".repeat(64),
        evidence_fields: fields.clone(),
        agent_claimed_labels: fields,
        principal: None,
    };
    let encoded = e
        .canonical(&tenant(), None)
        .expect("valid evidence names must be accepted");
    let value: Value = serde_json::from_str(&encoded).unwrap();
    assert_eq!(
        value["body"]["evidence_fields"]["memo_digest"]["sha256"],
        "a".repeat(64)
    );
    assert_eq!(
        value["body"]["agent_claimed_labels"]["hmac"]["sha256"],
        "a".repeat(64)
    );
}

#[test]
fn evidence_map_names_and_digest_values_are_validated_separately() {
    for labels in [false, true] {
        for (name, field) in [
            (
                "",
                EvidenceField::Clear {
                    value: ClearValue::Boolean(true),
                },
            ),
            (
                "raw name",
                EvidenceField::DigestOnly {
                    sha256: "a".repeat(64),
                },
            ),
            (
                "memo_digest",
                EvidenceField::DigestOnly {
                    sha256: "invalid".into(),
                },
            ),
            (
                "policy_hash",
                EvidenceField::Tokenize {
                    hmac: "invalid".into(),
                    last4: "1234".into(),
                },
            ),
        ] {
            let fields = [(name.to_owned(), field)].into();
            let mut e = event();
            let (evidence_fields, agent_claimed_labels) = if labels {
                (BTreeMap::new(), fields)
            } else {
                (fields, BTreeMap::new())
            };
            e.body = ActionPayload::ActionProposed {
                tool_ref: Uuid::new_v4(),
                contract_version: 1,
                args_digest: "b".repeat(64),
                evidence_fields,
                agent_claimed_labels,
                principal: None,
            };
            assert!(
                e.canonical(&tenant(), None).is_err(),
                "invalid evidence accepted: {name}"
            );
        }
    }
}
#[test]
fn token_tenant_isolation() {
    assert_ne!(
        minimize(
            &SecretString::from("tenant-a".to_owned()),
            EvidenceMode::Tokenize,
            "BEN-TEST-001"
        )
        .unwrap(),
        minimize(
            &SecretString::from("tenant-b".to_owned()),
            EvidenceMode::Tokenize,
            "BEN-TEST-001"
        )
        .unwrap()
    );
}
#[test]
fn typed_events() {
    let variants = [
        json!({"event_type":"action_proposed","tool_ref":Uuid::new_v4(),"contract_version":1,"args_digest":"a".repeat(64),"evidence_fields":{},"agent_claimed_labels":{}}),
        json!({"event_type":"decision_made","decision":"deny","rule_id":"rule","reason_codes":["limit"],"policy_id":Uuid::new_v4(),"policy_version":1,"policy_hash":"b".repeat(64)}),
        json!({"event_type":"approval_requested","approval_id":Uuid::new_v4(),"required_role":"admin","expires_at":"2026-10-22T00:00:00Z"}),
        json!({"event_type":"approval_granted","approval_id":Uuid::new_v4(),"decider_digest":"a".repeat(64),"note_digest":"b".repeat(64)}),
        json!({"event_type":"approval_denied","approval_id":Uuid::new_v4(),"decider_digest":"a".repeat(64),"note_digest":"b".repeat(64)}),
        json!({"event_type":"approval_attempt_rejected","approval_id":Uuid::new_v4(),"decider_digest":"a".repeat(64),"reason":"unauthorized"}),
        json!({"event_type":"approval_consumed","approval_id":Uuid::new_v4()}),
        json!({"event_type":"execution_started","execution_id":Uuid::new_v4(),"idempotency_key":Uuid::new_v4(),"attestation_key_id":"tool-v1"}),
        json!({"event_type":"execution_succeeded","execution_id":Uuid::new_v4(),"receipt_digest":"a".repeat(64)}),
        json!({"event_type":"execution_failed","execution_id":Uuid::new_v4(),"receipt_digest":"a".repeat(64)}),
        json!({"event_type":"execution_unknown","execution_id":Uuid::new_v4(),"receipt_digest":null}),
        json!({"event_type":"denied_runtime","reason":"workspace_paused"}),
        json!({"event_type":"policy_activated","policy_id":Uuid::new_v4(),"version":1,"policy_hash":"a".repeat(64),"publisher_digest":"b".repeat(64),"tool_ref":Uuid::new_v4(),"contract_version":1,"contract_hash":"c".repeat(64),"protected":true}),
    ];
    for value in variants {
        let p: ActionPayload = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(p).unwrap(), value);
    }
}
#[test]
fn unknown_event() {
    assert!(serde_json::from_value::<ActionPayload>(json!({"event_type":"invented"})).is_err());
}
#[test]
fn unknown_fields() {
    assert!(
        serde_json::from_value::<ActionPayload>(
            json!({"event_type":"denied_runtime","reason":"workspace_paused","raw_args":"secret"})
        )
        .is_err()
    );
}
#[test]
fn occurrence_bound() {
    let t = tenant();
    let mut e = event();
    let before = e.canonical(&t, None).unwrap();
    e.occurred_at += chrono::Duration::seconds(1);
    assert_ne!(before, e.canonical(&t, None).unwrap());
}
#[test]
fn flag_off() {
    assert!(!enabled(None));
    assert!(!enabled(Some(
        &crate::entitlement_cache::ResolvedEntitlements::deny_all()
    )));
}
#[test]
fn flag_enabled() {
    let mut r = crate::entitlement_cache::ResolvedEntitlements::deny_all();
    r.action_control = true;
    assert!(enabled(Some(&r)));
}
#[test]
fn checkpoint_verifies() {
    let t = tenant();
    let key = crate::audit_keys::TenantAuditKeypair::generate(t.clone()).unwrap();
    let cp = sign_checkpoint(&key, &t, Some((7, [8; 32])), None).unwrap();
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key.public_key_bytes())
        .verify(cp.statement.as_bytes(), &cp.signature)
        .unwrap();
    assert!(cp.statement.contains("tracelane.action-head.v1"));
    assert!(cp.statement.contains("\"seq\":\"7\""));
}
#[test]
fn checkpoint_tamper() {
    let t = tenant();
    let key = crate::audit_keys::TenantAuditKeypair::generate(t.clone()).unwrap();
    let cp = sign_checkpoint(&key, &t, None, None).unwrap();
    assert!(
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key.public_key_bytes())
            .verify(
                cp.statement.replace("null", "\"1\"").as_bytes(),
                &cp.signature
            )
            .is_err()
    );
}
#[test]
fn mixed_verifier() {
    let t = tenant();
    let genesis = crate::audit_format::genesis_prev_hash(&t);
    let legacy = crate::audit_format::canonical_payload(&json!({"model":"synthetic"}));
    let first =
        crate::audit_format::row_hash_v2(&genesis, &t, 0, "request.admitted", "synthetic", &legacy);
    let e = event();
    let payload = e.canonical(&t, None).unwrap();
    let second =
        crate::audit_format::row_hash_v2(&first, &t, 1, e.event_type(), "synthetic", &payload);
    let rows = [
        (0, "request.admitted", legacy, genesis, first),
        (1, e.event_type(), payload, first, second),
    ];
    let ndjson: String = rows.into_iter().map(|(seq, kind, payload, prev, hash)| json!({"format":"v2.1","tenant_id":t.to_string(),"seq":seq,"event_type":kind,"actor":"synthetic","payload":payload,"prev_hash":hex::encode(prev),"row_hash":hex::encode(hash),"event_time":"2026-10-22T00:00:00Z"}).to_string()+"\n").collect();
    let report = tracelane_audit_verifier::verify_ledger_reader(
        std::io::Cursor::new(ndjson),
        "mixed-action-v1",
        &Default::default(),
    )
    .unwrap();
    assert_eq!(report.errors.len(), 0, "{report:?}");
}

pub(super) async fn fixture() -> (deadpool_postgres::Pool, TenantId) {
    let pool = crate::entitlement_cache::b409_fixture::fresh_migrated_pool().await;
    let t = tenant();
    crate::db::tenants::create(&pool, *t.as_uuid(), "synthetic-c1", "free")
        .await
        .unwrap();
    (pool, t)
}
pub(super) fn claims(t: &TenantId) -> crate::auth::Claims {
    crate::auth::Claims {
        tenant_id: t.clone(),
        sub: format!("apikey:{}", Uuid::new_v4()),
        ..crate::auth::dev_stub_claims(crate::auth::AuthMethod::ApiKey)
    }
}
pub(super) fn grants() -> crate::entitlement_cache::ResolvedEntitlements {
    let mut e = crate::entitlement_cache::ResolvedEntitlements::deny_all();
    e.action_control = true;
    e
}
async fn business(tx: &tokio_postgres::Transaction<'_>, t: &TenantId, e: &ActionEvent, seq: u64) {
    tx.execute("INSERT INTO action_executions (tenant_id,execution_id,action_id,idempotency_key,request_digest,ledger_seq,agent_key_id,decision_id,policy_id,policy_version,policy_hash,state) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,1,$10,'in_flight')", &[t.as_uuid(), &Uuid::new_v4(), &e.action_id, &Uuid::new_v4(), &e.request_digest, &(seq as i64), &Uuid::new_v4(), &Uuid::new_v4(), &Uuid::new_v4(), &"b".repeat(64)]).await.unwrap();
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_commit() {
    let (pool, t) = fixture().await;
    let mut c = pool.get().await.unwrap();
    let tx = c.transaction().await.unwrap();
    let e = event();
    let out = append_actions_tx(&tx, &claims(&t), Some(&grants()), std::slice::from_ref(&e))
        .await
        .unwrap()
        .unwrap();
    business(&tx, &t, &e, out.first_seq).await;
    tx.commit().await.unwrap();
    assert_eq!(
        c.query_one(
            "SELECT count(*) FROM audit_appended WHERE event_id=$1",
            &[&format!("action:{t}:{}", e.event_id)]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    assert_eq!(
        crate::db::ledger::ledger_range(&pool, &t)
            .await
            .unwrap()
            .total,
        1
    );
    assert_eq!(
        c.query_one(
            "SELECT count(*) FROM action_executions WHERE tenant_id=$1",
            &[t.as_uuid()]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    assert_eq!(
        crate::db::audit_chain_state::load_all(&pool)
            .await
            .unwrap()
            .iter()
            .find(|r| r.tenant_id == t)
            .unwrap()
            .last_seq,
        0
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_rollback() {
    let (pool, t) = fixture().await;
    let mut c = pool.get().await.unwrap();
    let tx = c.transaction().await.unwrap();
    let e = event();
    let out = append_actions_tx(&tx, &claims(&t), Some(&grants()), std::slice::from_ref(&e))
        .await
        .unwrap()
        .unwrap();
    business(&tx, &t, &e, out.first_seq).await;
    tx.rollback().await.unwrap();
    assert_eq!(
        crate::db::ledger::ledger_range(&pool, &t)
            .await
            .unwrap()
            .total,
        0
    );
    for table in ["action_executions", "audit_chain_state"] {
        let sql = format!("SELECT count(*) FROM {table} WHERE tenant_id=$1");
        assert_eq!(
            c.query_one(&sql, &[t.as_uuid()])
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
    }
    assert_eq!(
        c.query_one(
            "SELECT count(*) FROM audit_appended WHERE event_id=$1",
            &[&format!("action:{t}:{}", e.event_id)]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_concurrent() {
    let (pool, t) = fixture().await;
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..50 {
        let pool = pool.clone();
        let t = t.clone();
        tasks.spawn(async move {
            let mut c = pool.get().await.unwrap();
            let tx = c.transaction().await.unwrap();
            let out = append_actions_tx(&tx, &claims(&t), Some(&grants()), &[event()])
                .await
                .unwrap()
                .unwrap();
            tx.commit().await.unwrap();
            out.first_seq
        });
    }
    let mut seqs = Vec::new();
    while let Some(r) = tasks.join_next().await {
        seqs.push(r.unwrap());
    }
    seqs.sort();
    assert_eq!(seqs, (0..50).collect::<Vec<_>>());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_tenant_crossing() {
    let (pool, a) = fixture().await;
    let b = tenant();
    crate::db::tenants::create(&pool, *b.as_uuid(), "synthetic-b", "free")
        .await
        .unwrap();
    let mut c = pool.get().await.unwrap();
    c.execute(
        "INSERT INTO plan_entitlements (plan_lookup_key) VALUES ('free_v1') ON CONFLICT DO NOTHING",
        &[],
    )
    .await
    .unwrap();
    c.execute(
        "UPDATE tenants SET action_control=true WHERE id=$1",
        &[a.as_uuid()],
    )
    .await
    .unwrap();
    let resolve = crate::entitlement_cache::pg_resolver(pool.clone());
    assert!(resolve(*a.as_uuid()).await.unwrap().action_control);
    assert!(!resolve(*b.as_uuid()).await.unwrap().action_control);
    let e = event();
    for t in [&a, &b] {
        let tx = c.transaction().await.unwrap();
        let out = append_actions_tx(&tx, &claims(t), Some(&grants()), std::slice::from_ref(&e))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(out.first_seq, 0, "stable event ID is tenant namespaced");
        tx.commit().await.unwrap();
    }
    let tx = c.transaction().await.unwrap();
    let result = crate::db::audit_chain_state::append_atomic_batch_tx(
        &tx,
        &a,
        [0; 32],
        None,
        1,
        &[None],
        |seq, prev, _| {
            let mut rows = rows_for(
                &b,
                None,
                Some(crate::auth::AuthMethod::JwtBearer),
                &[event()],
                seq,
                prev,
                &[0],
            )?;
            rows[0].tenant_id = b.to_string();
            Ok(rows)
        },
    )
    .await;
    assert!(result.is_err(), "foreign builder tenant must be refused");
    tx.rollback().await.unwrap();
    assert_eq!(
        crate::db::ledger::ledger_range(&pool, &a)
            .await
            .unwrap()
            .total,
        1
    );
    assert_eq!(
        crate::db::ledger::ledger_range(&pool, &b)
            .await
            .unwrap()
            .total,
        1
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_immutable() {
    let (pool, t) = fixture().await;
    let mut c = pool.get().await.unwrap();
    let tx = c.transaction().await.unwrap();
    append_actions_tx(&tx, &claims(&t), Some(&grants()), &[event()])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(
        c.execute(
            "UPDATE audit_log_rows SET payload='{}' WHERE tenant_id=$1",
            &[t.as_uuid()]
        )
        .await
        .is_err()
    );
    assert!(
        c.execute(
            "DELETE FROM audit_log_rows WHERE tenant_id=$1",
            &[t.as_uuid()]
        )
        .await
        .is_err()
    );
    c.execute("UPDATE audit_log_rows SET signature='synthetic-signature',signing_pubkey='synthetic-key' WHERE tenant_id=$1", &[t.as_uuid()]).await.unwrap();
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_checkpoint_and_secret() {
    let (pool, a) = fixture().await;
    let b = tenant();
    crate::db::tenants::create(&pool, *b.as_uuid(), "synthetic-b", "free")
        .await
        .unwrap();

    let mut c = pool.get().await.unwrap();
    let tx = c.transaction().await.unwrap();
    let master = std::sync::Arc::new(
        crate::byok::ByokMasterKey::from_values(
            Some(&base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                [7; 32],
            )),
            None,
            None,
        )
        .unwrap()
        .unwrap(),
    );
    let sa = tokenization_secret_tx(&tx, &a, Some(&grants()), &master)
        .await
        .unwrap();
    let sb = tokenization_secret_tx(&tx, &b, Some(&grants()), &master)
        .await
        .unwrap();
    assert_ne!(sa.expose_secret(), sb.expose_secret());
    let raw = "BEN-TEST-001";
    let mut e = event();
    e.body = ActionPayload::ActionProposed {
        tool_ref: Uuid::new_v4(),
        contract_version: 1,
        args_digest: "a".repeat(64),
        evidence_fields: [(
            "beneficiary".into(),
            minimize(&sa, EvidenceMode::Tokenize, raw).unwrap(),
        )]
        .into(),
        agent_claimed_labels: Default::default(),
        principal: None,
    };
    append_actions_tx(&tx, &claims(&a), Some(&grants()), &[e])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let keys = crate::audit_keys::TenantAuditKeyStore::new(pool.clone(), master.clone(), None);
    let cp = create_checkpoint(&pool, &a, Some(&grants()), &keys)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&cp.statement).unwrap();
    assert_eq!(body["seq"], "0");
    let empty = create_checkpoint(&pool, &b, Some(&grants()), &keys)
        .await
        .unwrap();
    let empty_body: Value = serde_json::from_str(&empty.statement).unwrap();
    assert!(empty_body["seq"].is_null());
    assert!(empty_body["head_hash"].is_null());
    assert!(
        empty_body["previous_checkpoint_digest"].is_null(),
        "foreign checkpoint must not become B's predecessor"
    );
    assert_ne!(empty_body["key_id"], body["key_id"]);
    assert!(
        load_checkpoint(&pool, &b, Some(&grants()), empty.id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        load_checkpoint(&pool, &a, Some(&grants()), empty.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        load_checkpoint(&pool, &b, Some(&grants()), cp.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        load_checkpoint(&pool, &a, Some(&grants()), cp.id)
            .await
            .unwrap()
            .is_some()
    );
    let rows = crate::db::ledger::read_rows_from(&pool, &a, 0, 10)
        .await
        .unwrap();
    assert!(!rows[0].payload.contains(raw));
    assert!(!format!("{rows:?}").contains(raw));
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_flag_off_no_tables() {
    let (pool, t) = fixture().await;
    let mut c = pool.get().await.unwrap();
    c.batch_execute("DROP TABLE action_executions; DROP TABLE audit_head_checkpoints; DROP TABLE action_tokenization_secrets").await.unwrap();
    let master = std::sync::Arc::new(
        crate::byok::ByokMasterKey::from_values(
            Some(&base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                [7; 32],
            )),
            None,
            None,
        )
        .unwrap()
        .unwrap(),
    );
    let keys = crate::audit_keys::TenantAuditKeyStore::new(pool.clone(), master.clone(), None);
    let tx = c.transaction().await.unwrap();
    for resolved in [
        None,
        Some(crate::entitlement_cache::ResolvedEntitlements::deny_all()),
    ] {
        assert_eq!(
            tokenization_secret_tx(&tx, &t, resolved.as_ref(), &master)
                .await
                .err()
                .unwrap()
                .to_string(),
            "action control disabled"
        );
        assert_eq!(
            create_checkpoint(&pool, &t, resolved.as_ref(), &keys)
                .await
                .err()
                .unwrap()
                .to_string(),
            "action control disabled"
        );
        assert_eq!(
            load_checkpoint(&pool, &t, resolved.as_ref(), Uuid::new_v4())
                .await
                .err()
                .unwrap()
                .to_string(),
            "action control disabled"
        );
    }
    assert!(
        append_actions_tx(&tx, &claims(&t), None, &[event()])
            .await
            .unwrap()
            .is_none()
    );
    tx.commit().await.unwrap();
    assert_eq!(
        crate::db::ledger::ledger_range(&pool, &t)
            .await
            .unwrap()
            .total,
        0
    );
}

#[test]
fn oversized_integer_tokens_cannot_collide() {
    for raw in [
        "18446744073709551616",
        "18446744073709551617",
        "-18446744073709551616",
        "[18446744073709551617]",
        "{\"n\":18446744073709551616}",
    ] {
        assert!(
            canonical_json(raw).is_err(),
            "overflow integer accepted: {raw}"
        );
    }
    assert!(canonical_json("1e30").is_err());
}
#[test]
fn legacy_float_bytes_unchanged() {
    let value: Value = serde_json::from_str("40583172120499283e-13").unwrap();
    assert_eq!(serde_json::to_string(&value).unwrap(), "4058.317212049928");
    // Ordinary audit formatting must keep its historical bytes too.
    assert_eq!(
        crate::audit_format::canonical_payload(&value),
        "4058.317212049928"
    );
    assert!(canonical_json("40583172120499283e-13").is_err());
}
#[test]
fn confidential_reason_codes_rejected() {
    for secret in [
        "customer bank account 1234",
        "sk_confidential_secret",
        "synthetic@example.test",
    ] {
        let body = json!({"event_type":"decision_made","decision":"deny","rule_id":"limit","reason_codes":[secret],"policy_id":Uuid::new_v4(),"policy_version":1,"policy_hash":"a".repeat(64)});
        assert!(
            serde_json::from_value::<ActionPayload>(body).is_err(),
            "secret accepted as reason code"
        );
        assert!(
            serde_json::from_value::<ActionPayload>(
                json!({"event_type":"denied_runtime","reason":secret})
            )
            .is_err()
        );
    }
}
#[test]
fn checkpoint_exact_protocol() {
    let t = tenant();
    let key = crate::audit_keys::TenantAuditKeypair::generate(t.clone()).unwrap();
    for head in [None, Some((7, [8; 32]))] {
        let cp = sign_checkpoint(&key, &t, head, None).unwrap();
        let body: Value = serde_json::from_str(&cp.statement).unwrap();
        let mut fields = body
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        fields.sort();
        assert_eq!(
            fields,
            vec![
                "created_at",
                "domain",
                "head_hash",
                "key_id",
                "previous_checkpoint_digest",
                "schema_version",
                "seq",
                "tenant_id"
            ]
        );
        assert_eq!(
            body["seq"],
            head.map(|h| Value::String(h.0.to_string()))
                .unwrap_or(Value::Null)
        );
        assert_eq!(
            body["head_hash"],
            head.map(|h| Value::String(hex::encode(h.1)))
                .unwrap_or(Value::Null)
        );
        assert_eq!(body["key_id"], sha(&key.public_key_bytes()));
    }
}
#[test]
fn token_hmac_known_answer_utf8() {
    // RFC 4231 case 2: independently published HMAC-SHA256 vector.
    let token = minimize(
        &SecretString::from("Jefe".to_owned()),
        EvidenceMode::Tokenize,
        "what do ya want for nothing?",
    )
    .unwrap();
    assert_eq!(
        token,
        EvidenceField::Tokenize {
            hmac: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843".into(),
            last4: "ing?".into()
        }
    );
}

#[tokio::test]
async fn disabled_checkpoints_refuse_before_pool_or_keys() {
    let mut config = deadpool_postgres::Config::new();
    config.host = Some("127.0.0.1".into());
    config.port = Some(1);
    config.user = Some("synthetic".into());
    config.dbname = Some("synthetic".into());
    let pool = config
        .create_pool(
            Some(deadpool_postgres::Runtime::Tokio1),
            tokio_postgres::NoTls,
        )
        .unwrap();
    let master = std::sync::Arc::new(
        crate::byok::ByokMasterKey::from_values(
            Some(&base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                [7; 32],
            )),
            None,
            None,
        )
        .unwrap()
        .unwrap(),
    );
    let keys = crate::audit_keys::TenantAuditKeyStore::new(pool.clone(), master, None);
    let tenant = tenant();
    let created = create_checkpoint(&pool, &tenant, None, &keys).await;
    assert_eq!(
        created.err().unwrap().to_string(),
        "action control disabled"
    );
    let loaded = load_checkpoint(&pool, &tenant, None, Uuid::new_v4()).await;
    assert_eq!(loaded.err().unwrap().to_string(), "action control disabled");
}

#[test]
fn floats_are_outside_action_contract() {
    for raw in ["1e0", "1e30", "1.0", "-0.0", "[1.5]", "{\"n\":2e3}"] {
        assert!(canonical_json(raw).is_err(), "float accepted: {raw}");
    }
}

#[test]
fn fix_pass_lifecycle_events_are_typed_and_minimized() {
    for tag in ["approval_expired", "approval_invalidated"] {
        let value = json!({"event_type":tag,"approval_id":Uuid::new_v4()});
        let body: ActionPayload =
            serde_json::from_value(value.clone()).expect("missing lifecycle action event");
        let mut e = event();
        e.body = body;
        assert_eq!(e.event_type(), tag);
        assert_eq!(serde_json::to_value(&e.body).unwrap(), value);
        let mut extra = value;
        extra["raw_args"] = json!("must not enter ledger");
        assert!(serde_json::from_value::<ActionPayload>(extra).is_err());
    }
}
#[test]
fn principal_denial_uses_v2() {
    for reason in [
        ReasonCode::PrincipalRequired,
        ReasonCode::PrincipalInvalid,
        ReasonCode::PrincipalUnverifiable,
    ] {
        let event = ActionEvent {
            event_id: Uuid::nil(),
            action_id: Uuid::nil(),
            occurred_at: Utc::now(),
            request_digest: "ab".repeat(32),
            body: ActionPayload::DeniedRuntime { reason },
        };
        let value: Value = serde_json::from_str(
            &event
                .canonical(&TenantId::from_jwt_claim(Uuid::nil()), None)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(value["schema_version"], 2);
    }
    let event = ActionEvent {
        event_id: Uuid::nil(),
        action_id: Uuid::nil(),
        occurred_at: Utc::now(),
        request_digest: "ab".repeat(32),
        body: ActionPayload::DeniedRuntime {
            reason: ReasonCode::PolicyDenied,
        },
    };
    let value: Value = serde_json::from_str(
        &event
            .canonical(&TenantId::from_jwt_claim(Uuid::nil()), None)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(value["schema_version"], 1);
}

//! Ordinary synthetic receipt-registration contracts against task-owned Postgres.
//! No direct alteration of existing registration evidence or external tool transport.
use super::*;

async fn canonical_registration(f: &Fixture, server: Uuid, seed: u8) {
    let public = pair(seed).public_key().as_ref().to_vec();
    let key_id = receipt_keys::receipt::key_id(&public);
    let event = ActionEvent {
        event_id: Uuid::new_v4(),
        action_id: server,
        occurred_at: Utc::now(),
        request_digest: key_id.clone(),
        body: ActionPayload::ToolReceiptKeyRegistered {
            server_id: server,
            receipt_key_id: key_id,
            public_key: hex::encode(public),
        },
    };
    let mut db = f.pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    tx.query_one(
        "SELECT id FROM tenants WHERE id=$1 FOR UPDATE",
        &[f.publisher.tenant_id.as_uuid()],
    )
    .await
    .unwrap();
    append_for_actor_tx(
        &tx,
        &f.publisher.tenant_id,
        None,
        Some(f.publisher.auth_method),
        &[event],
    )
    .await
    .unwrap()
    .unwrap();
    tx.commit().await.unwrap();
}

async fn effective(f: &Fixture, server: Uuid) -> Option<receipt_keys::ReceiptKey> {
    let mut db = f.pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    tx.query_one(
        "SELECT id FROM tenants WHERE id=$1 FOR UPDATE",
        &[f.agent.tenant_id.as_uuid()],
    )
    .await
    .unwrap();
    let result = receipt_keys::load_tx(
        &tx,
        &f.agent.tenant_id,
        server,
        Uuid::from_u128(11),
        Uuid::from_u128(12),
        &"e".repeat(64),
        "synthetic-attestation",
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    result
}

#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn b634_canonical_registration_is_effective() {
    let f = Fixture::new().await;
    canonical_registration(&f, f.server, 7).await;
    let key = effective(&f, f.server).await;
    receipt_keys::tests::assert_selected_registration(key.as_ref(), pair(7).public_key().as_ref());
    let key = key.unwrap();
    assert_eq!(key.binding.tenant_id, *f.agent.tenant_id.as_uuid());
    assert_eq!(key.binding.server_id, f.server);
    assert_eq!(key.binding.execution_id, Uuid::from_u128(11));
    assert_eq!(key.binding.action_id, Uuid::from_u128(12));
    assert_eq!(key.binding.request_digest, "e".repeat(64));
    assert_eq!(
        key.expected.attestation_digest,
        sha(b"synthetic-attestation")
    );
}

#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn b634_latest_sequence_wins() {
    let f = Fixture::new().await;
    canonical_registration(&f, f.server, 7).await;
    canonical_registration(&f, f.server, 8).await;
    let key = effective(&f, f.server).await;
    receipt_keys::tests::assert_selected_registration(key.as_ref(), pair(8).public_key().as_ref());
    assert_eq!(
        count(&f, &format!("{LEDGER}'tool_receipt_key_registered'")).await,
        2
    );
}

#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn b634_empty_and_other_namespaces_are_absent() {
    let f = Fixture::new().await;
    assert!(effective(&f, f.server).await.is_none());
    let other_server = Uuid::new_v4();
    canonical_registration(&f, other_server, 7).await;
    assert!(effective(&f, f.server).await.is_none());
    let other = f.other().await;
    canonical_registration(&other, f.server, 8).await;
    assert!(effective(&f, f.server).await.is_none());
}

#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn b634_ordinary_commit_loads() {
    let f = Fixture::new().await;
    register(&f, f.server, 7, grants()).await.unwrap();
    assert_eq!(
        effective(&f, f.server).await.unwrap().public,
        pair(7).public_key().as_ref()
    );
    register(&f, f.server, 8, grants()).await.unwrap();
    assert_eq!(
        effective(&f, f.server).await.unwrap().public,
        pair(8).public_key().as_ref()
    );
}

#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn b634_rotated_key_has_distinct_refusal_and_count() {
    // This exact test runs alone in a child test process. No production counter resets.
    const CHILD: &str = "TRACELANE_B634_COUNTER_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "action_control::approval_pg_tests::receipt_pg_tests::integrity_tests::b634_rotated_key_has_distinct_refusal_and_count", "--ignored", "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .output().unwrap();
        assert!(
            output.status.success(),
            "isolated counter contract failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
            "exact child filter must execute one test, not silently match zero"
        );
        return;
    }
    assert!(
        std::env::args().any(|arg| arg == "--exact"),
        "counter child requires exact test isolation"
    );
    let f = Fixture::new().await;
    let public: [u8; 32] = f.signer.public_key().try_into().unwrap();
    let actor = crate::control_plane::ControlActor::for_test(f.publisher.tenant_id.clone());
    receipt_keys::commit(
        &f.pool,
        &f.publisher,
        &actor,
        &grants(),
        std::time::Duration::from_secs(30),
        f.server,
        &public,
    )
    .await
    .unwrap();
    let id = f.pending().await;
    assert_eq!(f.decide(&f.human, id, true).await, None);
    let call = f.call(Uuid::new_v4(), Some(id));
    let before = conflict_count();
    let sent = std::sync::atomic::AtomicBool::new(false);
    let out = execute(
        &f.pool,
        &f.agent,
        Some(&grants()),
        &call,
        &f.signer,
        None,
        |_| {
            sent.store(true, std::sync::atomic::Ordering::SeqCst);
            async { Outcome::Succeeded(Uuid::new_v4()) }
        },
    )
    .await;
    assert!(!sent.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        out.expect_err("collision must refuse").to_string(),
        "receipt_key_conflict"
    );
    // exact-delta-ok: this child runs only this exact test; only its failed reservation notes this kind.
    assert_eq!(
        conflict_count(),
        before + 1,
        "one note per refused reservation"
    );
    assert_eq!(count(&f, &format!("{LEDGER}'execution_started'")).await, 0);
    assert_eq!(
        count(
            &f,
            "SELECT count(*) FROM action_executions WHERE tenant_id=$1"
        )
        .await,
        0
    );
    let success = Fixture::new().await;
    register(&success, success.server, 7, grants())
        .await
        .unwrap();
    let before_success = conflict_count();
    let result = run(&success, |h, id| {
        Outcome::Countersigned(id, tool_sign_header(&pair(7), h, success.server, id))
    })
    .await;
    assert_eq!(result.state, State::Succeeded);
    // exact-delta-ok: same isolated exact-test child; no other test or counter notifier runs here.
    assert_eq!(
        conflict_count(),
        before_success,
        "successful reservation must not note a conflict"
    );
}
fn conflict_count() -> u64 {
    tracelane_shared::degradation::snapshot()
        .into_iter()
        .find(|s| s.kind == "receipt_key_conflict")
        .map_or(0, |s| s.count)
}

#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn b634_platform_key_registration_refused() {
    use base64::Engine as _;
    use ring::signature::Ed25519KeyPair;
    let f = Fixture::new().await;
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let platform = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let encoded = base64::engine::general_purpose::STANDARD.encode(pkcs8.as_ref());
    let mut state = f.http_state(grants());
    state.audit_chain = std::sync::Arc::new(
        crate::audit::AuditChain::with_pg_pool(0, Some(&encoded), None, None).unwrap(),
    );
    let body = json!({"public_key": hex::encode(platform.public_key().as_ref())}).to_string();
    let actor = crate::control_plane::ControlActor::for_test(f.publisher.tenant_id.clone());
    let result = receipt_keys::register(
        &state,
        &f.publisher,
        &actor,
        &f.server.to_string(),
        body.as_bytes(),
    )
    .await;
    assert_eq!(
        result,
        Err((400, "invalid_receipt_key")),
        "platform and tool keys have separate purposes"
    );
    assert_eq!(
        count(&f, &format!("{LEDGER}'tool_receipt_key_registered'")).await,
        0
    );
}

/// Seed the tenant's gateway-held ledger key row with a given published public half.
async fn seed_tenant_audit_key(f: &Fixture, published: &str) {
    let db = f.pool.get().await.unwrap();
    db.execute(
        "INSERT INTO tenant_audit_keys (tenant_id, encrypted_private_key, public_key_b64) \
         VALUES ($1, 'test-not-a-real-envelope', $2)",
        &[f.publisher.tenant_id.as_uuid(), &published],
    )
    .await
    .unwrap();
}
#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn b634_tenant_audit_key_registration_refused() {
    use base64::Engine as _;
    let f = Fixture::new().await;
    let published = base64::engine::general_purpose::STANDARD.encode(pair(9).public_key().as_ref());
    seed_tenant_audit_key(&f, &published).await;
    assert_eq!(
        register(&f, f.server, 9, grants()).await,
        Err((400, "invalid_receipt_key")),
        "the tenant's gateway-held ledger key must never be a tool receipt key"
    );
    assert_eq!(
        count(&f, &format!("{LEDGER}'tool_receipt_key_registered'")).await,
        0
    );
    // A tool's own, different key still registers beside the tenant ledger key.
    register(&f, f.server, 10, grants()).await.unwrap();
}
#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn b634_unpublished_tenant_audit_key_is_unavailable() {
    let f = Fixture::new().await;
    seed_tenant_audit_key(&f, "").await;
    assert_eq!(
        register(&f, f.server, 9, grants()).await,
        Err((503, "evidence_unavailable")),
        "an unpublished ledger key cannot be compared, so registration fails closed"
    );
}

#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn b634_registration_before_value() {
    let f = Fixture::new().await;
    canonical_registration(&f, f.server, 7).await;
    register(&f, f.server, 8, grants()).await.unwrap();
    let db = f.pool.get().await.unwrap();
    let row=db.query_one("SELECT before_json,after_json FROM admin_audit_log WHERE actor_workspace_id=$1 AND action='mcp_server.receipt_key.set' AND target_id=$2", &[f.publisher.tenant_id.as_uuid(),&f.server.to_string()]).await.unwrap();
    let before: Value = row.get(0);
    let after: Value = row.get(1);
    assert_eq!(
        before["receipt_key_id"],
        receipt_keys::receipt::key_id(pair(7).public_key().as_ref())
    );
    assert_eq!(
        after["receipt_key_id"],
        receipt_keys::receipt::key_id(pair(8).public_key().as_ref())
    );
}
#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn b634_table_compatibility_write() {
    let f = Fixture::new().await;
    register(&f, f.server, 7, grants()).await.unwrap();
    register(&f, f.server, 8, grants()).await.unwrap();
    let db = f.pool.get().await.unwrap();
    let row=db.query_one("SELECT public_key,receipt_key_id FROM action_tool_receipt_keys WHERE tenant_id=$1 AND server_id=$2", &[f.agent.tenant_id.as_uuid(),&f.server]).await.unwrap();
    let public: Vec<u8> = row.get(0);
    let id: String = row.get(1);
    assert_eq!(public, pair(8).public_key().as_ref());
    assert_eq!(id, receipt_keys::receipt::key_id(&public));
    assert_eq!(
        count(&f, &format!("{LEDGER}'tool_receipt_key_registered'")).await,
        2
    );
}
#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn b634_same_key_reregistration() {
    let f = Fixture::new().await;
    register(&f, f.server, 7, grants()).await.unwrap();
    register(&f, f.server, 7, grants()).await.unwrap();
    assert_eq!(
        effective(&f, f.server).await.unwrap().public,
        pair(7).public_key().as_ref()
    );
    assert_eq!(
        count(&f, &format!("{LEDGER}'tool_receipt_key_registered'")).await,
        2
    );
}
#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn b634_same_server_two_tenants() {
    let f = Fixture::new().await;
    let other = f.other().await;
    canonical_registration(&f, f.server, 7).await;
    canonical_registration(&other, f.server, 8).await;
    assert_eq!(
        effective(&f, f.server).await.unwrap().public,
        pair(7).public_key().as_ref()
    );
    assert_eq!(
        effective(&other, f.server).await.unwrap().public,
        pair(8).public_key().as_ref()
    );
}
#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn b634_read_error_never_absent() {
    let f = Fixture::new().await;
    let mut db = f.pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    // An ordinary invalid expression aborts this disposable transaction; no table is altered.
    assert!(tx.simple_query("SELECT 1/0").await.is_err());
    let out = receipt_keys::load_tx(
        &tx,
        &f.agent.tenant_id,
        f.server,
        Uuid::new_v4(),
        Uuid::new_v4(),
        &"e".repeat(64),
        "fixture",
    )
    .await;
    assert!(
        out.is_err(),
        "a failed read must not permit unsigned execution"
    );
    tx.rollback().await.unwrap();
}
#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn b634_registration_rollback_atomic() {
    let f = Fixture::new().await;
    let mut db = f.pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    tx.query_one(
        "SELECT id FROM tenants WHERE id=$1 FOR UPDATE",
        &[f.publisher.tenant_id.as_uuid()],
    )
    .await
    .unwrap();
    let public = pair(7).public_key().as_ref().to_vec();
    let id = receipt_keys::receipt::key_id(&public);
    let event = ActionEvent {
        event_id: Uuid::new_v4(),
        action_id: f.server,
        occurred_at: Utc::now(),
        request_digest: id.clone(),
        body: ActionPayload::ToolReceiptKeyRegistered {
            server_id: f.server,
            receipt_key_id: id,
            public_key: hex::encode(public),
        },
    };
    append_for_actor_tx(
        &tx,
        &f.publisher.tenant_id,
        None,
        Some(f.publisher.auth_method),
        &[event],
    )
    .await
    .unwrap()
    .unwrap();
    tx.rollback().await.unwrap();
    assert!(effective(&f, f.server).await.is_none());
    assert_eq!(
        count(&f, &format!("{LEDGER}'tool_receipt_key_registered'")).await,
        0
    );
}
#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn b634_old_timestamp_new_sequence() {
    let f = Fixture::new().await;
    canonical_registration(&f, f.server, 7).await;
    let public = pair(8).public_key().as_ref().to_vec();
    let id = receipt_keys::receipt::key_id(&public);
    let event = ActionEvent {
        event_id: Uuid::new_v4(),
        action_id: f.server,
        occurred_at: chrono::DateTime::from_timestamp(1, 0).unwrap(),
        request_digest: id.clone(),
        body: ActionPayload::ToolReceiptKeyRegistered {
            server_id: f.server,
            receipt_key_id: id,
            public_key: hex::encode(public),
        },
    };
    let mut db = f.pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    tx.query_one(
        "SELECT id FROM tenants WHERE id=$1 FOR UPDATE",
        &[f.publisher.tenant_id.as_uuid()],
    )
    .await
    .unwrap();
    append_for_actor_tx(
        &tx,
        &f.publisher.tenant_id,
        None,
        Some(f.publisher.auth_method),
        &[event],
    )
    .await
    .unwrap()
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        effective(&f, f.server).await.unwrap().public,
        pair(8).public_key().as_ref()
    );
}
#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn b634_missing_required_signature_unknown() {
    let f = Fixture::new().await;
    register(&f, f.server, 7, grants()).await.unwrap();
    let result = run(&f, |_, id| Outcome::Succeeded(id)).await;
    assert_eq!(result.state, State::Unknown);
    assert_eq!(
        count(&f, &format!("{LEDGER}'execution_succeeded'")).await,
        0
    );
}
#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn b634_disabled_registration_no_write() {
    let f = Fixture::new().await;
    assert_eq!(
        register(
            &f,
            f.server,
            7,
            crate::entitlement_cache::ResolvedEntitlements::deny_all()
        )
        .await,
        Err((409, "action_control_disabled"))
    );
    assert!(effective(&f, f.server).await.is_none());
}

#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn b634_concurrent_rotation_serialized() {
    let f = Fixture::new().await;
    register(&f, f.server, 7, grants()).await.unwrap();
    let (rotation, observed) =
        tokio::join!(register(&f, f.server, 8, grants()), effective(&f, f.server));
    rotation.unwrap();
    let observed = observed.unwrap().public;
    assert!(observed == pair(7).public_key().as_ref() || observed == pair(8).public_key().as_ref());
    assert_eq!(
        effective(&f, f.server).await.unwrap().public,
        pair(8).public_key().as_ref()
    );
}
#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn b634_normal_countersigned_success() {
    let f = Fixture::new().await;
    register(&f, f.server, 7, grants()).await.unwrap();
    let result = run(&f, |h, id| {
        Outcome::Countersigned(id, tool_sign_header(&pair(7), h, f.server, id))
    })
    .await;
    assert_eq!(result.state, State::Succeeded);
    assert!(result.countersignature.is_some());
}
#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn b634_lookup_uses_registration_index() {
    let f = Fixture::new().await;
    let public = pair(7).public_key().as_ref().to_vec();
    let id = receipt_keys::receipt::key_id(&public);
    let events: Vec<_> = (0..1000)
        .map(|i| {
            let server = if i == 500 { f.server } else { Uuid::new_v4() };
            ActionEvent {
                event_id: Uuid::new_v4(),
                action_id: server,
                occurred_at: Utc::now(),
                request_digest: id.clone(),
                body: ActionPayload::ToolReceiptKeyRegistered {
                    server_id: server,
                    receipt_key_id: id.clone(),
                    public_key: hex::encode(&public),
                },
            }
        })
        .collect();
    let mut db = f.pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    tx.query_one(
        "SELECT id FROM tenants WHERE id=$1 FOR UPDATE",
        &[f.publisher.tenant_id.as_uuid()],
    )
    .await
    .unwrap();
    append_for_actor_tx(
        &tx,
        &f.publisher.tenant_id,
        None,
        Some(f.publisher.auth_method),
        &events,
    )
    .await
    .unwrap()
    .unwrap();
    tx.commit().await.unwrap();
    let row=db.query_one("EXPLAIN (FORMAT JSON) SELECT payload FROM audit_log_rows WHERE tenant_id=$1 AND event_type='tool_receipt_key_registered' AND (payload::jsonb)->>'action_id'=$2 ORDER BY seq DESC LIMIT 1", &[f.publisher.tenant_id.as_uuid(),&f.server.to_string()]).await.unwrap();
    let plan: Value = row.get(0);
    assert!(
        plan.to_string().contains("audit_receipt_key_lookup"),
        "{plan}"
    );
    assert_eq!(effective(&f, f.server).await.unwrap().public, public);
}

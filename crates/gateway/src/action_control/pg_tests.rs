//! Disposable-Postgres acceptance probes, selected by the standard PG runner.
use super::tests::{claims, event, fixture, grants};
use super::*;

async fn append(
    tx: &Transaction<'_>,
    tenant: &TenantId,
) -> crate::db::audit_chain_state::AtomicBatchAppend {
    append_actions_tx(tx, &claims(tenant), Some(&grants()), &[event()])
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_hook_refuses_before_commit_and_after_rollback() {
    let (pool, tenant) = fixture().await;
    let chain = crate::audit::AuditChain::with_pg_pool(0, None, None, Some(pool.clone())).unwrap();
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    let rolled_back = append(&tx, &tenant).await;
    assert!(
        chain
            .after_outer_commit(&tenant, rolled_back.clone())
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    assert!(
        chain
            .after_outer_commit(&tenant, rolled_back.clone())
            .await
            .is_err()
    );

    let tx = client.transaction().await.unwrap();
    let committed = append(&tx, &tenant).await;
    tx.commit().await.unwrap();
    assert_eq!(committed.first_seq, rolled_back.first_seq);
    assert!(
        chain
            .after_outer_commit(&tenant, rolled_back)
            .await
            .is_err()
    );

    let mut empty_hashes = committed.clone();
    empty_hashes.row_hashes.clear();
    assert!(
        chain
            .after_outer_commit(&tenant, empty_hashes)
            .await
            .is_err()
    );
    let mut fabricated_count = committed.clone();
    fabricated_count.kept.push(1);
    assert!(
        chain
            .after_outer_commit(&tenant, fabricated_count)
            .await
            .is_err()
    );
    let mut wrong_previous = committed.clone();
    wrong_previous.prev_hash[0] ^= 1;
    assert!(
        chain
            .after_outer_commit(&tenant, wrong_previous)
            .await
            .is_err()
    );
    let other = TenantId::from_jwt_claim(Uuid::new_v4());
    crate::db::tenants::create(&pool, *other.as_uuid(), "synthetic-other", "free")
        .await
        .unwrap();
    assert!(
        chain
            .after_outer_commit(&other, committed.clone())
            .await
            .is_err()
    );
    chain.after_outer_commit(&tenant, committed).await.unwrap();
    assert_eq!(
        crate::db::ledger::ledger_range(&pool, &tenant)
            .await
            .unwrap()
            .total,
        1
    );
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_conflicting_ledger_row_rolls_back_protected_append() {
    let (pool, tenant) = fixture().await;
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    let initial = append(&tx, &tenant).await;
    tx.commit().await.unwrap();
    let head_before = client
        .query_one(
            "SELECT last_seq, last_row_hash FROM audit_chain_state WHERE tenant_id=$1",
            &[tenant.as_uuid()],
        )
        .await
        .unwrap();

    // Recovery can adopt a row ahead of the locked head. Adoption stays idempotent.
    let mut conflict = initial.rows[0].clone();
    conflict.seq += 1;
    conflict.actor = "synthetic-conflicting-recovery".into();
    crate::db::ledger::insert_rows(&pool, std::slice::from_ref(&conflict))
        .await
        .unwrap();
    crate::db::ledger::insert_rows(&pool, std::slice::from_ref(&conflict))
        .await
        .unwrap();
    let identity: [Uuid; 6] = std::array::from_fn(|_| Uuid::new_v4());
    let mut protected = event();
    protected.action_id = identity[1];
    protected.body = ActionPayload::ExecutionStarted {
        execution_id: identity[0],
        idempotency_key: identity[2],
        attestation_key_id: "synthetic-tool-v1".into(),
        receipt_expected: None,
    };
    let mut auth = claims(&tenant);
    auth.sub = format!("apikey:{}", identity[3]);
    let tx = client.transaction().await.unwrap();
    // A real business reservation is already pending in the caller's transaction.
    tx.execute(
        "INSERT INTO action_executions (tenant_id,execution_id,action_id,idempotency_key,agent_key_id,decision_id,policy_id,policy_version,policy_hash,request_digest,ledger_seq,state) VALUES ($1,$2,$3,$4,$5,$6,$7,7,$8,$9,$10,'in_flight')",
        &[tenant.as_uuid(), &identity[0], &identity[1], &identity[2], &identity[3], &identity[4], &identity[5], &"b".repeat(64), &protected.request_digest, &(conflict.seq as i64)],
    ).await.unwrap();
    let result = append_actions_tx(
        &tx,
        &auth,
        Some(&grants()),
        std::slice::from_ref(&protected),
    )
    .await;
    tx.rollback().await.unwrap();
    assert!(
        result.is_err(),
        "conflicting canonical row must refuse protected append"
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("inserted 0 of 1 rows")
    );
    assert_eq!(
        client
            .query_one(
                "SELECT count(*) FROM action_executions WHERE tenant_id=$1",
                &[tenant.as_uuid()],
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        client
            .query_one(
                "SELECT count(*) FROM audit_appended WHERE event_id=$1",
                &[&format!("action:{tenant}:{}", protected.event_id)],
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let head_after = client
        .query_one(
            "SELECT last_seq, last_row_hash FROM audit_chain_state WHERE tenant_id=$1",
            &[tenant.as_uuid()],
        )
        .await
        .unwrap();
    assert_eq!(head_after.get::<_, i64>(0), head_before.get::<_, i64>(0));
    assert_eq!(
        head_after.get::<_, Vec<u8>>(1),
        head_before.get::<_, Vec<u8>>(1)
    );
    let rows = crate::db::ledger::read_rows_from(&pool, &tenant, conflict.seq, 10)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].actor, conflict.actor);
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_missed_hook_recovers_on_restart() {
    let (pool, tenant) = fixture().await;
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    let candidate = append(&tx, &tenant).await;
    append(&tx, &tenant).await;
    append(&tx, &tenant).await;
    tx.commit().await.unwrap();
    // Simulate a process exit between COMMIT and after_outer_commit. Recovery
    // must use the durable canonical head, even though no hook ran.
    drop(candidate);
    crate::audit::copy_tests::assert_restart_recovers_copy(&pool, &tenant).await;
    let signing_key =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let signing_key_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        signing_key.as_ref(),
    );
    // No tenant keystore means no external Rekor submit, even if its URL is
    // configured. The existing sweep signs the durable rows locally.
    let restarted =
        crate::audit::AuditChain::with_pg_pool(0, Some(&signing_key_b64), None, Some(pool.clone()))
            .unwrap();
    restarted.warm_from_postgres().await.unwrap();
    assert_eq!(restarted.in_memory_seq(&tenant), 3);
    assert_eq!(
        restarted
            .flush_aged_batches(std::time::Duration::ZERO)
            .await,
        1
    );
    assert_eq!(
        crate::db::ledger::last_anchored_end(&pool, &tenant)
            .await
            .unwrap(),
        Some(2)
    );
    assert_eq!(
        restarted
            .flush_aged_batches(std::time::Duration::ZERO)
            .await,
        0
    );
    restarted
        .append(crate::audit::AuditEvent {
            tenant_id: tenant.clone(),
            event_type: "request",
            actor: "synthetic-restart".into(),
            payload: json!({}),
        })
        .await
        .unwrap();
    let rows = crate::db::ledger::read_rows_from(&pool, &tenant, 0, 10)
        .await
        .unwrap();
    assert_eq!(
        rows.iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![0, 1, 2, 3]
    );
    for pair in rows.windows(2) {
        assert_eq!(pair[1].prev_hash, pair[0].row_hash);
    }
    assert_eq!(rows[0].event_type, "denied_runtime");
    assert_eq!(rows[3].event_type, "request");
    assert!(
        rows[..3].iter().all(|row| !row.signature.is_empty()),
        "the missed hook's canonical rows are signed by recovery"
    );
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_ciphertext_swap_refused() {
    let (pool, a) = fixture().await;
    let b = TenantId::from_jwt_claim(Uuid::new_v4());
    crate::db::tenants::create(&pool, *b.as_uuid(), "synthetic-b", "free")
        .await
        .unwrap();
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
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    let a_secret = tokenization_secret_tx(&tx, &a, Some(&grants()), &master)
        .await
        .unwrap();
    let b_secret = tokenization_secret_tx(&tx, &b, Some(&grants()), &master)
        .await
        .unwrap();
    assert_ne!(a_secret.expose_secret(), b_secret.expose_secret());
    tx.commit().await.unwrap();
    client.execute(
        "UPDATE action_tokenization_secrets SET encrypted_secret=(SELECT encrypted_secret FROM action_tokenization_secrets WHERE tenant_id=$1) WHERE tenant_id=$2",
        &[a.as_uuid(), b.as_uuid()],
    ).await.unwrap();
    let tx = client.transaction().await.unwrap();
    assert!(
        tokenization_secret_tx(&tx, &b, Some(&grants()), &master)
            .await
            .is_err()
    );
    assert_eq!(
        tokenization_secret_tx(&tx, &a, Some(&grants()), &master)
            .await
            .unwrap()
            .expose_secret(),
        a_secret.expose_secret()
    );
    tx.rollback().await.unwrap();
}

async fn insert_reservation(
    client: &tokio_postgres::Client,
    tenant: &TenantId,
    seq: i64,
    identity: &[Uuid; 6],
    policy_hash: &str,
) -> std::result::Result<u64, tokio_postgres::Error> {
    client.execute(
        "INSERT INTO action_executions (tenant_id,execution_id,action_id,idempotency_key,agent_key_id,decision_id,policy_id,policy_version,policy_hash,request_digest,ledger_seq,state) VALUES ($1,$2,$3,$4,$5,$6,$7,7,$8,$9,$10,'in_flight')",
        &[tenant.as_uuid(), &identity[0], &identity[1], &identity[2], &identity[3], &identity[4], &identity[5], &policy_hash, &"a".repeat(64), &seq],
    ).await
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_foreign_ledger_reference_refused() {
    let (pool, a) = fixture().await;
    let b = TenantId::from_jwt_claim(Uuid::new_v4());
    crate::db::tenants::create(&pool, *b.as_uuid(), "synthetic-b", "free")
        .await
        .unwrap();
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    let a_rows = append(&tx, &a).await;
    tx.commit().await.unwrap();
    let identity = std::array::from_fn(|_| Uuid::new_v4());
    let err = insert_reservation(
        &client,
        &b,
        a_rows.first_seq as i64,
        &identity,
        &"b".repeat(64),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.code(),
        Some(&tokio_postgres::error::SqlState::FOREIGN_KEY_VIOLATION)
    );
    // The same sequence is legal once tenant B has its OWN canonical row.
    let tx = client.transaction().await.unwrap();
    let b_rows = append(&tx, &b).await;
    tx.commit().await.unwrap();
    insert_reservation(
        &client,
        &b,
        b_rows.first_seq as i64,
        &identity,
        &"b".repeat(64),
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_reservation_binding_round_trip() {
    let (pool, tenant) = fixture().await;
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    let rows = append(&tx, &tenant).await;
    tx.commit().await.unwrap();
    let identity = std::array::from_fn(|_| Uuid::new_v4());
    let hash = "b".repeat(64);
    insert_reservation(&client, &tenant, rows.first_seq as i64, &identity, &hash)
        .await
        .unwrap();
    let row = client.query_one(
        "SELECT execution_id,action_id,idempotency_key,agent_key_id,decision_id,policy_id,policy_version,policy_hash,request_digest,ledger_seq FROM action_executions WHERE tenant_id=$1 AND execution_id=$2",
        &[tenant.as_uuid(), &identity[0]],
    ).await.unwrap();
    for (index, expected) in identity.iter().take(6).enumerate() {
        assert_eq!(row.get::<_, Uuid>(index), *expected);
    }
    assert_eq!(row.get::<_, i32>(6), 7);
    assert_eq!(row.get::<_, String>(7), hash);
    assert_eq!(row.get::<_, String>(8), "a".repeat(64));
    assert_eq!(row.get::<_, i64>(9), rows.first_seq as i64);
}

/// 2026-10-29 SRE review: every in-transaction expiry / revocation comparison reads the
/// DATABASE clock (`db_now`), the clock `revoked_at`, `expires_at` and the consume UPDATE
/// use. Bracketing it between two `clock_timestamp()` reads proves it is the DB's, not the
/// gateway's, independent of any skew between the two hosts.
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_db_now_reads_the_database_clock() {
    let (pool, ..) = super::policy_pg_tests::setup().await;
    let mut db = pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    let before: chrono::DateTime<chrono::Utc> = tx
        .query_one("SELECT clock_timestamp()", &[])
        .await
        .unwrap()
        .get(0);
    let now = db_now(&tx).await.unwrap();
    let after: chrono::DateTime<chrono::Utc> = tx
        .query_one("SELECT clock_timestamp()", &[])
        .await
        .unwrap()
        .get(0);
    assert!(
        before <= now && now <= after,
        "{before} <= {now} <= {after}"
    );
}

//! Synthetic recording identity contracts; real, task-owned Postgres only.
//! These tests exercise existing append APIs, so a red result must be an assertion failure.
use crate::audit::{AuditChain, AuditEventWire};
use serde_json::{Value, json};
use tracelane_shared::TenantId;
use uuid::Uuid;

async fn fixture() -> (deadpool_postgres::Pool, TenantId, AuditChain) {
    let pool = crate::entitlement_cache::b409_fixture::fresh_migrated_pool().await;
    let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
    crate::db::tenants::create(&pool, *tenant.as_uuid(), "synthetic-recording", "free")
        .await
        .unwrap();
    // No Rekor client, no ClickHouse client and no provider calls in identity tests.
    let chain = AuditChain::with_pg_pool(0, None, None, Some(pool.clone())).unwrap();
    (pool, tenant, chain)
}

fn wire(tenant: &TenantId, epoch: Uuid, seq: u64) -> AuditEventWire {
    let event_id = Uuid::new_v4().to_string();
    let payload = json!({
        "gateway_recording": {
            "schema_version": 1,
            "event_id": event_id,
            "record_kind": if seq == 0 { "epoch_start" } else { "intent" },
            "occurred_at": "2026-11-20T00:00:00.000Z",
            "emitter": {
                "instance": "synthetic-replica", "epoch": epoch.to_string(),
                "tenant": tenant.to_string(), "seq": seq.to_string()
            }
        }
    });
    AuditEventWire {
        event_id,
        tenant_id: *tenant.as_uuid(),
        event_type: if seq == 0 {
            "gateway.epoch_start"
        } else {
            "chat.completions.request"
        }
        .into(),
        actor: "synthetic-gateway".into(),
        payload_json: crate::action_control::canonical_json(&payload.to_string()).unwrap(),
    }
}

fn change_payload(wire: &mut AuditEventWire, apply: impl FnOnce(&mut Value)) {
    let mut value: Value = serde_json::from_str(&wire.payload_json).unwrap();
    apply(&mut value);
    // Invalid-input cases must reach the append boundary, not fail in the fixture's
    // stricter action canonicalizer (which rejects floats before our assertion).
    wire.payload_json = value.to_string();
}

async fn count(pool: &deadpool_postgres::Pool, tenant: &TenantId) -> u64 {
    crate::db::ledger::ledger_range(pool, tenant)
        .await
        .unwrap()
        .total
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn ri08_identical_redelivery_is_one_canonical_row() {
    let (pool, tenant, chain) = fixture().await;
    let event = wire(&tenant, Uuid::new_v4(), 0);
    chain
        .append_batch_from_wire(std::slice::from_ref(&event))
        .await
        .unwrap();
    chain
        .append_batch_from_wire(std::slice::from_ref(&event))
        .await
        .unwrap();
    let rows = crate::db::ledger::read_rows_from(&pool, &tenant, 0, 10)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].payload, event.payload_json);
    assert_eq!(rows[0].seq, 0);
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn ri08_same_event_id_with_different_content_is_refused() {
    let (pool, tenant, chain) = fixture().await;
    let event = wire(&tenant, Uuid::new_v4(), 0);
    chain
        .append_batch_from_wire(std::slice::from_ref(&event))
        .await
        .unwrap();
    let mut conflicting = event.clone();
    change_payload(&mut conflicting, |v| {
        v["gateway_recording"]["occurred_at"] = json!("2026-11-20T00:00:01.000Z");
    });
    let result = chain.append_batch_from_wire(&[conflicting]).await;
    assert!(
        result.is_err(),
        "recording event identity must bind its original content"
    );
    assert_eq!(count(&pool, &tenant).await, 1);
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn ri08_same_emitter_sequence_with_another_event_id_is_refused() {
    let (pool, tenant, chain) = fixture().await;
    let epoch = Uuid::new_v4();
    let event = wire(&tenant, epoch, 0);
    chain.append_batch_from_wire(&[event]).await.unwrap();
    let conflicting = wire(&tenant, epoch, 0);
    let result = chain.append_batch_from_wire(&[conflicting]).await;
    assert!(
        result.is_err(),
        "one emitter sequence cannot identify two logical records"
    );
    assert_eq!(count(&pool, &tenant).await, 1);
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn ri08_conflicting_identity_within_batch_rolls_back_every_row() {
    let (pool, tenant, chain) = fixture().await;
    let first = wire(&tenant, Uuid::new_v4(), 0);
    let mut other = first.clone();
    other.actor = "synthetic-different-actor".into();
    let result = chain.append_batch_from_wire(&[first, other]).await;
    assert!(
        result.is_err(),
        "batch conflict must be checked before first-wins dedup"
    );
    assert_eq!(count(&pool, &tenant).await, 0);
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn ri08_independent_tenants_can_each_start_at_zero() {
    let (pool, first, chain) = fixture().await;
    let second = TenantId::from_jwt_claim(Uuid::new_v4());
    crate::db::tenants::create(&pool, *second.as_uuid(), "synthetic-second", "free")
        .await
        .unwrap();
    let epoch = Uuid::new_v4();
    for tenant in [&first, &second] {
        chain
            .append_batch_from_wire(&[wire(tenant, epoch, 0)])
            .await
            .unwrap();
        assert_eq!(count(&pool, tenant).await, 1);
    }
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn ri08_late_unique_sequence_is_not_a_conflicting_replay() {
    let (pool, tenant, chain) = fixture().await;
    let epoch = Uuid::new_v4();
    for seq in [0, 2, 1] {
        chain
            .append_batch_from_wire(&[wire(&tenant, epoch, seq)])
            .await
            .unwrap();
    }
    assert_eq!(count(&pool, &tenant).await, 3);
    let rows = crate::db::ledger::read_rows_from(&pool, &tenant, 0, 10)
        .await
        .unwrap();
    let emitter_order: Vec<String> = rows
        .iter()
        .map(|r| {
            let payload: Value = serde_json::from_str(&r.payload).unwrap();
            payload["gateway_recording"]["emitter"]["seq"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(emitter_order, ["0", "2", "1"]);
    assert_eq!(rows.iter().map(|r| r.seq).collect::<Vec<_>>(), [0, 1, 2]);
}

/// Each named case reaches the existing canonical append entry with an otherwise valid
/// synthetic epoch start. All cases run before the aggregate assertion, so the report
/// distinguishes executed scenarios from the single Rust test function.
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn ri08_recording_metadata_validation_cases() {
    let (pool, tenant, chain) = fixture().await;
    let foreign = Uuid::new_v4().to_string();
    let cases: Vec<(&str, &str, Value)> = vec![
        ("schema null", "/schema_version", Value::Null),
        ("schema zero", "/schema_version", json!(0)),
        ("schema future", "/schema_version", json!(2)),
        ("schema string", "/schema_version", json!("1")),
        ("schema fractional", "/schema_version", json!(1.5)),
        ("event id empty", "/event_id", json!("")),
        ("event id numeric", "/event_id", json!(1)),
        ("event id null", "/event_id", Value::Null),
        (
            "event id disagrees with envelope",
            "/event_id",
            json!("synthetic-other-id"),
        ),
        ("kind unknown", "/record_kind", json!("unknown")),
        ("kind null", "/record_kind", Value::Null),
        ("kind numeric", "/record_kind", json!(0)),
        (
            "intent kind disagrees with epoch event",
            "/record_kind",
            json!("intent"),
        ),
        ("time null", "/occurred_at", Value::Null),
        ("time numeric", "/occurred_at", json!(0)),
        ("time invalid", "/occurred_at", json!("not-a-time")),
        (
            "time without offset",
            "/occurred_at",
            json!("2026-11-20T00:00:00"),
        ),
        ("emitter null", "/emitter", Value::Null),
        ("emitter array", "/emitter", json!([])),
        ("emitter string", "/emitter", json!("synthetic")),
        ("emitter empty object", "/emitter", json!({})),
        ("instance empty", "/emitter/instance", json!("")),
        ("instance null", "/emitter/instance", Value::Null),
        ("instance numeric", "/emitter/instance", json!(4)),
        ("epoch null", "/emitter/epoch", Value::Null),
        ("epoch numeric", "/emitter/epoch", json!(1)),
        (
            "epoch malformed",
            "/emitter/epoch",
            json!("synthetic-not-uuid"),
        ),
        (
            "epoch nil",
            "/emitter/epoch",
            json!(Uuid::nil().to_string()),
        ),
        ("tenant null", "/emitter/tenant", Value::Null),
        ("tenant numeric", "/emitter/tenant", json!(1)),
        (
            "tenant malformed",
            "/emitter/tenant",
            json!("synthetic-not-uuid"),
        ),
        ("tenant foreign", "/emitter/tenant", json!(foreign)),
        ("sequence null", "/emitter/seq", Value::Null),
        ("sequence numeric", "/emitter/seq", json!(0)),
        ("sequence negative", "/emitter/seq", json!("-1")),
        ("sequence empty", "/emitter/seq", json!("")),
        ("sequence padded", "/emitter/seq", json!(" 0")),
        ("sequence leading zero", "/emitter/seq", json!("00")),
        ("sequence explicit plus", "/emitter/seq", json!("+0")),
        ("sequence fractional", "/emitter/seq", json!("0.0")),
        (
            "sequence exceeds bigint",
            "/emitter/seq",
            json!("9223372036854775808"),
        ),
        ("epoch start sequence nonzero", "/emitter/seq", json!("1")),
    ];
    assert_eq!(cases.len(), 42);
    let mut accepted = Vec::new();
    for (name, path, invalid) in cases {
        let mut event = wire(&tenant, Uuid::new_v4(), 0);
        change_payload(&mut event, |value| {
            *value["gateway_recording"].pointer_mut(path).unwrap() = invalid;
        });
        if chain.append_batch_from_wire(&[event]).await.is_ok() {
            accepted.push(name);
        }
    }
    assert!(
        accepted.is_empty(),
        "invalid metadata accepted: {accepted:?}"
    );
    assert_eq!(count(&pool, &tenant).await, 0);
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn ri08_batch_rollback_and_namespace_cases() {
    let (pool, tenant, chain) = fixture().await;
    // Four independently named behaviors complement the 42 validation cases and
    // six top-level identity/order tests: 52 distinct scenarios in eight functions.
    let epoch = Uuid::new_v4();
    let first = wire(&tenant, epoch, 0);
    chain
        .append_batch_from_wire(&[first.clone(), first.clone()])
        .await
        .unwrap();
    assert_eq!(
        count(&pool, &tenant).await,
        1,
        "identical duplicate inside one batch"
    );
    let second_epoch = wire(&tenant, Uuid::new_v4(), 0);
    chain.append_batch_from_wire(&[second_epoch]).await.unwrap();
    assert_eq!(
        count(&pool, &tenant).await,
        2,
        "separate epoch has independent sequence"
    );
    let mut other_instance = wire(&tenant, epoch, 0);
    change_payload(&mut other_instance, |value| {
        value["gateway_recording"]["emitter"]["instance"] = json!("synthetic-replica-two");
    });
    chain
        .append_batch_from_wire(&[other_instance])
        .await
        .unwrap();
    assert_eq!(
        count(&pool, &tenant).await,
        3,
        "separate instance has independent sequence"
    );
    let next = wire(&tenant, epoch, 1);
    let mut duplicate = first;
    duplicate.actor = "synthetic-conflicting-actor".into();
    let result = chain.append_batch_from_wire(&[next, duplicate]).await;
    assert!(
        result.is_err(),
        "conflict after a new row rolls back the entire batch"
    );
    assert_eq!(count(&pool, &tenant).await, 3);
}

async fn append_in_tx(
    tx: &tokio_postgres::Transaction<'_>,
    tenant: &TenantId,
    event: &AuditEventWire,
    change_builder_actor: bool,
) -> anyhow::Result<Option<crate::db::audit_chain_state::AtomicBatchAppend>> {
    let ids = [event.event_id.clone()];
    let recordings = [crate::gateway_recording::Recording::parse(
        tenant,
        Some(&event.event_id),
        &event.event_type,
        &event.actor,
        &event.payload_json,
    )?];
    crate::db::audit_chain_state::append_atomic_batch_tx(
        tx,
        tenant,
        crate::audit_format::genesis_prev_hash(tenant),
        Some(&ids),
        1,
        &recordings,
        |seq, previous, kept| {
            let actor = if change_builder_actor {
                "synthetic-changed"
            } else {
                &event.actor
            };
            Ok(kept
                .iter()
                .map(|_| crate::db::ledger::AuditLogRow {
                    tenant_id: tenant.to_string(),
                    seq,
                    event_time: 0,
                    event_type: event.event_type.clone(),
                    actor: actor.into(),
                    payload: event.payload_json.clone(),
                    prev_hash: hex::encode(previous),
                    row_hash: hex::encode(crate::audit_format::row_hash_v2(
                        &previous,
                        tenant,
                        seq,
                        &event.event_type,
                        actor,
                        &event.payload_json,
                    )),
                    rekor_entry_id: None,
                    signature: String::new(),
                    signing_pubkey: String::new(),
                })
                .collect())
        },
    )
    .await
}

async fn projection(
    pool: &deadpool_postgres::Pool,
    tenant: &TenantId,
    epoch: Uuid,
) -> (i64, i64, i64) {
    let row = pool.get().await.unwrap().query_one(
        "SELECT highest_emitter_seq,last_ledger_seq,recorded_events FROM gateway_emitter_heads WHERE tenant_id=$1 AND boot_epoch=$2 AND instance_id='synthetic-replica'",
        &[tenant.as_uuid(), &epoch],
    ).await.unwrap();
    (row.get(0), row.get(1), row.get(2))
}

fn assert_projection(observed: (i64, i64, i64), emitter: &[i64], ledger: &[i64]) {
    assert_eq!(
        observed.0,
        *emitter.iter().max().unwrap(),
        "observed emitter high-water"
    );
    assert_eq!(
        observed.1,
        *ledger.iter().max().unwrap(),
        "canonical ledger high-water"
    );
    assert_eq!(observed.2, emitter.len() as i64, "recorded unique events");
}

#[test]
fn ri08_recording_fixture_validation() {
    // Sweep authenticated namespaces, independent epochs and canonical sequence
    // boundaries through the actual parser. This is a validation sweep, not a
    // projection/contiguity proof; real-store tests cover transactional state.
    let mutate = std::env::var_os("TRACELANE_TEST_INVALID_RECORDING_RESULT").is_some();
    let foreign = TenantId::from_jwt_claim(Uuid::from_u128(99));
    let mut checked = 0;
    for tenant_number in 1..=3 {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(tenant_number));
        for epoch_number in [10, 11] {
            for seq in [0, 1, 2, i64::MAX as u64] {
                let event = wire(&tenant, Uuid::from_u128(epoch_number), seq);
                let parse = |bound: &TenantId, id: &str, event: &AuditEventWire| {
                    crate::gateway_recording::Recording::parse(
                        bound,
                        Some(id),
                        &event.event_type,
                        &event.actor,
                        &event.payload_json,
                    )
                };
                // Mutation changes only the synthetic caller namespace. Production
                // validation and this positive assertion remain unchanged.
                let expected_tenant = if mutate { &foreign } else { &tenant };
                assert!(
                    parse(expected_tenant, &event.event_id, &event).is_ok_and(|r| r.is_some()),
                    "valid synthetic fixture must pass the real recording validator"
                );
                assert!(
                    parse(&foreign, &event.event_id, &event).is_err(),
                    "foreign authority refused"
                );
                assert!(
                    parse(&tenant, "synthetic-other-id", &event).is_err(),
                    "envelope identity bound"
                );
                let mut nil_epoch = event.clone();
                change_payload(&mut nil_epoch, |value| {
                    value["gateway_recording"]["emitter"]["epoch"] = json!(Uuid::nil().to_string());
                });
                assert!(
                    parse(&tenant, &nil_epoch.event_id, &nil_epoch).is_err(),
                    "nil epoch refused"
                );
                checked += 4;
            }
        }
    }
    assert_eq!(
        checked, 96,
        "24 input combinations, four authority/identity invariants each"
    );
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn ri08_caller_commit_rollback_and_builder_contract() {
    let (pool, tenant, chain) = fixture().await;
    let epoch = Uuid::new_v4();
    let first = wire(&tenant, epoch, 0);
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    append_in_tx(&tx, &tenant, &first, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        count(&pool, &tenant).await,
        0,
        "uncommitted candidate is invisible"
    );
    tx.rollback().await.unwrap();
    let pending: i64 = client
        .query_one(
            "SELECT count(*) FROM gateway_recording_events WHERE tenant_id=$1",
            &[tenant.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        pending, 0,
        "caller rollback removes reserved identity and projection"
    );
    let tx = client.transaction().await.unwrap();
    assert!(append_in_tx(&tx, &tenant, &first, true).await.is_err());
    tx.rollback().await.unwrap();
    assert_eq!(
        count(&pool, &tenant).await,
        0,
        "builder mismatch cannot escape rollback"
    );
    let tx = client.transaction().await.unwrap();
    append_in_tx(&tx, &tenant, &first, false)
        .await
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();
    // Async consumer sees the same binding as the direct caller transaction.
    chain.append_batch_from_wire(&[first]).await.unwrap();
    assert_projection(projection(&pool, &tenant, epoch).await, &[0], &[0]);
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn ri08_mixed_history_and_late_rows_preserve_observed_highwater() {
    let (pool, tenant, chain) = fixture().await;
    let epoch = Uuid::new_v4();
    let mut legacy = wire(&tenant, epoch, 0);
    legacy.payload_json = "{\"legacy\":true}".into();
    legacy.event_type = "chat.completions.request".into();
    chain
        .append_batch_from_wire(&[wire(&tenant, epoch, 0), legacy.clone()])
        .await
        .unwrap();
    for seq in [2, 1] {
        let event = wire(&tenant, epoch, seq);
        chain
            .append_batch_from_wire(&[event.clone(), event])
            .await
            .unwrap();
    }
    assert_projection(
        projection(&pool, &tenant, epoch).await,
        &[0, 2, 1],
        &[0, 2, 3],
    );
    assert_eq!(count(&pool, &tenant).await, 4);
    let rows = crate::db::ledger::read_rows_from(&pool, &tenant, 0, 10)
        .await
        .unwrap();
    assert_eq!(
        rows[1].payload, legacy.payload_json,
        "historical bytes untouched"
    );
    let foreign = TenantId::from_jwt_claim(Uuid::new_v4());
    let n: i64 = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT count(*) FROM gateway_emitter_heads WHERE tenant_id=$1",
            &[foreign.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(n, 0, "namespace lookup returns no foreign projection");
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn ri08_legacy_and_recording_identity_collisions_are_refused() {
    let (pool, tenant, chain) = fixture().await;
    let recorded = wire(&tenant, Uuid::new_v4(), 0);
    chain
        .append_batch_from_wire(std::slice::from_ref(&recorded))
        .await
        .unwrap();
    let mut legacy = recorded.clone();
    legacy.payload_json = "{\"legacy\":true}".into();
    assert!(chain.append_batch_from_wire(&[legacy]).await.is_err());
    let prospective = wire(&tenant, Uuid::new_v4(), 0);
    let mut old = prospective.clone();
    old.payload_json = "{\"legacy\":true}".into();
    chain.append_batch_from_wire(&[old]).await.unwrap();
    assert!(chain.append_batch_from_wire(&[prospective]).await.is_err());
    assert_eq!(count(&pool, &tenant).await, 2);
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn ri08_concurrent_exact_duplicates_commit_once() {
    let (pool, tenant, chain) = fixture().await;
    let epoch = Uuid::new_v4();
    let event = [wire(&tenant, epoch, 0)];
    let (a, b) = tokio::join!(
        chain.append_batch_from_wire(&event),
        chain.append_batch_from_wire(&event)
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(count(&pool, &tenant).await, 1);
    assert_projection(projection(&pool, &tenant, epoch).await, &[0], &[0]);
}

#[tokio::test]
#[ignore = "requires isolated Postgres and ClickHouse"]
async fn ri08_ch_canonical_and_clickhouse_copy_roundtrip() {
    let (pool, tenant, _) = fixture().await;
    let url = std::env::var("CLICKHOUSE_TEST_URL").expect("task-owned ClickHouse URL required");
    let ch = crate::clickhouse_query::ch_client(&url);
    ch.query("CREATE TABLE IF NOT EXISTS audit_log (tenant_id String, seq UInt64, event_time DateTime64(6,'UTC'), event_type String, actor String, payload String, prev_hash String, row_hash String, rekor_entry_id Nullable(String), signature String, signing_pubkey String) ENGINE=ReplacingMergeTree ORDER BY (tenant_id,seq)")
        .execute().await.unwrap();
    let chain = AuditChain::with_pg_pool(0, None, Some(&url), Some(pool.clone())).unwrap();
    let epoch = Uuid::new_v4();
    let events = [
        wire(&tenant, epoch, 0),
        wire(&tenant, epoch, 2),
        wire(&tenant, epoch, 1),
    ];
    chain.append_batch_from_wire(&events).await.unwrap();
    let canonical = crate::db::ledger::read_rows_from(&pool, &tenant, 0, 10)
        .await
        .unwrap();
    let copies = ch.query("SELECT tenant_id,seq,event_time,event_type,actor,payload,prev_hash,row_hash,rekor_entry_id,signature,signing_pubkey FROM audit_log FINAL WHERE tenant_id=? ORDER BY seq LIMIT 10")
        .bind(tenant.to_string()).fetch_all::<crate::db::ledger::AuditLogRow>().await.unwrap();
    assert_eq!(
        copies.len(),
        3,
        "actual derived rows exist after canonical commit"
    );
    for (a, b) in canonical.iter().zip(&copies) {
        assert_eq!(
            serde_json::to_value(a).unwrap(),
            serde_json::to_value(b).unwrap()
        );
    }
    assert_projection(
        projection(&pool, &tenant, epoch).await,
        &[0, 2, 1],
        &[0, 1, 2],
    );
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn ri08_restore_refuses_recording_batch_before_any_adoption() {
    let (source, tenant, chain) = fixture().await;
    let recorded = wire(&tenant, Uuid::new_v4(), 0);
    let mut legacy = recorded.clone();
    legacy.event_id = Uuid::new_v4().to_string();
    legacy.payload_json = "{\"legacy\":true}".into();
    legacy.event_type = "chat.completions.request".into();
    chain
        .append_batch_from_wire(&[legacy, recorded])
        .await
        .unwrap();
    let rows = crate::db::ledger::read_rows_from(&source, &tenant, 0, 10)
        .await
        .unwrap();
    let destination = crate::entitlement_cache::b409_fixture::fresh_migrated_pool().await;
    crate::db::tenants::create(&destination, *tenant.as_uuid(), "synthetic-restore", "free")
        .await
        .unwrap();
    assert!(
        crate::db::ledger::insert_rows(&destination, &rows)
            .await
            .is_err(),
        "recording recovery must refuse until identity and projection restoration is implemented"
    );
    assert_eq!(
        count(&destination, &tenant).await,
        0,
        "mixed restore must not partially adopt legacy rows"
    );
    crate::db::ledger::insert_rows(&destination, &rows[..1])
        .await
        .unwrap();
    assert_eq!(
        count(&destination, &tenant).await,
        1,
        "legacy recovery remains supported"
    );
    crate::db::ledger::insert_rows(&destination, &rows[..1])
        .await
        .unwrap();
    assert_eq!(
        count(&destination, &tenant).await,
        1,
        "legacy restore retry is idempotent"
    );
    let restored = crate::db::ledger::read_rows_from(&destination, &tenant, 0, 10)
        .await
        .unwrap();
    assert_eq!(
        restored[0].payload, rows[0].payload,
        "historical payload bytes preserved"
    );
    for reserved in [Value::Null, json!({"event_id":"synthetic-changed"})] {
        let mut unsupported = rows[1].clone();
        unsupported.payload = json!({"gateway_recording": reserved}).to_string();
        assert!(
            crate::db::ledger::insert_rows(&destination, &[unsupported])
                .await
                .is_err(),
            "malformed or changed reserved metadata cannot enter through recovery"
        );
    }
    assert_eq!(
        count(&destination, &tenant).await,
        1,
        "refusals leave legacy history unchanged"
    );
}

// ── Review of #394 (Medium): a message that can never append must not stall its tenant ──

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn ri08_conflicting_message_is_terminated_and_its_batch_mates_land() {
    let (pool, tenant, chain) = fixture().await;
    let epoch = Uuid::new_v4();
    chain
        .append_batch_from_wire(&[wire(&tenant, epoch, 0)])
        .await
        .unwrap();
    // A valid event from another emitter, co-batched with one that reuses (epoch, 0).
    let valid = wire(&tenant, Uuid::new_v4(), 0);
    let conflicting = wire(&tenant, epoch, 0);
    let outcomes = crate::audit_consumer::settle(&chain, 0, &[valid, conflicting]).await;
    use crate::audit_consumer::Outcome;
    assert_eq!(outcomes, vec![Outcome::Ack, Outcome::Term]);
    assert_eq!(
        count(&pool, &tenant).await,
        2,
        "the valid batch-mate landed"
    );
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn ri08_malformed_member_is_terminated_alone() {
    let (pool, tenant, chain) = fixture().await;
    let valid = wire(&tenant, Uuid::new_v4(), 0);
    let mut malformed = wire(&tenant, Uuid::new_v4(), 0);
    change_payload(&mut malformed, |v| {
        v["gateway_recording"]["emitter"]["seq"] = json!("007");
    });
    use crate::audit_consumer::Outcome;
    let outcomes = crate::audit_consumer::settle(&chain, 0, &[malformed, valid]).await;
    assert_eq!(outcomes, vec![Outcome::Term, Outcome::Ack]);
    assert_eq!(count(&pool, &tenant).await, 1);
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn ri08_valid_group_is_acked_whole() {
    let (pool, tenant, chain) = fixture().await;
    let epoch = Uuid::new_v4();
    use crate::audit_consumer::Outcome;
    let outcomes = crate::audit_consumer::settle(
        &chain,
        0,
        &[wire(&tenant, epoch, 0), wire(&tenant, epoch, 1)],
    )
    .await;
    assert_eq!(outcomes, vec![Outcome::Ack, Outcome::Ack]);
    assert_eq!(count(&pool, &tenant).await, 2);
}

#[test]
fn ri08_legacy_payload_without_the_member_is_never_parsed() {
    let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
    // Not JSON at all, and deeper than serde_json's recursion limit: both pre-date RI-08.
    let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
    // A control character makes serde emit `\u0001`, which forces the full parse; the parse
    // then fails on depth, and the legacy event must still not be refused.
    let deep_escaped = format!(
        "{}\"text\\u0001 gateway_recording\"{}",
        "[".repeat(200),
        "]".repeat(200)
    );
    for payload in ["not json", deep.as_str(), deep_escaped.as_str()] {
        let parsed =
            crate::gateway_recording::Recording::parse(&tenant, None, "chat.request", "a", payload);
        assert!(matches!(parsed, Ok(None)), "{payload:.20}: {parsed:?}");
    }
}

#[test]
fn ri08_escaped_reserved_key_is_still_validated() {
    let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
    // `\u0067` is `g`: this key decodes to the reserved member, so it must not pass as legacy.
    let payload = r#"{"\u0067ateway_recording":{"schema_version":1}}"#;
    let parsed =
        crate::gateway_recording::Recording::parse(&tenant, None, "chat.request", "a", payload);
    let err = parsed.expect_err("an escaped reserved key is the reserved member");
    assert!(crate::gateway_recording::is_permanent(&err));
}

#[test]
fn ri08_newer_recording_version_redelivers_instead_of_terminating() {
    // Version skew during a deploy: the event is valid for a newer consumer.
    let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
    let mut w = wire(&tenant, Uuid::new_v4(), 0);
    change_payload(&mut w, |v| {
        v["gateway_recording"]["schema_version"] = json!(2);
    });
    let err = crate::gateway_recording::Recording::parse(
        &tenant,
        Some(&w.event_id),
        &w.event_type,
        &w.actor,
        &w.payload_json,
    )
    .expect_err("an unknown version is refused by this build");
    assert!(!crate::gateway_recording::is_permanent(&err));
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn ri08_same_event_id_with_different_content_is_terminated_alone() {
    let (pool, tenant, chain) = fixture().await;
    let event = wire(&tenant, Uuid::new_v4(), 0);
    chain
        .append_batch_from_wire(std::slice::from_ref(&event))
        .await
        .unwrap();
    let mut conflicting = event.clone();
    change_payload(&mut conflicting, |v| {
        v["gateway_recording"]["occurred_at"] = json!("2026-11-20T00:00:01.000Z");
    });
    let valid = wire(&tenant, Uuid::new_v4(), 0);
    use crate::audit_consumer::Outcome;
    let outcomes = crate::audit_consumer::settle(&chain, 0, &[conflicting, valid]).await;
    assert_eq!(outcomes, vec![Outcome::Term, Outcome::Ack]);
    assert_eq!(count(&pool, &tenant).await, 2);
}

#[test]
fn ri08_only_typed_refusals_are_permanent() {
    let outage = anyhow::anyhow!("connection reset").context("append");
    assert!(!crate::gateway_recording::is_permanent(&outage));
    let refused: anyhow::Error =
        crate::gateway_recording::PermanentRejection("recording identity conflict").into();
    assert!(crate::gateway_recording::is_permanent(
        &refused.context("append batch")
    ));
}

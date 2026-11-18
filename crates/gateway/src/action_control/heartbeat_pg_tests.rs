//! AUD-32 slice A against isolated Postgres: heartbeats re-sign an unchanged head on cadence.
use super::*;
use crate::action_control::heartbeat::{beat, tick};
use std::sync::Arc;
use std::time::Duration;

const HOUR: Duration = Duration::from_secs(3600);

fn store(f: &Fixture, byte: u8) -> Arc<crate::audit_keys::TenantAuditKeyStore> {
    use base64::Engine;
    let master = crate::byok::ByokMasterKey::from_values(
        Some(&base64::engine::general_purpose::STANDARD.encode([byte; 32])),
        None,
        None,
    )
    .unwrap()
    .unwrap();
    Arc::new(crate::audit_keys::TenantAuditKeyStore::new(
        f.pool.clone(),
        Arc::new(master),
        None,
    ))
}
async fn checkpoints(f: &Fixture, tenant: &TenantId) -> Vec<Value> {
    f.pool
        .get()
        .await
        .unwrap()
        .query(
            "SELECT statement FROM audit_head_checkpoints WHERE tenant_id=$1 ORDER BY checkpoint_order",
            &[tenant.as_uuid()],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| serde_json::from_str(r.get::<_, &str>(0)).unwrap())
        .collect()
}
async fn statements(f: &Fixture, tenant: &TenantId) -> Vec<String> {
    f.pool
        .get()
        .await
        .unwrap()
        .query(
            "SELECT statement FROM audit_head_checkpoints WHERE tenant_id=$1 ORDER BY checkpoint_order",
            &[tenant.as_uuid()],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect()
}
fn me(f: &Fixture) -> &TenantId {
    &f.agent.tenant_id
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn heartbeat_mints_when_stale() {
    let f = Fixture::new().await;
    let keys = store(&f, 7);
    assert!(beat(&f.pool, &keys, me(&f), Duration::ZERO).await.unwrap());
    assert!(beat(&f.pool, &keys, me(&f), Duration::ZERO).await.unwrap());
    let cps = checkpoints(&f, me(&f)).await;
    assert_eq!(cps.len(), 2);
    assert_eq!(cps[0]["seq"], cps[1]["seq"]);
    assert_eq!(cps[0]["head_hash"], cps[1]["head_hash"]);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn heartbeat_reuses_fresh() {
    let f = Fixture::new().await;
    let keys = store(&f, 7);
    assert!(beat(&f.pool, &keys, me(&f), HOUR).await.unwrap());
    assert!(!beat(&f.pool, &keys, me(&f), HOUR).await.unwrap());
    assert_eq!(checkpoints(&f, me(&f)).await.len(), 1);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn second_tick_inside_period_noop() {
    let f = Fixture::new().await;
    let keys = store(&f, 7);
    let all = |_| async { true };
    assert_eq!(tick(&f.pool, &keys, HOUR, all).await.unwrap(), 1);
    assert_eq!(tick(&f.pool, &keys, HOUR, all).await.unwrap(), 0);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn new_head_inside_floor_skips() {
    let f = Fixture::new().await;
    let keys = store(&f, 7);
    assert!(beat(&f.pool, &keys, me(&f), HOUR).await.unwrap());
    f.pending().await; // the head moves
    // Under the 60 s export floor: skipped, never an error (no degradation).
    assert!(!beat(&f.pool, &keys, me(&f), HOUR).await.unwrap());
    assert_eq!(checkpoints(&f, me(&f)).await.len(), 1);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn heartbeat_links_previous() {
    let f = Fixture::new().await;
    let keys = store(&f, 7);
    beat(&f.pool, &keys, me(&f), Duration::ZERO).await.unwrap();
    beat(&f.pool, &keys, me(&f), Duration::ZERO).await.unwrap();
    let raw = statements(&f, me(&f)).await;
    let second: Value = serde_json::from_str(&raw[1]).unwrap();
    assert_eq!(second["previous_checkpoint_digest"], sha(raw[0].as_bytes()));
    let first: Value = serde_json::from_str(&raw[0]).unwrap();
    assert!(second["created_at"].as_str() >= first["created_at"].as_str());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn tick_covers_enabled_tenants() {
    let f = Fixture::new().await;
    let other = f.other().await;
    let keys = store(&f, 7);
    let all = |_| async { true };
    assert_eq!(tick(&f.pool, &keys, HOUR, all).await.unwrap(), 2);
    assert_eq!(checkpoints(&f, me(&f)).await.len(), 1);
    assert_eq!(checkpoints(&f, &other.agent.tenant_id).await.len(), 1);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn disabled_tenant_skipped() {
    let f = Fixture::new().await;
    let other = f.other().await;
    let keys = store(&f, 7);
    let only = *me(&f).as_uuid();
    let enabled = move |t: Uuid| async move { t == only };
    assert_eq!(tick(&f.pool, &keys, HOUR, enabled).await.unwrap(), 1);
    assert!(checkpoints(&f, &other.agent.tenant_id).await.is_empty());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn no_cross_tenant_link() {
    let f = Fixture::new().await;
    let other = f.other().await;
    let keys = store(&f, 7);
    beat(&f.pool, &keys, me(&f), Duration::ZERO).await.unwrap();
    beat(&f.pool, &keys, &other.agent.tenant_id, Duration::ZERO)
        .await
        .unwrap();
    let theirs = checkpoints(&f, &other.agent.tenant_id).await;
    assert_eq!(theirs.len(), 1);
    assert!(theirs[0]["previous_checkpoint_digest"].is_null());
    assert_eq!(theirs[0]["tenant_id"], other.agent.tenant_id.to_string());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn locked_tenant_skipped() {
    let f = Fixture::new().await;
    let keys = store(&f, 7);
    let mut held = f.pool.get().await.unwrap();
    let tx = held.transaction().await.unwrap();
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1::text || ':action_bundle', 0))",
        &[&me(&f).to_string()],
    )
    .await
    .unwrap();
    assert!(!beat(&f.pool, &keys, me(&f), Duration::ZERO).await.unwrap());
    tx.rollback().await.unwrap();
    assert!(checkpoints(&f, me(&f)).await.is_empty());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn head_conflict_refused() {
    let f = Fixture::new().await;
    let keys = store(&f, 7);
    beat(&f.pool, &keys, me(&f), HOUR).await.unwrap();
    // Corrupt the stored head hash: same seq, different hash = a conflicting head.
    let raw = statements(&f, me(&f)).await.remove(0);
    let mut forged: Value = serde_json::from_str(&raw).unwrap();
    forged["head_hash"] = json!("00".repeat(32));
    f.pool
        .get()
        .await
        .unwrap()
        .execute(
            "UPDATE audit_head_checkpoints SET statement=$2 WHERE tenant_id=$1",
            &[me(&f).as_uuid(), &canonical(&forged).unwrap()],
        )
        .await
        .unwrap();
    let error = beat(&f.pool, &keys, me(&f), Duration::ZERO)
        .await
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref(),
        Some(crate::audit_export::action::ExportError::InvalidEvidence { code: 4, .. })
    ));
    assert_eq!(checkpoints(&f, me(&f)).await.len(), 1);
}
/// Review M1: a real hourly period re-signs at 90% age (54 min), not only at 60 min.
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn heartbeat_real_period_uses_slack() {
    let f = Fixture::new().await;
    let keys = store(&f, 7);
    let due = crate::action_control::heartbeat::due_after(HOUR);
    assert!(beat(&f.pool, &keys, me(&f), due).await.unwrap());
    let backdate = |minutes: i64| {
        let pool = f.pool.clone();
        let tenant = *me(&f).as_uuid();
        async move {
            let db = pool.get().await.unwrap();
            let row = db
                .query_one(
                    "SELECT checkpoint_id,statement FROM audit_head_checkpoints WHERE tenant_id=$1 ORDER BY checkpoint_order DESC LIMIT 1",
                    &[&tenant],
                )
                .await
                .unwrap();
            let mut v: Value = serde_json::from_str(row.get::<_, &str>(1)).unwrap();
            v["created_at"] = json!(
                (Utc::now() - chrono::Duration::minutes(minutes))
                    .to_rfc3339_opts(SecondsFormat::Millis, true)
            );
            db.execute(
                "UPDATE audit_head_checkpoints SET statement=$3 WHERE tenant_id=$1 AND checkpoint_id=$2",
                &[&tenant, &row.get::<_, Uuid>(0), &canonical(&v).unwrap()],
            )
            .await
            .unwrap();
        }
    };
    backdate(50).await; // inside 54 min: reused
    assert!(!beat(&f.pool, &keys, me(&f), due).await.unwrap());
    backdate(55).await; // past 54 min, before 60: re-signed
    assert!(beat(&f.pool, &keys, me(&f), due).await.unwrap());
    assert_eq!(checkpoints(&f, me(&f)).await.len(), 2);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn key_failure_counts_and_continues() {
    let f = Fixture::new().await;
    let other = f.other().await;
    store(&f, 7).get_or_create(me(&f)).await.unwrap(); // key sealed under master A
    let wrong = store(&f, 9); // master B cannot open it
    let before = tracelane_shared::degradation::snapshot()
        .into_iter()
        .find(|s| s.kind == "action_heartbeat_failed")
        .map_or(0, |s| s.count);
    let all = |_| async { true };
    // `me` fails (wrong master), `other` still gets its heartbeat.
    assert_eq!(tick(&f.pool, &wrong, HOUR, all).await.unwrap(), 1);
    assert_eq!(checkpoints(&f, &other.agent.tenant_id).await.len(), 1);
    assert!(checkpoints(&f, me(&f)).await.is_empty());
    let after = tracelane_shared::degradation::snapshot()
        .into_iter()
        .find(|s| s.kind == "action_heartbeat_failed")
        .map_or(0, |s| s.count);
    assert!(after > before);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn no_ledger_no_heartbeat() {
    let f = Fixture::new().await;
    let keys = store(&f, 7);
    let stranger = TenantId::from_jwt_claim(Uuid::new_v4());
    crate::db::tenants::create(&f.pool, *stranger.as_uuid(), "no-ledger", "free")
        .await
        .unwrap();
    let all = |_| async { true };
    tick(&f.pool, &keys, HOUR, all).await.unwrap();
    assert!(checkpoints(&f, &stranger).await.is_empty());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn export_reuse_unchanged() {
    let f = Fixture::new().await;
    let keys = store(&f, 7);
    let key = keys.get_or_create(me(&f)).await.unwrap();
    let mut db = f.pool.get().await.unwrap();
    for _ in 0..2 {
        let tx = db
            .build_transaction()
            .isolation_level(CHECKPOINT_ISOLATION)
            .start()
            .await
            .unwrap();
        let head = checkpoint_head_tx(&tx, me(&f)).await.unwrap();
        checkpoint_for_head_tx(&tx, me(&f), head, &key, None)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    assert_eq!(checkpoints(&f, me(&f)).await.len(), 1);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn export_after_heartbeat_verifies() {
    let f = Fixture::new().await;
    let keys = store(&f, 7);
    beat(&f.pool, &keys, me(&f), Duration::ZERO).await.unwrap();
    beat(&f.pool, &keys, me(&f), Duration::ZERO).await.unwrap();
    let (zip, pin) = super::export_pg_tests::exported(&f).await;
    let report = tracelane_audit_verifier::action::bundle::verify(&zip, Some(pin)).unwrap();
    assert!(report.chain && report.head);
    // Slice B: every stored checkpoint ships in the signed chain, ending at the export head.
    let chain = report
        .checkpoint_chain
        .expect("bundle carries checkpoints.ndjson");
    assert_eq!(
        chain.checkpoints,
        u64::try_from(statements(&f, me(&f)).await.len()).unwrap()
    );
    assert!(chain.checkpoints >= 2, "heartbeats are in the chain");
    assert!(chain.gaps.is_empty());
    // A zero maximum turns every positive interval into a reported gap.
    let strict = tracelane_audit_verifier::action::bundle::verify_with_options(
        &zip,
        Some(pin),
        &[],
        Some(std::time::Duration::ZERO),
    )
    .unwrap();
    let strict = strict.checkpoint_chain.unwrap();
    assert_eq!(
        strict.gaps.len(),
        usize::try_from(chain.checkpoints).unwrap()
            - 1
            - zero_intervals(&statements(&f, me(&f)).await)
    );
}
fn zero_intervals(statements: &[String]) -> usize {
    let times: Vec<chrono::DateTime<chrono::Utc>> = statements
        .iter()
        .map(|s| {
            serde_json::from_str::<Value>(s).unwrap()["created_at"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap()
        })
        .collect();
    times.windows(2).filter(|w| w[1] == w[0]).count()
}

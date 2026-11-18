//! Real Postgres acquisition/export proof. Python cryptography signs only synthetic fixtures.
use super::*;
use crate::audit_export::{AuditExportReader, PgExportReader};
use base64::Engine;
use std::sync::Arc;
use tracelane_audit_verifier::action::{archive, bundle};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
#[tokio::test]
#[ignore = "requires isolated Postgres and Python cryptography; build tracelane-audit first"]
async fn timestamp_pg_export_roundtrip() {
    let _bypass = crate::handler_harness::LoopbackBypassGuard::new();
    let pool = crate::entitlement_cache::b409_fixture::fresh_migrated_pool().await;
    let tenant = tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::new_v4());
    crate::db::tenants::create(&pool, *tenant.as_uuid(), "synthetic-timestamp", "free")
        .await
        .unwrap();
    let master = crate::byok::ByokMasterKey::from_values(
        Some(&base64::engine::general_purpose::STANDARD.encode([7; 32])),
        None,
        None,
    )
    .unwrap()
    .unwrap();
    let keys = Arc::new(crate::audit_keys::TenantAuditKeyStore::new(
        pool.clone(),
        Arc::new(master),
        None,
    ));
    let pin: [u8; 32] = keys
        .get_or_create(&tenant)
        .await
        .unwrap()
        .public_key_bytes()
        .try_into()
        .unwrap();
    let other = tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::new_v4());
    crate::db::tenants::create(&pool, *other.as_uuid(), "synthetic-other-tsa", "free")
        .await
        .unwrap();
    let other_pin: [u8; 32] = keys
        .get_or_create(&other)
        .await
        .unwrap()
        .public_key_bytes()
        .try_into()
        .unwrap();
    let reader = PgExportReader::new(pool.clone()).with_action_keys(Some(keys));
    let mut grants = crate::entitlement_cache::ResolvedEntitlements::deny_all();
    grants.action_control = true;
    let initial = reader.action_bundle(&tenant, &grants).await.unwrap();
    assert!(!bundle::verify(&initial, Some(pin)).unwrap().timestamped);
    let other_initial = reader.action_bundle(&other, &grants).await.unwrap();
    assert!(
        !bundle::verify(&other_initial, Some(other_pin))
            .unwrap()
            .timestamped
    );
    // Same checkpoint selector in two tenants: UPDATE must bind tenant_id as well.
    let selector = uuid::Uuid::new_v4();
    for id in [&tenant, &other] {
        pool.get()
            .await
            .unwrap()
            .execute(
                "UPDATE audit_head_checkpoints SET checkpoint_id=$2 WHERE tenant_id=$1",
                &[id.as_uuid(), &selector],
            )
            .await
            .unwrap();
    }
    let files = archive::unpack(&initial).unwrap();
    let dir = LocalDir(root_temp());
    std::fs::create_dir_all(dir.path()).unwrap();
    let checkpoint = dir.path().join("input.json");
    std::fs::write(&checkpoint, &files["checkpoint.json"]).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let result = std::process::Command::new("python3")
        .arg(root.join("packages/verifier-rust/tests/fixtures/timestamp/generate.py"))
        .arg("--output")
        .arg(dir.path())
        .arg("--checkpoint")
        .arg(checkpoint)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "synthetic fixture generation: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let cert = std::fs::read(dir.path().join("good.der")).unwrap();
    let token = std::fs::read(dir.path().join("good.tsr")).unwrap();
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(token.clone())
                .insert_header("content-type", "application/timestamp-reply"),
        )
        .expect(2)
        .mount(&mock)
        .await;
    let cfg = Config {
        url: mock.uri(),
        timeout: Duration::from_secs(2),
        poll: Duration::from_secs(301),
        batch: 2,
        max_bytes: 65536,
        pins: vec![cert.clone()],
    };
    let before = degradation::count(Degradation::CheckpointTimestampFailed);
    poll_once(&pool, &cfg).await.unwrap();
    assert!(degradation::count(Degradation::CheckpointTimestampFailed) > before);
    let other_token:Option<Vec<u8>>=pool.get().await.unwrap().query_one("SELECT timestamp_response FROM audit_head_checkpoints WHERE tenant_id=$1 AND checkpoint_id=$2",&[other.as_uuid(),&selector]).await.unwrap().get(0);
    assert!(
        other_token.is_none(),
        "wrong-imprint token must not cross tenants"
    );
    let stored: Vec<u8> = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT timestamp_response FROM audit_head_checkpoints WHERE tenant_id=$1",
            &[tenant.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(stored, token);
    // The export reader's trusted pins are supplied explicitly, like the CLI's pins.
    let reader = reader.with_tsa_certs(vec![cert.clone()]);
    let later = chrono::Utc::now() + chrono::Duration::seconds(120);
    let zip = crate::audit_export::action::BUILD_NOW
        .scope(later, reader.action_bundle(&tenant, &grants))
        .await
        .unwrap();
    let other_zip = crate::audit_export::action::BUILD_NOW
        .scope(later, reader.action_bundle(&other, &grants))
        .await
        .unwrap();
    assert!(
        !bundle::verify(&other_zip, Some(other_pin))
            .unwrap()
            .timestamped,
        "TSA failure must leave ordinary export available"
    );
    let rotated_reader = reader.with_tsa_certs(vec![
        include_bytes!("../../../../packages/verifier-rust/tests/fixtures/timestamp/wrong-eku.der")
            .to_vec(),
    ]);
    // A second build for the same tenant needs its own slot past the per-tenant build floor.
    let rotated_zip = crate::audit_export::action::BUILD_NOW
        .scope(
            later + chrono::Duration::seconds(120),
            rotated_reader.action_bundle(&tenant, &grants),
        )
        .await
        .unwrap();
    assert_eq!(
        archive::unpack(&rotated_zip).unwrap()["checkpoint.tsr"],
        token
    );
    let unpinned = bundle::verify(&rotated_zip, Some(pin)).unwrap();
    assert!(!unpinned.timestamped);
    assert_eq!(
        serde_json::to_value(unpinned).unwrap()["timestamp_reason"],
        "tsa_unpinned"
    );
    let report = bundle::verify_with_tsa(&zip, Some(pin), &[cert]).unwrap();
    assert!(report.timestamped);
    assert_eq!(archive::unpack(&zip).unwrap()["checkpoint.tsr"], token);
    let archive = dir.path().join("evidence.zip");
    std::fs::write(&archive, zip).unwrap();
    let pubkey = dir.path().join("tenant.pub");
    std::fs::write(&pubkey, hex::encode(pin)).unwrap();
    let exe = std::env::current_exe().unwrap();
    let output = std::process::Command::new(
        exe.parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tracelane-audit"),
    )
    .args(["verify", "--offline", "--file"])
    .arg(archive)
    .arg("--pubkey")
    .arg(pubkey)
    .arg("--tsa-cert")
    .arg(dir.path().join("good.der"))
    .output()
    .unwrap();
    assert!(
        output.status.success(),
        "CLI: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("timestamped: true"));
}

struct LocalDir(std::path::PathBuf);
impl LocalDir {
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for LocalDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn root_temp() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("aud12-{}", uuid::Uuid::new_v4()))
}

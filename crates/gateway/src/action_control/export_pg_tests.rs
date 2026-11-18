//! Producer acceptance uses real request/approve/execute and isolated Postgres.
use super::*;
use crate::audit_export::{AuditExportReader, PgExportReader};
use tracelane_audit_verifier::action::{
    archive::{Files, pack, unpack},
    bundle,
};

async fn keys(f: &Fixture) -> Arc<crate::audit_keys::TenantAuditKeyStore> {
    use base64::Engine;
    let master = crate::byok::ByokMasterKey::from_values(
        Some(&base64::engine::general_purpose::STANDARD.encode([7; 32])),
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
use std::sync::Arc;
async fn completed() -> Fixture {
    let f = Fixture::new().await;
    let id = f.pending().await;
    assert_eq!(f.decide(&f.human, id, true).await, None);
    f.run(Uuid::new_v4(), id).await.unwrap();
    f
}
pub(in crate::action_control) async fn exported(f: &Fixture) -> (Vec<u8>, [u8; 32]) {
    let (zip, pin) = export_attempt(f).await;
    (zip.unwrap(), pin)
}
async fn export_attempt(f: &Fixture) -> (Result<Vec<u8>>, [u8; 32]) {
    let keys = keys(f).await;
    let pin = keys
        .get_or_create(&f.agent.tenant_id)
        .await
        .unwrap()
        .public_key_bytes()
        .try_into()
        .unwrap();
    static CLOCK: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(120);
    let now = Utc::now()
        + chrono::Duration::seconds(CLOCK.fetch_add(120, std::sync::atomic::Ordering::Relaxed));
    let reader = PgExportReader::new(f.pool.clone()).with_action_keys(Some(keys));
    let zip = crate::audit_export::action::BUILD_NOW
        .scope(now, reader.action_bundle(&f.agent.tenant_id, &grants()))
        .await;
    (zip, pin)
}
fn members(zip: &[u8]) -> Files {
    let mut files = unpack(zip).unwrap();
    files.remove("manifest.json");
    files
}
fn rows(files: &Files) -> Vec<Value> {
    std::str::from_utf8(&files["ledger.ndjson"])
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect()
}
fn replace_rows(files: &mut Files, rows: &[Value]) {
    files.insert(
        "ledger.ndjson".into(),
        rows.iter()
            .map(|v| format!("{v}\n"))
            .collect::<String>()
            .into_bytes(),
    );
}
// Build `cargo build -p tracelane-audit` in the same target before the PG runner.
fn cli(zip: &[u8], pin: Option<[u8; 32]>, expected: i32, name: &str) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let local = root.join("target/c1-5b/cli-fixtures");
    std::fs::create_dir_all(&local).unwrap();
    struct LocalDir(std::path::PathBuf);
    impl Drop for LocalDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let dir = LocalDir(local.join(Uuid::new_v4().to_string()));
    std::fs::create_dir(&dir.0).unwrap();
    let archive = dir.0.join("evidence.zip");
    let key = dir.0.join("external-pin.txt");
    std::fs::write(&archive, zip).unwrap();
    let exe = std::env::current_exe().unwrap();
    let binary = exe
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tracelane-audit");
    let mut cmd = std::process::Command::new(binary);
    cmd.arg("verify")
        .arg("--offline")
        .arg("--file")
        .arg(&archive);
    if let Some(pin) = pin {
        std::fs::write(&key, hex::encode(pin)).unwrap();
        cmd.arg("--pubkey").arg(&key);
    }
    let out = cmd
        .output()
        .expect("build CLI in the same CARGO_TARGET_DIR before isolated PG tests");
    let log = format!(
        "exit: {:?}\n{}\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.status.code(), Some(expected), "{name}: {log}");
    std::fs::write(
        root.join(format!(
            "docs/internal/codex-missions/2026-10-22-c1-5b.proofs/green-{name}.log"
        )),
        log,
    )
    .unwrap();
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_export_roundtrip() {
    let f = completed().await;
    let (zip, pin) = exported(&f).await;
    let r = bundle::verify(&zip, Some(pin)).unwrap();
    cli(&zip, Some(pin), 0, "roundtrip");
    assert!(r.chain && r.head && r.rows > 5 && r.actions.unknown.is_empty());
    let files = members(&zip);
    for table in ["action_policies", "action_tool_contracts"] {
        // Fixed test-only table names, never request input.
        let stored: String = f
            .pool
            .get()
            .await
            .unwrap()
            .query_one(
                &format!("SELECT body_jcs FROM {table} WHERE tenant_id=$1"),
                &[f.agent.tenant_id.as_uuid()],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(
            files[&format!("artifacts/{}.json", sha(stored.as_bytes()))],
            stored.as_bytes()
        );
    }
    let cp = f.pool.get().await.unwrap().query_one(
        "SELECT statement,signature FROM audit_head_checkpoints WHERE tenant_id=$1 ORDER BY checkpoint_order DESC LIMIT 1",
        &[f.agent.tenant_id.as_uuid()]).await.unwrap();
    assert_eq!(files["checkpoint.json"], cp.get::<_, String>(0).as_bytes());
    assert_eq!(files["checkpoint.sig"], cp.get::<_, Vec<u8>>(1));
}
/// PLT-50: the real export carries `checkpoint.cose`, and an independent COSE implementation
/// (coset builds the RFC 9052 Sig_structure) verifies it under the tenant key.
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn export_pg_bundle_carries_cose_statement() {
    use coset::{CoseSign1, TaggedCborSerializable};
    let f = completed().await;
    let (zip, pin) = exported(&f).await;
    assert!(bundle::verify(&zip, Some(pin)).unwrap().cose_statement);
    let files = members(&zip);
    let message = CoseSign1::from_tagged_slice(&files["checkpoint.cose"]).unwrap();
    assert_eq!(
        message.payload.as_deref(),
        Some(files["checkpoint.json"].as_slice())
    );
    let head: Value = serde_json::from_slice(&files["checkpoint.json"]).unwrap();
    assert_eq!(
        message.protected.header.key_id,
        head["key_id"].as_str().unwrap().as_bytes()
    );
    let verify = |key: &[u8]| {
        message.verify_signature(b"", |sig, data| {
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
                .verify(data, sig)
        })
    };
    verify(&pin).unwrap();
    assert!(verify(&[9; 32]).is_err(), "another key must not verify");
    // Stripping the member is not detectable (unsigned manifest); it is reported, not hidden.
    let mut stripped = files.clone();
    stripped.remove("checkpoint.cose");
    let report = bundle::verify(&bundle::seal(stripped).unwrap(), Some(pin)).unwrap();
    assert!(!report.cose_statement);
    // A COSE member from another tenant's export is refused under this pin.
    let other = completed().await;
    let (other_zip, _) = exported(&other).await;
    let mut swapped = files;
    swapped.insert(
        "checkpoint.cose".into(),
        members(&other_zip)["checkpoint.cose"].clone(),
    );
    let error = bundle::verify(&bundle::seal(swapped).unwrap(), Some(pin)).unwrap_err();
    assert_eq!(error.code, 4, "{error}");
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_export_tamper() {
    let f = completed().await;
    let (zip, pin) = exported(&f).await;
    for mode in [
        "deleted",
        "altered",
        "reordered",
        "stripped",
        "other-key",
        "embedded-key",
        "manifest",
    ] {
        let mut files = members(&zip);
        let mut ledger = rows(&files);
        let expected = match mode {
            "deleted" => {
                ledger.remove(2);
                4
            }
            "altered" => {
                let text = ledger[0]["payload"].as_str().unwrap();
                let mut e: Value = serde_json::from_str(text).unwrap();
                e["request_digest"] = json!("a".repeat(64));
                ledger[0]["payload"] = json!(canonical(&e).unwrap());
                4
            }
            "reordered" => {
                ledger.swap(1, 2);
                4
            }
            "stripped" => {
                files.remove("checkpoint.json");
                4
            }
            "other-key" => {
                let other =
                    crate::audit_keys::TenantAuditKeypair::generate(f.agent.tenant_id.clone())
                        .unwrap();
                files.insert(
                    "checkpoint.sig".into(),
                    other.sign(&files["checkpoint.json"]),
                );
                5
            }
            "embedded-key" => {
                use base64::Engine;
                ledger.push(json!({"type":"anchor","ed25519":{"pubkey":base64::engine::general_purpose::STANDARD.encode(pin)}}));
                5
            }
            "manifest" => 4,
            _ => unreachable!(),
        };
        replace_rows(&mut files, &ledger);
        let mut changed = bundle::seal(files).unwrap();
        if mode == "manifest" {
            let mut files = unpack(&changed).unwrap();
            files.insert("ledger.ndjson".into(), b"altered".to_vec());
            changed = pack(&files).unwrap();
        }
        let trust = if mode == "embedded-key" {
            None
        } else {
            Some(pin)
        };
        let e = bundle::verify(&changed, trust).unwrap_err();
        assert_eq!(e.code, expected, "{mode}: {e}");
        cli(&changed, trust, i32::from(expected), mode);
    }
}
// After-export semantic tampering is rehashed/re-signed using the synthetic key,
// so only the causal control (not a stale chain hash) can detect it.
async fn resign(f: &Fixture, mut files: Files, mut ledger: Vec<Value>) -> Vec<u8> {
    let mut prev = crate::audit_format::genesis_prev_hash(&f.agent.tenant_id);
    for (seq, row) in ledger.iter_mut().enumerate() {
        row["seq"] = json!(seq);
        row["prev_hash"] = json!(hex::encode(prev));
        prev = crate::audit_format::row_hash_v2(
            &prev,
            &f.agent.tenant_id,
            seq as u64,
            row["event_type"].as_str().unwrap(),
            row["actor"].as_str().unwrap(),
            row["payload"].as_str().unwrap(),
        );
        row["row_hash"] = json!(hex::encode(prev));
    }
    replace_rows(&mut files, &ledger);
    let mut cp: Value = serde_json::from_slice(&files["checkpoint.json"]).unwrap();
    cp["seq"] = json!((ledger.len() - 1).to_string());
    cp["head_hash"] = json!(hex::encode(prev));
    let text = canonical(&cp).unwrap();
    let key = keys(f)
        .await
        .get_or_create(&f.agent.tenant_id)
        .await
        .unwrap();
    files.insert("checkpoint.sig".into(), key.sign(text.as_bytes()));
    // A key-holding re-signer re-wraps the COSE envelope too, so the verdict under test is
    // the semantic one (6), not a stale-envelope format failure (4).
    if files.contains_key("checkpoint.cose") {
        let cose = tracelane_audit_verifier::action::cose::sign1(text.as_bytes(), |m| key.sign(m))
            .unwrap();
        files.insert("checkpoint.cose".into(), cose);
    }
    files.insert("checkpoint.json".into(), text.into_bytes());
    // The key holder re-signs the tree checkpoint too, so only semantics can refuse.
    let files = crate::audit_export::action::with_tree_checkpoint(files, &key).unwrap();
    bundle::seal(files).unwrap()
}
// AUD-06: two real exports of one growing ledger carry C2SP checkpoints that agree
// with the rows, prove every row, and prove the later tree extends the earlier one.
/// Moves the latest checkpoint back past the export rate limit and re-signs it under the
/// workspace key, so a second export in the same test is allowed and its chain still verifies.
async fn age_latest_checkpoint(f: &Fixture) {
    let key = keys(f)
        .await
        .get_or_create(&f.agent.tenant_id)
        .await
        .unwrap();
    let db = f.pool.get().await.unwrap();
    let tenant = *f.agent.tenant_id.as_uuid();
    let row = db
        .query_one(
            "SELECT checkpoint_id,statement FROM audit_head_checkpoints WHERE tenant_id=$1 ORDER BY checkpoint_order DESC LIMIT 1",
            &[&tenant],
        )
        .await
        .unwrap();
    let mut v: Value = serde_json::from_str(row.get::<_, &str>(1)).unwrap();
    let earlier = chrono::Utc::now()
        - chrono::Duration::seconds(2 * crate::action_control::CHECKPOINT_MIN_INTERVAL_SECS);
    v["created_at"] = json!(earlier.to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
    let text = canonical(&v).unwrap();
    db.execute(
        "UPDATE audit_head_checkpoints SET statement=$3, signature=$4 WHERE tenant_id=$1 AND checkpoint_id=$2",
        &[&tenant, &row.get::<_, Uuid>(0), &text, &key.sign(text.as_bytes())],
    )
    .await
    .unwrap();
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_export_tree_checkpoint() {
    use tracelane_audit_verifier::action::tree;
    let f = completed().await;
    let (first, pin) = exported(&f).await;
    f.pending().await;
    age_latest_checkpoint(&f).await;
    let (second, _) = exported(&f).await;
    let (a, b) = (members(&first), members(&second));
    let origin = tree::origin(*f.agent.tenant_id.as_uuid());
    let old = tree::open_checkpoint(&a[tree::MEMBER], &origin, &pin).unwrap();
    let new = tree::open_checkpoint(&b[tree::MEMBER], &origin, &pin).unwrap();
    let report = bundle::verify(&second, Some(pin)).unwrap();
    assert_eq!(report.tree_size, Some(report.rows));
    assert_eq!(report.tree_root, Some(hex::encode(new.root)));
    assert!(
        old.size > 5 && new.size > old.size,
        "{} {}",
        old.size,
        new.size
    );
    let leaves = tree::ledger_leaves(&b["ledger.ndjson"]).unwrap();
    assert_eq!(leaves.len() as u64, new.size);
    for (i, leaf) in leaves.iter().enumerate() {
        let proof = tree::inclusion_proof(&leaves, i).unwrap();
        tree::verify_inclusion(leaf, i as u64, new.size, &proof, &new.root).unwrap();
        assert!(tree::verify_inclusion(leaf, i as u64, old.size, &proof, &old.root).is_err());
    }
    let proof = tree::consistency_proof(&leaves, old.size as usize).unwrap();
    tree::verify_consistency(old.size, new.size, &old.root, &new.root, &proof).unwrap();
    assert!(tree::verify_consistency(old.size, new.size, &new.root, &new.root, &proof).is_err());
    // A validly signed but stale checkpoint inside the later bundle is refused.
    let mut stale = b.clone();
    stale.insert(tree::MEMBER.into(), a[tree::MEMBER].clone());
    let error = bundle::verify(&bundle::seal(stale).unwrap(), Some(pin)).unwrap_err();
    assert_eq!(
        (error.code, error.detail.as_str()),
        (4, "tree checkpoint does not match the ledger rows")
    );
    // Another tenant's key cannot stand in: the note fails under that pin.
    let other = [9u8; 32];
    assert!(tree::open_checkpoint(&b[tree::MEMBER], &origin, &other).is_err());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_export_semantics() {
    let f = completed().await;
    let (zip, pin) = exported(&f).await;
    for (mode, removed) in [
        ("unapproved", "approval_granted"),
        ("no-start", "execution_started"),
        ("digest", ""),
    ] {
        let files = members(&zip);
        let mut ledger = rows(&files);
        if mode == "digest" {
            let row = ledger
                .iter_mut()
                .find(|r| r["event_type"] == "approval_consumed")
                .unwrap();
            let mut e: Value = serde_json::from_str(row["payload"].as_str().unwrap()).unwrap();
            e["request_digest"] = json!("a".repeat(64));
            row["payload"] = json!(canonical(&e).unwrap());
        } else {
            ledger.retain(|r| r["event_type"] != removed);
        }
        let changed = resign(&f, files, ledger).await;
        assert_eq!(
            bundle::verify(&changed, Some(pin)).unwrap_err().code,
            6,
            "{mode}"
        );
        cli(&changed, Some(pin), 6, mode);
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_export_unknown() {
    let f = Fixture::new().await;
    let id = f.pending().await;
    f.decide(&f.human, id, true).await;
    execute(
        &f.pool,
        &f.agent,
        Some(&grants()),
        &f.call(Uuid::new_v4(), Some(id)),
        &f.signer,
        None,
        |_| async { Outcome::Unknown },
    )
    .await
    .unwrap();
    let (zip, pin) = exported(&f).await;
    let r = bundle::verify(&zip, Some(pin)).unwrap();
    assert_eq!(r.actions.unknown.len(), 1);
    cli(&zip, Some(pin), 0, "unknown");
    assert!(r.to_string().contains("UNKNOWN outcomes: 1"));
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_export_outside() {
    let f = completed().await;
    // Causal event appended with the real append API, pointing to an absent action.
    let mut c = f.pool.get().await.unwrap();
    let tx = c.transaction().await.unwrap();
    let e = ActionEvent {
        event_id: Uuid::new_v4(),
        action_id: Uuid::new_v4(),
        occurred_at: db_now(&tx).await.unwrap(),
        request_digest: "a".repeat(64),
        body: ActionPayload::ApprovalConsumed {
            approval_id: Uuid::new_v4(),
        },
    };
    append_actions_tx(&tx, &f.agent, Some(&grants()), &[e])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let err = PgExportReader::new(f.pool.clone())
        .with_action_keys(Some(keys(&f).await))
        .action_bundle(&f.agent.tenant_id, &grants())
        .await
        .unwrap_err();
    assert!(
        err.downcast_ref::<crate::audit_export::action::ExportError>()
            .is_some_and(|e| matches!(
                e,
                crate::audit_export::action::ExportError::ReferenceOutsideRange
            )),
        "{err:#}"
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_export_empty() {
    let f = Fixture::legacy().await;
    let (zip, pin) = exported(&f).await;
    let r = bundle::verify(&zip, Some(pin)).unwrap();
    assert_eq!(r.rows, 0);
    assert_eq!(r.head_seq, None);
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_export_tenant_and_artifact() {
    let f = completed().await;
    let other = f.other().await;
    let id = other.pending().await;
    other.decide(&other.human, id, true).await;
    other.run(Uuid::new_v4(), id).await.unwrap();
    let (first, _) = exported(&f).await;
    let (foreign, _) = exported(&other).await;
    // Poison ONLY the foreign anchor, on real API-appended rows. An unscoped
    // anchor query must make the positive own-tenant export fail verification.
    let db = f.pool.get().await.unwrap();
    db.execute("INSERT INTO audit_anchor_records(tenant_id,batch_start_seq,batch_end_seq,merkle_root,anchor_state,anchored_at) VALUES($1,0,0,$2,'unanchored',now())", &[other.agent.tenant_id.as_uuid(),&"a".repeat(64)]).await.unwrap();
    let (zip, pin) = exported(&f).await;
    assert!(bundle::verify(&zip, Some(pin)).is_ok());
    let own = members(&zip);
    assert!(
        rows(&own)
            .iter()
            .all(|r| r["tenant_id"] == f.agent.tenant_id.to_string())
    );
    let cp: Value = serde_json::from_slice(&own["checkpoint.json"]).unwrap();
    assert_eq!(own["checkpoint.json"], members(&first)["checkpoint.json"]);
    assert_ne!(
        cp["previous_checkpoint_digest"],
        sha(&members(&foreign)["checkpoint.json"])
    );
    let body = |files: &Files, field: &str| -> Vec<String> {
        rows(files)
            .iter()
            .filter(|r| r["event_type"] == "policy_activated")
            .map(|r| {
                serde_json::from_str::<Value>(r["payload"].as_str().unwrap()).unwrap()["body"]
                    [field]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect()
    };
    let foreign = members(&foreign);
    let (p, c) = (body(&own, "policy_hash"), body(&own, "contract_hash"));
    let (fp, fc) = (
        body(&foreign, "policy_hash"),
        body(&foreign, "contract_hash"),
    );
    drop(db);
    let mut db = f.pool.get().await.unwrap();
    let tx = db.transaction().await.unwrap();
    assert_eq!(
        crate::audit_export::action::artifacts_tx(&tx, &f.agent.tenant_id, &p, &c)
            .await
            .unwrap()
            .len(),
        2
    );
    // Separate negative per artifact query: the other query has a valid own selector.
    assert!(
        crate::audit_export::action::artifacts_tx(&tx, &f.agent.tenant_id, &fp, &c)
            .await
            .is_err()
    );
    assert!(
        crate::audit_export::action::artifacts_tx(&tx, &f.agent.tenant_id, &p, &fc)
            .await
            .is_err()
    );
    // Deliberate corruption in this disposable fixture transaction only; rollback
    // restores both artifacts and trigger. No ledger row is fabricated or rewritten.
    tx.batch_execute("ALTER TABLE action_policies DISABLE TRIGGER action_policy_immutable")
        .await
        .unwrap();
    for (body, hash) in [(" {}", sha(b" {}")), ("{}", "0".repeat(64))] {
        tx.execute(
            "UPDATE action_policies SET body_jcs=$2,policy_hash=$3 WHERE tenant_id=$1",
            &[f.agent.tenant_id.as_uuid(), &body, &hash],
        )
        .await
        .unwrap();
        assert_eq!(
            crate::audit_export::action::artifacts_tx(&tx, &f.agent.tenant_id, &[hash], &c)
                .await
                .unwrap_err()
                .to_string(),
            "invalid original artifact bytes"
        );
    }
    tx.rollback().await.unwrap();
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_export_snapshot() {
    let f = completed().await;
    let keys = keys(&f).await;
    let key = keys.get_or_create(&f.agent.tenant_id).await.unwrap();
    let pin = key.public_key_bytes().try_into().unwrap();
    let mut db = f.pool.get().await.unwrap();
    let tx = db
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .await
        .unwrap();
    let head = checkpoint_head_tx(&tx, &f.agent.tenant_id).await.unwrap();
    let cp = sign_checkpoint(&key, &f.agent.tenant_id, head, None).unwrap();
    let expected: Value = serde_json::from_str(&cp.statement).unwrap();
    // Commit a real canonical batch backfill after the export snapshot exists.
    // RC would include this anchor; the frozen export must retain zero coverage.
    use base64::Engine;
    let end = expected["seq"].as_str().unwrap().parse::<u64>().unwrap();
    let hashes = crate::db::ledger::read_row_hashes(&f.pool, &f.agent.tenant_id, 0, end)
        .await
        .unwrap();
    let root = crate::audit_format::merkle_root_v2(&hashes);
    let sig = base64::engine::general_purpose::STANDARD
        .encode(crate::audit::sign_unanchored_for_test(&key, &root));
    let pk = base64::engine::general_purpose::STANDARD.encode(key.public_key_bytes());
    crate::db::ledger::backfill_signature(&f.pool, &f.agent.tenant_id, &sig, &pk, 0, end)
        .await
        .unwrap();
    crate::db::ledger::insert_anchor_record(
        &f.pool,
        &crate::db::ledger::AuditAnchorRecordRow {
            tenant_id: f.agent.tenant_id.to_string(),
            batch_start_seq: 0,
            batch_end_seq: end,
            merkle_root: hex::encode(root),
            anchor_state: "unanchored".into(),
            ed25519_sig: sig,
            ed25519_pubkey: pk,
            ecdsa_pubkey_spki: String::new(),
            rekor_log_url: String::new(),
            rekor_log_index: String::new(),
            canonicalized_body: String::new(),
            inclusion_proof: String::new(),
            checkpoint_envelope: String::new(),
            anchored_at: Utc::now().timestamp_micros(),
        },
    )
    .await
    .unwrap();
    let started = tokio::sync::Notify::new();
    let (zip, _) = tokio::join!(
        async {
            started.notified().await;
            let oversized = crate::audit_export::action::snapshot_files_tx(
                &tx,
                &f.agent.tenant_id,
                head,
                crate::audit_export::action::EvidenceBuffer::new().with_limit(2048 + 512),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                oversized.downcast_ref(),
                Some(crate::audit_export::action::ExportError::TooLarge)
            ));
            let mut files = crate::audit_export::action::snapshot_files_tx(
                &tx,
                &f.agent.tenant_id,
                head,
                crate::audit_export::action::EvidenceBuffer::new(),
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
            files.insert("checkpoint.json".into(), cp.statement.as_bytes().to_vec());
            files.insert("checkpoint.sig".into(), cp.signature.clone());
            crate::audit_export::action::seal_verified(files, &key).unwrap()
        },
        async {
            started.notify_one();
            f.pending().await
        }
    );
    let r = bundle::verify(&zip, Some(pin)).unwrap();
    assert_eq!(r.head_seq.as_deref(), expected["seq"].as_str());
    let (later, pin) = exported(&f).await;
    let later = bundle::verify(&later, Some(pin)).unwrap();
    assert_eq!(
        r.batch_signatures, 0,
        "backfill leaked into frozen snapshot"
    );
    assert_eq!(
        later.batch_signatures, 1,
        "valid own anchor was not exported"
    );
    assert!(
        later.rows > r.rows,
        "append must have committed after frozen export"
    );
    cli(&zip, Some(pin), 0, "snapshot");
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_export_head_inconsistency() {
    let f = completed().await;
    let (zip, _) = exported(&f).await;
    let ledger = rows(&members(&zip));
    let prior = &ledger[ledger.len() - 2];
    let db = f.pool.get().await.unwrap();
    for missing in [true, false] {
        db.execute(
            "DELETE FROM audit_chain_state WHERE tenant_id=$1",
            &[f.agent.tenant_id.as_uuid()],
        )
        .await
        .unwrap();
        if !missing {
            db.execute(
                "INSERT INTO audit_chain_state(tenant_id,last_seq,last_row_hash) VALUES($1,$2,$3)",
                &[
                    f.agent.tenant_id.as_uuid(),
                    &i64::try_from(prior["seq"].as_u64().unwrap()).unwrap(),
                    &hex::decode(prior["row_hash"].as_str().unwrap()).unwrap(),
                ],
            )
            .await
            .unwrap();
        }
        let e = export_attempt(&f).await.0.unwrap_err();
        assert!(
            e.downcast_ref::<crate::audit_export::action::ExportError>()
                .is_some_and(|e| matches!(
                    e,
                    crate::audit_export::action::ExportError::InvalidEvidence { code: 4, .. }
                )),
            "{e:#}"
        );
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_export_concurrent_checkpoints() {
    let f = completed().await;
    let key = keys(&f)
        .await
        .get_or_create(&f.agent.tenant_id)
        .await
        .unwrap();
    let mut db = f.pool.get().await.unwrap();
    let snapshot = db
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .await
        .unwrap();
    let head = checkpoint_head_tx(&snapshot, &f.agent.tenant_id)
        .await
        .unwrap();
    let pause = Arc::new((tokio::sync::Notify::new(), tokio::sync::Notify::new()));
    let read = crate::audit_export::action::READ_PAUSE.scope(
        std::cell::RefCell::new(Some(pause.clone())),
        crate::audit_export::action::snapshot_files_tx(
            &snapshot,
            &f.agent.tenant_id,
            head,
            crate::audit_export::action::EvidenceBuffer::new(),
        ),
    );
    let (read_result, winner) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(read, async {
            pause.0.notified().await;
            f.pending().await;
            let winner = exported(&f).await;
            pause.1.notify_one();
            winner
        })
    })
    .await
    .unwrap();
    read_result.unwrap();
    snapshot.commit().await.unwrap();
    let count: i64 = db
        .query_one(
            "SELECT count(*) FROM audit_head_checkpoints WHERE tenant_id=$1",
            &[f.agent.tenant_id.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    for candidate in [
        head,
        Some((
            rows(&members(&winner.0)).last().unwrap()["seq"]
                .as_u64()
                .unwrap(),
            [0; 32],
        )),
    ] {
        let tx = db
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
            .start()
            .await
            .unwrap();
        let error = checkpoint_for_head_tx(&tx, &f.agent.tenant_id, candidate, &key, None)
            .await
            .err()
            .unwrap();
        if candidate == head {
            let response = crate::audit_export::action::refusal(&error);
            assert_eq!(response.status().as_u16(), 503);
            assert_eq!(response.headers()["retry-after"], "1");
        } else {
            assert!(matches!(
                error.downcast_ref(),
                Some(crate::audit_export::action::ExportError::InvalidEvidence { .. })
            ));
        }
        tx.rollback().await.unwrap();
    }
    let retained: i64 = db
        .query_one(
            "SELECT count(*) FROM audit_head_checkpoints WHERE tenant_id=$1",
            &[f.agent.tenant_id.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(retained, count);
    assert_eq!(count, 1, "stale or equivocal checkpoint was inserted");
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_fix3_minter_sees_winner() {
    let f = completed().await;
    let key = keys(&f)
        .await
        .get_or_create(&f.agent.tenant_id)
        .await
        .unwrap();
    let (mut a, mut b) = (f.pool.get().await.unwrap(), f.pool.get().await.unwrap());
    let first = a
        .build_transaction()
        .isolation_level(CHECKPOINT_ISOLATION)
        .start()
        .await
        .unwrap();
    let cp = create_checkpoint_tx(&first, &f.agent.tenant_id, Some(&grants()), &key)
        .await
        .unwrap();
    let second = b
        .build_transaction()
        .isolation_level(CHECKPOINT_ISOLATION)
        .start()
        .await
        .unwrap();
    let isolation: String = second
        .query_one("SHOW transaction_isolation", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(isolation, "read committed");
    second
        .query_one(
            "SELECT id FROM tenants WHERE id=$1",
            &[f.agent.tenant_id.as_uuid()],
        )
        .await
        .unwrap();
    let resolved = grants();
    let (next, ()) = tokio::join!(
        create_checkpoint_tx(&second, &f.agent.tenant_id, Some(&resolved), &key),
        async {
            first.commit().await.unwrap();
        }
    );
    assert_eq!(next.unwrap().statement, cp.statement);
    second.commit().await.unwrap();
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_fix_checkpoint_reuse_and_throttle() {
    let f = completed().await;
    let (first, _) = exported(&f).await;
    let (second, _) = exported(&f).await;
    assert_eq!(
        members(&first)["checkpoint.json"],
        members(&second)["checkpoint.json"]
    );
    f.pending().await;
    let error = PgExportReader::new(f.pool.clone())
        .with_action_keys(Some(keys(&f).await))
        .action_bundle(&f.agent.tenant_id, &grants())
        .await
        .unwrap_err();
    assert!(
        matches!(
            error.downcast_ref(),
            Some(crate::audit_export::action::ExportError::CheckpointRateLimited(_))
        ),
        "{error}"
    );
    let count: i64 = f
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT count(*) FROM audit_head_checkpoints WHERE tenant_id=$1",
            &[f.agent.tenant_id.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_fix3_tenant_admission_before_snapshot() {
    let f = completed().await;
    let pause = Arc::new((tokio::sync::Notify::new(), tokio::sync::Notify::new()));
    let first = crate::audit_export::action::READ_PAUSE
        .scope(std::cell::RefCell::new(Some(pause.clone())), exported(&f));
    let (_, ()) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(first, async {
            pause.0.notified().await;
            let mut db = f.pool.get().await.unwrap();
            let tx = db.transaction().await.unwrap();
            let acquired: bool = tx.query_one("SELECT pg_try_advisory_xact_lock(hashtextextended($1::text || ':action_bundle', 0))", &[&f.agent.tenant_id.to_string()]).await.unwrap().get(0);
            assert!(!acquired, "replica admitted same tenant while export paused");
            tx.rollback().await.unwrap();
            let e = PgExportReader::new(f.pool.clone()).with_action_keys(Some(keys(&f).await)).action_bundle(&f.agent.tenant_id, &grants()).await.unwrap_err();
            let response = crate::audit_export::action::refusal(&e);
            assert_eq!(response.status().as_u16(), 429);
            assert!(response.headers().contains_key("retry-after"));
            pause.1.notify_one();
        })
    }).await.unwrap();
    // Even an unchanged head must be refused before reaching the snapshot hook.
    let trap = Arc::new((tokio::sync::Notify::new(), tokio::sync::Notify::new()));
    let reader = PgExportReader::new(f.pool.clone()).with_action_keys(Some(keys(&f).await));
    let e = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        crate::audit_export::action::READ_PAUSE.scope(
            std::cell::RefCell::new(Some(trap)),
            reader.action_bundle(&f.agent.tenant_id, &grants()),
        ),
    )
    .await
    .expect("throttle reached snapshot")
    .unwrap_err();
    assert_eq!(
        crate::audit_export::action::refusal(&e).status().as_u16(),
        429
    );
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_fix_append_commits_mid_export() {
    use crate::audit_export::action::READ_PAUSE;
    let f = completed().await;
    let pause = Arc::new((tokio::sync::Notify::new(), tokio::sync::Notify::new()));
    let export = READ_PAUSE.scope(std::cell::RefCell::new(Some(pause.clone())), exported(&f));
    let ((zip, pin), ()) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(export, async {
            pause.0.notified().await;
            tokio::time::timeout(std::time::Duration::from_secs(5), f.pending())
                .await
                .expect("append blocked by paused export");
            pause.1.notify_one(); // Export cannot finish until append COMMITTED.
        })
    })
    .await
    .unwrap();
    let verified = bundle::verify(&zip, Some(pin)).unwrap();
    let current: i64 = f
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT last_seq FROM audit_chain_state WHERE tenant_id=$1",
            &[f.agent.tenant_id.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert!(current > verified.head_seq.unwrap().parse::<i64>().unwrap());
}

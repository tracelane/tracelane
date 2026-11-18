//! Real appended C1-4 evidence, never handwritten ledger rows. Standard PG runner filter.
use super::*;
use crate::audit_export::AuditExportReader;
use tracelane_audit_verifier::action::{archive::unpack, bundle};
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_bundle_offline_tamper_matrix() {
    let f = Fixture::new().await;
    let id = f.pending().await;
    assert_eq!(f.decide(&f.human, id, true).await, None);
    f.run(Uuid::new_v4(), id).await.unwrap();
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
    let keys = crate::audit_keys::TenantAuditKeyStore::new(
        f.pool.clone(),
        std::sync::Arc::new(master),
        None,
    );
    let cp = create_checkpoint(&f.pool, &f.agent.tenant_id, Some(&grants()), &keys)
        .await
        .unwrap();
    let pin = keys
        .get_or_create(&f.agent.tenant_id)
        .await
        .unwrap()
        .public_key_bytes()
        .try_into()
        .unwrap();
    let reader = crate::audit_export::PgExportReader::new(f.pool.clone());
    let rows = reader
        .read_range_page(
            &f.agent.tenant_id,
            DateTime::UNIX_EPOCH,
            DateTime::<Utc>::MAX_UTC,
            None,
            1000,
        )
        .await
        .unwrap();
    let mut ledger = String::new();
    for row in rows {
        ledger.push_str(&serde_json::to_string(&row).unwrap());
        ledger.push('\n');
    }
    let mut files = std::collections::BTreeMap::from([
        ("ledger.ndjson".into(), ledger.into_bytes()),
        ("checkpoint.json".into(), cp.statement.into_bytes()),
        ("checkpoint.sig".into(), cp.signature),
    ]);
    for text in [&f.policy, &f.contract] {
        let bytes = canonical_json(text).unwrap().into_bytes();
        files.insert(format!("artifacts/{}.json", sha(&bytes)), bytes);
    }
    let zip = bundle::seal(files.clone()).unwrap();
    let report = bundle::verify(&zip, Some(pin)).unwrap();
    assert!(report.chain && report.head && report.actions.unknown.is_empty());
    assert_eq!(bundle::verify(&zip, None).unwrap_err().code, 5);
    assert_eq!(bundle::verify(&zip, Some([9; 32])).unwrap_err().code, 5);
    for mode in [
        "deleted",
        "altered",
        "reordered",
        "stripped",
        "manifest",
        "legacy",
    ] {
        let mut changed = files.clone();
        match mode {
            "stripped" => {
                changed.remove("checkpoint.json");
            }
            "deleted" | "reordered" => {
                let mut lines = std::str::from_utf8(&changed["ledger.ndjson"])
                    .unwrap()
                    .lines()
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                if mode == "deleted" {
                    lines.remove(2);
                } else {
                    lines.swap(1, 2);
                }
                changed.insert(
                    "ledger.ndjson".into(),
                    format!("{}\n", lines.join("\n")).into_bytes(),
                );
            }
            "legacy" => {
                let mut lines = std::str::from_utf8(&changed["ledger.ndjson"])
                    .unwrap()
                    .lines()
                    .map(|l| serde_json::from_str::<Value>(l).unwrap())
                    .collect::<Vec<_>>();
                lines[0]["format"] = json!("v2");
                lines[0]["payload"] = json!({"amount":1.0});
                changed.insert(
                    "ledger.ndjson".into(),
                    lines
                        .iter()
                        .map(|v| format!("{v}\n"))
                        .collect::<String>()
                        .into_bytes(),
                );
            }
            "altered" => {
                changed.insert(
                    "ledger.ndjson".into(),
                    alter_payload(&changed["ledger.ndjson"]),
                );
            }
            "manifest" => {} // The sealed ZIP is changed below without resealing.
            _ => unreachable!(),
        }
        let altered = if mode == "manifest" {
            let mut f = unpack(&zip).unwrap();
            f.insert("ledger.ndjson".into(), b"altered".to_vec());
            tracelane_audit_verifier::action::archive::pack(&f).unwrap()
        } else {
            bundle::seal(changed).unwrap()
        };
        let failure = bundle::verify(&altered, Some(pin)).unwrap_err();
        assert_eq!(failure.code, 4, "{mode}: {failure}");
        if mode == "altered" {
            assert_eq!(failure.detail, "row hash mismatch at 0");
        }
    }
}

// Keep the row valid JSON/JCS and its stored hash unchanged; mutate inside payload.
fn alter_payload(ledger: &[u8]) -> Vec<u8> {
    let mut rows = std::str::from_utf8(ledger)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    let payload = rows[0]["payload"].as_str().unwrap();
    let envelope: Value = serde_json::from_str(payload).unwrap();
    let digest = envelope["request_digest"].as_str().unwrap();
    let mut changed = digest.as_bytes().to_vec();
    changed[0] = if changed[0] == b'a' { b'b' } else { b'a' };
    rows[0]["payload"] = json!(payload.replacen(digest, std::str::from_utf8(&changed).unwrap(), 1));
    rows.iter()
        .map(|row| format!("{row}\n"))
        .collect::<String>()
        .into_bytes()
}
#[test]
fn altered_mode_mutates_inside_payload_and_preserves_json_and_hash() {
    let payload = r#"{"request_digest":"aaaa"}"#;
    let original = json!({"payload":payload,"row_hash":"unchanged","tenant_id":"unchanged"});
    let changed: Value =
        serde_json::from_slice(&alter_payload(format!("{original}\n").as_bytes())).unwrap();
    assert_eq!(changed["row_hash"], original["row_hash"]);
    assert_eq!(changed["tenant_id"], original["tenant_id"]);
    assert_eq!(changed["payload"], r#"{"request_digest":"baaa"}"#);
    assert_eq!(
        canonical_json(changed["payload"].as_str().unwrap()).unwrap(),
        changed["payload"].as_str().unwrap()
    );
}

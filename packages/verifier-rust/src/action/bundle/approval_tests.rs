//! ACT-40: default-path approval records inside a signed bundle, end to end.
use super::*;
use crate::approval::{EXPIRY_ACTOR, Record};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::json;

const FP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
fn tenant() -> Uuid {
    Uuid::from_u128(1)
}
/// requested -> approved -> consumed, as the gateway writes them (`approvals/ledger.rs`).
fn lifecycle() -> Vec<(String, String, String)> {
    let r = |transition: &str, extra: serde_json::Value| {
        let mut v = json!({"record":"tool_approval","v":1,"tenant_id":tenant(),
            "approval_id":Uuid::from_u128(5),"transition":transition,
            "occurred_at":"2026-11-20T12:00:01Z","request_fingerprint":FP,
            "requester":"apikey:7f","subject_kind":"tool","subject":"delete_repo",
            "server_id":Uuid::from_u128(9)});
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        let payload = canonical_json(&v.to_string()).unwrap();
        let rec: Record = serde_json::from_str(&payload).unwrap();
        (
            rec.transition.event_type(),
            rec.expected_actor().to_owned(),
            payload,
        )
    };
    vec![
        r("requested", json!({"expires_at":"2026-11-20T12:10:00Z"})),
        r(
            "approved",
            json!({"decided_by":"user_approver","expires_at":"2026-11-20T12:20:00Z"}),
        ),
        r("consumed", json!({})),
    ]
}
fn bundle(rows: &[(String, String, String)]) -> (Files, [u8; 32]) {
    let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    let pin: [u8; 32] = key.public_key().as_ref().try_into().unwrap();
    let mut prev = crate::genesis_v2(tenant().as_bytes());
    let mut ledger = String::new();
    for (seq, (event_type, actor, payload)) in rows.iter().enumerate() {
        let seq = seq as u64;
        let hash = crate::row_hash_v2(&prev, tenant().as_bytes(), seq, event_type, actor, payload);
        let row = json!({"format":"v2.1","tenant_id":tenant(),"seq":seq,"event_time":"2026-11-20T12:00:00Z","event_type":event_type,"actor":actor,"payload":payload,"prev_hash":hex::encode(prev),"row_hash":hex::encode(hash)});
        ledger.push_str(&format!("{row}\n"));
        prev = hash;
    }
    let head = canonical_json(&json!({"domain":"tracelane.action-head.v1","schema_version":1,"tenant_id":tenant(),"seq":(rows.len()-1).to_string(),"head_hash":hex::encode(prev),"created_at":"2026-11-20T12:30:00Z","key_id":hex::encode(crate::sha256(&pin)),"previous_checkpoint_digest":null}).to_string()).unwrap();
    let sig = key.sign(head.as_bytes()).as_ref().to_vec();
    (
        [
            ("ledger.ndjson".into(), ledger.into_bytes()),
            ("checkpoint.json".into(), head.into_bytes()),
            ("checkpoint.sig".into(), sig),
        ]
        .into(),
        pin,
    )
}
fn run(rows: &[(String, String, String)]) -> std::result::Result<Report, Failure> {
    let (files, pin) = bundle(rows);
    verify(&seal(files).unwrap(), Some(pin))
}

#[test]
fn approval_lifecycle_verifies_and_is_reported() {
    let report = run(&lifecycle()).unwrap();
    assert_eq!(report.rows, 3);
    assert_eq!(
        (
            report.approvals.requested,
            report.approvals.approved,
            report.approvals.consumed,
            report.approvals.open
        ),
        (1, 1, 1, 0)
    );
    let text = report.to_string();
    assert!(
        text.contains("approvals: 1 requested, 1 approved, 0 denied, 1 consumed, 0 expired, 0 open, 0 self-decided"),
        "{text}"
    );
}
#[test]
fn ledger_without_approvals_prints_as_before() {
    let mut rows = lifecycle();
    for r in &mut rows {
        r.0 = "fixture".into();
    }
    let text = run(&rows).unwrap().to_string();
    assert!(!text.contains(" requested, "), "{text}");
}
#[test]
fn one_byte_tamper_in_an_approval_record_fails() {
    // Edit the decider in the stored payload and reseal the zip: the row hash no longer
    // matches, so the integrity check (code 4) fails before semantics run.
    let (mut files, pin) = bundle(&lifecycle());
    let ledger = String::from_utf8(files["ledger.ndjson"].clone()).unwrap();
    assert!(ledger.contains("user_approver"));
    files.insert(
        "ledger.ndjson".into(),
        ledger
            .replacen("user_approver", "user_approvef", 1)
            .into_bytes(),
    );
    let e = verify(&seal(files).unwrap(), Some(pin)).unwrap_err();
    assert_eq!((e.code, e.detail.as_str()), (4, "row hash mismatch at 1"));
}
#[test]
fn rehashed_double_consume_fails_semantics() {
    // A writer that re-chains correctly but consumes twice is caught by the replay (code 6).
    let mut rows = lifecycle();
    rows.push(rows[2].clone());
    let e = run(&rows).unwrap_err();
    assert_eq!(
        (e.code, e.detail.as_str()),
        (6, "approval not approved, expired or already consumed")
    );
}
#[test]
fn rehashed_consume_without_approval_fails_semantics() {
    let mut rows = lifecycle();
    rows.remove(1);
    assert_eq!(run(&rows).unwrap_err().code, 6);
}
#[test]
fn rehashed_actor_swap_fails() {
    // The requester recorded as the approver of its own call is refused as an identity
    // mismatch, even when the chain is recomputed around it.
    let mut rows = lifecycle();
    rows[1].1 = "apikey:7f".into();
    let e = run(&rows).unwrap_err();
    assert_eq!(
        (e.code, e.detail.as_str()),
        (4, "approval record identity mismatch")
    );
}
#[test]
fn malformed_approval_payload_fails_closed() {
    let mut rows = lifecycle();
    rows[0].2 = "{}".into();
    assert_eq!(run(&rows).unwrap_err().code, 4);
}
#[test]
fn expiry_row_with_system_actor_verifies() {
    let mut rows = lifecycle();
    rows.truncate(1);
    let v = json!({"record":"tool_approval","v":1,"tenant_id":tenant(),
        "approval_id":Uuid::from_u128(5),"transition":"expired",
        "occurred_at":"2026-11-20T12:10:00Z","request_fingerprint":FP,
        "requester":"apikey:7f","subject_kind":"tool","subject":"delete_repo",
        "server_id":Uuid::from_u128(9)});
    rows.push((
        "tool_approval.expired".into(),
        EXPIRY_ACTOR.into(),
        canonical_json(&v.to_string()).unwrap(),
    ));
    assert_eq!(run(&rows).unwrap().approvals.expired, 1);
}
#[test]
fn plain_ledger_verify_treats_approval_rows_generically_and_catches_tamper() {
    // `tlane verify` on an NDJSON range: approval rows chain like any other row.
    let (files, _) = bundle(&lifecycle());
    let ledger = String::from_utf8(files["ledger.ndjson"].clone()).unwrap();
    let opts = crate::VerifyOptions::default();
    let clean =
        crate::verify_ledger_reader(std::io::Cursor::new(ledger.as_bytes()), "t", &opts).unwrap();
    assert!(clean.errors.is_empty(), "{:?}", clean.errors);
    let tampered = ledger.replacen("delete_repo", "delete_repp", 1);
    let bad =
        crate::verify_ledger_reader(std::io::Cursor::new(tampered.as_bytes()), "t", &opts).unwrap();
    assert!(!bad.errors.is_empty());
}

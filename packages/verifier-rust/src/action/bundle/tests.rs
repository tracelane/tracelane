use super::*;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};

fn key(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}
fn pin(key: &Ed25519KeyPair) -> [u8; 32] {
    key.public_key().as_ref().try_into().unwrap()
}
// Synthetic verifier inputs only; real-appended acceptance remains in the gateway PG test.
fn fixture(payload: &str) -> (Files, [u8; 32]) {
    let key = key(7);
    let tenant = Uuid::from_u128(1);
    let mut prev = crate::genesis_v2(tenant.as_bytes());
    let mut ledger = String::new();
    for seq in 0..3 {
        let hash = crate::row_hash_v2(&prev, tenant.as_bytes(), seq, "fixture", "test", payload);
        let row = json!({"format":"v2.1","tenant_id":tenant,"seq":seq,"event_time":"2026-10-30T12:00:00Z","event_type":"fixture","actor":"test","payload":payload,"prev_hash":hex::encode(prev),"row_hash":hex::encode(hash)});
        ledger.push_str(&format!("{row}\n"));
        prev = hash;
    }
    let head = canonical_json(&json!({"domain":"tracelane.action-head.v1","schema_version":1,"tenant_id":tenant,"seq":"2","head_hash":hex::encode(prev),"created_at":"2026-10-30T12:00:00Z","key_id":hex::encode(crate::sha256(&pin(&key))),"previous_checkpoint_digest":null}).to_string()).unwrap();
    let sig = key.sign(head.as_bytes()).as_ref().to_vec();
    (
        [
            ("ledger.ndjson".into(), ledger.into_bytes()),
            ("checkpoint.json".into(), head.into_bytes()),
            ("checkpoint.sig".into(), sig),
        ]
        .into(),
        pin(&key),
    )
}
fn failure_is(raw: &[u8], pin: Option<[u8; 32]>, code: u8, detail: &str) {
    let error = verify(raw, pin).unwrap_err();
    assert_eq!(error.code, code, "{error}");
    assert_eq!(error.detail, detail);
}
#[test]
fn clean_bundle() {
    let (files, pin) = fixture("{}");
    let report = verify(&seal(files).unwrap(), Some(pin)).unwrap();
    assert_eq!(report.rows, 3);
    assert!(report.chain && report.head);
    assert_eq!(report.batch_signatures, 0);
    assert_eq!(report.rekor_included, 0);
    let text = report.to_string();
    assert!(
        text.contains("rows: 3; signed range: 0..=2; head seq: 2"),
        "{text}"
    );
    assert!(text.contains(report.head_hash.as_ref().unwrap()), "{text}");
}
#[test]
fn manifest_hash_mismatch() {
    let (files, pin) = fixture("{}");
    let mut sealed = unpack(&seal(files).unwrap()).unwrap();
    // This un-resealed edit fails the manifest checksum. event_time is outside the
    // row-hash preimage; an attacker can reseal it, so it is not authenticated.
    let ledger = String::from_utf8(sealed["ledger.ndjson"].clone()).unwrap();
    sealed.insert(
        "ledger.ndjson".into(),
        ledger.replacen("12:00:00Z", "12:00:01Z", 1).into_bytes(),
    );
    failure_is(
        &pack(&sealed).unwrap(),
        Some(pin),
        4,
        "manifest hash mismatch: ledger.ndjson",
    );
}
fn change_rows(change: impl FnOnce(&mut Vec<String>)) -> (Vec<u8>, [u8; 32]) {
    let (mut files, pin) = fixture("{}");
    let mut rows = std::str::from_utf8(&files["ledger.ndjson"])
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    change(&mut rows);
    files.insert(
        "ledger.ndjson".into(),
        format!("{}\n", rows.join("\n")).into_bytes(),
    );
    (seal(files).unwrap(), pin)
}
#[test]
fn chain_reorder() {
    let (raw, pin) = change_rows(|rows| rows.swap(1, 2));
    failure_is(
        &raw,
        Some(pin),
        4,
        "tenant/sequence/previous hash mismatch at 1",
    );
}
#[test]
fn deleted_row() {
    let (raw, pin) = change_rows(|rows| {
        rows.remove(1);
    });
    failure_is(
        &raw,
        Some(pin),
        4,
        "tenant/sequence/previous hash mismatch at 1",
    );
}
#[test]
fn stripped_checkpoint() {
    let (mut files, pin) = fixture("{}");
    files.remove("checkpoint.json");
    failure_is(
        &seal(files).unwrap(),
        Some(pin),
        4,
        "missing checkpoint.json",
    );
}
#[test]
fn other_key_checkpoint() {
    let (mut files, pin) = fixture("{}");
    // Preserve key_id so the signature check, rather than the identifier gate, must reject.
    let sig = key(8).sign(&files["checkpoint.json"]);
    files.insert("checkpoint.sig".into(), sig.as_ref().to_vec());
    failure_is(
        &seal(files).unwrap(),
        Some(pin),
        5,
        "checkpoint does not verify under external pin",
    );
}
#[test]
fn embedded_key_refused_as_trust_root() {
    let (files, _) = fixture("{}");
    // The signed checkpoint carries its own key_id; an embedded batch also carries pubkey.
    let files = with_signed_batch(files, false);
    failure_is(
        &seal(files).unwrap(),
        None,
        5,
        "external --pubkey file required; bundle keys are not trust roots",
    );
}
#[test]
fn legacy_float_payload() {
    let (files, pin) = fixture(r#"{"amount":1.0}"#);
    failure_is(
        &seal(files).unwrap(),
        Some(pin),
        4,
        "unverifiable legacy payload: floats/non-JCS bytes",
    );
}
#[test]
fn non_jcs_payload() {
    let (files, pin) = fixture(r#"{ "amount":1}"#);
    failure_is(
        &seal(files).unwrap(),
        Some(pin),
        4,
        "unverifiable legacy payload: non-JCS bytes",
    );
}
#[test]
fn legacy_object_envelope() {
    let (raw, pin) = change_rows(|rows| {
        let mut row: Value = serde_json::from_str(&rows[0]).unwrap();
        row["format"] = json!("v2");
        row["payload"] = json!({});
        rows[0] = row.to_string();
    });
    failure_is(
        &raw,
        Some(pin),
        4,
        "legacy object envelope is unverifiable in action bundles",
    );
}
fn b64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().fold(0u32, |n, b| (n << 8) | u32::from(*b)) << (8 * (3 - chunk.len()));
        for index in 0..4 {
            out.push(if index > chunk.len() {
                '='
            } else {
                ALPHABET[((n >> (18 - 6 * index)) & 63) as usize] as char
            });
        }
    }
    out
}
fn with_signed_batch(mut files: Files, corrupt: bool) -> Files {
    let hashes: Vec<[u8; 32]> = std::str::from_utf8(&files["ledger.ndjson"])
        .unwrap()
        .lines()
        .map(|line| {
            let row: Value = serde_json::from_str(line).unwrap();
            hex::decode(row["row_hash"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect();
    let root = crate::merkle_root_v2(&hashes);
    let key = key(7);
    let msg = [crate::DOMAIN_ATTEST, &root, &[0]].concat();
    let mut sig = key.sign(&msg).as_ref().to_vec();
    if corrupt {
        sig[0] ^= 1;
    }
    let anchor = json!({"type":"anchor","tenant_id":Uuid::from_u128(1),"batch_start_seq":0,"batch_end_seq":2,"merkle_root":hex::encode(root),"anchor_state":"unanchored","ed25519":{"signature":b64(&sig),"pubkey":b64(&pin(&key))}});
    files
        .get_mut("ledger.ndjson")
        .unwrap()
        .extend(format!("{anchor}\n").as_bytes());
    files
}
#[test]
fn signed_unanchored_batch_counted() {
    let (files, pin) = fixture("{}");
    let report = verify(&seal(with_signed_batch(files, false)).unwrap(), Some(pin)).unwrap();
    assert_eq!(report.batch_signatures, 1);
    assert_eq!(report.rekor_included, 0);
}
#[test]
fn invalid_batch_signature_rejected() {
    let (files, pin) = fixture("{}");
    let error = verify(&seal(with_signed_batch(files, true)).unwrap(), Some(pin)).unwrap_err();
    assert_eq!(error.code, 4);
    assert!(error.detail.contains("attestation_invalid"), "{error}");
}

#[test]
fn report_discloses_signed_tenant_head_time_and_rows() {
    let (files, pin) = fixture("{}");
    let report = serde_json::to_value(verify(&seal(files).unwrap(), Some(pin)).unwrap()).unwrap();
    assert_eq!(report["tenant_id"], json!(Uuid::from_u128(1)));
    assert_eq!(report["head_seq"], "2");
    assert_eq!(report["head_hash"].as_str().unwrap().len(), 64);
    assert_eq!(report["created_at"], "2026-10-30T12:00:00Z");
    assert_eq!(report["rows"], 3);
}
#[test]
fn embedded_attacker_key_with_external_pin_is_trust_failure() {
    for attacker in [b64(&pin(&key(8))), "invalid-key".into()] {
        let (files, pin) = fixture("{}");
        let mut files = with_signed_batch(files, false);
        let mut rows = String::from_utf8(files["ledger.ndjson"].clone())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mut anchor: Value = serde_json::from_str(rows.last().unwrap()).unwrap();
        anchor["ed25519"]["pubkey"] = json!(attacker);
        let root = hex::decode(anchor["merkle_root"].as_str().unwrap()).unwrap();
        let message = [crate::DOMAIN_ATTEST, root.as_slice(), &[0]].concat();
        anchor["ed25519"]["signature"] = json!(b64(key(8).sign(&message).as_ref()));
        *rows.last_mut().unwrap() = anchor.to_string();
        files.insert(
            "ledger.ndjson".into(),
            format!("{}\n", rows.join("\n")).into_bytes(),
        );
        let error = verify(&seal(files).unwrap(), Some(pin)).unwrap_err();
        assert_eq!(error.code, 5, "{error}");
        assert!(
            error.detail.contains(if attacker == "invalid-key" {
                "bad_tenant_pubkey"
            } else {
                "untrusted_tenant_key"
            }),
            "{error}"
        );
    }
}

#[test]
fn report_text_lists_unknown_ids_and_explicit_empty_signed_head() {
    let (mut files, pin) = fixture("{}");
    let mut head: Value = serde_json::from_slice(&files["checkpoint.json"]).unwrap();
    head["seq"] = Value::Null;
    head["head_hash"] = Value::Null;
    let head = canonical_json(&head.to_string()).unwrap();
    files.insert(
        "checkpoint.sig".into(),
        key(7).sign(head.as_bytes()).as_ref().to_vec(),
    );
    files.insert("checkpoint.json".into(), head.into_bytes());
    files.insert("ledger.ndjson".into(), Vec::new());
    let mut report = verify(&seal(files).unwrap(), Some(pin)).unwrap();
    assert_eq!(report.head_seq, None);
    assert_eq!(report.head_hash, None);
    assert_eq!(report.rows, 0);
    report.actions.unknown = vec![Uuid::from_u128(99), Uuid::from_u128(100)];
    let text = report.to_string();
    for expected in [
        "EMPTY signed head",
        "head seq: null",
        "head hash: null",
        "rows: 0",
        "checkpoint created_at: 2026-10-30T12:00:00+00:00",
        &Uuid::from_u128(1).to_string(),
        &Uuid::from_u128(99).to_string(),
        &Uuid::from_u128(100).to_string(),
    ] {
        assert!(text.contains(expected), "{text}");
    }
}

#[test]
fn fix_outside_range_is_typed() {
    for missing in [0, 1, 3] {
        let (mut events, artifacts) = crate::action::tests::fixture();
        events.remove(missing);
        let error = semantic_failure(super::semantics(&events, &artifacts).unwrap_err());
        assert_eq!(error.code, 6);
        assert_eq!(error.kind, FailureKind::ReferenceOutsideRange);
    }
}

#[test]
fn timestamp_missing_report_json() {
    let (files, pin) = fixture("{}");
    let report = serde_json::to_value(verify(&seal(files).unwrap(), Some(pin)).unwrap()).unwrap();
    assert_eq!(report["timestamped"], false);
    assert!(report.get("gen_time").is_some_and(Value::is_null));
}
#[test]
fn timestamp_missing_report_text() {
    let (files, pin) = fixture("{}");
    let report = verify(&seal(files).unwrap(), Some(pin)).unwrap();
    assert!(report.to_string().contains("timestamped: false"));
}

#[test]
fn timestamp_bundle_roundtrip() {
    let files = [
        ("ledger.ndjson".into(), vec![]),
        (
            "checkpoint.json".into(),
            include_bytes!("../../../tests/fixtures/timestamp/checkpoint.json").to_vec(),
        ),
        (
            "checkpoint.sig".into(),
            include_bytes!("../../../tests/fixtures/timestamp/checkpoint.sig").to_vec(),
        ),
        (
            "checkpoint.tsr".into(),
            include_bytes!("../../../tests/fixtures/timestamp/good.tsr").to_vec(),
        ),
    ]
    .into();
    let cert = include_bytes!("../../../tests/fixtures/timestamp/good.der").to_vec();
    let key = hex::decode(include_str!("../../../tests/fixtures/timestamp/tenant.pub"))
        .unwrap()
        .try_into()
        .unwrap();
    let zip = seal(files).unwrap();
    let r = verify_with_tsa(&zip, Some(key), &[cert]).unwrap();
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(json["timestamped"], true);
    assert_eq!(json["gen_time"], "2026-11-13T12:00:00Z");
    assert!(r.to_string().contains("timestamped: true"));
    let unpinned = verify(&zip, Some(key)).unwrap();
    assert!(!unpinned.timestamped, "embedded certificates are not pins");
    assert_eq!(
        serde_json::to_value(&unpinned).unwrap()["timestamp_reason"],
        "tsa_unpinned"
    );
    assert!(unpinned.to_string().contains("tsa_unpinned"));
}
fn principal_bundle_report(with_chain: bool, with_cose: bool) -> Report {
    let (events, artifacts) = super::super::tests::principal_fixture();
    let signing = key(7);
    let tenant = events[0].tenant_id;
    let mut previous = crate::genesis_v2(tenant.as_bytes());
    let mut ledger = String::new();
    for (seq, event) in events.iter().enumerate() {
        let payload = canonical_json(&serde_json::to_string(event).unwrap()).unwrap();
        let event_type = serde_json::to_value(&event.body).unwrap()["event_type"]
            .as_str()
            .unwrap()
            .to_owned();
        let actor = event
            .agent_key_id
            .map_or_else(|| "human".to_owned(), |id| id.to_string());
        let hash = crate::row_hash_v2(
            &previous,
            tenant.as_bytes(),
            seq as u64,
            &event_type,
            &actor,
            &payload,
        );
        let row = json!({"format":"v2.1","tenant_id":tenant,"seq":seq,"event_time":"2026-10-30T12:00:00Z","event_type":event_type,"actor":actor,"payload":payload,"prev_hash":hex::encode(previous),"row_hash":hex::encode(hash)});
        ledger.push_str(&format!("{row}\n"));
        previous = hash;
    }
    let head=canonical_json(&json!({"domain":"tracelane.action-head.v1","schema_version":1,"tenant_id":tenant,"seq":(events.len()-1).to_string(),"head_hash":hex::encode(previous),"created_at":"2026-10-30T12:00:00Z","key_id":hex::encode(crate::sha256(&pin(&signing))),"previous_checkpoint_digest":null}).to_string()).unwrap();
    let signature = signing.sign(head.as_bytes()).as_ref().to_vec();
    let mut files: Files = [
        ("ledger.ndjson".into(), ledger.into_bytes()),
        ("checkpoint.json".into(), head.clone().into_bytes()),
        ("checkpoint.sig".into(), signature.clone()),
    ]
    .into();
    for (hash, body) in artifacts {
        files.insert(format!("artifacts/{hash}.json"), body);
    }
    if with_chain {
        files.insert(
            "checkpoints.ndjson".into(),
            format!(
                "{}\n",
                json!({"statement":head,"signature":hex::encode(signature)})
            )
            .into_bytes(),
        );
    }
    if with_cose {
        files = self::with_cose(files, 7, false);
    }
    verify(&seal(files).unwrap(), Some(pin(&signing))).unwrap()
}
#[test]
fn principal_bundle_and_cose_statement_coexist() {
    let report = principal_bundle_report(true, true);
    assert_eq!(report.actions.principals.len(), 1);
    assert_eq!(report.actions.replayed, 1);
    let text = report.to_string();
    assert!(text.contains("COSE statement: true"));
    assert!(text.contains("1 signed checkpoints"));
    assert!(text.contains("principal evidence is a gateway assertion; IdP token omitted"));
}
#[test]
fn principal_bundle_and_checkpoint_chain_coexist() {
    let report = principal_bundle_report(true, false);
    assert_eq!(report.actions.principals.len(), 1);
    assert_eq!(report.actions.replayed, 1);
    assert!(report.to_string().contains("1 signed checkpoints"));
}
#[test]
fn principal_bundle_reports_verified_identity() {
    let report = principal_bundle_report(false, false);
    assert_eq!(report.actions.principals.len(), 1);
    assert_eq!(report.actions.replayed, 1);
    let text = report.to_string();
    assert!(text.contains("gateway-attested principals: 1"));
    assert!(text.contains("principal evidence is a gateway assertion; IdP token omitted"));
    assert!(text.contains("https://issuer.example"));
    assert!(text.contains("treasury"));
    assert!(text.contains(&"b".repeat(64)));
}

fn with_cose(mut files: Files, signer: u8, flip: bool) -> Files {
    let mut cose = crate::action::cose::sign1(&files["checkpoint.json"], |m| {
        key(signer).sign(m).as_ref().to_vec()
    })
    .unwrap();
    if flip {
        cose[1] ^= 1;
    }
    files.insert("checkpoint.cose".into(), cose);
    files
}
#[test]
fn cose_bundle_roundtrip() {
    let (files, pin) = fixture("{}");
    let report = verify(&seal(with_cose(files, 7, false)).unwrap(), Some(pin)).unwrap();
    assert!(report.cose_statement);
    assert_eq!(
        serde_json::to_value(&report).unwrap()["cose_statement"],
        true
    );
}
#[test]
fn cose_absent_bundle_still_verifies() {
    let (files, pin) = fixture("{}");
    let report = verify(&seal(files).unwrap(), Some(pin)).unwrap();
    assert!(!report.cose_statement);
    assert_eq!(
        serde_json::to_value(&report).unwrap()["cose_statement"],
        false
    );
}
#[test]
fn cose_report_text() {
    let (files, pin) = fixture("{}");
    let absent = verify(&seal(files.clone()).unwrap(), Some(pin)).unwrap();
    assert!(absent.to_string().contains("; COSE statement: false;"));
    let present = verify(&seal(with_cose(files, 7, false)).unwrap(), Some(pin)).unwrap();
    assert!(present.to_string().contains("; COSE statement: true;"));
}
#[test]
fn cose_bad_signature_is_trust_failure() {
    let (files, pin) = fixture("{}");
    failure_is(
        &seal(with_cose(files, 8, false)).unwrap(),
        Some(pin),
        5,
        "checkpoint.cose does not verify under external pin",
    );
}
#[test]
fn cose_malformed_is_format_failure() {
    let (files, pin) = fixture("{}");
    failure_is(
        &seal(with_cose(files, 7, true)).unwrap(),
        Some(pin),
        4,
        "checkpoint.cose: not the expected COSE_Sign1 encoding of checkpoint.json",
    );
}
// ── Checkpoint chain (`checkpoints.ndjson`) ──────────────────────────────
/// Chain of signed statements `(created_at, seq)`; the last becomes the covering head. `edit`
/// may tamper with (statement, signature) pairs after signing.
fn chained(
    points: &[(&str, u64)],
    edit: impl FnOnce(&mut Vec<(String, Vec<u8>)>),
) -> (Files, [u8; 32]) {
    let hashed: Vec<(&str, u64, Option<String>)> =
        points.iter().map(|(t, q)| (*t, *q, None)).collect();
    chained_hashes(&hashed, edit)
}
/// As `chained`, with an optional head-hash override per point (for equivocation cases).
fn chained_hashes(
    points: &[(&str, u64, Option<String>)],
    edit: impl FnOnce(&mut Vec<(String, Vec<u8>)>),
) -> (Files, [u8; 32]) {
    let (mut files, pin) = fixture("{}");
    let k = key(7);
    let head: Value = serde_json::from_slice(&files["checkpoint.json"]).unwrap();
    let mut prev: Option<String> = None;
    let mut lines = Vec::new();
    for (at, seq, forced) in points {
        let hash = match forced {
            Some(h) => json!(h),
            None if *seq == 2 => head["head_hash"].clone(),
            None => json!(format!("{seq:064}")),
        };
        let s = canonical_json(&json!({"domain":"tracelane.action-head.v1","schema_version":1,"tenant_id":head["tenant_id"],"seq":seq.to_string(),"head_hash":hash,"created_at":at,"key_id":head["key_id"],"previous_checkpoint_digest":prev}).to_string()).unwrap();
        prev = Some(hex::encode(crate::sha256(s.as_bytes())));
        let sig = k.sign(s.as_bytes()).as_ref().to_vec();
        lines.push((s, sig));
    }
    let (last, sig) = lines.last().cloned().unwrap();
    files.insert("checkpoint.json".into(), last.into_bytes());
    files.insert("checkpoint.sig".into(), sig);
    edit(&mut lines);
    let ndjson: String = lines
        .iter()
        .map(|(s, sig)| format!("{}\n", json!({"statement":s,"signature":hex::encode(sig)})))
        .collect();
    files.insert("checkpoints.ndjson".into(), ndjson.into_bytes());
    (files, pin)
}
const BEATS: &[(&str, u64)] = &[
    ("2026-10-30T12:00:00Z", 1),
    ("2026-10-30T12:10:00Z", 1),
    ("2026-10-30T12:20:00Z", 2),
    ("2026-10-30T14:20:00Z", 2),
];
fn chain_failure(edit: impl FnOnce(&mut Vec<(String, Vec<u8>)>), code: u8, detail: &str) {
    let (files, pin) = chained(BEATS, edit);
    failure_is(&seal(files).unwrap(), Some(pin), code, detail);
}
#[test]
fn chain_reports_count_interval_and_gaps() {
    let (files, pin) = chained(BEATS, |_| {});
    let zip = seal(files).unwrap();
    let r = verify_with_options(
        &zip,
        Some(pin),
        &[],
        Some(std::time::Duration::from_secs(900)),
    )
    .unwrap();
    let c = r.checkpoint_chain.as_ref().unwrap();
    assert_eq!(c.checkpoints, 4);
    assert_eq!(c.max_interval_secs, Some(7200));
    assert_eq!(c.gaps.len(), 1);
    assert_eq!(c.gaps[0].from.to_rfc3339(), "2026-10-30T12:20:00+00:00");
    assert_eq!(c.gaps[0].to.to_rfc3339(), "2026-10-30T14:20:00+00:00");
    assert!(r.to_string().contains("4 signed checkpoints"), "{r}");
    assert!(r.to_string().contains("gaps: 1"), "{r}");
    // No maximum given: the interval is still reported, nothing is called a gap.
    let r = verify(&zip, Some(pin)).unwrap();
    assert!(r.checkpoint_chain.unwrap().gaps.is_empty());
}
#[test]
fn chain_absent_in_older_bundle() {
    let (files, pin) = fixture("{}");
    let r = verify(&seal(files).unwrap(), Some(pin)).unwrap();
    assert!(r.checkpoint_chain.is_none());
    assert!(r.to_string().contains("checkpoint chain: absent"));
}
#[test]
fn chain_dropped_checkpoint_breaks_link() {
    chain_failure(
        |l| {
            l.remove(1);
        },
        4,
        "checkpoint chain link broken",
    );
}
#[test]
fn chain_reordered_fails() {
    chain_failure(|l| l.swap(1, 2), 4, "checkpoint chain link broken");
}
#[test]
fn chain_forged_signature_is_trust_failure() {
    chain_failure(
        |l| l[1].1[0] ^= 1,
        5,
        "chain checkpoint does not verify under external pin",
    );
}
#[test]
fn chain_other_key_is_trust_failure() {
    let other = key(9);
    chain_failure(
        |l| l[0].1 = other.sign(l[0].0.as_bytes()).as_ref().to_vec(),
        5,
        "chain checkpoint does not verify under external pin",
    );
}
#[test]
fn chain_must_end_at_covering_head() {
    chain_failure(
        |l| {
            l.pop();
        },
        4,
        "checkpoint chain does not end at the covering head",
    );
}
#[test]
fn chain_window_reports_its_start() {
    // A windowed export starts mid-chain: allowed, and the report says where it starts.
    let (files, pin) = chained(BEATS, |l| {
        l.remove(0);
    });
    let r = verify(&seal(files).unwrap(), Some(pin)).unwrap();
    let c = r.checkpoint_chain.as_ref().unwrap();
    assert_eq!(c.checkpoints, 3);
    assert!(!c.from_genesis);
    assert_eq!(
        c.chain_start.unwrap().to_rfc3339(),
        "2026-10-30T12:10:00+00:00"
    );
    assert!(
        r.to_string()
            .contains("window starts at 2026-10-30T12:10:00"),
        "{r}"
    );
    let (files, pin) = chained(BEATS, |_| {});
    let r = verify(&seal(files).unwrap(), Some(pin)).unwrap();
    assert!(r.checkpoint_chain.unwrap().from_genesis);
}
#[test]
fn chain_stripped_with_max_gap_fails() {
    // The manifest is unsigned: dropping the member must not turn a requested gap check into a pass.
    let (files, pin) = fixture("{}");
    let error = verify_with_options(
        &seal(files).unwrap(),
        Some(pin),
        &[],
        Some(std::time::Duration::from_secs(900)),
    )
    .unwrap_err();
    assert_eq!(error.code, 4);
    assert!(
        error
            .detail
            .contains("--max-gap requires checkpoints.ndjson"),
        "{error}"
    );
}
#[test]
fn chain_empty_member_fails() {
    let (mut files, pin) = chained(BEATS, |_| {});
    files.insert("checkpoints.ndjson".into(), Vec::new());
    failure_is(
        &seal(files).unwrap(),
        Some(pin),
        4,
        "checkpoint chain does not end at the covering head",
    );
}
#[test]
fn chain_duplicated_line_fails() {
    chain_failure(
        |l| {
            let dup = l[1].clone();
            l.insert(2, dup);
        },
        4,
        "checkpoint chain link broken",
    );
}
#[test]
fn chain_time_regression_fails() {
    let (files, pin) = chained(
        &[("2026-10-30T12:10:00Z", 1), ("2026-10-30T12:00:00Z", 2)],
        |_| {},
    );
    failure_is(
        &seal(files).unwrap(),
        Some(pin),
        4,
        "checkpoint time regressed",
    );
}
#[test]
fn chain_sequence_regression_fails() {
    let (files, pin) = chained(
        &[
            ("2026-10-30T12:00:00Z", 2),
            ("2026-10-30T12:10:00Z", 1),
            ("2026-10-30T12:20:00Z", 2),
        ],
        |_| {},
    );
    failure_is(
        &seal(files).unwrap(),
        Some(pin),
        4,
        "checkpoint sequence regressed",
    );
}
#[test]
fn chain_equivocation_at_equal_sequence_fails() {
    // Two signed statements for seq 1 with different head hashes; the covering head (seq 2) and
    // the ledger are untouched, so only the equal-sequence check can refuse this.
    let (files, pin) = chained_hashes(
        &[
            ("2026-10-30T12:00:00Z", 1, None),
            ("2026-10-30T12:10:00Z", 1, Some("f".repeat(64))),
            ("2026-10-30T12:20:00Z", 2, None),
        ],
        |_| {},
    );
    failure_is(
        &seal(files).unwrap(),
        Some(pin),
        4,
        "checkpoint head conflict at equal sequence",
    );
}
#[test]
fn chain_timestamp_must_name_a_chain_checkpoint() {
    let (mut files, pin) = chained(BEATS, |_| {});
    files.insert(
        format!("timestamps/{}.tsr", "0".repeat(64)),
        vec![0x30, 0x00],
    );
    failure_is(
        &seal(files).unwrap(),
        Some(pin),
        4,
        "timestamp names no chain checkpoint",
    );
}
#[test]
fn chain_unexpected_member_refused() {
    let (mut files, pin) = chained(BEATS, |_| {});
    files.insert("timestamps/short.tsr".into(), vec![0]);
    failure_is(
        &seal(files).unwrap(),
        Some(pin),
        4,
        "unexpected bundle member",
    );
}
// The browser verifier (packages/verifier-wasm) tests against these checked-in files.
// Regenerate: TRACELANE_WRITE_FIXTURES=1 cargo test -p tracelane-audit-verifier browser_fixtures
#[test]
fn browser_fixtures_are_current() {
    let (files, pin) = fixture("{}");
    let good = seal(files).unwrap();
    let mut members = unpack(&good).unwrap();
    let ledger = String::from_utf8(members["ledger.ndjson"].clone()).unwrap();
    members.insert(
        "ledger.ndjson".into(),
        ledger.replacen("12:00:00Z", "12:00:01Z", 1).into_bytes(),
    );
    let tampered = pack(&members).unwrap();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../verifier-wasm/fixtures");
    for (name, bytes) in [
        ("good.zip", good),
        ("tampered.zip", tampered),
        (
            "workspace.pub",
            format!("{}\n", hex::encode(pin)).into_bytes(),
        ),
    ] {
        let path = dir.join(name);
        if std::env::var_os("TRACELANE_WRITE_FIXTURES").is_some() {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(&path, &bytes).unwrap();
        }
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "stale fixture {name}");
    }
}
#[path = "tree_tests.rs"]
mod tree_tests;

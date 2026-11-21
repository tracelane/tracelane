//! Signed-head contract fixtures built from synthetic rows and dummy keys only.
use super::*;
use crate::action::tree;

fn rows(count: usize) -> (String, Vec<[u8; 32]>, Vec<[u8; 32]>) {
    let tenant = Uuid::from_u128(1);
    let mut previous = crate::genesis_v2(tenant.as_bytes());
    let mut ledger = String::new();
    let mut hashes = Vec::new();
    let mut leaves = Vec::new();
    for seq in 0..count {
        let hash = crate::row_hash_v2(
            &previous,
            tenant.as_bytes(),
            seq as u64,
            "fixture",
            "test",
            "{}",
        );
        let row = json!({"format":"v2.1","tenant_id":tenant,"seq":seq,"event_time":"2026-11-20T00:00:00Z","event_type":"fixture","actor":"test","payload":"{}","prev_hash":hex::encode(previous),"row_hash":hex::encode(hash)});
        ledger.push_str(&format!("{row}\n"));
        hashes.push(hash);
        leaves.push(tree::leaf_hash(&hash));
        previous = hash;
    }
    (ledger, hashes, leaves)
}
fn statement(
    version: u32,
    hashes: &[[u8; 32]],
    leaves: &[[u8; 32]],
    previous: Option<String>,
) -> Value {
    let mut value = json!({"domain":"tracelane.action-head.v1","schema_version":version,"tenant_id":Uuid::from_u128(1),"seq":hashes.len().checked_sub(1).map(|n|n.to_string()),"head_hash":hashes.last().map(hex::encode),"created_at":"2026-11-20T00:00:00Z","key_id":hex::encode(crate::sha256(&pin(&key(7)))),"previous_checkpoint_digest":previous});
    if version == 2 {
        value["tree_size"] = json!(leaves.len().to_string());
        value["tree_root"] = json!(hex::encode(tree::root(leaves)));
    }
    value
}
fn signed(value: &Value) -> (String, Vec<u8>) {
    let text = canonical_json(&value.to_string()).unwrap();
    let signature = key(7).sign(text.as_bytes()).as_ref().to_vec();
    (text, signature)
}
fn synthetic(
    count: usize,
    version: u32,
    note: bool,
    chain: bool,
    fields: impl FnOnce(&mut Value),
) -> (Vec<u8>, [u8; 32]) {
    let (ledger, hashes, leaves) = rows(count);
    let mut head = statement(version, &hashes, &leaves, None);
    fields(&mut head);
    let (text, signature) = signed(&head);
    let mut files: Files = [
        ("ledger.ndjson".into(), ledger.into_bytes()),
        ("checkpoint.json".into(), text.as_bytes().to_vec()),
        ("checkpoint.sig".into(), signature.clone()),
    ]
    .into();
    if chain {
        files.insert(
            "checkpoints.ndjson".into(),
            format!(
                "{}\n",
                json!({"statement":text,"signature":hex::encode(signature)})
            )
            .into_bytes(),
        );
    }
    if note {
        let origin = tree::origin(Uuid::from_u128(1));
        let body = tree::checkpoint_body(&origin, count as u64, &tree::root(&leaves));
        let signature = key(7).sign(body.as_bytes());
        let text = tree::signed_note(&body, &origin, &pin(&key(7)), signature.as_ref());
        files.insert(tree::MEMBER.into(), text.into_bytes());
    }
    (seal(files).unwrap(), pin(&key(7)))
}
#[test]
fn signed_head_v2_accepts_bound_synthetic_checkpoint() {
    let (bundle, pin) = synthetic(3, 2, true, false, |_| {});
    let report = verify(&bundle, Some(pin)).expect("valid schema-2 signed tree head must verify");
    assert_eq!(report.tree_size, Some(3));
}
#[test]
fn signed_head_v2_contract_matrix_56_cases() {
    let mut failures = Vec::new();
    let mut count = 0;
    for size in [0, 1, 2, 3, 7, 8, 9] {
        for version in [1, 2] {
            for note in [false, true] {
                for chain in [false, true] {
                    let (bundle, pin) = synthetic(size, version, note, chain, |_| {});
                    let result = verify(&bundle, Some(pin));
                    let accepted = version == 1 || note;
                    if result.is_ok() != accepted {
                        failures.push(format!(
                            "size={size} version={version} note={note} chain={chain}: {result:?}"
                        ));
                    } else if let Ok(report) = result {
                        assert_eq!(report.rows, size as u64);
                        assert_eq!(report.tree_size, note.then_some(size as u64));
                        assert_eq!(report.checkpoint_chain.is_some(), chain);
                    }
                    count += 1;
                }
            }
        }
    }
    assert_eq!(count, 56);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
#[test]
fn signed_head_v2_missing_note_is_evidence_failure() {
    let (bundle, pin) = synthetic(3, 2, false, false, |_| {});
    let error = verify(&bundle, Some(pin)).unwrap_err();
    assert_eq!(error.code, 4);
    assert_eq!(
        error.detail,
        "signed tree head requires tree-checkpoint.note"
    );
}
#[test]
fn signed_head_v2_invalid_field_contracts() {
    let cases: Vec<(&str, &str, Option<Value>)> = vec![
        ("size missing", "tree_size", None),
        ("root missing", "tree_root", None),
        ("size null", "tree_size", Some(Value::Null)),
        ("root null", "tree_root", Some(Value::Null)),
        ("size numeric", "tree_size", Some(json!(3))),
        ("size negative", "tree_size", Some(json!("-1"))),
        ("size zero padded", "tree_size", Some(json!("03"))),
        ("size plus", "tree_size", Some(json!("+3"))),
        ("size whitespace", "tree_size", Some(json!(" 3"))),
        (
            "size overflow",
            "tree_size",
            Some(json!("18446744073709551616")),
        ),
        ("size mismatch", "tree_size", Some(json!("4"))),
        ("size zero mismatch", "tree_size", Some(json!("0"))),
        ("root short", "tree_root", Some(json!("00"))),
        ("root long", "tree_root", Some(json!("0".repeat(66)))),
        ("root uppercase", "tree_root", Some(json!("A".repeat(64)))),
        ("root nonhex", "tree_root", Some(json!("g".repeat(64)))),
        (
            "root inconsistent",
            "tree_root",
            Some(json!("0".repeat(64))),
        ),
        ("unknown version", "schema_version", Some(json!(3))),
        (
            "wrong purpose",
            "domain",
            Some(json!("example.invalid/other-purpose")),
        ),
        ("unknown field", "unexpected", Some(json!(true))),
    ];
    for (name, field, value) in cases {
        let (bundle, pin) = synthetic(3, 2, true, false, |head| {
            if let Some(value) = value {
                head[field] = value;
            } else {
                head.as_object_mut().unwrap().remove(field);
            }
        });
        let error = verify(&bundle, Some(pin)).expect_err(name);
        assert_eq!(error.code, 4, "{name}: {error}");
    }
}
#[test]
fn signed_head_v1_keeps_its_exact_field_contract() {
    for field in ["tree_size", "tree_root"] {
        let (bundle, pin) = synthetic(3, 1, true, false, |head| {
            head[field] = Value::Null;
        });
        assert_eq!(verify(&bundle, Some(pin)).unwrap_err().code, 4);
    }
}

fn synthetic_chain(
    entries: &[(u32, usize)],
    windowed: bool,
    fields: impl Fn(usize, &mut Value),
) -> (Vec<u8>, [u8; 32]) {
    let count = entries.last().unwrap().1;
    let (ledger, hashes, leaves) = rows(count);
    let mut previous = windowed.then(|| "1".repeat(64));
    let mut lines = String::new();
    let mut last = None;
    for (index, &(version, size)) in entries.iter().enumerate() {
        let mut head = statement(version, &hashes[..size], &leaves[..size], previous);
        head["created_at"] = json!(format!("2026-11-20T00:0{index}:00Z"));
        fields(index, &mut head);
        let (text, signature) = signed(&head);
        previous = Some(hex::encode(crate::sha256(text.as_bytes())));
        lines.push_str(&format!(
            "{}\n",
            json!({"statement":text,"signature":hex::encode(&signature)})
        ));
        last = Some((text, signature));
    }
    let (text, signature) = last.unwrap();
    let origin = tree::origin(Uuid::from_u128(1));
    let body = tree::checkpoint_body(&origin, count as u64, &tree::root(&leaves));
    let note_signature = key(7).sign(body.as_bytes());
    let note = tree::signed_note(&body, &origin, &pin(&key(7)), note_signature.as_ref());
    let files: Files = [
        ("ledger.ndjson".into(), ledger.into_bytes()),
        ("checkpoint.json".into(), text.into_bytes()),
        ("checkpoint.sig".into(), signature),
        ("checkpoints.ndjson".into(), lines.into_bytes()),
        (tree::MEMBER.into(), note.into_bytes()),
    ]
    .into();
    (seal(files).unwrap(), pin(&key(7)))
}
#[test]
fn signed_head_v2_mixed_history_and_heartbeats() {
    let cases: &[&[(u32, usize)]] = &[
        &[(1, 0), (1, 1), (2, 3)],
        &[(1, 1), (2, 1), (2, 3)],
        &[(2, 0), (2, 0), (2, 3)],
        &[(2, 1), (2, 1), (2, 3)],
        &[(2, 1), (2, 2), (2, 3)],
        &[(2, 0), (2, 0), (2, 0)],
    ];
    for entries in cases {
        for windowed in [false, true] {
            let (bundle, pin) = synthetic_chain(entries, windowed, |_, _| {});
            let result = verify(&bundle, Some(pin));
            let report = result.unwrap_or_else(|e| panic!("{entries:?} windowed={windowed}: {e}"));
            let chain = report.checkpoint_chain.unwrap();
            assert_eq!(chain.checkpoints, entries.len() as u64);
            assert_eq!(chain.from_genesis, !windowed);
        }
    }
}
#[test]
fn signed_head_v2_intermediate_prefix_root_must_match_rows() {
    let (bundle, pin) = synthetic_chain(&[(2, 1), (2, 2), (2, 3)], false, |index, head| {
        if index == 1 {
            head["tree_root"] = json!("0".repeat(64));
        }
    });
    let error = verify(&bundle, Some(pin)).unwrap_err();
    assert_eq!(error.code, 4);
    assert_eq!(
        error.detail,
        "signed tree head does not match ledger prefix"
    );
}
#[test]
fn signed_head_v2_cannot_downgrade_in_chain() {
    let (bundle, pin) = synthetic_chain(&[(2, 1), (1, 2), (2, 3)], false, |_, _| {});
    let error = verify(&bundle, Some(pin)).unwrap_err();
    assert_eq!(error.code, 4);
    assert_eq!(error.detail, "checkpoint tree schema regressed");
}
#[test]
fn signed_head_v2_empty_root_mismatch_is_refused() {
    // Size 0 must carry SHA-256("") as its root; any other root is evidence failure.
    let (bundle, pin) = synthetic(0, 2, true, true, |head| {
        head["tree_root"] = json!("1".repeat(64));
    });
    let error = verify(&bundle, Some(pin)).unwrap_err();
    assert_eq!(error.code, 4);
    assert_eq!(error.detail, "invalid signed empty tree");
}
#[test]
fn signed_head_v2_equal_head_root_mismatch_is_refused() {
    // A heartbeat repeating size 1 must repeat its root; a different root at the same size fails.
    let (bundle, pin) = synthetic_chain(&[(2, 1), (2, 1), (2, 3)], false, |index, head| {
        if index == 1 {
            head["tree_root"] = json!("0".repeat(64));
        }
    });
    let error = verify(&bundle, Some(pin)).unwrap_err();
    assert_eq!(error.code, 4);
    assert_eq!(
        error.detail,
        "signed tree head does not match ledger prefix"
    );
}

#[test]
fn signed_head_prefix_roots_match_reference_at_every_boundary() {
    let (_, _, leaves) = rows(257);
    let mut frontier = tree::PrefixRoots::default();
    for size in 0..=leaves.len() {
        let expected = tree::root(&leaves[..size]);
        assert_eq!(frontier.at(&leaves, size as u64).unwrap(), expected);
        // Unchanged-head heartbeats do not consume leaves a second time.
        assert_eq!(frontier.at(&leaves, size as u64).unwrap(), expected);
    }
    assert!(frontier.at(&leaves, 256).is_err());
    assert!(frontier.at(&leaves, 258).is_err());
    let mut skipped = tree::PrefixRoots::default();
    for size in [0, 1, 3, 7, 8, 15, 16, 129, 256, 257] {
        assert_eq!(
            skipped.at(&leaves, size as u64).unwrap(),
            tree::root(&leaves[..size])
        );
    }
}
#[test]
fn signed_head_v2_internal_parse_state_is_not_a_wire_field() {
    let (bundle, pin) = synthetic(3, 2, true, false, |head| {
        head["tree"] = json!([3, "internal"]);
    });
    assert_eq!(verify(&bundle, Some(pin)).unwrap_err().code, 4);
}
#[test]
fn signed_head_v2_trust_pin_still_controls_acceptance() {
    let (bundle, _) = synthetic(3, 2, true, true, |_| {});
    assert_eq!(verify(&bundle, Some(pin(&key(8)))).unwrap_err().code, 5);
    assert_eq!(verify(&bundle, None).unwrap_err().code, 5);
}

#[test]
fn signed_head_v2_intermediate_row_hash_must_match_rows() {
    for windowed in [false, true] {
        let (bundle, pin) = synthetic_chain(&[(2, 1), (2, 2), (2, 3)], windowed, |index, head| {
            if index == 1 {
                head["head_hash"] = json!("0".repeat(64));
            }
        });
        let error = verify(&bundle, Some(pin)).unwrap_err();
        assert_eq!(error.code, 4);
        assert_eq!(
            error.detail,
            "signed checkpoint hash does not match ledger row"
        );
    }
}

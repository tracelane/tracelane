//! AUD-06: the optional `tree-checkpoint.note` member, on the shared bundle fixture.
use super::*;

// AUD-06: a C2SP checkpoint note over the ledger rows (minus `drop_last`), signed
// by key `signer` for tenant `tenant`.
fn with_tree(mut files: Files, signer: u8, tenant: u128, drop_last: usize) -> Files {
    use crate::action::tree;
    let mut leaves = tree::ledger_leaves(&files["ledger.ndjson"]).unwrap();
    leaves.truncate(leaves.len() - drop_last);
    let (signer, origin) = (key(signer), tree::origin(Uuid::from_u128(tenant)));
    let body = tree::checkpoint_body(&origin, leaves.len() as u64, &tree::root(&leaves));
    let signature = signer.sign(body.as_bytes());
    let note = tree::signed_note(&body, &origin, &pin(&signer), signature.as_ref());
    files.insert(tree::MEMBER.into(), note.into_bytes());
    files
}
#[test]
fn tree_checkpoint_reported() {
    let (files, pin) = fixture("{}");
    let leaves = crate::action::tree::ledger_leaves(&files["ledger.ndjson"]).unwrap();
    let report = verify(&seal(with_tree(files, 7, 1, 0)).unwrap(), Some(pin)).unwrap();
    assert_eq!(report.tree_size, Some(3));
    let root = hex::encode(crate::action::tree::root(&leaves));
    assert_eq!(report.tree_root.as_deref(), Some(root.as_str()));
    let text = report.to_string();
    assert!(
        text.contains(&format!("; tree checkpoint: size 3 root {root};")),
        "{text}"
    );
    assert_eq!(serde_json::to_value(&report).unwrap()["tree_size"], 3);
}
#[test]
fn tree_checkpoint_absent() {
    let (files, pin) = fixture("{}");
    let report = verify(&seal(files).unwrap(), Some(pin)).unwrap();
    assert_eq!((report.tree_size, report.tree_root.as_ref()), (None, None));
    let text = report.to_string();
    assert!(text.contains("; tree checkpoint: absent;"), "{text}");
    assert!(serde_json::to_value(&report).unwrap()["tree_root"].is_null());
}
#[test]
fn tree_checkpoint_root_mismatch() {
    let (files, pin) = fixture("{}");
    // Correctly signed by the pinned key, but over a shorter tree than the ledger rows.
    failure_is(
        &seal(with_tree(files, 7, 1, 1)).unwrap(),
        Some(pin),
        4,
        "tree checkpoint does not match the ledger rows",
    );
    // Same size, different leaves: a validly signed note taken from another ledger.
    let (files, pin) = fixture("{}");
    let (other, _) = fixture("{\"a\":1}");
    let note = with_tree(other, 7, 1, 0).remove(crate::action::tree::MEMBER);
    let mut files = with_tree(files, 7, 1, 0);
    assert_ne!(files[crate::action::tree::MEMBER], *note.as_ref().unwrap());
    files.insert(crate::action::tree::MEMBER.into(), note.unwrap());
    failure_is(
        &seal(files).unwrap(),
        Some(pin),
        4,
        "tree checkpoint does not match the ledger rows",
    );
}
#[test]
fn tree_checkpoint_other_key() {
    let (files, pin) = fixture("{}");
    let error = verify(&seal(with_tree(files, 8, 1, 0)).unwrap(), Some(pin)).unwrap_err();
    assert_eq!(error.code, 5, "{error}");
    assert!(error.detail.starts_with("tree checkpoint: "), "{error}");
}
#[test]
fn tree_checkpoint_other_tenant() {
    let (files, pin) = fixture("{}");
    let error = verify(&seal(with_tree(files, 7, 2, 0)).unwrap(), Some(pin)).unwrap_err();
    assert_eq!(error.code, 5, "{error}");
    assert!(error.detail.starts_with("tree checkpoint: "), "{error}");
}

#[test]
fn tree_requirement_preserves_legacy_entry_points() {
    let (files, pin) = fixture("{}");
    let raw = seal(files).unwrap();
    assert!(verify(&raw, Some(pin)).unwrap().tree_size.is_none());
    assert!(
        verify_with_tree_requirement(&raw, Some(pin), &[], None, false)
            .unwrap()
            .tree_size
            .is_none()
    );
    let error = verify_with_tree_requirement(&raw, Some(pin), &[], None, true).unwrap_err();
    assert_eq!(error.code, 4);
    assert_eq!(error.detail, "required tree checkpoint is absent");
}

#[test]
fn tree_requirement_reports_absent_optional_timestamp_and_chain() {
    let (files, pin) = fixture("{}");
    let raw = seal(with_tree(files, 7, 1, 0)).unwrap();
    let missing_chain = verify_with_tree_requirement(
        &raw,
        Some(pin),
        &[],
        Some(std::time::Duration::from_secs(60)),
        true,
    )
    .unwrap_err();
    assert_eq!(missing_chain.code, 4);
    assert!(missing_chain.detail.contains("requires checkpoints.ndjson"));
    let report = verify_with_tree_requirement(&raw, Some(pin), &[], None, true).unwrap();
    assert_eq!(report.tree_size, Some(3));
    assert!(!report.timestamped);
    assert!(report.checkpoint_chain.is_none());
}

#[test]
fn tree_requirement_does_not_replace_external_trust() {
    let (files, _) = fixture("{}");
    let raw = seal(with_tree(files, 7, 1, 0)).unwrap();
    for pin in [None, Some([9; 32])] {
        assert_eq!(
            verify_with_tree_requirement(&raw, pin, &[], None, true)
                .unwrap_err()
                .code,
            5
        );
    }
}

#[test]
fn tree_requirement_accepts_verified_empty_tree_not_unknown() {
    let (mut files, pin) = fixture("{}");
    let mut head: serde_json::Value = serde_json::from_slice(&files["checkpoint.json"]).unwrap();
    head["seq"] = serde_json::Value::Null;
    head["head_hash"] = serde_json::Value::Null;
    let head = canonical_json(&head.to_string()).unwrap();
    files.insert(
        "checkpoint.sig".into(),
        key(7).sign(head.as_bytes()).as_ref().to_vec(),
    );
    files.insert("checkpoint.json".into(), head.into_bytes());
    files.insert("ledger.ndjson".into(), Vec::new());
    let raw = seal(with_tree(files, 7, 1, 0)).unwrap();
    let report = verify_with_tree_requirement(&raw, Some(pin), &[], None, true).unwrap();
    assert_eq!(report.tree_size, Some(0));
    assert_eq!(
        report.tree_root,
        Some(hex::encode(crate::action::tree::root(&[])))
    );
}

#[test]
fn tree_requirement_preserves_max_gap_bounds() {
    let (files, pin) = fixture("{}");
    let raw = seal(with_tree(files, 7, 1, 0)).unwrap();
    let error =
        verify_with_tree_requirement(&raw, Some(pin), &[], Some(std::time::Duration::MAX), true)
            .unwrap_err();
    assert_eq!(error.code, 4);
    assert_eq!(error.detail, "max_gap out of range");
}

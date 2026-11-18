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

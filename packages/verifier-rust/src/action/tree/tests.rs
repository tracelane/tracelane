use super::*;
use ring::signature::{Ed25519KeyPair, KeyPair};

fn leaves(n: usize) -> Vec<Hash> {
    (0..n).map(|i| leaf_hash(&[i as u8; 32])).collect()
}
fn key(seed: u8) -> (Ed25519KeyPair, [u8; 32]) {
    let key = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
    let pin = key.public_key().as_ref().try_into().unwrap();
    (key, pin)
}
fn note(seed: u8, origin: &str, size: u64, root: &Hash) -> (String, [u8; 32]) {
    let (key, pin) = key(seed);
    let body = checkpoint_body(origin, size, root);
    (
        signed_note(&body, origin, &pin, key.sign(body.as_bytes()).as_ref()),
        pin,
    )
}
fn signature_line(note: &str) -> &str {
    note.trim_end().rsplit('\n').next().unwrap()
}
const ORIGIN: &str = "tracelane.dev/action-ledger/00000000-0000-0000-0000-000000000001";
const EMPTY_ROOT: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// Reference leaves and roots from the certificate-transparency RFC 6962 test suite.
#[test]
fn rfc6962_reference_roots() {
    let data = [
        "",
        "00",
        "10",
        "2021",
        "3031",
        "40414243",
        "5051525354555657",
        "606162636465666768696a6b6c6d6e6f",
    ];
    let roots = [
        EMPTY_ROOT,
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ];
    let all: Vec<Hash> = data
        .iter()
        .map(|d| leaf_hash(&hex::decode(d).unwrap()))
        .collect();
    for (n, expected) in roots.iter().enumerate() {
        assert_eq!(hex::encode(root(&all[..n])), *expected, "size {n}");
    }
}
#[test]
fn inclusion_every_leaf() {
    for n in 1..=33 {
        let all = leaves(n);
        let top = root(&all);
        for (i, leaf) in all.iter().enumerate() {
            let proof = inclusion_proof(&all, i).unwrap();
            verify_inclusion(leaf, i as u64, n as u64, &proof, &top)
                .unwrap_or_else(|e| panic!("leaf {i} of {n}: {e}"));
        }
    }
}
#[test]
fn consistency_every_pair() {
    for n in 0..=33 {
        let all = leaves(n);
        for m in 0..=n {
            let proof = consistency_proof(&all, m).unwrap();
            verify_consistency(m as u64, n as u64, &root(&all[..m]), &root(&all), &proof)
                .unwrap_or_else(|e| panic!("{m} -> {n}: {e}"));
        }
    }
}
#[test]
fn single_leaf_empty_proof() {
    let all = leaves(1);
    assert!(inclusion_proof(&all, 0).unwrap().is_empty());
    assert_eq!(root(&all), all[0]);
    verify_inclusion(&all[0], 0, 1, &[], &all[0]).unwrap();
}
#[test]
fn checkpoint_roundtrip() {
    let top = root(&leaves(5));
    let (text, pin) = note(7, ORIGIN, 5, &top);
    assert!(text.starts_with(&format!("{ORIGIN}\n5\n")), "{text}");
    let cp = open_checkpoint(text.as_bytes(), ORIGIN, &pin).unwrap();
    assert_eq!((cp.origin.as_str(), cp.size, cp.root), (ORIGIN, 5, top));
}
#[test]
fn empty_tree_checkpoint() {
    let (text, pin) = note(7, ORIGIN, 0, &root(&[]));
    let cp = open_checkpoint(text.as_bytes(), ORIGIN, &pin).unwrap();
    assert_eq!(cp.size, 0);
    assert_eq!(hex::encode(cp.root), EMPTY_ROOT);
}
// Reference note and verifier key from golang.org/x/mod/sumdb/note (key hash c74f20a3).
#[test]
fn sumdb_reference_note() {
    let key = crate::base64_decode("ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW").unwrap();
    assert_eq!(key[0], 1, "Ed25519 signature type");
    let pin: [u8; 32] = key[1..].try_into().unwrap();
    assert_eq!(hex::encode(key_id("PeterNeumann", &pin)), "c74f20a3");
    let text = "If you think cryptography is the answer to your problem,\nthen you don't know what your problem is.\n\n\u{2014} PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n";
    let body = verify_note(text.as_bytes(), "PeterNeumann", &pin).unwrap();
    assert!(body.ends_with("your problem is.\n"));
}
#[test]
fn foreign_signature_ignored() {
    let top = root(&leaves(3));
    let (mut text, pin) = note(7, ORIGIN, 3, &top);
    let (witness, witness_pin) = key(9);
    let body = checkpoint_body(ORIGIN, 3, &top);
    let cosigned = signed_note(
        &body,
        "witness.example/w1",
        &witness_pin,
        witness.sign(body.as_bytes()).as_ref(),
    );
    text.push_str(signature_line(&cosigned));
    text.push('\n');
    assert_eq!(text.matches('\u{2014}').count(), 2);
    let cp = open_checkpoint(text.as_bytes(), ORIGIN, &pin).unwrap();
    assert_eq!(cp.size, 3);
}
#[test]
fn ledger_leaves_skip_anchors() {
    let a = hex::encode([1u8; 32]);
    let b = hex::encode([2u8; 32]);
    let ledger = format!(
        "{{\"seq\":0,\"row_hash\":\"{a}\"}}\n{{\"type\":\"anchor\",\"merkle_root\":\"x\"}}\n{{\"seq\":1,\"row_hash\":\"{b}\"}}\n"
    );
    assert_eq!(
        ledger_leaves(ledger.as_bytes()).unwrap(),
        vec![leaf_hash(&[1u8; 32]), leaf_hash(&[2u8; 32])]
    );
    assert!(ledger_leaves(b"{\"seq\":0,\"row_hash\":\"abcd\"}\n").is_err());
}

#[test]
fn inclusion_wrong_leaf() {
    let all = leaves(7);
    let proof = inclusion_proof(&all, 2).unwrap();
    assert!(verify_inclusion(&all[3], 2, 7, &proof, &root(&all)).is_err());
    assert!(verify_inclusion(&leaf_hash(b"absent"), 2, 7, &proof, &root(&all)).is_err());
}
#[test]
fn inclusion_wrong_index() {
    let all = leaves(7);
    let proof = inclusion_proof(&all, 2).unwrap();
    for index in [0, 1, 3, 6] {
        assert!(verify_inclusion(&all[2], index, 7, &proof, &root(&all)).is_err());
    }
}
#[test]
fn inclusion_index_out_of_range() {
    let all = leaves(4);
    assert!(inclusion_proof(&all, 4).is_err());
    let proof = inclusion_proof(&all, 3).unwrap();
    assert!(verify_inclusion(&all[3], 4, 4, &proof, &root(&all)).is_err());
    assert!(verify_inclusion(&all[3], 0, 0, &[], &root(&[])).is_err());
}
#[test]
fn inclusion_wrong_length() {
    let all = leaves(9);
    let top = root(&all);
    let mut proof = inclusion_proof(&all, 4).unwrap();
    let last = proof.pop().unwrap();
    assert!(verify_inclusion(&all[4], 4, 9, &proof, &top).is_err());
    proof.extend([last, last]);
    assert!(verify_inclusion(&all[4], 4, 9, &proof, &top).is_err());
}
#[test]
fn inclusion_wrong_root() {
    let all = leaves(6);
    let proof = inclusion_proof(&all, 1).unwrap();
    assert!(verify_inclusion(&all[1], 1, 6, &proof, &root(&all[..5])).is_err());
}
#[test]
fn consistency_rewritten_history() {
    let old = leaves(5);
    let mut new = leaves(9);
    new[1] = leaf_hash(b"rewritten");
    let proof = consistency_proof(&new, 5).unwrap();
    assert!(verify_consistency(5, 9, &root(&old), &root(&new), &proof).is_err());
    // The honest pair fails too once the claimed old root is swapped.
    let honest = leaves(9);
    let proof = consistency_proof(&honest, 5).unwrap();
    assert!(verify_consistency(5, 9, &root(&new[..5]), &root(&honest), &proof).is_err());
}
#[test]
fn consistency_old_larger() {
    let all = leaves(6);
    assert!(consistency_proof(&all, 7).is_err());
    assert!(verify_consistency(7, 6, &root(&all), &root(&all), &[]).is_err());
}
#[test]
fn consistency_wrong_shape() {
    let all = leaves(8);
    let top = root(&all);
    assert!(verify_consistency(8, 8, &top, &top, &[top]).is_err());
    assert!(verify_consistency(8, 8, &root(&all[..7]), &top, &[]).is_err());
    assert!(verify_consistency(3, 8, &root(&all[..3]), &top, &[]).is_err());
    assert!(verify_consistency(0, 8, &root(&[]), &top, &[top]).is_err());
    // An empty old tree has exactly one root; any other value is not a consistent history.
    verify_consistency(0, 8, &root(&[]), &top, &[]).unwrap();
    assert!(verify_consistency(0, 8, &top, &top, &[]).is_err());
    let mut proof = consistency_proof(&all, 3).unwrap();
    proof.push(top);
    assert!(verify_consistency(3, 8, &root(&all[..3]), &top, &proof).is_err());
}
#[test]
fn note_other_key() {
    let (text, _) = note(8, ORIGIN, 2, &root(&leaves(2)));
    let (_, pin) = key(7);
    assert!(open_checkpoint(text.as_bytes(), ORIGIN, &pin).is_err());
    // Right key id on the line, signature taken from a different body.
    let (good, pin) = note(7, ORIGIN, 2, &root(&leaves(2)));
    let (other, _) = note(7, ORIGIN, 3, &root(&leaves(3)));
    let forged = format!(
        "{}\n{}\n",
        checkpoint_body(ORIGIN, 2, &root(&leaves(2))),
        signature_line(&other)
    );
    assert_ne!(forged, good);
    assert!(open_checkpoint(forged.as_bytes(), ORIGIN, &pin).is_err());
}
#[test]
fn note_edited_body() {
    let (text, pin) = note(7, ORIGIN, 2, &root(&leaves(2)));
    let edited = text.replacen("\n2\n", "\n3\n", 1);
    assert_ne!(edited, text);
    assert!(open_checkpoint(edited.as_bytes(), ORIGIN, &pin).is_err());
}
#[test]
fn note_wrong_origin() {
    let other = "tracelane.dev/action-ledger/00000000-0000-0000-0000-000000000002";
    let (text, pin) = note(7, other, 2, &root(&leaves(2)));
    assert!(open_checkpoint(text.as_bytes(), ORIGIN, &pin).is_err());
    open_checkpoint(text.as_bytes(), other, &pin).unwrap();
}
#[test]
fn note_malformed() {
    let (key, pin) = key(7);
    let good = checkpoint_body(ORIGIN, 2, &root(&leaves(2)));
    let b64_root = good.lines().nth(2).unwrap();
    let sign = |body: &str| signed_note(body, ORIGIN, &pin, key.sign(body.as_bytes()).as_ref());
    for body in [
        format!("{ORIGIN}\n02\n{b64_root}\n"),
        format!("{ORIGIN}\n+2\n{b64_root}\n"),
        format!("{ORIGIN}\n2\n{}\n", &b64_root[..40]),
        format!("{ORIGIN}\n2\n{b64_root}\nextension\n"),
        format!("{ORIGIN}\n2\n"),
    ] {
        assert!(
            open_checkpoint(sign(&body).as_bytes(), ORIGIN, &pin).is_err(),
            "{body:?}"
        );
    }
    let text = sign(&good);
    open_checkpoint(text.as_bytes(), ORIGIN, &pin).unwrap();
    for bad in [
        good.clone(),
        text.trim_end().to_owned(),
        text.replace('\u{2014}', "-"),
        format!("{text}trailing"),
        text.replacen('\n', "\r\n", 1),
    ] {
        assert!(
            open_checkpoint(bad.as_bytes(), ORIGIN, &pin).is_err(),
            "{bad:?}"
        );
    }
    assert!(open_checkpoint(&[0xff, 0xfe], ORIGIN, &pin).is_err());
}
#[test]
fn note_signature_base64_must_be_canonical() {
    let (text, pin) = note(7, ORIGIN, 5, &root(&leaves(5)));
    let line = signature_line(&text);
    let (head, blob) = line.rsplit_once(' ').unwrap();
    // The same bytes, re-spelled: an inner space, and extra padding.
    let spaced = format!("{head} {} {}", &blob[..8], &blob[8..]);
    let padded = format!("{line}==");
    for bad in [spaced, padded] {
        let forged = text.replace(line, &bad);
        assert!(
            open_checkpoint(forged.as_bytes(), ORIGIN, &pin).is_err(),
            "{bad}"
        );
    }
}
#[test]
fn note_too_many_signatures() {
    let (mut text, pin) = note(7, ORIGIN, 2, &root(&leaves(2)));
    let line = signature_line(&text).to_owned();
    for _ in 0..MAX_SIGNATURES {
        text.push_str(&format!("{line}\n"));
    }
    assert!(open_checkpoint(text.as_bytes(), ORIGIN, &pin).is_err());
}

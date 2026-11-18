use super::*;
use ring::signature::{Ed25519KeyPair, KeyPair};
use uuid::Uuid;

fn key(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}
fn pin(key: &Ed25519KeyPair) -> [u8; 32] {
    key.public_key().as_ref().try_into().unwrap()
}
fn key_id(key: &Ed25519KeyPair) -> String {
    hex::encode(crate::sha256(&pin(key)))
}
fn statement(key: &Ed25519KeyPair, tenant: u128, pad: &str) -> Vec<u8> {
    crate::action::canonical_json(
        &serde_json::json!({"domain":DOMAIN,"schema_version":1,"tenant_id":Uuid::from_u128(tenant),"seq":null,"head_hash":null,"created_at":"2026-11-13T12:00:00.000Z","key_id":key_id(key),"previous_checkpoint_digest":pad})
            .to_string(),
    )
    .unwrap()
    .into_bytes()
}
const DOMAIN: &str = "tracelane.action-head.v1";
fn signed(key: &Ed25519KeyPair, statement: &[u8]) -> Vec<u8> {
    sign1(statement, |m| key.sign(m).as_ref().to_vec()).unwrap()
}
/// A message with arbitrary header and payload, validly signed: only the profile check can refuse it.
fn assemble(key: &Ed25519KeyPair, protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = envelope(protected, payload);
    bstr(
        &mut out,
        key.sign(&sig_structure(protected, payload)).as_ref(),
    );
    out
}
fn is_format(result: Result<(), Error>) {
    assert!(matches!(result, Err(Error::Format(_))), "{result:?}");
}
fn is_signature(result: Result<(), Error>) {
    assert!(matches!(result, Err(Error::Signature)), "{result:?}");
}

#[test]
fn sign1_roundtrip() {
    let k = key(7);
    let s = statement(&k, 1, "");
    verify(&signed(&k, &s), &s, &pin(&k)).unwrap();
}
#[test]
fn sign1_is_deterministic() {
    let k = key(7);
    let s = statement(&k, 1, "");
    assert_eq!(signed(&k, &s), signed(&k, &s));
}
#[test]
fn golden_protected_header_bytes() {
    // Written out by hand from RFC 8949 and the draft's CDDL, not with the encoder under test.
    let mut want = vec![0xa4, 0x01, 0x27, 0x03, 0x70];
    want.extend(b"application/json");
    want.extend([0x04, 0x58, 0x40]);
    want.extend("ab".repeat(32).as_bytes());
    want.extend([0x0f, 0xa2, 0x01, 0x78, 0x2d]);
    want.extend(b"urn:uuid:00000000-0000-0000-0000-000000000001");
    want.extend([0x02, 0x78, 0x18]);
    want.extend(DOMAIN.as_bytes());
    assert_eq!(
        hex::encode(protected_header(
            &"ab".repeat(32),
            &Uuid::from_u128(1),
            DOMAIN
        )),
        hex::encode(want)
    );
}
#[test]
fn long_statement_roundtrip() {
    let k = key(7);
    let s = statement(&k, 1, &"0".repeat(70_000));
    let cose = signed(&k, &s);
    verify(&cose, &s, &pin(&k)).unwrap();
    // 4-byte length head (major 2, additional 26) for a payload over 65535 bytes.
    assert!(
        cose.windows(5)
            .any(|w| w[0] == 0x5a && w[1..] == u32::try_from(s.len()).unwrap().to_be_bytes())
    );
}

#[test]
fn wrong_key_refused() {
    let k = key(7);
    let s = statement(&k, 1, "");
    is_signature(verify(&signed(&key(8), &s), &s, &pin(&k)));
}
#[test]
fn tampered_signature_refused() {
    let k = key(7);
    let s = statement(&k, 1, "");
    let mut cose = signed(&k, &s);
    *cose.last_mut().unwrap() ^= 1;
    is_signature(verify(&cose, &s, &pin(&k)));
}
#[test]
fn payload_differs_from_checkpoint_refused() {
    let k = key(7);
    let other = statement(&k, 1, "x");
    is_format(verify(&signed(&k, &other), &statement(&k, 1, ""), &pin(&k)));
}
#[test]
fn tampered_protected_header_refused() {
    let k = key(7);
    let s = statement(&k, 1, "");
    let mut protected = protected_header(&key_id(&k), &Uuid::from_u128(1), DOMAIN);
    protected[2] = 0x26; // alg -7 (ES256) instead of -8
    is_format(verify(&assemble(&k, &protected, &s), &s, &pin(&k)));
}
#[test]
fn untagged_message_refused() {
    let k = key(7);
    let s = statement(&k, 1, "");
    is_format(verify(&signed(&k, &s)[1..], &s, &pin(&k)));
}
#[test]
fn trailing_bytes_refused() {
    let k = key(7);
    let s = statement(&k, 1, "");
    let mut cose = signed(&k, &s);
    cose.push(0);
    is_format(verify(&cose, &s, &pin(&k)));
}
#[test]
fn truncated_refused() {
    let k = key(7);
    let s = statement(&k, 1, "");
    let cose = signed(&k, &s);
    for cut in [0, 1, cose.len() / 2, cose.len() - 1] {
        is_format(verify(&cose[..cut], &s, &pin(&k)));
    }
}
#[test]
fn detached_payload_refused() {
    let k = key(7);
    let s = statement(&k, 1, "");
    let protected = protected_header(&key_id(&k), &Uuid::from_u128(1), DOMAIN);
    let mut cose = vec![0xd2, 0x84];
    bstr(&mut cose, &protected);
    cose.extend([0xa0, 0xf6]); // {} then nil
    bstr(&mut cose, k.sign(&sig_structure(&protected, &s)).as_ref());
    is_format(verify(&cose, &s, &pin(&k)));
}
#[test]
fn nonempty_unprotected_header_refused() {
    let k = key(7);
    let s = statement(&k, 1, "");
    let protected = protected_header(&key_id(&k), &Uuid::from_u128(1), DOMAIN);
    let mut cose = vec![0xd2, 0x84];
    bstr(&mut cose, &protected);
    cose.extend([0xa1, 0x04, 0x41, 0x00]); // {4: h'00'}
    bstr(&mut cose, &s);
    bstr(&mut cose, k.sign(&sig_structure(&protected, &s)).as_ref());
    is_format(verify(&cose, &s, &pin(&k)));
}
#[test]
fn wrong_kid_refused() {
    let k = key(7);
    let s = statement(&k, 1, "");
    let protected = protected_header(&key_id(&key(8)), &Uuid::from_u128(1), DOMAIN);
    is_format(verify(&assemble(&k, &protected, &s), &s, &pin(&k)));
}
#[test]
fn wrong_issuer_refused() {
    let k = key(7);
    let s = statement(&k, 1, "");
    let protected = protected_header(&key_id(&k), &Uuid::from_u128(2), DOMAIN);
    is_format(verify(&assemble(&k, &protected, &s), &s, &pin(&k)));
}
#[test]
fn malformed_statement_refused() {
    let k = key(7);
    for bad in [&b"{}"[..], b"not json", b""] {
        assert!(sign1(bad, |m| k.sign(m).as_ref().to_vec()).is_err());
        is_format(verify(&[0xd2], bad, &pin(&k)));
    }
    // A signer that returns the wrong length never yields a member.
    assert!(sign1(&statement(&k, 1, ""), |_| vec![0; 63]).is_err());
}

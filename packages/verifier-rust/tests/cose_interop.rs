//! Interop proof for `checkpoint.cose`: an independent COSE implementation (`coset`) parses the
//! message and rebuilds the RFC 9052 `Sig_structure`, and `ed25519-dalek` checks the signature.
//! Nothing here calls the verifier under test; `sign1` only produces the bytes.
use coset::cbor::value::Value;
use coset::{CborSerializable, CoseSign1, Label, TaggedCborSerializable, iana};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

const TENANT: &str = "00000000-0000-0000-0000-000000000001";
const DOMAIN: &str = "tracelane.action-head.v1";

fn produced() -> (Vec<u8>, Vec<u8>, VerifyingKey, String) {
    let key = SigningKey::from_bytes(&[7; 32]);
    let key_id = hex::encode(Sha256::digest(key.verifying_key().as_bytes()));
    // Key order is already JCS order; the bytes are what a checkpoint.json holds.
    let statement = format!(
        r#"{{"created_at":"2026-11-13T12:00:00.000Z","domain":"{DOMAIN}","head_hash":null,"key_id":"{key_id}","previous_checkpoint_digest":null,"schema_version":1,"seq":null,"tenant_id":"{TENANT}"}}"#
    )
    .into_bytes();
    let cose = tracelane_audit_verifier::action::cose::sign1(&statement, |m| {
        key.sign(m).to_bytes().to_vec()
    })
    .unwrap();
    (cose, statement, key.verifying_key(), key_id)
}
fn dalek_verifies(message: &CoseSign1, key: &VerifyingKey) -> bool {
    message
        .verify_signature(b"", |sig, data| {
            key.verify_strict(data, &Signature::from_slice(sig)?)
        })
        .is_ok()
}

#[test]
fn coset_verifies_signature_with_dalek() {
    let (cose, _, key, _) = produced();
    let message = CoseSign1::from_tagged_slice(&cose).unwrap();
    assert!(dalek_verifies(&message, &key));
    let other = SigningKey::from_bytes(&[8; 32]).verifying_key();
    assert!(!dalek_verifies(&message, &other));
}

#[test]
fn coset_reads_scitt_headers() {
    let (cose, _, _, key_id) = produced();
    let message = CoseSign1::from_tagged_slice(&cose).unwrap();
    let header = &message.protected.header;
    assert_eq!(
        header.alg,
        Some(coset::RegisteredLabelWithPrivate::Assigned(
            iana::Algorithm::EdDSA
        ))
    );
    assert_eq!(
        header.content_type,
        Some(coset::ContentType::Text("application/json".into()))
    );
    assert_eq!(header.key_id, key_id.as_bytes());
    // CWT Claims header parameter (label 15) with iss (1) and sub (2), as the draft requires.
    assert_eq!(
        header.rest,
        vec![(
            Label::Int(15),
            Value::Map(vec![
                (
                    Value::from(1),
                    Value::from(format!("urn:uuid:{TENANT}").as_str())
                ),
                (Value::from(2), Value::from(DOMAIN)),
            ])
        )]
    );
    assert!(message.unprotected.is_empty(), "no receipt is claimed");
}

#[test]
fn coset_payload_equals_checkpoint() {
    let (cose, statement, _, _) = produced();
    assert_eq!(cose[0], 0xd2, "COSE_Sign1 tag 18");
    let message = CoseSign1::from_tagged_slice(&cose).unwrap();
    assert_eq!(message.payload.as_deref(), Some(statement.as_slice()));
    // Deterministic encoding: an independent re-encode gives the same bytes.
    assert_eq!(message.to_tagged_vec().unwrap(), cose);
    assert!(CoseSign1::from_slice(&cose).is_err(), "untagged parse");
}

#[test]
fn coset_rejects_tampered_payload() {
    let (cose, _, key, _) = produced();
    let mut message = CoseSign1::from_tagged_slice(&cose).unwrap();
    message.payload.as_mut().unwrap()[0] ^= 1;
    assert!(!dalek_verifies(&message, &key));
}

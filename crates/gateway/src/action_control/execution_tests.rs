use super::execution::*;
use super::*;

pub(super) fn signer() -> AttestationSigner {
    use base64::Engine;
    let der = ring::signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    AttestationSigner::from_pkcs8(SecretString::from(
        base64::engine::general_purpose::STANDARD.encode(der.as_ref()),
    ))
    .unwrap()
}
fn statement(s: &AttestationSigner) -> Attestation {
    let contract = policy::parse_contract(&json!({"tool_ref":Uuid::new_v4(),"server_id":Uuid::new_v4(),"tool_name":"pay","version":1,"protected":true,"fields":{"amount":{"path":"/amount_minor","kind":"minor_units","required":true,"evidence":"clear"},"currency":{"path":"/currency","kind":"currency","required":true,"evidence":"clear"}}}).to_string()).unwrap();
    let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
    let key = Uuid::new_v4();
    Attestation {
        principal_digest: None,
        domain: "tracelane.tool-execution.v1".into(),
        key_id: s.key_id(),
        tenant_id: *tenant.as_uuid(),
        execution_id: Uuid::new_v4(),
        action_id: Uuid::new_v4(),
        request_digest: policy::intent_digest(&tenant, key, &contract, 1, ARGS).unwrap(),
        idempotency_key: Uuid::new_v4(),
        exp: 200,
        agent_key_id: key,
        contract,
        policy_version: 1,
    }
}
pub(super) const ARGS: &str = r#"{"amount_minor":5000,"currency":"USD"}"#;
fn check(
    s: &AttestationSigner,
    a: &Attestation,
    header: Option<&str>,
    args: &str,
    now: i64,
) -> Result<Attestation> {
    verify(
        header,
        &s.public_key(),
        a.tenant_id,
        a.contract.server_id,
        "pay",
        args,
        now,
    )
}
#[test]
fn attestation_missing() {
    let s = signer();
    let a = statement(&s);
    assert!(
        check(&s, &a, None, ARGS, 100).is_err(),
        "direct call accepted"
    );
}
#[test]
fn attestation_tampered() {
    let s = signer();
    let a = statement(&s);
    let h = s.issue(&a).unwrap();
    assert!(
        check(
            &s,
            &a,
            Some(&h),
            r#"{"amount_minor":15000,"currency":"USD"}"#,
            100
        )
        .is_err(),
        "tampered payment accepted"
    );
}
#[test]
fn attestation_expired() {
    let s = signer();
    let a = statement(&s);
    let h = s.issue(&a).unwrap();
    assert!(
        check(&s, &a, Some(&h), ARGS, 200).is_err(),
        "expired attestation accepted"
    );
}
#[test]
fn attestation_valid() {
    let s = signer();
    let a = statement(&s);
    let h = s.issue(&a).unwrap();
    assert_eq!(
        check(&s, &a, Some(&h), ARGS, 100).unwrap().execution_id,
        a.execution_id
    );
}
#[test]
fn attestation_order() {
    let s = signer();
    let a = statement(&s);
    let h = s.issue(&a).unwrap();
    assert!(
        check(
            &s,
            &a,
            Some(&h),
            r#"{"currency":"USD", "amount_minor":5000}"#,
            100
        )
        .is_ok()
    );
}
#[test]
fn attestation_key() {
    let s = signer();
    let a = statement(&s);
    let h = s.issue(&a).unwrap();
    assert_eq!(a.key_id, sha(&s.public_key()));
    assert!(
        check(&signer(), &a, Some(&h), ARGS, 100).is_err(),
        "untrusted signer accepted"
    );
    let mut forged = h.into_bytes();
    let n = forged.len() - 3;
    forged[n] = if forged[n] == b'A' { b'B' } else { b'A' };
    assert!(
        check(
            &s,
            &a,
            Some(std::str::from_utf8(&forged).unwrap()),
            ARGS,
            100
        )
        .is_err(),
        "bad signature accepted"
    );
}
#[test]
fn attestation_identity() {
    let s = signer();
    let a = statement(&s);
    let h = s.issue(&a).unwrap();
    for (tenant, server, tool) in [
        (Uuid::new_v4(), a.contract.server_id, "pay"),
        (a.tenant_id, Uuid::new_v4(), "pay"),
        (a.tenant_id, a.contract.server_id, "Pay"),
    ] {
        assert!(
            verify(Some(&h), &s.public_key(), tenant, server, tool, ARGS, 100).is_err(),
            "foreign audience accepted"
        );
    }
    assert_eq!(
        check(&s, &a, Some(&h), ARGS, 100).unwrap().agent_key_id,
        a.agent_key_id
    );
}
#[test]
fn attestation_money() {
    let s = signer();
    let a = statement(&s);
    let h = s.issue(&a).unwrap();
    assert!(check(&s, &a, Some(&h), ARGS, 100).is_ok());
    for args in [
        r#"{"amount_minor":5000.0,"currency":"USD"}"#,
        r#"{"amount_minor":-1,"currency":"USD"}"#,
        r#"{"amount_minor":"5000","currency":"USD"}"#,
        r#"{"amount_minor":5000,"amount_minor":5000,"currency":"USD"}"#,
        r#"{"amount_minor":5000,"currency":"EUR"}"#,
    ] {
        assert!(
            check(&s, &a, Some(&h), args, 100).is_err(),
            "invalid money accepted"
        );
    }
}

#[test]
fn money_validation_errors() {
    let a = statement(&signer());
    for (raw, expected) in [
        (r#"{"currency":"USD"}"#, "field_missing"),
        (r#"{"amount_minor":-1,"currency":"USD"}"#, "amount_negative"),
        (
            r#"{"amount_minor":1.5,"currency":"USD"}"#,
            "amount_not_integer",
        ),
        (r#"{"amount_minor":1,"currency":"EUR"}"#, "currency_invalid"),
    ] {
        let error = policy::fields(&a.contract, &serde_json::from_str(raw).unwrap())
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            expected,
            "validation masked by digest mismatch"
        );
    }
    assert!(
        policy::intent_digest(
            &TenantId::from_jwt_claim(a.tenant_id),
            a.agent_key_id,
            &a.contract,
            1,
            r#"{"amount_minor":1.0,"currency":"USD"}"#
        )
        .is_err()
    );
}

#[test]
fn attestation_wire_rejections() {
    use base64::{
        Engine,
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let der = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(der.as_ref()).unwrap();
    let signer =
        AttestationSigner::from_pkcs8(SecretString::from(STANDARD.encode(der.as_ref()))).unwrap();
    let mut a = statement(&signer);
    for bad_domain in [false, true] {
        a.domain = if bad_domain {
            "wrong-purpose"
        } else {
            "tracelane.tool-execution.v1"
        }
        .into();
        let raw = if bad_domain {
            canonical(&a).unwrap()
        } else {
            serde_json::to_string_pretty(&a).unwrap()
        };
        let h = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(raw.as_bytes()),
            URL_SAFE_NO_PAD.encode(pair.sign(raw.as_bytes()).as_ref())
        );
        assert!(
            verify(
                Some(&h),
                pair.public_key().as_ref(),
                a.tenant_id,
                a.contract.server_id,
                "pay",
                ARGS,
                100
            )
            .is_err(),
            "signed invalid wire body accepted"
        );
    }
}

#[test]
fn attestation_key_purpose_separation() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let der = ring::signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let raw = STANDARD.encode(der.as_ref());
    assert!(
        AttestationSigner::configured(Some(SecretString::from(raw.clone())), Some(&raw)).is_err(),
        "audit key reused for tool authorization"
    );
    assert!(
        AttestationSigner::configured(Some(SecretString::from(raw)), None)
            .unwrap()
            .is_some()
    );
}

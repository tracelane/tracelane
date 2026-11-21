//! Pure defensive registration contracts. Every payload is an in-memory synthetic value.
use super::tests::{SERVER, TENANT, pair};
use super::*;
use ring::signature::KeyPair;

fn tenant() -> TenantId {
    TenantId::from_jwt_claim(TENANT)
}
fn document() -> Value {
    let public = pair(7).public_key().as_ref().to_vec();
    let key_id = receipt::key_id(&public);
    json!({"schema_version":1,"event_id":Uuid::from_u128(4),"action_id":SERVER,
        "tenant_id":TENANT,"agent_key_id":null,"occurred_at":"2026-11-20T00:00:00.000Z",
        "request_digest":key_id,"body":{"event_type":"tool_receipt_key_registered",
        "server_id":SERVER,"receipt_key_id":key_id,"public_key":hex::encode(public)}})
}
fn accepts(v: &Value) -> bool {
    registered_payload(&v.to_string(), &tenant(), SERVER).is_ok()
}
macro_rules! refusal {
    ($name:ident, $path:literal, $value:expr) => {
        #[test]
        fn $name() {
            let mut v = document();
            *v.pointer_mut($path).unwrap() = $value;
            assert!(!accepts(&v), stringify!($name));
        }
    };
}
refusal!(
    b634_wrong_latest_tenant,
    "/tenant_id",
    json!(Uuid::from_u128(9))
);
refusal!(
    b634_wrong_latest_server,
    "/body/server_id",
    json!(Uuid::from_u128(9))
);
refusal!(
    b634_wrong_latest_action,
    "/action_id",
    json!(Uuid::from_u128(9))
);
refusal!(
    b634_registration_agent_identity,
    "/agent_key_id",
    json!(Uuid::from_u128(9))
);
refusal!(
    b634_wrong_latest_request_digest,
    "/request_digest",
    json!("e".repeat(64))
);
refusal!(
    b634_wrong_latest_key_id,
    "/body/receipt_key_id",
    json!("e".repeat(64))
);
refusal!(b634_unknown_latest_schema, "/schema_version", json!(3));
refusal!(
    b634_principal_schema_not_registration,
    "/schema_version",
    json!(2)
);
refusal!(b634_zero_schema, "/schema_version", json!(0));
refusal!(b634_string_schema, "/schema_version", json!("1"));
refusal!(b634_negative_schema, "/schema_version", json!(-1));
refusal!(
    b634_wrong_latest_event_type,
    "/body/event_type",
    json!("execution_started")
);
refusal!(b634_null_latest_body, "/body", Value::Null);
refusal!(b634_array_latest_body, "/body", json!([]));
refusal!(
    b634_invalid_latest_key,
    "/body/public_key",
    json!("zz".repeat(32))
);
refusal!(b634_empty_latest_key, "/body/public_key", json!(""));
refusal!(
    b634_short_latest_key,
    "/body/public_key",
    json!("ab".repeat(31))
);
refusal!(
    b634_long_latest_key,
    "/body/public_key",
    json!("ab".repeat(33))
);
refusal!(
    b634_small_order_latest_key,
    "/body/public_key",
    json!("00".repeat(32))
);
refusal!(b634_array_latest_key, "/body/public_key", json!([7, 7, 7]));
refusal!(b634_null_latest_key, "/body/public_key", Value::Null);
refusal!(b634_null_latest_key_id, "/body/receipt_key_id", Value::Null);
refusal!(b634_invalid_event_uuid, "/event_id", json!("bad"));
refusal!(b634_invalid_timestamp, "/occurred_at", json!("yesterday"));
refusal!(b634_null_tenant, "/tenant_id", Value::Null);
refusal!(b634_null_server, "/body/server_id", Value::Null);
refusal!(
    b634_unicode_latest_key,
    "/body/public_key",
    json!("é".repeat(32))
);
refusal!(
    b634_whitespace_latest_key,
    "/body/public_key",
    json!(" ".repeat(64))
);

#[test]
fn b634_uppercase_latest_key() {
    let mut v = document();
    v["body"]["public_key"] = json!(v["body"]["public_key"].as_str().unwrap().to_uppercase());
    assert!(!accepts(&v));
}
macro_rules! missing {
    ($name:ident, $parent:literal, $key:literal) => {
        #[test]
        fn $name() {
            let mut v = document();
            v.pointer_mut($parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove($key);
            assert!(!accepts(&v));
        }
    };
}
missing!(b634_missing_latest_key, "/body", "public_key");
missing!(b634_missing_latest_key_id, "/body", "receipt_key_id");
missing!(b634_missing_latest_server, "/body", "server_id");
missing!(b634_missing_latest_domain, "/body", "event_type");
missing!(b634_missing_latest_schema, "", "schema_version");
missing!(b634_missing_latest_agent_field, "", "agent_key_id");
missing!(b634_missing_latest_digest, "", "request_digest");

#[test]
fn b634_unknown_envelope_field() {
    let mut v = document();
    v["extra"] = json!(1);
    assert!(!accepts(&v));
}
#[test]
fn b634_unknown_body_field() {
    let mut v = document();
    v["body"]["extra"] = json!(1);
    assert!(!accepts(&v));
}
#[test]
fn b634_duplicate_envelope_member() {
    let s = document()
        .to_string()
        .replacen('{', "{\"schema_version\":1,", 1);
    assert!(registered_payload(&s, &tenant(), SERVER).is_err());
}
#[test]
fn b634_duplicate_body_member() {
    let s = document()
        .to_string()
        .replace("\"body\":{", "\"body\":{\"public_key\":\"00\",");
    assert!(registered_payload(&s, &tenant(), SERVER).is_err());
}
#[test]
fn b634_malformed_latest_payload() {
    for s in ["{", "null", "[]", "true", "{}{}"] {
        assert!(registered_payload(s, &tenant(), SERVER).is_err(), "{s}");
    }
}
#[test]
fn b634_valid_typed_registration() {
    let (id, public) = registered_payload(&document().to_string(), &tenant(), SERVER).unwrap();
    assert_eq!(public, pair(7).public_key().as_ref());
    assert_eq!(id, receipt::key_id(&public));
}
#[test]
fn b634_key_rotation_encoding_invariant() {
    for seed in 1..=64 {
        let public = pair(seed).public_key().as_ref().to_vec();
        let id = receipt::key_id(&public);
        let mut v = document();
        v["body"]["public_key"] = json!(hex::encode(&public));
        v["body"]["receipt_key_id"] = json!(id);
        v["request_digest"] = json!(id);
        assert_eq!(
            registered_payload(&v.to_string(), &tenant(), SERVER).unwrap(),
            (id, public)
        );
    }
}
#[test]
fn b634_no_platform_accepts_tool_key() {
    let public = pair(7).public_key().as_ref().try_into().unwrap();
    assert_eq!(refuse_gateway_key(None, None, &public), Ok(()));
}
#[test]
fn b634_different_platform_accepts_tool_key() {
    let public = pair(7).public_key().as_ref().try_into().unwrap();
    let platform = pair(8);
    assert_eq!(
        refuse_gateway_key(None, Some(platform.public_key().as_ref()), &public),
        Ok(())
    );
}
#[test]
fn b634_different_attestation_accepts_tool_key() {
    let public = pair(7).public_key().as_ref().try_into().unwrap();
    let signer = crate::action_control::execution_tests::signer();
    assert_eq!(refuse_gateway_key(Some(&signer), None, &public), Ok(()));
}
#[test]
fn b634_attestation_key_registration_refused() {
    let signer = crate::action_control::execution_tests::signer();
    assert_eq!(
        refuse_gateway_key(
            Some(&signer),
            None,
            &signer.public_key().try_into().unwrap()
        ),
        Err(INVALID)
    );
}
#[test]
fn b634_both_gateway_keys_refused() {
    let signer = crate::action_control::execution_tests::signer();
    let platform = pair(8);
    for public in [
        signer.public_key().try_into().unwrap(),
        platform.public_key().as_ref().try_into().unwrap(),
    ] {
        assert_eq!(
            refuse_gateway_key(Some(&signer), Some(platform.public_key().as_ref()), &public),
            Err(INVALID)
        );
    }
}
#[test]
fn b634_public_bytes_match_loaded_key() {
    use base64::Engine as _;
    let pkcs8 =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let encoded = base64::engine::general_purpose::STANDARD.encode(pkcs8.as_ref());
    let chain = crate::audit::AuditChain::with_pg_pool(0, Some(&encoded), None, None).unwrap();
    assert_eq!(
        chain.platform_public_key(),
        Some(pair.public_key().as_ref())
    );
}
#[test]
fn b634_missing_platform_is_none() {
    assert_eq!(
        crate::audit::AuditChain::with_pg_pool(0, None, None, None)
            .unwrap()
            .platform_public_key(),
        None
    );
}
#[test]
fn b634_invalid_platform_is_error() {
    assert!(crate::audit::AuditChain::with_pg_pool(0, Some("not-pkcs8"), None, None).is_err());
}
#[test]
fn b634_fixture_mutation_breaks_contract() {
    // Only this pure fixture changes. The positive assertion is shared with the PG contract.
    let selected = if std::env::var("TRACELANE_B634_FIXTURE_MUTATION").as_deref() == Ok("missing") {
        None
    } else {
        Some(super::tests::key(&pair(7), "synthetic-attestation"))
    };
    super::tests::assert_selected_registration(selected.as_ref(), pair(7).public_key().as_ref());
}
#[test]
fn b634_fixture_latest_selection_contract() {
    let old = super::tests::key(&pair(7), "synthetic-attestation");
    let latest = super::tests::key(&pair(8), "synthetic-attestation");
    let selected = if std::env::var("TRACELANE_B634_FIXTURE_MUTATION").as_deref() == Ok("old") {
        &old
    } else {
        &latest
    };
    // Same positive key-selection assertion used by the real PG newest-sequence contract.
    super::tests::assert_selected_registration(Some(selected), pair(8).public_key().as_ref());
}

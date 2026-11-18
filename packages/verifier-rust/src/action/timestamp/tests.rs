use super::*;
const CP: &[u8] = include_bytes!("../../../tests/fixtures/timestamp/checkpoint.json");
const GOOD: &[u8] = include_bytes!("../../../tests/fixtures/timestamp/good.tsr");
const CERT: &[u8] = include_bytes!("../../../tests/fixtures/timestamp/good.der");
fn pins() -> Vec<Vec<u8>> {
    vec![CERT.to_vec()]
}
fn good() -> DateTime<Utc> {
    verify_optional(Some(GOOD), CP, &pins()).unwrap().unwrap()
}
fn refused(token: &[u8], cp: &[u8], pins: &[Vec<u8>], reason: &str) {
    let error = verify_optional(Some(token), cp, pins)
        .unwrap_err()
        .to_string();
    assert!(error.contains(reason), "expected {reason}; got {error}");
}
#[test]
fn good_token() {
    assert_eq!(good().to_rfc3339(), "2026-11-13T12:00:00+00:00");
}
#[test]
fn missing_token() {
    assert_eq!(verify_optional(None, CP, &[]).unwrap(), None);
}
#[test]
fn exact_bytes() {
    assert!(verify_optional(Some(GOOD), CP, &pins()).unwrap().is_some());
}
#[test]
fn rsa_pin() {
    assert_eq!(good().timestamp(), 1794571200);
}
#[test]
fn pin_set() {
    let mut p = vec![include_bytes!("../../../tests/fixtures/timestamp/wrong-eku.der").to_vec()];
    p.extend(pins());
    assert!(verify_optional(Some(GOOD), CP, &p).unwrap().is_some());
}
#[test]
fn valid_at_generation() {
    assert_eq!(good().date_naive().to_string(), "2026-11-13");
}
#[test]
fn request_imprint() {
    let req = request(CP).unwrap();
    assert!(req.windows(32).any(|w| w == crate::sha256(CP)));
    assert_eq!(req[0], 0x30);
}
#[test]
fn swapped_token() {
    refused(GOOD, b"other checkpoint", &pins(), "imprint");
}
#[test]
fn wrong_imprint() {
    refused(
        include_bytes!("../../../tests/fixtures/timestamp/wrong-imprint.tsr"),
        CP,
        &pins(),
        "imprint",
    );
}
#[test]
fn corrupt_token() {
    refused(&GOOD[..20], CP, &pins(), "DER");
}
#[test]
fn unpinned_cert() {
    assert!(verify_optional(Some(GOOD), CP, &[]).unwrap().is_none());
}
#[test]
fn expired_at_generation() {
    refused(
        include_bytes!("../../../tests/fixtures/timestamp/expired.tsr"),
        CP,
        &[include_bytes!("../../../tests/fixtures/timestamp/expired.der").to_vec()],
        "validity",
    );
}
#[test]
fn wrong_eku() {
    refused(
        include_bytes!("../../../tests/fixtures/timestamp/wrong-eku.tsr"),
        CP,
        &[include_bytes!("../../../tests/fixtures/timestamp/wrong-eku.der").to_vec()],
        "EKU",
    );
}
#[test]
fn bad_signature() {
    refused(
        include_bytes!("../../../tests/fixtures/timestamp/bad-signature.tsr"),
        CP,
        &pins(),
        "signature",
    );
}
#[test]
fn missing_attrs() {
    refused(
        include_bytes!("../../../tests/fixtures/timestamp/missing-attrs.tsr"),
        CP,
        &pins(),
        "attribute",
    );
}
#[test]
fn bad_cert_hash() {
    // A binding that names no pinned certificate is unpinned (never true), not a failure:
    // equivalent to the token being stripped from the unsigned manifest.
    assert_eq!(
        verify_optional(
            Some(include_bytes!(
                "../../../tests/fixtures/timestamp/bad-cert-hash.tsr"
            )),
            CP,
            &pins()
        )
        .unwrap(),
        None
    );
}
#[test]
fn trailing_bytes() {
    let mut t = GOOD.to_vec();
    t.push(0);
    refused(&t, CP, &pins(), "DER");
}

fn mutate_signed(change: impl FnOnce(&mut SignedData)) -> Vec<u8> {
    let mut response = Response::from_der(GOOD).unwrap();
    let content = response.token.as_mut().unwrap();
    let mut signed = content.content.decode_as::<SignedData>().unwrap();
    change(&mut signed);
    content.content = Any::from_der(&signed.to_der().unwrap()).unwrap();
    response.to_der().unwrap()
}
#[test]
fn invalid_signed_data_version() {
    let token = mutate_signed(|s| s.version = cms::content_info::CmsVersion::V1);
    refused(&token, CP, &pins(), "version");
}
#[test]
fn invalid_signer_version() {
    let token = mutate_signed(|s| {
        let mut signer = s.signer_infos.0.get(0).unwrap().clone();
        signer.version = cms::content_info::CmsVersion::V3;
        s.signer_infos.0 = der::asn1::SetOfVec::try_from(vec![signer]).unwrap();
    });
    refused(&token, CP, &pins(), "version");
}
#[test]
fn invalid_signature_parameters() {
    let token = mutate_signed(|s| {
        let mut signer = s.signer_infos.0.get(0).unwrap().clone();
        signer.signature_algorithm.parameters = Some(Any::from_der(&[2, 1, 7]).unwrap());
        s.signer_infos.0 = der::asn1::SetOfVec::try_from(vec![signer]).unwrap();
    });
    refused(&token, CP, &pins(), "parameters");
}
#[test]
fn invalid_status_fields() {
    let mut response = Response::from_der(GOOD).unwrap();
    response.status = Any::from_der(&[0x30, 6, 2, 1, 0, 2, 1, 9]).unwrap();
    refused(&response.to_der().unwrap(), CP, &pins(), "status");
}
#[test]
fn contradictory_key_usage_refused() {
    refused(
        include_bytes!("../../../tests/fixtures/timestamp/key-usage.tsr"),
        CP,
        &[include_bytes!("../../../tests/fixtures/timestamp/key-usage.der").to_vec()],
        "key usage",
    );
}
#[test]
fn unknown_critical_extension_refused() {
    refused(
        include_bytes!("../../../tests/fixtures/timestamp/critical-extension.tsr"),
        CP,
        &[include_bytes!("../../../tests/fixtures/timestamp/critical-extension.der").to_vec()],
        "critical extension",
    );
}
#[test]
fn fractional_expiry_refused() {
    refused(
        include_bytes!("../../../tests/fixtures/timestamp/fractional-expiry.tsr"),
        CP,
        &[include_bytes!("../../../tests/fixtures/timestamp/fractional-expiry.der").to_vec()],
        "validity",
    );
}
#[test]
fn ecdsa_pin_accepted() {
    assert!(
        verify_optional(
            Some(include_bytes!(
                "../../../tests/fixtures/timestamp/ecdsa.tsr"
            )),
            CP,
            &[include_bytes!("../../../tests/fixtures/timestamp/ecdsa.der").to_vec()]
        )
        .unwrap()
        .is_some()
    );
}
#[test]
fn pem_pin_accepted() {
    use der::EncodePem;
    let pem = Certificate::from_der(CERT)
        .unwrap()
        .to_pem(der::pem::LineEnding::LF)
        .unwrap();
    assert!(
        verify_optional(Some(GOOD), CP, &[pem.into_bytes()])
            .unwrap()
            .is_some()
    );
}

#[test]
fn unrelated_pin_reports_unverified() {
    assert!(
        verify_optional(
            Some(GOOD),
            CP,
            &[include_bytes!("../../../tests/fixtures/timestamp/wrong-eku.der").to_vec()]
        )
        .unwrap()
        .is_none()
    );
}
/// Review M-A: a garbage pin is not a trust root; it must not fail a well-formed token.
#[test]
fn garbage_pin_is_unpinned_not_failure() {
    let garbage = b"Certificate:\n    Data:\n        Version: 3 (0x2)\n".to_vec();
    assert!(validate_pin(&garbage).is_err());
    assert_eq!(
        verify_optional(Some(GOOD), CP, std::slice::from_ref(&garbage)).unwrap(),
        None
    );
    // A garbage pin beside the real one still lets the real one match.
    let mut mixed = vec![garbage];
    mixed.extend(pins());
    assert!(verify_optional(Some(GOOD), CP, &mixed).unwrap().is_some());
}
#[test]
fn validate_pin_accepts_real_certificate() {
    assert!(validate_pin(CERT).is_ok());
}

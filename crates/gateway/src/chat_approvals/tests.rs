use super::*;
use ring::hmac;

const SECRET: &str = "unit-test-slack-signing-secret-do-not-use";
const OTHER: &str = "a-different-test-secret-do-not-use";
const NOW: i64 = 1_800_000_000;
const LIMITS: Limits = Limits { replay_window_secs: 300, max_body_bytes: 32768 };

fn secret() -> SecretString {
    SecretString::from(SECRET.to_owned())
}
/// Independent of the code under test: v0=hex(HMAC-SHA256(secret, "v0:{ts}:{body}")).
fn sign_with(secret: &str, ts: &str, body: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let mut base = format!("v0:{ts}:").into_bytes();
    base.extend_from_slice(body);
    format!("v0={}", hex::encode(hmac::sign(&key, &base).as_ref()))
}
fn check(ts: &str, sig: &str, body: &[u8], now: i64) -> Result<(), Reject> {
    verify_request(&secret(), &LIMITS, now, &[ts], &[sig], body).map(|_| ())
}
fn check_signed(ts: i64, body: &[u8], now: i64) -> Result<(), Reject> {
    let t = ts.to_string();
    check(&t, &sign_with(SECRET, &t, body), body, now)
}

// ---- signature, timestamp, body cap (N1-N8) ----
#[test]
fn sig_accepts_boundary_300s() {
    assert_eq!(check_signed(NOW, b"payload=%7B%7D", NOW), Ok(()));
    assert_eq!(check_signed(NOW - 300, b"x", NOW), Ok(()));
}
#[test]
fn sig_accepts_future_skew_within_window() {
    assert_eq!(check_signed(NOW + 299, b"x", NOW), Ok(()));
    assert_eq!(check_signed(NOW + 300, b"x", NOW), Ok(()));
}
#[test]
fn sig_rejects_bad_signature() {
    let ts = NOW.to_string();
    assert_eq!(check(&ts, &sign_with(OTHER, &ts, b"x"), b"x", NOW), Err(Reject::SignatureMismatch));
    let good = sign_with(SECRET, &ts, b"x");
    let last = if good.ends_with('0') { '1' } else { '0' };
    let flipped = format!("{}{last}", &good[..good.len() - 1]);
    assert_eq!(check(&ts, &flipped, b"x", NOW), Err(Reject::SignatureMismatch));
}
#[test]
fn sig_rejects_body_tamper() {
    let ts = NOW.to_string();
    let sig = sign_with(SECRET, &ts, b"payload=aaa");
    assert_eq!(check(&ts, &sig, b"payload=aab", NOW), Err(Reject::SignatureMismatch));
}
#[test]
fn sig_binds_the_timestamp() {
    // The timestamp is inside the signed bytes: a valid signature moved to a fresher timestamp fails.
    let sig = sign_with(SECRET, &(NOW - 10).to_string(), b"x");
    assert_eq!(check(&NOW.to_string(), &sig, b"x", NOW), Err(Reject::SignatureMismatch));
}
#[test]
fn sig_rejects_stale_timestamp_301s() {
    for ts in [NOW - 301, NOW + 301, 0] {
        assert_eq!(check_signed(ts, b"x", NOW), Err(Reject::StaleTimestamp), "{ts}");
    }
}
#[test]
fn sig_rejects_far_future_timestamp() {
    for ts in [NOW + 86_400, 999_999_999_999] {
        assert_eq!(check_signed(ts, b"x", NOW), Err(Reject::StaleTimestamp), "{ts}");
    }
}
#[test]
fn sig_rejects_non_integer_ts() {
    for bad in ["abc", "", "12.5", "-5", "-0", "+5", " 5", "5 ", "1e3", "0x10", "١٢٣", "9999999999999999999999"] {
        let sig = sign_with(SECRET, bad, b"x");
        assert_eq!(check(bad, &sig, b"x", NOW), Err(Reject::BadTimestamp), "ts {bad:?}");
    }
}
#[test]
fn sig_rejects_duplicate_or_missing_headers() {
    let ts = NOW.to_string();
    let (good, bad) = (sign_with(SECRET, &ts, b"x"), sign_with(OTHER, &ts, b"x"));
    let go = |t: &[&str], s: &[&str]| verify_request(&secret(), &LIMITS, NOW, t, s, b"x").map(|_| ());
    assert_eq!(go(&[&ts], &[&good, &bad]), Err(Reject::DuplicateSignature));
    assert_eq!(go(&[&ts], &[&bad, &good]), Err(Reject::DuplicateSignature));
    assert_eq!(go(&[&ts], &[&good, &good]), Err(Reject::DuplicateSignature));
    assert_eq!(go(&[&ts, &ts], &[&good]), Err(Reject::DuplicateTimestamp));
    assert_eq!(go(&[], &[&good]), Err(Reject::MissingTimestamp));
    assert_eq!(go(&[&ts], &[]), Err(Reject::MissingSignature));
}
#[test]
fn sig_rejects_unknown_scheme() {
    let ts = NOW.to_string();
    let good = sign_with(SECRET, &ts, b"x");
    let h = good.strip_prefix("v0=").unwrap();
    for bad in [format!("v1={h}"), h.to_owned(), format!("V0={h}"), format!(" v0={h}")] {
        assert_eq!(check(&ts, &bad, b"x", NOW), Err(Reject::BadSignatureFormat), "{bad}");
    }
}
#[test]
fn sig_rejects_malformed_hex_without_panic() {
    let ts = NOW.to_string();
    let h = sign_with(SECRET, &ts, b"x").strip_prefix("v0=").unwrap().to_owned();
    let cases = [
        "v0=".to_owned(),
        format!("v0={}", &h[..63]), // odd length
        format!("v0={}", &h[..62]),
        format!("v0={h}0"),
        format!("v0={h}00"),
        format!("v0={}", h.to_uppercase()), // Slack sends lower case
        format!("v0={}g", &h[..63]),
        format!("v0={}é", &h[..62]), // multi-byte char at the end
        format!("v0={h}\n"),
    ];
    for bad in cases {
        assert_eq!(check(&ts, &bad, b"x", NOW), Err(Reject::BadSignatureFormat), "{bad:?}");
    }
}
#[test]
fn oversize_body_rejected_before_hmac() {
    let big = vec![b'a'; LIMITS.max_body_bytes + 1];
    // Refused even when correctly signed, and before any other check: no HMAC is computed.
    assert_eq!(check_signed(NOW, &big, NOW), Err(Reject::BodyTooLarge));
    let empty = SecretString::from(String::new());
    assert_eq!(verify_request(&empty, &LIMITS, NOW, &[], &[], &big).unwrap_err(), Reject::BodyTooLarge);
    assert_eq!(Reject::BodyTooLarge.status(), 413);
    assert_eq!(check_signed(NOW, &vec![b'a'; LIMITS.max_body_bytes], NOW), Ok(()));
}
#[test]
fn route_absent_without_signing_secret() {
    assert!(configured_secret(None).is_none());
    assert!(configured_secret(Some("")).is_none());
    assert!(configured_secret(Some("  \n")).is_none());
    assert!(configured_secret(Some(SECRET)).is_some());
}
#[test]
fn empty_signing_secret_fails_closed() {
    let ts = NOW.to_string();
    let sig = sign_with("", &ts, b"x");
    for blank in ["", " ", "\t\n "] {
        let empty = SecretString::from(blank.to_owned());
        let r = verify_request(&empty, &LIMITS, NOW, &[&ts], &[&sig], b"x");
        assert_eq!(r.unwrap_err(), Reject::NoSigningSecret, "{blank:?}");
        // A whitespace secret that matches the signature must still refuse.
        let signed = sign_with(blank, &ts, b"x");
        let r = verify_request(&empty, &LIMITS, NOW, &[&ts], &[&signed], b"x");
        assert_eq!(r.unwrap_err(), Reject::NoSigningSecret, "{blank:?}");
    }
}
#[test]
fn limits_come_from_the_reference_table() {
    let l = Limits::from_settings(crate::mcp_policy::settings().unwrap());
    assert_eq!((l.replay_window_secs, l.max_body_bytes), (300, 32768));
}

// ---- payload shape (N29-N31) ----
/// Sign and verify `body` with the test secret, then parse: the only path to an `Interaction`.
fn parse(body: &[u8]) -> Result<Interaction, Reject> {
    let ts = NOW.to_string();
    let sig = sign_with(SECRET, &ts, body);
    parse_interaction(&verify_request(&secret(), &LIMITS, NOW, &[&ts], &[&sig], body)?)
}
fn form(json: &str) -> Vec<u8> {
    let mut out = String::from("payload=");
    for b in json.bytes() {
        if b.is_ascii_alphanumeric() { out.push(b as char) } else { out.push_str(&format!("%{b:02X}")) }
    }
    out.into_bytes()
}
fn payload(kind: &str, actions: &str) -> Vec<u8> {
    form(&format!(
        r#"{{"type":"{kind}","team":{{"id":"T0001"}},"user":{{"id":"U0001","name":"ignored"}},"trigger_id":"1337.42.abc","actions":{actions},"extra":1}}"#
    ))
}
fn one(action: &str) -> Vec<u8> {
    payload("block_actions", &format!(r#"[{{"action_id":"{action}","value":"v","type":"button"}}]"#))
}
#[test]
fn parse_accepts_the_three_actions() {
    for (id, want) in [("tl_approve", Action::Approve), ("tl_deny", Action::Deny), ("tl_open", Action::Open)] {
        let i = parse(&one(id)).unwrap();
        assert_eq!((i.action, i.team_id.as_str(), i.user_id.as_str()), (want, "T0001", "U0001"));
        assert_eq!((i.trigger_id.as_str(), i.value.as_str()), ("1337.42.abc", "v"));
        assert_eq!(i.action.decides(), want != Action::Open);
    }
}
#[test]
fn unknown_action_id_rejected() {
    for id in ["tl_APPROVE", "approve", "", "tl_approve ", "tl_delete", "tl_approve\\u0000"] {
        assert_eq!(parse(&one(id)), Err(Reject::UnknownAction), "{id:?}");
    }
}
#[test]
fn multiple_actions_rejected() {
    let two = payload("block_actions", r#"[{"action_id":"tl_approve"},{"action_id":"tl_deny"}]"#);
    assert_eq!(parse(&two), Err(Reject::BadActionCount));
    let same = payload("block_actions", r#"[{"action_id":"tl_deny"},{"action_id":"tl_deny"}]"#);
    assert_eq!(parse(&same), Err(Reject::BadActionCount));
    assert_eq!(parse(&payload("block_actions", "[]")), Err(Reject::BadActionCount));
}
#[test]
fn non_block_actions_rejected() {
    for kind in ["view_submission", "view_closed", "shortcut", "block_suggestion", "Block_Actions", ""] {
        let body = payload(kind, r#"[{"action_id":"tl_approve"}]"#);
        assert_eq!(parse(&body), Err(Reject::NotBlockActions), "{kind:?}");
    }
}
#[test]
fn malformed_payloads_rejected() {
    for body in [&b"other=1"[..], b"", b"payload=%zz", b"payload=%4", b"payload=%FF%FE", &[b'p', 0xff]] {
        assert_eq!(parse(body), Err(Reject::NotFormEncoded), "{body:?}");
    }
    let mut dup = one("tl_approve");
    dup.extend_from_slice(b"&payload=%7B%7D");
    assert_eq!(parse(&dup), Err(Reject::NotFormEncoded));
    assert_eq!(percent_decode("a+b%41"), Some(b"a bA".to_vec()));
    assert_eq!(parse(b"payload=not-json"), Err(Reject::BadPayload));
    assert_eq!(parse(&form("[]")), Err(Reject::BadPayload));
    assert_eq!(parse(&form(r#"{"type":"block_actions"}"#)), Err(Reject::BadPayload));
}
#[test]
fn malformed_ids_rejected() {
    let with = |team: &str, user: &str, trig: &str| {
        form(&format!(
            r#"{{"type":"block_actions","team":{{"id":"{team}"}},"user":{{"id":"{user}"}},"trigger_id":"{trig}","actions":[{{"action_id":"tl_approve"}}]}}"#
        ))
    };
    assert!(parse(&with("T1", "U1", "1.2")).is_ok());
    for (t, u, g) in [("", "U1", "1"), ("T1", "", "1"), ("T1", "U1", ""), ("T 1", "U1", "1"), ("T1", "U1", "a:b"), (&"T".repeat(65), "U1", "1")] {
        assert_eq!(parse(&with(t, u, g)), Err(Reject::BadPayload), "{t:?} {u:?} {g:?}");
    }
}
// ---- button MAC ----
fn key(n: u8) -> SecretBox<[u8; 32]> {
    SecretBox::new(Box::new([n; 32]))
}
const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TENANT: Uuid = Uuid::from_u128(0xa1);
const APPROVAL: Uuid = Uuid::from_u128(0xb2);
const INSTALL: Uuid = Uuid::from_u128(0xc3);
fn mint(decision: Decision) -> String {
    mint_button(&key(1), TENANT, APPROVAL, decision, INSTALL, DIGEST)
}
#[test]
fn button_round_trips() {
    for d in [Decision::Approve, Decision::Deny] {
        let b = parse_button(&mint(d)).unwrap();
        assert_eq!((b.approval_id, b.decision, b.installation_id), (APPROVAL, d, INSTALL));
        assert_eq!(b.descriptor_digest, DIGEST);
        assert_eq!(verify_button(&key(1), TENANT, INSTALL, &b), Ok(()));
    }
}
#[test]
fn forged_button_mac_rejected() {
    let v = mint(Decision::Approve);
    let forged = format!("{}.{}", v.rsplit_once('.').unwrap().0, "0".repeat(64));
    let b = parse_button(&forged).unwrap();
    assert_eq!(verify_button(&key(1), TENANT, INSTALL, &b), Err(Reject::ButtonMacMismatch));
}
#[test]
fn button_fields_are_all_bound() {
    let v = mint(Decision::Approve);
    let swap = |from: &str, to: &str| parse_button(&v.replacen(from, to, 1)).unwrap();
    let other = Uuid::from_u128(0xd4);
    // (button, installation the caller looked up). The swapped installation is passed as the
    // lookup too, so only the MAC can refuse it.
    for (b, install) in [
        (swap(".a.", ".d."), INSTALL),
        (swap(&APPROVAL.to_string(), &other.to_string()), INSTALL),
        (swap(&INSTALL.to_string(), &other.to_string()), other),
        (swap(DIGEST, &"f".repeat(64)), INSTALL),
    ] {
        assert_eq!(verify_button(&key(1), TENANT, install, &b), Err(Reject::ButtonMacMismatch));
    }
}
#[test]
fn cross_tenant_button_value_rejected() {
    let b = parse_button(&mint(Decision::Approve)).unwrap();
    assert_eq!(verify_button(&key(1), Uuid::from_u128(0xff), INSTALL, &b), Err(Reject::ButtonMacMismatch));
    assert_eq!(verify_button(&key(2), TENANT, INSTALL, &b), Err(Reject::ButtonMacMismatch));
}
#[test]
fn malformed_button_values_rejected() {
    let good = mint(Decision::Approve);
    let mac = good.rsplit_once('.').unwrap().1.to_owned();
    let bad = [
        String::new(),
        "v1".into(),
        good.replacen("v1.", "v2.", 1),
        good.replacen(".a.", ".x.", 1),
        good.replacen(&APPROVAL.to_string(), "not-a-uuid", 1),
        good.replacen(&INSTALL.to_string(), "", 1),
        format!("{good}.extra"),
        good.replacen(DIGEST, &DIGEST[..63], 1),
        good.replacen(DIGEST, &DIGEST.to_uppercase(), 1),
        good.replacen(&mac, &mac[..63], 1),
        good.replace('.', ":"),
    ];
    for v in bad {
        assert_eq!(parse_button(&v), Err(Reject::BadButtonValue), "{v}");
    }
}
#[test]
fn button_installation_must_match_team_lookup() {
    // The MAC is valid under this tenant key, but the installation found from the signed team.id
    // is a different (e.g. revoked and reinstalled) one: refused.
    let b = parse_button(&mint(Decision::Approve)).unwrap();
    assert_eq!(verify_button(&key(1), TENANT, INSTALL, &b), Ok(()));
    let other = Uuid::from_u128(0xc4);
    assert_eq!(verify_button(&key(1), TENANT, other, &b), Err(Reject::InstallationMismatch));
    assert_eq!(verify_button(&key(1), TENANT, Uuid::nil(), &b), Err(Reject::InstallationMismatch));
}
#[test]
fn verified_body_is_the_signed_bytes() {
    let ts = NOW.to_string();
    let v = verify_request(&secret(), &LIMITS, NOW, &[&ts], &[&sign_with(SECRET, &ts, b"abc")], b"abc").unwrap();
    assert_eq!(v.body(), b"abc");
}
#[test]
fn dedup_key_binds_team_and_trigger() {
    let i = parse(&one("tl_approve")).unwrap();
    let want = hex::encode(ring::digest::digest(&ring::digest::SHA256, b"T0001:1337.42.abc"));
    assert_eq!(i.dedup_key(), want);
    assert_eq!(parse(&one("tl_deny")).unwrap().dedup_key(), want); // same click id, same key
    let other = |team: &str, trig: &str| {
        form(&format!(r#"{{"type":"block_actions","team":{{"id":"{team}"}},"user":{{"id":"U1"}},"trigger_id":"{trig}","actions":[{{"action_id":"tl_approve"}}]}}"#))
    };
    for (t, g) in [("T0002", "1337.42.abc"), ("T0001", "1337.42.abd")] {
        assert_ne!(parse(&other(t, g)).unwrap().dedup_key(), want);
    }
}

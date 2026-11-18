//! Browser wrapper around the Tracelane action-bundle verifier.
//!
//! One job: hand the bytes the page read locally to
//! `tracelane_audit_verifier::action::bundle::verify_with_tsa` and return its
//! verdict as JSON. No check is reimplemented here and nothing is fetched.
use serde_json::json;
use tracelane_audit_verifier::action::{archive, bundle, timestamp};

fn fail(code: u8, detail: impl std::fmt::Display) -> String {
    json!({"ok": false, "code": code, "detail": detail.to_string()}).to_string()
}

/// Decode an Ed25519 public key exactly as the CLI's `decode_pubkey32` does:
/// trimmed; 64 hex characters, otherwise standard base64; exactly 32 bytes.
///
/// # Errors
/// Fails CLOSED: any other text is refused, never guessed at.
pub fn decode_pubkey32(text: &str) -> Result<[u8; 32], String> {
    use base64::Engine as _;
    let s = text.trim();
    let raw = if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        hex::decode(s).map_err(|_| "is not valid hex".to_owned())?
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|_| "is not valid base64 (nor 64-char hex)".to_owned())?
    };
    let len = raw.len();
    raw.try_into()
        .map_err(|_| format!("must decode to exactly 32 bytes (got {len})"))
}

/// Verify an action evidence ZIP against an externally supplied public key and
/// optional TSA leaf certificates (DER or PEM).
///
/// Returns `{"ok":true,"summary":…,"report":…}` or `{"ok":false,"code":…,"detail":…}`.
/// Codes are the CLI's exit codes: 4 format/proof, 5 trust, 6 action semantics.
/// Every input error fails CLOSED; a key inside the bundle is never a trust root.
pub fn verify_json(zip: &[u8], pubkey_text: &str, tsa_certs: &[Vec<u8>]) -> String {
    if let Err(e) = archive::check_size(zip.len() as u64) {
        return fail(4, e);
    }
    if pubkey_text.trim().is_empty() {
        return fail(
            5,
            "an external public key is required; keys inside the bundle are not trust roots",
        );
    }
    let pin = match decode_pubkey32(pubkey_text) {
        Ok(pin) => pin,
        Err(e) => return fail(5, format!("public key {e}")),
    };
    if tsa_certs
        .iter()
        .any(|c| timestamp::validate_pin(c).is_err())
    {
        return fail(5, "a TSA certificate is not a PEM or DER X.509 certificate");
    }
    match bundle::verify_with_tsa(zip, Some(pin), tsa_certs) {
        Ok(report) => match serde_json::to_value(&report) {
            Ok(value) => {
                json!({"ok": true, "summary": report.to_string(), "report": value}).to_string()
            }
            Err(e) => fail(4, e),
        },
        Err(failure) => fail(failure.code, failure.detail),
    }
}

/// The page's only entry point. See [`verify_json`].
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn verify_bundle(zip: &[u8], pubkey_text: &str, tsa_certs: Vec<js_sys::Uint8Array>) -> String {
    let certs: Vec<Vec<u8>> = tsa_certs.iter().map(js_sys::Uint8Array::to_vec).collect();
    verify_json(zip, pubkey_text, &certs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use serde_json::Value;

    const GOOD: &[u8] = include_bytes!("../fixtures/good.zip");
    const TAMPERED: &[u8] = include_bytes!("../fixtures/tampered.zip");
    const KEY: &str = include_str!("../fixtures/workspace.pub");
    const TS: &str = "../../verifier-rust/tests/fixtures/timestamp";

    fn run(zip: &[u8], key: &str, certs: &[Vec<u8>]) -> Value {
        serde_json::from_str(&verify_json(zip, key, certs)).unwrap()
    }
    fn refused(zip: &[u8], key: &str, certs: &[Vec<u8>], code: u8) -> String {
        let v = run(zip, key, certs);
        assert_eq!(v["ok"], false, "{v}");
        assert_eq!(v["code"], code, "{v}");
        assert!(v.get("report").is_none(), "{v}");
        v["detail"].as_str().unwrap().to_owned()
    }
    fn timestamped() -> (Vec<u8>, String, Vec<u8>) {
        let read = |name: &str| {
            std::fs::read(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("src")
                    .join(TS)
                    .join(name),
            )
            .unwrap()
        };
        let files = [
            ("ledger.ndjson".to_owned(), vec![]),
            ("checkpoint.json".to_owned(), read("checkpoint.json")),
            ("checkpoint.sig".to_owned(), read("checkpoint.sig")),
            ("checkpoint.tsr".to_owned(), read("good.tsr")),
        ]
        .into();
        (
            bundle::seal(files).unwrap(),
            String::from_utf8(read("tenant.pub")).unwrap(),
            read("good.der"),
        )
    }

    #[test]
    fn good_bundle_passes() {
        let v = run(GOOD, KEY, &[]);
        assert_eq!(v["ok"], true, "{v}");
    }
    #[test]
    fn base64_key_accepted() {
        let raw = hex::decode(KEY.trim()).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        assert_eq!(run(GOOD, &b64, &[])["ok"], true);
    }
    #[test]
    fn key_whitespace_tolerated() {
        assert_eq!(run(GOOD, &format!("  {}\r\n", KEY.trim()), &[])["ok"], true);
    }
    #[test]
    fn report_is_verifier_json() {
        let report = &run(GOOD, KEY, &[])["report"];
        assert_eq!(report["rows"], 3);
        assert_eq!(report["chain"], true);
        assert_eq!(report["head"], true);
        assert_eq!(report["head_seq"], "2");
        assert_eq!(report["timestamped"], false);
    }
    #[test]
    fn summary_is_cli_pass_line() {
        let v = run(GOOD, KEY, &[]);
        let summary = v["summary"].as_str().unwrap();
        assert!(
            summary.starts_with("PASS — chain, covering head"),
            "{summary}"
        );
        assert!(
            summary.contains("rows: 3; signed range: 0..=2"),
            "{summary}"
        );
    }
    #[test]
    fn tsa_pin_timestamps() {
        let (zip, key, cert) = timestamped();
        let report = &run(&zip, &key, &[cert])["report"];
        assert_eq!(report["timestamped"], true);
        assert_eq!(report["gen_time"], "2026-11-13T12:00:00Z");
    }
    #[test]
    fn tsa_unpinned_still_passes() {
        let (zip, key, _) = timestamped();
        let v = run(&zip, &key, &[]);
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["report"]["timestamped"], false);
        assert_eq!(v["report"]["timestamp_reason"], "tsa_unpinned");
    }

    #[test]
    fn tampered_fails_code_4() {
        let detail = refused(TAMPERED, KEY, &[], 4);
        assert_eq!(detail, "manifest hash mismatch: ledger.ndjson");
    }
    #[test]
    fn wrong_key_fails_code_5() {
        let detail = refused(GOOD, &hex::encode([9u8; 32]), &[], 5);
        assert_eq!(detail, "checkpoint does not verify under external pin");
    }
    #[test]
    fn bad_key_text_refused() {
        let detail = refused(GOOD, "not a key!", &[], 5);
        assert_eq!(detail, "public key is not valid base64 (nor 64-char hex)");
    }
    #[test]
    fn short_key_refused() {
        let b64 = base64::engine::general_purpose::STANDARD.encode([7u8; 16]);
        let detail = refused(GOOD, &b64, &[], 5);
        assert_eq!(
            detail,
            "public key must decode to exactly 32 bytes (got 16)"
        );
    }
    #[test]
    fn blank_key_refused() {
        let detail = refused(GOOD, " \n", &[], 5);
        assert!(detail.contains("not trust roots"), "{detail}");
    }
    #[test]
    fn garbage_zip_fails_code_4() {
        refused(b"definitely not a zip", KEY, &[], 4);
        refused(&[], KEY, &[], 4);
    }
    #[test]
    fn bad_tsa_cert_refused() {
        let detail = refused(GOOD, KEY, &[b"not a certificate".to_vec()], 5);
        assert!(detail.contains("TSA certificate"), "{detail}");
    }
    #[test]
    fn oversize_bundle_refused() {
        let big = vec![0u8; archive::MAX_BUNDLE_BYTES as usize + 1];
        let detail = refused(&big, KEY, &[], 4);
        assert_eq!(detail, "action bundle exceeds 67108864 byte limit");
    }
}

use std::{
    io::Write,
    process::{Command, Stdio},
};

fn cli(file: &str, input: Option<&[u8]>) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tracelane-audit"))
        .args(["verify", "--file", file, "--offline", "--format", "json"])
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(input) = input {
        child.stdin.take().unwrap().write_all(input).unwrap();
    }
    child.wait_with_output().unwrap()
}
#[test]
fn legacy_stdin_matches_file_verification() {
    // This row is syntactically valid but has a forged hash: it must never vanish.
    let input=br#"{"tenant_id":"00000000-0000-0000-0000-00000000000a","seq":0,"event_type":"test.event","actor":"test","payload":{},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","row_hash":"0000000000000000000000000000000000000000000000000000000000000000"}
"#;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(input).unwrap();
    let regular = cli(file.path().to_str().unwrap(), None);
    let pipe = cli("/dev/stdin", Some(input));
    assert_eq!(regular.status.code(), Some(1));
    assert_eq!(
        pipe.status.code(),
        regular.status.code(),
        "{}",
        String::from_utf8_lossy(&pipe.stdout)
    );
    let mut expected: serde_json::Value = serde_json::from_slice(&regular.stdout).unwrap();
    let mut actual: serde_json::Value = serde_json::from_slice(&pipe.stdout).unwrap();
    expected["ledger_path"] = serde_json::Value::Null;
    actual["ledger_path"] = serde_json::Value::Null;
    assert_eq!(actual, expected);
    let expected_bytes = String::from_utf8(regular.stdout).unwrap().replace(
        &serde_json::to_string(file.path().to_str().unwrap()).unwrap(),
        "\"<ledger>\"",
    );
    let actual_bytes = String::from_utf8(pipe.stdout)
        .unwrap()
        .replace("\"/dev/stdin\"", "\"<ledger>\"");
    assert_eq!(
        actual_bytes, expected_bytes,
        "legacy report bytes differ beyond the path label"
    );
}
#[test]
fn oversized_bundle_is_refused_before_trust_or_allocation() {
    let mut file = tempfile::Builder::new().suffix(".zip").tempfile().unwrap();
    file.write_all(b"PK\x03\x04").unwrap();
    file.as_file().set_len(64 * 1024 * 1024 + 1).unwrap();
    let out = cli(file.path().to_str().unwrap(), None);
    assert_eq!(
        out.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("action bundle exceeds 67108864 byte limit")
    );
}
#[test]
fn oversized_bundle_stream_is_refused_with_same_limit() {
    let mut bytes = vec![0u8; 64 * 1024 * 1024 + 1];
    bytes[..4].copy_from_slice(b"PK\x03\x04");
    let out = cli("/dev/stdin", Some(&bytes));
    assert_eq!(
        out.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("action bundle exceeds 67108864 byte limit")
    );
}

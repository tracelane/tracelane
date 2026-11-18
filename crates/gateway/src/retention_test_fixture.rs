//! Destructive minimal-schema retention tests own a separate local service.
//! Run serially. Port 18139 must have its own disposable container/data directory;
//! the canonical ClickHouse integration fixture at 18138 must never be reset here.

const DISPOSABLE_URL: &str = "http://127.0.0.1:18139";

fn validate_url(url: Option<&str>) -> Result<&str, &'static str> {
    match url {
        Some(DISPOSABLE_URL) => Ok(DISPOSABLE_URL),
        _ => Err(
            "CLICKHOUSE_RETENTION_TEST_URL must be exactly http://127.0.0.1:18139 on a separate disposable service",
        ),
    }
}

pub(super) fn disposable_url() -> String {
    let url = std::env::var("CLICKHOUSE_RETENTION_TEST_URL").ok();
    validate_url(url.as_deref())
        .expect("refuse unsafe retention fixture")
        .to_owned()
}

pub(super) async fn reset(url: &str) -> clickhouse::Client {
    // Validate before constructing a client or executing destructive SQL.
    let url = validate_url(Some(url)).expect("refuse unsafe retention fixture");
    let ch = clickhouse::Client::default().with_url(url);
    ch.query("DROP DATABASE IF EXISTS tracelane SYNC")
        .execute()
        .await
        .unwrap();
    ch.query("CREATE DATABASE tracelane")
        .execute()
        .await
        .unwrap();
    ch
}

#[test]
fn dedicated_endpoint_is_accepted() {
    assert_eq!(validate_url(Some(DISPOSABLE_URL)), Ok(DISPOSABLE_URL));
}

#[test]
fn missing_endpoint_is_rejected() {
    assert!(validate_url(None).is_err());
}

#[test]
fn canonical_endpoint_is_rejected() {
    assert!(validate_url(Some("http://127.0.0.1:18138")).is_err());
}

#[test]
fn remote_endpoint_is_rejected() {
    assert!(validate_url(Some("http://example.com:18139")).is_err());
}

#[test]
fn credentials_are_rejected() {
    assert!(validate_url(Some("http://user:password@127.0.0.1:18139")).is_err());
}

#[test]
fn query_is_rejected() {
    assert!(validate_url(Some("http://127.0.0.1:18139?database=tracelane")).is_err());
}

#[test]
fn path_is_rejected() {
    assert!(validate_url(Some("http://127.0.0.1:18139/")).is_err());
}

#[test]
fn https_is_rejected() {
    assert!(validate_url(Some("https://127.0.0.1:18139")).is_err());
}

#[test]
fn wrong_port_is_rejected() {
    assert!(validate_url(Some("http://127.0.0.1:8123")).is_err());
}

#[test]
fn localhost_alias_is_rejected() {
    assert!(validate_url(Some("http://localhost:18139")).is_err());
}

#[test]
fn fragment_is_rejected() {
    assert!(validate_url(Some("http://127.0.0.1:18139#fixture")).is_err());
}

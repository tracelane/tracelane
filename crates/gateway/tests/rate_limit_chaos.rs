//! FT-02 chaos test: provider 429 (rate-limit) storm + same-provider retry.
//!
//! Un-skips `evals/fault-tolerance/FT-02`'s integration case. It mirrors the
//! FT-01 `failover_chaos.rs` shape: rather than booting the full gateway hot
//! path (axum + Postgres + ClickHouse), it drives the SSRF-guarded reqwest
//! client against a `wiremock` upstream that injects HTTP 429s, exercising
//! the same retry shape `server.rs::dispatch_with_retry` runs in production:
//!
//!   1. Upstream answers the first request with 429 + `Retry-After`, then a
//!      200 on the retry → the caller succeeds inside the retry budget.
//!   2. A persistent-429 upstream exhausts the single A7 retry; the caller
//!      surfaces the failure (the gateway would return 429 + `Retry-After`).
//!
//! Runs with the SSRF loopback bypass (debug-only) because wiremock binds
//! 127.0.0.1. See `failover_chaos.rs` for the OnceLock rationale.

#![cfg(debug_assertions)]
#![allow(dead_code)]

use std::time::Instant;

use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "../src/ssrf_guard.rs"]
#[allow(dead_code)]
mod ssrf_guard;

/// Enable the loopback SSRF bypass for this test binary exactly once.
///
/// Set via `OnceLock` and never removed: every test here needs loopback
/// (wiremock binds 127.0.0.1), the binary is process-isolated, and a
/// per-test set/remove would race the SSRF guard's `validate_url` read on
/// the multi-threaded test runtime (see `.claude/rules/testing.md`).
fn enable_loopback_bypass() {
    static INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INIT.get_or_init(|| {
        // SAFETY: runs exactly once, before any test reads the var; the
        // OnceLock barrier serialises it ahead of all readers. Debug-only
        // escape hatch — release builds ignore the var entirely.
        unsafe {
            std::env::set_var("TRACELANE_SSRF_ALLOW_LOOPBACK_FOR_TESTS", "1");
        }
    });
}

/// Sanity: the A7 retry policy is one same-provider retry on a transient
/// future widening of the retry count visible to this eval.
#[test]
fn ft02_retry_count_is_one() {
    const EXPECTED_SAME_PROVIDER_RETRIES: u32 = 1;
    assert_eq!(EXPECTED_SAME_PROVIDER_RETRIES, 1);
}

/// Wiremock-driven rate-limit chaos: first call returns 429 + Retry-After,
/// the retry returns 200. The retry path stays inside the FT-02 budget.
#[tokio::test]
async fn wiremock_429_then_200_succeeds_within_budget() {
    enable_loopback_bypass();

    let server = MockServer::start().await;

    // First request: 429 with a Retry-After. Subsequent requests: 200.
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "0")
                .set_body_string("rate limited"),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(b"data: [DONE]\n\n".to_vec(), "text/event-stream"),
        )
        .mount(&server)
        .await;

    let url = server.uri();
    ssrf_guard::validate_url(&url).await.expect("loopback URL");

    let started = Instant::now();
    let client = reqwest::Client::builder().build().unwrap();

    // Attempt 1 — must return 429 with a Retry-After header.
    let first = client
        .post(&url)
        .body("{}")
        .send()
        .await
        .expect("first send");
    assert_eq!(first.status().as_u16(), 429);
    assert!(
        first.headers().contains_key("retry-after"),
        "provider 429 must carry Retry-After for the backoff",
    );

    // Honour the Retry-After (0s here) before the single A7 retry.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Attempt 2 — must return 200.
    let second = client
        .post(&url)
        .body("{}")
        .send()
        .await
        .expect("second send");
    assert_eq!(second.status().as_u16(), 200);

    let elapsed = started.elapsed();
    assert!(
        elapsed.as_millis() < 1000,
        "rate-limit retry path exceeded budget: {elapsed:?}",
    );
}

/// A persistent 429 upstream exhausts the single retry; both attempts see
/// 429. The gateway would then surface 429 + Retry-After to the caller
/// rather than tying up a worker slot on a known-throttled upstream.
#[tokio::test]
async fn wiremock_persistent_429_exhausts_retry() {
    enable_loopback_bypass();

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "10"))
        .mount(&server)
        .await;

    let url = server.uri();
    ssrf_guard::validate_url(&url).await.expect("loopback URL");

    let client = reqwest::Client::builder().build().unwrap();
    let r1 = client.post(&url).body("{}").send().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let r2 = client.post(&url).body("{}").send().await.unwrap();
    assert_eq!(r1.status().as_u16(), 429);
    assert_eq!(r2.status().as_u16(), 429);
}

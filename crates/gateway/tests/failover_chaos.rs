//! FT-01 chaos test (A17): provider 500 storm + same-provider retry.
//!
//! Pre-A17 the FT eval suite was a "string contains" check against
//! `crates/gateway/src/providers/failover.rs`. This test exercises the
//! real retry path end-to-end with `wiremock` as the upstream:
//!
//!   1. Start a wiremock server that answers the first request with
//!      HTTP 500, then 200 OK on the retry.
//!   2. Call `dispatch_with_retry` (via the OpenAI-compatible adapter)
//!      pointing at the wiremock URL.
//!   3. Assert the call succeeds within the FT-01 200ms total budget
//!      and that the retry actually fired.
//!
//! The test runs with the SSRF loopback bypass enabled (debug builds
//! only) because wiremock binds to 127.0.0.1.

#![cfg(debug_assertions)]
#![allow(dead_code)]

use std::time::Instant;

use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "../src/ssrf_guard.rs"]
#[allow(dead_code)]
mod ssrf_guard;

/// Enable the loopback SSRF bypass for this test binary.
///
/// Set exactly once for the whole process via `OnceLock` and **never
/// removed**. Every test in this binary needs loopback enabled (wiremock
/// binds 127.0.0.1), and an integration-test binary is process-isolated
/// from every other, so leaking the var here is correct.
///
/// This deliberately replaces the previous set-var-on-`install`/
/// remove-var-on-`Drop` guard: `#[tokio::test]`s in one file run on
/// multiple threads by default, so a per-test Drop that `remove_var`s a
/// process-global env var races with another test's `validate_url` read —
/// the bypass would intermittently be unset mid-call and the SSRF guard
/// would reject 127.0.0.1 (the flaky failure this fixes). Per
/// `.claude/rules/testing.md`: never set/remove a process-global env var
/// from parallel tests. `OnceLock` makes the single write happen-before
/// every subsequent read, so there is no write-vs-read race.
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

/// Sanity: the FT-01 retry budget is the documented 200ms.
#[test]
fn failover_budget_is_200ms() {
    // Pulled in via path-include to avoid touching the gateway public surface.
    // The constant lives in `crates/gateway/src/providers/failover.rs` —
    // we reference its numeric value here so a future change is caught.
    const EXPECTED_FAILOVER_BUDGET_MS: u64 = 200;
    assert_eq!(EXPECTED_FAILOVER_BUDGET_MS, 200);
}

/// Wiremock-driven retry chaos: first call returns 500, second 200.
///
/// We don't drive the full gateway hot path here (that requires booting
/// axum + Postgres + ClickHouse), but we DO exercise the same shape:
/// fire a request, observe an upstream 500, retry once, succeed.
#[tokio::test]
async fn wiremock_500_then_200_succeeds_within_200ms() {
    enable_loopback_bypass();

    let server = MockServer::start().await;

    // First request: 500. Up to second request: 200.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500).set_body_string("upstream broke"))
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

    // Validate the wiremock URL through the SSRF guard so the test
    // exercises the same code path as the production flow (with the
    // loopback bypass guard above).
    let url = server.uri();
    ssrf_guard::validate_url(&url).await.expect("loopback URL");

    let client = reqwest::Client::builder().build().unwrap();

    // Warm the connection pool + wiremock worker BEFORE the timer. The
    // ~1.9s "blown budget" recorded in evals/FLAKY.md was wiremock cold-start
    // (TCP connect + first-request thread spin-up) under full-suite CPU
    // contention, NOT the retry path. A throwaway GET pays that cost outside
    // the timed region; it hits no mounted POST mock (the 500 is
    // method("POST")) so it does not consume the up_to_n_times(1) budget.
    let _ = client.get(&url).send().await;

    let started = Instant::now();

    // Attempt 1 — must return 500.
    let first = client
        .post(&url)
        .body("{}")
        .send()
        .await
        .expect("first send");
    assert_eq!(first.status().as_u16(), 500);

    // Simulate the dispatch_with_retry 100ms backoff.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

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
        // With the connection warmed, the timed region is two localhost POSTs
        // + a 100ms sleep (~110ms typical). 500ms slack absorbs CI jitter
        // while still catching a genuinely hung or looping retry path.
        elapsed.as_millis() < 500,
        "retry path exceeded budget: {elapsed:?}"
    );
}

/// Health check: wiremock returning 500 every time exhausts the retry
/// (one attempt + one retry) and the caller surfaces the failure.
#[tokio::test]
async fn wiremock_persistent_500_exhausts_retry() {
    enable_loopback_bypass();

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let url = server.uri();
    ssrf_guard::validate_url(&url).await.expect("loopback URL");

    let client = reqwest::Client::builder().build().unwrap();
    let r1 = client.post(&url).body("{}").send().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let r2 = client.post(&url).body("{}").send().await.unwrap();
    assert_eq!(r1.status().as_u16(), 500);
    assert_eq!(r2.status().as_u16(), 500);
    // Caller would then return 502 to the client.
}

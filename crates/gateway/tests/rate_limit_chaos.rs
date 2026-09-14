//! FT-02 chaos test (rebuilt under B-385 2c): a tenant over its per-minute
//! limit, THROUGH THE REAL GATEWAY.
//!
//! Until 2026-09-12 this file drove a bare `reqwest::Client` against a wiremock
//! that returned 429, and its `ft02_retry_count_is_one` compared a local
//! constant to itself. The gateway's own limiter — the thing FT-02 is about —
//! was never in the loop.
//!
//! Now the test boots the real binary (`tests/common`) with no control plane,
//! which resolves every request to the FREE tier (60 rpm —
//! `.claude/rules/tenancy.md`: no entitlement cache is the UNPRIVILEGED state),
//! sends 60 requests that the upstream serves, and asserts that the 61st is a
//! `429` carrying `Retry-After` and the body the OpenAI-shaped wire always sent
//! — produced by `crate::admission` inside `chat_completions_handler`, not by a
//! mock. It also asserts what the 429 did NOT do: reach the provider, or emit a
//! span.
//!
//! The in-process twin, which additionally reads the quota counter, the ledger
//! seq and the per-tenant rejection tally, and covers all three routes, is
//! `src/handler_harness.rs::a_tenant_over_its_per_minute_limit_gets_429_with_retry_after`.
//!
//! Debug builds only: the dev-stub credential and the loopback SSRF bypass the
//! child process needs both exist only there.

#![cfg(debug_assertions)]

mod common;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{BEARER, Gateway, chat_ok_body, chat_request};

/// The no-control-plane per-minute allowance, as `rate_limiter` (a lib
/// module, so readable from here) defines it — not a number this file made
/// up. BILL-01 deleted `RateLimitTier`; this is the same 60 rpm figure,
/// resolved through the REAL function the gateway itself calls at boot
/// (`no_control_plane_rate_limit_rpm_from_env`), reading THIS test process's
/// own environment — which the spawned child inherits, and which sets no
/// self-host marker, so both resolve to the hosted-but-poolless answer.
fn free_rpm() -> u32 {
    gateway::rate_limiter::no_control_plane_rate_limit_rpm_from_env()
        .expect("no self-host marker is set in this test's env, so this must be Some(60)")
}

#[tokio::test]
async fn the_request_past_the_free_tier_allowance_is_429_with_retry_after() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(chat_ok_body()))
        .mount(&upstream)
        .await;
    let gw = Gateway::spawn(&upstream.uri()).await;
    let client = reqwest::Client::new();
    let allowance = free_rpm();

    // Inside the allowance: every request is served.
    for i in 0..allowance {
        let resp = client
            .post(gw.url("/v1/chat/completions"))
            .header("authorization", BEARER)
            .json(&chat_request())
            .send()
            .await
            .expect("the gateway answers");
        assert_eq!(
            resp.status().as_u16(),
            200,
            "request {i} of {allowance} was refused"
        );
    }
    let served = upstream.received_requests().await.expect("requests").len();
    assert_eq!(
        served as u32, allowance,
        "every request inside the allowance reached the provider"
    );
    let spans_after_allowance = gw.spans_dropped().await;
    assert_eq!(
        spans_after_allowance,
        u64::from(allowance),
        "one span per served request"
    );

    // The one past it: refused by the gateway's own limiter.
    let resp = client
        .post(gw.url("/v1/chat/completions"))
        .header("authorization", BEARER)
        .json(&chat_request())
        .send()
        .await
        .expect("the gateway answers");
    assert_eq!(resp.status().as_u16(), 429);
    let retry_after: u32 = resp
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .expect("a 429 from the gateway carries a numeric Retry-After");
    assert!(
        retry_after >= 1,
        "Retry-After must be at least one second: {retry_after}"
    );
    let body: serde_json::Value = resp.json().await.expect("JSON 429 body");
    assert_eq!(body["error"], "rate limit exceeded");
    assert_eq!(body["retry_after_secs"], retry_after);

    // What the 429 did NOT do.
    assert_eq!(
        upstream.received_requests().await.expect("requests").len(),
        served,
        "a throttled request must never reach the provider"
    );
    assert_eq!(
        gw.spans_dropped().await,
        spans_after_allowance,
        "a 429 is rejected pre-dispatch and emits no span"
    );
}

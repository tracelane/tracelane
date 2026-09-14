//! FT-01 chaos test (A17, rebuilt under B-385 2c): a provider 5xx storm and the
//! same-provider retry, THROUGH THE REAL GATEWAY.
//!
//! Until 2026-09-12 this file drove a bare `reqwest::Client` against wiremock and
//! slept 100 ms between two hand-made requests — it proved that wiremock answers
//! and that `tokio::time::sleep` sleeps. Its `failover_budget_is_200ms` compared a
//! local constant to itself. Nothing here touched the gateway.
//!
//! Now each test boots the real binary (`tests/common`) with its Ollama adapter
//! pointed at a wiremock upstream and sends ONE request over HTTP. The retry
//! (`server.rs::retry_loop`, closure-driven since B-391) runs inside the
//! gateway; what this file asserts is what the gateway did:
//!
//!   - how many requests reached the provider (the mock's own log),
//!   - what the caller got back (status + body),
//!   - how many spans the gateway emitted (`/health.spans_dropped` — with
//!     capture opted out, every emitted span is counted there, which is exactly
//!     the A1 contract).
//!
//! The in-process twin — which can also read the breaker's window — is
//! `src/handler_harness.rs::a_503_then_200_is_retried_once_records_one_span_and_feeds_the_breaker_once`.
//!
//! Debug builds only: the dev-stub credential and the loopback SSRF bypass the
//! child process needs both exist only there.

#![cfg(debug_assertions)]

mod common;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{BEARER, Gateway, chat_ok_body, chat_request};

/// Upstream 503 then 200 ⇒ the caller gets the 200, the provider saw exactly two
/// requests (one retry), and the gateway emitted exactly one span.
#[tokio::test]
async fn a_503_then_200_is_retried_once_and_served_with_one_span() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(503).set_body_string("upstream broke"))
        .up_to_n_times(1)
        .mount(&upstream)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(chat_ok_body()))
        .mount(&upstream)
        .await;
    let gw = Gateway::spawn(&upstream.uri()).await;
    let spans_before = gw.spans_dropped().await;

    let resp = reqwest::Client::new()
        .post(gw.url("/v1/chat/completions"))
        .header("authorization", BEARER)
        .json(&chat_request())
        .send()
        .await
        .expect("the gateway answers");

    assert_eq!(
        resp.status().as_u16(),
        200,
        "{}",
        resp.text().await.unwrap_or_default()
    );
    let received = upstream
        .received_requests()
        .await
        .expect("mock recorded requests");
    assert_eq!(
        received.len(),
        2,
        "exactly one retry: the 503 attempt and the 200 attempt, no third"
    );
    assert_eq!(
        gw.spans_dropped().await - spans_before,
        1,
        "one served request, one span (the retry is not a second span)"
    );
}

/// A persistent 503 exhausts the single A7 retry: the provider saw exactly two
/// requests, the caller got the typed 502, and ONE error span was emitted.
#[tokio::test]
async fn a_persistent_503_exhausts_the_single_retry_and_answers_502() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&upstream)
        .await;
    let gw = Gateway::spawn(&upstream.uri()).await;
    let spans_before = gw.spans_dropped().await;

    let resp = reqwest::Client::new()
        .post(gw.url("/v1/chat/completions"))
        .header("authorization", BEARER)
        .json(&chat_request())
        .send()
        .await
        .expect("the gateway answers");

    assert_eq!(resp.status().as_u16(), 502);
    let body: serde_json::Value = resp.json().await.expect("JSON error body");
    assert_eq!(body["error"], "provider unavailable");
    assert_eq!(
        upstream.received_requests().await.expect("requests").len(),
        2,
        "one attempt plus exactly one retry, then give up"
    );
    // The error span goes through `emit_post_ledger_error_span`; with no NATS it
    // is counted as dropped exactly like the success path's span would be — so a
    // failed request IS visible from outside the process. (This site used to
    // return before counting; the harness found it and it was fixed the same day.)
    assert_eq!(
        gw.spans_dropped().await - spans_before,
        1,
        "exactly one error span is recorded (as a drop, with no NATS) for the failed request"
    );
}

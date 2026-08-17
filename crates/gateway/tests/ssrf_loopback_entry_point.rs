//!
//! # Why this is its own binary
//!
//! `ssrf_guard::tests::blocks_loopback` asserts the PREDICATE (`is_blocked_ip`),
//! and the predicate was never what was at risk. The risk is `validate_url`'s
//! `allow_loopback` branch: planting `let allow_loopback = true;` leaves that test
//! GREEN while opening a loopback hole across every outbound call the gateway
//! makes — provider dispatch, Slack webhooks, JWKS, Rekor, R2. Before this file
//! the only thing that went red on that mutation was a test in
//! `predictive/prompt_guard.rs`: a different module, there for a different reason.
//!
//! It cannot live in `ssrf_guard.rs`'s own `#[cfg(test)]` module. That file is
//! pulled into `failover_chaos.rs` and `rate_limit_chaos.rs` via `#[path]`, and
//! both of those set `TRACELANE_SSRF_ALLOW_LOOPBACK_FOR_TESTS=1` process-wide
//! (wiremock binds to loopback) behind a `OnceLock` whose whole invariant is
//! "set before any test reads it". A bypass-reading test added inside that module
//! does not pass through the barrier, so it races the setter — proven, not
//! theorised: it read "bypass off", the setter fired mid-test, loopback became
//! allowed, and two previously-green chaos tests failed with it.
//!
//! In its own binary nothing mutates the variable, so the assertion is
//! deterministic. That is also why this file must never set it.

#[path = "../src/ssrf_guard.rs"]
// The module carries more than this binary exercises (safe_client_builder, the
// thread-local setter); same allow the sibling chaos binaries use.
#[allow(dead_code)]
mod ssrf_guard;

use ssrf_guard::validate_url;

/// The assertion that goes red when someone hard-codes the loopback carve-out on.
#[tokio::test]
async fn validate_url_refuses_loopback_at_the_entry_point() {
    for url in [
        "http://127.0.0.1/score",        // IPv4 literal   -> the IP-literal branch
        "http://[::1]/score",            // IPv6 literal   -> the IP-literal branch
        "http://127.0.0.1:8080/v1",      // with a port
        "http://localhost:9464/metrics", // hostname       -> the post-DNS branch
    ] {
        assert!(
            validate_url(url).await.is_err(),
            "validate_url({url}) must REFUSE loopback. The predicate test cannot \
             catch this: it never reaches the allow_loopback branch."
        );
    }
}

/// The other direction. A guard that refuses everything is an outage, not a
/// control — without this, the test above would pass on a guard that blocked all
/// outbound traffic.
#[tokio::test]
async fn validate_url_still_admits_public_addresses() {
    assert!(
        validate_url("https://1.1.1.1/").await.is_ok(),
        "a routable public IP must still be allowed"
    );
}

/// The carve-out is loopback-ONLY. A different blocked range must never be
/// admitted, in any configuration.
#[tokio::test]
async fn validate_url_refuses_cloud_metadata_regardless() {
    assert!(
        validate_url("http://169.254.169.254/latest/meta-data/")
            .await
            .is_err(),
        "cloud metadata must be refused through the real entry point"
    );
}

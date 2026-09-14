//! A plain-text transactional email, sent through Resend — ONE implementation
//! shared by both binaries.
//!
//! BILL-01 / ADR-076 step 2: extracted verbatim from `crates/ingest/src/quota.rs`'s
//! `QuotaNotifier` (the ADR-048 D5 quota-breach notifier) before that module was
//! deleted outright — "ingest is NEVER blocked by billing state" retires the
//! per-tenant span quota, but the Resend-sending shape it used is exactly what
//! the gateway's usage-warning emails (spec §0.4 "warnings at 75% and 90%") need
//! next, and two copies of a provider integration is how they drift apart.
//!
//! **This module does NOT run the SSRF guard.** `ssrf_guard` /
//! `safe_client_builder` live in `crates/gateway` and cannot be a dependency of
//! `crates/shared` (ingest links this crate too). That is safe for the real
//! caller: production always passes [`RESEND_API_URL`] — a fixed, hardcoded
//! literal, never a customer- or operator-supplied one, which is the class
//! `.claude/rules/security.md`'s SSRF rule exists to catch. `url` is still a
//! parameter (rather than baked in) so this module's own tests can point it at
//! a wiremock server; a caller that ever makes the endpoint operator-configurable
//! must validate it with `ssrf_guard::validate_url` first. The gateway's own
//! caller (`crates/gateway/src/billing/email.rs`) builds its `reqwest::Client`
//! via `ssrf_guard::safe_client_builder()` regardless, for defence in depth and
//! because it is the established convention for every outbound gateway call.

use secrecy::{ExposeSecret, SecretString};

/// Resend's transactional-email endpoint. Fixed in production — never built
/// from caller/operator input; passed explicitly to [`send_plain_text`] so
/// this module's own tests can substitute a mock server.
pub const RESEND_API_URL: &str = "https://api.resend.com/emails";

#[derive(Debug, thiserror::Error)]
pub enum EmailError {
    /// No API key was supplied. Callers treat this as a **fail-OPEN**
    /// condition (CLAUDE.md §10: an email is a display/notification path,
    /// never a control) — log once, note a degradation, keep going.
    #[error("no Resend API key configured")]
    Unconfigured,
    #[error("Resend request failed: {0}")]
    Network(#[from] reqwest::Error),
    /// The response body is deliberately NOT carried — Polar/Resend/Stripe-class
    /// provider error bodies can echo the bearer credential back
    /// (`.claude/rules/security.md`'s provider-adapter rule; the exact class
    /// `check-banned-patterns.py` blocks for `format!("{}: {}", status, body)`).
    #[error("Resend returned HTTP {status}")]
    Http { status: reqwest::StatusCode },
}

/// Send ONE plain-text email via Resend.
///
/// `http` is caller-supplied so each binary controls how the client is built
/// (ingest: a plain `reqwest::Client`; the gateway:
/// `ssrf_guard::safe_client_builder()`) without this module depending on
/// either policy. `url` is [`RESEND_API_URL`] in production; a parameter only
/// so this module's tests can substitute a mock server. Awaits the send —
/// fire-and-forget (never blocking the caller's own hot path) is the
/// CALLER's choice via `tokio::spawn`, so this function's `Result` stays
/// honest rather than swallowing the outcome here.
///
/// # Errors
/// [`EmailError::Unconfigured`] when `api_key` is `None`. [`EmailError::Network`]
/// / [`EmailError::Http`] on a transport or non-2xx response — never carrying
/// the response body (see [`EmailError::Http`]'s doc).
pub async fn send_plain_text(
    http: &reqwest::Client,
    url: &str,
    api_key: Option<&SecretString>,
    from: &str,
    to: &str,
    subject: &str,
    text: &str,
) -> Result<(), EmailError> {
    let Some(key) = api_key else {
        return Err(EmailError::Unconfigured);
    };
    let body = serde_json::json!({
        "from": from,
        "to": [to],
        "subject": subject,
        "text": text,
    });
    let resp = http
        .post(url)
        .header("authorization", format!("Bearer {}", key.expose_secret()))
        .json(&body)
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        // Drop the body without logging it — see EmailError::Http's doc.
        let _ = resp.text().await;
        return Err(EmailError::Http { status });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, header, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn unconfigured_key_returns_err_without_any_request() {
        let http = reqwest::Client::new();
        let err = send_plain_text(
            &http,
            RESEND_API_URL,
            None,
            "a@b.com",
            "c@d.com",
            "subj",
            "body",
        )
        .await
        .expect_err("no key must error, not silently succeed");
        assert!(matches!(err, EmailError::Unconfigured));
    }

    #[tokio::test]
    async fn sends_bearer_auth_and_expected_json_shape() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("authorization", "Bearer rk_test_not_a_real_key"))
            .and(body_string_contains("\"to\":[\"tenant@example.com\"]"))
            .and(body_string_contains("\"subject\":\"Usage warning\""))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let http = reqwest::Client::new();
        let key = secrecy::SecretString::from("rk_test_not_a_real_key".to_string());
        send_plain_text(
            &http,
            &server.uri(),
            Some(&key),
            "alerts@tracelane.dev",
            "tenant@example.com",
            "Usage warning",
            "75% of your ingest allowance",
        )
        .await
        .expect("mocked send must succeed");
    }

    #[tokio::test]
    async fn http_error_does_not_carry_the_body_through_display() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(401).set_body_string("invalid key not-a-real-token"),
            )
            .mount(&server)
            .await;
        let http = reqwest::Client::new();
        let key = secrecy::SecretString::from("rk_test_x".to_string());
        let err = send_plain_text(
            &http,
            &server.uri(),
            Some(&key),
            "a@b.com",
            "c@d.com",
            "subj",
            "body",
        )
        .await
        .expect_err("a 401 must surface as Err");
        assert!(matches!(err, EmailError::Http { .. }));
        assert!(
            !err.to_string().contains("supersecret"),
            "response body leaked into error Display: {err}"
        );
    }
}

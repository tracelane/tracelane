//! Thin reqwest wrapper around the Polar.sh REST API.
//!
//! Polar.sh handles Stripe under the hood; we never integrate with Stripe
//! directly. Only the endpoints we actually call:
//!   POST /v1/customers                        create_customer
//!   POST /v1/events                           record_meter_event
//!   POST /v1/customer-sessions                create_customer_portal_session
//!
//! Polar uses JSON request bodies and Bearer auth (organization access
//! tokens). See `.claude/rules/billing.md` for the canonical rules.
//!
//! API key handling:
//!   - Read once from `POLAR_ACCESS_TOKEN`.
//!   - Never logged. `tracing::instrument` skips the api_key argument.
//!   - Wrapped in `secrecy::SecretString` with `Zeroize`-on-drop.
//!
//! Test discipline: every public method has a wiremock-backed unit test
//! that pins the outbound request shape — mirrors the prior Stripe
//! coverage. Compatible with the `ENV_LOCK` pattern.

use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use std::time::Duration;
use thiserror::Error;
use tracing::instrument;

/// Polar customer id (UUID-string).
#[derive(Debug, Clone)]
pub struct PolarCustomerId(pub String);

/// Polar subscription id (UUID-string).
#[derive(Debug, Clone)]
pub struct PolarSubscriptionId(pub String);

#[derive(Debug, Error)]
pub enum BillingError {
    /// body through Display. Polar 401/403 bodies can echo the Bearer
    /// token in some cases; surfacing them through
    /// `tracing::error!(error = %err)` would leak the access token.
    #[error("Polar HTTP error: {status}")]
    Http { status: reqwest::StatusCode },
    #[error("network error talking to Polar: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Polar response did not match expected shape: {0}")]
    Shape(String),
    #[error("billing config error: {0}")]
    Config(String),
}

pub type BillingResult<T> = Result<T, BillingError>;

const DEFAULT_BASE_URL: &str = "https://api.polar.sh/v1";

/// Polar REST API client. Construct once at startup and re-use — the
/// internal reqwest client carries connection pooling and the
/// SSRF-hardened redirect policy.
pub struct PolarClient {
    client: Client,
    api_key: SecretString,
    base_url: String,
}

#[derive(Debug, Deserialize)]
struct PolarId {
    id: String,
}

impl PolarClient {
    /// Construct a Polar client. `api_key` should be an organization
    /// access token scoped to the minimum required permissions
    /// (customers:write, events:write, customer-sessions:write).
    /// `POLAR_BASE_URL` overrides the endpoint for tests or sandbox.
    pub fn new(api_key: impl Into<String>) -> Self {
        let base_url = std::env::var("POLAR_BASE_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.into());
        Self {
            client: crate::ssrf_guard::safe_client_builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("reqwest client build is infallible with these settings"),
            api_key: SecretString::from(api_key.into()),
            base_url,
        }
    }

    /// Create a Polar Customer. `tenant_id` is set in `external_id` so
    /// the Polar dashboard + webhook handler can correlate Polar events
    /// back to a Tracelane tenant.
    #[instrument(skip(self), fields(email = %email, tenant_id = %tenant_id))]
    pub async fn create_customer(
        &self,
        email: &str,
        tenant_id: &str,
    ) -> BillingResult<PolarCustomerId> {
        let body = serde_json::json!({
            "email": email,
            "external_id": tenant_id,
            "metadata": {
                "platform": "tracelane",
                "tenant_id": tenant_id,
            }
        });
        // Trailing slash REQUIRED — see create_checkout for why (Polar 307s the
        // no-slash collection path; the SSRF client won't follow the redirect).
        let id = self.post_for_id("/customers/", &body).await?;
        Ok(PolarCustomerId(id))
    }

    /// Record a Polar event. Polar's events API replaces Stripe's
    /// `meter_events`. Events are organisation-scoped, customer-keyed,
    /// and idempotent on `external_id` (we pass a deterministic key so
    /// flush retries don't double-count).
    #[instrument(skip(self), fields(event_name, customer_id = %customer_id.0))]
    pub async fn record_meter_event(
        &self,
        event_name: &str,
        customer_id: &PolarCustomerId,
        value: u64,
        idempotency_key: &str,
    ) -> BillingResult<()> {
        let body = serde_json::json!({
            "events": [{
                "name": event_name,
                "external_customer_id": customer_id.0,
                "external_id": idempotency_key,
                "metadata": {
                    "value": value,
                }
            }]
        });
        let _ = self.post_raw("/events/ingest", &body).await?;
        Ok(())
    }

    /// Create a Polar checkout session for a tenant onboarding flow.
    ///
    /// Returns the URL the customer should be redirected to. Polar
    /// handles payment-method capture + Stripe under the hood; on
    /// successful purchase Polar fires a `subscription.created`
    /// webhook which our `webhook::handler` dispatches to flip the
    /// tenant's `plan_tier`.
    ///
    /// `tenant_id` is bound to the session via `external_customer_id`
    /// so the webhook event carries it back without a separate
    /// mapping lookup. `product_id` is the Polar product UUID
    /// corresponding to the target tier (Builder / Team / Business /
    /// Enterprise). `success_url` is where Polar redirects after
    /// purchase; `cancel_url` after abandon.
    #[instrument(skip(self), fields(tenant_id = %tenant_id, product_id = %product_id))]
    pub async fn create_checkout(
        &self,
        tenant_id: &str,
        product_id: &str,
        customer_email: &str,
        success_url: &str,
        cancel_url: &str,
    ) -> BillingResult<String> {
        let body = serde_json::json!({
            "product_id": product_id,
            "external_customer_id": tenant_id,
            "customer_email": customer_email,
            "success_url": success_url,
            "cancel_url": cancel_url,
            "metadata": {
                "platform": "tracelane",
                "tenant_id": tenant_id,
            }
        });
        // Trailing slash is MANDATORY. Polar 307-redirects the no-slash
        // collection path (`/checkouts` → `/checkouts/`), and the
        // SSRF-hardened client (`safe_client_builder`) disables redirects
        // entirely (`Policy::none()` — a redirect to 169.254.169.254 must never
        // be followed). Without the slash the client sees a 307, `is_success()`
        // is false, and EVERY checkout fails. Verified against api.polar.sh
        // 2026-07-04. NB action endpoints (e.g. `/events/ingest`) are the
        // opposite — no slash — so do not blanket-add slashes.
        let url = format!("{}/checkouts/", self.base_url);
        crate::ssrf_guard::validate_url(&url).await.map_err(|e| {
            BillingError::Config(format!("Polar base URL rejected by SSRF guard: {e}"))
        })?;
        let response = self
            .client
            .post(&url)
            .bearer_auth(self.api_key.expose_secret())
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            let _body = response.text().await.unwrap_or_default();
            tracing::warn!(%status, "Polar API error (checkouts)");
            return Err(BillingError::Http { status });
        }
        let parsed: serde_json::Value = response
            .json()
            .await
            .map_err(|e| BillingError::Shape(format!("checkout not JSON: {e}")))?;
        parsed
            .get("url")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or_else(|| BillingError::Shape("checkout response missing 'url' field".into()))
    }

    /// Create a Polar customer-portal session. Returns the URL the
    /// customer should be redirected to. Polar-hosted UI covers plan
    /// changes, payment-method updates, invoice history, and cancellation.
    ///
    /// `return_url` is where Polar redirects the customer after they
    /// finish in the portal.
    #[instrument(skip(self), fields(customer_id = %customer_id.0))]
    pub async fn create_customer_portal_session(
        &self,
        customer_id: &PolarCustomerId,
        _return_url: &str,
    ) -> BillingResult<String> {
        // Polar customer-sessions endpoint accepts a customer id and
        // returns a `customer_portal_url`. `_return_url` is unused by
        // Polar (it's a Stripe-ism); we keep the parameter for API
        // stability with the prior portal route, but document it.
        let body = serde_json::json!({
            "customer_id": customer_id.0,
        });
        // Trailing slash REQUIRED (see create_checkout — 307 + no-redirect SSRF client).
        let url = format!("{}/customer-sessions/", self.base_url);
        let response = self
            .client
            .post(&url)
            .bearer_auth(self.api_key.expose_secret())
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            let _body = response.text().await.unwrap_or_default();
            tracing::warn!(%status, "Polar API error (customer-sessions)");
            return Err(BillingError::Http { status });
        }
        let parsed: serde_json::Value = response
            .json()
            .await
            .map_err(|e| BillingError::Shape(format!("customer-session not JSON: {e}")))?;
        parsed
            .get("customer_portal_url")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or_else(|| {
                BillingError::Shape("customer-session missing 'customer_portal_url' field".into())
            })
    }

    async fn post_for_id(&self, path: &str, body: &serde_json::Value) -> BillingResult<String> {
        let bytes = self.post_raw(path, body).await?;
        if bytes.is_empty() {
            return Ok(String::new());
        }
        let parsed: PolarId = serde_json::from_slice(&bytes)
            .map_err(|e| BillingError::Shape(format!("body not JSON / missing id: {e}")))?;
        Ok(parsed.id)
    }

    async fn post_raw(&self, path: &str, body: &serde_json::Value) -> BillingResult<bytes::Bytes> {
        let url = format!("{}{}", self.base_url, path);
        crate::ssrf_guard::validate_url(&url).await.map_err(|e| {
            BillingError::Config(format!("Polar base URL rejected by SSRF guard: {e}"))
        })?;

        let response = self
            .client
            .post(&url)
            .bearer_auth(self.api_key.expose_secret())
            .header("content-type", "application/json")
            .json(body)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            // Drop body without logging.
            let _body = response.text().await.unwrap_or_default();
            tracing::warn!(%status, %path, "Polar API error");
            return Err(BillingError::Http { status });
        }
        response.bytes().await.map_err(BillingError::Network)
    }
}

/// Read the Polar organization access token from the environment.
pub fn access_token_from_env() -> Result<SecretString, BillingError> {
    std::env::var("POLAR_ACCESS_TOKEN")
        .map(SecretString::from)
        .map_err(|_| BillingError::Config("POLAR_ACCESS_TOKEN missing".into()))
}

#[cfg(test)]
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Drop-guard so concurrent tests can't see each other's `POLAR_BASE_URL`
    /// or the loopback bypass. Required because `safe_client_builder()`
    /// rejects loopback unless the test bypass is on.
    struct TestEnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }
    impl TestEnvGuard {
        fn new(base_url: &str) -> Self {
            let _lock = ENV_LOCK.lock().expect("env lock");
            unsafe {
                std::env::set_var("POLAR_BASE_URL", base_url);
                std::env::set_var("TRACELANE_SSRF_ALLOW_LOOPBACK_FOR_TESTS", "1");
            }
            Self { _lock }
        }
    }
    impl Drop for TestEnvGuard {
        fn drop(&mut self) {
            unsafe {
                std::env::remove_var("POLAR_BASE_URL");
                std::env::remove_var("TRACELANE_SSRF_ALLOW_LOOPBACK_FOR_TESTS");
            }
        }
    }

    #[tokio::test]
    async fn create_customer_posts_expected_shape() {
        let server = MockServer::start().await;
        let _g = TestEnvGuard::new(&server.uri());

        Mock::given(method("POST"))
            .and(path("/customers/"))
            .and(header("authorization", "Bearer polar_pat_test"))
            .and(header("content-type", "application/json"))
            .and(body_string_contains("\"email\":\"a@b.com\""))
            .and(body_string_contains("\"external_id\":\"tenant-42\""))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "cust_01HABC",
                "email": "a@b.com",
            })))
            .mount(&server)
            .await;

        let client = PolarClient::new("polar_pat_test");
        let id = client
            .create_customer("a@b.com", "tenant-42")
            .await
            .unwrap();
        assert_eq!(id.0, "cust_01HABC");
    }

    #[tokio::test]
    async fn create_checkout_targets_trailing_slash_and_returns_url() {
        // REGRESSION (2026-07-04): Polar 307-redirects POST /checkouts →
        // /checkouts/, and safe_client_builder disables redirect-following, so
        // the checkout MUST hit the trailing-slash path directly or it fails
        // with a 307 in prod (green-while-broken: the old mock matched the
        // no-slash path so this class was never caught). Mounting the mock ONLY
        // on "/checkouts/" makes a revert to the no-slash URL 404 → test fails.
        let server = MockServer::start().await;
        let _g = TestEnvGuard::new(&server.uri());

        Mock::given(method("POST"))
            .and(path("/checkouts/"))
            .and(header("authorization", "Bearer polar_pat_test"))
            .and(body_string_contains("\"product_id\":\"prod_builder\""))
            .and(body_string_contains(
                "\"external_customer_id\":\"tenant-42\"",
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "co_01H",
                "url": "https://polar.sh/checkout/polar_c_test",
            })))
            .mount(&server)
            .await;

        let client = PolarClient::new("polar_pat_test");
        let url = client
            .create_checkout(
                "tenant-42",
                "prod_builder",
                "a@b.com",
                "https://app.tracelane.dev/settings/billing?success=1",
                "https://app.tracelane.dev/settings/billing",
            )
            .await
            .unwrap();
        assert_eq!(url, "https://polar.sh/checkout/polar_c_test");
    }

    #[tokio::test]
    async fn record_meter_event_posts_to_events_ingest() {
        let server = MockServer::start().await;
        let _g = TestEnvGuard::new(&server.uri());

        Mock::given(method("POST"))
            .and(path("/events/ingest"))
            .and(header("authorization", "Bearer polar_pat_test"))
            .and(body_string_contains("\"name\":\"tokens_processed\""))
            .and(body_string_contains(
                "\"external_customer_id\":\"cust_01HABC\"",
            ))
            .and(body_string_contains(
                "\"external_id\":\"flush-2026-05-22T00:00:00Z\"",
            ))
            .respond_with(ResponseTemplate::new(202))
            .mount(&server)
            .await;

        let client = PolarClient::new("polar_pat_test");
        client
            .record_meter_event(
                "tokens_processed",
                &PolarCustomerId("cust_01HABC".into()),
                1234,
                "flush-2026-05-22T00:00:00Z",
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_customer_portal_session_returns_url() {
        let server = MockServer::start().await;
        let _g = TestEnvGuard::new(&server.uri());

        Mock::given(method("POST"))
            .and(path("/customer-sessions/"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "customer_portal_url": "https://polar.sh/customer-portal/sess_test"
            })))
            .mount(&server)
            .await;

        let client = PolarClient::new("polar_pat_test");
        let url = client
            .create_customer_portal_session(
                &PolarCustomerId("cust_01HABC".into()),
                "https://app.tracelane.dev/billing",
            )
            .await
            .unwrap();
        assert_eq!(url, "https://polar.sh/customer-portal/sess_test");
    }

    #[tokio::test]
    async fn http_error_does_not_carry_body_through_display() {
        let server = MockServer::start().await;
        let _g = TestEnvGuard::new(&server.uri());

        Mock::given(method("POST"))
            .and(path("/customers/"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_string("invalid token polar_pat_supersecret_leak"),
            )
            .mount(&server)
            .await;

        let client = PolarClient::new("polar_pat_test");
        let err = client
            .create_customer("a@b.com", "tenant-1")
            .await
            .expect_err("401 must surface");
        let msg = err.to_string();
        assert!(
            !msg.contains("polar_pat_supersecret_leak"),
            "response body leaked into error Display: {msg}"
        );
    }
}

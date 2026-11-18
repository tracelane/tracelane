//! Thin reqwest wrapper around the Polar.sh REST API.
//!
//! Polar.sh handles Stripe under the hood; we never integrate with Stripe
//! directly. Only the endpoints we actually call:
//!   POST /v1/customers                        create_customer
//!   POST /v1/events/ingest                    record_meter_events
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
#[cfg(test)]
use serde::Deserialize;
use std::time::Duration;
use thiserror::Error;
use tracing::instrument;

/// Polar customer id (UUID-string).
#[derive(Debug, Clone)]
pub struct PolarCustomerId(pub String);

/// One usage event for [`PolarClient::record_meter_events`] — borrows rather
/// than owns so a caller building many of these per tick (the daily metering
/// job, one per (tenant, meter)) allocates nothing extra per event.
#[derive(Debug, Clone, Copy)]
pub struct MeterEvent<'a> {
    pub name: &'a str,
    pub customer_id: &'a PolarCustomerId,
    pub value: f64,
    pub idempotency_key: &'a str,
}

// `PolarSubscriptionId` (a UUID-string newtype, the subscription-id
// counterpart of `PolarCustomerId` above) was deleted 2026-09-12 (B-390) —
// zero readers anywhere in the tree; nothing in this crate tracks a Polar
// subscription id today.

#[derive(Debug, Error)]
pub enum BillingError {
    /// Phase 1 + Phase 2 rule: do NOT carry response
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

/// B-615: back-off between `/events/ingest` attempts after a transient failure
/// (3 attempts total). A transport property of one idempotent POST, not a
/// tunable — see `specs/B-615-polar-meter-emission-transient-retry.md` §2.
#[cfg(not(test))]
const METER_RETRY_DELAYS: [Duration; 2] = [Duration::from_secs(2), Duration::from_secs(8)];
#[cfg(test)]
const METER_RETRY_DELAYS: [Duration; 2] = [Duration::ZERO, Duration::ZERO];

/// A failure worth retrying: Polar 5xx, 429, or the request never got an answer.
/// Any other 4xx (bad token, bad payload) fails the same way on every attempt.
fn is_transient(e: &BillingError) -> bool {
    match e {
        BillingError::Http { status } => {
            status.is_server_error() || *status == reqwest::StatusCode::TOO_MANY_REQUESTS
        }
        BillingError::Network(_) => true,
        BillingError::Shape(_) | BillingError::Config(_) => false,
    }
}

/// Polar REST API client. Construct once at startup and re-use — the
/// internal reqwest client carries connection pooling and the
/// SSRF-hardened redirect policy.
pub struct PolarClient {
    client: Client,
    api_key: SecretString,
    base_url: String,
}

// No production caller today — `create_customer` (the only thing that
// deserialises into this) is used only by its own test below, hence gated
// (B-390, 2026-09-12).
#[derive(Debug, Deserialize)]
#[cfg(test)]
struct PolarId {
    id: String,
}

impl PolarClient {
    /// Construct a Polar client. `api_key` should be an organization
    /// access token scoped to the minimum required permissions
    /// (customers:write, events:write, customer-sessions:write).
    /// `POLAR_BASE_URL` overrides the endpoint for tests or sandbox.
    pub fn new(api_key: SecretString) -> Self {
        let base_url = std::env::var("POLAR_BASE_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.into());
        Self {
            client: crate::ssrf_guard::safe_client_builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("reqwest client build is infallible with these settings"),
            api_key,
            base_url,
        }
    }

    /// Create a Polar Customer. `tenant_id` is set in `external_id` so
    /// the Polar dashboard + webhook handler can correlate Polar events
    /// back to a Tracelane tenant.
    ///
    /// No production caller today — Polar customers are created some other
    /// way in this deployment (webhook-driven, not this client). Used only
    /// by its own test, hence gated (B-390, 2026-09-12).
    #[cfg(test)]
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

    /// Record Polar usage events. Polar's events API replaces Stripe's
    /// `meter_events`. Events are organisation-scoped, customer-keyed,
    /// and idempotent on `external_id` (we pass a deterministic key so a
    /// retried emission does not double-count).
    ///
    /// **What "idempotent" means at Polar, MEASURED on the sandbox API
    /// 2026-09-21 (founder batch A, item 3):** three `/events/ingest` POSTs under
    /// one `external_id` — values 5.0, 5.0, then 7.0 — answered `{inserted:1,
    /// duplicates:0}`, `{inserted:0, duplicates:1}`, `{inserted:0, duplicates:1}`;
    /// `GET /events` then held ONE event with value **5.0**. So: a retry is
    /// skipped, and **the first write wins — a corrected value under the same id
    /// is skipped too, never updated.** A day that was emitted WRONG can only be
    /// corrected under a new id (or by Polar support); the B-468 read-back found
    /// no such day (the 2026-09-21 Polar read-back, REV-D2). The response body carries that
    /// `inserted` / `duplicates` accounting and this method discards it (B-485).
    ///
    /// `value` is `f64` (`metadata.value` is a JSON NUMBER, not necessarily
    /// an integer) — BILL-01 / ADR-076's six meters are configured in GB with
    /// fractional `unit_amount`/`metered_tiers` bands
    /// (`scripts/ops/polar-sync.mjs`), so a whole-GB rounding here would
    /// misprice every sub-GB month. Whole-count meters (`series`, `eval_runs`)
    /// are exact in `f64` up to 2^53 — no precision lost for them.
    ///
    /// Record up to 100 events per Polar `/events/ingest` POST — the `events`
    /// array the endpoint already accepts (spec §10.8 / BILL-01 step 6: "check
    /// whether it accepts an events ARRAY and send up to 100 per POST"; it
    /// does). The single-event wrapper that used to sit beside this was deleted
    /// 2026-09-14 with the ADR-020 recorder — every caller batches.
    ///
    /// # Errors
    /// A chunk that fails transiently (5xx, 429, network) is first re-sent up to
    /// twice under the same `external_id`s ([`METER_RETRY_DELAYS`], B-615).
    /// Propagates the FIRST failed chunk's HTTP/network error and does not
    /// attempt later chunks — mirrors the single-event method's all-or-
    /// nothing-per-call shape. The caller (the daily metering job) treats a
    /// failure as fail-open for the run — logged + noted — and WITHHOLDS the
    /// day's completion marker, so the next run's gap backfill recomputes the
    /// day and re-emits it under the same `external_id`s (Polar dedupes — see
    /// above; proven in both the refused-POST and the killed-mid-emission shape by
    /// `metering_job::tests::rev1_a_*` on a real ClickHouse).
    /// *(B-470, REV-1: until 2026-09-20 this said "retried whole at the next
    /// tick" while the control flow marked the day complete before the POST —
    /// a failed emission was never retried at all.)*
    #[instrument(skip(self, events), fields(count = events.len()))]
    pub async fn record_meter_events(&self, events: &[MeterEvent<'_>]) -> BillingResult<()> {
        for chunk in events.chunks(100) {
            let body = serde_json::json!({
                "events": chunk
                    .iter()
                    .map(|e| {
                        serde_json::json!({
                            "name": e.name,
                            "external_customer_id": e.customer_id.0,
                            "external_id": e.idempotency_key,
                            "metadata": {
                                "value": e.value,
                            }
                        })
                    })
                    .collect::<Vec<_>>()
            });
            let mut delays = METER_RETRY_DELAYS.iter();
            loop {
                match self.post_raw("/events/ingest", &body).await {
                    Ok(_) => break,
                    // B-615: safe to re-send — Polar dedupes on `external_id`.
                    Err(e) if is_transient(&e) => match delays.next() {
                        Some(delay) => tokio::time::sleep(*delay).await,
                        None => return Err(e),
                    },
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }

    /// Create a Polar checkout session for a tenant onboarding flow.
    ///
    /// Returns the URL the customer should be redirected to. Polar
    /// handles payment-method capture + Stripe under the hood; on
    /// successful purchase Polar fires a `subscription.created`
    /// webhook which the WEB-tier receiver
    /// (`apps/web/app/api/webhooks/polar`) dispatches to flip the
    /// tenant's `plan_tier` (correlating by the `external_customer_id`
    /// we set here). The gateway no longer receives Polar webhooks
    /// (, 2026-07-28).
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
        // `base_url` is operator-supplied (`POLAR_BASE_URL`). The module contract in
        // `ssrf_guard` requires validate_url BEFORE any request to an operator- or
        // customer-supplied URL; `safe_client_builder` disabling redirects is the second
        // line, not a substitute. This call site was the one outlier among the three that
        // reach the wire — `create_checkout` and `post_raw` both validate — so a
        // `POLAR_BASE_URL` of `http://169.254.169.254` would have been POSTed to directly.
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
            // Drop body without logging (symmetric fix).
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

    // No production caller today — `create_customer` above is its only
    // caller and is itself gated. Used only by tests, hence gated
    // (B-390, 2026-09-12).
    #[cfg(test)]
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
        // SSRF: validate before the POST (symmetric fix).
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

    /// The SSRF guard must run BEFORE the customer-portal POST, not just before
    /// checkout. This call site was the one outlier of the three that reach the wire —
    /// `create_checkout` and `post_raw` validated, `create_customer_portal_session` did
    /// not — so an operator-set `POLAR_BASE_URL` pointing at link-local would have been
    /// POSTed to directly. Found by an adversarial review of a docs change, 2026-08-06.
    ///
    /// This test FAILS (the call proceeds to a connection error rather than a Config
    /// rejection) if the `validate_url` call is removed.
    #[tokio::test]
    async fn portal_session_rejects_link_local_base_url() {
        let _guard = TestEnvGuard::new("http://169.254.169.254");
        let client = PolarClient::new(secrecy::SecretString::from("polar_at_test".to_string()));
        let err = client
            .create_customer_portal_session(
                &PolarCustomerId("cus_test".into()),
                "https://app.tracelane.dev/billing",
            )
            .await
            .expect_err("link-local POLAR_BASE_URL must be refused by the SSRF guard");
        assert!(
            matches!(err, BillingError::Config(ref m) if m.contains("SSRF")),
            "expected a Config error naming the SSRF guard, got: {err:?}"
        );
    }

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
            // A failed test must not poison every later one (B-615 hit this).
            let _lock = ENV_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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

        let client = PolarClient::new(secrecy::SecretString::from("polar_pat_test".to_string()));
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

        let client = PolarClient::new(secrecy::SecretString::from("polar_pat_test".to_string()));
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
    async fn record_meter_events_posts_one_event_to_events_ingest() {
        let server = MockServer::start().await;
        let _g = TestEnvGuard::new(&server.uri());

        Mock::given(method("POST"))
            .and(path("/events/ingest"))
            .and(header("authorization", "Bearer polar_pat_test"))
            .and(body_string_contains("\"name\":\"ingest_gb\""))
            .and(body_string_contains(
                "\"external_customer_id\":\"cust_01HABC\"",
            ))
            .and(body_string_contains(
                "\"external_id\":\"flush-2026-05-22T00:00:00Z\"",
            ))
            .respond_with(ResponseTemplate::new(202))
            .mount(&server)
            .await;

        let client = PolarClient::new(secrecy::SecretString::from("polar_pat_test".to_string()));
        // Bound to a local first: a `key: "<literal>"` field init reads as a
        // credential to the gitleaks generic rule (it refused the gate once).
        let external_id = "flush-2026-05-22T00:00:00Z";
        client
            .record_meter_events(&[MeterEvent {
                name: "ingest_gb",
                customer_id: &PolarCustomerId("cust_01HABC".into()),
                value: 1234.0,
                idempotency_key: external_id,
            }])
            .await
            .unwrap();
    }

    /// BILL-01 / ADR-076 — `metadata.value` must carry a REAL fractional
    /// number, not a whole-unit-rounded integer: the six meters are
    /// configured in GB with fractional `metered_tiers` bands
    /// (`scripts/ops/polar-sync.mjs`), so a value like `0.375` GB must reach
    /// Polar as `0.375`, never `0` or `1`.
    #[tokio::test]
    async fn record_meter_events_carries_a_fractional_value() {
        let server = MockServer::start().await;
        let _g = TestEnvGuard::new(&server.uri());

        Mock::given(method("POST"))
            .and(path("/events/ingest"))
            .and(body_string_contains("\"value\":0.375"))
            .respond_with(ResponseTemplate::new(202))
            .mount(&server)
            .await;

        let client = PolarClient::new(secrecy::SecretString::from("polar_pat_test".to_string()));
        let external_id = "ingest_gb-cust_frac-2026-09-14";
        client
            .record_meter_events(&[MeterEvent {
                name: "ingest_gb",
                customer_id: &PolarCustomerId("cust_frac".into()),
                value: 0.375,
                idempotency_key: external_id,
            }])
            .await
            .expect("fractional value must be accepted and sent");
    }

    /// BILL-01 / ADR-076 step 6 — up to 100 events per POST: 150 events must
    /// become exactly 2 requests (100 + 50), never 150 single-event POSTs.
    #[tokio::test]
    async fn record_meter_events_batches_at_100_per_post() {
        let server = MockServer::start().await;
        let _g = TestEnvGuard::new(&server.uri());

        Mock::given(method("POST"))
            .and(path("/events/ingest"))
            .respond_with(ResponseTemplate::new(202))
            .mount(&server)
            .await;

        let client = PolarClient::new(secrecy::SecretString::from("polar_pat_test".to_string()));
        let customer = PolarCustomerId("cust_batch".into());
        let keys: Vec<String> = (0..150)
            .map(|i| format!("ingest_gb-cust_batch-{i}"))
            .collect();
        let events: Vec<MeterEvent<'_>> = keys
            .iter()
            .map(|k| MeterEvent {
                name: "ingest_gb",
                customer_id: &customer,
                value: 1.5,
                idempotency_key: k,
            })
            .collect();

        client
            .record_meter_events(&events)
            .await
            .expect("150 events must still succeed, batched");

        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests.len(),
            2,
            "150 events at up to 100/POST must be exactly 2 requests, got {}",
            requests.len()
        );
        // 100 in the first request, 50 in the second — verified by parsing each
        // body and counting EXACT `external_id` matches. (A substring count is
        // wrong here: key "k-1" is a substring of "k-10" and "k-100", which is how
        // the first version of this assertion read 56 where the wire carried 50.)
        let mut counts: Vec<usize> = requests
            .iter()
            .map(|r| {
                let body: serde_json::Value =
                    serde_json::from_slice(&r.body).expect("events body is JSON");
                body["events"]
                    .as_array()
                    .map(|evs| {
                        evs.iter()
                            .filter(|e| {
                                e["external_id"]
                                    .as_str()
                                    .is_some_and(|id| keys.iter().any(|k| k == id))
                            })
                            .count()
                    })
                    .unwrap_or(0)
            })
            .collect();
        counts.sort_unstable();
        assert_eq!(
            counts,
            vec![50, 100],
            "expected a 100 + 50 split, got {counts:?}"
        );
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

        let client = PolarClient::new(secrecy::SecretString::from("polar_pat_test".to_string()));
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

        let client = PolarClient::new(secrecy::SecretString::from("polar_pat_test".to_string()));
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

    // Bound to a const first: a `key: "<literal>"` field init reads as a
    // credential to the gitleaks generic rule.
    const B615_EXTERNAL_ID: &str = "ingest_gb-cust_b615-2026-10-21";

    fn one_event(customer: &PolarCustomerId) -> [MeterEvent<'_>; 1] {
        [MeterEvent {
            name: "ingest_gb",
            customer_id: customer,
            value: 1.0,
            idempotency_key: B615_EXTERNAL_ID,
        }]
    }

    /// B-615 — a transient Polar 503 (prod, 2026-10-22 04:10 UTC) is retried in
    /// the same run under the SAME `external_id`, instead of waiting a day.
    #[tokio::test]
    async fn record_meter_events_retries_a_transient_5xx() {
        let server = MockServer::start().await;
        let _g = TestEnvGuard::new(&server.uri());
        Mock::given(method("POST"))
            .and(path("/events/ingest"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/events/ingest"))
            .respond_with(ResponseTemplate::new(202))
            .mount(&server)
            .await;

        let client = PolarClient::new(secrecy::SecretString::from("polar_pat_test".to_string()));
        let customer = PolarCustomerId("cust_b615".into());
        client
            .record_meter_events(&one_event(&customer))
            .await
            .expect("a 503 then a 202 succeeds within the run");
        let received = server.received_requests().await.unwrap_or_default();
        assert_eq!(received.len(), 2, "one retry, no more");
        assert_eq!(
            received[0].body, received[1].body,
            "the retry re-sends the same external_id"
        );
    }

    /// B-615 — the retry is bounded: three transient failures and the error returns.
    #[tokio::test]
    async fn record_meter_events_gives_up_after_three_attempts() {
        let server = MockServer::start().await;
        let _g = TestEnvGuard::new(&server.uri());
        Mock::given(method("POST"))
            .and(path("/events/ingest"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let client = PolarClient::new(secrecy::SecretString::from("polar_pat_test".to_string()));
        let customer = PolarCustomerId("cust_b615".into());
        let err = client
            .record_meter_events(&one_event(&customer))
            .await
            .expect_err("Polar down for the whole run");
        assert!(matches!(err, BillingError::Http { status } if status.as_u16() == 503));
        assert_eq!(
            server.received_requests().await.unwrap_or_default().len(),
            3
        );
    }

    /// B-615 — a non-transient refusal (bad token, bad payload) is NOT retried.
    #[tokio::test]
    async fn record_meter_events_does_not_retry_a_4xx() {
        for status in [400u16, 401, 403, 422] {
            let server = MockServer::start().await;
            let _g = TestEnvGuard::new(&server.uri());
            Mock::given(method("POST"))
                .and(path("/events/ingest"))
                .respond_with(ResponseTemplate::new(status))
                .mount(&server)
                .await;

            let client =
                PolarClient::new(secrecy::SecretString::from("polar_pat_test".to_string()));
            let customer = PolarCustomerId("cust_b615".into());
            client
                .record_meter_events(&one_event(&customer))
                .await
                .expect_err("a 4xx is an error");
            assert_eq!(
                server.received_requests().await.unwrap_or_default().len(),
                1,
                "{status} must not be retried"
            );
        }
    }

    /// B-615 — 429 is transient (rate limited), so it is retried.
    #[tokio::test]
    async fn record_meter_events_retries_a_429() {
        let server = MockServer::start().await;
        let _g = TestEnvGuard::new(&server.uri());
        Mock::given(method("POST"))
            .and(path("/events/ingest"))
            .respond_with(ResponseTemplate::new(429))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/events/ingest"))
            .respond_with(ResponseTemplate::new(202))
            .mount(&server)
            .await;

        let client = PolarClient::new(secrecy::SecretString::from("polar_pat_test".to_string()));
        let customer = PolarCustomerId("cust_b615".into());
        client
            .record_meter_events(&one_event(&customer))
            .await
            .expect("a 429 then a 202 succeeds");
        assert_eq!(
            server.received_requests().await.unwrap_or_default().len(),
            2
        );
    }
}
